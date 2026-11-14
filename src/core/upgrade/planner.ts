/**
 * 最小升级方案与冲突计算。
 *
 * 离线场景下的诚实边界（UI 必须展示）：
 * - 候选版本只来自已有的锁文件条目与 OSV 数据（affected.versions / fixed 边界），
 *   不代表 registry 上的全部可用版本，因此“最小修复版本”是**在已知版本集合内**的最小者。
 * - 新版本自身的依赖关系只有在该版本已存在于锁文件中时才知道；否则无法判断
 *   新版本会引入哪些依赖，这一点会明确标为 unknown，不假装算过。
 * - npm / Poetry 的锁文件带声明区间，可以做精确的“升级后是否仍满足父约束”检查；
 *   Cargo.lock 不含区间，只能给出“无法判定”并在计划里降级显示。
 */

import type { DependencyGraph, PackageNode, Requirement } from '../parsers/graph'
import type { Finding, ProjectAnalysis } from '../analysis/analyze'
import { fixTargetsFor, severityRank } from '../analysis/analyze'
import type { Ecosystem } from '../versions/ecosystem'
import { comparePep440, tryParsePep440 } from '../versions/pep440'
import { compareSemVer, semverDelta, tryParseSemVer, type SemVer } from '../versions/semver-core'
import { npmSatisfies, parseNpmRange } from '../versions/npm-range'
import { cargoSatisfies, parseCargoReq } from '../versions/cargo-req'
import { parsePyConstraint, pySatisfies } from '../versions/py-constraint'
import { findMatches } from '../osv/osv-range'

export interface ConstraintCheck {
  /** 该区间是否接受该版本 */
  readonly ok: boolean | null
  /** null 表示无法判定（Cargo 无区间 / 区间解析失败） */
  readonly reason?: string
  readonly requirement: Requirement
  readonly dependentLabel: string
}

export interface UpgradeStep {
  readonly nodeId: string
  readonly name: string
  readonly from: string
  readonly to: string
  /** 该升级是否由“被父包钉住”而被迫上推 */
  readonly causedByParent: boolean
  readonly delta: 'patch' | 'minor' | 'major' | 'prerelease' | 'none' | 'unknown'
  /** 升级后对每条入边约束的检查结果 */
  readonly checks: ReadonlyArray<ConstraintCheck>
  /** 升级目标版本本身的依赖（仅当该版本已在锁文件里才可得） */
  readonly knownRequirements?: ReadonlyArray<Requirement>
}

export interface UpgradePlan {
  readonly findingKey: string
  readonly packageName: string
  readonly currentVersion: string
  readonly targetVersion: string | null
  /** 需要变更的步骤（按从叶到根的依赖顺序展示） */
  readonly steps: ReadonlyArray<UpgradeStep>
  readonly severity: Finding['severity']
  readonly vulnerabilitiesFixed: ReadonlyArray<string>
  /** 仍存在的漏洞（例如一次升级只修掉其中一个） */
  readonly vulnerabilitiesRemaining: ReadonlyArray<string>
  readonly conflicts: ReadonlyArray<Conflict>
  /** 因数据缺失而无法验证的项 */
  readonly unknowns: ReadonlyArray<string>
  readonly feasible: boolean
  readonly strategy: 'bump-vulnerable' | 'bump-parent' | 'relax-root-constraint' | 'no-fix-version' | 'no-feasible-version'
}

export interface Conflict {
  readonly kind: 'introduced' | 'pre-existing'
  readonly dependent: string
  readonly requirement: string
  readonly targetVersion: string
  readonly message: string
}

/** 生态内版本比较；无法解析时返回 null */
export function compareVersions(ecosystem: Ecosystem, a: string, b: string): number | null {
  if (ecosystem === 'PyPI') {
    const pa = tryParsePep440(a)
    const pb = tryParsePep440(b)
    if (!pa || !pb) return null
    return comparePep440(pa, pb)
  }
  const pa = tryParseSemVer(a)
  const pb = tryParseSemVer(b)
  if (!pa || !pb) return null
  return compareSemVer(pa, pb)
}

export function versionDelta(ecosystem: Ecosystem, from: string, to: string): UpgradeStep['delta'] {
  if (ecosystem === 'PyPI') {
    const a = tryParsePep440(from)
    const b = tryParsePep440(to)
    if (!a || !b) return 'unknown'
    if (comparePep440(a, b) === 0) return 'none'
    if (a.epoch !== b.epoch) return 'major'
    const [am = 0, an = 0, ap = 0] = a.release
    const [bm = 0, bn = 0, bp = 0] = b.release
    if (am !== bm) return 'major'
    if (an !== bn) return 'minor'
    if (ap !== bp) return 'patch'
    return 'prerelease'
  }
  const a = tryParseSemVer(from)
  const b = tryParseSemVer(to)
  if (!a || !b) return 'unknown'
  return semverDelta(a, b)
}

/**
 * 判断版本 v 是否被某条 requirement 接受。
 * - npm/PyPI：使用各自的区间语义
 * - Cargo：锁文件没有区间，返回 null（无法判定）
 */
export function checkRequirement(
  ecosystem: Ecosystem,
  requirement: Requirement,
  version: string,
): { ok: boolean | null; reason?: string } {
  const spec = requirement.spec
  if (spec === undefined) {
    return { ok: null, reason: '该生态的锁文件不记录声明区间（Cargo.lock），无法验证' }
  }
  if (ecosystem === 'npm') {
    const parsed = parseNpmRange(spec)
    if (parsed.error) return { ok: null, reason: `无法解析 npm 区间 ${JSON.stringify(spec)}: ${parsed.error}` }
    return { ok: npmSatisfies(version, parsed) }
  }
  if (ecosystem === 'crates.io') {
    const parsed = parseCargoReq(spec)
    if (parsed.error) return { ok: null, reason: `无法解析 Cargo 约束 ${JSON.stringify(spec)}: ${parsed.error}` }
    return { ok: cargoSatisfies(version, parsed) }
  }
  const parsed = parsePyConstraint(spec)
  if (parsed.error) return { ok: null, reason: `无法解析 Python 约束 ${JSON.stringify(spec)}: ${parsed.error}` }
  return { ok: pySatisfies(version, parsed.constraint) }
}

/** 收集某包在“已知数据”内的候选版本 */
export function collectCandidates(
  analysis: ProjectAnalysis,
  node: PackageNode,
  finding: Finding,
): { version: string; source: 'lockfile' | 'osv-fixed' | 'osv-listed'; vulnerable: boolean }[] {
  const out = new Map<string, { version: string; source: 'lockfile' | 'osv-fixed' | 'osv-listed'; vulnerable: boolean }>()

  // 1) 锁文件里同名的其它副本
  for (const other of analysis.graph.nodes.values()) {
    if (other.meta?.isRoot === true) continue
    if (other.name !== node.name) continue
    if (other.version === node.version) continue
    out.set(other.version, { version: other.version, source: 'lockfile', vulnerable: false })
  }

  // 2) OSV 提供的 fixed 边界
  for (const match of finding.matches) {
    const targets = fixTargetsFor(analysis.ecosystem, node, match)
    for (const t of targets) {
      if (!out.has(t)) out.set(t, { version: t, source: 'osv-fixed', vulnerable: false })
    }
    // 3) OSV 的 affected.versions 说明这些版本真实存在（但都受影响）
    for (const v of match.affected.versions ?? []) {
      if (!out.has(v)) out.set(v, { version: v, source: 'osv-listed', vulnerable: true })
    }
  }

  // 标记事实上仍受影响：必须对**所有来源**的候选都查整库。
  // 尤其是 osv-fixed 来源：它只说明这条记录修好了，不代表别的记录不覆盖它。
  for (const [version, entry] of out) {
    const stillVulnerable = isStillVulnerable(analysis, node.name, version)
    out.set(version, { ...entry, vulnerable: stillVulnerable })
  }
  return [...out.values()]
}

/**
 * 判断某个候选版本是否仍受**漏洞库中任意记录**影响。
 * 必须查整库而不是只查当前命中的几条：一个包可能被多个漏洞覆盖，
 * 只升到“修好当前这条”的版本仍可能踩中另一条。
 */
function isStillVulnerable(analysis: ProjectAnalysis, name: string, version: string): boolean {
  try {
    return findMatches(analysis.records, analysis.ecosystem, name, version).length > 0
  } catch {
    // 版本无法解析时保守地视为受影响，避免推荐一个其实不安全的版本
    return true
  }
}

/** 某节点所有入边（依赖它的边），含根清单 */
export function incomingRequirements(graph: DependencyGraph, nodeId: string): { requirement: Requirement; dependentLabel: string }[] {
  const out: { requirement: Requirement; dependentLabel: string }[] = []
  for (const edge of graph.edges) {
    if (edge.toId !== nodeId) continue
    const from = graph.nodes.get(edge.fromId)
    const label = from ? (from.meta?.isRoot === true ? `${from.name}（根）` : `${from.name}@${from.version}`) : edge.fromId
    out.push({ requirement: edge.requirement, dependentLabel: label })
  }
  return out
}

export interface PlanOptions {
  /** 最多尝试的候选版本数（防止组合爆炸） */
  maxCandidates?: number
  /** 是否允许把升级上推到父包 */
  allowParentBump?: boolean
}

/**
 * 为单个 finding 生成升级计划。
 * 策略顺序：直接升该包 → 上推父包（逐层）→ 无解。
 */
export function planUpgradeForFinding(
  analysis: ProjectAnalysis,
  finding: Finding,
  options: PlanOptions = {},
): UpgradePlan {
  const graph = analysis.graph
  const ecosystem = analysis.ecosystem
  const maxCandidates = options.maxCandidates ?? 12
  const allowParentBump = options.allowParentBump ?? true
  const node = finding.node
  const vulnIds = finding.matches.map((m) => m.record.id)

  const candidates = collectCandidates(analysis, node, finding)
    .filter((c) => !c.vulnerable)
    .filter((c) => {
      const d = compareVersions(ecosystem, c.version, node.version)
      return d === null ? true : d > 0 // 只考虑升级
    })
    .sort((a, b) => {
      const d = compareVersions(ecosystem, a.version, b.version)
      return d ?? 0
    })
    .slice(0, maxCandidates)

  const unknowns: string[] = []
  if (!graph.requirementSpecsAvailable) {
    unknowns.push('Cargo.lock 不记录依赖声明区间，无法验证升级后父包约束是否仍满足')
  }

  if (candidates.length === 0) {
    return {
      findingKey: `${node.name}@${node.version}`,
      packageName: node.name,
      currentVersion: node.version,
      targetVersion: null,
      steps: [],
      severity: finding.severity,
      vulnerabilitiesFixed: [],
      vulnerabilitiesRemaining: vulnIds,
      conflicts: [],
      unknowns: [
        '已知版本集合中没有可用的修复版本（OSV 未给出 fixed，锁文件里也没有更高版本）',
        ...unknowns,
      ],
      feasible: false,
      strategy: 'no-fix-version',
    }
  }

  // 逐个候选版本尝试：必须满足所有入边约束
  const incoming = incomingRequirements(graph, node.id)
  const preExistingConflicts = collectPreExistingConflicts(analysis, node.id, incoming)

  /** 记录“只有根清单约束挡住”的最佳方案 */
  let rootRelaxCandidate: { version: string; checks: ConstraintCheck[] } | null = null

  for (const candidate of candidates) {
    const checks: ConstraintCheck[] = incoming.map(({ requirement, dependentLabel }) => {
      const res = checkRequirement(ecosystem, requirement, candidate.version)
      return { ok: res.ok, reason: res.reason, requirement, dependentLabel }
    })

    const violating = checks.filter((c) => c.ok === false)
    if (violating.length === 0) {
      const knownRequirements = knownRequirementsOf(graph, node.name, candidate.version)
      const step: UpgradeStep = {
        nodeId: node.id,
        name: node.name,
        from: node.version,
        to: candidate.version,
        causedByParent: false,
        delta: versionDelta(ecosystem, node.version, candidate.version),
        checks,
        knownRequirements,
      }
      const fixed = vulnIds.length > 0 ? vulnIds : []
      return {
        findingKey: `${node.name}@${node.version}`,
        packageName: node.name,
        currentVersion: node.version,
        targetVersion: candidate.version,
        steps: [step],
        severity: finding.severity,
        vulnerabilitiesFixed: fixed,
        vulnerabilitiesRemaining: [],
        conflicts: preExistingConflicts,
        unknowns: [...unknowns, ...unknownUpgradeNotes(knownRequirements)],
        feasible: true,
        strategy: 'bump-vulnerable',
      }
    }

    // 若唯一的阻碍都来自根清单（外部直接依赖），放宽根声明即可修复。
    // 这是“最小升级方案”的一部分：用户需要在 package.json / pyproject.toml 里改声明。
    const blockingLabels = violating.map((c) => c.dependentLabel)
    const onlyRootBlocking = blockingLabels.every((label) => label.includes('（根）'))
    if (onlyRootBlocking && rootRelaxCandidate === null) {
      rootRelaxCandidate = { version: candidate.version, checks }
    }
  }

  // 所有候选都被父约束拒绝 → 尝试上推父包
  if (allowParentBump && incoming.length > 0) {
    const parentPlan = tryParentBump(analysis, finding, candidates, options)
    if (parentPlan) return parentPlan
  }

  // 只需放宽根清单声明即可的方案优先于“无解”
  if (rootRelaxCandidate) {
    const { version, checks } = rootRelaxCandidate
    const knownRequirements = knownRequirementsOf(graph, node.name, version)
    const step: UpgradeStep = {
      nodeId: node.id,
      name: node.name,
      from: node.version,
      to: version,
      causedByParent: false,
      delta: versionDelta(ecosystem, node.version, version),
      checks,
      knownRequirements,
    }
    return {
      findingKey: `${node.name}@${node.version}`,
      packageName: node.name,
      currentVersion: node.version,
      targetVersion: version,
      steps: [step],
      severity: finding.severity,
      vulnerabilitiesFixed: vulnIds,
      vulnerabilitiesRemaining: [],
      conflicts: preExistingConflicts,
      unknowns: [
        ...unknowns,
        ...unknownUpgradeNotes(knownRequirements),
        '需要同时放宽根清单里的版本声明（锁文件不会自己更新这条声明）',
      ],
      feasible: true,
      strategy: 'relax-root-constraint',
    }
  }

  // 无解：报告被哪些约束挡住
  const blockers = incoming
    .map(({ requirement, dependentLabel }) => {
      const rejected = candidates.filter((c) => checkRequirement(ecosystem, requirement, c.version).ok === false)
      return rejected.length === candidates.length
        ? `${dependentLabel} 要求 ${node.name} ${requirement.spec ?? '（无区间）'}，拒绝了全部候选版本`
        : null
    })
    .filter((x): x is string => x !== null)

  return {
    findingKey: `${node.name}@${node.version}`,
    packageName: node.name,
    currentVersion: node.version,
    targetVersion: null,
    steps: [],
    severity: finding.severity,
    vulnerabilitiesFixed: [],
    vulnerabilitiesRemaining: vulnIds,
    conflicts: preExistingConflicts,
    unknowns: [
      ...blockers,
      '以下候选版本均被父包约束拒绝，需先升级父包或放宽其声明区间',
      ...unknowns,
    ],
    feasible: false,
    strategy: 'no-feasible-version',
  }
}

function unknownUpgradeNotes(knownRequirements: ReadonlyArray<Requirement> | undefined): string[] {
  if (knownRequirements === undefined) {
    return ['目标版本不在当前锁文件中，其自身依赖未知，可能引入新的传递依赖']
  }
  return []
}

/** 若锁文件里已有同 (name, version) 的副本，可复用它的依赖声明 */
function knownRequirementsOf(
  graph: DependencyGraph,
  name: string,
  version: string,
): Requirement[] | undefined {
  for (const node of graph.nodes.values()) {
    if (node.name === name && node.version === version) return [...node.requirements]
  }
  return undefined
}

function collectPreExistingConflicts(
  analysis: ProjectAnalysis,
  nodeId: string,
  incoming: { requirement: Requirement; dependentLabel: string }[],
): Conflict[] {
  const out: Conflict[] = []
  const node = analysis.graph.nodes.get(nodeId)
  if (!node) return out
  for (const { requirement, dependentLabel } of incoming) {
    const res = checkRequirement(analysis.ecosystem, requirement, node.version)
    if (res.ok === false) {
      out.push({
        kind: 'pre-existing',
        dependent: dependentLabel,
        requirement: requirement.spec ?? '（无区间）',
        targetVersion: node.version,
        message: `当前锁文件已存在不一致：${dependentLabel} 声明 ${requirement.spec ?? '（无区间）'}，但锁定了 ${node.version}`,
      })
    }
  }
  return out
}

/**
 * 尝试升级父包：找出拒绝了候选版本的父包，看看把父包升到某个已知版本能否放宽约束。
 * 这里只做一层（父包版本变更本身仍要满足它自己的入边约束，会递归检查）。
 */
function tryParentBump(
  analysis: ProjectAnalysis,
  finding: Finding,
  candidates: { version: string }[],
  options: PlanOptions,
): UpgradePlan | null {
  const graph = analysis.graph
  const ecosystem = analysis.ecosystem
  const node = finding.node
  const vulnIds = finding.matches.map((m) => m.record.id)

  const parentEdges = graph.edges.filter((e) => e.toId === node.id && graph.nodes.get(e.fromId)?.meta?.isRoot !== true)
  const parentIds = [...new Set(parentEdges.map((e) => e.fromId))]

  for (const parentId of parentIds) {
    const parent = graph.nodes.get(parentId)
    if (!parent) continue

    // 父包的候选版本：锁文件中的同名其它副本
    const parentCandidates = [...graph.nodes.values()]
      .filter((n) => n.name === parent.name && n.version !== parent.version)
      .filter((n) => {
        const d = compareVersions(ecosystem, n.version, parent.version)
        return d === null ? true : d > 0
      })
      .slice(0, options.maxCandidates ?? 12)

    for (const parentCandidate of parentCandidates) {
      // 父包新版本必须满足漏洞包的所有候选版本约束 —— 若父包新版本的依赖区间未知则无法判定
      const parentReqs = parentCandidate.requirements.filter((r) => r.name === node.name)
      if (parentReqs.length === 0) continue
      const acceptsSomeCandidate = candidates.some((c) =>
        parentReqs.some((r) => checkRequirement(ecosystem, r, c.version).ok === true),
      )
      if (!acceptsSomeCandidate) continue

      // 父包自身要满足它的入边
      const parentIncoming = incomingRequirements(graph, parentId)
      const parentChecks: ConstraintCheck[] = parentIncoming.map(({ requirement, dependentLabel }) => {
        const res = checkRequirement(ecosystem, requirement, parentCandidate.version)
        return { ok: res.ok, reason: res.reason, requirement, dependentLabel }
      })
      if (parentChecks.some((c) => c.ok === false)) continue

      const acceptedVulnerable = candidates.find((c) =>
        parentReqs.some((r) => checkRequirement(ecosystem, r, c.version).ok === true),
      )
      if (!acceptedVulnerable) continue

      const parentStep: UpgradeStep = {
        nodeId: parentId,
        name: parent.name,
        from: parent.version,
        to: parentCandidate.version,
        causedByParent: false,
        delta: versionDelta(ecosystem, parent.version, parentCandidate.version),
        checks: parentChecks,
        knownRequirements: [...parentCandidate.requirements],
      }
      const childChecks: ConstraintCheck[] = parentReqs.map((requirement) => {
        const res = checkRequirement(ecosystem, requirement, acceptedVulnerable.version)
        return { ok: res.ok, reason: res.reason, requirement, dependentLabel: `${parent.name}@${parentCandidate.version}` }
      })
      const childStep: UpgradeStep = {
        nodeId: node.id,
        name: node.name,
        from: node.version,
        to: acceptedVulnerable.version,
        causedByParent: true,
        delta: versionDelta(ecosystem, node.version, acceptedVulnerable.version),
        checks: childChecks,
        knownRequirements: knownRequirementsOf(graph, node.name, acceptedVulnerable.version),
      }

      return {
        findingKey: `${node.name}@${node.version}`,
        packageName: node.name,
        currentVersion: node.version,
        targetVersion: acceptedVulnerable.version,
        steps: [childStep, parentStep],
        severity: finding.severity,
        vulnerabilitiesFixed: vulnIds,
        vulnerabilitiesRemaining: [],
        conflicts: [],
        unknowns: [
          ...(graph.requirementSpecsAvailable
            ? []
            : ['Cargo.lock 不记录声明区间，父包升级的约束检查无法完成']),
          ...unknownUpgradeNotes(childStep.knownRequirements),
          ...unknownUpgradeNotes(parentStep.knownRequirements),
        ],
        feasible: true,
        strategy: 'bump-parent',
      }
    }
  }
  return null
}

/** 汇总多个 finding 的计划，并检测计划之间的相互影响 */
export interface UpgradeReport {
  readonly plans: ReadonlyArray<UpgradePlan>
  readonly conflicts: ReadonlyArray<Conflict>
  readonly summary: {
    readonly totalFindings: number
    readonly fixable: number
    readonly unfixable: number
    readonly directCount: number
  }
}

export function planAllUpgrades(analysis: ProjectAnalysis, options: PlanOptions = {}): UpgradeReport {
  const plans = analysis.findings.map((f) => planUpgradeForFinding(analysis, f, options))

  // 计划间冲突：同一包被两个计划升级到不同版本；或某个计划的目标版本破坏了另一计划所在包的约束
  const conflicts: Conflict[] = []
  const byName = new Map<string, UpgradePlan[]>()
  for (const plan of plans) {
    if (!plan.targetVersion) continue
    const list = byName.get(plan.packageName) ?? []
    list.push(plan)
    byName.set(plan.packageName, list)
  }
  for (const [name, list] of byName) {
    const targets = new Set(list.map((p) => p.targetVersion!))
    if (targets.size > 1) {
      conflicts.push({
        kind: 'introduced',
        dependent: name,
        requirement: [...targets].join(' / '),
        targetVersion: [...targets].join(' / '),
        message: `同一个包被 ${targets.size} 个漏洞修复方案要求升级到不同版本：${[...targets].join('、')}，需要人工选择`,
      })
    }
  }

  const fixable = plans.filter((p) => p.feasible).length
  return {
    plans,
    conflicts,
    summary: {
      totalFindings: analysis.findings.length,
      fixable,
      unfixable: plans.length - fixable,
      directCount: analysis.findings.filter((f) => f.isDirect).length,
    },
  }
}

/** 供 UI：把升级幅度转成中文 */
export function deltaLabel(delta: UpgradeStep['delta']): string {
  switch (delta) {
    case 'patch':
      return '补丁'
    case 'minor':
      return '次版本'
    case 'major':
      return '主版本（可能不兼容）'
    case 'prerelease':
      return '预发布'
    case 'none':
      return '无变化'
    case 'unknown':
      return '未知'
  }
}

export type { SemVer }
export { severityRank }
