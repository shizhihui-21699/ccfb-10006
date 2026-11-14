/**
 * 升级后影响面模拟：把计划应用到一个“虚拟锁文件”上，重新检查整个依赖图的一致性。
 *
 * 关键设计：不假装能凭空知道新版本的依赖。
 * - 若目标版本在锁文件里已存在（例如同一包的另一个副本），可以直接复用它的依赖声明，
 *   这时的模拟是**有依据的**；
 * - 否则目标版本的依赖未知，模拟只能检查“已有入边约束是否仍满足”，并在 unknowns 里声明
 *   无法得知新增依赖。这一点在 UI 上必须分开显示。
 */

import type { DependencyGraph, Requirement } from '../parsers/graph'
import { parseNpmRange, npmSatisfies } from '../versions/npm-range'
import { parseCargoReq, cargoSatisfies } from '../versions/cargo-req'
import { parsePyConstraint, pySatisfies } from '../versions/py-constraint'
import type { Ecosystem } from '../versions/ecosystem'
import type { UpgradePlan, UpgradeStep } from './planner'
import { checkRequirement, versionDelta } from './planner'

export interface SimulatedChange {
  readonly name: string
  readonly from: string
  readonly to: string
  readonly dependentsAffected: number
}

export interface SimulationResult {
  /** 应用计划后，所有“仍不满足的入边约束” */
  readonly brokenRequirements: ReadonlyArray<{
    readonly dependent: string
    readonly requirement: Requirement
    readonly targetVersion: string
    readonly message: string
  }>
  /** 因目标版本已在锁文件里而确知的新增依赖 */
  readonly newDirectRequirements: ReadonlyArray<Requirement>
  /** 无法验证的部分（必须显式呈现） */
  readonly unknowns: ReadonlyArray<string>
  readonly changes: ReadonlyArray<SimulatedChange>
}

function check(ecosystem: Ecosystem, spec: string | undefined, version: string): boolean | null {
  if (spec === undefined) return null
  if (ecosystem === 'npm') {
    const r = parseNpmRange(spec)
    if (r.error) return null
    return npmSatisfies(version, r)
  }
  if (ecosystem === 'crates.io') {
    const r = parseCargoReq(spec)
    if (r.error) return null
    return cargoSatisfies(version, r)
  }
  const r = parsePyConstraint(spec)
  if (r.error) return null
  return pySatisfies(version, r.constraint)
}

/** 模拟单个计划的影响 */
export function simulatePlan(graph: DependencyGraph, plan: UpgradePlan): SimulationResult {
  const ecosystem = graph.ecosystem
  const broken: SimulationResult['brokenRequirements'][number][] = []
  const unknowns: string[] = []
  const changes: SimulatedChange[] = []

  // 精确到节点：同一包的不同副本可能只有其中一个需要升级，
  // 按包名覆盖版本会把无关副本也算进来，导致误报冲突。
  const upgradedNodeIds = new Set(plan.steps.map((s) => s.nodeId))
  const newVersionByNodeId = new Map<string, string>()
  for (const step of plan.steps) newVersionByNodeId.set(step.nodeId, step.to)

  for (const step of plan.steps) {
    const copies = [...graph.nodes.values()].filter(
      (n) => n.name === step.name && n.meta?.isRoot !== true && n.id !== step.nodeId,
    )
    changes.push({
      name: step.name,
      from: step.from,
      to: step.to,
      dependentsAffected: copies.length,
    })
  }

  // 1) 检查所有指向“被升级节点”的边：新版本是否仍满足声明。
  //    声明者本身若也在升级（被替换掉了），它的旧约束不再适用，跳过。
  for (const edge of graph.edges) {
    if (upgradedNodeIds.has(edge.fromId)) continue
    const newVersion = newVersionByNodeId.get(edge.toId)
    if (newVersion === undefined) continue
    const target = graph.nodes.get(edge.toId)
    if (!target) continue

    const ok = check(ecosystem, edge.requirement.spec, newVersion)
    if (ok === null) {
      unknowns.push(
        `${graph.nodes.get(edge.fromId)?.name ?? edge.fromId} → ${target.name}: 无法验证约束 ${edge.requirement.spec ?? '（无区间）'}`,
      )
      continue
    }
    if (!ok) {
      const from = graph.nodes.get(edge.fromId)
      broken.push({
        dependent: from ? `${from.name}@${from.version}` : edge.fromId,
        requirement: edge.requirement,
        targetVersion: newVersion,
        message: `${from ? from.name : edge.fromId} 声明 ${target.name} ${edge.requirement.spec ?? '（无区间）'}，不接受 ${newVersion}`,
      })
    }
  }

  // 2) 目标版本的依赖：只有锁文件里已有同 (name, version) 时才确知
  const newDirectRequirements: Requirement[] = []
  for (const step of plan.steps) {
    const known = knownRequirements(graph, step.name, step.to)
    if (known === undefined) {
      unknowns.push(
        `${step.name}@${step.to} 不在当前锁文件中，其依赖声明未知，无法判断是否引入新的传递依赖或版本冲突`,
      )
      continue
    }
    for (const req of known) {
      newDirectRequirements.push(req)
      // 新依赖能否与现有（未被升级的）版本共存？
      const existing = [...graph.nodes.values()].filter(
        (n) =>
          n.name === req.name &&
          n.meta?.isRoot !== true &&
          !upgradedNodeIds.has(n.id) &&
          !(n.name === step.name && n.version === step.to),
      )
      if (existing.length === 0) {
        unknowns.push(
          `${step.name}@${step.to} 新增依赖 ${req.name}${req.spec ? ' ' + req.spec : ''}，当前锁文件没有该包`,
        )
        continue
      }
      const accepted = existing.some((n) => check(ecosystem, req.spec, n.version) === true)
      if (!accepted) {
        broken.push({
          dependent: `${step.name}@${step.to}`,
          requirement: req,
          targetVersion: existing[0]!.version,
          message: `${step.name}@${step.to} 要求 ${req.name} ${req.spec}，但锁文件中现有版本 ${existing.map((n) => n.version).join(' / ')} 不满足`,
        })
      }
    }
  }

  // 3) 同一包还有其它副本：提示体积/一致性问题。
  //    同一 name@version 可能有多个安装路径（不同父包各装一份），按版本去重后再展示。
  for (const step of plan.steps) {
    const copyVersions = [
      ...new Set(
        [...graph.nodes.values()]
          .filter((n) => n.name === step.name && n.meta?.isRoot !== true && n.id !== step.nodeId)
          .map((n) => n.version),
      ),
    ]
    if (copyVersions.length > 0) {
      unknowns.push(
        `锁文件中 ${step.name} 还有其它副本（${copyVersions.join('、')}），本次只升级其中一处；若其它副本未受影响可保留，否则需一并处理`,
      )
    }
  }

  return {
    brokenRequirements: dedupeBroken(broken),
    newDirectRequirements: dedupeRequirements(newDirectRequirements),
    unknowns: [...new Set(unknowns)],
    changes,
  }
}

function dedupeBroken(list: SimulationResult['brokenRequirements'][number][]): SimulationResult['brokenRequirements'][number][] {
  const seen = new Set<string>()
  const out: typeof list = []
  for (const item of list) {
    const key = `${item.dependent}|${item.requirement.name}|${item.requirement.spec ?? ''}|${item.targetVersion}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(item)
  }
  return out
}

function dedupeRequirements(list: Requirement[]): Requirement[] {
  const seen = new Set<string>()
  return list.filter((r) => {
    const key = `${r.fromId}|${r.name}|${r.spec ?? ''}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function knownRequirements(graph: DependencyGraph, name: string, version: string): Requirement[] | undefined {
  for (const node of graph.nodes.values()) {
    if (node.name === name && node.version === version) return [...node.requirements]
  }
  return undefined
}

/** 全量模拟：所有计划合并后的整体影响 */
export interface CombinedSimulation {
  readonly perPlan: ReadonlyArray<{ readonly plan: UpgradePlan; readonly result: SimulationResult }>
  /** 计划之间互相冲突的目标版本 */
  readonly crossPlanConflicts: ReadonlyArray<string>
  readonly unknowns: ReadonlyArray<string>
}

export function simulateAll(graph: DependencyGraph, plans: readonly UpgradePlan[]): CombinedSimulation {
  const perPlan = plans
    .filter((p) => p.feasible)
    .map((plan) => ({ plan, result: simulatePlan(graph, plan) }))

  // 同一包被不同计划要求升到不同版本
  const targets = new Map<string, Set<string>>()
  for (const { plan } of perPlan) {
    if (!plan.targetVersion) continue
    const set = targets.get(plan.packageName) ?? new Set<string>()
    set.add(plan.targetVersion)
    targets.set(plan.packageName, set)
  }
  const crossPlanConflicts: string[] = []
  for (const [name, versions] of targets) {
    if (versions.size > 1) {
      crossPlanConflicts.push(`${name} 被不同修复方案要求升级到不同版本：${[...versions].join('、')}`)
    }
  }

  const unknowns = new Set<string>()
  for (const { result } of perPlan) for (const u of result.unknowns) unknowns.add(u)
  for (const { plan } of perPlan) {
    for (const step of plan.steps) {
      if (versionDelta(graph.ecosystem, step.from, step.to) === 'major') {
        unknowns.add(`${step.name} 的升级跨越主版本（${step.from} → ${step.to}），可能存在破坏性变更，需要人工确认`)
      }
    }
  }

  return { perPlan, crossPlanConflicts, unknowns: [...unknowns] }
}

/** 供 UI：把步骤的依赖关系排序成“先升 X 才能升 Y”的顺序 */
export function orderSteps(plan: UpgradePlan): UpgradeStep[] {
  // 依赖者（父包）在后者：causedByParent 的步骤应先展示子包，再展示父包
  return [...plan.steps].sort((a, b) => Number(a.causedByParent) - Number(b.causedByParent))
}

export { checkRequirement }
