/**
 * 漏洞影响分析：把依赖图中的每个节点与 OSV 库对照。
 *
 * 输出刻意保留“为什么命中”的信息（区间边界、命中来源是 versions 列表还是 range），
 * 因为用户排查时最需要的是可复核的证据，而不是一个布尔结论。
 */

import type { DependencyGraph, NodePath, PackageNode } from '../parsers/graph'
import { findPathsTo } from '../parsers/graph'
import type { OsvDatabase, OsvRecord } from '../osv/osv-schema'
import type { OsvMatch } from '../osv/osv-range'
import { earliestFix, findMatches, nextFixAtOrAbove } from '../osv/osv-range'
import type { Ecosystem } from '../versions/ecosystem'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown'

export interface Finding {
  readonly node: PackageNode
  readonly matches: ReadonlyArray<OsvMatch>
  /** 指向该节点的依赖路径（按长度升序） */
  readonly paths: ReadonlyArray<NodePath>
  /** 最短路径长度（根=1 跳） */
  readonly shortestDepth: number
  readonly severity: Severity
  readonly isDirect: boolean
  readonly devOnly: boolean
}

export interface AnalysisIssue {
  readonly level: 'warning' | 'error'
  readonly message: string
  readonly packageName?: string
  readonly version?: string
}

export interface ProjectAnalysis {
  readonly ecosystem: Ecosystem
  readonly graph: DependencyGraph
  readonly findings: ReadonlyArray<Finding>
  readonly scannedCount: number
  readonly issues: ReadonlyArray<AnalysisIssue>
  /** 命中的漏洞 ID 去重后的集合 */
  readonly vulnerableIds: ReadonlyArray<string>
  /** 参与分析的漏洞库记录（升级候选的受影响性判定需要复用） */
  readonly records: ReadonlyArray<OsvRecord>
}

/**
 * 从 OSV 的 severity 字段推断等级。
 * CVSS 向量解析只取 base score 的粗略档位即可（这里用官方三段映射）。
 * 没有 severity 时回退到数据库级别的 severity，再回退 unknown。
 */
export function severityOf(record: OsvRecord): Severity {
  const vector = record.severity?.find((s) => s.type === 'CVSS_V3' || s.type === 'CVSS_V4')?.score
  if (vector) {
    const parsed = cvssBaseScore(vector)
    if (parsed !== null) {
      if (parsed >= 9) return 'critical'
      if (parsed >= 7) return 'high'
      if (parsed >= 4) return 'medium'
      if (parsed > 0) return 'low'
    }
  }
  if (vector && !vector.includes('CVSS')) {
    // 有些库直接写数字分数
    const n = Number(vector)
    if (Number.isFinite(n)) {
      if (n >= 9) return 'critical'
      if (n >= 7) return 'high'
      if (n >= 4) return 'medium'
      return 'low'
    }
  }
  const dbSeverity =
    (record.database_specific?.severity as string | undefined) ??
    (record.affected?.[0]?.ecosystem_specific?.severity as string | undefined)
  if (typeof dbSeverity === 'string') {
    const s = dbSeverity.toLowerCase()
    if (s === 'critical' || s === 'high' || s === 'moderate' || s === 'medium' || s === 'low') {
      return s === 'moderate' ? 'medium' : (s as Severity)
    }
  }
  return 'unknown'
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 }

export function severityRank(s: Severity): number {
  return SEVERITY_RANK[s]
}

/**
 * 计算 CVSS v3/v4 的 base score。
 * 公式来自 CVSS 规范；未知指标返回 null，不做猜测。
 */
export function cvssBaseScore(vector: string): number | null {
  if (!vector.includes('CVSS')) return null
  const metrics = new Map<string, string>()
  for (const part of vector.split('/')) {
    const [k, v] = part.split(':')
    if (k && v) metrics.set(k, v)
  }
  // v4 的评分公式复杂，这里只做保守近似：取已知指标数量判断是否高危
  if (vector.startsWith('CVSS:4.0')) return null

  const av = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[metrics.get('AV') ?? ''] ?? null
  const ac = { L: 0.77, H: 0.44 }[metrics.get('AC') ?? ''] ?? null
  const prRaw = { N: 0.85, L: 0.62, H: 0.27 }[metrics.get('PR') ?? ''] ?? null
  const ui = { N: 0.85, R: 0.62 }[metrics.get('UI') ?? ''] ?? null
  const c = { H: 0.56, L: 0.22, N: 0 }[metrics.get('C') ?? ''] ?? null
  const i = { H: 0.56, L: 0.22, N: 0 }[metrics.get('I') ?? ''] ?? null
  const a = { H: 0.56, L: 0.22, N: 0 }[metrics.get('A') ?? ''] ?? null
  if ([av, ac, prRaw, ui, c, i, a].some((x) => x === null)) return null

  const scope = metrics.get('S') === 'C' ? 'changed' : 'unchanged'
  const pr = scope === 'changed' ? ({ N: 0.85, L: 0.68, H: 0.5 }[metrics.get('PR') ?? ''] ?? prRaw) : prRaw

  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!)
  const impact =
    scope === 'changed' ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss
  const exploitability = 8.22 * av! * ac! * pr! * ui!

  if (impact <= 0) return 0
  const raw = scope === 'changed'
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10)
  // CVSS 规范要求向上取到一位小数
  return Math.ceil(raw * 10) / 10
}

/** 对单个项目执行分析 */
export function analyzeProject(
  graph: DependencyGraph,
  db: OsvDatabase,
  options: { includeDev?: boolean } = {},
): ProjectAnalysis {
  const findings: Finding[] = []
  const issues: AnalysisIssue[] = []
  const vulnerableIds = new Set<string>()
  let scannedCount = 0

  const records = db.records

  for (const node of graph.nodes.values()) {
    if (node.meta?.isRoot === true) continue
    scannedCount++

    if (options.includeDev === false && node.dev) continue

    let matches: OsvMatch[]
    try {
      matches = findMatches(records, graph.ecosystem, node.name, node.version)
    } catch (err) {
      issues.push({
        level: 'error',
        message: `匹配 ${node.name}@${node.version} 时出错：${(err as Error).message}`,
        packageName: node.name,
        version: node.version,
      })
      continue
    }

    if (matches.length === 0) continue

    for (const m of matches) vulnerableIds.add(m.record.id)

    const paths = findPathsTo(graph, node.id, { maxPaths: 20, maxDepth: 60 })
    if (paths.length === 0) {
      issues.push({
        level: 'warning',
        message: `${node.name}@${node.version} 命中了漏洞，但从根节点不可达（可能是 workspace 或孤立的 resolved 条目）`,
        packageName: node.name,
        version: node.version,
      })
    }

    const severity = matches.reduce<Severity>((acc, m) => {
      const s = severityOf(m.record)
      return severityRank(s) > severityRank(acc) ? s : acc
    }, 'unknown')

    findings.push({
      node,
      matches,
      paths,
      shortestDepth: paths.length ? paths[0]!.length - 1 : Number.POSITIVE_INFINITY,
      severity,
      isDirect: node.direct,
      devOnly: node.dev && !node.direct,
    })
  }

  // 数据质量：库中含本生态的记录数、以及无法对齐的包名
  if (db.issues.length > 0) {
    for (const issue of db.issues) {
      issues.push({ level: issue.level, message: `[${issue.source}] ${issue.message}` })
    }
  }

  findings.sort((a, b) => {
    const sev = severityRank(b.severity) - severityRank(a.severity)
    if (sev !== 0) return sev
    if (a.shortestDepth !== b.shortestDepth) return a.shortestDepth - b.shortestDepth
    return a.node.name.localeCompare(b.node.name)
  })

  return {
    ecosystem: graph.ecosystem,
    graph,
    findings,
    scannedCount,
    issues,
    vulnerableIds: [...vulnerableIds],
    records,
  }
}

/** UI 用：把命中原因写成一句话 */
export function describeMatch(match: OsvMatch): string {
  if (match.viaVersionsList) return '该版本被明确列入受影响版本清单'
  if (match.ranges.length === 0) return '在受影响范围内'
  const parts: string[] = []
  for (const hit of match.ranges) {
    const from = hit.interval.from
    const to = hit.interval.to
    const fromText = from === '0' || from === undefined ? '' : from
    if (fromText && to) {
      parts.push(`${fromText} ≤ v ${hit.interval.toInclusive ? '≤' : '<'} ${to}`)
    } else if (!fromText && to) {
      parts.push(`v ${hit.interval.toInclusive ? '≤' : '<'} ${to}`)
    } else if (fromText) {
      parts.push(`v ≥ ${fromText}`)
    } else {
      parts.push('该版本落在受影响区间')
    }
  }
  return parts.join('；') || '在受影响范围内'
}

/** 针对某命中记录，给出“升到多少能修复”的候选值 */
export function fixTargetsFor(ecosystem: Ecosystem, node: PackageNode, match: OsvMatch): string[] {
  const out: string[] = []
  const atOrAbove = nextFixAtOrAbove(ecosystem, match.affected, node.version)
  if (atOrAbove) out.push(atOrAbove)
  const earliest = earliestFix(ecosystem, match.affected)
  if (earliest && earliest !== atOrAbove) out.push(earliest)
  return out
}
