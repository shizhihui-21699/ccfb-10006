/**
 * 应用状态与流程编排（与 DOM 解耦，便于测试）。
 */

import type { DependencyGraph } from '../core/parsers/graph'
import type { OsvDatabase, OsvParseIssue } from '../core/osv/osv-schema'
import { mergeOsvDatabases, parseOsvText } from '../core/osv/osv-schema'
import { parseProject } from '../core/parsers'
import { analyzeProject, type ProjectAnalysis } from '../core/analysis/analyze'
import { planAllUpgrades, type UpgradeReport } from '../core/upgrade/planner'
import { simulateAll, type CombinedSimulation } from '../core/upgrade/simulate'

export interface LoadedProject {
  readonly key: string
  readonly kind: string
  readonly graph: DependencyGraph
  readonly analysis: ProjectAnalysis
  readonly report: UpgradeReport
  readonly simulation: CombinedSimulation
}

export interface AppState {
  readonly osv: OsvDatabase | null
  readonly projects: ReadonlyArray<LoadedProject>
  readonly parseIssues: ReadonlyArray<{ source: string; level: 'error' | 'warning'; message: string }>
  readonly osvIssues: ReadonlyArray<OsvParseIssue>
  readonly activeProjectKey: string | null
  readonly files: ReadonlyArray<{ filename: string; size: number }>
}

export function emptyState(): AppState {
  return {
    osv: null,
    projects: [],
    parseIssues: [],
    osvIssues: [],
    activeProjectKey: null,
    files: [],
  }
}

export interface RawFile {
  readonly filename: string
  readonly text: string
}

/**
 * 构建状态：OSV 文件与锁文件可以一次性全部导入。
 * 多个 OSV 文件会被合并（同一漏洞 ID 的 affected 合并）；多个锁文件各自成为独立工程。
 */
export function buildState(files: ReadonlyArray<RawFile>): AppState {
  const osvFiles = files.filter((f) => isOsvFile(f))
  const lockFiles = files.filter((f) => !isOsvFile(f))

  let osv: OsvDatabase | null = null
  if (osvFiles.length > 0) {
    osv = mergeOsvDatabases(osvFiles.map((f) => parseOsvText(f.text, f.filename)))
  }

  const { projects: parsedProjects, issues } = parseProject(lockFiles)

  const projects: LoadedProject[] = []
  if (osv) {
    for (const project of parsedProjects) {
      const analysis = analyzeProject(project.graph, osv)
      const report = planAllUpgrades(analysis)
      const simulation = simulateAll(project.graph, report.plans)
      projects.push({
        key: project.graph.sourceLabel,
        kind: project.kind,
        graph: project.graph,
        analysis,
        report,
        simulation,
      })
    }
  }

  return {
    osv,
    projects,
    parseIssues: issues,
    osvIssues: osv?.issues ?? [],
    activeProjectKey: projects[0]?.key ?? null,
    files: files.map((f) => ({ filename: f.filename, size: f.text.length })),
  }
}

function isOsvFile(file: RawFile): boolean {
  const name = file.filename.toLowerCase()
  if (name.endsWith('package-lock.json') || name.endsWith('poetry.lock') || name.endsWith('cargo.lock') || name.endsWith('pyproject.toml')) {
    return false
  }
  const trimmed = file.text.trim()
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    // 含 lockfileVersion / packages 的是 npm 锁文件
    if (trimmed.includes('"lockfileVersion"')) return false
    // TOML 不会以 { 或 [ 开头（除 [[package]]，但那不匹配 {）
    return true
  }
  // JSONL：每行都是 JSON 对象且含 "id" 与 "affected"
  const firstLine = trimmed.split('\n')[0] ?? ''
  return firstLine.trim().startsWith('{') && trimmed.includes('"affected"')
}

/** 汇总所有工程的合计（给顶部统计用） */
export function totals(projects: ReadonlyArray<LoadedProject>): {
  findings: number
  bySeverity: Record<string, number>
  packages: number
  fixable: number
} {
  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }
  let findings = 0
  let packages = 0
  let fixable = 0
  for (const p of projects) {
    findings += p.analysis.findings.length
    packages += p.analysis.scannedCount
    fixable += p.report.summary.fixable
    for (const f of p.analysis.findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1
  }
  return { findings, bySeverity, packages, fixable }
}
