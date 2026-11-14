import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { parseProject } from '../core/parsers'
import { analyzeProject } from '../core/analysis/analyze'
import { planUpgradeForFinding } from '../core/upgrade/planner'
import { simulatePlan, simulateAll } from '../core/upgrade/simulate'
import { parseOsvText } from '../core/osv/osv-schema'

const read = (p: string) => readFileSync(p, 'utf8')
const osv = parseOsvText(read('fixtures/osv/core.json'))

function setup() {
  const parsed = parseProject([{ filename: 'package-lock.json', text: read('fixtures/node/package-lock.json') }])
  return analyzeProject(parsed.projects[0]!.graph, osv)
}

describe('升级影响模拟', () => {
  const analysis = setup()
  const leaf2 = analysis.findings.find((f) => f.node.name === 'leaf' && f.node.version === '2.0.0')!

  it('父包方案模拟后无破坏（pinner 新版本依赖已知）', () => {
    const plan = planUpgradeForFinding(analysis, leaf2)
    const sim = simulatePlan(analysis.graph, plan)
    // pinner 的 1.1.0 版本在锁文件里已存在，其间依赖可复用
    expect(sim.brokenRequirements).toEqual([])
  })

  it('放宽根约束的方案会给出“需改根清单”的说明', () => {
    const tiny = analysis.findings.find((f) => f.node.name === 'tiny')!
    const plan = planUpgradeForFinding(analysis, tiny)
    expect(plan.strategy).toBe('relax-root-constraint')
    const sim = simulatePlan(analysis.graph, plan)
    // target 0.0.4 不在锁文件中，其依赖未知
    expect(sim.unknowns.join('')).toContain('不在当前锁文件中')
  })

  it('整体模拟能发现跨方案的目标版本冲突', () => {
    // 人为构造两个计划指向同一包的不同版本
    const plans = [
      { ...planUpgradeForFinding(analysis, analysis.findings.find((f) => f.node.name === 'middle')!), targetVersion: '1.1.0', packageName: 'middle', feasible: true },
      { ...planUpgradeForFinding(analysis, analysis.findings.find((f) => f.node.name === 'middle')!), targetVersion: '1.2.0', packageName: 'middle', feasible: true },
    ]
    const combined = simulateAll(analysis.graph, plans)
    expect(combined.crossPlanConflicts.length).toBe(1)
    expect(combined.crossPlanConflicts[0]).toContain('middle')
  })
})
