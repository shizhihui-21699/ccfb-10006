import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { parseProject } from '../core/parsers'
import { analyzeProject, describeMatch } from '../core/analysis/analyze'
import { planAllUpgrades, planUpgradeForFinding } from '../core/upgrade/planner'
import { parseOsvText } from '../core/osv/osv-schema'

const read = (p: string) => readFileSync(p, 'utf8')

const osv = parseOsvText(read('fixtures/osv/core.json'), 'core.json')
const nodeFiles = [
  { filename: 'node/package-lock.json', text: read('fixtures/node/package-lock.json') },
]
const rustFiles = [{ filename: 'rust/Cargo.lock', text: read('fixtures/rust/Cargo.lock') }]

function analyze(files: { filename: string; text: string }[]) {
  const parsed = parseProject(files)
  expect(parsed.projects).toHaveLength(1)
  return analyzeProject(parsed.projects[0]!.graph, osv)
}

describe('OSV 库自身健康度', () => {
  it('能解析全部记录且无错误', () => {
    expect(osv.records.length).toBeGreaterThan(10)
    expect(osv.issues.filter((i) => i.level === 'error')).toEqual([])
    expect(osv.ecosystems).toEqual(expect.arrayContaining(['npm', 'PyPI', 'crates.io']))
  })
})

describe('npm 端到端', () => {
  const analysis = analyze(nodeFiles)

  it('依赖树与安装路径解析正确', () => {
    const names = [...analysis.graph.nodes.values()].map((n) => `${n.name}@${n.version}`)
    expect(names).toContain('ansi-regex@5.0.1')
    expect(names).toContain('ansi-regex@6.0.1')
    expect(names).toContain('pre-core@1.2.3-beta.4')
    expect(names).toContain('pre-core@1.2.3-beta.10')
  })

  it('预发布边界：beta.4 受影响而 beta.10 不受影响', () => {
    const hits = analysis.findings.filter((f) => f.node.name === 'pre-core')
    expect(hits).toHaveLength(1)
    expect(hits[0]!.node.version).toBe('1.2.3-beta.4')
    expect(hits[0]!.matches[0]!.record.id).toBe('GHSA-TEST-NPM-PRECORE')
  })

  it('fixed 恰好等于当前版本时不报（ansi-regex 5.0.1 / 6.0.1）', () => {
    expect(analysis.findings.some((f) => f.node.name === 'ansi-regex')).toBe(false)
  })

  it('affected.versions 精确清单命中 serde 之外的 npm 记录为零', () => {
    expect(analysis.findings.some((f) => f.node.name === 'pinner')).toBe(false)
  })

  it('漏洞路径可回溯到根，且最短路径正确', () => {
    const leafFinding = analysis.findings.find((f) => f.node.name === 'stuck')!
    expect(leafFinding.paths[0]!.steps.map((s) => s.name)).toEqual(['edge-market', 'blocker', 'stuck'])
    const preCoreFinding = analysis.findings.find((f) => f.node.name === 'pre-core')!
    expect(preCoreFinding.paths[0]!.steps.map((s) => s.name)).toEqual(['edge-market', 'pre-core'])
    const nestedLeaf = analysis.findings.find((f) => f.node.name === 'leaf' && f.node.version === '2.0.0')
    expect(nestedLeaf!.paths[0]!.steps.map((s) => s.name)).toEqual(['edge-market', 'pinner', 'leaf'])
  })

  it('0.x 的 caret 边界：zero 0.2.3 可升到 0.2.4，tiny 只能放宽约束', () => {
    const zero = analysis.findings.find((f) => f.node.name === 'zero')!
    const zeroPlan = planUpgradeForFinding(analysis, zero)
    expect(zeroPlan.feasible).toBe(true)
    expect(zeroPlan.targetVersion).toBe('0.2.4')
    expect(zeroPlan.steps[0]!.delta).toBe('patch')

    const tiny = analysis.findings.find((f) => f.node.name === 'tiny')!
    const tinyPlan = planUpgradeForFinding(analysis, tiny)
    expect(tinyPlan.targetVersion).toBe('0.0.4')
    // 根清单 ^0.0.3 不接受 0.0.4 → 必须放宽声明
    const rootCheck = tinyPlan.steps[0]!.checks.find((c) => c.dependentLabel.includes('根'))
    expect(rootCheck?.ok).toBe(false)
  })

  it('父包精确 pin 场景：leaf 需要连带升级 pinner 与 other-tool', () => {
    const leaf2 = analysis.findings.find((f) => f.node.name === 'leaf' && f.node.version === '2.0.0')!
    const plan = planUpgradeForFinding(analysis, leaf2)
    expect(plan.strategy).toBe('bump-parent')
    expect(plan.steps.map((s) => s.name)).toEqual(['leaf', 'pinner'])
    expect(plan.steps[0]!.causedByParent).toBe(true)
    expect(plan.feasible).toBe(true)
  })

  it('无解场景：stuck 被 blocker 精确锁死，且无更高 blocker', () => {
    const stuck = analysis.findings.find((f) => f.node.name === 'stuck')!
    const plan = planUpgradeForFinding(analysis, stuck)
    expect(plan.feasible).toBe(false)
    expect(plan.strategy).toBe('no-feasible-version')
    expect(plan.vulnerabilitiesRemaining).toContain('GHSA-TEST-NPM-STUCK')
  })

  it('dev 依赖被标注，可在报告中过滤', () => {
    const isOdd = analysis.findings.find((f) => f.node.name === 'is-odd')
    expect(isOdd?.devOnly).toBe(true)
  })

  it('汇总报告统计正确', () => {
    const report = planAllUpgrades(analysis)
    expect(report.plans.length).toBe(analysis.findings.length)
    expect(report.summary.fixable).toBeGreaterThan(0)
    expect(report.summary.unfixable).toBeGreaterThan(0)
  })

  it('命中原因可读', () => {
    const f = analysis.findings.find((x) => x.node.name === 'zero')!
    expect(describeMatch(f.matches[0]!)).toContain('0.2.3')
  })
})

describe('Cargo 端到端', () => {
  const analysis = analyze(rustFiles)

  it('含预发布边界的 crate 命中，正式版不命中', () => {
    const hits = analysis.findings.filter((f) => f.node.name === 'powerfmt')
    expect(hits).toHaveLength(1)
    expect(hits[0]!.node.version).toBe('0.2.0-rc.2')
  })

  it('多版本 crate 中只有受影响的那个命中', () => {
    const syn = analysis.findings.filter((f) => f.node.name === 'syn')
    expect(syn).toHaveLength(1)
    expect(syn[0]!.node.version).toBe('1.0.109')
    expect(syn[0]!.paths.length).toBeGreaterThan(0)
    expect(syn[0]!.paths[0]!.steps[0]!.name).toBe('edge-service')
  })

  it('Cargo.lock 无区间：升级计划显式标注未知，不假装验证过', () => {
    const time = analysis.findings.find((f) => f.node.name === 'time')!
    const plan = planUpgradeForFinding(analysis, time)
    expect(plan.targetVersion).toBe('0.3.37')
    for (const check of plan.steps[0]!.checks) {
      expect(check.ok).toBeNull()
      expect(check.reason).toContain('Cargo.lock')
    }
    expect(plan.unknowns.join('')).toContain('Cargo.lock 不记录依赖声明区间')
  })

  it('affected.versions 精确清单路径（SemVer build/等值）', () => {
    const serde = analysis.findings.find((f) => f.node.name === 'serde')!
    const viaList = serde.matches.some((m) => m.viaVersionsList)
    expect(viaList).toBe(true)
  })
})

describe('Python 端到端', () => {
  const files = [
    { filename: 'python/pyproject.toml', text: read('fixtures/python/pyproject.toml') },
    { filename: 'python/poetry.lock', text: read('fixtures/python/poetry.lock') },
  ]
  const analysis = analyze(files)

  it('边界：urllib3 1.26.4 落在 [1.26.0, 1.26.5)', () => {
    const f = analysis.findings.find((x) => x.node.name === 'urllib3')!
    expect(f.node.version).toBe('1.26.4')
    expect(f.matches[0]!.record.id).toBe('PYSEC-TEST-URLLIB3')
  })

  it('last_affected 闭区间：5.4.1 本身受影响，且拿不到 fixed 版本', () => {
    const f = analysis.findings.find((x) => x.node.name === 'pyyaml')!
    const plan = planUpgradeForFinding(analysis, f)
    expect(plan.targetVersion).toBeNull()
    expect(plan.strategy).toBe('no-fix-version')
  })

  it('预发布版本落在区间内：2.10.0rc1 受影响，且 2.10.0 满足 ~=2.10.0rc1', () => {
    const f = analysis.findings.find((x) => x.node.name === 'ansible-base')!
    expect(f.node.version).toBe('2.10.0rc1')
    const plan = planUpgradeForFinding(analysis, f)
    expect(plan.targetVersion).toBe('2.10.0')
    const rootCheck = plan.steps[0]!.checks.find((c) => c.dependentLabel.includes('根'))
    expect(rootCheck?.ok).toBe(true)
  })

  it('local 版本段参与排序：3.0.1+local 在 [3.0, 3.1) 内', () => {
    const f = analysis.findings.find((x) => x.node.name === 'idna')
    expect(f?.node.version).toBe('3.0.1+local')
  })

  it('已修复的包不误报（charset-normalizer / certifi）', () => {
    expect(analysis.findings.some((x) => x.node.name === 'certifi')).toBe(false)
    expect(analysis.findings.some((x) => x.node.name === 'charset-normalizer')).toBe(false)
  })

  it('pyproject 的根依赖被识别为直接依赖', () => {
    const requests = [...analysis.graph.nodes.values()].find((n) => n.name === 'requests')!
    expect(requests.direct).toBe(true)
  })
})
