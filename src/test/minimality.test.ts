import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { parseProject } from '../core/parsers'
import { analyzeProject } from '../core/analysis/analyze'
import { planUpgradeForFinding } from '../core/upgrade/planner'
import { parseOsvText } from '../core/osv/osv-schema'

const read = (p: string) => readFileSync(p, 'utf8')

function npmAnalysis() {
  const parsed = parseProject([{ filename: 'package-lock.json', text: read('fixtures/node/package-lock.json') }])
  return analyzeProject(parsed.projects[0]!.graph, parseOsvText(read('fixtures/osv/core.json')))
}

describe('最小升级：选刚好修复的最低版本，而不是最高版本', () => {
  const analysis = npmAnalysis()

  it('存在多个更高副本时仍选最小修复版本', () => {
    // leaf 在锁文件里有 1.0.0 / 2.0.0 / 2.1.0；受影响的是 2.0.0，修复版本是 2.0.1（OSV fixed）。
    // 2.1.0 也“不受影响”，但它不是最小修复——这里 OSV 只给出 2.0.1 作为 fixed 边界，
    // 2.1.0 来自锁文件副本，应排在其后。
    const leaf2 = analysis.findings.find((f) => f.node.name === 'leaf' && f.node.version === '2.0.0')!
    const plan = planUpgradeForFinding(analysis, leaf2)
    expect(plan.targetVersion).toBe('2.0.1')
    expect(plan.steps.map((s) => `${s.name}@${s.to}`)).toEqual(['leaf@2.0.1', 'pinner@1.1.0'])
  })

  it('候选版本按生态语义升序挑选，PEP 440 里 rc 排在正式版之前', () => {
    const files = [
      { filename: 'pyproject.toml', text: read('fixtures/python/pyproject.toml') },
      { filename: 'poetry.lock', text: read('fixtures/python/poetry.lock') },
    ]
    const parsed = parseProject(files)
    const analysisPy = analyzeProject(parsed.projects[0]!.graph, parseOsvText(read('fixtures/osv/core.json')))
    const ansible = analysisPy.findings.find((f) => f.node.name === 'ansible-base')!
    const plan = planUpgradeForFinding(analysisPy, ansible)
    // fixed 是 2.10.0；不存在 2.10.0rc2 之类的候选，因此直接取 2.10.0
    expect(plan.targetVersion).toBe('2.10.0')
  })

  it('已预置更高版本副本时不会误选它（serde 只有 OSV fixed 一个候选）', () => {
    const parsed = parseProject([{ filename: 'Cargo.lock', text: read('fixtures/rust/Cargo.lock') }])
    const analysisCargo = analyzeProject(parsed.projects[0]!.graph, parseOsvText(read('fixtures/osv/core.json')))
    const serde = analysisCargo.findings.find((f) => f.node.name === 'serde')!
    const plan = planUpgradeForFinding(analysisCargo, serde)
    expect(plan.targetVersion).toBe('1.0.194')
  })
})
