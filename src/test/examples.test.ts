import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import {
  EXAMPLE_NPM_LOCK,
  EXAMPLE_CARGO_LOCK,
  EXAMPLE_POETRY_LOCK,
  EXAMPLE_PYPROJECT,
  EXAMPLE_OSV,
} from '../ui/examples'
import { parseProject } from '../core/parsers'
import { analyzeProject } from '../core/analysis/analyze'
import { planAllUpgrades } from '../core/upgrade/planner'
import { parseOsvText } from '../core/osv/osv-schema'

describe('内置示例与 fixtures 保持一致', () => {
  it('npm 锁文件解析出的依赖图与 fixtures 一致（示例省略了 resolved 等元数据）', () => {
    const fromExample = parseProject([{ filename: 'package-lock.json', text: EXAMPLE_NPM_LOCK }]).projects[0]!.graph
    const fromFixture = parseProject([
      { filename: 'package-lock.json', text: readFileSync('fixtures/node/package-lock.json', 'utf8') },
    ]).projects[0]!.graph
    const summarize = (g: typeof fromExample) =>
      [...g.nodes.values()]
        .map((n) => `${n.name}@${n.version}|direct=${n.direct}|dev=${n.dev}|reqs=${n.requirements.map((r) => `${r.name}${r.spec ?? ''}`).join(',')}`)
        .sort()
    expect(summarize(fromExample)).toEqual(summarize(fromFixture))
    const edgeKey = (g: typeof fromExample) =>
      g.edges.map((e) => `${g.nodes.get(e.fromId)?.name}->${g.nodes.get(e.toId)?.name}@${g.nodes.get(e.toId)?.version}:${e.requirement.spec ?? ''}`).sort()
    expect(edgeKey(fromExample)).toEqual(edgeKey(fromFixture))
  })

  it('pyproject.toml 内容等价', () => {
    expect(EXAMPLE_PYPROJECT.trim()).toBe(readFileSync('fixtures/python/pyproject.toml', 'utf8').trim())
  })

  it('内置示例能跑通完整分析', () => {
    const osv = parseOsvText(EXAMPLE_OSV)
    expect(osv.issues.filter((i) => i.level === 'error')).toEqual([])
    const parsed = parseProject([{ filename: 'package-lock.json', text: EXAMPLE_NPM_LOCK }])
    const analysis = analyzeProject(parsed.projects[0]!.graph, osv)
    expect(analysis.findings.length).toBeGreaterThan(0)
    const report = planAllUpgrades(analysis)
    expect(report.plans.length).toBe(analysis.findings.length)
    void EXAMPLE_CARGO_LOCK
    void EXAMPLE_POETRY_LOCK
  })
})
