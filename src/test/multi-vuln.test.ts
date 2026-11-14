import { describe, expect, it } from 'vitest'
import { parsePackageLock } from '../core/parsers/npm-lock'
import { analyzeProject } from '../core/analysis/analyze'
import { planUpgradeForFinding } from '../core/upgrade/planner'
import { parseOsvText } from '../core/osv/osv-schema'

const lock = JSON.stringify({
  name: 'app',
  version: '1.0.0',
  lockfileVersion: 3,
  packages: {
    '': { name: 'app', version: '1.0.0', dependencies: { multi: '^1.0.0' } },
    'node_modules/multi': { version: '1.0.0' },
    'node_modules/multi2': { version: '1.0.0' },
  },
})

const osv = parseOsvText(
  JSON.stringify([
    {
      id: 'VULN-A',
      affected: [
        {
          package: { ecosystem: 'npm', name: 'multi' },
          ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.2.0' }] }],
        },
      ],
    },
    {
      // 第二个漏洞：1.0.0 ~ 1.4.x 都受影响；只有 >= 1.5.0 才干净
      id: 'VULN-B',
      affected: [
        {
          package: { ecosystem: 'npm', name: 'multi' },
          ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.5.0' }] }],
        },
      ],
    },
  ]),
)

describe('同一包被多个漏洞覆盖时，候选版本必须查整库', () => {
  const graph = parsePackageLock(lock)
  const analysis = analyzeProject(graph, osv)

  it('该包同时命中两条记录', () => {
    const f = analysis.findings.find((x) => x.node.name === 'multi')!
    expect(f.matches.map((m) => m.record.id).sort()).toEqual(['VULN-A', 'VULN-B'])
  })

  it('候选 1.2.0 修好了 A 但没修好 B，因此不能被推荐为最终目标', () => {
    const f = analysis.findings.find((x) => x.node.name === 'multi')!
    const plan = planUpgradeForFinding(analysis, f)
    // 两个 fixed 里最小且不受任何记录影响的是 1.5.0；1.2.0 仍命中 VULN-B
    expect(plan.targetVersion).toBe('1.5.0')
  })

  it('若库中只有 A，同一候选仍会选 1.2.0（说明差异确实来自整库检查）', () => {
    const onlyA = parseOsvText(
      JSON.stringify([
        {
          id: 'VULN-A',
          affected: [
            {
              package: { ecosystem: 'npm', name: 'multi' },
              ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.2.0' }] }],
            },
          ],
        },
      ]),
    )
    const analysisA = analyzeProject(parsePackageLock(lock), onlyA)
    const f = analysisA.findings.find((x) => x.node.name === 'multi')!
    expect(planUpgradeForFinding(analysisA, f).targetVersion).toBe('1.2.0')
  })
})
