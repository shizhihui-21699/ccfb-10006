import { describe, expect, it } from 'vitest'
import { rangeAffectsVersion, findMatches } from '../core/osv/osv-range'
import type { OsvRange, OsvRecord } from '../core/osv/osv-schema'

const r = (events: OsvRange['events'], type: OsvRange['type'] = 'ECOSYSTEM'): OsvRange => ({ type, events })

describe('OSV 事件流求值', () => {
  it('introduced/fixed 是 左闭右开', () => {
    const range = r([{ introduced: '1.2.3' }, { fixed: '1.3.0' }])
    expect(rangeAffectsVersion('npm', range, '1.2.2').affected).toBe(false)
    expect(rangeAffectsVersion('npm', range, '1.2.3').affected).toBe(true)
    expect(rangeAffectsVersion('npm', range, '1.2.9').affected).toBe(true)
    expect(rangeAffectsVersion('npm', range, '1.3.0').affected).toBe(false)
    expect(rangeAffectsVersion('npm', range, '1.3.1').affected).toBe(false)
  })

  it('last_affected 是闭区间', () => {
    const range = r([{ introduced: '1.0.0' }, { last_affected: '1.2.3' }])
    expect(rangeAffectsVersion('npm', range, '1.2.3').affected).toBe(true)
    expect(rangeAffectsVersion('npm', range, '1.2.4').affected).toBe(false)
  })

  it('introduced: 0 表示低于一切版本', () => {
    const range = r([{ introduced: '0' }, { fixed: '1.0.0' }])
    expect(rangeAffectsVersion('npm', range, '0.0.0').affected).toBe(true)
    expect(rangeAffectsVersion('npm', range, '0.9.9').affected).toBe(true)
    expect(rangeAffectsVersion('npm', range, '1.0.0').affected).toBe(false)
  })

  it('多个 introduced/fixed 交替形成多段区间', () => {
    const range = r([
      { introduced: '1.0.0' },
      { fixed: '1.1.0' },
      { introduced: '1.2.0' },
      { fixed: '1.3.0' },
    ])
    expect(rangeAffectsVersion('npm', range, '1.0.5').affected).toBe(true)
    expect(rangeAffectsVersion('npm', range, '1.1.0').affected).toBe(false)
    expect(rangeAffectsVersion('npm', range, '1.1.5').affected).toBe(false)
    expect(rangeAffectsVersion('npm', range, '1.2.5').affected).toBe(true)
    expect(rangeAffectsVersion('npm', range, '1.3.0').affected).toBe(false)
  })

  it('limit 限制评估范围但不改变受影响状态', () => {
    const range = r([{ introduced: '1.0.0' }, { limit: '2.0.0' }])
    expect(rangeAffectsVersion('npm', range, '1.5.0').affected).toBe(true)
    expect(rangeAffectsVersion('npm', range, '2.0.0').affected).toBe(false)
    expect(rangeAffectsVersion('npm', range, '2.5.0').affected).toBe(false)
  })

  it('预发布按生态排序参与：1.2.3-rc.1 < 1.2.3', () => {
    const range = r([{ introduced: '0' }, { fixed: '1.2.3' }])
    expect(rangeAffectsVersion('npm', range, '1.2.3-rc.1').affected).toBe(true)
    expect(rangeAffectsVersion('npm', range, '1.2.3').affected).toBe(false)
  })

  it('PEP 440：1.2.3rc1 < 1.2.3，且 dev 更低', () => {
    const range = r([{ introduced: '1.2.3' }, { fixed: '1.2.4' }])
    expect(rangeAffectsVersion('PyPI', range, '1.2.3rc1').affected).toBe(false)
    expect(rangeAffectsVersion('PyPI', range, '1.2.3').affected).toBe(true)
    const range2 = r([{ introduced: '0' }, { fixed: '1.2.3' }])
    expect(rangeAffectsVersion('PyPI', range2, '1.2.3rc1').affected).toBe(true)
    expect(rangeAffectsVersion('PyPI', range2, '1.2.3.dev1').affected).toBe(true)
    expect(rangeAffectsVersion('PyPI', range2, '1.2.2.post1').affected).toBe(true)
  })

  it('SEMVER 类型与 ECOSYSTEM 类型对同一 npm 版本结果一致', () => {
    for (const type of ['SEMVER', 'ECOSYSTEM'] as const) {
      const range = r([{ introduced: '1.0.0' }, { fixed: '1.0.1' }], type)
      expect(rangeAffectsVersion('npm', range, '1.0.0').affected).toBe(true)
      expect(rangeAffectsVersion('npm', range, '1.0.1').affected).toBe(false)
    }
  })

  it('versions 列表是精确相等（含 SemVer build metadata 等价）', () => {
    const record: OsvRecord = {
      id: 'X',
      affected: [{ package: { ecosystem: 'npm', name: 'pkg' }, versions: ['1.0.0'] }],
    }
    expect(findMatches([record], 'npm', 'pkg', '1.0.0+build').length).toBe(1)
    expect(findMatches([record], 'npm', 'pkg', '1.0.1').length).toBe(0)
  })

  it('已撤回的记录不参与匹配', () => {
    const record: OsvRecord = {
      id: 'X',
      withdrawn: '2024-01-01T00:00:00Z',
      affected: [{ package: { ecosystem: 'npm', name: 'pkg' }, ranges: [r([{ introduced: '0' }])] }],
    }
    expect(findMatches([record], 'npm', 'pkg', '1.0.0').length).toBe(0)
  })
})
