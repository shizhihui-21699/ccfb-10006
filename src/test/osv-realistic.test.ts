import { describe, expect, it } from 'vitest'
import { parseOsvText } from '../core/osv/osv-schema'
import { findMatches } from '../core/osv/osv-range'
import { cvssBaseScore, severityOf } from '../core/analysis/analyze'

// 形态参考 OSV schema 与 GHSA / OSV 官方导出文件的真实字段组合
const realistic = {
  id: 'GHSA-35jh-r3h4-6jhm',
  summary: 'Command Injection in lodash',
  details: 'Versions of lodash prior to 4.17.21 are vulnerable to Command Injection.',
  aliases: ['CVE-2021-23337'],
  modified: '2023-11-08T04:05:16.709939Z',
  published: '2022-02-01T00:00:31Z',
  database_specific: {
    cwe_ids: ['CWE-77'],
    severity: 'HIGH',
    github_reviewed: true,
    nvd_published_at: '2021-02-15T13:15:00Z',
  },
  references: [
    { type: 'ADVISORY', url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337' },
    { type: 'WEB', url: 'https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c' },
  ],
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }],
  affected: [
    {
      package: { ecosystem: 'npm', name: 'lodash', purl: 'pkg:npm/lodash' },
      ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
      database_specific: { source: 'https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2022/02/GHSA-35jh-r3h4-6jhm/GHSA-35jh-r3h4-6jhm.json' },
    },
    {
      // 真实数据里常见：同一漏洞在多个生态各有一条 affected
      package: { ecosystem: 'PyPI', name: 'lodash' },
      ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.0.0' }] }],
    },
    {
      // GIT 类型 range 应当被忽略而不是报错
      package: { ecosystem: 'npm', name: 'lodash-other' },
      ranges: [{ type: 'GIT', repo: 'https://github.com/lodash/lodash', events: [{ introduced: '0' }, { fixed: '3469357cff396a26c363f8c1b5a91dde28ba4b1c' }] }],
    },
  ],
}

describe('真实 OSV 记录形态', () => {
  const db = parseOsvText(JSON.stringify([realistic]))

  it('完整记录被接受', () => {
    expect(db.records).toHaveLength(1)
    expect(db.issues.filter((i) => i.level === 'error')).toEqual([])
    expect(db.ecosystems.sort()).toEqual(['PyPI', 'npm'])
  })

  it('lodash 4.17.20 命中，4.17.21 不命中', () => {
    expect(findMatches(db.records, 'npm', 'lodash', '4.17.20')).toHaveLength(1)
    expect(findMatches(db.records, 'npm', 'lodash', '4.17.21')).toHaveLength(0)
  })

  it('GIT range 不影响版本匹配（该包不会被误判）', () => {
    expect(findMatches(db.records, 'npm', 'lodash-other', '0.0.1')).toHaveLength(0)
  })

  it('PyPI 的 lodash 归一到自己的生态，不与 npm 混用', () => {
    expect(findMatches(db.records, 'PyPI', 'lodash', '0.5.0')).toHaveLength(1)
    expect(findMatches(db.records, 'PyPI', 'lodash', '1.0.0')).toHaveLength(0)
  })

  it('严重度优先用 CVSS 向量，缺失时回退 database_specific', () => {
    expect(severityOf(db.records[0]!)).toBe('high')
    expect(severityOf({ id: 'X', database_specific: { severity: 'MODERATE' } })).toBe('medium')
    expect(severityOf({ id: 'Y' })).toBe('unknown')
  })
})

describe('CVSS 分数计算', () => {
  const cases: [string, number][] = [
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', 7.2],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N', 8.7],
    ['CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L', 3.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5],
  ]
  for (const [vector, score] of cases) {
    it(`${vector} = ${score}`, () => {
      expect(cvssBaseScore(vector)).toBe(score)
    })
  }

  it('CVSS v4 不猜分数（返回 null，交给上层回退）', () => {
    expect(cvssBaseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')).toBeNull()
  })
})
