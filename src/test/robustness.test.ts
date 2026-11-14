import { describe, expect, it } from 'vitest'
import { parseOsvText, mergeOsvDatabases } from '../core/osv/osv-schema'
import { parsePackageLock } from '../core/parsers/npm-lock'
import { parsePoetryLock } from '../core/parsers/poetry-lock'
import { parseCargoLock } from '../core/parsers/cargo-lock'
import { findPathsTo } from '../core/parsers/graph'
import { parseProject, detectLockfileKind } from '../core/parsers'
import { analyzeProject } from '../core/analysis/analyze'
import { findMatches } from '../core/osv/osv-range'

describe('OSV 数据健壮性', () => {
  it('支持 JSON Lines（每行一条）', () => {
    const jsonl = [
      JSON.stringify({ id: 'A', affected: [{ package: { ecosystem: 'npm', name: 'x' }, versions: ['1.0.0'] }] }),
      JSON.stringify({ id: 'B', affected: [{ package: { ecosystem: 'npm', name: 'y' }, versions: ['2.0.0'] }] }),
    ].join('\n')
    const db = parseOsvText(jsonl)
    expect(db.records.map((r) => r.id)).toEqual(['A', 'B'])
    expect(db.issues.filter((i) => i.level === 'error')).toEqual([])
  })

  it('拒绝 events 中同时含两个键的条目，但保留同记录中合法的 range', () => {
    const db = parseOsvText(
      JSON.stringify({
        id: 'C',
        affected: [
          {
            package: { ecosystem: 'npm', name: 'z' },
            ranges: [
              { type: 'ECOSYSTEM', events: [{ introduced: '1.0.0', fixed: '2.0.0' }] },
              { type: 'ECOSYSTEM', events: [{ introduced: '3.0.0' }, { fixed: '4.0.0' }] },
            ],
          },
        ],
      }),
    )
    expect(db.records).toHaveLength(1)
    expect(db.records[0]!.affected![0]!.ranges).toHaveLength(1)
    expect(db.issues.some((i) => i.level === 'error' && i.message.includes('events'))).toBe(true)
  })

  it('缺少 introduced 的 range 被拒绝', () => {
    const db = parseOsvText(
      JSON.stringify({
        id: 'D',
        affected: [{ package: { ecosystem: 'npm', name: 'z' }, ranges: [{ type: 'ECOSYSTEM', events: [{ fixed: '1.0.0' }] }] }],
      }),
    )
    expect(db.records).toHaveLength(0)
    expect(db.issues.some((i) => i.level === 'error')).toBe(true)
  })

  it('fixed 与 last_affected 混用被拒绝', () => {
    const db = parseOsvText(
      JSON.stringify({
        id: 'E',
        affected: [
          {
            package: { ecosystem: 'npm', name: 'z' },
            ranges: [
              { type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.0.0' }, { last_affected: '1.5.0' }] },
            ],
          },
        ],
      }),
    )
    expect(db.records).toHaveLength(0)
  })

  it('完全非法的输入给出清晰错误而不是抛异常', () => {
    expect(() => parseOsvText('not json at all')).not.toThrow()
    const db = parseOsvText('not json at all')
    expect(db.records).toHaveLength(0)
    expect(db.issues[0]!.level).toBe('error')
  })

  it('同一 ID 的多份文件合并 affected', () => {
    const a = parseOsvText(
      JSON.stringify({ id: 'X', affected: [{ package: { ecosystem: 'npm', name: 'a' }, versions: ['1.0.0'] }] }),
    )
    const b = parseOsvText(
      JSON.stringify({ id: 'X', affected: [{ package: { ecosystem: 'npm', name: 'b' }, versions: ['2.0.0'] }] }),
    )
    const merged = mergeOsvDatabases([a, b])
    expect(merged.records).toHaveLength(1)
    expect(merged.records[0]!.affected).toHaveLength(2)
  })

  it('边界版本无法解析时跳过该 range 而非让整次分析崩溃', () => {
    const db = parseOsvText(
      JSON.stringify({
        id: 'F',
        affected: [
          {
            package: { ecosystem: 'npm', name: 'x' },
            ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: 'not-a-version' }, { fixed: '1.0.0' }] }],
          },
        ],
      }),
    )
    expect(() => findMatches(db.records, 'npm', 'x', '0.5.0')).not.toThrow()
    expect(findMatches(db.records, 'npm', 'x', '0.5.0')).toHaveLength(0)
  })
})

describe('npm v1 锁文件', () => {
  const v1 = JSON.stringify({
    name: 'legacy',
    version: '1.0.0',
    lockfileVersion: 1,
    requires: true,
    dependencies: {
      a: {
        version: '1.0.0',
        requires: { b: '^2.0.0' },
        dependencies: { b: { version: '2.0.0' } },
      },
      b: { version: '3.0.0' },
    },
  })

  it('解析嵌套树并保留父包约束', () => {
    const g = parsePackageLock(v1)
    const nodes = [...g.nodes.values()]
    const b2 = nodes.find((n) => n.name === 'b' && n.version === '2.0.0')
    const b3 = nodes.find((n) => n.name === 'b' && n.version === '3.0.0')
    expect(b2).toBeTruthy()
    expect(b3).toBeTruthy()
    const a = nodes.find((n) => n.name === 'a')!
    // a 的 b 应按 Node 解析命中嵌套副本
    expect(a.resolved.get('b')).toEqual([b2!.id])
    expect(g.issues.some((i) => i.message.includes('lockfileVersion 1'))).toBe(true)
  })
})

describe('Poetry 边界', () => {
  it('依赖对象数组形式与 markers 会产生提示但不丢边', () => {
    const lock = `
[[package]]
name = "a"
version = "1.0"
optional = false
python-versions = "*"
groups = ["main"]

[package.dependencies]
b = [{version = ">=1.0", markers = "python_version < '3.9'"}, {version = ">=2.0", markers = "python_version >= '3.9'"}]

[[package]]
name = "b"
version = "2.5"
optional = false
python-versions = "*"
groups = ["main"]

[metadata]
lock-version = "2.1"
`
    const g = parsePoetryLock(lock)
    const a = [...g.nodes.values()].find((n) => n.name === 'a')!
    expect(a.requirements).toHaveLength(1)
    expect(a.requirements[0]!.spec).toContain('||')
    expect(g.issues.some((i) => i.message.includes('环境标记'))).toBe(true)
  })

  it('同名包重复出现时只保留首个并告警', () => {
    const lock = `
[[package]]
name = "dup"
version = "1.0"
optional = false
python-versions = "*"
groups = ["main"]

[[package]]
name = "dup"
version = "2.0"
optional = false
python-versions = "*"
groups = ["main"]

[metadata]
lock-version = "2.1"
`
    const g = parsePoetryLock(lock)
    const dups = [...g.nodes.values()].filter((n) => n.name === 'dup')
    expect(dups).toHaveLength(1)
    expect(dups[0]!.version).toBe('1.0')
    expect(g.issues.some((i) => i.level === 'warning')).toBe(true)
  })
})

describe('Cargo 边界', () => {
  it('v1 锁文件里未标版本的依赖按最小版本归属并告警', () => {
    const lock = `
version = 1
[[package]]
name = "root"
version = "0.1.0"
dependencies = ["multi"]

[[package]]
name = "multi"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "a"

[[package]]
name = "multi"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "b"
`
    const g = parseCargoLock(lock)
    const root = g.roots[0]!
    const edge = g.edges.find((e) => e.fromId === root.id && e.requirement.name === 'multi')!
    expect(g.nodes.get(edge.toId)!.version).toBe('1.0.0')
    expect(g.issues.some((i) => i.message.includes('最小版本'))).toBe(true)
  })

  it('缺少本地包（无 source）时给出明确错误', () => {
    const lock = `
version = 4
[[package]]
name = "only-dep"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "a"
`
    const g = parseCargoLock(lock)
    expect(g.roots).toHaveLength(0)
    expect(g.issues.some((i) => i.level === 'error' && i.message.includes('本地包'))).toBe(true)
  })
})

describe('环路', () => {
  it('循环依赖不会让路径枚举无限递归', () => {
    const lock = JSON.stringify({
      name: 'cyc',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        '': { name: 'cyc', version: '1.0.0', dependencies: { a: '^1.0.0' } },
        'node_modules/a': { version: '1.0.0', dependencies: { b: '^1.0.0' } },
        'node_modules/b': { version: '1.0.0', dependencies: { a: '^1.0.0' } },
      },
    })
    const g = parsePackageLock(lock)
    const a = [...g.nodes.values()].find((n) => n.name === 'a')!
    // 目标是 a，从根直达即命中，因此不会走到环；关键是必须终止并给出有限路径。
    const paths = findPathsTo(g, a.id)
    expect(paths.length).toBeGreaterThan(0)
    expect(paths[0]!.steps.map((s) => s.name)).toEqual(['cyc', 'a'])
    expect(paths.length).toBeLessThan(50)
    // 目标为 b 时，a→b→a 的环会被检测到并标记
    const b = [...g.nodes.values()].find((n) => n.name === 'b')!
    const bPaths = findPathsTo(g, b.id)
    expect(bPaths.length).toBeGreaterThan(0)
    expect(bPaths.length).toBeLessThan(50)
  })
})

describe('文件类型识别', () => {
  it('按文件名与内容识别', () => {
    expect(detectLockfileKind('package-lock.json', '{}')).toBe('npm')
    expect(detectLockfileKind('poetry.lock', '')).toBe('poetry')
    expect(detectLockfileKind('Cargo.lock', '')).toBe('cargo')
    expect(detectLockfileKind('pyproject.toml', '')).toBe('pyproject')
    expect(detectLockfileKind('unknown.txt', 'hello')).toBe('unknown')
  })

  it('parseProject 对无法识别的文件给出错误但不崩', () => {
    const result = parseProject([{ filename: 'nope.txt', text: 'hello' }])
    expect(result.projects).toHaveLength(0)
    expect(result.issues[0]!.level).toBe('error')
  })

  it('没有 OSV 时仍解析锁文件（分析在 UI 层按需进行）', () => {
    const result = parseProject([{ filename: 'Cargo.lock', text: 'version = 4\n' }])
    expect(result.projects).toHaveLength(1)
    expect(result.projects[0]!.kind).toBe('cargo')
  })
})

describe('分析对空库/空图不崩', () => {
  it('空漏洞库', () => {
    const g = parseCargoLock('[metadata]\n') // 无 package
    const analysis = analyzeProject(g, { records: [], issues: [], ecosystems: [] })
    expect(analysis.findings).toEqual([])
  })
})
