import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { parsePackageLock } from '../core/parsers/npm-lock'
import { parsePoetryLock, parsePyprojectRoot } from '../core/parsers/poetry-lock'
import { parseCargoLock } from '../core/parsers/cargo-lock'
import { findPathsTo } from '../core/parsers/graph'

const npmLock3 = readFileSync('/tmp/lockgen/package-lock.json', 'utf8')

describe('npm 锁解析', () => {
  it('解析出节点、根依赖与边', () => {
    const g = parsePackageLock(npmLock3)
    expect(g.ecosystem).toBe('npm')
    expect(g.roots).toHaveLength(1)
    const names = [...g.nodes.values()].map((n) => n.name).sort()
    expect(names).toContain('ansi-regex')
    expect(names).toContain('left-pad')
    expect(names).toContain('is-odd')
    expect(names).toContain('is-number')
    const odd = [...g.nodes.values()].find((n) => n.name === 'is-odd')!
    expect(odd.version).toBe('3.0.1')
    expect(odd.dev).toBe(true)
    const paths = findPathsTo(g, odd.id)
    expect(paths.length).toBeGreaterThan(0)
    expect(paths[0]!.steps.map((s) => s.name)).toEqual(['demo-app', 'is-odd'])
  })
})

describe('poetry 锁解析', () => {
  const lock = readFileSync('/tmp/poetrygen/poetry.lock', 'utf8')
  const py = readFileSync('/tmp/poetrygen/pyproject.toml', 'utf8')
  it('用 pyproject 确定根依赖', () => {
    const root = parsePyprojectRoot(py)
    const g = parsePoetryLock(lock, 'poetry.lock', root)
    expect(g.ecosystem).toBe('PyPI')
    expect(g.roots[0]!.inferred).toBe(false)
    const urllib3 = [...g.nodes.values()].find((n) => n.name === 'urllib3')!
    expect(urllib3.version).toBe('2.0.7')
    const paths = findPathsTo(g, urllib3.id)
    expect(paths.some((p) => p.steps.map((s) => s.name).includes('requests'))).toBe(true)
    expect(paths.every((p) => p.steps.map((s) => s.name).includes('urllib3'))).toBe(true)
  })
})

describe('cargo 锁解析', () => {
  const lock = readFileSync('/tmp/cargogen/Cargo.lock', 'utf8')
  it('解析多版本 crate 与 workspace 根', () => {
    const g = parseCargoLock(lock)
    expect(g.ecosystem).toBe('crates.io')
    expect(g.requirementSpecsAvailable).toBe(false)
    const serde = [...g.nodes.values()].filter((n) => n.name === 'serde')
    expect(serde.length).toBeGreaterThanOrEqual(1)
    const time = [...g.nodes.values()].find((n) => n.name === 'time')!
    expect(time.version).toBe('0.3.36')
    const paths = findPathsTo(g, time.id)
    expect(paths.length).toBeGreaterThan(0)
    expect(paths[0]!.steps[0]!.name).toBe('demo-cli')
  })
})
