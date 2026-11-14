import { describe, expect, it } from 'vitest'
import corpus from './spec-parity.json'
import { parsePep440SpecifierSet } from '../core/versions/py-constraint'
import { tryParsePep440 } from '../core/versions/pep440'

describe('PEP 440 SpecifierSet 与 packaging 对齐（prereleases=true 语义）', () => {
  for (const entry of corpus as { spec: string; error?: string; results?: Record<string, boolean> }[]) {
    if (entry.error !== undefined) {
      it(`拒绝 ${JSON.stringify(entry.spec)}`, () => {
        expect(parsePep440SpecifierSet(entry.spec).error).toBeDefined()
      })
      continue
    }
    for (const [version, expected] of Object.entries(entry.results ?? {})) {
      it(`${JSON.stringify(entry.spec)} ∋ ${version} → ${expected}`, () => {
        const spec = parsePep440SpecifierSet(entry.spec)
        expect(spec.error).toBeUndefined()
        const v = tryParsePep440(version)!
        expect(spec.matches(v, true)).toBe(expected)
      })
    }
  }
})
