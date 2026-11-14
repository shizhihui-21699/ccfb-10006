import { describe, expect, it } from 'vitest'
import corpus from '/Users/shizhihui/ccfb/runs/10006/workspace/src/test/py-parity.json'
import { parsePyConstraint, pySatisfies } from '/Users/shizhihui/ccfb/runs/10006/workspace/src/core/versions/py-constraint'

describe('PEP440/poetry 对齐', () => {
  for (const entry of corpus as any[]) {
    if (entry.error !== undefined) {
      it(`拒绝 ${entry.constraint}`, () => {
        expect(parsePyConstraint(entry.constraint).error).toBeDefined()
      })
      continue
    }
    for (const [version, expected] of Object.entries(entry.results)) {
      it(`${entry.constraint} ∋ ${version} → ${expected}`, () => {
        const parsed = parsePyConstraint(entry.constraint)
        expect(parsed.error, parsed.error ?? '').toBeUndefined()
        expect(pySatisfies(version, parsed.constraint)).toBe(expected)
      })
    }
  }
})
