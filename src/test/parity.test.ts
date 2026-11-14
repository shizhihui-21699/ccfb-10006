import { describe, expect, it } from 'vitest'
import npmCases from './npm-parity.json'
import cargoCases from './cargo-parity.json'
import { npmSatisfies } from '../core/versions/npm-range'
import { cargoSatisfies } from '../core/versions/cargo-req'

// 这些用例的期望值全部由官方实现实测得到（node-semver 7.8 / Rust semver crate 1.0.28），
// 不是手写猜测，用于锁定复刻的准确性。
describe('npm 区间语义与 node-semver 对齐', () => {
  for (const [version, range, expected] of npmCases as [string, string, boolean][]) {
    it(`${version} 满足 ${JSON.stringify(range)} → ${expected}`, () => {
      expect(npmSatisfies(version, range)).toBe(expected)
    })
  }
})

describe('Cargo 区间语义与 semver crate 对齐', () => {
  for (const [version, range, expected] of cargoCases as [string, string, boolean][]) {
    it(`${version} 满足 ${JSON.stringify(range)} → ${expected}`, () => {
      expect(cargoSatisfies(version, range)).toBe(expected)
    })
  }
})
