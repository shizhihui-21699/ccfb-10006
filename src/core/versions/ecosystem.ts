/**
 * 版本比较的生态适配层。
 *
 * OSV 的 range 有两种类型：
 * - SEMVER：按 SemVer 2.0.0 §11 的优先级比较（注意：这里比的是“版本先后”，
 *   不是 npm 区间表达式；OSV 的边界是事件流，见 osv-range.ts）。
 * - ECOSYSTEM：按各生态自己的版本规则比较。npm/crates.io 均为 SemVer 语义，
 *   PyPI 为 PEP 440。
 *
 * 预发布在两类里都参与比较：`1.2.3-rc.1 < 1.2.3`，因此 [0, 1.2.3) 会命中 rc 版本；
 * 这与“npm 区间表达式默认排除预发布”是两套不同规则，不能混用。
 */

import { compareSemVer, tryParseSemVer, formatSemVer, type SemVer } from './semver-core'
import { comparePep440, formatPep440, normalizePypiName, tryParsePep440, type Pep440Version } from './pep440'

export type Ecosystem = 'npm' | 'PyPI' | 'crates.io'

export const ECOSYSTEM_LABEL: Record<Ecosystem, string> = {
  npm: 'npm',
  PyPI: 'PyPI',
  'crates.io': 'crates.io',
}

export class UncomparableVersion extends Error {
  constructor(ecosystem: Ecosystem, text: string) {
    super(`${ecosystem} 无法比较版本 ${JSON.stringify(text)}`)
    this.name = 'UncomparableVersion'
  }
}

/** 生态内项目名归一化，用于和 OSV 记录对齐 */
export function normalizePackageName(ecosystem: Ecosystem, name: string): string {
  if (ecosystem === 'PyPI') return normalizePypiName(name)
  return name.trim().toLowerCase()
}

export type ParsedVersion =
  | { kind: 'semver'; value: SemVer }
  | { kind: 'pep440'; value: Pep440Version }

export function parseEcosystemVersion(ecosystem: Ecosystem, text: string): ParsedVersion {
  if (ecosystem === 'PyPI') {
    const v = tryParsePep440(text)
    if (!v) throw new UncomparableVersion(ecosystem, text)
    return { kind: 'pep440', value: v }
  }
  const v = tryParseSemVer(text)
  if (!v) throw new UncomparableVersion(ecosystem, text)
  return { kind: 'semver', value: v }
}

export function tryParseEcosystemVersion(ecosystem: Ecosystem, text: string): ParsedVersion | null {
  try {
    return parseEcosystemVersion(ecosystem, text)
  } catch {
    return null
  }
}

export function compareParsedVersions(a: ParsedVersion, b: ParsedVersion): number {
  if (a.kind === 'semver' && b.kind === 'semver') return compareSemVer(a.value, b.value)
  if (a.kind === 'pep440' && b.kind === 'pep440') return comparePep440(a.value, b.value)
  throw new Error('不能比较不同生态体系的版本对象')
}

/**
 * range 类型为 SEMVER 时按 SemVer 优先级比较；ECOSYSTEM 时按生态规则。
 * 对 PyPI，SEMVER 类型不常见，若版本不是合法 SemVer 则回落到 PEP 440。
 */
export function parseBoundary(
  ecosystem: Ecosystem,
  rangeType: 'SEMVER' | 'ECOSYSTEM',
  text: string,
): ParsedVersion {
  if (rangeType === 'ECOSYSTEM') return parseEcosystemVersion(ecosystem, text)
  if (ecosystem === 'PyPI') {
    const pep = tryParsePep440(text)
    if (pep) return { kind: 'pep440', value: pep }
  }
  const v = tryParseSemVer(text)
  if (!v) throw new UncomparableVersion(ecosystem, text)
  return { kind: 'semver', value: v }
}
