/**
 * SemVer 2.0.0 内核：解析与优先级比较。
 *
 * 说明：
 * - 这里只实现“版本”本身（SemVer §11 的优先级规则），不涉及区间语义。
 * - npm 的区间语义见 npm-range.ts，Cargo 的见 cargo-req.ts，两者规则差异很大，
 *   因此刻意不共用区间解析器。
 * - 数字型预发布标识符 > 10 时按数值比较（beta.10 > beta.2），字符串型按 ASCII
 *   字典序比较，这是 SemVer 规范的要求，也是 npm 与 Cargo 共同的部分。
 */

export interface SemVer {
  readonly major: number
  readonly minor: number
  readonly patch: number
  /** 数字标识符以 number 保存，字符串标识符以 string 保存 */
  readonly prerelease: ReadonlyArray<string | number>
  readonly build: ReadonlyArray<string>
  readonly raw: string
}

export class VersionParseError extends Error {
  readonly input: string
  constructor(input: string, message: string) {
    super(message)
    this.name = 'VersionParseError'
    this.input = input
  }
}

const NUM = '0|[1-9]\\d*'
const NONNUM = '\\d*[a-zA-Z-][a-zA-Z0-9-]*'
const PRE_ID = `(?:${NONNUM}|${NUM})`
const PRE = `(?:-(${PRE_ID}(?:\\.${PRE_ID})*))`
const BUILD = `(?:\\+([a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*))`

/** 严格 SemVer：三段数字、不允许前导零、可选 v 前缀 */
const STRICT = new RegExp(
  `^v?(${NUM})\\.(${NUM})\\.(${NUM})${PRE}?${BUILD}?$`,
)
/** Cargo 接受的版本：不允许 v 前缀（cargo 的 Version::parse 会拒绝 v1.2.3） */
const STRICT_NO_V = new RegExp(
  `^(${NUM})\\.(${NUM})\\.(${NUM})${PRE}?${BUILD}?$`,
)

function splitIdentifiers(raw: string | undefined, numeric: boolean): (string | number)[] {
  if (raw === undefined) return []
  return raw.split('.').map((part) =>
    numeric && /^\d+$/.test(part) ? Number(part) : part,
  )
}

/** 解析严格 SemVer。allowV=false 时拒绝 `v` 前缀（Cargo 行为）。 */
export function parseSemVer(input: string, allowV = true): SemVer {
  const text = input.trim()
  const re = allowV ? STRICT : STRICT_NO_V
  const m = re.exec(text)
  if (!m) {
    throw new VersionParseError(input, `不是合法的 SemVer 版本: ${JSON.stringify(input)}`)
  }
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    prerelease: splitIdentifiers(m[4], true),
    build: m[5] ? m[5].split('.') : [],
    raw: text,
  }
}

export function tryParseSemVer(input: string, allowV = true): SemVer | null {
  try {
    return parseSemVer(input, allowV)
  } catch {
    return null
  }
}

function compareIdentifiers(a: string | number, b: string | number): number {
  const aNum = typeof a === 'number'
  const bNum = typeof b === 'number'
  if (aNum && bNum) return a === b ? 0 : a < b ? -1 : 1
  if (aNum) return -1 // 数字标识符优先级低于字母数字标识符
  if (bNum) return 1
  return a === b ? 0 : a < b ? -1 : 1
}

/** SemVer §11 优先级比较；build metadata 不参与比较。 */
export function compareSemVer(a: SemVer, b: SemVer): number {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1

  const ap = a.prerelease
  const bp = b.prerelease
  if (ap.length === 0 && bp.length === 0) return 0
  if (ap.length === 0) return 1 // 无预发布 > 有预发布
  if (bp.length === 0) return -1

  const n = Math.max(ap.length, bp.length)
  for (let i = 0; i < n; i++) {
    const x = ap[i]
    const y = bp[i]
    if (x === undefined && y === undefined) return 0
    if (y === undefined) return 1 // 前缀更短者优先级更低
    if (x === undefined) return -1
    const c = compareIdentifiers(x, y)
    if (c !== 0) return c
  }
  return 0
}

/** 规范化显示（保留 build metadata） */
export function formatSemVer(v: SemVer): string {
  let out = `${v.major}.${v.minor}.${v.patch}`
  if (v.prerelease.length) out += `-${v.prerelease.join('.')}`
  if (v.build.length) out += `+${v.build.join('.')}`
  return out
}

/** 用于 UI 的升级幅度分类 */
export function semverDelta(from: SemVer, to: SemVer): 'patch' | 'minor' | 'major' | 'prerelease' | 'none' {
  if (compareSemVer(from, to) === 0) return 'none'
  if (from.major !== to.major) return 'major'
  if (from.minor !== to.minor) return 'minor'
  if (from.patch !== to.patch) return 'patch'
  return 'prerelease'
}
