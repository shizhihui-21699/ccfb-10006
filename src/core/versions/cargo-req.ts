/**
 * Cargo 版本区间引擎（对齐 Rust `semver` crate 1.0 的 VersionReq 语义）。
 *
 * 与 npm 的关键差别（都来自 semver crate 的实际行为）：
 * 1. Cargo 的 comparator 是**部分绑定**的：`1.2` 表示 `>=1.2.0, <1.3.0`（tilde 式），
 *    而 npm 的 `1.2` 是 `1.2.x`（x-range）。`*` 只匹配无预发布版本。
 * 2. 预发布门控同样存在，但条件是 comparator 的 major.minor.patch 与版本完全一致
 *    且 comparator 自身带预发布段。
 * 3. 不支持 `||`、不支持连字符区间；多个 comparator 用逗号或空格分隔，效果都是“且”。
 * 4. 通配符只允许出现在尾部，`1.2.*.*` 非法；`1.x.x` 合法。
 * 5. `v1.2.3` 非法（cargo 不认 v 前缀）。
 * 6. comparator 的 `=1.2` 是精确前缀匹配（语义同 `1.2`），`>=1.2` 则是 `>=1.2.0`。
 */

import {
  compareSemVer,
  formatSemVer,
  type SemVer,
  tryParseSemVer,
  VersionParseError,
} from './semver-core'

export type CargoOp = 'Exact' | 'Greater' | 'GreaterEq' | 'Less' | 'LessEq' | 'Tilde' | 'Caret' | 'Wildcard'

export interface CargoComparator {
  readonly op: CargoOp
  readonly major: number
  readonly minor: number | null
  readonly patch: number | null
  readonly pre: ReadonlyArray<string | number>
  readonly raw: string
}

export interface CargoReq {
  readonly raw: string
  readonly comparators: ReadonlyArray<CargoComparator>
  readonly error?: string
}

const NUM = '0|[1-9]\\d*'
const PRE_ID = '(?:\\d*[a-zA-Z-][a-zA-Z0-9-]*|0|[1-9]\\d*)'
const PRE = `(?:-(${PRE_ID}(?:\\.${PRE_ID})*))`
const BUILD = '(?:\\+[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*)?'

const PART_RE = new RegExp(
  `^(\\^|~|>=|<=|>|<|=)?\\s*(${NUM})(?:\\.(${NUM}|[xX*])(?:\\.(${NUM}|[xX*])${PRE}?)?)?${BUILD}$`,
)

function toPre(raw: string | undefined): (string | number)[] {
  if (!raw) return []
  return raw.split('.').map((p) => (/^\d+$/.test(p) ? Number(p) : p))
}

function parseOne(text: string): CargoComparator {
  const t = text.trim()
  if (t === '*') return { op: 'Wildcard', major: 0, minor: null, patch: null, pre: [], raw: '*' }
  const m = PART_RE.exec(t)
  if (!m) throw new VersionParseError(t, `非法的 Cargo 版本约束: ${JSON.stringify(t)}`)
  const opText = m[1] ?? ''
  const majorText = m[2]!
  const minorText = m[3]
  const patchText = m[4]
  const pre = toPre(m[5])

  const isWild = (s: string | undefined): boolean => s === undefined ? false : /^[xX*]$/.test(s)

  if (isWild(minorText)) {
    // 1.x / 1.* → Wildcard，且后面不能再有段
    if (patchText !== undefined && !isWild(patchText)) {
      throw new VersionParseError(t, `通配符顺序错误: ${JSON.stringify(t)}`)
    }
    return { op: 'Wildcard', major: Number(majorText), minor: null, patch: null, pre: [], raw: t }
  }
  if (isWild(patchText)) {
    return { op: 'Wildcard', major: Number(majorText), minor: Number(minorText), patch: null, pre: [], raw: t }
  }
  if (patchText !== undefined && minorText === undefined) {
    throw new VersionParseError(t, `非法的 Cargo 版本约束: ${JSON.stringify(t)}`)
  }
  // 预发布段只允许出现在完整三段上
  if (pre.length > 0 && (minorText === undefined || patchText === undefined)) {
    throw new VersionParseError(t, `预发布段需要完整三段版本: ${JSON.stringify(t)}`)
  }

  let op: CargoOp
  switch (opText) {
    case '':
      // Cargo 的关键语义：裸版本 `1.2` 等价于 `^1.2`（caret），不是精确匹配。
      // 精确匹配必须显式写 `=1.2`。
      op = 'Caret'
      break
    case '=':
      op = 'Exact'
      break
    case '>':
      op = 'Greater'
      break
    case '>=':
      op = 'GreaterEq'
      break
    case '<':
      op = 'Less'
      break
    case '<=':
      op = 'LessEq'
      break
    case '~':
      op = 'Tilde'
      break
    case '^':
      op = 'Caret'
      break
    default:
      throw new VersionParseError(t, `未知操作符: ${opText}`)
  }

  return {
    op,
    major: Number(majorText),
    minor: minorText === undefined ? null : Number(minorText),
    patch: patchText === undefined ? null : Number(patchText),
    pre,
    raw: t,
  }
}

export function parseCargoReq(raw: string): CargoReq {
  try {
    if (typeof raw !== 'string' || raw.trim() === '') throw new VersionParseError(raw, '空的版本约束')
    if (raw.includes('||')) throw new VersionParseError(raw, 'Cargo 版本约束不支持 ||')
    const text = raw.trim()
    // semver crate 允许逗号或空格分隔，且允许操作符与版本之间有空隙（`>= 1.2`）。
    // 先把操作符后的空白吸掉，再按空白/逗号切开。
    const joined = text.replace(/(\^|~|>=|<=|>|<|=)\s+/g, '$1')
    const tokens = joined.split(/[\s,]+/).filter((t) => t !== '' && t !== '*')
    if (tokens.length === 0) return { raw, comparators: [] }
    const comparators = tokens.map(parseOne)
    return { raw, comparators }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return { raw, comparators: [], error: message }
  }
}

function cmpToVersion(c: CargoComparator, minor: number, patch: number): SemVer {
  const v = tryParseSemVer(`${c.major}.${minor}.${patch}`)
  if (!v) throw new VersionParseError(c.raw, '内部错误：构造版本失败')
  return v
}

/** 把 comparator 的 pre 与某版本比较；semver crate 直接按预发布序列比较 */
function preCompare(c: CargoComparator, v: SemVer): number {
  const fake: SemVer = {
    major: c.major,
    minor: c.minor ?? 0,
    patch: c.patch ?? 0,
    prerelease: c.pre,
    build: [],
    raw: c.raw,
  }
  return compareSemVer(v, fake)
}

/**
 * 直接复刻 semver crate 的 matches_impl（eval.rs），逐分支对照。
 * 返回匹配结果；预发布门控由外层 npmSatisfies 的等价逻辑处理。
 */
function matchesImpl(c: CargoComparator, v: SemVer): boolean {
  const majorEq = v.major === c.major
  switch (c.op) {
    case 'Exact':
    case 'Wildcard': {
      if (!majorEq) return false
      if (c.minor !== null && v.minor !== c.minor) return false
      if (c.patch !== null && v.patch !== c.patch) return false
      return comparePreArray(v.prerelease, c.pre) === 0
    }
    case 'Greater': {
      if (!majorEq) return v.major > c.major
      if (c.minor === null) return false
      if (v.minor !== c.minor) return v.minor > c.minor
      if (c.patch === null) return false
      if (v.patch !== c.patch) return v.patch > c.patch
      return preCompare(c, v) > 0
    }
    case 'Less': {
      if (!majorEq) return v.major < c.major
      if (c.minor === null) return false
      if (v.minor !== c.minor) return v.minor < c.minor
      if (c.patch === null) return false
      if (v.patch !== c.patch) return v.patch < c.patch
      return preCompare(c, v) < 0
    }
    case 'GreaterEq':
      return matchesImpl({ ...c, op: 'Exact' }, v) || matchesImpl({ ...c, op: 'Greater' }, v)
    case 'LessEq':
      return matchesImpl({ ...c, op: 'Exact' }, v) || matchesImpl({ ...c, op: 'Less' }, v)
    case 'Tilde': {
      if (!majorEq) return false
      if (c.minor !== null && v.minor !== c.minor) return false
      if (c.patch !== null && v.patch !== c.patch) return v.patch > c.patch
      return comparePreArray(v.prerelease, c.pre) >= 0
    }
    case 'Caret': {
      if (!majorEq) return false
      if (c.minor === null) return true
      if (c.patch === null) {
        return c.major > 0 ? v.minor >= c.minor : v.minor === c.minor
      }
      if (c.major > 0) {
        if (v.minor !== c.minor) return v.minor > c.minor
        if (v.patch !== c.patch) return v.patch > c.patch
      } else if (c.minor > 0) {
        if (v.minor !== c.minor) return false
        if (v.patch !== c.patch) return v.patch > c.patch
      } else if (v.minor !== c.minor || v.patch !== c.patch) {
        return false
      }
      return comparePreArray(v.prerelease, c.pre) >= 0
    }
  }
}

function comparePreArray(a: ReadonlyArray<string | number>, b: ReadonlyArray<string | number>): number {
  const fakeA: SemVer = { major: 0, minor: 0, patch: 0, prerelease: a, build: [], raw: '' }
  const fakeB: SemVer = { major: 0, minor: 0, patch: 0, prerelease: b, build: [], raw: '' }
  return compareSemVer(fakeA, fakeB)
}

function preIsCompatible(c: CargoComparator, v: SemVer): boolean {
  return c.major === v.major && c.minor === v.minor && c.patch === v.patch && c.pre.length > 0
}

export function cargoSatisfies(version: string | SemVer, req: CargoReq | string): boolean {
  const v = typeof version === 'string' ? tryParseSemVer(version, false) : version
  if (!v) return false
  const r = typeof req === 'string' ? parseCargoReq(req) : req
  if (r.error) return false

  for (const c of r.comparators) {
    if (!matchesImpl(c, v)) return false
  }
  if (v.prerelease.length === 0) return true
  for (const c of r.comparators) {
    if (preIsCompatible(c, v)) return true
  }
  return false
}


