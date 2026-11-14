/**
 * npm 语义版本区间引擎（对齐 node-semver 7.x 的默认模式）。
 *
 * 关键规则（与 node-semver 一致，均有测试锁定）：
 * 1. `^` 对 0.x 特殊：^0.2.3 → >=0.2.3 <0.3.0-0；^0.0.3 → >=0.0.3 <0.0.4-0。
 * 2. `~` 只锁 minor：~1.2.3 → >=1.2.3 <1.3.0-0；~1 → >=1.0.0 <2.0.0-0。
 * 3. 通配（x / X / * / 缺省段）会展开成上下界，且上界带 `-0` 后缀，
 *    因此 2.0.0-alpha 不会落进 ^1.2.3（上界 <2.0.0-0）。
 * 4. 预发布门控：带预发布段的版本只有在“同一 major.minor.patch 上存在带预发布的
 *    comparator”时才允许匹配。所以 1.2.3-beta 满足 ^1.2.3-beta.1，却不满足 *。
 * 5. build metadata 在区间里被剥离（1.2.3+build 等价 1.2.3）。
 * 6. 空格分隔的 comparator 是“且”，`||` 是“或”；逗号非法。
 */

import {
  compareSemVer,
  formatSemVer,
  type SemVer,
  tryParseSemVer,
  VersionParseError,
} from './semver-core'

export interface NpmComparator {
  /** 空字符串表示 ANY（等价于 *） */
  readonly op: '' | '>' | '>=' | '<' | '<='
  readonly version: SemVer | null
}

export interface NpmRange {
  readonly raw: string
  /** 或关系的外层；每个内层是且关系 */
  readonly sets: ReadonlyArray<ReadonlyArray<NpmComparator>>
  readonly error?: string
}

const NUM = '0|[1-9]\\d*'
const XID = `${NUM}|[xX*]`
const PRE_ID = '(?:\\d*[a-zA-Z-][a-zA-Z0-9-]*|0|[1-9]\\d*)'
const PRE = `(?:-(${PRE_ID}(?:\\.${PRE_ID})*))`
const BUILD = '(?:\\+([a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*))'

interface PartialVersion {
  major: string
  minor?: string
  patch?: string
  prerelease: ReadonlyArray<string | number>
}

const PARTIAL_RE = new RegExp(`^v?(${XID})(?:\\.(${XID})(?:\\.(${XID}))?${PRE}?)?$`)
const FULL_RE = new RegExp(`^v?(${NUM})\\.(${NUM})\\.(${NUM})${PRE}?$`)

const isX = (s: string | undefined): boolean =>
  s === undefined || s === '' || s.toLowerCase() === 'x' || s === '*'

function parsePartial(text: string): PartialVersion | null {
  const m = PARTIAL_RE.exec(text)
  if (!m) return null
  // 预发布只能出现在完整三段版本上（node-semver 的 XRANGEPLAIN 结构如此）
  const prerelease = m[4] ? m[4].split('.').map((p) => (/^\d+$/.test(p) ? Number(p) : p)) : []
  return { major: m[1]!, minor: m[2], patch: m[3], prerelease }
}

function makeVersion(
  major: string,
  minor: string,
  patch: string,
  prerelease: ReadonlyArray<string | number> = [],
): SemVer {
  const v = tryParseSemVer(`${major}.${minor}.${patch}${prerelease.length ? '-' + prerelease.join('.') : ''}`)
  if (!v) throw new VersionParseError(`${major}.${minor}.${patch}`, '区间展开产生了非法版本')
  return v
}

/** 上界 `<M.m.p-0`：`-0` 是预发布里最小的标识符 */
function upperBound(major: number, minor: number, patch: number, zero: boolean): NpmComparator {
  return {
    op: '<',
    version: makeVersion(String(major), String(minor), String(patch), zero ? [0] : []),
  }
}

function cmp(op: NpmComparator['op'], major: string, minor: string, patch: string, pre: ReadonlyArray<string | number>): NpmComparator {
  return { op, version: makeVersion(major, minor, patch, pre) }
}

/** 把 1 / 1.2 / 1.2.x 这类 x-range 展开为 comparator 列表 */
function expandXRange(op: NpmComparator['op'], p: PartialVersion): NpmComparator[] {
  const xM = isX(p.major)
  const xm = xM || isX(p.minor)
  const xp = xm || isX(p.patch)
  const anyX = xp

  if (xM) {
    if (op === '>' || op === '<') return [{ op: '<', version: makeVersion('0', '0', '0', [0]) }]
    return [] // ANY
  }

  let M = p.major
  let m = xm ? '0' : p.minor!
  let patch = '0'

  if (op !== '' && anyX) {
    if (op === '>') {
      if (xm) return [{ op: '>=', version: makeVersion(String(Number(M) + 1), '0', '0') }]
      return [{ op: '>=', version: makeVersion(M, String(Number(m) + 1), '0') }]
    }
    if (op === '<=') {
      if (xm) return [upperBound(Number(M) + 1, 0, 0, true)]
      return [upperBound(Number(M), Number(m) + 1, 0, true)]
    }
    if (op === '<') {
      return [upperBound(Number(M), Number(m), Number(patch), true)]
    }
    if (op === '>=') {
      return [{ op: '>=', version: makeVersion(M, m, patch) }]
    }
  }

  if (xm) return [{ op: '>=', version: makeVersion(M, '0', '0') }, upperBound(Number(M) + 1, 0, 0, true)]
  if (xp) return [{ op: '>=', version: makeVersion(M, m, '0') }, upperBound(Number(M), Number(m) + 1, 0, true)]

  // 完整三段：保留预发布段（`>=1.2.3-alpha.3` 的预发布参与比较，也用于预发布门控）
  return [{ op, version: makeVersion(M, m, p.patch!, p.prerelease) }]
}

function expandCaret(p: PartialVersion): NpmComparator[] {
  const xM = isX(p.major)
  const xm = xM || isX(p.minor)
  const xp = xm || isX(p.patch)
  const M = p.major
  const m = xm ? '0' : p.minor!

  if (xM) return []
  if (xm) return [{ op: '>=', version: makeVersion(M, '0', '0') }, upperBound(Number(M) + 1, 0, 0, true)]
  if (xp) {
    if (M === '0') return [{ op: '>=', version: makeVersion(M, m, '0') }, upperBound(0, Number(m) + 1, 0, true)]
    return [{ op: '>=', version: makeVersion(M, m, '0') }, upperBound(Number(M) + 1, 0, 0, true)]
  }

  const patch = p.patch!
  const lower: NpmComparator = { op: '>=', version: makeVersion(M, m, patch, p.prerelease) }
  if (M === '0') {
    if (m === '0') return [lower, upperBound(0, 0, Number(patch) + 1, true)]
    return [lower, upperBound(0, Number(m) + 1, 0, true)]
  }
  return [lower, upperBound(Number(M) + 1, 0, 0, true)]
}

function expandTilde(p: PartialVersion): NpmComparator[] {
  const xM = isX(p.major)
  const xm = xM || isX(p.minor)
  const xp = xm || isX(p.patch)
  const M = p.major
  const m = xm ? '0' : p.minor!

  if (xM) return []
  if (xm) return [{ op: '>=', version: makeVersion(M, '0', '0') }, upperBound(Number(M) + 1, 0, 0, true)]
  if (xp) return [{ op: '>=', version: makeVersion(M, m, '0') }, upperBound(Number(M), Number(m) + 1, 0, true)]
  return [
    { op: '>=', version: makeVersion(M, m, p.patch!, p.prerelease) },
    upperBound(Number(M), Number(m) + 1, 0, true),
  ]
}

const COMPARATOR_RE = /^(<=|>=|<|>|=)?\s*(.+)$/

/** 解析单个 comparator token（已剥离 build metadata、已合并操作符空白） */
function parseComparatorToken(token: string): NpmComparator[] {
  const t = token.trim()
  if (t === '') return [] // ANY

  const opMatch = COMPARATOR_RE.exec(t)
  if (!opMatch) throw new VersionParseError(token, `非法的 npm comparator: ${JSON.stringify(token)}`)
  const opRaw = opMatch[1] ?? ''
  // node-semver 把 `=` 归一化成空操作符（即精确相等）
  const op = (opRaw === '=' ? '' : opRaw) as '' | '<' | '<=' | '>' | '>='
  const body = opMatch[2]!

  if (body.startsWith('^')) {
    const p = parsePartial(body.slice(1))
    if (!p) throw new VersionParseError(token, `非法的 ^ 区间: ${JSON.stringify(token)}`)
    return expandCaret(p)
  }
  if (body.startsWith('~>') || body.startsWith('~')) {
    const rest = body.startsWith('~>') ? body.slice(2) : body.slice(1)
    const p = parsePartial(rest)
    if (!p) throw new VersionParseError(token, `非法的 ~ 区间: ${JSON.stringify(token)}`)
    return expandTilde(p)
  }

  const p = parsePartial(body)
  if (!p) throw new VersionParseError(token, `非法的版本区间: ${JSON.stringify(token)}`)
  return expandXRange(op, p)
}

/** `1.2.3 - 2.3` → comparator 列表（node-semver hyphenReplace） */
function expandHyphen(fromText: string, toText: string): NpmComparator[] {
  const from = parsePartial(fromText)
  const to = parsePartial(toText)
  if (!from || !to) throw new VersionParseError(`${fromText} - ${toText}`, '非法的连字符区间')
  const out: NpmComparator[] = []

  if (isX(from.major)) {
    // 下界为 -inf
  } else if (isX(from.minor)) {
    out.push({ op: '>=', version: makeVersion(from.major, '0', '0') })
  } else if (isX(from.patch)) {
    out.push({ op: '>=', version: makeVersion(from.major, from.minor!, '0') })
  } else if (from.prerelease.length) {
    out.push({ op: '>=', version: makeVersion(from.major, from.minor!, from.patch!, from.prerelease) })
  } else {
    out.push({ op: '>=', version: makeVersion(from.major, from.minor!, from.patch!) })
  }

  if (isX(to.major)) {
    // 上界为 +inf
  } else if (isX(to.minor)) {
    out.push(upperBound(Number(to.major) + 1, 0, 0, true))
  } else if (isX(to.patch)) {
    out.push(upperBound(Number(to.major), Number(to.minor) + 1, 0, true))
  } else if (to.prerelease.length) {
    out.push({ op: '<=', version: makeVersion(to.major, to.minor!, to.patch!, to.prerelease) })
  } else {
    out.push({ op: '<=', version: makeVersion(to.major, to.minor!, to.patch!) })
  }
  return out
}

const BUILD_GLOBAL = /\+[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*/g
const HYPHEN_RE = /^\s*(\S+)\s+-\s+(\S+)\s*$/

function normalizeOperatorWhitespace(s: string): string {
  let prev = ''
  let cur = s
  // 反复替换，处理 `>= 1 < 2` 这种连续形式；`-` 不在操作符集合内，不会破坏连字符区间
  while (prev !== cur) {
    prev = cur
    cur = cur.replace(/(<=|>=|~>|<|>|=|~|\^)\s+/g, '$1')
  }
  return cur
}

export function parseNpmRange(raw: string): NpmRange {
  const original = raw
  try {
    if (typeof raw !== 'string' || raw.trim() === '') throw new VersionParseError(raw, '空区间')
    // build metadata 全局剥离
    let text = raw.replace(BUILD_GLOBAL, '').trim()

    const sets: NpmComparator[][] = []
    for (const orPart of text.split('||')) {
      const part = orPart.trim()
      if (part === '') throw new VersionParseError(original, `空的可选分支: ${JSON.stringify(raw)}`)

      let expanded: NpmComparator[]
      const hyphen = HYPHEN_RE.exec(part)
      if (hyphen) {
        expanded = expandHyphen(hyphen[1]!, hyphen[2]!)
      } else {
        const normalized = normalizeOperatorWhitespace(part)
        const tokens = normalized.split(/\s+/).filter((t) => t !== '')
        if (tokens.length === 0) throw new VersionParseError(original, `空的可选分支: ${JSON.stringify(raw)}`)
        expanded = []
        for (const token of tokens) expanded.push(...parseComparatorToken(token))
        // >=0.0.0 等价于 *（node-semver 的 replaceGTE0）
        expanded = expanded.filter(
          (c) => !(c.op === '>=' && c.version && c.version.major === 0 && c.version.minor === 0 && c.version.patch === 0 && c.version.prerelease.length === 0),
        )
      }

      // 去重，保持顺序
      const seen = new Set<string>()
      const unique: NpmComparator[] = []
      for (const c of expanded) {
        const key = c.version ? `${c.op}${formatSemVer(c.version)}` : ''
        if (!seen.has(key)) {
          seen.add(key)
          unique.push(c)
        }
      }

      // 含 null set（<0.0.0-0）时该分支只剩 null set
      const nullSet = unique.find(
        (c) => c.op === '<' && c.version && c.version.major === 0 && c.version.minor === 0 && c.version.patch === 0 && c.version.prerelease.length === 1 && c.version.prerelease[0] === 0,
      )
      sets.push(nullSet ? [nullSet] : unique)
    }
    if (sets.length === 0) throw new VersionParseError(original, '没有任何可选分支')
    // 若存在 ANY 分支，整体简化为 ANY
    if (sets.some((s) => s.length === 1 && s[0]!.version === null)) {
      return { raw: original, sets: [[]] }
    }
    return { raw: original, sets }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return { raw: original, sets: [], error: message }
  }
}

function comparatorTest(c: NpmComparator, v: SemVer): boolean {
  if (c.version === null) return true
  const delta = compareSemVer(v, c.version)
  switch (c.op) {
    case '':
      return delta === 0
    case '>':
      return delta > 0
    case '>=':
      return delta >= 0
    case '<':
      return delta < 0
    case '<=':
      return delta <= 0
  }
}

/**
 * 区间匹配。`includePrerelease` 默认为 false，即 node-semver 默认的预发布门控。
 */
export function npmSatisfies(version: string | SemVer, range: NpmRange | string, includePrerelease = false): boolean {
  const parsed = typeof version === 'string' ? tryParseSemVer(version) : version
  if (!parsed) return false
  const r = typeof range === 'string' ? parseNpmRange(range) : range
  if (r.error) return false

  for (const set of r.sets) {
    if (set.every((c) => comparatorTest(c, parsed))) {
      if (parsed.prerelease.length === 0 || includePrerelease) return true
      // 预发布门控：需要同 major.minor.patch 且带预发布段的 comparator
      for (const c of set) {
        if (c.version && c.version.prerelease.length > 0 && c.version.major === parsed.major && c.version.minor === parsed.minor && c.version.patch === parsed.patch) {
          return true
        }
      }
    }
  }
  return false
}
