/**
 * Python 版本约束引擎（Poetry / PEP 440）。
 *
 * 为什么不用 packaging 的 SpecifierSet 语义：poetry.lock 里的依赖声明来自
 * pyproject.toml 的 poetry 语法（^、~、通配、`||`），而 OSV 对 PyPI 的区间通常写成
 * `>=x,<y`。因此这里以 poetry-core 的 parse_constraint 为准（它同时兼容 PEP 440 的
 * `~=` 与比较符），并额外提供 PEP 440 SpecifierSet 的严格解析用于 OSV ECOSYSTEM 区间。
 *
 * 与 npm/Cargo 的关键差别：
 * 1. 存在 epoch（`1!2.0`），release 段长度可变且尾部零等价（1.0 == 1.0.0）。
 * 2. dev < pre(a<b<rc) < 正式 < post；`1.0.dev1` 低于 `1.0a1`。
 * 3. `>V` 不允许 V 的 post 版本，也不允许 V 的 local 版本；`<V`（V 为正式版时）
 *    不允许 V 的任何预发布。
 * 4. `==` 忽略 local 段（`==1.0` 匹配 `1.0+local`），但 `==1.0+local` 只匹配该 local。
 * 5. 通配 `1.2.*` 等价于 `>=1.2.dev0,<1.3.dev0`，且**允许预发布**（1.2.0rc1 命中）。
 * 6. `^`/`~` 在 poetry 里是“区间”，上界会被规范化为 `X.dev0` 以便排除 X 的预发布。
 */

import {
  comparePep440,
  firstDevRelease,
  formatPep440,
  isDevrelease,
  isLocal,
  isPostrelease,
  isPrerelease,
  nextMajor,
  nextMinor,
  nextPatch,
  nextRelease,
  parsePep440,
  publicOf,
  tryParsePep440,
  withDev,
  withPost,
  withPre,
  withRelease,
  withoutLocal,
  withoutPost,
  Pep440ParseError,
  type Pep440Version,
  normalizePypiName,
} from './pep440'

export { normalizePypiName }

export type PyConstraint =
  | { kind: 'any' }
  | { kind: 'empty' }
  | { kind: 'version'; version: Pep440Version }
  /** `!=V`：精确排除 V（含其 local 变体），但 V 的 post / 预发布仍可命中 */
  | { kind: 'notVersion'; version: Pep440Version }
  | { kind: 'range'; min: Pep440Version | null; max: Pep440Version | null; includeMin: boolean; includeMax: boolean }
  | { kind: 'union'; ranges: PyConstraint[] }
  | { kind: 'and'; parts: PyConstraint[] }

export interface PyParseResult {
  readonly raw: string
  readonly constraint: PyConstraint
  readonly error?: string
}

const eq = (a: Pep440Version, b: Pep440Version): boolean => comparePep440(a, b) === 0

function isAny(c: PyConstraint): boolean {
  return c.kind === 'any'
}

function isEmpty(c: PyConstraint): boolean {
  return c.kind === 'empty'
}

function rangeIsEmpty(r: Extract<PyConstraint, { kind: 'range' }>): boolean {
  if (r.min === null || r.max === null) return false
  const d = comparePep440(r.min, r.max)
  if (d === 0) return !(r.includeMin && r.includeMax)
  return d > 0
}

function mkRange(
  min: Pep440Version | null,
  max: Pep440Version | null,
  includeMin: boolean,
  includeMax: boolean,
): PyConstraint {
  const r = { kind: 'range' as const, min, max, includeMin, includeMax }
  return rangeIsEmpty(r) ? { kind: 'empty' } : r
}

function mkVersion(v: Pep440Version): PyConstraint {
  return { kind: 'version', version: v }
}

/** poetry 的 Version.allows：非 local 约束可以匹配同版本的 local 变体 */
function versionAllows(constraint: Pep440Version, v: Pep440Version): boolean {
  let other = v
  if (!isLocal(constraint) && isLocal(other)) other = withoutLocal(other)
  return eq(constraint, other)
}

/** poetry VersionRange.allows 的逐条复刻 */
function rangeAllows(
  r: Extract<PyConstraint, { kind: 'range' }>,
  v: Pep440Version,
): boolean {
  let other = v
  if (r.min !== null) {
    let thisMin = r.min
    if (!r.includeMin && !isPostrelease(thisMin) && isPostrelease(other)) {
      // >V 不匹配 V 的 post 版本
      other = withoutPost(other)
    }
    if (!isLocal(thisMin) && isLocal(other)) {
      // >V 不匹配 V 的 local 版本
      other = withoutLocal(other)
    }
    if (comparePep440(other, thisMin) < 0) return false
    if (!r.includeMin && (eq(other, r.min) || eq(other, thisMin))) return false
  }

  if (r.max !== null) {
    const thisMax = r.max
    let cmpOther = other
    if (!isLocal(thisMax) && isLocal(cmpOther)) cmpOther = withoutLocal(cmpOther)
    if (comparePep440(cmpOther, thisMax) > 0) return false
    if (!r.includeMax && (eq(cmpOther, r.max) || eq(cmpOther, thisMax))) return false
  }
  return true
}

export function pyAllows(c: PyConstraint, v: Pep440Version): boolean {
  switch (c.kind) {
    case 'any':
      return true
    case 'empty':
      return false
    case 'version':
      return versionAllows(c.version, v)
    case 'notVersion':
      return !versionAllows(c.version, v)
    case 'range':
      return rangeAllows(c, v)
    case 'and':
      return c.parts.every((p) => pyAllows(p, v))
    case 'union':
      return c.ranges.some((r) => pyAllows(r, v))
  }
}

/** poetry 的“严格上界规范化”：<V 对正式 V 变成 <V.dev0 */
function canonicalStrictMax(v: Pep440Version): Pep440Version {
  if (isPrerelease(v) || isDevrelease(v)) return v
  return firstDevRelease(v)
}

function stableOf(v: Pep440Version): Pep440Version {
  if (!isPrerelease(v)) return v
  const post = v.pre === null ? v.post : null
  return { epoch: v.epoch, release: v.release, pre: null, post, dev: null, local: null, raw: formatPep440(v) }
}

function nextBreaking(v: Pep440Version): Pep440Version {
  const s = stableOf(v)
  const major = v.release[0] ?? 0
  const hasMinor = v.release.length >= 2
  const minor = v.release[1] ?? 0
  const hasPatch = v.release.length >= 3
  if (major > 0 || !hasMinor) return nextMajor(s)
  if (minor > 0 || !hasPatch) return nextMinor(s)
  return nextPatch(s)
}

/** poetry 的 next_stable：按当前精度进一位（~ 的上界） */
function nextStable(v: Pep440Version): Pep440Version {
  return { ...nextRelease(v), local: v.local }
}

function xRange(version: Pep440Version, invert: boolean): PyConstraint {
  let next: Pep440Version
  if (version.post !== null) {
    next = { ...version, post: version.post + 1, dev: null }
  } else if (!isPrerelease(version) && version.dev === null) {
    next = nextStable(stableOf(version))
  } else if (isPrerelease(version)) {
    // next_prerelease：沿用 pre，数字 +1
    next = { ...version, pre: version.pre ? [version.pre[0], version.pre[1] + 1] : version.pre, dev: null }
  } else {
    next = { ...version, dev: (version.dev ?? 0) + 1 }
  }
  const min = firstDevRelease(version)
  const max = isDevrelease(next) ? next : firstDevRelease(next)
  const r = mkRange(min, max, true, false)
  if (!invert) return r
  return unionOf([mkRange(null, min, false, false), mkRange(max, null, true, false)])
}

function unionOf(parts: PyConstraint[]): PyConstraint {
  const flat: PyConstraint[] = []
  for (const p of parts) {
    if (isEmpty(p)) continue
    if (p.kind === 'union') flat.push(...p.ranges)
    else flat.push(p)
  }
  if (flat.length === 0) return { kind: 'empty' }
  if (flat.length === 1) return flat[0]!
  return { kind: 'union', ranges: flat }
}

function intersectConstraints(a: PyConstraint, b: PyConstraint): PyConstraint {
  if (isEmpty(a) || isEmpty(b)) return { kind: 'empty' }
  if (isAny(a)) return b
  if (isAny(b)) return a

  // `!=V` 与 `and` 不参与区间求交，保留为合取节点（判定语义仍然精确）
  if (a.kind === 'notVersion' || b.kind === 'notVersion' || a.kind === 'and' || b.kind === 'and') {
    const parts =
      a.kind === 'and' ? [...a.parts, b] : b.kind === 'and' ? [a, ...b.parts] : [a, b]
    return { kind: 'and', parts }
  }

  if (a.kind === 'version' && b.kind === 'version') return eq(a.version, b.version) ? a : { kind: 'empty' }
  if (a.kind === 'version') return pyAllows(b, a.version) ? a : { kind: 'empty' }
  if (b.kind === 'version') return pyAllows(a, b.version) ? b : { kind: 'empty' }
  if (a.kind === 'union' || b.kind === 'union') {
    const as = a.kind === 'union' ? a.ranges : [a]
    const bs = b.kind === 'union' ? b.ranges : [b]
    const out: PyConstraint[] = []
    for (const x of as) for (const y of bs) out.push(intersectConstraints(x, y))
    return unionOf(out)
  }
  // 走到这里的只剩两个 range
  if (a.kind !== 'range' || b.kind !== 'range') {
    throw new Error(`内部错误：非预期的约束组合 ${a.kind} / ${b.kind}`)
  }
  let min = a.min
  let includeMin = a.includeMin
  if (b.min !== null) {
    if (min === null) {
      min = b.min
      includeMin = b.includeMin
    } else {
      const d = comparePep440(b.min, min)
      if (d > 0) {
        min = b.min
        includeMin = b.includeMin
      } else if (d === 0) {
        includeMin = includeMin && b.includeMin
      }
    }
  }
  let max = a.max
  let includeMax = a.includeMax
  if (b.max !== null) {
    if (max === null) {
      max = b.max
      includeMax = b.includeMax
    } else {
      const d = comparePep440(b.max, max)
      if (d < 0) {
        max = b.max
        includeMax = b.includeMax
      } else if (d === 0) {
        includeMax = includeMax && b.includeMax
      }
    }
  }
  return mkRange(min, max, includeMin, includeMax)
}

const CARET_RE = /^\^\s*(.+)$/
const TILDE_RE = /^~(?!=)\s*(.+)$/
const TILDE_PEP440_RE = /^~=\s*(.+)$/

function parseSingle(text: string): PyConstraint | null {
  const t = text.trim()
  if (t === '') return null

  if (/^v?[xX*](\.[xX*])*$/.test(t)) return { kind: 'any' }

  let m = CARET_RE.exec(t)
  if (m) {
    const v = parsePep440(m[1]!)
    const upper = canonicalStrictMax(nextBreaking(v))
    return mkRange(v, upper, true, false)
  }

  m = TILDE_PEP440_RE.exec(t)
  if (m) {
    const v = parsePep440(m[1]!)
    const parts = [...stableOf(v).release]
    let upper: Pep440Version
    if (parts.length < 2) {
      upper = nextMajor(stableOf(v))
    } else {
      const idx = parts.length - 2
      parts[idx] = parts[idx]! + 1
      for (let i = idx + 1; i < parts.length; i++) parts[i] = 0
      upper = { epoch: v.epoch, release: parts, pre: null, post: null, dev: null, local: null, raw: parts.join('.') }
    }
    return mkRange(v, canonicalStrictMax(upper), true, false)
  }

  m = TILDE_RE.exec(t)
  if (m) {
    const v = parsePep440(m[1]!)
    const stable = stableOf(v)
    const high = stable.release.length === 1 ? nextMajor(stable) : nextMinor(stable)
    return mkRange(v, canonicalStrictMax(high), true, false)
  }

  // x-range：1.* / 1.2.* / ==1.2.* / !=1.2.*
  m = /^(!=|==)?\s*(v?\d+(?:\.\d+)*)((?:\.\*)+)$/.exec(t)
  if (m) {
    const op = m[1] ?? ''
    const v = parsePep440(m[2]!)
    return xRange(v, op === '!=')
  }

  // 基本比较符
  m = /^(<>|!=|>=?|<=?|==?)?\s*(.+?)(\.\*)?$/.exec(t)
  if (m) {
    const op = m[1] ?? ''
    let versionText = m[2]!
    if (versionText === 'dev') versionText = '0.0-dev'
    const wildcard = m[3] !== undefined
    let v: Pep440Version
    try {
      v = parsePep440(versionText)
    } catch {
      return null
    }
    if (op === '<' || op === '<>') return mkRange(null, canonicalStrictMax(v), false, false)
    if (op === '<=') return mkRange(null, v, false, true)
    if (op === '>') return mkRange(v, null, false, false)
    if (op === '>=') return mkRange(v, null, true, false)
    if (wildcard) {
      if (op === '!=') return xRange(v, true)
      if (op === '' || op === '=' || op === '==') return xRange(v, false)
      return null
    }
    if (op === '!=') {
      // poetry 的 !=V 是“排除恰好 V（含其 local 变体）”：
      // 1.0.post1、1.0rc1 仍然命中 !=1.0，只有 1.0 / 1.0.0 / 1.0+local 被排除。
      return { kind: 'notVersion', version: v }
    }
    return mkVersion(v)
  }
  return null
}

/** poetry 的 AND 切分：`>=1.0,<2.0` 或 `>=1.0 <2.0`（连字符区间不合法） */
function splitAnd(orPart: string): string[] {
  const trimmed = orPart.replace(/,+$/, '').trim()
  if (trimmed === '') return []
  // 允许 `>=1.0,<2.0` 与 `>=1.0 <2.0` 两种写法；`1.2.3 - 2.0` 会被切成三段后失败
  return trimmed
    .split(/(?<!^)(?<![\^~=>< ,]) *(?<!-)[, ](?!-) *(?!,|$)/)
    .map((s) => s.trim())
    .filter((s) => s !== '')
}

export function parsePyConstraint(raw: string): PyParseResult {
  try {
    if (typeof raw !== 'string' || raw.trim() === '') throw new Pep440ParseError(raw, '空的版本约束')
    const text = raw.trim()
    if (text === '*') return { raw, constraint: { kind: 'any' } }

    const orGroups = text.split(/\s*\|\|?\s*/)
    const parts: PyConstraint[] = []
    for (const group of orGroups) {
      const andParts = splitAnd(group)
      if (andParts.length === 0) throw new Pep440ParseError(raw, `空的或分支: ${JSON.stringify(raw)}`)
      let acc: PyConstraint | null = null
      for (const piece of andParts) {
        const c = parseSingle(piece)
        if (c === null) throw new Pep440ParseError(raw, `无法解析约束片段: ${JSON.stringify(piece)}`)
        acc = acc === null ? c : intersectConstraints(acc, c)
      }
      parts.push(acc ?? { kind: 'any' })
    }
    const constraint = unionOf(parts)
    if (isEmpty(constraint)) {
      // 空集仍然是合法解析（>=2,<1 这种自相矛盾的约束）
      return { raw, constraint }
    }
    return { raw, constraint }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return { raw, constraint: { kind: 'empty' }, error: message }
  }
}

export function pySatisfies(version: string | Pep440Version, constraint: PyConstraint | string): boolean {
  const v = typeof version === 'string' ? tryParsePep440(version) : version
  if (!v) return false
  const c = typeof constraint === 'string' ? parsePyConstraint(constraint).constraint : constraint
  return pyAllows(c, v)
}

/** 用约束的展示文本（不含 min/max 细节） */
export function describePyConstraint(c: PyConstraint): string {
  switch (c.kind) {
    case 'any':
      return '*'
    case 'empty':
      return '<空>'
    case 'version':
      return formatPep440(c.version)
    case 'notVersion':
      return `!=${formatPep440(c.version)}`
    case 'and':
      return c.parts.map(describePyConstraint).join(',')
    case 'range': {
      const left = c.min ? `${c.includeMin ? '>=' : '>'}${formatPep440(c.min)}` : ''
      const right = c.max ? `${c.includeMax ? '<=' : '<'}${formatPep440(c.max)}` : ''
      return [left, right].filter(Boolean).join(',') || '*'
    }
    case 'union':
      return c.ranges.map(describePyConstraint).join(' || ')
  }
}

/**
 * PEP 440 SpecifierSet 解析（用于 OSV 的 PyPI ECOSYSTEM 区间，语义为 packaging 默认）。
 * 这里返回一个判定函数，预发布默认按 PEP 440 处理：若集合中存在正式版候选才排除预发布。
 * 我们按 OSV 的用法（逐个已安装版本判断）实现为：带预发布段的版本只在
 * specifier 自身带预发布时匹配，除非调用方显式 includePrerelease。
 */
export interface Pep440Specifier {
  readonly raw: string
  /** 返回匹配结果；version 为正式版时直接按区间判定 */
  matches(v: Pep440Version, includePrerelease?: boolean): boolean
  readonly error?: string
}

type SpecPart =
  | { op: '~=' | '==' | '!=' | '<=' | '>=' | '<' | '>' | '==='; version: Pep440Version | null; rawVersion: string; wildcard: boolean }

export function parsePep440SpecifierSet(raw: string): Pep440Specifier {
  try {
    if (raw.trim() === '') {
      return { raw, matches: (v, inc = false) => inc || !isPrerelease(v) }
    }
    const parts: SpecPart[] = raw
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s !== '')
      .map((s) => {
        const m = /^(~=|===|==|!=|<=|>=|<|>)\s*(.+)$/.exec(s)
        if (!m) throw new Pep440ParseError(raw, `非法的 PEP 440 specifier: ${JSON.stringify(s)}`)
        const op = m[1] as SpecPart['op']
        const rawVersion = m[2]!.trim()
        if (op === '===') return { op, version: null, rawVersion, wildcard: false }
        if (rawVersion.endsWith('.*')) {
          const base = rawVersion.slice(0, -2)
          const v = parsePep440(base)
          if (op === '~=' || op === '<=' || op === '>=' || op === '<' || op === '>') {
            throw new Pep440ParseError(raw, `操作符 ${op} 不支持通配: ${JSON.stringify(s)}`)
          }
          return { op, version: v, rawVersion, wildcard: true }
        }
        if (op === '~=') {
          // ~= 需要 release 至少两段
          const v = parsePep440(rawVersion)
          if (v.release.length < 2) throw new Pep440ParseError(raw, `~= 需要至少两段版本: ${JSON.stringify(s)}`)
          if (isLocal(v)) throw new Pep440ParseError(raw, `~= 不允许 local 段: ${JSON.stringify(s)}`)
          return { op, version: v, rawVersion, wildcard: false }
        }
        const v = parsePep440(rawVersion)
        if (isLocal(v) && !['==', '!='].includes(op)) {
          throw new Pep440ParseError(raw, `操作符 ${op} 不允许 local 段: ${JSON.stringify(s)}`)
        }
        return { op, version: v, rawVersion, wildcard: false }
      })

    const specAllowsPrerelease = parts.some((p) => {
      if (p.op === '!=') return false
      if (p.op === '==' && p.wildcard) return false
      return p.version !== null && isPrerelease(p.version)
    })

    const matches = (v: Pep440Version, includePrerelease = false): boolean => {
      if (isPrerelease(v) && !includePrerelease && !specAllowsPrerelease) return false
      for (const p of parts) {
        if (!specPartMatches(p, v)) return false
      }
      return true
    }
    return { raw, matches }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return { raw, matches: () => false, error: message }
  }
}

function publicEq(a: Pep440Version, b: Pep440Version): boolean {
  return eq(publicOf(a), publicOf(b))
}

function prefixMatch(prospective: Pep440Version, spec: Pep440Version): boolean {
  // 对齐 packaging 的 _compare_equal 通配分支：epoch 参与比较，release 尾部补零后
  // 截断到 spec 的段数；local 段忽略。
  if (prospective.epoch !== spec.epoch) return false
  const target = [...spec.release]
  const padded = [...prospective.release]
  while (padded.length < target.length) padded.push(0)
  const shortened = padded.slice(0, target.length)
  if (shortened.length !== target.length) return false
  return shortened.every((n, i) => n === target[i])
}

function specPartMatches(p: SpecPart, v: Pep440Version): boolean {
  if (p.op === '===') {
    return v.raw.toLowerCase() === p.rawVersion.toLowerCase() || formatPep440(v).toLowerCase() === p.rawVersion.toLowerCase()
  }
  const sv = p.version!
  switch (p.op) {
    case '==':
      if (p.wildcard) return prefixMatch(publicOf(v), sv)
      if (!isLocal(sv)) return eq(publicOf(v), sv)
      return eq(v, sv)
    case '!=':
      if (p.wildcard) return !prefixMatch(publicOf(v), sv)
      if (!isLocal(sv)) return !eq(publicOf(v), sv)
      return !eq(v, sv)
    case '<=':
      return comparePep440(publicOf(v), sv) <= 0
    case '>=':
      return comparePep440(publicOf(v), sv) >= 0
    case '<': {
      if (comparePep440(v, sv) >= 0) return false
      // <V 不允许 V 的预发布（除非 V 自身是预发布）
      if (!isPrerelease(sv) && isPrerelease(v) && comparePep440(v, firstDevRelease(sv)) >= 0) return false
      return true
    }
    case '>': {
      if (comparePep440(v, sv) <= 0) return false
      if (!isPostrelease(sv) && isPostrelease(v)) {
        // >V 不允许 V 的 post 版本；1.0.post1.dev1 的“基底”也要去掉 dev 再比
        const base = withoutLocal(withoutPost({ ...v, dev: null }))
        if (eq(base, sv)) return false
      }
      if (isLocal(v) && eq(publicOf(v), sv)) return false
      return true
    }
    case '~=': {
      // PEP 440：~=X.Y.Z 等价于 >=X.Y.Z, ==X.Y.*；即“去掉最后一段”做前缀匹配，
      // 不额外进位（上界由 ==X.Y.* 的前缀语义给出）。
      if (comparePep440(publicOf(v), sv) < 0) return false
      const prefixRelease = sv.release.slice(0, -1)
      const prefix: Pep440Version = {
        epoch: sv.epoch,
        release: prefixRelease,
        pre: null,
        post: null,
        dev: null,
        local: null,
        raw: prefixRelease.join('.'),
      }
      return prefixMatch(publicOf(v), prefix)
    }
  }
}

export { formatPep440, comparePep440 }
