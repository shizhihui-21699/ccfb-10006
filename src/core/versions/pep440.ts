/**
 * PEP 440 版本模型（对齐 Python `packaging` 的 Version 实现）。
 *
 * 与 SemVer 的关键差别：
 * 1. 可选的 epoch（`1!2.0`）、任意长度的 release 段（`1.2.3.4`），且尾部零被忽略
 *    （1.0 == 1 == 1.0.0）。
 * 2. 可选后缀：pre（a/b/rc，含 alpha/beta/preview/pre/c 别名）、post（含 rev/r/-N）、
 *    dev。排序为 dev < a < b < rc < 正式 < post；同一 release 上 `1.0.dev1 < 1.0a1`。
 * 3. local 段（`+ubuntu.1`）只在精确相等时参与，且字符串段排在数字段之前。
 * 4. pre/post/dev 段允许连字符、下划线、点等分隔形式，且数字可省略（默认 0）。
 */

export class Pep440ParseError extends Error {
  readonly input: string
  constructor(input: string, message: string) {
    super(message)
    this.name = 'Pep440ParseError'
    this.input = input
  }
}

export interface Pep440Version {
  readonly epoch: number
  readonly release: ReadonlyArray<number>
  readonly pre: readonly ['a' | 'b' | 'rc', number] | null
  readonly post: number | null
  readonly dev: number | null
  readonly local: ReadonlyArray<string | number> | null
  readonly raw: string
}

const PATTERN = new RegExp(
  '^\\s*' +
    'v?' +
    '(?:(\\d+)!)?' +
    '(\\d+(?:\\.\\d+)*)' +
    '(?:[._-]?(alpha|a|beta|b|preview|pre|c|rc)[._-]?(\\d+)?)?' +
    '(?:(?:-(\\d+))|(?:[._-]?(post|rev|r)[._-]?(\\d+)?))?' +
    '(?:[._-]?(dev)[._-]?(\\d+)?)?' +
    '(?:\\+([a-z0-9]+(?:[._-][a-z0-9]+)*))?' +
    '\\s*$',
  'i',
)

const PRE_NORMALIZE: Record<string, 'a' | 'b' | 'rc'> = {
  alpha: 'a',
  a: 'a',
  beta: 'b',
  b: 'b',
  preview: 'rc',
  pre: 'rc',
  c: 'rc',
  rc: 'rc',
}

export function parsePep440(input: string): Pep440Version {
  const m = PATTERN.exec(input)
  if (!m) throw new Pep440ParseError(input, `不是合法的 PEP 440 版本: ${JSON.stringify(input)}`)
  const epoch = m[1] ? Number(m[1]) : 0
  const release = m[2]!.split('.').map(Number)

  let pre: ['a' | 'b' | 'rc', number] | null = null
  if (m[3]) pre = [PRE_NORMALIZE[m[3].toLowerCase()]!, m[4] ? Number(m[4]) : 0]

  let post: number | null = null
  if (m[5] !== undefined) post = Number(m[5])
  else if (m[6] !== undefined) post = m[7] ? Number(m[7]) : 0

  let dev: number | null = null
  if (m[8] !== undefined) dev = m[9] ? Number(m[9]) : 0

  let local: (string | number)[] | null = null
  if (m[10]) {
    local = m[10]
      .split(/[._-]/)
      .map((part) => (/^\d+$/.test(part) ? Number(part) : part.toLowerCase()))
  }

  return { epoch, release, pre, post, dev, local, raw: input.trim() }
}

export function tryParsePep440(input: string): Pep440Version | null {
  try {
    return parsePep440(input)
  } catch {
    return null
  }
}

const PRE_RANK: Record<'a' | 'b' | 'rc', number> = { a: 0, b: 1, rc: 2 }
const PRE_RANK_DEV_ONLY = -1
const PRE_RANK_STABLE = 3

function trimmedRelease(release: ReadonlyArray<number>): number[] {
  const out = [...release]
  while (out.length > 0 && out[out.length - 1] === 0) out.pop()
  return out
}

type CmpKey = [number, number[], number, number, number, number, number, number, ([string, string] | [number, string])[]?]

function cmpKey(v: Pep440Version): CmpKey {
  const release = trimmedRelease(v.release)

  let preRank: number
  let preN: number
  if (v.pre === null && v.post === null && v.dev !== null) {
    // 仅 dev：1.0.dev1 排在 1.0a1 之前
    preRank = PRE_RANK_DEV_ONLY
    preN = 0
  } else if (v.pre === null) {
    preRank = PRE_RANK_STABLE
    preN = 0
  } else {
    preRank = PRE_RANK[v.pre[0]]
    preN = v.pre[1]
  }

  const postRank = v.post === null ? 0 : 1
  const postN = v.post === null ? 0 : v.post
  const devRank = v.dev === null ? 1 : 0
  const devN = v.dev === null ? 0 : v.dev

  const key: CmpKey = [v.epoch, release, preRank, preN, postRank, postN, devRank, devN]
  if (v.local !== null) {
    key.push(v.local.map((seg): [string, string] | [number, string] => (typeof seg === 'number' ? [seg, ''] : [-1, seg])))
  }
  return key
}

function compareArrays(a: unknown[], b: unknown[]): number {
  const n = Math.max(a.length, b.length)
  for (let i = 0; i < n; i++) {
    const x = a[i]
    const y = b[i]
    if (x === undefined && y === undefined) return 0
    if (y === undefined) return 1
    if (x === undefined) return -1
    if (Array.isArray(x) && Array.isArray(y)) {
      const c = compareArrays(x, y)
      if (c !== 0) return c
    } else if (typeof x === 'number' && typeof y === 'number') {
      if (x !== y) return x < y ? -1 : 1
    } else {
      const sx = String(x)
      const sy = String(y)
      if (sx !== sy) return sx < sy ? -1 : 1
    }
  }
  return 0
}

/** PEP 440 排序；local 段参与比较（与 packaging 一致） */
export function comparePep440(a: Pep440Version, b: Pep440Version): number {
  return compareArrays(cmpKey(a) as unknown[], cmpKey(b) as unknown[])
}

/** 忽略 local 的等价比较，用于 `==`/`!=`/区间端点（packaging 的 _public_version） */
export function publicOf(v: Pep440Version): Pep440Version {
  return v.local === null ? v : { ...v, local: null }
}

export function withoutLocal(v: Pep440Version): Pep440Version {
  return v.local === null ? v : { ...v, local: null }
}

export function withoutPost(v: Pep440Version): Pep440Version {
  return v.post === null ? v : { ...v, post: null }
}

export function isPrerelease(v: Pep440Version): boolean {
  return v.dev !== null || v.pre !== null
}

export function isPostrelease(v: Pep440Version): boolean {
  return v.post !== null
}

export function isDevrelease(v: Pep440Version): boolean {
  return v.dev !== null
}

export function isLocal(v: Pep440Version): boolean {
  return v.local !== null
}

export function isStable(v: Pep440Version): boolean {
  return !isPrerelease(v)
}

/** release 段精度（不含 epoch / 后缀） */
export function releasePrecision(v: Pep440Version): number {
  return v.release.length
}

function bumpRelease(release: ReadonlyArray<number>, index: number): number[] {
  const out = [...release]
  while (out.length <= index) out.push(0)
  out[index] = out[index]! + 1
  for (let i = index + 1; i < out.length; i++) out[i] = 0
  return out
}

export function nextMajor(v: Pep440Version): Pep440Version {
  return mk(v.epoch, bumpRelease(v.release, 0))
}

export function nextMinor(v: Pep440Version): Pep440Version {
  return mk(v.epoch, bumpRelease(v.release, 1))
}

export function nextPatch(v: Pep440Version): Pep440Version {
  return mk(v.epoch, bumpRelease(v.release, 2))
}

/** poetry 的 Release.next()：按精度进位（1 → 2, 1.2 → 1.3, 1.2.3 → 1.2.4） */
export function nextRelease(v: Pep440Version): Pep440Version {
  const precision = v.release.length
  if (precision === 1) return nextMajor(v)
  if (precision === 2) return nextMinor(v)
  return nextPatch(v)
}

function mk(epoch: number, release: number[]): Pep440Version {
  return { epoch, release, pre: null, post: null, dev: null, local: null, raw: release.join('.') }
}

/** 加上 dev0 后缀，用作排他上界（poetry 的 _canonical_strict_max） */
export function firstDevRelease(v: Pep440Version): Pep440Version {
  return { ...v, dev: 0 }
}

export function withPre(v: Pep440Version, pre: readonly [string, number] | null): Pep440Version {
  return { ...v, pre: pre as Pep440Version['pre'] }
}

export function withDev(v: Pep440Version, dev: number | null): Pep440Version {
  return { ...v, dev }
}

export function withPost(v: Pep440Version, post: number | null): Pep440Version {
  return { ...v, post }
}

export function withRelease(v: Pep440Version, release: ReadonlyArray<number>): Pep440Version {
  return { ...v, release }
}

/** 规范化显示 */
export function formatPep440(v: Pep440Version): string {
  let out = v.release.join('.')
  if (v.epoch) out = `${v.epoch}!${out}`
  if (v.pre) out += `${v.pre[0]}${v.pre[1]}`
  if (v.post !== null) out += `.post${v.post}`
  if (v.dev !== null) out += `.dev${v.dev}`
  if (v.local !== null) out += `+${v.local.join('.')}`
  return out
}

/** PEP 503 规范化项目名：小写，[-_.]+ → - */
export function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-')
}
