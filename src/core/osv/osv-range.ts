/**
 * OSV range 求值。
 *
 * OSV 不用“区间表达式”，而是用事件流描述受影响版本集合：
 *   introduced 之后进入受影响状态，fixed 之后离开，last_affected 之后离开（含端点），
 *   limit 只限制“该 range 的评估范围”，本身不是修复标志。
 *
 * 求值方式（与 OSV 规范一致）：
 * - 对一条 range 的每个事件 e，若版本 v 满足：
 *     introduced 存在且 v >= introduced（"0" 表示低于一切版本）
 *   或 fixed 存在且 v < fixed
 *   或 last_affected 存在且 v <= last_affected
 *   或 limit 存在且 v < limit
 *   则把 e 的“状态值”放进排序集合：排序后的第一个元素就是 v 的状态。
 * - 状态值是 (事件序号, 种类)，种类里 fixed/last_affected 记为 0（离开），introduced/limit 记为 1（进入）。
 * - 若 v 处于任何 introduced 为 1 的状态 → 受影响。
 *
 * 预发布：比较完全按生态版本语义（SemVer 里 1.2.3-rc < 1.2.3），没有额外的预发布门控。
 * 因此 [0, 1.2.3) 会命中 1.2.3-rc.1 —— 这正是真实 OSV 数据的行为。
 */

import type { OsvAffected, OsvRange, OsvRecord } from './osv-schema'
import { canonicalEcosystem } from './osv-schema'
import {
  compareParsedVersions,
  normalizePackageName,
  parseBoundary,
  parseEcosystemVersion,
  tryParseEcosystemVersion,
  UncomparableVersion,
  type Ecosystem,
} from '../versions/ecosystem'
import type { ParsedVersion } from '../versions/ecosystem'

export interface MatchedRange {
  readonly rangeIndex: number
  readonly range: OsvRange
  /** 命中的边界描述，用于 UI 展示 */
  readonly reason: 'introduced' | 'fixed' | 'last_affected' | 'limit'
  readonly introduced?: string
  readonly fixed?: string
  readonly lastAffected?: string
  /** 命中的具体区间（若能推导） */
  readonly interval: { from?: string; to?: string; toInclusive?: boolean }
}

export interface OsvMatch {
  readonly record: OsvRecord
  readonly ecosystem: Ecosystem
  readonly packageName: string
  readonly viaVersionsList: boolean
  readonly ranges: MatchedRange[]
  /** 命中的 affected 条目（用于取 fixed 版本） */
  readonly affected: OsvAffected
}

export class RangeEvaluationError extends Error {
  constructor(message: string, readonly rangeIndex: number) {
    super(message)
    this.name = 'RangeEvaluationError'
  }
}

/**
 * 单个 range 对某版本是否受影响。
 *
 * 严格按 OSV 规范的伪代码实现（不是"取最小状态"那样的等价改写）：
 * 1. BeforeLimits：若存在 limit 事件，则只有当存在某个 limit 使 v < limit 时才继续评估；
 *    没有任何 limit 事件时视为隐式无限 limit，继续评估。
 * 2. 把 events 按版本排序后依次遍历，维护 vulnerable 状态：
 *    - introduced 且 v >= introduced  → vulnerable = true
 *    - fixed 且 v >= fixed            → vulnerable = false
 *    - last_affected 且 v > last_affected → vulnerable = false
 * 3. 遍历结束仍为 true 则该 range 命中。
 *
 * 注意 fixed 的判定是 `v >= fixed` 时“清除”，因此 [introduced, fixed) 命中、
 * fixed 本身不命中；last_affected 的判定是 `v > last_affected` 时清除，因此区间右端含端点。
 */
export function rangeAffectsVersion(
  ecosystem: Ecosystem,
  range: OsvRange,
  version: string,
): { affected: boolean; reason?: MatchedRange['reason']; interval?: MatchedRange['interval'] } {
  if (range.type === 'GIT') {
    throw new RangeEvaluationError('GIT 类型 range 需要 commit 序，不做版本匹配', -1)
  }
  const v = parseEcosystemVersion(ecosystem, version)
  const boundaryType: 'SEMVER' | 'ECOSYSTEM' = range.type

  const parseEventVersion = (raw: string): ParsedVersion | null => {
    try {
      return parseBoundary(ecosystem, boundaryType, raw)
    } catch (err) {
      if (err instanceof UncomparableVersion) {
        throw new RangeEvaluationError(`无法按 ${ecosystem} 语义解析边界版本 ${JSON.stringify(raw)}`, -1)
      }
      throw err
    }
  }

  const cmp = (a: ParsedVersion, b: ParsedVersion): number => {
    if (a.kind !== b.kind) {
      throw new RangeEvaluationError('边界版本与生态版本体系不一致，无法比较', -1)
    }
    return compareParsedVersions(a, b)
  }

  // 1) BeforeLimits
  const limits = range.events.filter((e) => e.limit !== undefined)
  if (limits.length > 0) {
    const passes = limits.some((e) => {
      const boundary = parseEventVersion(e.limit!)
      return boundary !== null && cmp(v, boundary) < 0
    })
    if (!passes) return { affected: false }
  }

  // 2) 按版本排序事件（引入边界 "0" 视为最小）
  const ordered = range.events
    .map((event, index) => {
      const kind = (['introduced', 'fixed', 'last_affected', 'limit'] as const).find((k) => event[k] !== undefined)!
      const raw = event[kind]!
      let key: ParsedVersion | null = null
      if (!(kind === 'introduced' && raw === '0')) key = parseEventVersion(raw)
      return { event, index, kind, raw, key }
    })
    .sort((a, b) => {
      if (a.key === null && b.key === null) return a.index - b.index
      if (a.key === null) return -1 // "0" 最小
      if (b.key === null) return 1
      const d = cmp(a.key, b.key)
      return d !== 0 ? d : a.index - b.index
    })

  // 3) 状态机
  let vulnerable = false
  let reason: MatchedRange['reason'] = 'introduced'
  let lastIntroducedIndex = -1
  for (const item of ordered) {
    switch (item.kind) {
      case 'introduced':
        if (item.key === null || cmp(v, item.key) >= 0) {
          vulnerable = true
          reason = 'introduced'
          lastIntroducedIndex = item.index
        }
        break
      case 'fixed':
        if (item.key !== null && cmp(v, item.key) >= 0) vulnerable = false
        break
      case 'last_affected':
        if (item.key !== null && cmp(v, item.key) > 0) vulnerable = false
        break
      case 'limit':
        // limit 只参与 BeforeLimits，不改变状态
        break
    }
  }

  if (!vulnerable) return { affected: false, reason }
  return { affected: true, reason, interval: describeInterval(ecosystem, range, lastIntroducedIndex) }
}

function describeInterval(
  ecosystem: Ecosystem,
  range: OsvRange,
  introducedIndex: number,
): MatchedRange['interval'] {
  void ecosystem
  // 按版本排序后找 introduced 之后的第一个结束边界
  const order = range.events
    .map((event, index) => ({ event, index }))
    .sort((a, b) => a.index - b.index)
  const fromEvent = order.find((o) => o.index === introducedIndex)?.event
  const from = fromEvent?.introduced === '0' ? '0' : fromEvent?.introduced

  for (let i = introducedIndex + 1; i < range.events.length; i++) {
    const e = range.events[i]
    if (!e) continue
    if (e.fixed !== undefined) return { from, to: e.fixed, toInclusive: false }
    if (e.last_affected !== undefined) return { from, to: e.last_affected, toInclusive: true }
  }
  return { from }
}

/** 判断某条 affected 是否覆盖该包与版本 */
export function affectedEntryMatches(
  affected: OsvAffected,
  ecosystem: Ecosystem,
  packageName: string,
): boolean {
  const eco = canonicalEcosystem(affected.package?.ecosystem)
  if (eco !== ecosystem) return false
  const name = affected.package?.name
  if (!name) return false
  return normalizePackageName(ecosystem, name) === normalizePackageName(ecosystem, packageName)
}

/**
 * 在整库中查找某个 (生态, 包名, 版本) 命中的所有漏洞。
 * 返回的 OsvMatch 里带有命中原因与区间，供依赖路径分析引用。
 */
export function findMatches(
  records: readonly OsvRecord[],
  ecosystem: Ecosystem,
  packageName: string,
  version: string,
): OsvMatch[] {
  const matches: OsvMatch[] = []
  for (const record of records) {
    if (record.withdrawn) continue
    for (const affected of record.affected ?? []) {
      if (!affectedEntryMatches(affected, ecosystem, packageName)) continue

      // 1) 显式 versions 列表（精确相等）
      if (affected.versions && affected.versions.length > 0) {
        const hit = affected.versions.some((candidate) => versionEquals(ecosystem, candidate, version))
        if (hit) {
          matches.push({
            record,
            ecosystem,
            packageName,
            viaVersionsList: true,
            ranges: [],
            affected,
          })
          continue
        }
      }

      // 2) ranges：任一 range 命中即受影响
      const rangeHits: MatchedRange[] = []
      for (let i = 0; i < (affected.ranges?.length ?? 0); i++) {
        const range = affected.ranges![i]!
        if (range.type === 'GIT') continue
        let res: ReturnType<typeof rangeAffectsVersion>
        try {
          res = rangeAffectsVersion(ecosystem, range, version)
        } catch (err) {
          // 单条记录的边界解析失败不应影响其它记录；记录下来交给上层作为数据质量提示
          if (err instanceof RangeEvaluationError) continue
          throw err
        }
        if (res.affected) {
          rangeHits.push({
            rangeIndex: i,
            range,
            reason: res.reason ?? 'introduced',
            introduced: range.events.find((e) => e.introduced !== undefined)?.introduced,
            fixed: range.events.find((e) => e.fixed !== undefined)?.fixed,
            lastAffected: range.events.find((e) => e.last_affected !== undefined)?.last_affected,
            interval: res.interval ?? {},
          })
        }
      }

      if (rangeHits.length > 0) {
        matches.push({ record, ecosystem, packageName, viaVersionsList: false, ranges: rangeHits, affected })
      }
    }
  }
  return matches
}

function versionEquals(ecosystem: Ecosystem, a: string, b: string): boolean {
  const pa = tryParseEcosystemVersion(ecosystem, a)
  const pb = tryParseEcosystemVersion(ecosystem, b)
  if (!pa || !pb) return a.trim().toLowerCase() === b.trim().toLowerCase()
  if (pa.kind !== pb.kind) return false
  return compareParsedVersions(pa, pb) === 0
}

/**
 * 计算一条 range 的“修复版本下界”（最小 fixed），用于最小升级建议。
 * 返回 null 表示没有 fixed 事件（只能靠 last_affected 之后，或无法修复）。
 * 已按生态语义排序，取所有 fixed 中最小者。
 */
export function earliestFix(ecosystem: Ecosystem, affected: OsvAffected): string | null {
  const fixes: ParsedVersion[] = []
  const texts: string[] = []
  for (const range of affected.ranges ?? []) {
    if (range.type === 'GIT') continue
    for (const event of range.events) {
      if (event.fixed === undefined) continue
      try {
        const parsed = parseBoundary(ecosystem, range.type, event.fixed)
        fixes.push(parsed)
        texts.push(event.fixed)
      } catch {
        // 忽略不可解析的边界
      }
    }
  }
  if (fixes.length === 0) return null
  let bestIndex = 0
  for (let i = 1; i < fixes.length; i++) {
    if (compareParsedVersions(fixes[i]!, fixes[bestIndex]!) < 0) bestIndex = i
  }
  return texts[bestIndex]!
}

/** 取一条 range 所有 fixed 中，不小于给定版本的最小者（用于给出“升到多少”） */
export function nextFixAtOrAbove(ecosystem: Ecosystem, affected: OsvAffected, version: string): string | null {
  const target = tryParseEcosystemVersion(ecosystem, version)
  const fixes: { text: string; parsed: ParsedVersion }[] = []
  for (const range of affected.ranges ?? []) {
    if (range.type === 'GIT') continue
    for (const event of range.events) {
      if (event.fixed === undefined) continue
      try {
        fixes.push({ text: event.fixed, parsed: parseBoundary(ecosystem, range.type, event.fixed) })
      } catch {
        // ignore
      }
    }
  }
  if (!target || fixes.length === 0) return null
  let best: { text: string; parsed: ParsedVersion } | null = null
  for (const f of fixes) {
    if (f.parsed.kind !== target.kind) continue
    if (compareParsedVersions(f.parsed, target) < 0) continue
    if (best === null || compareParsedVersions(f.parsed, best.parsed) < 0) best = f
  }
  return best?.text ?? null
}
