/**
 * OSV schema 的类型定义与解析。
 *
 * 参考 https://ossf.github.io/osv-schema/。
 * 支持两种形态：
 * - 单条记录（含 id / affected / ranges / versions）
 * - 导出的批量文件：JSON 数组，或每行一条 JSON（OSV 官方 all.zip 解包后的形态）
 */

import type { Ecosystem } from '../versions/ecosystem'

export interface OsvEvent {
  introduced?: string
  fixed?: string
  last_affected?: string
  limit?: string
}

export interface OsvRange {
  type: 'SEMVER' | 'ECOSYSTEM' | 'GIT'
  /** GIT 范围没有 ecosystem_specific */
  events: OsvEvent[]
  /** OSV schema 里 GIT 范围用于 repo 信息 */
  repo?: string
}

export interface OsvAffected {
  package?: {
    ecosystem?: string
    name?: string
    purl?: string
  }
  ranges?: OsvRange[]
  versions?: string[]
  ecosystem_specific?: {
    severity?: string
    [key: string]: unknown
  }
  database_specific?: Record<string, unknown>
}

export interface OsvSeverity {
  type?: string
  score?: string
}

export interface OsvRecord {
  id: string
  summary?: string
  details?: string
  aliases?: string[]
  related?: string[]
  modified?: string
  published?: string
  withdrawn?: string
  severity?: OsvSeverity[]
  affected?: OsvAffected[]
  references?: { type?: string; url?: string }[]
  database_specific?: Record<string, unknown>
}

export interface OsvParseIssue {
  source: string
  level: 'error' | 'warning'
  message: string
}

export interface OsvDatabase {
  records: OsvRecord[]
  issues: OsvParseIssue[]
  /** 每条记录已解析的生态（用于 UI 过滤） */
  ecosystems: Ecosystem[]
}

const KNOWN_ECOSYSTEMS: Record<string, Ecosystem> = {
  npm: 'npm',
  pypi: 'PyPI',
  'crates.io': 'crates.io',
}

export function canonicalEcosystem(raw: string | undefined): Ecosystem | null {
  if (!raw) return null
  return KNOWN_ECOSYSTEMS[raw.trim().toLowerCase()] ?? null
}

function isRecordLike(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function validateRecord(value: unknown, source: string, issues: OsvParseIssue[]): OsvRecord | null {
  if (!isRecordLike(value)) {
    issues.push({ source, level: 'error', message: '记录不是 JSON 对象' })
    return null
  }
  if (typeof value.id !== 'string' || value.id.trim() === '') {
    issues.push({ source, level: 'error', message: '记录缺少字符串 id 字段' })
    return null
  }

  const affected = value.affected
  if (affected !== undefined && !Array.isArray(affected)) {
    issues.push({ source, level: 'error', message: `${value.id}: affected 不是数组` })
    return null
  }

  // 逐条校验 range 的事件结构；结构错误只丢弃该 range，不丢整条记录
  const cleanedAffected: OsvAffected[] = []
  for (const rawAffected of (affected ?? []) as unknown[]) {
    if (!isRecordLike(rawAffected)) {
      issues.push({ source, level: 'warning', message: `${value.id}: affected 条目不是对象，已跳过` })
      continue
    }
    const entry: OsvAffected = {
      package: isRecordLike(rawAffected.package)
        ? {
            ecosystem: typeof rawAffected.package.ecosystem === 'string' ? rawAffected.package.ecosystem : undefined,
            name: typeof rawAffected.package.name === 'string' ? rawAffected.package.name : undefined,
            purl: typeof rawAffected.package.purl === 'string' ? rawAffected.package.purl : undefined,
          }
        : undefined,
      versions: Array.isArray(rawAffected.versions)
        ? (rawAffected.versions.filter((v) => typeof v === 'string') as string[])
        : undefined,
      ecosystem_specific: isRecordLike(rawAffected.ecosystem_specific) ? rawAffected.ecosystem_specific : undefined,
    }

    if (Array.isArray(rawAffected.ranges)) {
      const ranges: OsvRange[] = []
      for (const rawRange of rawAffected.ranges) {
        if (!isRecordLike(rawRange)) {
          issues.push({ source, level: 'warning', message: `${value.id}: range 不是对象，已跳过` })
          continue
        }
        const type = rawRange.type
        if (typeof type !== 'string' || (type !== 'SEMVER' && type !== 'ECOSYSTEM' && type !== 'GIT')) {
          issues.push({ source, level: 'warning', message: `${value.id}: 未知 range 类型 ${JSON.stringify(type)}，已跳过` })
          continue
        }
        if (!Array.isArray(rawRange.events)) {
          issues.push({ source, level: 'error', message: `${value.id}: ${type} range 缺少 events 数组，已跳过` })
          continue
        }
        const events: OsvEvent[] = []
        let structuralError = false
        for (const rawEvent of rawRange.events) {
          if (!isRecordLike(rawEvent)) {
            structuralError = true
            break
          }
          const keys = ['introduced', 'fixed', 'last_affected', 'limit'].filter((k) => k in rawEvent)
          if (keys.length !== 1 || typeof rawEvent[keys[0]!] !== 'string') {
            structuralError = true
            break
          }
          events.push({ [keys[0]!]: rawEvent[keys[0]!] as string } as OsvEvent)
        }
        if (structuralError) {
          issues.push({ source, level: 'error', message: `${value.id}: events 结构非法（每个事件必须且只能含一个字符串键），该 range 已跳过` })
          continue
        }
        if (!events.some((e) => e.introduced !== undefined)) {
          issues.push({ source, level: 'error', message: `${value.id}: range 至少需要一个 introduced 事件，该 range 已跳过` })
          continue
        }
        if (events.some((e) => e.fixed !== undefined) && events.some((e) => e.last_affected !== undefined)) {
          issues.push({ source, level: 'error', message: `${value.id}: 同一 range 不能同时使用 fixed 与 last_affected，该 range 已跳过` })
          continue
        }
        ranges.push({ type, events, repo: typeof rawRange.repo === 'string' ? rawRange.repo : undefined })
      }
      if (rawAffected.ranges.length > 0 && ranges.length === 0) {
        issues.push({ source, level: 'warning', message: `${value.id}: affected 条目的所有 range 均非法，已跳过该条目` })
        continue
      }
      entry.ranges = ranges
    }

    if (entry.package === undefined && entry.ranges === undefined && entry.versions === undefined) {
      issues.push({ source, level: 'warning', message: `${value.id}: affected 条目为空，已跳过` })
      continue
    }
    cleanedAffected.push(entry)
  }

  if (cleanedAffected.length === 0) {
    issues.push({ source, level: 'error', message: `${value.id}: 没有任何可用的 affected 条目` })
    return null
  }

  const record: OsvRecord = {
    id: value.id.trim(),
    summary: typeof value.summary === 'string' ? value.summary : undefined,
    details: typeof value.details === 'string' ? value.details : undefined,
    aliases: Array.isArray(value.aliases) ? (value.aliases.filter((x) => typeof x === 'string') as string[]) : undefined,
    modified: typeof value.modified === 'string' ? value.modified : undefined,
    published: typeof value.published === 'string' ? value.published : undefined,
    withdrawn: typeof value.withdrawn === 'string' ? value.withdrawn : undefined,
    severity: Array.isArray(value.severity)
      ? (value.severity as OsvSeverity[]).filter((s) => isRecordLike(s))
      : undefined,
    affected: cleanedAffected,
    references: Array.isArray(value.references)
      ? ((value.references as unknown[]).filter((r) => isRecordLike(r)) as OsvRecord['references'])
      : undefined,
    database_specific: isRecordLike(value.database_specific) ? value.database_specific : undefined,
  }
  return record
}

/** 解析一个 OSV 文件内容（自动识别单条 / 数组 / JSONL） */
export function parseOsvText(text: string, source = '<OSV>'): OsvDatabase {
  const issues: OsvParseIssue[] = []
  const records: OsvRecord[] = []
  let raw: unknown[] = []

  const trimmed = text.trim()
  if (trimmed === '') {
    return { records, issues: [{ source, level: 'error', message: '文件为空' }], ecosystems: [] }
  }

  try {
    const parsed: unknown = JSON.parse(trimmed)
    if (Array.isArray(parsed)) raw = parsed
    else raw = [parsed]
  } catch {
    // 尝试 JSONL（每行一条）
    const lines = trimmed.split('\n').map((l) => l.trim()).filter((l) => l !== '')
    let parsedAll = true
    for (const line of lines) {
      try {
        raw.push(JSON.parse(line))
      } catch {
        parsedAll = false
        break
      }
    }
    if (!parsedAll) {
      return {
        records,
        issues: [{ source, level: 'error', message: '既不是合法 JSON，也不是合法的 JSON Lines（每行一条记录）' }],
        ecosystems: [],
      }
    }
  }

  for (const item of raw) {
    const rec = validateRecord(item, source, issues)
    if (rec) records.push(rec)
  }

  const ecosystems = new Set<Ecosystem>()
  for (const rec of records) {
    for (const aff of rec.affected ?? []) {
      const eco = canonicalEcosystem(aff.package?.ecosystem)
      if (eco) ecosystems.add(eco)
    }
  }

  if (records.length === 0 && issues.every((i) => i.level !== 'error')) {
    issues.push({ source, level: 'error', message: '文件中没有任何可用记录' })
  }

  return { records, issues, ecosystems: [...ecosystems] }
}

/** 合并多个 OSV 库文件 */
export function mergeOsvDatabases(dbs: OsvDatabase[]): OsvDatabase {
  const records: OsvRecord[] = []
  const issues: OsvParseIssue[] = []
  const idSeen = new Map<string, OsvRecord>()
  for (const db of dbs) {
    issues.push(...db.issues)
    for (const rec of db.records) {
      const existing = idSeen.get(rec.id)
      if (existing) {
        // 同一漏洞 ID 出现多次：合并 affected 条目，保留首个元数据
        existing.affected = [...(existing.affected ?? []), ...(rec.affected ?? [])]
        continue
      }
      const copy: OsvRecord = { ...rec }
      idSeen.set(rec.id, copy)
      records.push(copy)
    }
  }
  const ecosystems = new Set<Ecosystem>()
  for (const rec of records) {
    for (const aff of rec.affected ?? []) {
      const eco = canonicalEcosystem(aff.package?.ecosystem)
      if (eco) ecosystems.add(eco)
    }
  }
  return { records, issues, ecosystems: [...ecosystems] }
}
