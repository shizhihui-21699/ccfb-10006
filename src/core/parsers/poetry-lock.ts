/**
 * poetry.lock 解析器（Poetry 1.x / 2.x，lock-version 1.1 ~ 2.1）。
 *
 * 结构要点：
 * - [[package]] 是**已解析结果**（name + version），同一包名在 lock 里通常只出现一次；
 * - [package.dependencies] 是声明区间：值可能是字符串，也可能是
 *   `{version=..., markers=..., extras=...}` 数组（用于条件依赖 / 多约束）；
 * - Poetry 1.1 及更早用 [package.dependencies] 的 `name = "..."`，
 *   2.x 仍有 groups 字段；
 * - lock 文件**不含根项目条目**，根依赖需从 pyproject.toml 读取；若只给 lock，
 *   则把“没有任何包依赖它”的包视为顶层入口作为推断（UI 明确标注为推断）。
 *
 * 解析时对 marker 不做求值（缺少 Python 环境信息），而是保留原文并在 UI 里提示；
 * 这一点宁可显式暴露，也不静默丢弃条件依赖。
 */

import { parse as parseToml } from 'smol-toml'
import { normalizePypiName } from '../versions/pep440'
import type { DependencyGraph, DependencyEdge, PackageNode, Requirement, RootInfo } from './graph'

const ROOT_ID = '<root>'

interface RawDependencyObject {
  version?: string
  markers?: string
  extras?: string[]
  optional?: boolean
  python?: string
  platform?: string
  [key: string]: unknown
}

interface RawPoetryPackage {
  name?: string
  version?: string
  description?: string
  optional?: boolean
  'python-versions'?: string
  groups?: string[]
  files?: unknown[]
  source?: { type?: string; url?: string; reference?: string }
  dependencies?: Record<string, string | RawDependencyObject | Array<string | RawDependencyObject>>
  extras?: Record<string, string[]>
  [key: string]: unknown
}

interface RawPoetryLock {
  package?: RawPoetryPackage[]
  metadata?: {
    'lock-version'?: string
    'python-versions'?: string
    'content-hash'?: string
    [key: string]: unknown
  }
  [key: string]: unknown
}

function normalizeSpec(value: string | RawDependencyObject | Array<string | RawDependencyObject>): {
  spec?: string
  optional: boolean
  markers?: string
  extras?: string[]
} {
  if (typeof value === 'string') return { spec: value, optional: false }
  if (Array.isArray(value)) {
    // 多约束：合并为一个展示串；标记原文保留
    const specs = value.map((v) => (typeof v === 'string' ? v : v.version)).filter((v): v is string => typeof v === 'string')
    const markers = value
      .map((v) => (typeof v === 'string' ? undefined : v.markers))
      .filter((m): m is string => typeof m === 'string')
    return {
      spec: specs.length ? specs.join(' || ') : undefined,
      optional: value.some((v) => typeof v !== 'string' && v.optional === true),
      markers: markers.length ? markers.join(' or ') : undefined,
    }
  }
  return {
    spec: typeof value.version === 'string' ? value.version : undefined,
    optional: value.optional === true,
    markers: typeof value.markers === 'string' ? value.markers : undefined,
    extras: Array.isArray(value.extras) ? value.extras : undefined,
  }
}

export interface PyprojectRoot {
  name?: string
  version?: string
  /** 依赖声明：name → 区间（规范化后的包名作为 key） */
  requirements: Requirement[]
}

/**
 * 解析 pyproject.toml 的根依赖（Poetry 与 PEP 621 两种写法）。
 * 只取版本声明，不解析 `[tool.poetry.extras]` 的实际启用状态。
 */
export function parsePyprojectRoot(text: string): PyprojectRoot {
  const doc = parseToml(text) as Record<string, unknown>
  const requirements: Requirement[] = []

  const pushSpec = (rawName: string, rawSpec: unknown, kind: Requirement['kind']): void => {
    let name = rawName
    let spec: string | undefined
    if (typeof rawSpec === 'string') {
      spec = rawSpec.trim()
    } else if (rawSpec && typeof rawSpec === 'object' && !Array.isArray(rawSpec)) {
      const obj = rawSpec as RawDependencyObject & { git?: string; path?: string; url?: string }
      if (typeof obj.version === 'string') spec = obj.version
      else if (obj.git) spec = undefined
      else if (obj.path) spec = undefined
      // extras 写在名字后面，例如 "requests[socks]"
    }
    // PEP 621 风格： "requests>=2.25" / "requests[socks]>=2.0; python_version<'3.10'"
    if (typeof rawName === 'string' && (rawName.includes('>') || rawName.includes('<') || rawName.includes('=') || rawName.includes('['))) {
      const m = /^\s*([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*(.*)$/.exec(rawName)
      if (m) {
        name = m[1]!
        const rest = m[2]!.split(';')[0]!.trim()
        if (rest !== '') spec = rest
      }
    }
    if (spec === '') spec = '*'
    requirements.push({ name: normalizePypiName(name), spec, kind: kind ?? 'normal', fromId: ROOT_ID })
  }

  // PEP 621: [project] dependencies / optional-dependencies
  const project = doc.project as Record<string, unknown> | undefined
  if (project && typeof project === 'object') {
    const deps = project.dependencies
    if (Array.isArray(deps)) {
      for (const dep of deps) if (typeof dep === 'string') pushSpec(dep, undefined, 'normal')
    }
    const optional = project['optional-dependencies'] as Record<string, unknown> | undefined
    if (optional && typeof optional === 'object') {
      for (const list of Object.values(optional)) {
        if (Array.isArray(list)) for (const dep of list) if (typeof dep === 'string') pushSpec(dep, undefined, 'optional')
      }
    }
  }

  // Poetry 1.x: [tool.poetry] dependencies / dev-dependencies / group.*.dependencies
  const tool = doc.tool as Record<string, unknown> | undefined
  const poetry = tool?.poetry as Record<string, unknown> | undefined
  if (poetry && typeof poetry === 'object') {
    for (const section of ['dependencies', 'dev-dependencies'] as const) {
      const deps = poetry[section] as Record<string, unknown> | undefined
      if (!deps || typeof deps !== 'object') continue
      for (const [name, spec] of Object.entries(deps)) {
        if (name.toLowerCase() === 'python') continue // Python 版本声明不是包依赖
        pushSpec(name, spec, section === 'dev-dependencies' ? 'dev' : 'normal')
      }
    }
    const groups = poetry.group as Record<string, unknown> | undefined
    if (groups && typeof groups === 'object') {
      for (const [groupName, group] of Object.entries(groups)) {
        if (!group || typeof group !== 'object') continue
        const deps = (group as Record<string, unknown>).dependencies as Record<string, unknown> | undefined
        if (!deps || typeof deps !== 'object') continue
        for (const [name, spec] of Object.entries(deps)) pushSpec(name, spec, groupName === 'dev' ? 'dev' : 'normal')
      }
    }
  }

  return {
    name: typeof project?.name === 'string' ? project.name : typeof poetry?.name === 'string' ? poetry.name : undefined,
    version: typeof project?.version === 'string' ? project.version : typeof poetry?.version === 'string' ? poetry.version : undefined,
    requirements,
  }
}

export function parsePoetryLock(
  text: string,
  sourceLabel = 'poetry.lock',
  pyproject?: PyprojectRoot,
): DependencyGraph {
  let doc: RawPoetryLock
  try {
    doc = parseToml(text) as RawPoetryLock
  } catch (err) {
    return {
      ecosystem: 'PyPI',
      nodes: new Map(),
      roots: [],
      edges: [],
      issues: [{ level: 'error', message: `poetry.lock 不是合法 TOML：${(err as Error).message}` }],
      requirementSpecsAvailable: true,
      sourceLabel,
    }
  }

  const issues: { level: 'warning' | 'error'; message: string }[] = []
  const packages = Array.isArray(doc.package) ? doc.package : []
  if (packages.length === 0) {
    return {
      ecosystem: 'PyPI',
      nodes: new Map(),
      roots: [],
      edges: [],
      issues: [{ level: 'error', message: 'poetry.lock 中没有 [[package]] 条目' }],
      requirementSpecsAvailable: true,
      sourceLabel,
    }
  }

  const lockVersion = doc.metadata?.['lock-version']
  if (lockVersion && !/^2\.|^1\.1/.test(String(lockVersion))) {
    issues.push({ level: 'warning', message: `未验证的 lock-version=${String(lockVersion)}，按 2.x 结构解析` })
  }

  // 同名包在 lock 里应唯一；若出现重复（多 source），保留第一条并告警
  const byName = new Map<string, RawPoetryPackage>()
  for (const pkg of packages) {
    if (typeof pkg.name !== 'string' || typeof pkg.version !== 'string') {
      issues.push({ level: 'warning', message: '存在缺少 name/version 的 [[package]]，已跳过' })
      continue
    }
    const key = normalizePypiName(pkg.name)
    if (byName.has(key)) {
      issues.push({
        level: 'warning',
        message: `包 ${pkg.name} 在锁文件里出现多次（不同 source），仅使用首个版本 ${byName.get(key)!.version}`,
      })
      continue
    }
    byName.set(key, pkg)
  }

  const nodes = new Map<string, PackageNode>()
  const idOf = (normalizedName: string): string => `pypi:${normalizedName}`

  for (const [key, pkg] of byName) {
    const groups = Array.isArray(pkg.groups) ? pkg.groups : []
    nodes.set(idOf(key), {
      id: idOf(key),
      ecosystem: 'PyPI',
      name: pkg.name!,
      version: pkg.version!,
      source: pkg.source?.url ?? pkg.source?.type,
      direct: false,
      dev: groups.includes('dev') && !groups.includes('main'),
      optional: pkg.optional === true,
      requirements: [],
      resolved: new Map(),
      meta: {
        description: pkg.description,
        pythonVersions: pkg['python-versions'],
        groups,
        files: Array.isArray(pkg.files) ? pkg.files.length : undefined,
      },
    })
  }

  const edges: DependencyEdge[] = []
  const requirementMap = new Map<string, Requirement[]>()
  const resolvedMap = new Map<string, Map<string, string[]>>()

  for (const [key, pkg] of byName) {
    const fromId = idOf(key)
    const reqs: Requirement[] = []
    const resolved = new Map<string, string[]>()
    const deps = pkg.dependencies
    if (deps && typeof deps === 'object') {
      for (const [rawName, rawSpec] of Object.entries(deps)) {
        const targetKey = normalizePypiName(rawName)
        const normalized = normalizeSpec(rawSpec)
        const requirement: Requirement = {
          name: targetKey,
          spec: normalized.spec,
          kind: normalized.optional ? 'optional' : 'normal',
          optional: normalized.optional || undefined,
          fromId,
        }
        reqs.push(requirement)
        if (normalized.markers) {
          issues.push({
            level: 'warning',
            message: `${pkg.name} 依赖 ${rawName} 带环境标记「${normalized.markers}」，marker 未求值，按无条件依赖处理`,
          })
        }
        if (!byName.has(targetKey)) {
          // extras 依赖（如 requests[socks]）会引用未安装的包，属正常
          if (!normalized.optional) {
            issues.push({
              level: 'warning',
              message: `${pkg.name}@${pkg.version} 声明了 ${rawName}（${normalized.spec ?? '无区间'}），但锁文件中没有该包`,
            })
          }
          continue
        }
        const targetId = idOf(targetKey)
        const list = resolved.get(targetKey) ?? []
        list.push(targetId)
        resolved.set(targetKey, list)
        edges.push({ fromId, toId: targetId, requirement })
      }
    }
    requirementMap.set(fromId, reqs)
    resolvedMap.set(fromId, resolved)
  }

  // 根依赖：优先用 pyproject.toml；否则推断“无人依赖的包”为顶层入口
  let rootRequirements: Requirement[] = []
  let rootName = pyproject?.name ?? 'Python 项目根'
  let rootVersion = pyproject?.version
  let inferredRoot = false

  if (pyproject && pyproject.requirements.length > 0) {
    rootRequirements = pyproject.requirements.map((r) => ({ ...r, fromId: ROOT_ID }))
    const missing = rootRequirements.filter((r) => !byName.has(normalizePypiName(r.name)))
    for (const m of missing) {
      issues.push({
        level: 'warning',
        message: `pyproject.toml 声明的依赖 ${m.name} 不在 poetry.lock 中（可能未安装或属于 extras）`,
      })
    }
  } else {
    inferredRoot = true
    const depended = new Set(edges.map((e) => e.toId))
    const topLevel = [...nodes.values()].filter((n) => !depended.has(n.id))
    rootRequirements = topLevel.map((n) => ({
      name: normalizePypiName(n.name),
      spec: undefined,
      kind: 'normal' as const,
      fromId: ROOT_ID,
    }))
    if (topLevel.length > 0) {
      issues.push({
        level: 'warning',
        message: `未提供 pyproject.toml，根依赖是推断的：把 ${topLevel.length} 个无人依赖的包视为顶层入口（可能含 extras 引入的包）`,
      })
    }
  }

  // 边：根 → 直接依赖
  const rootResolved = new Map<string, string[]>()
  for (const req of rootRequirements) {
    const key = normalizePypiName(req.name)
    if (!byName.has(key)) continue
    const targetId = idOf(key)
    rootResolved.set(key, [targetId])
    const node = nodes.get(targetId)
    if (node) nodes.set(targetId, { ...node, direct: true })
    edges.push({ fromId: ROOT_ID, toId: targetId, requirement: req })
  }

  const rootInfo: RootInfo = {
    id: ROOT_ID,
    name: rootName,
    version: rootVersion,
    requirements: rootRequirements,
    inferred: inferredRoot,
  }

  // 回填 requirements
  for (const [id, node] of nodes) {
    nodes.set(id, {
      ...node,
      requirements: requirementMap.get(id) ?? [],
      resolved: resolvedMap.get(id) ?? new Map(),
    })
  }

  nodes.set(ROOT_ID, {
    id: ROOT_ID,
    ecosystem: 'PyPI',
    name: rootName,
    version: rootVersion ?? '0',
    direct: true,
    dev: false,
    optional: false,
    requirements: rootRequirements,
    resolved: rootResolved,
    meta: { isRoot: true },
  })

  return {
    ecosystem: 'PyPI',
    nodes,
    roots: [rootInfo],
    edges,
    issues,
    requirementSpecsAvailable: true,
    sourceLabel,
  }
}
