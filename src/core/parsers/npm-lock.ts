/**
 * package-lock.json 解析器。
 *
 * 支持 lockfileVersion 1 / 2 / 3：
 * - v1：嵌套 `dependencies` 树，没有 packages 表。
 * - v2：同时有 `packages`（扁平的安装路径表）与 `dependencies`（兼容 v1 的树）。
 * - v3：只有 `packages`。
 *
 * 解析要点：
 * 1. 依赖解析用 Node 的真实解析算法：从声明者所在目录向上逐级查找
 *    `node_modules/<name>`，第一个命中的即解析目标。这一步必须做对，否则
 *    “哪条路径引入了漏洞包”会算错。
 * 2. 每个包的 `dependencies` / `optionalDependencies` / `peerDependencies`
 *    / `devDependencies` 都是**声明区间**，保留原文用于冲突分析。
 * 3. 根包（packages[""]）的 dependencies/devDependencies 构成直接依赖。
 * 4. workspace 场景下 packages 里会出现 `packages/a` 这类路径，同样按路径解析。
 * 5. 同名不同版本的多个副本会各自成为独立节点，id 用安装路径保证唯一。
 */

import type { DependencyGraph, DependencyEdge, PackageNode, Requirement, RootInfo } from './graph'

const ROOT_ID = '<root>'

interface RawPackageEntry {
  name?: string
  version?: string
  resolved?: string
  link?: boolean
  dev?: boolean
  optional?: boolean
  devOptional?: boolean
  license?: string
  dependencies?: Record<string, string>
  devDependencies?: Record<string, string>
  optionalDependencies?: Record<string, string>
  peerDependencies?: Record<string, string>
  [key: string]: unknown
}

interface RawNpmLock {
  name?: string
  version?: string
  lockfileVersion?: number
  packages?: Record<string, RawPackageEntry>
  dependencies?: Record<string, RawNestedDependency>
}

interface RawNestedDependency {
  version?: string
  resolved?: string
  requires?: Record<string, string>
  dependencies?: Record<string, RawNestedDependency>
  dev?: boolean
  optional?: boolean
  [key: string]: unknown
}

/** package name 来自路径：`node_modules/a/node_modules/@scope/b` → `@scope/b` */
function nameFromPath(path: string): string | null {
  const marker = 'node_modules/'
  const idx = path.lastIndexOf(marker)
  if (idx === -1) return null
  const rest = path.slice(idx + marker.length)
  if (rest === '') return null
  const parts = rest.split('/')
  if (parts[0]?.startsWith('@')) return parts.slice(0, 2).join('/')
  return parts[0] ?? null
}

/** 某安装路径的父目录（用于向上查找） */
function parentDir(path: string): string {
  const idx = path.lastIndexOf('/node_modules/')
  if (idx === -1) {
    if (path.startsWith('node_modules/')) return ''
    // workspace 目录：../..
    const trimmed = path.replace(/\/+$/, '')
    const slash = trimmed.lastIndexOf('/')
    return slash === -1 ? '' : trimmed.slice(0, slash)
  }
  return path.slice(0, idx)
}

/** Node 解析：从 fromDir 向上逐级找 node_modules/<name>，模拟真实安装布局 */
function resolveNpm(
  packages: Map<string, RawPackageEntry>,
  fromDir: string,
  name: string,
): string | null {
  let dir = fromDir
  for (;;) {
    const candidate = dir === '' ? `node_modules/${name}` : `${dir}/node_modules/${name}`
    if (packages.has(candidate)) return candidate
    if (dir === '') return null
    dir = parentDir(dir)
  }
}

function requirementKind(
  section: 'dependencies' | 'devDependencies' | 'optionalDependencies' | 'peerDependencies',
): Requirement['kind'] {
  return section === 'dependencies'
    ? 'normal'
    : section === 'devDependencies'
      ? 'dev'
      : section === 'optionalDependencies'
        ? 'optional'
        : 'peer'
}

export function parsePackageLock(text: string, sourceLabel = 'package-lock.json'): DependencyGraph {
  let raw: RawNpmLock
  try {
    raw = JSON.parse(text) as RawNpmLock
  } catch (err) {
    return {
      ecosystem: 'npm',
      nodes: new Map(),
      roots: [],
      edges: [],
      issues: [{ level: 'error', message: `package-lock.json 不是合法 JSON：${(err as Error).message}` }],
      requirementSpecsAvailable: true,
      sourceLabel,
    }
  }

  const issues: { level: 'warning' | 'error'; message: string }[] = []
  const version = raw.lockfileVersion
  if (version === undefined) {
    issues.push({ level: 'warning', message: '锁文件缺少 lockfileVersion，按 v1 树格式解析' })
  } else if (typeof version !== 'number' || version < 1 || version > 3) {
    issues.push({ level: 'warning', message: `未知的 lockfileVersion=${String(version)}，按 v3 的 packages 表解析` })
  }

  // 统一成“安装路径 → 条目”的表
  const packages = new Map<string, RawPackageEntry>()
  if (raw.packages && typeof raw.packages === 'object') {
    for (const [path, entry] of Object.entries(raw.packages)) {
      if (typeof entry !== 'object' || entry === null) continue
      packages.set(path, entry)
    }
  }
  if (packages.size === 0 && raw.dependencies && typeof raw.dependencies === 'object') {
    // v1：把嵌套树展开成路径表
    const walk = (deps: Record<string, RawNestedDependency>, prefix: string): void => {
      for (const [name, entry] of Object.entries(deps)) {
        if (typeof entry !== 'object' || entry === null) continue
        const path = `${prefix}node_modules/${name}`
        const converted: RawPackageEntry = {
          version: entry.version,
          resolved: entry.resolved,
          dev: entry.dev,
          optional: entry.optional,
          dependencies: entry.requires,
        }
        packages.set(path, converted)
        if (entry.dependencies) walk(entry.dependencies, `${path}/`)
      }
    }
    walk(raw.dependencies, '')
    issues.push({ level: 'warning', message: '按 lockfileVersion 1 的嵌套 dependencies 树解析（无 packages 表）' })
  }

  if (packages.size === 0) {
    return {
      ecosystem: 'npm',
      nodes: new Map(),
      roots: [],
      edges: [],
      issues: [...issues, { level: 'error', message: '锁文件中没有任何依赖条目' }],
      requirementSpecsAvailable: true,
      sourceLabel,
    }
  }

  const nodes = new Map<string, PackageNode>()
  const rootEntry = packages.get('') ?? {}

  // 根节点
  const rootRequirementList: Requirement[] = []
  for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as const) {
    const sectionDeps = rootEntry[section]
    if (!sectionDeps || typeof sectionDeps !== 'object') continue
    for (const [name, spec] of Object.entries(sectionDeps)) {
      if (typeof spec !== 'string') continue
      rootRequirementList.push({ name, spec, kind: requirementKind(section), fromId: ROOT_ID })
    }
  }
  const rootInfo: RootInfo = {
    id: ROOT_ID,
    name: raw.name ?? rootEntry.name ?? 'npm 项目根',
    version: raw.version ?? rootEntry.version,
    requirements: rootRequirementList,
    inferred: false,
  }

  // 先建立所有节点
  for (const [path, entry] of packages) {
    if (path === '') continue
    const name = entry.name ?? nameFromPath(path)
    if (!name || typeof entry.version !== 'string') {
      issues.push({ level: 'warning', message: `条目 ${path} 缺少 name/version，已跳过` })
      continue
    }
    if (entry.link) {
      // link 条目只是软链，真实内容在别处，避免重复节点
      continue
    }
    nodes.set(path, {
      id: path,
      ecosystem: 'npm',
      name,
      version: entry.version,
      source: entry.resolved,
      direct: false,
      dev: entry.dev === true || entry.devOptional === true,
      optional: entry.optional === true || entry.devOptional === true,
      license: typeof entry.license === 'string' ? entry.license : undefined,
      requirements: [],
      resolved: new Map(),
      meta: { installPath: path },
    })
  }

  // 建立边：每个包的声明依赖 → Node 解析
  const edges: DependencyEdge[] = []
  const requirementMap = new Map<string, Requirement[]>()
  const resolvedMap = new Map<string, Map<string, string[]>>()

  const addEdges = (fromId: string, fromDir: string, entry: RawPackageEntry): void => {
    const reqs: Requirement[] = []
    const resolved = new Map<string, string[]>()
    for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as const) {
      const sectionDeps = entry[section]
      if (!sectionDeps || typeof sectionDeps !== 'object') continue
      for (const [name, spec] of Object.entries(sectionDeps)) {
        if (typeof spec !== 'string') continue
        const requirement: Requirement = {
          name,
          spec,
          kind: requirementKind(section),
          optional: section === 'optionalDependencies' ? true : undefined,
          fromId,
        }
        reqs.push(requirement)
        const targetPath = resolveNpm(packages, fromDir, name)
        if (targetPath === null) {
          // dev/optional/peer 依赖在安装时可能不存在，这是正常的
          if (section === 'dependencies') {
            issues.push({
              level: 'warning',
              message: `${fromId === ROOT_ID ? '根包' : fromId} 声明的依赖 ${name}@${spec} 在 node_modules 中找不到解析结果`,
            })
          }
          continue
        }
        const list = resolved.get(name) ?? []
        list.push(targetPath)
        resolved.set(name, list)
        if (nodes.has(targetPath)) {
          edges.push({ fromId, toId: targetPath, requirement })
        }
      }
    }
    requirementMap.set(fromId, reqs)
    resolvedMap.set(fromId, resolved)
  }

  addEdges(ROOT_ID, '', rootEntry)
  for (const [path, entry] of packages) {
    if (path === '' || !nodes.has(path)) continue
    addEdges(path, path, entry)
  }

  // 回填 requirements / resolved / direct 标记
  for (const [id, node] of nodes) {
    const reqs = requirementMap.get(id) ?? []
    const resolved = resolvedMap.get(id) ?? new Map<string, string[]>()
    const isDirect = rootRequirementList.some((r) => (resolved.get(r.name) ?? []).includes(id))
    nodes.set(id, {
      ...node,
      requirements: reqs,
      resolved,
      direct: isDirect,
      dev: node.dev || false,
    })
  }

  const rootNode: PackageNode = {
    id: ROOT_ID,
    ecosystem: 'npm',
    name: rootInfo.name,
    version: rootInfo.version ?? '0.0.0',
    direct: true,
    dev: false,
    optional: false,
    requirements: rootRequirementList,
    resolved: resolvedMap.get(ROOT_ID) ?? new Map(),
    meta: { isRoot: true },
  }
  nodes.set(ROOT_ID, rootNode)

  // 推断 dev 传播：devDependencies 的直接依赖及其子树标记为 dev
  propagateDevFlags(nodes, edges, rootRequirementList)

  return {
    ecosystem: 'npm',
    nodes,
    roots: [rootInfo],
    edges,
    issues,
    requirementSpecsAvailable: true,
    sourceLabel,
  }
}

/** 从 dev 依赖出发，把只在 dev 子树里出现的包标记为 dev（与 npm 的 dev 标记语义一致） */
function propagateDevFlags(
  nodes: Map<string, PackageNode>,
  edges: DependencyEdge[],
  rootRequirements: Requirement[],
): void {
  const devRoots = new Set<string>()
  for (const req of rootRequirements) {
    if (req.kind !== 'dev') continue
    const resolved = nodes.get(ROOT_ID)?.resolved.get(req.name) ?? []
    for (const id of resolved) devRoots.add(id)
  }
  const devReachable = new Set<string>()
  const stack = [...devRoots]
  while (stack.length > 0) {
    const id = stack.pop()!
    if (devReachable.has(id)) continue
    devReachable.add(id)
    for (const edge of edges) {
      if (edge.fromId === id) stack.push(edge.toId)
    }
  }
  for (const id of devReachable) {
    const node = nodes.get(id)
    if (node && !node.direct) nodes.set(id, { ...node, dev: true })
  }
}
