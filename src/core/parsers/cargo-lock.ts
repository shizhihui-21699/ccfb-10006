/**
 * Cargo.lock 解析器（lockfile version 1 ~ 4）。
 *
 * 结构要点：
 * - [[package]] 的 dependencies 是**已解析结果**，元素可能是
 *   `name`、`name version`、`name version (source)` 三种形式；
 *   只有 name 时表示“唯一同名包”。
 * - 同一个 crate 可以出现多个版本，因此必须用 (name, version) 定位节点。
 * - **Cargo.lock 不记录声明区间**（那是 Cargo.toml 的内容），所以：
 *   · 依赖边只有“存在性”，没有版本约束；
 *   · 升级冲突分析会明确标注“Cargo 锁文件不提供约束，无法判断是否会引入冲突”。
 * - 根包是没有 source 字段的 package（本地 workspace 成员）。
 */

import { parse as parseToml } from 'smol-toml'
import { parseSemVer, tryParseSemVer } from '../versions/semver-core'
import type { DependencyGraph, DependencyEdge, PackageNode, Requirement, RootInfo } from './graph'

const ROOT_PREFIX = '<root>:'

interface RawCargoPackage {
  name?: string
  version?: string
  source?: string
  checksum?: string
  dependencies?: string[]
  [key: string]: unknown
}

interface RawCargoLock {
  version?: number
  package?: RawCargoPackage[]
  [key: string]: unknown
}

const idOf = (name: string, version: string): string => `crate:${name}@${version}`

/** 解析 "name" / "name version" / "name version (source)" 三元组 */
function parseDependencyRef(ref: string): { name: string; version?: string; source?: string } {
  const trimmed = ref.trim()
  const m = /^(\S+)(?:\s+(\S+))?(?:\s+\((.+)\))?$/.exec(trimmed)
  if (!m) return { name: trimmed }
  return { name: m[1]!, version: m[2], source: m[3] }
}

export function parseCargoLock(text: string, sourceLabel = 'Cargo.lock'): DependencyGraph {
  let doc: RawCargoLock
  try {
    doc = parseToml(text) as RawCargoLock
  } catch (err) {
    return {
      ecosystem: 'crates.io',
      nodes: new Map(),
      roots: [],
      edges: [],
      issues: [{ level: 'error', message: `Cargo.lock 不是合法 TOML：${(err as Error).message}` }],
      requirementSpecsAvailable: false,
      sourceLabel,
    }
  }

  const issues: { level: 'warning' | 'error'; message: string }[] = []
  const packages = Array.isArray(doc.package) ? doc.package : []
  if (packages.length === 0) {
    return {
      ecosystem: 'crates.io',
      nodes: new Map(),
      roots: [],
      edges: [],
      issues: [{ level: 'error', message: 'Cargo.lock 中没有 [[package]] 条目' }],
      requirementSpecsAvailable: false,
      sourceLabel,
    }
  }

  const lockVersion = doc.version
  if (lockVersion !== undefined && (typeof lockVersion !== 'number' || lockVersion < 1 || lockVersion > 4)) {
    issues.push({ level: 'warning', message: `未知的 Cargo.lock version=${String(lockVersion)}，按 v3/v4 结构解析` })
  }
  if (lockVersion === 1) {
    issues.push({ level: 'warning', message: 'Cargo.lock v1 的 dependencies 不带版本号，存在多版本 crate 时无法精确归属' })
  }

  // 建立 (name, version) 索引
  const nodes = new Map<string, PackageNode>()
  const byName = new Map<string, string[]>()
  for (const pkg of packages) {
    if (typeof pkg.name !== 'string' || typeof pkg.version !== 'string') {
      issues.push({ level: 'warning', message: '存在缺少 name/version 的 [[package]]，已跳过' })
      continue
    }
    const id = idOf(pkg.name, pkg.version)
    const isRootPackage = pkg.source === undefined
    if (!byName.has(pkg.name)) byName.set(pkg.name, [])
    byName.get(pkg.name)!.push(id)
    nodes.set(id, {
      id,
      ecosystem: 'crates.io',
      name: pkg.name,
      version: pkg.version,
      source: pkg.source,
      direct: false,
      dev: false,
      optional: false,
      requirements: [],
      resolved: new Map(),
      meta: {
        checksum: pkg.checksum,
        isWorkspaceMember: isRootPackage,
      },
    })
  }

  // 找出根包：没有 source 的条目
  const rootIds = [...nodes.values()].filter((n) => n.meta?.isWorkspaceMember === true)
  if (rootIds.length === 0) {
    issues.push({ level: 'error', message: 'Cargo.lock 中没有找到本地包（无 source 字段的条目），无法确定依赖入口' })
  }

  const edges: DependencyEdge[] = []
  const requirementMap = new Map<string, Requirement[]>()
  const resolvedMap = new Map<string, Map<string, string[]>>()

  for (const pkg of packages) {
    if (typeof pkg.name !== 'string' || typeof pkg.version !== 'string') continue
    const fromId = idOf(pkg.name, pkg.version)
    const reqs: Requirement[] = []
    const resolved = new Map<string, string[]>()
    for (const ref of Array.isArray(pkg.dependencies) ? pkg.dependencies : []) {
      if (typeof ref !== 'string') continue
      const parsed = parseDependencyRef(ref)
      let targetId: string | null = null

      if (parsed.version !== undefined) {
        const candidate = idOf(parsed.name, parsed.version)
        if (nodes.has(candidate)) targetId = candidate
      } else {
        const candidates = byName.get(parsed.name) ?? []
        if (candidates.length === 1) {
          targetId = candidates[0]!
        } else if (candidates.length > 1) {
          // v1 锁文件里同名多版本无法区分，选语义版本最小者并告警
          const sorted = [...candidates].sort((a, b) => {
            const va = tryParseSemVer(nodes.get(a)!.version)
            const vb = tryParseSemVer(nodes.get(b)!.version)
            if (!va || !vb) return 0
            return va.major - vb.major || va.minor - vb.minor || va.patch - vb.patch
          })
          targetId = sorted[0]!
          issues.push({
            level: 'warning',
            message: `${fromId} 的依赖 ${parsed.name} 在锁文件中有 ${candidates.length} 个版本，但引用未标版本，已按最小版本 ${nodes.get(targetId)!.version} 归属`,
          })
        }
      }

      if (targetId === null) {
        issues.push({ level: 'warning', message: `${fromId} 的依赖 ${ref} 在锁文件中找不到对应包` })
        continue
      }

      const requirement: Requirement = { name: parsed.name, fromId }
      reqs.push(requirement)
      const list = resolved.get(parsed.name) ?? []
      list.push(targetId)
      resolved.set(parsed.name, list)
      edges.push({ fromId, toId: targetId, requirement })
    }
    requirementMap.set(fromId, reqs)
    resolvedMap.set(fromId, resolved)
  }

  // 回填
  for (const [id, node] of nodes) {
    nodes.set(id, {
      ...node,
      requirements: requirementMap.get(id) ?? [],
      resolved: resolvedMap.get(id) ?? new Map(),
    })
  }

  // 根节点：Cargo.lock 可以有多个 workspace 成员，因此每个根包各自成为一个 RootInfo
  const roots: RootInfo[] = []
  const rootNodeIds: string[] = []
  for (const node of rootIds) {
    const rootId = `${ROOT_PREFIX}${node.name}`
    const requirements: Requirement[] = node.requirements.map((r) => ({ ...r, fromId: rootId }))
    roots.push({
      id: rootId,
      name: node.name,
      version: node.version,
      requirements,
      inferred: false,
    })
    rootNodeIds.push(node.id)
    nodes.set(rootId, {
      id: rootId,
      ecosystem: 'crates.io',
      name: node.name,
      version: node.version,
      direct: true,
      dev: false,
      optional: false,
      requirements,
      resolved: node.resolved,
      meta: { isRoot: true, workspaceMemberId: node.id },
    })
  }

  // 根节点 → 其直接依赖；同时标记直接依赖
  const finalEdges: DependencyEdge[] = [...edges]
  for (const root of roots) {
    const member = nodes.get(`${ROOT_PREFIX}${root.name}`)
    if (!member) continue
    const memberNode = nodes.get(member.meta!.workspaceMemberId as string)
    if (!memberNode) continue
    for (const edge of finalEdges.filter((e) => e.fromId === memberNode.id)) {
      finalEdges.push({ fromId: root.id, toId: edge.toId, requirement: { ...edge.requirement, fromId: root.id } })
      const target = nodes.get(edge.toId)
      if (target) nodes.set(edge.toId, { ...target, direct: true })
    }
  }
  // 移除中间层“workspace 成员包”的节点，避免图上出现重复路径
  for (const memberId of rootNodeIds) nodes.delete(memberId)
  const cleanedEdges = finalEdges.filter((e) => !rootNodeIds.includes(e.fromId) && !rootNodeIds.includes(e.toId))

  return {
    ecosystem: 'crates.io',
    nodes,
    roots,
    edges: cleanedEdges,
    issues,
    requirementSpecsAvailable: false,
    sourceLabel,
  }
}

/** 供 UI 显示：版本合法性检查（Cargo 拒绝 v 前缀与缺段版本） */
export function validateCargoVersion(version: string): string | null {
  try {
    parseSemVer(version, false)
    return null
  } catch (err) {
    return (err as Error).message
  }
}
