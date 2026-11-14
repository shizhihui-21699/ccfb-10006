/**
 * 统一的依赖图模型。
 *
 * 三份锁文件的信息密度不同，这里显式记录“哪些信息缺失”，避免下游把
 * “未知”误当成“无冲突”：
 * - npm（lockfileVersion 2/3）：每个包记录了自己对依赖的**声明区间**，
 *   因此可以离线判断“升级后父包的约束是否仍满足”。
 * - Poetry：`[package.dependencies]` 同样是声明区间，可用。
 * - Cargo：Cargo.lock 只记录解析结果，**不含声明区间**，因此父包约束未知。
 *   这一点在 UI 与升级分析中都明确标注，不用猜测填坑。
 */

import type { Ecosystem } from '../versions/ecosystem'

export interface Requirement {
  readonly name: string
  /** 声明区间原文；undefined 表示该生态的锁文件不提供（如 Cargo） */
  readonly spec?: string
  readonly optional?: boolean
  readonly kind?: 'normal' | 'dev' | 'build' | 'peer' | 'extra' | 'optional'
  /** 该依赖声明来自哪个包；根清单为 null */
  readonly fromId: string
}

export interface PackageNode {
  readonly id: string
  readonly ecosystem: Ecosystem
  readonly name: string
  readonly version: string
  /** 锁文件里的来源（registry / git / path 等） */
  readonly source?: string
  /** 直接依赖（根清单声明） */
  readonly direct: boolean
  readonly dev: boolean
  readonly optional: boolean
  readonly license?: string
  readonly yanked?: boolean
  /** 本包声明的依赖（出边） */
  readonly requirements: ReadonlyArray<Requirement>
  /** 解析后指向的包 id（入边关系由 requirements 决定） */
  readonly resolved: ReadonlyMap<string, ReadonlyArray<string>>
  /** 额外元数据，按生态存放 */
  readonly meta?: Record<string, unknown>
}

export interface DependencyEdge {
  readonly fromId: string
  readonly toId: string
  readonly requirement: Requirement
}

export interface RootInfo {
  readonly id: string
  readonly name: string
  readonly version?: string
  /** 根清单声明（若锁文件含根包信息） */
  readonly requirements: ReadonlyArray<Requirement>
  /** 是否为推断出来的根（Poetry 锁文件不含根包条目） */
  readonly inferred: boolean
}

export interface DependencyGraph {
  readonly ecosystem: Ecosystem
  readonly nodes: ReadonlyMap<string, PackageNode>
  readonly roots: ReadonlyArray<RootInfo>
  readonly edges: ReadonlyArray<DependencyEdge>
  /** 解析时发现的数据问题 */
  readonly issues: ReadonlyArray<{ level: 'warning' | 'error'; message: string }>
  /** 该生态锁文件是否提供依赖声明区间 */
  readonly requirementSpecsAvailable: boolean
  /** 源文件名 */
  readonly sourceLabel: string
}

export function nodeLabel(node: Pick<PackageNode, 'name' | 'version'>): string {
  return `${node.name}@${node.version}`
}

/** 从根出发到目标节点的所有路径（用于“漏洞从哪条依赖路径进来”） */
export interface PathStep {
  readonly nodeId: string
  readonly name: string
  readonly version: string
  /** 走到下一步所用的声明区间（根到第一跳时为根清单区间） */
  readonly spec?: string
}

export interface NodePath {
  readonly steps: ReadonlyArray<PathStep>
  readonly length: number
  /** 该路径上是否有 dev 依赖 */
  readonly involvesDev: boolean
  /** 是否绕过了循环 */
  readonly cyclic: boolean
}

/**
 * 枚举从根到目标节点的简单路径（不重复节点），限制条数与深度，避免组合爆炸。
 * 返回按长度升序，便于先展示最短、最直接的引入路径。
 */
export function findPathsTo(
  graph: DependencyGraph,
  targetId: string,
  options: { maxPaths?: number; maxDepth?: number } = {},
): NodePath[] {
  const maxPaths = options.maxPaths ?? 40
  const maxDepth = options.maxDepth ?? 40
  const results: NodePath[] = []

  const edgesFrom = new Map<string, DependencyEdge[]>()
  for (const edge of graph.edges) {
    const list = edgesFrom.get(edge.fromId) ?? []
    list.push(edge)
    edgesFrom.set(edge.fromId, list)
  }

  for (const root of graph.roots) {
    const stack: { id: string; path: PathStep[]; cyclic: boolean; dev: boolean }[] = [
      {
        id: root.id,
        path: [{ nodeId: root.id, name: root.name, version: root.version ?? '' }],
        cyclic: false,
        dev: false,
      },
    ]
    while (stack.length > 0) {
      const current = stack.pop()!
      if (current.path.length > maxDepth) continue
      if (current.id === targetId) {
        results.push({
          steps: current.path,
          length: current.path.length,
          involvesDev: current.dev,
          cyclic: current.cyclic,
        })
        continue
      }
      const outgoing = edgesFrom.get(current.id) ?? []
      // 逆序压栈，保证先展开字典序靠前的分支
      for (let i = outgoing.length - 1; i >= 0; i--) {
        const edge = outgoing[i]!
        const node = graph.nodes.get(edge.toId)
        if (!node) continue
        const visited = current.path.some((s) => s.nodeId === edge.toId)
        if (visited) {
          results.push({
            steps: [...current.path, { nodeId: node.id, name: node.name, version: node.version, spec: edge.requirement.spec }],
            length: current.path.length + 1,
            involvesDev: current.dev || node.dev,
            cyclic: true,
          })
          continue
        }
        stack.push({
          id: edge.toId,
          path: [...current.path, { nodeId: node.id, name: node.name, version: node.version, spec: edge.requirement.spec }],
          cyclic: current.cyclic,
          dev: current.dev || node.dev,
        })
      }
      if (results.length > maxPaths * 4) break
    }
  }

  // 去重（相同节点序列）并按长度排序
  const seen = new Set<string>()
  const unique: NodePath[] = []
  for (const p of results) {
    const key = p.steps.map((s) => s.nodeId).join('\u0000')
    if (seen.has(key)) continue
    seen.add(key)
    unique.push(p)
  }
  unique.sort((a, b) => a.length - b.length)
  return unique.slice(0, maxPaths)
}

/** 反向：谁依赖了这个节点（直接父节点） */
export function directDependents(graph: DependencyGraph, nodeId: string): DependencyEdge[] {
  return graph.edges.filter((e) => e.toId === nodeId)
}
