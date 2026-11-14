/**
 * 依赖路径的 DAG 视图（SVG，无第三方库）。
 *
 * 只画“从根到某个漏洞包的路径并集”，而不是整个依赖树：
 * 真实项目动辄上千节点，全图既慢又无用。用户要回答的是
 * “这个漏洞是从哪进来的”，所以只保留相关子图。
 */

import { el, clear } from './dom'
import type { NodePath } from '../core/parsers/graph'

interface GraphInput {
  readonly paths: ReadonlyArray<NodePath>
  readonly highlightNodeId: string
}

const NODE_W = 168
const NODE_H = 34
const GAP_X = 56
const GAP_Y = 14
const PADDING = 22

interface Positioned {
  id: string
  name: string
  version: string
  x: number
  y: number
  depth: number
  count: number
  highlighted: boolean
}

/** 按路径长度分层布局：同深度的节点纵向排列 */
export function renderPathGraph(container: HTMLElement, input: GraphInput): void {
  clear(container)
  if (input.paths.length === 0) {
    container.append(el('div', { class: 'empty', text: '没有可展示的依赖路径' }))
    return
  }

  // 收集节点与边
  const byId = new Map<string, Positioned>()
  const edges = new Set<string>()
  const layers = new Map<number, string[]>()

  for (const path of input.paths) {
    path.steps.forEach((step, index) => {
      const existing = byId.get(step.nodeId)
      if (!existing) {
        byId.set(step.nodeId, {
          id: step.nodeId,
          name: step.name,
          version: step.version,
          x: 0,
          y: 0,
          depth: index,
          count: 0,
          highlighted: step.nodeId === input.highlightNodeId,
        })
        const layer = layers.get(index) ?? []
        layer.push(step.nodeId)
        layers.set(index, layer)
      }
      const node = byId.get(step.nodeId)!
      node.count++
      if (index > 0) {
        const prev = path.steps[index - 1]!
        edges.add(`${prev.nodeId}\u0000${step.nodeId}`)
      }
    })
  }

  // 每个深度内部按出现次数（越多越靠上）排序，减少交叉
  const depthKeys = [...layers.keys()].sort((a, b) => a - b)
  let maxRows = 0
  for (const depth of depthKeys) {
    const ids = layers.get(depth)!
    ids.sort((a, b) => {
      const na = byId.get(a)!
      const nb = byId.get(b)!
      if (nb.count !== na.count) return nb.count - na.count
      return na.name.localeCompare(nb.name)
    })
    maxRows = Math.max(maxRows, ids.length)
    ids.forEach((id, row) => {
      const node = byId.get(id)!
      node.x = PADDING + depth * (NODE_W + GAP_X)
      node.y = PADDING + row * (NODE_H + GAP_Y)
    })
  }

  const width = PADDING * 2 + depthKeys.length * NODE_W + (depthKeys.length - 1) * GAP_X
  const height = PADDING * 2 + maxRows * NODE_H + (maxRows - 1) * GAP_Y

  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
  svg.setAttribute('width', String(Math.max(width, 400)))
  svg.setAttribute('height', String(Math.max(height, 120)))
  svg.setAttribute('viewBox', `0 0 ${Math.max(width, 400)} ${Math.max(height, 120)}`)

  // 边
  for (const key of edges) {
    const [fromId, toId] = key.split('\u0000') as [string, string]
    const from = byId.get(fromId)
    const to = byId.get(toId)
    if (!from || !to) continue
    const x1 = from.x + NODE_W
    const y1 = from.y + NODE_H / 2
    const x2 = to.x
    const y2 = to.y + NODE_H / 2
    const midX = (x1 + x2) / 2
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path')
    path.setAttribute('d', `M${x1},${y1} C${midX},${y1} ${midX},${y2} ${x2},${y2}`)
    path.setAttribute('fill', 'none')
    path.setAttribute('stroke', to.highlighted ? '#f85149' : '#30363d')
    path.setAttribute('stroke-width', to.highlighted ? '2' : '1.2')
    svg.append(path)
  }

  // 节点
  for (const node of byId.values()) {
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g')

    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect')
    rect.setAttribute('x', String(node.x))
    rect.setAttribute('y', String(node.y))
    rect.setAttribute('width', String(NODE_W))
    rect.setAttribute('height', String(NODE_H))
    rect.setAttribute('rx', '7')
    rect.setAttribute('fill', node.highlighted ? '#3d1418' : '#161b22')
    rect.setAttribute('stroke', node.highlighted ? '#f85149' : '#30363d')
    rect.setAttribute('stroke-width', node.highlighted ? '2' : '1')
    g.append(rect)

    const label = document.createElementNS('http://www.w3.org/2000/svg', 'text')
    label.setAttribute('x', String(node.x + 10))
    label.setAttribute('y', String(node.y + 14))
    label.setAttribute('fill', node.highlighted ? '#ffa198' : '#e6edf3')
    label.textContent = truncate(node.name, 20)
    g.append(label)

    const ver = document.createElementNS('http://www.w3.org/2000/svg', 'text')
    ver.setAttribute('x', String(node.x + 10))
    ver.setAttribute('y', String(node.y + 27))
    ver.setAttribute('fill', node.highlighted ? '#f85149' : '#8b949e')
    ver.setAttribute('font-size', '10')
    ver.textContent = node.version ? `v${node.version}` : ''
    g.append(ver)

    const title = document.createElementNS('http://www.w3.org/2000/svg', 'title')
    title.textContent = `${node.name}@${node.version}\n出现于 ${node.count} 条路径`
    g.append(title)

    svg.append(g)
  }

  const wrap = el('div', { class: 'graph-wrap' })
  wrap.append(svg)
  container.append(wrap)
}

function truncate(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`
}
