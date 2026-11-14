/**
 * 主界面渲染。
 *
 * 信息层级：
 * 1. 顶部：一句话结论（受影响包数 / 可直接修复数） + 严重度分布。
 * 2. 每条发现：包与版本、严重度、是否直接依赖、命中的漏洞、依赖路径、升级方案。
 * 3. 升级方案里逐条列出约束检查（✓ / ✗ / ?），并明确“哪些东西没法验证”。
 *
 * 所有外部数据（包名、漏洞摘要、路径）都通过 textContent 写入，避免注入。
 */

import { clear, copyToClipboard, el, frag } from './dom'
import { renderPathGraph } from './path-graph'
import type { AppState, LoadedProject } from './state'
import { totals } from './state'
import type { Finding, Severity } from '../core/analysis/analyze'
import { describeMatch, severityOf } from '../core/analysis/analyze'
import type { UpgradePlan, UpgradeStep } from '../core/upgrade/planner'
import { deltaLabel } from '../core/upgrade/planner'
import { simulatePlan } from '../core/upgrade/simulate'
import { ECOSYSTEM_LABEL } from '../core/versions/ecosystem'

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  unknown: '未评级',
}

export interface ViewOptions {
  readonly search: string
  readonly severity: Set<Severity>
  readonly includeDev: boolean
  readonly tab: 'findings' | 'issues'
  readonly expanded: Set<string>
  readonly pathMode: Map<string, 'list' | 'graph'>
  readonly showAllPaths: Set<string>
}

export function defaultViewOptions(): ViewOptions {
  return {
    search: '',
    severity: new Set<Severity>(['critical', 'high', 'medium', 'low', 'unknown']),
    includeDev: true,
    tab: 'findings',
    expanded: new Set(),
    pathMode: new Map(),
    showAllPaths: new Set(),
  }
}

export function severityPill(severity: Severity): HTMLElement {
  return el(
    'span',
    { class: `sev sev-${severity}` },
    el('span', { class: 'dot' }),
    SEVERITY_LABEL[severity],
  )
}

export function renderApp(root: HTMLElement, state: AppState, options: ViewOptions): void {
  clear(root)

  root.append(renderHeader())

  const layout = el('div', { class: 'layout' })
  layout.append(renderSidebar(state))
  layout.append(renderMain(state, options))
  root.append(layout)
}

function renderHeader(): HTMLElement {
  return el(
    'header',
    { class: 'app-header' },
    el('h1', { text: '依赖漏洞影响分析器' }),
    el('span', {
      class: 'tagline',
      text: '解析 package-lock.json / poetry.lock / Cargo.lock，按各生态版本语义匹配本地 OSV 库，回溯依赖路径并给出最小升级方案',
    }),
  )
}

function renderSidebar(state: AppState): HTMLElement {
  const side = el('aside', { class: 'sidebar' })

  // 导入区由 main.ts 挂载处理函数（通过自定义事件）
  const panel = el('div', { class: 'panel' }, el('h2', { text: '数据导入' }))
  const dropzone = el('div', { class: 'dropzone', id: 'dropzone' }, el('strong', { text: '拖拽文件到这里，或点击选择' }), el('div', { class: 'small-muted', text: 'OSV 漏洞库（JSON / JSONL）+ 任意多个锁文件' }))
  const input = el('input', {
    type: 'file',
    multiple: true,
    id: 'file-input',
    style: 'display:none',
  })
  const btnRow = el('div', { class: 'btn-row' })
  btnRow.append(
    el('button', { class: 'btn primary', id: 'load-example', text: '载入内置示例' }),
    el('button', { class: 'btn', id: 'clear-all', text: '清空' }),
  )
  panel.append(dropzone, input, btnRow)

  if (state.files.length > 0) {
    const list = el('ul', { class: 'file-list' })
    for (const f of state.files) {
      list.append(
        el('li', {}, el('span', { class: 'mono', text: f.filename }), el('span', { class: 'size', text: formatBytes(f.size) })),
      )
    }
    panel.append(list)
  }

  side.append(panel)

  // 工程切换
  if (state.projects.length > 0) {
    const panelProjects = el('div', { class: 'panel' }, el('h2', { text: '已解析工程' }))
    const selector = el('div', { class: 'project-select', id: 'project-select' })
    for (const project of state.projects) {
      const active = project.key === state.activeProjectKey
      const button = el('button', { class: active ? 'active' : '', 'data-key': project.key })
      button.append(
        el('div', {}, el('span', { class: 'mono', text: project.graph.sourceLabel })),
        el('div', {
          class: 'meta',
          text: `${ECOSYSTEM_LABEL[project.graph.ecosystem]} · ${countPackages(project)} 个包 · ${project.analysis.findings.length} 条发现`,
        }),
      )
      selector.append(button)
    }
    panelProjects.append(selector)
    side.append(panelProjects)
  }

  // 版本语义说明（帮助用户理解判定依据）
  const panelSemantics = el('div', { class: 'panel' }, el('h2', { text: '版本判定口径' }))
  panelSemantics.append(
    el(
      'div',
      { class: 'small-muted' },
      el('p', { text: 'npm：node-semver 语义（^ 对 0.x 特殊；x-range 上界带 -0；预发布需同版本号 comparator 才放行）。' }),
      el('p', { text: 'Cargo：Rust semver crate 语义（裸版本 = caret；部分版本按 tilde 处理；不支持 || 与连字符区间）。' }),
      el('p', { text: 'PyPI：PEP 440（epoch / local / pre / post / dev 全参与排序；== 忽略 local；last_affected 闭区间）。' }),
      el('p', { text: 'OSV 区间按事件流求值：introduced 进入受影响，fixed 之后排除，limit 只限制评估范围。' }),
    ),
  )
  side.append(panelSemantics)

  return side
}

function countPackages(project: LoadedProject): number {
  let n = 0
  for (const node of project.graph.nodes.values()) if (node.meta?.isRoot !== true) n++
  return n
}

function renderMain(state: AppState, options: ViewOptions): HTMLElement {
  const main = el('main', { class: 'main' })

  if (!state.osv) {
    main.append(
      el(
        'div',
        { class: 'empty' },
        el('div', { class: 'big', text: '还没有导入数据' }),
        el('div', {
          text: '需要两部分：一份 OSV 格式漏洞库（JSON 数组或 JSONL），以及 package-lock.json / poetry.lock / Cargo.lock。',
        }),
        el('div', { class: 'small-muted', text: '点击左侧“载入内置示例”可以先用演示数据体验完整流程。' }),
      ),
    )
    return main
  }

  if (state.projects.length === 0) {
    main.append(
      el(
        'div',
        { class: 'empty' },
        el('div', { class: 'big', text: '漏洞库已就绪，但还没有可分析的锁文件' }),
        el('div', { text: `已载入 ${state.osv.records.length} 条记录，覆盖 ${state.osv.ecosystems.join('、') || '未知生态'}。` }),
      ),
    )
    main.append(renderIssues(state))
    return main
  }

  const active = state.projects.find((p) => p.key === state.activeProjectKey) ?? state.projects[0]!
  main.append(renderTotals(state, active))
  main.append(renderFilters(options, active))
  main.append(renderTabs(options, active))
  if (options.tab === 'findings') {
    main.append(renderFindings(active, options))
  } else {
    main.append(renderIssues(state, active))
  }
  return main
}

function renderTotals(state: AppState, active: LoadedProject): HTMLElement {
  const t = totals(state.projects)
  const grid = el('div', { class: 'stat-grid' })

  const countSeverity = (s: Severity): number => active.analysis.findings.filter((f) => f.severity === s).length

  grid.append(
    stat('受影响包（当前工程）', String(active.analysis.findings.length), active.analysis.findings.length > 0 ? 'high' : 'ok'),
    stat('可直接修复', `${active.report.summary.fixable}`, 'ok'),
    stat('需人工处理', `${active.report.summary.unfixable}`, active.report.summary.unfixable > 0 ? 'medium' : 'ok'),
    stat(
      '严重程度分布',
      `${countSeverity('critical')} / ${countSeverity('high')} / ${countSeverity('medium')} / ${countSeverity('low')}`,
      countSeverity('critical') > 0 ? 'critical' : countSeverity('high') > 0 ? 'high' : 'ok',
    ),
  )

  const wrap = el('div')
  wrap.append(grid)
  wrap.append(
    el('div', {
      class: 'small-muted',
      style: 'margin:-6px 0 14px',
      text: `共导入 ${state.projects.length} 个工程，累计扫描 ${t.packages} 个依赖；漏洞库 ${state.osv?.records.length ?? 0} 条记录。`,
    }),
  )

  // 库层面数据问题
  if (state.osv && state.osvIssues.some((i) => i.level === 'error')) {
    wrap.append(
      el('div', {
        class: 'conflict',
        text: `漏洞库存在 ${state.osvIssues.filter((i) => i.level === 'error').length} 条结构错误，相关记录已被跳过（详见“数据问题”页）。`,
      }),
    )
  }
  return wrap
}

function stat(label: string, value: string, tone: string): HTMLElement {
  return el(
    'div',
    { class: 'stat' },
    el('div', { class: 'label', text: label }),
    el('div', { class: `value ${tone}`, text: value }),
  )
}

function renderFilters(options: ViewOptions, active: LoadedProject): HTMLElement {
  const bar = el('div', { class: 'filters' })
  const search = el('input', {
    type: 'search',
    placeholder: '筛选包名或漏洞 ID…',
    value: options.search,
    id: 'search-input',
  })
  bar.append(search)

  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'unknown']
  for (const s of severities) {
    const count = active.analysis.findings.filter((f) => f.severity === s).length
    if (count === 0) continue
    const checkbox = el('input', { type: 'checkbox', 'data-severity': s, checked: options.severity.has(s) }) as HTMLInputElement
    bar.append(el('label', {}, checkbox, severityPill(s), el('span', { class: 'small-muted', text: String(count) })))
  }

  const devBox = el('input', { type: 'checkbox', id: 'include-dev', checked: options.includeDev }) as HTMLInputElement
  bar.append(el('label', {}, devBox, '包含 dev 依赖'))
  return bar
}

function renderTabs(options: ViewOptions, active: LoadedProject): HTMLElement {
  const tabs = el('div', { class: 'tabs' })
  const issuesCount = active.analysis.issues.length + active.graph.issues.length
  tabs.append(
    el('button', { class: options.tab === 'findings' ? 'active' : '', 'data-tab': 'findings', text: `漏洞发现（${active.analysis.findings.length}）` }),
    el('button', { class: options.tab === 'issues' ? 'active' : '', 'data-tab': 'issues', text: `数据问题（${issuesCount}）` }),
  )
  return tabs
}

function renderFindings(active: LoadedProject, options: ViewOptions): HTMLElement {
  const container = el('div')

  const filtered = active.analysis.findings.filter((f) => {
    if (!options.severity.has(f.severity)) return false
    if (!options.includeDev && f.devOnly) return false
    if (options.search.trim() !== '') {
      const q = options.search.trim().toLowerCase()
      const hay = [
        f.node.name,
        f.node.version,
        ...f.matches.map((m) => m.record.id),
        ...f.matches.map((m) => m.record.summary ?? ''),
        ...f.paths.flatMap((p) => p.steps.map((s) => s.name)),
      ].join(' ').toLowerCase()
      if (!hay.includes(q)) return false
    }
    return true
  })

  if (filtered.length === 0) {
    container.append(
      el(
        'div',
        { class: 'empty' },
        el('div', { class: 'big', text: '没有符合当前筛选条件的漏洞' }),
        el('div', { class: 'small-muted', text: '放宽严重度筛选或清空搜索词试试；也可能是这个工程确实没有命中库里的记录。' }),
      ),
    )
    return container
  }

  if (active.report.conflicts.length > 0) {
    const box = el('div', { class: 'panel' }, el('h2', { text: '方案之间的冲突' }))
    for (const c of active.report.conflicts) {
      box.append(el('div', { class: 'conflict', text: c.message }))
    }
    container.append(box)
  }

  if (active.simulation.crossPlanConflicts.length > 0) {
    const box = el('div', { class: 'panel' }, el('h2', { text: '合并所有方案后的冲突' }))
    for (const c of active.simulation.crossPlanConflicts) {
      box.append(el('div', { class: 'conflict', text: c }))
    }
    container.append(box)
  }

  for (const finding of filtered) {
    container.append(renderFinding(active, finding, options))
  }
  return container
}

function findingKey(project: LoadedProject, finding: Finding): string {
  return `${project.key}|${finding.node.id}`
}

function renderFinding(project: LoadedProject, finding: Finding, options: ViewOptions): HTMLElement {
  const key = findingKey(project, finding)
  const expanded = options.expanded.has(key)
  const card = el('div', { class: 'finding' })

  const head = el('div', { class: 'finding-head', 'data-toggle': key })
  head.append(severityPill(finding.severity), el('span', { class: 'pkg', text: `${finding.node.name}@${finding.node.version}` }))

  const badges = el('div', { class: 'badges' })
  if (finding.isDirect) badges.append(el('span', { class: 'badge direct', text: '直接依赖' }))
  if (finding.devOnly) badges.append(el('span', { class: 'badge dev', text: '仅 dev' }))
  badges.append(el('span', { class: 'badge', text: `深度 ${finding.shortestDepth === Number.POSITIVE_INFINITY ? '—' : finding.shortestDepth}` }))
  badges.append(el('span', { class: 'badge', text: `${finding.paths.length} 条路径` }))
  badges.append(el('span', { class: 'badge', text: finding.matches.map((m) => m.record.id).join(' · ') }))
  head.append(badges)
  card.append(head)

  if (expanded) card.append(renderFindingBody(project, finding, options, key))
  return card
}

function renderFindingBody(project: LoadedProject, finding: Finding, options: ViewOptions, key: string): HTMLElement {
  const body = el('div', { class: 'finding-body' })

  // 漏洞详情
  for (const match of finding.matches) {
    const block = el('div', { class: 'vuln-block' })
    const title = el('div', { class: 'vuln-title' })
    title.append(el('span', { class: 'id', text: match.record.id }))
    title.append(severityPill(severityOf(match.record)))
    if (match.record.aliases?.length) title.append(el('span', { class: 'badge', text: match.record.aliases.join(', ') }))
    const copyBtn = el('button', { class: 'copy-btn', text: '复制 ID' })
    copyBtn.addEventListener('click', (ev) => {
      ev.stopPropagation()
      void copyToClipboard(match.record.id)
      copyBtn.textContent = '已复制'
      setTimeout(() => (copyBtn.textContent = '复制 ID'), 1200)
    })
    title.append(copyBtn)
    block.append(title)
    if (match.record.summary) block.append(el('div', { class: 'summary', style: 'margin-bottom:6px', text: match.record.summary }))

    const kv = el('dl', { class: 'kv' })
    kv.append(el('dt', { text: '命中依据' }), el('dd', { text: describeMatch(match) }))
    kv.append(el('dt', { text: '判定来源' }), el('dd', { text: match.viaVersionsList ? 'affected.versions 精确清单' : `ranges[${match.ranges.map((r) => r.rangeIndex).join(',')}]（${match.ranges[0]?.range.type ?? '—'}）` }))
    if (match.record.published) kv.append(el('dt', { text: '发布时间' }), el('dd', { text: match.record.published }))
    block.append(kv)

    if (match.record.details) {
      const details = el('details')
      details.append(el('summary', { class: 'paths-toggle', text: '查看详情描述' }))
      details.append(el('div', { class: 'small-muted', style: 'white-space:pre-wrap;margin-top:4px', text: match.record.details }))
      block.append(details)
    }
    if (match.record.references?.length) {
      const refs = el('div', { class: 'small-muted', style: 'margin-top:4px' })
      refs.append('参考：')
      match.record.references.slice(0, 4).forEach((ref, i) => {
        if (!ref.url) return
        if (i > 0) refs.append(' · ')
        const link = el('a', { href: ref.url, target: '_blank', rel: 'noopener noreferrer', text: ref.type ?? ref.url })
        refs.append(link)
      })
      block.append(refs)
    }
    body.append(block)
  }

  // 依赖路径
  const pathHeader = el('div', { class: 'section-label', text: `依赖路径（${finding.paths.length} 条，按长度排序）` })
  body.append(pathHeader)

  const mode = options.pathMode.get(key) ?? 'list'
  const modeRow = el('div', { class: 'btn-row', style: 'margin:0 0 8px' })
  const listBtn = el('button', { class: `btn ${mode === 'list' ? 'primary' : ''}`, text: '路径列表' })
  const graphBtn = el('button', { class: `btn ${mode === 'graph' ? 'primary' : ''}`, text: '依赖图' })
  listBtn.addEventListener('click', (e) => {
    e.stopPropagation()
    options.pathMode.set(key, 'list')
    window.dispatchEvent(new CustomEvent('app:rerender'))
  })
  graphBtn.addEventListener('click', (e) => {
    e.stopPropagation()
    options.pathMode.set(key, 'graph')
    window.dispatchEvent(new CustomEvent('app:rerender'))
  })
  modeRow.append(listBtn, graphBtn)
  body.append(modeRow)

  if (mode === 'graph') {
    const graphHost = el('div')
    renderPathGraph(graphHost, { paths: finding.paths, highlightNodeId: finding.node.id })
    body.append(graphHost)
  } else {
    const showAll = options.showAllPaths.has(key)
    const visible = showAll ? finding.paths : finding.paths.slice(0, 3)
    for (const path of visible) {
      const row = el('div', { class: 'path' })
      path.steps.forEach((step, index) => {
        if (index > 0) {
          row.append(el('span', { class: 'arrow', text: '→' }))
          if (step.spec) row.append(el('span', { class: 'spec', text: `(${step.spec})` }))
        }
        const isTarget = step.nodeId === finding.node.id
        row.append(
          el('span', {
            class: isTarget ? 'node target' : 'node',
            text: step.version ? `${step.name}@${step.version}` : step.name,
          }),
        )
      })
      row.append(el('span', { class: 'depth', text: path.cyclic ? '（含循环）' : `${path.length - 1} 跳` }))
      body.append(row)
    }
    if (finding.paths.length > 3) {
      const toggle = el('button', { class: 'paths-toggle', text: showAll ? '收起' : `展开其余 ${finding.paths.length - 3} 条` })
      toggle.addEventListener('click', (e) => {
        e.stopPropagation()
        if (showAll) options.showAllPaths.delete(key)
        else options.showAllPaths.add(key)
        window.dispatchEvent(new CustomEvent('app:rerender'))
      })
      body.append(toggle)
    }
  }

  // 升级方案
  body.append(renderPlan(project, finding))
  return body
}

function renderPlan(project: LoadedProject, finding: Finding): HTMLElement {
  const plan = project.report.plans.find((p) => p.findingKey === `${finding.node.name}@${finding.node.version}`)
  const box = el('div', { class: 'section-label', text: '最小升级方案' })
  if (!plan) {
    box.append(el('div', { class: 'small-muted', text: '未生成方案' }))
    return box
  }

  const card = el('div', { class: `upgrade ${plan.feasible ? 'feasible' : 'infeasible'}` })
  const head = el('div', { class: 'upgrade-head' })
  head.append(el('span', { text: plan.packageName }))
  head.append(el('span', { class: 'ver', text: plan.currentVersion }))
  head.append(el('span', { class: 'arrow', text: '→' }))
  if (plan.targetVersion) {
    head.append(el('span', { class: 'ver new', text: plan.targetVersion }))
    const delta = plan.steps[0] ? deltaLabel(plan.steps[0].delta) : ''
    head.append(el('span', { class: 'badge', text: delta }))
  } else {
    head.append(el('span', { class: 'ver', style: 'color:var(--err)', text: '无可用修复版本' }))
  }
  head.append(el('span', { class: 'badge', text: strategyLabel(plan.strategy) }))
  card.append(head)

  if (plan.steps.length > 0) {
    const steps = el('ol', { class: 'steps' })
    for (const step of plan.steps) {
      steps.append(renderStepBody(project, step))
    }
    card.append(steps)
  }

  if (plan.conflicts.length > 0) {
    for (const c of plan.conflicts) card.append(el('div', { class: 'conflict', text: c.message }))
  }

  // 模拟结果（合并后的影响）
  if (plan.feasible) {
    const sim = simulatePlan(project.graph, plan)
    if (sim.brokenRequirements.length > 0) {
      const heading =
        plan.strategy === 'relax-root-constraint'
          ? '若不修改根清单声明，以下约束会不满足（这正是需要放宽它的原因）：'
          : '应用该方案后会破坏以下约束：'
      const box2 = el('div', { class: 'conflict' }, el('div', { style: 'font-weight:600', text: heading }))
      for (const b of sim.brokenRequirements) box2.append(el('div', { text: `· ${b.message}` }))
      card.append(box2)
    }
    // 方案自身的未知项与模拟未知项合并去重后只渲染一次，
    // 否则“目标版本不在锁文件里”这类说明会重复出现。
    const merged = [...new Set([...plan.unknowns, ...sim.unknowns])]
    if (merged.length > 0) card.append(renderUnknowns(merged))
  } else if (plan.unknowns.length > 0) {
    card.append(renderUnknowns(plan.unknowns))
  }

  box.append(card)
  return box
}

function renderStepBody(project: LoadedProject, step: UpgradeStep): HTMLElement {
  const li = el('li')
  li.append(el('div', { class: 'step-line', text: `${step.name}：${step.from} → ${step.to}` }))
  if (step.causedByParent) {
    li.append(el('div', { class: 'step-note', text: '该升级是被父包的约束推动的：父包新版本放宽了声明区间。' }))
  }
  const checks = el('ul', { class: 'checks' })
  for (const check of step.checks) {
    const icon = check.ok === true ? '✓' : check.ok === false ? '✗' : '?'
    const cls = check.ok === true ? 'ok' : check.ok === false ? 'bad' : 'unknown'
    const item = el('li')
    item.append(el('span', { class: `check-icon ${cls}`, text: icon }))
    const desc = el('span')
    desc.append(el('span', { text: `${check.dependentLabel} 声明 ` }), el('span', { class: 'mono', text: check.requirement.spec ?? '（无区间）' }))
    if (check.ok === null && check.reason) desc.append(el('span', { class: 'small-muted', text: ` — ${check.reason}` }))
    item.append(desc)
    checks.append(item)
  }
  if (checks.childElementCount > 0) {
    li.append(el('div', { class: 'step-note', text: '升级后父包约束检查：' }), checks)
  }
  return li
}

function renderUnknowns(list: ReadonlyArray<string>): HTMLElement {
  const box = el('div', { class: 'unknowns' })
  box.append(el('div', { style: 'font-weight:600', text: '以下内容无法在此离线环境中确认：' }))
  const ul = el('ul')
  for (const item of list) ul.append(el('li', { text: item }))
  box.append(ul)
  return box
}

function strategyLabel(strategy: UpgradePlan['strategy']): string {
  switch (strategy) {
    case 'bump-vulnerable':
      return '直接升级'
    case 'bump-parent':
      return '需连带升级父包'
    case 'relax-root-constraint':
      return '需放宽根声明'
    case 'no-fix-version':
      return '漏洞库无修复版本'
    case 'no-feasible-version':
      return '无可行版本'
  }
}

function renderIssues(state: AppState, active?: LoadedProject): HTMLElement {
  const container = el('div')
  const kinds: { label: string; items: { level: 'error' | 'warning'; message: string; source?: string }[] }[] = []

  kinds.push({
    label: '漏洞库（OSV）',
    items: state.osvIssues.map((i) => ({ level: i.level, message: i.message, source: i.source })),
  })
  kinds.push({
    label: '锁文件解析',
    items: state.parseIssues.map((i) => ({ level: i.level, message: i.message, source: i.source })),
  })
  if (active) {
    kinds.push({
      label: `分析过程（${active.graph.sourceLabel}）`,
      items: active.analysis.issues.map((i) => ({ level: i.level, message: i.message })),
    })
  }

  let any = false
  for (const kind of kinds) {
    if (kind.items.length === 0) continue
    any = true
    const panel = el('div', { class: 'panel' }, el('h2', { text: `${kind.label}（${kind.items.length}）` }))
    const list = el('div', { class: 'issues-list' })
    for (const item of kind.items) {
      const row = el('div', { class: `issue ${item.level}` })
      row.append(el('span', { class: 'icon', text: item.level === 'error' ? '✗' : '!' }))
      const body = el('span')
      if (item.source) body.append(el('span', { class: 'src', text: `${item.source} ` }))
      body.append(el('span', { text: item.message }))
      row.append(body)
      list.append(row)
    }
    panel.append(list)
    container.append(panel)
  }

  if (!any) {
    container.append(
      el('div', { class: 'empty' }, el('div', { class: 'big', text: '没有数据问题' }), el('div', { class: 'small-muted', text: '所有记录与锁文件条目都解析成功。' })),
    )
  }
  return container
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

export { frag }
