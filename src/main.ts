/**
 * 入口：事件绑定与状态更新。
 */

import './ui/styles.css'
import { buildState, emptyState, type AppState, type RawFile } from './ui/state'
import { defaultViewOptions, renderApp, type ViewOptions } from './ui/render'
import { EXAMPLE_OSV, EXAMPLE_PROJECTS } from './ui/examples'

const root = document.getElementById('app')
if (!root) throw new Error('缺少 #app 容器')

let state: AppState = emptyState()
let options: ViewOptions = defaultViewOptions()

function rerender(): void {
  renderApp(root!, state, options)
  bind()
}

function setFiles(files: RawFile[]): void {
  if (files.length === 0) {
    state = emptyState()
    options = defaultViewOptions()
    rerender()
    return
  }
  state = buildState(files)
  // 默认展开前 3 条发现之外的都收起；展开状态在重新分析时重置，避免指向已不存在的节点
  options = defaultViewOptions()
  const active = state.projects.find((p) => p.key === state.activeProjectKey)
  if (active) {
    active.analysis.findings.slice(0, 3).forEach((f) => options.expanded.add(`${active.key}|${f.node.id}`))
  }
  rerender()
}

async function readFiles(fileList: FileList | File[]): Promise<RawFile[]> {
  const out: RawFile[] = []
  for (const file of Array.from(fileList)) {
    // 保留 webkitRelativePath 以区分同名文件（例如多个 package-lock.json）
    const name = (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name
    out.push({ filename: name, text: await file.text() })
  }
  return out
}

function bind(): void {
  const dropzone = document.getElementById('dropzone')
  const input = document.getElementById('file-input') as HTMLInputElement | null
  if (dropzone && input) {
    dropzone.addEventListener('click', () => input.click())
    dropzone.addEventListener('dragover', (ev) => {
      ev.preventDefault()
      dropzone.classList.add('dragging')
    })
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragging'))
    dropzone.addEventListener('drop', async (ev) => {
      ev.preventDefault()
      dropzone.classList.remove('dragging')
      const files = (ev as DragEvent).dataTransfer?.files
      if (files && files.length > 0) setFiles(await readFiles(files))
    })
    input.addEventListener('change', async () => {
      if (input.files && input.files.length > 0) setFiles(await readFiles(input.files))
    })
  }

  document.getElementById('load-example')?.addEventListener('click', () => {
    const files: RawFile[] = [
      { filename: 'osv/core.json', text: EXAMPLE_OSV },
      ...EXAMPLE_PROJECTS.flatMap((p) => p.files),
    ]
    setFiles(files)
  })

  document.getElementById('clear-all')?.addEventListener('click', () => {
    setFiles([])
  })

  for (const button of Array.from(document.querySelectorAll<HTMLButtonElement>('#project-select button'))) {
    button.addEventListener('click', () => {
      state = { ...state, activeProjectKey: button.dataset.key ?? null }
      rerender()
    })
  }

  const search = document.getElementById('search-input') as HTMLInputElement | null
  if (search) {
    search.addEventListener('input', () => {
      options = { ...options, search: search.value }
      // 搜索时保持输入焦点：只重绘结果区，避免输入框失焦
      rerenderPreservingFocus(search.value)
    })
  }

  for (const box of Array.from(document.querySelectorAll<HTMLInputElement>('[data-severity]'))) {
    box.addEventListener('change', () => {
      const severity = box.dataset.severity as 'critical' | 'high' | 'medium' | 'low' | 'unknown'
      const next = new Set(options.severity)
      if (box.checked) next.add(severity)
      else next.delete(severity)
      options = { ...options, severity: next }
      rerender()
    })
  }

  const includeDev = document.getElementById('include-dev') as HTMLInputElement | null
  includeDev?.addEventListener('change', () => {
    options = { ...options, includeDev: includeDev.checked }
    rerender()
  })

  for (const tab of Array.from(document.querySelectorAll<HTMLButtonElement>('[data-tab]'))) {
    tab.addEventListener('click', () => {
      options = { ...options, tab: (tab.dataset.tab as 'findings' | 'issues') ?? 'findings' }
      rerender()
    })
  }

  for (const head of Array.from(document.querySelectorAll<HTMLElement>('[data-toggle]'))) {
    head.addEventListener('click', () => {
      const key = head.dataset.toggle!
      if (options.expanded.has(key)) options.expanded.delete(key)
      else options.expanded.add(key)
      rerender()
    })
  }
}

/** 搜索时重绘但恢复焦点与光标位置 */
function rerenderPreservingFocus(value: string): void {
  rerender()
  const next = document.getElementById('search-input') as HTMLInputElement | null
  if (next) {
    next.value = value
    next.focus()
    next.setSelectionRange(value.length, value.length)
  }
}

window.addEventListener('app:rerender', () => rerender())

rerender()
