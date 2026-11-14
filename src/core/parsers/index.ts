/**
 * 锁文件类型识别与统一入口。
 */

import type { DependencyGraph } from './graph'
import { parsePackageLock } from './npm-lock'
import { parseCargoLock } from './cargo-lock'
import { parsePoetryLock, parsePyprojectRoot, type PyprojectRoot } from './poetry-lock'

export type LockfileKind = 'npm' | 'poetry' | 'cargo' | 'pyproject' | 'unknown'

export interface LockfileInput {
  readonly filename: string
  readonly text: string
}

export interface ParsedProject {
  readonly graph: DependencyGraph
  readonly kind: LockfileKind
  /** 同一次导入里附带的 pyproject.toml（Poetry 用） */
  readonly pyproject?: PyprojectRoot
}

/** 根据文件名与内容特征识别锁文件类型 */
export function detectLockfileKind(filename: string, text: string): LockfileKind {
  const lower = filename.toLowerCase()
  if (lower.endsWith('package-lock.json') || lower === 'npm-shrinkwrap.json') return 'npm'
  if (lower.endsWith('poetry.lock')) return 'poetry'
  if (lower.endsWith('cargo.lock')) return 'cargo'
  if (lower.endsWith('pyproject.toml')) return 'pyproject'

  // 内容启发式
  const head = text.slice(0, 4000)
  if (head.includes('"lockfileVersion"') || head.includes('"packages"')) return 'npm'
  if (head.includes('[[package]]') && head.includes('lock-version')) return 'poetry'
  if (head.includes('[[package]]') && (head.includes('checksum =') || head.includes('version = 4'))) return 'cargo'
  if (head.includes('[tool.poetry]') || (head.includes('[project]') && head.includes('dependencies'))) return 'pyproject'
  return 'unknown'
}

/**
 * 解析一组导入文件。pyproject.toml 只在与 poetry.lock 同批出现时才使用；
 * 路径相似性（同目录）由 UI 层负责，这里只保证“同批”可用。
 */
export function parseProject(files: readonly LockfileInput[]): {
  projects: ParsedProject[]
  issues: { source: string; level: 'error' | 'warning'; message: string }[]
} {
  const issues: { source: string; level: 'error' | 'warning'; message: string }[] = []
  const projects: ParsedProject[] = []

  const pyprojects: { filename: string; root: PyprojectRoot }[] = []
  const lockfiles: LockfileInput[] = []

  for (const file of files) {
    const kind = detectLockfileKind(file.filename, file.text)
    if (kind === 'pyproject') {
      try {
        pyprojects.push({ filename: file.filename, root: parsePyprojectRoot(file.text) })
      } catch (err) {
        issues.push({ source: file.filename, level: 'error', message: `pyproject.toml 解析失败：${(err as Error).message}` })
      }
      continue
    }
    if (kind === 'unknown') {
      issues.push({
        source: file.filename,
        level: 'error',
        message: '无法识别锁文件类型（支持 package-lock.json / poetry.lock / Cargo.lock，另可附 pyproject.toml）',
      })
      continue
    }
    lockfiles.push(file)
  }

  for (const file of lockfiles) {
    const kind = detectLockfileKind(file.filename, file.text)
    if (kind === 'npm') {
      const graph = parsePackageLock(file.text, file.filename)
      for (const issue of graph.issues) issues.push({ source: file.filename, ...issue })
      projects.push({ graph, kind })
    } else if (kind === 'poetry') {
      // 找同名目录下的 pyproject；没有则用推断根
      const pyproject = pyprojects.find((p) => sameDir(p.filename, file.filename)) ?? pyprojects[0]
      const graph = parsePoetryLock(file.text, file.filename, pyproject?.root)
      for (const issue of graph.issues) issues.push({ source: file.filename, ...issue })
      projects.push({ graph, kind, pyproject: pyproject?.root })
    } else if (kind === 'cargo') {
      const graph = parseCargoLock(file.text, file.filename)
      for (const issue of graph.issues) issues.push({ source: file.filename, ...issue })
      projects.push({ graph, kind })
    }
  }

  return { projects, issues }
}

function sameDir(a: string, b: string): boolean {
  const dirA = a.includes('/') ? a.slice(0, a.lastIndexOf('/')) : ''
  const dirB = b.includes('/') ? b.slice(0, b.lastIndexOf('/')) : ''
  return dirA === dirB
}
