/**
 * 极简 DOM 辅助：不引入框架，保持“原生 TypeScript”的要求。
 * 所有文本都通过 textContent 写入，避免 XSS（漏洞库内容属于外部不可信数据）。
 */

export type Child = Node | string | null | undefined | false

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string | boolean | number | undefined> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue
    if (key === 'class') node.className = String(value)
    else if (key === 'text') node.textContent = String(value)
    else if (key === 'html') throw new Error('禁止使用 html 属性，请用 textContent 组装')
    else if (value === true) node.setAttribute(key, '')
    else node.setAttribute(key, String(value))
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue
    node.append(child instanceof Node ? child : document.createTextNode(String(child)))
  }
  return node
}

export function clear(node: HTMLElement): void {
  while (node.firstChild) node.removeChild(node.firstChild)
}

export function frag(...children: Child[]): DocumentFragment {
  const f = document.createDocumentFragment()
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue
    f.append(child instanceof Node ? child : document.createTextNode(String(child)))
  }
  return f
}

/** 文本内容可能是外部数据，统一走 textContent */
export function text(value: string): Text {
  return document.createTextNode(value)
}

export async function copyToClipboard(value: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value)
  } catch {
    // 非安全上下文时回退到 select + execCommand
    const ta = document.createElement('textarea')
    ta.value = value
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.append(ta)
    ta.select()
    document.execCommand('copy')
    ta.remove()
  }
}
