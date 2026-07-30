const markdownCodePattern = /(```[\s\S]*?```|~~~[\s\S]*?~~~|`[^`\n]*`)/g

function normalizeProseMarkdown(value: string, flattenedBlocks: boolean) {
  const normalized = value
    .replace(/\r\n?/g, "\n")
    // Some model providers flatten block Markdown into one physical line. Restore
    // unambiguous block boundaries without touching fenced or inline code.
    .replace(/([^\n])[\t ]+(?=#{1,6}[\t ]+\S)/g, "$1\n\n")
    .replace(/([^\n])[\t ]+(?=(?:---|\*\*\*|___)(?:[\t \n]|$))/g, "$1\n\n")
    .replace(/([^\n])[\t ]+(?=-[\t ]+(?:\*\*|`|\[[ xX]\]))/g, "$1\n")
    .replace(/([^\n])[\t ]+(?=\d+\.[\t ]+(?:\*\*|`))/g, "$1\n")
    .replace(/\n{3,}/g, "\n\n")

  if (!flattenedBlocks) return normalized

  // Once the payload is known to contain flattened block syntax, plain list
  // markers are block delimiters too. This covers model output such as
  // "### 证据 - Manifest... - Binder..." without guessing on normal prose.
  return normalized
    .replace(/([^\n])[\t ]+(?=-[\t ]+\S)/g, "$1\n")
    .replace(/([^\n])[\t ]+(?=\d+\.[\t ]+\S)/g, "$1\n")
}

export function normalizeModelMarkdown(markdown: string) {
  const parts = markdown.split(markdownCodePattern)
  const flattenedBlocks = parts.some(
    (part, index) =>
      index % 2 === 0 &&
      (/[^\n][\t ]+#{1,6}[\t ]+\S/.test(part) ||
        /[^\n][\t ]+(?:---|\*\*\*|___)(?:[\t \n]|$)/.test(part)),
  )

  return parts
    .map((part, index) => (index % 2 === 0 ? normalizeProseMarkdown(part, flattenedBlocks) : part))
    .join("")
}

export function markdownToPlainText(markdown: string) {
  return normalizeModelMarkdown(markdown)
    .replace(/```[\w-]*\n?/g, "")
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
    .replace(/^\s{0,3}#{1,6}\s+/gm, "")
    .replace(/^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/gm, "")
    .replace(/^\s*(?:[-*+]|\d+\.)\s+/gm, "")
    .replace(/[*~`>|]/g, "")
    .replace(/\s+/g, " ")
    .trim()
}
