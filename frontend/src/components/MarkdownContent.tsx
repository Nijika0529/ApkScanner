import type { ComponentPropsWithoutRef } from "react"
import { useMemo } from "react"
import ReactMarkdown, { type Components } from "react-markdown"
import remarkGfm from "remark-gfm"
import { cn } from "../lib"
import { normalizeModelMarkdown } from "../markdown"

const components: Components = {
  h1: ({ children }) => <h1 className="mt-6 text-xl font-bold tracking-tight text-slate-950 first:mt-0">{children}</h1>,
  h2: ({ children }) => <h2 className="mt-6 border-b border-slate-200 pb-2 text-lg font-bold tracking-tight text-slate-950 first:mt-0">{children}</h2>,
  h3: ({ children }) => <h3 className="mt-5 text-base font-semibold text-slate-900 first:mt-0">{children}</h3>,
  h4: ({ children }) => <h4 className="mt-4 text-sm font-semibold text-slate-900 first:mt-0">{children}</h4>,
  p: ({ children }) => <p className="my-3 text-sm leading-7 text-slate-700 first:mt-0 last:mb-0">{children}</p>,
  ul: ({ children }) => <ul className="my-3 list-disc space-y-1.5 pl-6 text-sm leading-6 text-slate-700">{children}</ul>,
  ol: ({ children }) => <ol className="my-3 list-decimal space-y-1.5 pl-6 text-sm leading-6 text-slate-700">{children}</ol>,
  li: ({ children }) => <li className="pl-1 marker:font-semibold marker:text-cyan-700">{children}</li>,
  blockquote: ({ children }) => <blockquote className="my-4 border-l-4 border-cyan-300 bg-cyan-50/70 px-4 py-2 text-slate-700">{children}</blockquote>,
  hr: () => <hr className="my-6 border-slate-200" />,
  strong: ({ children }) => <strong className="font-semibold text-slate-950">{children}</strong>,
  a: ({ children, href }) => (
    <a
      href={href}
      target={href?.startsWith("http://") || href?.startsWith("https://") ? "_blank" : undefined}
      rel="noreferrer noopener"
      className="font-medium text-cyan-800 underline decoration-cyan-300 underline-offset-2 hover:text-cyan-950"
    >
      {children}
    </a>
  ),
  img: ({ alt }) => <span className="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-500">[图片：{alt || "无描述"}]</span>,
  code: ({ children, className }) => (
    <code className={cn("rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[0.85em] text-slate-900", className)}>
      {children}
    </code>
  ),
  pre: ({ children }) => (
    <pre className="my-4 max-h-[32rem] overflow-auto rounded-xl border border-slate-700 bg-slate-950 p-4 font-mono text-xs leading-6 text-slate-100 [&>code]:bg-transparent [&>code]:p-0 [&>code]:text-inherit">
      {children}
    </pre>
  ),
  table: ({ children }) => (
    <div className="my-4 overflow-x-auto rounded-xl border border-slate-200">
      <table className="w-full min-w-[32rem] border-collapse text-left text-sm">{children}</table>
    </div>
  ),
  thead: ({ children }) => <thead className="bg-slate-100 text-xs uppercase tracking-wide text-slate-600">{children}</thead>,
  tbody: ({ children }) => <tbody className="divide-y divide-slate-200 bg-white">{children}</tbody>,
  tr: ({ children }) => <tr className="divide-x divide-slate-200">{children}</tr>,
  th: ({ children }) => <th className="px-3 py-2.5 font-semibold">{children}</th>,
  td: ({ children }) => <td className="px-3 py-2.5 align-top leading-6 text-slate-700">{children}</td>,
  input: (props: ComponentPropsWithoutRef<"input">) => <input {...props} disabled className="mr-2 accent-cyan-700" />,
}

export function MarkdownContent({ children, className }: { children: string; className?: string }) {
  const normalizedMarkdown = useMemo(() => normalizeModelMarkdown(children), [children])

  return (
    <div className={cn("markdown-content min-w-0 break-words", className)}>
      <ReactMarkdown remarkPlugins={[remarkGfm]} skipHtml components={components}>
        {normalizedMarkdown}
      </ReactMarkdown>
    </div>
  )
}
