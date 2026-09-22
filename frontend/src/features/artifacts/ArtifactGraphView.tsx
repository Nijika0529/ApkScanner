import { Box, ChevronRight, Code2, FileArchive, Link2, Network, Route } from "lucide-react"
import { useMemo, useState } from "react"

import { Badge, Button } from "../../components/ui"
import { cn, shortHash } from "../../lib"
import type { ArtifactGraph } from "../../types"

type NativeBinding = {
  edge: ArtifactGraph["edges"][number]
  bridge: ArtifactGraph["nodes"][number] | undefined
  library: ArtifactGraph["nodes"][number] | undefined
}

type NativeBindingGroup = {
  id: string
  library: ArtifactGraph["nodes"][number] | undefined
  items: NativeBinding[]
  classNames: string[]
  staticCount: number
  dynamicCount: number
}

export function ArtifactGraphView({ graph }: { graph: ArtifactGraph }) {
  const [visibleLibraries, setVisibleLibraries] = useState(80)
  const [visibleBindingGroups, setVisibleBindingGroups] = useState(8)
  const nodesById = useMemo(
    () => new Map(graph.nodes.map((node) => [node.id, node])),
    [graph.nodes],
  )
  const apkNodes = graph.nodes.filter((node) => node.kind === "apk")
  const nativeNodes = graph.nodes.filter((node) => node.kind === "native_library")
  const bridgeNodes = graph.nodes.filter((node) => node.kind === "java_native_bridge")
  const pluginLoaderNodes = graph.nodes.filter((node) => node.kind === "plugin_loader_reference")
  const pluginEntryNodes = graph.nodes.filter((node) => node.kind === "embedded_plugin_entry")
  const summary = graph.summary ?? {}
  const abiCounts = asRecord(summary.native_libraries_by_abi) ?? {}
  const bridgeOwnership = asRecord(summary.java_bridges_by_ownership) ?? {}
  const bindings = useMemo<NativeBinding[]>(() => graph.edges
    .filter((edge) => ["binds_to_jni", "possible_dynamic_registration"].includes(edge.relation))
    .map((edge) => ({
      edge,
      bridge: nodesById.get(edge.from),
      library: nodesById.get(edge.to),
    })), [graph.edges, nodesById])
  const bindingGroups = useMemo<NativeBindingGroup[]>(() => {
    const groups = new Map<string, NativeBindingGroup>()
    bindings.forEach((item) => {
      const id = item.library?.id ?? item.edge.to
      const group = groups.get(id) ?? {
        id,
        library: item.library,
        items: [],
        classNames: [],
        staticCount: 0,
        dynamicCount: 0,
      }
      group.items.push(item)
      const className = textValue(item.bridge?.class_name) ?? textValue(item.edge.class_name) ?? item.edge.from
      if (!group.classNames.includes(className)) group.classNames.push(className)
      if (item.edge.relation === "binds_to_jni") group.staticCount += 1
      else group.dynamicCount += 1
      groups.set(id, group)
    })
    return [...groups.values()].sort((left, right) => right.items.length - left.items.length)
  }, [bindings])
  const loadEdges = graph.edges.filter((edge) => edge.relation === "loads_native_library")
  const embeddedEdges = graph.edges.filter((edge) => edge.relation === "contains")
  return <div className="space-y-6">
    <div className="rounded-xl border border-cyan-200 bg-cyan-50 px-4 py-3 text-sm leading-6 text-cyan-950">
      这里展示的是可追踪的产品资产关系，不是简单文件数量：主 APK、内嵌 APK、Java Native 声明、JNI 导出符号和具体 ABI 的 SO 都使用稳定节点连接。Agent 可沿同一组节点 ID 和路径继续读取反编译代码或执行 readelf、nm、strings。
    </div>
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-7">
      <Metric label="APK / 插件" value={numberValue(summary.apk_count) ?? apkNodes.length} icon={FileArchive} tone="cyan" />
      <Metric label="插件加载器" value={numberValue(summary.plugin_loader_count) ?? pluginLoaderNodes.length} icon={Route} tone="cyan" />
      <Metric label="插件入口" value={numberValue(summary.embedded_plugin_entry_count) ?? pluginEntryNodes.length} icon={Network} tone="emerald" />
      <Metric label="Native SO" value={numberValue(summary.native_library_count) ?? nativeNodes.length} icon={Box} tone="violet" />
      <Metric label="Java Native 方法" value={numberValue(summary.java_native_method_count) ?? 0} icon={Code2} tone="cyan" />
      <Metric label="已链接方法" value={numberValue(summary.linked_java_native_method_count) ?? bindings.length} icon={Link2} tone="emerald" />
      <Metric label="JNI 导出" value={numberValue(summary.jni_symbol_count) ?? 0} icon={Network} tone="rose" />
    </div>
    <div className="grid gap-5 xl:grid-cols-2">
      <section className="rounded-xl border border-slate-200 p-4">
        <SectionTitle icon={FileArchive} title="产品包层级" description="主包、内嵌 APK 与 ABI 分布" />
        <div className="mt-4 space-y-2">
          {apkNodes.map((node) => <div key={node.id} className="rounded-lg bg-slate-50 px-3 py-2"><div className="flex flex-wrap items-center justify-between gap-2"><p className="font-mono text-xs font-semibold text-slate-800">{textValue(node.package_name) ?? textValue(node.name) ?? node.id}</p><Badge tone={node.id === graph.root_id ? "info" : "warning"}>{node.id === graph.root_id ? "主 APK" : "内嵌 APK"}</Badge></div><p className="mt-1 truncate text-[11px] text-slate-500" title={node.path}>{node.path}</p></div>)}
          {!apkNodes.length && <EmptyRow text="没有 APK 资产节点" />}
        </div>
        {embeddedEdges.length > 0 && <p className="mt-3 text-xs text-slate-500">检测到 {embeddedEdges.length} 条嵌套包含关系；相同 SHA-256 的插件只分析一次，但保留全部嵌入位置。</p>}
        <div className="mt-4 flex flex-wrap gap-2">{Object.entries(abiCounts).map(([abi, count]) => <Badge key={abi}>{abi} · {String(count)}</Badge>)}{!Object.keys(abiCounts).length && <span className="text-xs text-slate-500">没有 Native ABI</span>}</div>
      </section>
      <section className="rounded-xl border border-slate-200 p-4">
        <SectionTitle icon={Link2} title="Java ↔ JNI ↔ SO" description="按 SO 聚合；展开后查看类、方法与符号绑定" />
        {bindings.length > 0 && <div className="mt-4 grid grid-cols-3 gap-2 rounded-lg border border-slate-200 bg-slate-50 p-3 text-center">
          <div><p className="text-lg font-bold tabular-nums text-slate-900">{bindingGroups.length}</p><p className="text-[11px] text-slate-500">关联 SO</p></div>
          <div><p className="text-lg font-bold tabular-nums text-slate-900">{bridgeNodes.length}</p><p className="text-[11px] text-slate-500">桥接类</p></div>
          <div><p className="text-lg font-bold tabular-nums text-slate-900">{bindings.length}</p><p className="text-[11px] text-slate-500">方法绑定</p></div>
        </div>}
        <div className="mt-3 space-y-2">
          {bindingGroups.slice(0, visibleBindingGroups).map((group) => <NativeBindingGroupCard key={group.id} group={group} />)}
          {!bindings.length && <EmptyRow text="尚未把 Java native 方法解析到静态 JNI 导出或动态注册候选" />}
        </div>
        {visibleBindingGroups < bindingGroups.length && <div className="mt-3 flex justify-center"><Button variant="secondary" size="sm" onClick={() => setVisibleBindingGroups((count) => count + 8)}>加载更多 SO · {bindingGroups.length - visibleBindingGroups}</Button></div>}
        {loadEdges.length > 0 && <p className="mt-3 text-xs text-slate-500">另有 {loadEdges.length} 条 System.loadLibrary / System.load 装载关系，覆盖 {bridgeNodes.length} 个 Java Native 桥类。</p>}
        <div className="mt-3 flex flex-wrap gap-2">{Object.entries(bridgeOwnership).map(([scope, count]) => <Badge key={scope} tone={scope === "application" ? "good" : scope === "vendor" ? "info" : "neutral"}>{scope} · {String(count)}</Badge>)}</div>
      </section>
    </div>
    {pluginLoaderNodes.length > 0 && <section className="rounded-xl border border-cyan-200 bg-cyan-50/40 p-4">
      <SectionTitle icon={Route} title="宿主 → 内嵌 APK → 插件入口" description="从包含关系提升为可追踪的实际加载链" />
      <div className="mt-4 space-y-3">{pluginLoaderNodes.map((loader) => {
        const loadedApkIds = graph.edges.filter((edge) => edge.from === loader.id && edge.relation === "loads_embedded_apk").map((edge) => edge.to)
        const invokedEntryIds = graph.edges.filter((edge) => edge.from === loader.id && edge.relation === "may_invoke_plugin_entry").map((edge) => edge.to)
        const loadedApks = loadedApkIds.map((id) => nodesById.get(id)).filter(Boolean)
        const invokedEntries = invokedEntryIds.map((id) => nodesById.get(id)).filter(Boolean)
        const mechanisms = Array.isArray(loader.mechanisms) ? loader.mechanisms : []
        return <div key={loader.id} className="rounded-lg border border-cyan-200 bg-white p-3"><div className="grid gap-3 text-xs lg:grid-cols-[1fr_auto_1fr_auto_1fr] lg:items-center"><div className="min-w-0"><p className="font-semibold text-slate-800">宿主加载证据</p><p className="mt-1 truncate font-mono text-slate-600" title={loader.path}>{loader.path}</p><div className="mt-2 flex flex-wrap gap-1">{mechanisms.map((value) => <Badge key={String(value)}>{String(value)}</Badge>)}</div></div><ChevronRight className="hidden h-4 w-4 text-cyan-500 lg:block" /><div className="min-w-0"><p className="font-semibold text-slate-800">{loadedApks.map((node) => textValue(node?.package_name) ?? node?.id).join(", ") || "内嵌 APK"}</p><p className="mt-1 truncate font-mono text-slate-600">{textValue(loader.archive_path) ?? textValue(loader.name)}</p></div><ChevronRight className="hidden h-4 w-4 text-cyan-500 lg:block" /><div className="min-w-0"><p className="font-semibold text-slate-800">入口候选</p>{invokedEntries.length ? invokedEntries.map((node) => <p key={node?.id} className="mt-1 truncate font-mono text-slate-600" title={textValue(node?.class_name)}>{textValue(node?.class_name) ?? node?.id}</p>) : <p className="mt-1 text-slate-500">尚未解析入口类</p>}</div></div></div>
      })}</div>
    </section>}
    <section>
      <SectionTitle icon={Box} title="Native 库总览" description="标准化 ELF、动态符号、JNI 与基础加固摘要" />
      <div className="mt-4 overflow-x-auto rounded-xl border border-slate-200"><table className="w-full min-w-[980px] text-left text-sm"><thead className="bg-slate-50 text-xs text-slate-500"><tr><th className="px-4 py-3 font-medium">SO / ABI</th><th className="px-4 py-3 font-medium">ELF</th><th className="px-4 py-3 font-medium">依赖</th><th className="px-4 py-3 font-medium">符号</th><th className="px-4 py-3 font-medium">JNI</th><th className="px-4 py-3 font-medium">加固摘要</th></tr></thead><tbody className="divide-y divide-slate-200">{nativeNodes.slice(0, visibleLibraries).map((node) => {
        const elf = asRecord(node.elf) ?? {}
        const symbols = asRecord(node.symbols) ?? {}
        const jni = asRecord(node.jni) ?? {}
        const hardening = asRecord(node.hardening) ?? {}
        const dependencies = Array.isArray(node.dependencies) ? node.dependencies : []
        return <tr key={node.id} className="align-top hover:bg-slate-50"><td className="px-4 py-3"><p className="font-mono text-xs font-semibold text-slate-800">{textValue(node.name) ?? node.id}</p><p className="mt-1 text-[11px] text-slate-500">{textValue(node.abi) ?? "unknown"} · {shortHash(textValue(node.sha256) ?? "")}</p></td><td className="px-4 py-3 text-xs text-slate-600">{elf.valid === false ? <Badge tone="warning">非 ELF / 解析失败</Badge> : <><p>{textValue(elf.machine_description) ?? textValue(elf.machine) ?? "未知架构"}</p><p className="mt-1 text-slate-500">{textValue(elf.class) ?? `${String(elf.bits ?? "?")} bit`} · {textValue(elf.soname) ?? "无 SONAME"}</p></>}</td><td className="max-w-xs px-4 py-3 text-xs text-slate-600"><p className="line-clamp-3" title={dependencies.join(", ")}>{dependencies.slice(0, 6).join(", ") || "无动态依赖记录"}</p></td><td className="px-4 py-3 text-xs text-slate-600">导出 {String(symbols.exported_count ?? 0)}<br />导入 {String(symbols.imported_count ?? 0)}</td><td className="px-4 py-3 text-xs"><div className="flex flex-wrap gap-1"><Badge tone={numberValue(jni.export_count) ? "info" : "neutral"}>导出 {String(jni.export_count ?? 0)}</Badge>{jni.dynamic_registration === true && <Badge tone="warning">动态注册</Badge>}{jni.has_jni_onload === true && <Badge>JNI_OnLoad</Badge>}</div></td><td className="px-4 py-3 text-xs"><div className="flex flex-wrap gap-1"><Badge tone={hardening.gnu_relro === true ? "good" : "warning"}>RELRO</Badge><Badge tone={hardening.stack_canary === true ? "good" : "neutral"}>Canary</Badge><Badge tone={hardening.executable_stack === false ? "good" : hardening.executable_stack === true ? "danger" : "neutral"}>NX Stack</Badge>{hardening.stripped === true && <Badge>Stripped</Badge>}</div></td></tr>
      })}</tbody></table>{!nativeNodes.length && <EmptyRow text="当前产品包没有 Native 库" />}</div>
      {visibleLibraries < nativeNodes.length && <div className="mt-3 flex justify-center"><Button variant="secondary" size="sm" onClick={() => setVisibleLibraries((count) => count + 80)}>加载更多 SO · {nativeNodes.length - visibleLibraries}</Button></div>}
    </section>
  </div>
}

function NativeBindingGroupCard({ group }: { group: NativeBindingGroup }) {
  const [open, setOpen] = useState(false)
  const classGroups = useMemo(() => {
    if (!open) return []
    const grouped = new Map<string, NativeBinding[]>()
    group.items.forEach((item) => {
      const className = textValue(item.bridge?.class_name) ?? textValue(item.edge.class_name) ?? item.edge.from
      grouped.set(className, [...(grouped.get(className) ?? []), item])
    })
    return [...grouped.entries()].sort((left, right) => right[1].length - left[1].length)
  }, [group.items, open])
  const libraryName = textValue(group.library?.name) ?? group.id
  const abi = textValue(group.library?.abi) ?? "ABI 未知"
  return <article className="overflow-hidden rounded-lg border border-slate-200 bg-white">
    <button type="button" onClick={() => setOpen((value) => !value)} aria-expanded={open} className="w-full px-3 py-3 text-left transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-cyan-700">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <p className="min-w-0 truncate font-mono text-xs font-semibold text-violet-800" title={libraryName}>{libraryName}</p>
            <Badge>{abi}</Badge>
            <Badge tone="info">{group.items.length} 个方法</Badge>
            {group.dynamicCount > 0 && <Badge tone="warning">动态注册 {group.dynamicCount}</Badge>}
          </div>
          <div className="mt-2 flex min-w-0 flex-wrap gap-1.5">
            {group.classNames.slice(0, 3).map((className) => <span key={className} title={className} className="max-w-full truncate rounded-md bg-slate-100 px-2 py-1 font-mono text-[10px] text-slate-600">{className}</span>)}
            {group.classNames.length > 3 && <span className="rounded-md bg-slate-100 px-2 py-1 text-[10px] font-semibold text-slate-500">+{group.classNames.length - 3} 个类</span>}
          </div>
        </div>
        <ChevronRight className={cn("mt-1 h-4 w-4 shrink-0 text-slate-500 transition-transform", open && "rotate-90")} />
      </div>
    </button>
    {open && <div className="border-t border-slate-200 bg-slate-50/60 p-3">
      <div className="mb-2 flex flex-wrap gap-2 text-[11px] text-slate-500"><span>静态导出 {group.staticCount}</span><span>动态注册推断 {group.dynamicCount}</span><span>Java 类 {group.classNames.length}</span></div>
      <div className="max-h-80 space-y-2 overflow-y-auto pr-1">
        {classGroups.map(([className, items]) => <div key={className} className="rounded-lg border border-slate-200 bg-white p-3">
          <div className="flex items-center justify-between gap-3"><p className="min-w-0 truncate font-mono text-[11px] font-semibold text-slate-800" title={className}>{className}</p><Badge>{items.length}</Badge></div>
          <div className="mt-2 divide-y divide-slate-100">{items.map(({ edge }, index) => <div key={`${edge.from}:${edge.to}:${textValue(edge.method_signature_key) ?? `${textValue(edge.method_name) ?? "dynamic"}:${index}`}`} className="grid gap-1 py-2 text-[11px] sm:grid-cols-[minmax(7rem,0.35fr)_minmax(0,0.65fr)] sm:gap-3">
            <p className="truncate font-mono font-semibold text-slate-700" title={textValue(edge.method_name) ?? edge.from}>{textValue(edge.method_name) ?? "动态注册候选"}</p>
            <div className="min-w-0"><p className="truncate font-mono text-slate-600" title={textValue(edge.jni_symbol)}>{textValue(edge.jni_symbol) ?? "RegisterNatives 符号待运行时确认"}</p><p className="mt-0.5 text-[10px] text-slate-400">{edge.relation === "binds_to_jni" ? "静态 JNI 导出" : "动态注册推断"} · {textValue(edge.confidence) ?? "unknown"}</p></div>
          </div>)}</div>
        </div>)}
      </div>
    </div>}
  </article>
}


function Metric({ label, value, icon: Icon, tone }: { label: string; value: number | string; icon: typeof Box; tone: "rose" | "cyan" | "violet" | "emerald" }) {
  const tones = { rose: "from-rose-50 text-rose-700", cyan: "from-cyan-50 text-cyan-700", violet: "from-violet-50 text-violet-700", emerald: "from-emerald-50 text-emerald-700" }
  return <div className={`rounded-xl border border-slate-200 bg-gradient-to-br ${tones[tone]} to-white p-4`}><Icon className="h-4 w-4" /><p className="mt-3 text-2xl font-bold tabular-nums text-slate-950">{value}</p><p className="mt-1 text-xs text-slate-500">{label}</p></div>
}

function SectionTitle({ icon: Icon, title, description }: { icon: typeof Box; title: string; description: string }) {
  return <div className="flex items-center gap-3"><div className="grid h-9 w-9 place-items-center rounded-lg bg-slate-100 text-cyan-700"><Icon className="h-4 w-4" /></div><div><h3 className="text-sm font-semibold text-slate-900">{title}</h3><p className="text-xs text-slate-600">{description}</p></div></div>
}

function EmptyRow({ text }: { text: string }) {
  return <div className="grid min-h-32 place-items-center p-6 text-sm text-slate-600">{text}</div>
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined
}

function textValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined
}
