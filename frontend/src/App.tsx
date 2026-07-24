import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  Bot,
  Box,
  Check,
  ChevronRight,
  CircleDot,
  Clock3,
  Code2,
  FileArchive,
  Fingerprint,
  Gauge,
  Link2,
  ListChecks,
  LoaderCircle,
  Menu,
  Network,
  Plus,
  RefreshCw,
  ScanSearch,
  ScrollText,
  ServerCog,
  ShieldCheck,
  ShieldX,
  Smartphone,
  Trash2,
  UploadCloud,
  X,
} from "lucide-react"
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react"
import { api } from "./api"
import { Badge, Button, Card, Dialog, DialogContent, DialogDescription, DialogTitle, Progress, Tabs, TabsContent, TabsList, TabsTrigger } from "./components/ui"
import { cn, formatDate, shortHash, statusLabel } from "./lib"
import type { AgentAudit, CoverageItem, EntryPoint, Finding, Health, InvestigationTask, InvestigatorChoice, Scan, ScanEvent } from "./types"

const severityTone = {
  critical: "danger",
  high: "danger",
  medium: "warning",
  low: "info",
  info: "neutral",
} as const

function statusTone(status: string): "neutral" | "good" | "warning" | "danger" | "info" {
  if (["final", "completed", "covered", "accepted", "reproduced_blackbox"].includes(status)) return "good"
  if (["failed", "critical", "high", "tool_failed"].includes(status)) return "danger"
  if (["inconclusive", "timed_out", "blocked_device", "partial", "degraded", "preliminary_ready"].includes(status)) return "warning"
  if (["investigating", "static_running", "observed_instrumented", "running"].includes(status)) return "info"
  return "neutral"
}

function scanProgress(status: string) {
  return { queued: 5, intake: 12, static_running: 35, static_complete: 55, preliminary_ready: 68, investigating: 82, final: 100, failed: 100 }[status] ?? 0
}

interface DetailData {
  scan: Scan
  entries: EntryPoint[]
  findings: Finding[]
  coverage: CoverageItem[]
  tasks: InvestigationTask[]
  audits: AgentAudit[]
  events: ScanEvent[]
}

function App() {
  const [scans, setScans] = useState<Scan[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [detail, setDetail] = useState<DetailData | null>(null)
  const [health, setHealth] = useState<Health | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [uploadOpen, setUploadOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<Scan | null>(null)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)

  const loadScans = useCallback(async () => {
    const data = await api.scans()
    setScans(data)
    setSelectedId((current) => current ?? data[0]?.id ?? null)
  }, [])

  const loadDetail = useCallback(async (id: string) => {
    const [scan, entries, findings, coverage, tasks, audits, events] = await Promise.all([
      api.scan(id), api.entries(id), api.findings(id), api.coverage(id), api.tasks(id), api.agentAudits(id), api.events(id),
    ])
    setDetail({ scan, entries, findings, coverage, tasks, audits, events })
    setScans((items) => items.map((item) => item.id === scan.id ? scan : item))
  }, [])

  useEffect(() => {
    Promise.all([loadScans(), api.health().then(setHealth)])
      .catch((reason: Error) => setError(reason.message))
      .finally(() => setLoading(false))
  }, [loadScans])

  useEffect(() => {
    if (!selectedId) { setDetail(null); return }
    setLoading(true)
    loadDetail(selectedId).catch((reason: Error) => setError(reason.message)).finally(() => setLoading(false))
    const source = new EventSource(`/api/v1/scans/${selectedId}/events/stream`)
    const refresh = () => void loadDetail(selectedId).catch(() => undefined)
    source.onmessage = refresh
    source.addEventListener("static.completed", refresh)
    source.addEventListener("task.completed", refresh)
    source.addEventListener("scan.final", refresh)
    source.addEventListener("scan.failed", refresh)
    source.addEventListener("end", () => source.close())
    return () => source.close()
  }, [selectedId, loadDetail])

  async function onUploaded(scan: Scan) {
    setUploadOpen(false)
    setScans((items) => [scan, ...items])
    setSelectedId(scan.id)
    await loadDetail(scan.id)
  }

  async function onDeleted(scanId: string, warnings: string[]) {
    const remaining = scans.filter((scan) => scan.id !== scanId)
    setDeleteTarget(null)
    setScans(remaining)
    setDetail(null)
    setSelectedId(remaining[0]?.id ?? null)
    if (warnings.length) setError(`扫描已删除，但有文件未能清理：${warnings.join("；")}`)
  }

  const sidebar = (
    <Sidebar
      scans={scans}
      selectedId={selectedId}
      health={health}
      onSelect={(id) => { setSelectedId(id); setMobileNavOpen(false) }}
      onUpload={() => { setUploadOpen(true); setMobileNavOpen(false) }}
    />
  )

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <a href="#main-content" className="sr-only fixed left-4 top-4 z-[100] rounded-lg bg-cyan-700 px-4 py-2 font-semibold text-white focus:not-sr-only">跳到主要内容</a>
      <div className="app-grid" aria-hidden="true" />
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-80 border-r border-slate-200/80 bg-white/95 backdrop-blur-xl lg:block">{sidebar}</aside>
      {mobileNavOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <button className="absolute inset-0 bg-slate-900/35" aria-label="关闭导航" onClick={() => setMobileNavOpen(false)} />
          <aside className="relative h-full w-[min(88vw,22rem)] border-r border-slate-200 bg-white shadow-2xl">{sidebar}</aside>
        </div>
      )}
      <main id="main-content" className="relative min-h-screen lg:pl-80">
        <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-slate-200/80 bg-white/85 px-4 backdrop-blur-xl sm:px-6 lg:px-8">
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="icon" className="lg:hidden" onClick={() => setMobileNavOpen(true)} aria-label="打开扫描列表"><Menu className="h-5 w-5" /></Button>
            <div>
              <p className="text-sm font-semibold text-slate-900">{detail?.scan.package_name ?? detail?.scan.filename ?? "安全审计工作台"}</p>
              <p className="hidden text-xs text-slate-500 sm:block">APK-only · Android 16 · evidence-first</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {detail && <Badge tone={statusTone(detail.scan.status)}><span className={cn("mr-1.5 h-1.5 w-1.5 rounded-full", detail.scan.status === "final" ? "bg-emerald-400" : "animate-pulse bg-current motion-reduce:animate-none")} />{statusLabel(detail.scan.status)}</Badge>}
            <Button variant="secondary" size="sm" onClick={() => selectedId && loadDetail(selectedId)} disabled={!selectedId} aria-label="刷新数据"><RefreshCw className="h-3.5 w-3.5" /><span className="hidden sm:inline">刷新</span></Button>
          </div>
        </header>
        <div className="mx-auto max-w-[1500px] p-4 sm:p-6 lg:p-8">
          {error && <div role="alert" className="mb-6 flex items-start gap-3 rounded-xl border border-rose-500/35 bg-rose-500/10 p-4 text-sm text-rose-800"><AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" /><span>{error}</span><button className="ml-auto" onClick={() => setError(null)} aria-label="关闭错误"><X className="h-4 w-4" /></button></div>}
          {loading && !detail ? <LoadingState /> : detail ? <ScanDetailView data={detail} health={health} onRefresh={() => loadDetail(detail.scan.id)} onDelete={() => setDeleteTarget(detail.scan)} /> : <EmptyState onUpload={() => setUploadOpen(true)} />}
        </div>
      </main>
      <UploadDialog open={uploadOpen} onOpenChange={setUploadOpen} onUploaded={onUploaded} health={health} />
      <DeleteScanDialog scan={deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)} onDeleted={onDeleted} />
    </div>
  )
}

function Sidebar({ scans, selectedId, health, onSelect, onUpload }: { scans: Scan[]; selectedId: string | null; health: Health | null; onSelect: (id: string) => void; onUpload: () => void }) {
  const ready = health?.capabilities.filter((item) => item.available).length ?? 0
  const total = health?.capabilities.length ?? 0
  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-slate-200 p-6">
        <div className="mb-6 flex items-center gap-3">
          <div className="grid h-11 w-11 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-400/10 text-cyan-700 shadow-[0_0_30px_rgba(34,211,238,.1)]"><Fingerprint className="h-6 w-6" /></div>
          <div><h1 className="font-display text-lg font-bold tracking-tight">APK Scanner</h1><p className="text-xs text-slate-500">Mobile attack surface lab</p></div>
        </div>
        <Button className="w-full" onClick={onUpload}><Plus className="h-4 w-4" />新建 APK 扫描</Button>
      </div>
      <nav className="min-h-0 flex-1 overflow-y-auto p-3" aria-label="扫描任务">
        <p className="px-3 pb-2 pt-2 text-[11px] font-bold uppercase tracking-[.16em] text-slate-600">最近扫描</p>
        <div className="space-y-1">
          {scans.map((scan) => (
            <button key={scan.id} onClick={() => onSelect(scan.id)} className={cn("group w-full rounded-xl border px-3 py-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-700", selectedId === scan.id ? "border-cyan-500/30 bg-cyan-500/10" : "border-transparent hover:border-slate-200 hover:bg-slate-100")}>
              <div className="mb-1.5 flex items-center justify-between gap-2"><span className="truncate text-sm font-medium text-slate-800">{scan.package_name ?? scan.filename}</span><ChevronRight className={cn("h-4 w-4 shrink-0 text-slate-700", selectedId === scan.id && "text-cyan-600")} /></div>
              <div className="flex items-center justify-between gap-2 text-[11px] text-slate-500"><span>{formatDate(scan.created_at)}</span><span>{statusLabel(scan.status)}</span></div>
            </button>
          ))}
          {!scans.length && <p className="px-3 py-8 text-center text-sm text-slate-600">还没有扫描记录</p>}
        </div>
      </nav>
      <div className="border-t border-slate-200 p-4">
        <div className="rounded-xl bg-slate-100 p-3">
          <div className="mb-2 flex items-center justify-between text-xs"><span className="flex items-center gap-2 text-slate-600"><ServerCog className="h-3.5 w-3.5" />本机能力</span><span className="font-mono text-slate-700">{ready}/{total}</span></div>
          <div className="h-1.5 overflow-hidden rounded-full bg-slate-200"><div className="h-full bg-cyan-700" style={{ width: `${total ? ready / total * 100 : 0}%` }} /></div>
        </div>
      </div>
    </div>
  )
}

function ScanDetailView({ data, health, onRefresh, onDelete }: { data: DetailData; health: Health | null; onRefresh: () => Promise<void>; onDelete: () => void }) {
  const { scan, entries, findings, coverage, tasks, audits, events } = data
  const high = findings.filter((item) => ["critical", "high"].includes(item.severity)).length
  const reproduced = findings.filter((item) => item.status === "reproduced_blackbox").length
  const exported = entries.filter((item) => item.exported && item.kind !== "deep_link").length
  const links = entries.filter((item) => item.kind === "deep_link").length
  const covered = coverage.filter((item) => item.status === "covered").length
  const coveragePercent = coverage.length ? covered / coverage.length * 100 : 0
  return (
    <div className="space-y-6">
      <section className="relative overflow-hidden rounded-2xl border border-slate-200 bg-gradient-to-br from-white via-white to-cyan-50 p-5 shadow-sm sm:p-7">
        <div className="absolute -right-20 -top-28 h-72 w-72 rounded-full bg-cyan-400/10 blur-3xl" />
        <div className="relative flex flex-col gap-6 xl:flex-row xl:items-end xl:justify-between">
          <div className="min-w-0">
            <div className="mb-3 flex flex-wrap items-center gap-2"><Badge tone="info">Android {String(scan.target_sdk ?? "?")}</Badge><Badge>{scan.version_name ?? "版本未知"}</Badge><Badge tone={scan.signing && (scan.signing.verified as boolean) ? "good" : "warning"}>{scan.signing && (scan.signing.verified as boolean) ? "签名已验证" : "签名待验证"}</Badge></div>
            <h2 className="font-display truncate text-2xl font-bold tracking-tight text-slate-950 sm:text-3xl">{scan.package_name ?? scan.filename}</h2>
            <div className="mt-3 flex flex-wrap gap-x-5 gap-y-2 font-mono text-xs text-slate-500"><span>SHA256 {shortHash(scan.artifact_sha256)}</span><span>versionCode {scan.version_code ?? "—"}</span><span>minSdk {scan.min_sdk ?? "—"}</span></div>
          </div>
          <div className="w-full max-w-lg space-y-3"><Progress value={scanProgress(scan.status)} label="扫描进度" /><div className="flex flex-wrap gap-2"><ReportLink scanId={scan.id} format="html" label="HTML" /><ReportLink scanId={scan.id} format="json" label="JSON" /><ReportLink scanId={scan.id} format="sarif" label="SARIF" /><Button variant="danger" size="sm" onClick={onDelete} disabled={!["final", "failed"].includes(scan.status)} title={["final", "failed"].includes(scan.status) ? "永久删除扫描及其独占文件" : "运行中的扫描不能删除"}><Trash2 className="h-3.5 w-3.5" />删除扫描</Button></div></div>
        </div>
      </section>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Metric label="高危候选" value={high} icon={AlertTriangle} tone="rose" />
        <Metric label="黑盒复现" value={reproduced} icon={ShieldX} tone="rose" />
        <Metric label="导出组件" value={exported} icon={Box} tone="cyan" />
        <Metric label="Deep Link" value={links} icon={Link2} tone="cyan" />
        <Metric label="探索任务" value={tasks.length} icon={Bot} tone="violet" />
        <Metric label="覆盖项目" value={`${Math.round(coveragePercent)}%`} icon={Gauge} tone="emerald" />
      </div>
      <Card className="p-4 sm:p-6">
        <Tabs defaultValue="overview">
          <TabsList aria-label="扫描详情">
            <TabsTrigger value="overview">总览</TabsTrigger><TabsTrigger value="entries">攻击面 <span className="ml-1 text-xs text-slate-500">{entries.length}</span></TabsTrigger><TabsTrigger value="findings">Finding <span className="ml-1 text-xs text-slate-500">{findings.length}</span></TabsTrigger><TabsTrigger value="coverage">覆盖矩阵</TabsTrigger><TabsTrigger value="tasks">探索任务</TabsTrigger><TabsTrigger value="audits">AI 审计 <span className="ml-1 text-xs text-slate-500">{audits.length}</span></TabsTrigger>
          </TabsList>
          <TabsContent value="overview"><Overview scan={scan} events={events} health={health} coverage={coverage} /></TabsContent>
          <TabsContent value="entries"><EntryPoints entries={entries} /></TabsContent>
          <TabsContent value="findings"><Findings findings={findings} onRefresh={onRefresh} /></TabsContent>
          <TabsContent value="coverage"><CoverageMatrix coverage={coverage} /></TabsContent>
          <TabsContent value="tasks"><Tasks tasks={tasks} entries={entries} audits={audits} onRefresh={onRefresh} /></TabsContent>
          <TabsContent value="audits"><AgentAudits audits={audits} tasks={tasks} entries={entries} /></TabsContent>
        </Tabs>
      </Card>
    </div>
  )
}

function Overview({ scan, events, health, coverage }: { scan: Scan; events: ScanEvent[]; health: Health | null; coverage: CoverageItem[] }) {
  const baselines = coverage.filter((item) => item.control_id.endsWith("-BASELINE"))
  return <div className="grid gap-6 xl:grid-cols-[1.35fr_.65fr]">
    <div><SectionTitle icon={Activity} title="扫描活动" description="平台事件与证据生成轨迹" /><ol className="mt-4 space-y-1">{events.slice().reverse().map((event, index) => <li key={event.id} className="relative flex gap-4 py-3"><div className="relative flex w-5 justify-center"><span className={cn("mt-1.5 h-2.5 w-2.5 rounded-full border-2", index === 0 ? "border-cyan-300 bg-cyan-600" : "border-slate-300 bg-slate-100")} />{index < events.length - 1 && <span className="absolute left-1/2 top-6 h-[calc(100%-10px)] w-px -translate-x-1/2 bg-slate-100" />}</div><div className="min-w-0"><p className="text-sm text-slate-800">{event.message}</p><p className="mt-1 text-xs text-slate-600">{formatDate(event.created_at)} · {event.event_type}</p></div></li>)}{!events.length && <EmptyRow text="扫描事件尚未生成" />}</ol></div>
    <div className="space-y-6"><div><SectionTitle icon={ListChecks} title="MASVS 基线" description="APK-only 初始覆盖" /><div className="mt-4 space-y-3">{baselines.map((item) => <div key={item.id} className="rounded-xl border border-slate-200 bg-slate-50 p-3"><div className="mb-2 flex items-center justify-between gap-3"><span className="text-xs font-semibold text-slate-700">{item.domain.replace("MASVS-", "")}</span><Badge tone={statusTone(item.status)}>{statusLabel(item.status)}</Badge></div><p className="text-xs leading-relaxed text-slate-500">{item.gap_reason ?? item.title}</p></div>)}</div></div><div><SectionTitle icon={ServerCog} title="运行能力" description="缺失能力会形成覆盖缺口" /><div className="mt-4 grid grid-cols-2 gap-2">{health?.capabilities.map((item) => <div key={item.name} className="flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-xs"><span className={cn("h-2 w-2 rounded-full", item.available ? "bg-emerald-400" : "bg-slate-300")} /><span className="truncate text-slate-600">{item.name}</span></div>)}</div></div></div>
    {scan.error && <p className="text-rose-700">{scan.error}</p>}
  </div>
}

function EntryPoints({ entries }: { entries: EntryPoint[] }) {
  const [query, setQuery] = useState("")
  const [kind, setKind] = useState("all")
  const filtered = entries.filter((entry) => (kind === "all" || entry.kind === kind) && `${entry.name} ${entry.owner_component}`.toLowerCase().includes(query.toLowerCase()))
  return <div><div className="mb-5 flex flex-col gap-3 sm:flex-row"><label className="flex-1"><span className="sr-only">搜索入口</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索组件、URI 或 authority" className="field" /></label><label><span className="sr-only">入口类型</span><select value={kind} onChange={(event) => setKind(event.target.value)} className="field sm:w-48"><option value="all">全部入口</option><option value="activity">Activity</option><option value="service">Service</option><option value="receiver">Receiver</option><option value="provider">Provider</option><option value="deep_link">Deep Link</option></select></label></div><div className="overflow-x-auto rounded-xl border border-slate-200"><table className="w-full min-w-[760px] text-left text-sm"><thead className="bg-slate-50 text-xs text-slate-500"><tr><th className="px-4 py-3 font-medium">类型</th><th className="px-4 py-3 font-medium">入口</th><th className="px-4 py-3 font-medium">可达性</th><th className="px-4 py-3 font-medium">权限</th><th className="px-4 py-3 font-medium">判定依据</th></tr></thead><tbody className="divide-y divide-slate-200">{filtered.map((entry) => <tr key={entry.id} className="hover:bg-slate-100"><td className="px-4 py-3"><EntryIcon kind={entry.kind} /></td><td className="max-w-md px-4 py-3"><p className="truncate font-mono text-xs text-slate-800" title={entry.name}>{entry.name}</p>{entry.owner_component && entry.owner_component !== entry.name && <p className="mt-1 truncate text-xs text-slate-600">handler · {entry.owner_component}</p>}</td><td className="px-4 py-3"><Badge tone={entry.exported ? "warning" : "good"}>{entry.exported ? "外部可达" : "私有"}</Badge></td><td className="px-4 py-3 text-xs text-slate-600">{entry.permission ?? "无"}{entry.permission_protection && <span className="block text-slate-600">{entry.permission_protection}</span>}</td><td className="px-4 py-3 text-xs text-slate-500">{entry.exported_reason}</td></tr>)}</tbody></table>{!filtered.length && <EmptyRow text="没有匹配的入口" />}</div></div>
}

function Findings({ findings, onRefresh }: { findings: Finding[]; onRefresh: () => Promise<void> }) {
  const sorted = [...findings].sort((a, b) => ["critical", "high", "medium", "low", "info"].indexOf(a.severity) - ["critical", "high", "medium", "low", "info"].indexOf(b.severity))
  return <div className="space-y-3">{sorted.map((finding) => <FindingCard key={finding.id} finding={finding} onRefresh={onRefresh} />)}{!findings.length && <EmptyRow text="尚未产生 Finding" />}</div>
}

function FindingCard({ finding, onRefresh }: { finding: Finding; onRefresh: () => Promise<void> }) {
  const [open, setOpen] = useState(false)
  const [reviewOpen, setReviewOpen] = useState(false)
  return <article className="rounded-xl border border-slate-200 bg-slate-50/70"><button onClick={() => setOpen(!open)} className="flex w-full items-start gap-4 p-4 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-700 sm:p-5" aria-expanded={open}><Badge tone={severityTone[finding.severity]} className="mt-0.5 min-w-16 justify-center uppercase">{finding.severity}</Badge><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><h3 className="font-semibold text-slate-900">{finding.title}</h3><Badge tone={statusTone(finding.status)}>{statusLabel(finding.status)}</Badge></div><p className="mt-1.5 line-clamp-2 text-sm leading-relaxed text-slate-500">{finding.description}</p><div className="mt-3 flex flex-wrap gap-3 text-[11px] text-slate-600"><span>{finding.masvs}</span>{finding.cwe && <span>{finding.cwe}</span>}<span>置信度 {finding.confidence}</span><span>{finding.source}</span></div></div><ChevronRight className={cn("mt-1 h-4 w-4 shrink-0 text-slate-600 transition-transform", open && "rotate-90")} /></button>{open && <div className="border-t border-slate-200 px-4 py-5 sm:px-5"><div className="grid gap-5 lg:grid-cols-2"><div><p className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500">风险说明</p><p className="text-sm leading-7 text-slate-700">{finding.description}</p></div><div><p className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500">修复建议</p><p className="text-sm leading-7 text-slate-700">{finding.remediation}</p></div></div><div className="mt-5 flex flex-wrap items-center justify-between gap-3"><p className="font-mono text-xs text-slate-600">rule · {finding.rule_id} · evidence {finding.evidence_ids.length}</p><Button variant="secondary" size="sm" onClick={() => setReviewOpen(true)}>人工审核</Button></div></div>}<ReviewDialog finding={finding} open={reviewOpen} onOpenChange={setReviewOpen} onReviewed={onRefresh} /></article>
}

function ReviewDialog({ finding, open, onOpenChange, onReviewed }: { finding: Finding; open: boolean; onOpenChange: (open: boolean) => void; onReviewed: () => Promise<void> }) {
  const [status, setStatus] = useState<"accepted" | "false_positive" | "candidate">("accepted")
  const [note, setNote] = useState("")
  const [saving, setSaving] = useState(false)
  async function submit(event: FormEvent) { event.preventDefault(); setSaving(true); try { await api.review(finding.id, status, note); onOpenChange(false); setNote(""); await onReviewed() } finally { setSaving(false) } }
  return <Dialog open={open} onOpenChange={onOpenChange}><DialogContent><DialogTitle className="text-xl font-bold text-slate-950">审核 Finding</DialogTitle><DialogDescription className="mt-2 text-sm text-slate-600">Agent 和规则结论不会自动成为发布门禁，请记录人工判断依据。</DialogDescription><form className="mt-6 space-y-5" onSubmit={submit}><fieldset><legend className="mb-3 text-sm font-semibold text-slate-800">审核结论</legend><div className="grid grid-cols-3 gap-2">{([['accepted','接受'],['false_positive','误报'],['candidate','待确认']] as const).map(([value,label]) => <label key={value} className={cn("cursor-pointer rounded-lg border p-3 text-center text-sm", status === value ? "border-cyan-400 bg-cyan-400/10 text-cyan-800" : "border-slate-300 text-slate-600")}><input type="radio" name="status" value={value} checked={status === value} onChange={() => setStatus(value)} className="sr-only" />{label}</label>)}</div></fieldset><label className="block"><span className="mb-2 block text-sm font-semibold text-slate-800">审核备注 <span className="text-rose-700">*</span></span><textarea required minLength={1} maxLength={4000} value={note} onChange={(event) => setNote(event.target.value)} rows={5} className="field resize-y" placeholder="说明接受、误报或待确认的依据" /></label><div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>取消</Button><Button type="submit" disabled={saving || !note.trim()}>{saving && <LoaderCircle className="h-4 w-4 animate-spin" />}保存审核</Button></div></form></DialogContent></Dialog>
}

function CoverageMatrix({ coverage }: { coverage: CoverageItem[] }) {
  const baseline = coverage.filter((item) => item.control_id.endsWith("-BASELINE"))
  const entryCoverage = coverage.filter((item) => item.entry_point_id)
  const stages = ["static", "deterministic_dynamic", "agent", "blackbox", "instrumented"]
  return <div className="space-y-8"><div><SectionTitle icon={ShieldCheck} title="MASVS 域覆盖" description="覆盖不代表无漏洞；缺口必须进入报告" /><div className="mt-4 overflow-x-auto rounded-xl border border-slate-200"><table className="w-full min-w-[850px] text-sm"><thead className="bg-slate-50 text-xs text-slate-500"><tr><th className="px-4 py-3 text-left font-medium">Domain</th>{stages.map((stage) => <th key={stage} className="px-3 py-3 text-center font-medium">{stage.replace("deterministic_dynamic", "确定性动态")}</th>)}<th className="px-4 py-3 text-left font-medium">缺口</th></tr></thead><tbody className="divide-y divide-slate-200">{baseline.map((item) => <tr key={item.id}><td className="px-4 py-3 font-semibold text-slate-700">{item.domain}</td>{stages.map((stage) => <td key={stage} className="px-3 py-3 text-center"><StageState value={String(item.stages[stage] ?? "pending")} /></td>)}<td className="max-w-xs px-4 py-3 text-xs leading-relaxed text-slate-500">{item.gap_reason ?? "—"}</td></tr>)}</tbody></table></div></div><div><SectionTitle icon={CircleDot} title="入口覆盖" description={`${entryCoverage.length} 个入口的逐项状态`} /><div className="mt-4 grid gap-2 md:grid-cols-2 xl:grid-cols-3">{entryCoverage.map((item) => <div key={item.id} className="rounded-xl border border-slate-200 p-3"><div className="mb-2 flex items-center justify-between gap-3"><p className="truncate font-mono text-xs text-slate-700" title={item.title}>{item.title.replace("Entry point: ", "")}</p><Badge tone={statusTone(item.status)}>{statusLabel(item.status)}</Badge></div><p className="line-clamp-2 text-xs text-slate-600">{item.gap_reason ?? "全部计划阶段已记录"}</p></div>)}</div></div></div>
}

function Tasks({ tasks, entries, audits, onRefresh }: { tasks: InvestigationTask[]; entries: EntryPoint[]; audits: AgentAudit[]; onRefresh: () => Promise<void> }) {
  const names = new Map(entries.map((item) => [item.id, item.name]))
  const auditCounts = audits.reduce((counts, audit) => counts.set(audit.task_id, (counts.get(audit.task_id) ?? 0) + 1), new Map<string | null, number>())
  const [retrying, setRetrying] = useState<string | null>(null)
  async function retry(id: string) { setRetrying(id); try { await api.retryTask(id); await onRefresh() } finally { setRetrying(null) } }
  return <div className="space-y-3">{tasks.map((task) => <article key={task.id} className="rounded-xl border border-slate-200 bg-slate-50/70 p-4 sm:p-5"><div className="flex flex-col gap-4 sm:flex-row sm:items-start"><div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-violet-500/10 text-violet-700"><Bot className="h-5 w-5" /></div><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><h3 className="font-semibold text-slate-900">{task.task_type === "deep_link" ? "Deep Link handler 探索" : "导出组件探索"}</h3><Badge tone={statusTone(task.status)}>{statusLabel(task.status)}</Badge><Badge>priority {task.priority}</Badge>{Boolean(auditCounts.get(task.id)) && <Badge tone="info">AI 调用 {auditCounts.get(task.id)}</Badge>}</div><p className="mt-2 truncate font-mono text-xs text-slate-500">{task.target_entry_ids.map((id) => names.get(id) ?? id).join(" · ")}</p><ul className="mt-3 space-y-1 text-xs leading-relaxed text-slate-500">{task.hypotheses.slice(0, 3).map((item) => <li key={item} className="flex gap-2"><span className="text-slate-700">—</span><span>{item}</span></li>)}</ul>{task.error && <p className="mt-3 text-xs text-amber-700">{task.error}</p>}</div><div className="flex shrink-0 items-center gap-3 text-xs text-slate-600"><span>attempt {task.attempts}/2</span>{["failed", "inconclusive", "blocked_device"].includes(task.status) && task.attempts < 2 && <Button variant="secondary" size="sm" onClick={() => retry(task.id)} disabled={retrying === task.id}>{retrying === task.id ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}重试</Button>}</div></div></article>)}{!tasks.length && <EmptyRow text="静态规划完成后将生成入口探索任务" />}</div>
}

function AgentAudits({ audits, tasks, entries }: { audits: AgentAudit[]; tasks: InvestigationTask[]; entries: EntryPoint[] }) {
  const tasksById = new Map(tasks.map((task) => [task.id, task]))
  const names = new Map(entries.map((entry) => [entry.id, entry.name]))
  if (!audits.length) return <EmptyRow text="本次扫描没有调用 AI，因此没有 AI 审计记录" />
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-cyan-200 bg-cyan-50 p-4 text-sm leading-6 text-cyan-950">
        每次模型调用的精确输入、结构化原始输出、测试裁决和证据校验均保存为不可变 Evidence。下方 SHA-256 用于核对审计内容完整性。
      </div>
      {audits.map((audit) => {
        const task = audit.task_id ? tasksById.get(audit.task_id) : undefined
        const target = task?.target_entry_ids.map((id) => names.get(id) ?? id).join(" · ")
        return (
          <article key={audit.id} className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
            <div className="flex flex-col gap-4 border-b border-slate-200 p-4 sm:flex-row sm:items-start sm:justify-between">
              <div className="flex min-w-0 gap-3">
                <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-violet-50 text-violet-700"><ScrollText className="h-5 w-5" /></div>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="font-semibold text-slate-950">{auditPhaseLabel(audit.phase)}</h3>
                    <Badge tone={statusTone(audit.status)}>{statusLabel(audit.status)}</Badge>
                    <Badge tone={audit.integrity === "verified" ? "good" : "danger"}>{audit.integrity === "verified" ? "SHA-256 已验证" : "完整性异常"}</Badge>
                  </div>
                  <p className="mt-1 truncate text-sm text-slate-600">{target ?? audit.task_id ?? "未知任务"}</p>
                  <p className="mt-2 font-mono text-xs text-slate-500">{audit.backend} · {audit.provider}/{audit.model} · {audit.isolation} · attempt {audit.attempt}</p>
                </div>
              </div>
              <div className="shrink-0 text-right text-xs text-slate-500">
                <p>{formatDate(audit.started_at)}</p>
                <p className="mt-1 font-mono">audit {shortHash(audit.id)}</p>
              </div>
            </div>
            <div className="grid gap-3 p-4 md:grid-cols-2">
              <AuditValue label="Thread ID" value={audit.thread_id ?? "—"} />
              <AuditValue label="Turn ID" value={audit.turn_id ?? "—"} />
            </div>
            {audit.integrity_errors.length > 0 && <div role="alert" className="mx-4 mb-4 rounded-lg border border-rose-200 bg-rose-50 p-3 text-xs text-rose-700">{audit.integrity_errors.join("；")}</div>}
            <div className="space-y-3 px-4 pb-4">
              <AuditArtifact title="模型精确输入" artifact={audit.artifacts.request} />
              <AuditArtifact title="模型结构化原始输出" artifact={audit.artifacts.response} />
              <AuditArtifact title="AI 申请测试的白名单裁决" artifact={audit.artifacts.test_validation} />
              <AuditArtifact title="平台证据校验与最终结论" artifact={audit.artifacts.validation} />
              <AuditArtifact title="调用错误" artifact={audit.artifacts.error} />
            </div>
          </article>
        )
      })}
    </div>
  )
}

function AuditArtifact({ title, artifact }: { title: string; artifact?: AgentAudit["artifacts"][string] }) {
  if (!artifact) return null
  return (
    <details className="group rounded-lg border border-slate-200 bg-slate-50">
      <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-3 px-3 py-2 text-sm font-semibold text-slate-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-700">
        <span>{title}</span>
        <span className="font-mono text-[11px] font-normal text-slate-500">SHA256 {shortHash(artifact.sha256)}</span>
      </summary>
      <div className="border-t border-slate-200 p-3">
        <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-white p-4 font-mono text-xs leading-6 text-slate-800 ring-1 ring-inset ring-slate-200">{formatAuditContent(artifact.content)}</pre>
        <a className="mt-3 inline-flex text-xs font-semibold text-cyan-800 underline-offset-4 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-700" href={`/api/v1/evidence/${artifact.evidence_id}/download`}>下载不可变 Evidence</a>
      </div>
    </details>
  )
}

function AuditValue({ label, value }: { label: string; value: string }) {
  return <div className="rounded-lg bg-slate-50 px-3 py-2"><p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</p><p className="mt-1 break-all font-mono text-xs text-slate-700">{value}</p></div>
}

function auditPhaseLabel(phase: string) {
  return {
    static_only: "静态证据判断",
    test_planning: "补充测试规划",
    final_evaluation: "最终证据判断",
    recovery_evaluation: "异常恢复判断",
  }[phase] ?? phase
}

function formatAuditContent(value: unknown) {
  if (value === null || value === undefined) return "内容不可用"
  if (typeof value === "string") return value
  return JSON.stringify(value, null, 2)
}

function DeleteScanDialog({ scan, onOpenChange, onDeleted }: { scan: Scan | null; onOpenChange: (open: boolean) => void; onDeleted: (scanId: string, warnings: string[]) => Promise<void> }) {
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => setError(null), [scan?.id])
  async function remove() {
    if (!scan) return
    setDeleting(true)
    setError(null)
    try {
      const result = await api.deleteScan(scan.id)
      await onDeleted(scan.id, result.cleanup_warnings)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "删除失败")
    } finally {
      setDeleting(false)
    }
  }
  return (
    <Dialog open={Boolean(scan)} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogTitle className="text-xl font-bold text-slate-950">永久删除扫描？</DialogTitle>
        <DialogDescription className="mt-2 text-sm leading-6 text-slate-600">这会删除扫描记录、任务、Finding、AI 审计 Evidence 和独占工作文件。被其他扫描复用的内容寻址文件会保留。此操作不可撤销。</DialogDescription>
        {scan && <div className="mt-5 rounded-xl border border-rose-200 bg-rose-50 p-4"><p className="font-semibold text-rose-900">{scan.package_name ?? scan.filename}</p><p className="mt-1 font-mono text-xs text-rose-700">SHA256 {shortHash(scan.artifact_sha256)}</p></div>}
        {error && <p role="alert" className="mt-4 text-sm text-rose-700">{error}</p>}
        <div className="mt-6 flex justify-end gap-2"><Button variant="ghost" onClick={() => onOpenChange(false)} disabled={deleting}>取消</Button><Button variant="danger" onClick={remove} disabled={deleting}>{deleting ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}{deleting ? "正在删除" : "确认永久删除"}</Button></div>
      </DialogContent>
    </Dialog>
  )
}

function UploadDialog({ open, onOpenChange, onUploaded, health }: { open: boolean; onOpenChange: (open: boolean) => void; onUploaded: (scan: Scan) => Promise<void>; health: Health | null }) {
  const [file, setFile] = useState<File | null>(null)
  const [investigator, setInvestigator] = useState<InvestigatorChoice>("configured")
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  async function submit(event: FormEvent) { event.preventDefault(); if (!file) return; setUploading(true); setError(null); try { const scan = await api.upload(file, investigator); setFile(null); setInvestigator("configured"); await onUploaded(scan) } catch (reason) { setError(reason instanceof Error ? reason.message : "上传失败") } finally { setUploading(false) } }
  function choose(candidate?: File) { if (!candidate) return; if (!candidate.name.toLowerCase().endsWith(".apk")) { setError("首期仅支持单个可安装 .apk 文件"); return } setError(null); setFile(candidate) }
  const defaultLabel = health?.default_investigator === "opencode" ? "OpenCode + DeepSeek" : health?.default_investigator === "codex" ? "Codex" : "仅静态与确定性动态"
  const codexReady = Boolean(health?.enabled_investigators.includes("codex") && health.capabilities.find((item) => item.name === "codex")?.available)
  const opencodeReady = Boolean(health?.enabled_investigators.includes("opencode") && health.capabilities.find((item) => item.name === "opencode_deepseek")?.available)
  return <Dialog open={open} onOpenChange={onOpenChange}><DialogContent><DialogTitle className="text-xl font-bold text-slate-950">新建 APK 安全扫描</DialogTitle><DialogDescription className="mt-2 text-sm leading-relaxed text-slate-600">APK 将保存在本机内容寻址存储中。AI 受单次任务范围约束，所有进入报告的结论仍须通过平台证据校验。</DialogDescription><form className="mt-6" onSubmit={submit}><button type="button" className={cn("grid min-h-52 w-full place-items-center rounded-2xl border border-dashed p-6 text-center transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-700", dragging ? "border-cyan-300 bg-cyan-400/10" : "border-slate-300 bg-slate-50 hover:border-slate-500")} onClick={() => inputRef.current?.click()} onDragOver={(event) => { event.preventDefault(); setDragging(true) }} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); choose(event.dataTransfer.files[0]) }}><input ref={inputRef} type="file" accept=".apk,application/vnd.android.package-archive" className="sr-only" onChange={(event) => choose(event.target.files?.[0])} /><div>{file ? <><FileArchive className="mx-auto h-10 w-10 text-cyan-700" /><p className="mt-4 break-all font-semibold text-slate-900">{file.name}</p><p className="mt-2 text-xs text-slate-500">{(file.size / 1024 / 1024).toFixed(2)} MB · 点击更换</p></> : <><UploadCloud className="mx-auto h-10 w-10 text-slate-500" /><p className="mt-4 font-semibold text-slate-800">拖入 APK 或点击选择</p><p className="mt-2 text-xs text-slate-600">最大 512 MB · 不支持 AAB/XAPK/split APK</p></>}</div></button><label className="mt-5 block"><span className="mb-2 block text-sm font-semibold text-slate-800">语义探索后端</span><select className="field w-full" value={investigator} onChange={(event) => setInvestigator(event.target.value as InvestigatorChoice)}><option value="configured">服务默认 · {defaultLabel}</option><option value="codex" disabled={!codexReady}>Codex · {codexReady ? "已就绪" : "未启用或依赖未就绪"}</option><option value="opencode" disabled={!opencodeReady}>OpenCode + DeepSeek · {opencodeReady ? "已就绪" : "未启用或依赖未就绪"}</option><option value="none">关闭 AI · 仅规则和确定性动态测试</option></select><span className="mt-2 block text-xs leading-relaxed text-slate-600">选择会固化到本次扫描；切换服务默认不会影响已经排队的任务。</span></label>{error && <p role="alert" className="mt-3 text-sm text-rose-700">{error}</p>}<div className="mt-6 flex justify-end gap-2"><Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>取消</Button><Button type="submit" disabled={!file || uploading}>{uploading ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <ScanSearch className="h-4 w-4" />}{uploading ? "正在接收" : "开始扫描"}</Button></div></form></DialogContent></Dialog>
}

function Metric({ label, value, icon: Icon, tone }: { label: string; value: number | string; icon: typeof AlertTriangle; tone: "rose" | "cyan" | "violet" | "emerald" }) {
  const colors = { rose: "bg-rose-500/10 text-rose-700", cyan: "bg-cyan-500/10 text-cyan-700", violet: "bg-violet-500/10 text-violet-700", emerald: "bg-emerald-500/10 text-emerald-700" }
  return <Card className="p-4"><div className={cn("mb-4 grid h-9 w-9 place-items-center rounded-lg", colors[tone])}><Icon className="h-4 w-4" /></div><p className="font-display text-2xl font-bold text-slate-950">{value}</p><p className="mt-1 text-xs text-slate-500">{label}</p></Card>
}

function SectionTitle({ icon: Icon, title, description }: { icon: typeof Activity; title: string; description: string }) { return <div className="flex items-center gap-3"><div className="grid h-9 w-9 place-items-center rounded-lg bg-slate-100 text-cyan-700"><Icon className="h-4 w-4" /></div><div><h3 className="text-sm font-semibold text-slate-900">{title}</h3><p className="text-xs text-slate-600">{description}</p></div></div> }
function ReportLink({ scanId, format, label }: { scanId: string; format: string; label: string }) { return <a href={`/api/v1/scans/${scanId}/report/${format}`} target="_blank" rel="noreferrer" className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-slate-300 px-3 text-xs font-semibold text-slate-700 hover:border-slate-500 hover:text-slate-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-700"><ArrowDownToLine className="h-3.5 w-3.5" />{label}</a> }
function EntryIcon({ kind }: { kind: string }) { const icons: Record<string, typeof Box> = { activity: Smartphone, activity_alias: Smartphone, service: ServerCog, receiver: Network, provider: Box, deep_link: Link2 }; const Icon = icons[kind] ?? Code2; return <span className="inline-flex items-center gap-2 text-xs text-slate-600"><Icon className="h-3.5 w-3.5 text-cyan-600" />{kind}</span> }
function StageState({ value }: { value: string }) { if (["completed", "covered", "attempted"].includes(value)) return <Check className="mx-auto h-4 w-4 text-emerald-600" aria-label={value} />; if (["blocked", "failed", "not_tested"].includes(value)) return <X className="mx-auto h-4 w-4 text-rose-600" aria-label={value} />; return <Clock3 className="mx-auto h-4 w-4 text-slate-600" aria-label={value} /> }
function EmptyRow({ text }: { text: string }) { return <div className="grid min-h-32 place-items-center p-6 text-sm text-slate-600">{text}</div> }
function LoadingState() { return <div className="grid min-h-[60vh] place-items-center"><div className="text-center"><LoaderCircle className="mx-auto h-7 w-7 animate-spin text-cyan-700 motion-reduce:animate-none" /><p className="mt-3 text-sm text-slate-500">正在加载审计数据</p></div></div> }
function EmptyState({ onUpload }: { onUpload: () => void }) { return <div className="grid min-h-[70vh] place-items-center"><div className="max-w-md text-center"><div className="mx-auto grid h-16 w-16 place-items-center rounded-2xl border border-cyan-400/20 bg-cyan-400/5 text-cyan-700"><Smartphone className="h-8 w-8" /></div><h2 className="font-display mt-6 text-2xl font-bold text-slate-950">从一个上线 APK 开始</h2><p className="mt-3 text-sm leading-7 text-slate-500">先建立确定性攻击面，再由选定的 AI 后端对导出组件和 Deep Link 逐项探索。每个结论都保留覆盖状态与证据链。</p><Button className="mt-6" onClick={onUpload}><UploadCloud className="h-4 w-4" />选择 APK</Button></div></div> }

export default App
