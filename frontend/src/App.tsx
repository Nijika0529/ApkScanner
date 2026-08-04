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
  Power,
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
import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState, type FormEvent } from "react"
import { api } from "./api"
import { MarkdownContent } from "./components/MarkdownContent"
import { Badge, Button, Card, Dialog, DialogContent, DialogDescription, DialogTitle, Progress, Tabs, TabsContent, TabsList, TabsTrigger } from "./components/ui"
import { cn, formatDate, shortHash, statusLabel } from "./lib"
import { markdownToPlainText } from "./markdown"
import type { AdbDevice, AgentAudit, BenchmarkEvaluation, CoverageItem, EntryPoint, Finding, Health, InvestigationTask, InvestigatorChoice, PatternMatch, Scan, ScanEvent, SecurityHypothesis, SecuritySnapshot, VersionDiff } from "./types"

const severityTone = {
  critical: "danger",
  high: "danger",
  medium: "warning",
  low: "info",
  info: "neutral",
} as const

const DETAIL_REFRESH_EVENTS = [
  "static.started",
  "static.completed",
  "scan.preliminary_ready",
  "scan.preliminary_sla_missed",
  "scan.deadline_exhausted",
  "scan.final",
  "scan.failed",
  "investigation.pool.started",
  "task.worker_requeued",
  "task.device_requeued",
  "task.device_interrupted",
  "task.failed",
  "task.awaiting_device",
  "task.device_acquired",
  "task.device_released",
  "task.started",
  "task.completed",
  "task.cancel_requested",
  "task.cancelled",
  "task.cancelled_after_deletion",
  "task.deleted",
  "exploration.update",
  "device.pool.connected",
  "device.pool.draining",
  "device.pool.removed",
] as const

const MUTABLE_EXPLORATION_EVENTS = new Set([
  "exploration.action.completed",
  "exploration.cancelled",
  "exploration.completed",
  "exploration.conclusion.recorded",
  "exploration.control.updated",
  "exploration.debate.completed",
  "exploration.failed",
  "exploration.hypothesis.recorded",
  "exploration.model.cancelled",
  "exploration.model.completed",
  "exploration.model.failed",
  "exploration.poc.build.completed",
  "exploration.poc.build.failed",
  "exploration.proof_replay.completed",
  "exploration.proof_terminal",
  "exploration.started",
])

function statusTone(status: string): "neutral" | "good" | "warning" | "danger" | "info" {
  if (["final", "completed", "covered", "accepted", "reproduced_blackbox", "proven"].includes(status)) return "good"
  if (["failed", "critical", "high", "tool_failed"].includes(status)) return "danger"
  if (["inconclusive", "timed_out", "blocked_device", "partial", "degraded", "preliminary_ready", "cancel_requested", "challenged"].includes(status)) return "warning"
  if (["investigating", "static_running", "running", "queued", "accepted_for_proof", "proof_planned", "executing"].includes(status)) return "info"
  return "neutral"
}

function scanProgress(status: string) {
  return { queued: 5, intake: 12, static_running: 35, static_complete: 55, preliminary_ready: 68, investigating: 82, final: 100, failed: 100 }[status] ?? 0
}

function isAbortError(reason: unknown) {
  return reason instanceof DOMException && reason.name === "AbortError"
}

function sameJsonValue(left: unknown, right: unknown) {
  return left === right || JSON.stringify(left) === JSON.stringify(right)
}

function replaceScanIfChanged(items: Scan[], scan: Scan) {
  const current = items.find((item) => item.id === scan.id)
  if (current && sameJsonValue(current, scan)) return items
  return items.map((item) => item.id === scan.id ? scan : item)
}

interface DetailData {
  scan: Scan
  entries: EntryPoint[]
  findings: Finding[]
  signals: Finding[]
  coverage: CoverageItem[]
  tasks: InvestigationTask[]
  audits: AgentAudit[]
  hypotheses: SecurityHypothesis[]
  evaluations: BenchmarkEvaluation[]
}

type ScanEventSubscriber = (event: ScanEvent) => void

function App() {
  const [scans, setScans] = useState<Scan[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [detail, setDetail] = useState<DetailData | null>(null)
  const [health, setHealth] = useState<Health | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [uploadOpen, setUploadOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<Scan | null>(null)
  const [freshRunTarget, setFreshRunTarget] = useState<Scan | null>(null)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const detailRequestRef = useRef(0)
  const liveRequestRef = useRef(0)
  const latestEventIdRef = useRef(0)
  const eventSubscribersRef = useRef(new Set<ScanEventSubscriber>())
  const selectedIdRef = useRef<string | null>(selectedId)

  const subscribeEvents = useCallback((subscriber: ScanEventSubscriber) => {
    eventSubscribersRef.current.add(subscriber)
    return () => eventSubscribersRef.current.delete(subscriber)
  }, [])

  const updateHealth = useCallback((next: Health) => {
    setHealth((current) => current && sameJsonValue(current, next) ? current : next)
  }, [])

  const loadScans = useCallback(async () => {
    const data = await api.scans()
    setScans((current) => {
      const returnedIds = new Set(data.map((scan) => scan.id))
      const optimistic = current.filter((scan) => !returnedIds.has(scan.id))
      return [...optimistic, ...data]
    })
    const next = selectedIdRef.current ?? data[0]?.id ?? null
    selectedIdRef.current = next
    setSelectedId(next)
    return data
  }, [])

  const loadDetail = useCallback(async (id: string, signal?: AbortSignal) => {
    const requestId = ++detailRequestRef.current
    try {
      const [scan, entries, findings, signals, coverage, tasks, audits, hypotheses, evaluations, eventCursor] = await Promise.all([
        api.scan(id, signal),
        api.entries(id, signal),
        api.findings(id, signal),
        api.signals(id, signal),
        api.coverage(id, signal),
        api.tasks(id, signal),
        api.agentAudits(id, signal),
        api.hypotheses(id, signal),
        api.evaluations(id, signal),
        api.events(id, signal, 0, 1),
      ])
      if (signal?.aborted || requestId !== detailRequestRef.current) return false
      const data = { scan, entries, findings, signals, coverage, tasks, audits, hypotheses, evaluations }
      latestEventIdRef.current = eventCursor.at(-1)?.id ?? 0
      setDetail(data)
      setScans((items) => replaceScanIfChanged(items, scan))
      return true
    } catch (reason) {
      if (signal?.aborted || requestId !== detailRequestRef.current || isAbortError(reason)) {
        return false
      }
      throw reason
    } finally {
      if (!signal?.aborted && requestId === detailRequestRef.current) setLoading(false)
    }
  }, [])

  const refreshMutableDetail = useCallback(async (id: string, signal?: AbortSignal) => {
    const requestId = ++liveRequestRef.current
    try {
      const [scan, findings, signals, coverage, tasks, audits, hypotheses] = await Promise.all([
        api.scan(id, signal),
        api.findings(id, signal),
        api.signals(id, signal),
        api.coverage(id, signal),
        api.tasks(id, signal),
        api.agentAudits(id, signal),
        api.hypotheses(id, signal),
      ])
      if (signal?.aborted || requestId !== liveRequestRef.current) return
      setDetail((current) => {
        if (current?.scan.id !== id) return current
        if (
          sameJsonValue(current.scan, scan)
          && sameJsonValue(current.findings, findings)
          && sameJsonValue(current.signals, signals)
          && sameJsonValue(current.coverage, coverage)
          && sameJsonValue(current.tasks, tasks)
          && sameJsonValue(current.audits, audits)
          && sameJsonValue(current.hypotheses, hypotheses)
        ) return current
        return {
          ...current,
          scan,
          findings,
          signals,
          coverage,
          tasks,
          audits,
          hypotheses,
        }
      })
      setScans((items) => replaceScanIfChanged(items, scan))
    } catch (reason) {
      if (!signal?.aborted && requestId === liveRequestRef.current && !isAbortError(reason)) {
        throw reason
      }
    }
  }, [])

  const refreshDetail = useCallback(async (
    id: string,
    { signal, reportError = true }: { signal?: AbortSignal; reportError?: boolean } = {},
  ) => {
    if (selectedIdRef.current !== id) return
    try {
      await loadDetail(id, signal)
    } catch (reason) {
      if (reportError && !signal?.aborted) {
        setError(reason instanceof Error ? reason.message : "刷新扫描详情失败")
      }
    }
  }, [loadDetail])

  useEffect(() => {
    void loadScans()
      .then((items) => {
        if (!items.length) setLoading(false)
      })
      .catch((reason: Error) => {
        setError(reason.message)
        setLoading(false)
      })
    void api.health()
      .then(updateHealth)
      .catch((reason: Error) => setError(reason.message))
    const healthTimer = window.setInterval(
      () => void api.health().then(updateHealth).catch(() => undefined),
      15_000,
    )
    return () => window.clearInterval(healthTimer)
  }, [loadScans, updateHealth])

  useEffect(() => {
    if (!selectedId) {
      detailRequestRef.current += 1
      setDetail(null)
      setLoading(false)
      return
    }
    const controller = new AbortController()
    setDetail(null)
    setLoading(true)
    let source: EventSource | null = null
    let refreshTimer: ReturnType<typeof setTimeout> | undefined
    let pendingFullRefresh = false
    const refresh = (full = false) => {
      pendingFullRefresh = pendingFullRefresh || full
      if (refreshTimer) clearTimeout(refreshTimer)
      refreshTimer = setTimeout(
        () => {
          const runFullRefresh = pendingFullRefresh
          pendingFullRefresh = false
          if (runFullRefresh) api.invalidateScanCache(selectedId)
          void (runFullRefresh
            ? refreshDetail(selectedId, { signal: controller.signal, reportError: false })
            : refreshMutableDetail(selectedId, controller.signal).catch(() => undefined))
        },
        650,
      )
    }
    const receive = (raw: Event) => {
      if (!(raw instanceof MessageEvent) || typeof raw.data !== "string") return
      let event: ScanEvent
      try {
        event = JSON.parse(raw.data) as ScanEvent
      } catch {
        return
      }
      latestEventIdRef.current = Math.max(latestEventIdRef.current, event.id)
      eventSubscribersRef.current.forEach((subscriber) => subscriber(event))
      const full = ["static.completed", "scan.final", "scan.failed"].includes(event.event_type)
      const mutable = !event.event_type.startsWith("exploration.")
        || MUTABLE_EXPLORATION_EVENTS.has(event.event_type)
      if (full || mutable) refresh(full)
    }
    void refreshDetail(selectedId, { signal: controller.signal }).finally(() => {
      if (controller.signal.aborted) return
      source = new EventSource(
        `/api/v1/scans/${selectedId}/events/stream?detail=summary&after=${latestEventIdRef.current}`,
      )
      DETAIL_REFRESH_EVENTS.forEach((eventType) => source?.addEventListener(eventType, receive))
      source.addEventListener("end", () => source?.close())
    })
    return () => {
      if (refreshTimer) clearTimeout(refreshTimer)
      controller.abort()
      source?.close()
    }
  }, [selectedId, refreshDetail, refreshMutableDetail])

  async function onUploaded(scan: Scan) {
    setUploadOpen(false)
    setScans((items) => [scan, ...items])
    detailRequestRef.current += 1
    setDetail(null)
    setLoading(true)
    selectedIdRef.current = scan.id
    setSelectedId(scan.id)
  }

  async function onDeleted(scanId: string, warnings: string[]) {
    const remaining = scans.filter((scan) => scan.id !== scanId)
    detailRequestRef.current += 1
    setDeleteTarget(null)
    setScans(remaining)
    setDetail(null)
    setLoading(Boolean(remaining[0]))
    selectedIdRef.current = remaining[0]?.id ?? null
    setSelectedId(selectedIdRef.current)
    if (warnings.length) setError(`扫描已删除，但有文件未能清理：${warnings.join("；")}`)
  }

  const sidebar = (
    <Sidebar
      scans={scans}
      selectedId={selectedId}
      health={health}
      onSelect={(id) => {
        if (id !== selectedId) {
          detailRequestRef.current += 1
          setDetail(null)
          setLoading(true)
          selectedIdRef.current = id
          setSelectedId(id)
        }
        setMobileNavOpen(false)
      }}
      onUpload={() => { setUploadOpen(true); setMobileNavOpen(false) }}
    />
  )

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <a href="#main-content" className="sr-only fixed left-4 top-4 z-[100] rounded-lg bg-cyan-700 px-4 py-2 font-semibold text-white focus:not-sr-only">跳到主要内容</a>
      <div className="app-grid" aria-hidden="true" />
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-80 border-r border-slate-200 bg-white lg:block">{sidebar}</aside>
      {mobileNavOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <button className="absolute inset-0 bg-slate-900/35" aria-label="关闭导航" onClick={() => setMobileNavOpen(false)} />
          <aside className="relative h-full w-[min(88vw,22rem)] border-r border-slate-200 bg-white shadow-2xl">{sidebar}</aside>
        </div>
      )}
      <main id="main-content" className="relative min-h-screen lg:pl-80">
        <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-slate-200 bg-white px-4 sm:px-6 lg:px-8">
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="icon" className="lg:hidden" onClick={() => setMobileNavOpen(true)} aria-label="打开扫描列表"><Menu className="h-5 w-5" /></Button>
            <div>
              <p className="text-sm font-semibold text-slate-900">{detail?.scan.package_name ?? detail?.scan.filename ?? "安全审计工作台"}</p>
              <p className="hidden text-xs text-slate-500 sm:block">APK-only · Android 16 · evidence-first</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {detail && <Badge tone={statusTone(detail.scan.status)}><span className={cn("mr-1.5 h-1.5 w-1.5 rounded-full", detail.scan.status === "final" ? "bg-emerald-400" : "animate-pulse bg-current motion-reduce:animate-none")} />{statusLabel(detail.scan.status)}</Badge>}
            <Button variant="secondary" size="sm" onClick={() => selectedId && void refreshDetail(selectedId)} disabled={!selectedId} aria-label="刷新数据"><RefreshCw className="h-3.5 w-3.5" /><span className="hidden sm:inline">刷新</span></Button>
          </div>
        </header>
        <div className="mx-auto max-w-[1500px] p-4 sm:p-6 lg:p-8">
          {error && <div role="alert" className="mb-6 flex items-start gap-3 rounded-xl border border-rose-500/35 bg-rose-500/10 p-4 text-sm text-rose-800"><AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" /><span>{error}</span><button className="ml-auto" onClick={() => setError(null)} aria-label="关闭错误"><X className="h-4 w-4" /></button></div>}
          {loading && !detail ? <LoadingState /> : detail ? <ScanDetailView data={detail} health={health} subscribeEvents={subscribeEvents} onRefresh={() => refreshDetail(detail.scan.id)} onDelete={() => setDeleteTarget(detail.scan)} onFreshRun={() => setFreshRunTarget(detail.scan)} onVersionCreated={onUploaded} /> : <EmptyState onUpload={() => setUploadOpen(true)} />}
        </div>
      </main>
      <UploadDialog open={uploadOpen} onOpenChange={setUploadOpen} onUploaded={onUploaded} health={health} />
      <DeleteScanDialog scan={deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)} onDeleted={onDeleted} />
      <FreshRunDialog scan={freshRunTarget} onOpenChange={(open) => !open && setFreshRunTarget(null)} onCreated={async (scan) => { setFreshRunTarget(null); await onUploaded(scan) }} />
    </div>
  )
}

function Sidebar({ scans, selectedId, health, onSelect, onUpload }: { scans: Scan[]; selectedId: string | null; health: Health | null; onSelect: (id: string) => void; onUpload: () => void }) {
  const [visibleCount, setVisibleCount] = useState(100)
  const ready = health?.capabilities.filter((item) => item.available || item.busy).length ?? 0
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
          {scans.slice(0, visibleCount).map((scan) => (
            <button key={scan.id} onClick={() => onSelect(scan.id)} className={cn("group w-full rounded-xl border px-3 py-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-700", selectedId === scan.id ? "border-cyan-500/30 bg-cyan-500/10" : "border-transparent hover:border-slate-200 hover:bg-slate-100")}>
              <div className="mb-1.5 flex items-center justify-between gap-2"><span className="truncate text-sm font-medium text-slate-800">{scan.package_name ?? scan.filename}</span><ChevronRight className={cn("h-4 w-4 shrink-0 text-slate-700", selectedId === scan.id && "text-cyan-600")} /></div>
              <div className="flex items-center justify-between gap-2 text-[11px] text-slate-500"><span>{formatDate(scan.created_at)}</span><span>{statusLabel(scan.status)}</span></div>
            </button>
          ))}
          {visibleCount < scans.length && <Button className="mt-2 w-full" variant="ghost" size="sm" onClick={() => setVisibleCount((count) => count + 100)}>加载更多扫描 · {scans.length - visibleCount}</Button>}
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

function ScanDetailView({ data, health, subscribeEvents, onRefresh, onDelete, onFreshRun, onVersionCreated }: { data: DetailData; health: Health | null; subscribeEvents: (subscriber: ScanEventSubscriber) => () => void; onRefresh: () => Promise<void>; onDelete: () => void; onFreshRun: () => void; onVersionCreated: (scan: Scan) => Promise<void> }) {
  const { scan, entries, findings, signals, coverage, tasks, audits, hypotheses, evaluations } = data
  const [versionData, setVersionData] = useState<{ snapshot: SecuritySnapshot | null; diff: VersionDiff | null; matches: PatternMatch[] } | null>(null)
  const [versionLoading, setVersionLoading] = useState(false)
  const [versionLoadError, setVersionLoadError] = useState<string | null>(null)
  const loadVersionData = useCallback(async () => {
    if (versionData || versionLoading) return
    setVersionLoading(true)
    setVersionLoadError(null)
    try {
      const [snapshot, diff, matches] = await Promise.all([
        api.securitySnapshot(scan.id),
        api.versionDiff(scan.id),
        api.patternMatches(scan.id),
      ])
      setVersionData({ snapshot, diff, matches })
    } catch (reason) {
      setVersionLoadError(reason instanceof Error ? reason.message : "版本演进数据加载失败")
    } finally {
      setVersionLoading(false)
    }
  }, [scan.id, versionData, versionLoading])
  const verificationCandidates = signals.filter(isVerificationCandidate)
  const staticSignals = signals.filter((signal) => !isVerificationCandidate(signal))
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
          <div className="w-full max-w-lg space-y-3"><Progress value={scanProgress(scan.status)} label="扫描进度" /><div className="flex flex-wrap gap-2"><ReportLink scanId={scan.id} format="html" label="HTML" /><ReportLink scanId={scan.id} format="json" label="JSON" /><ReportLink scanId={scan.id} format="sarif" label="SARIF" /><Button variant="secondary" size="sm" onClick={onFreshRun} disabled={!["final", "failed"].includes(scan.status)} title={["final", "failed"].includes(scan.status) ? "只复用原始 APK，创建不继承历史结果的独立扫描" : "当前扫描结束后才能全新重扫"}><ScanSearch className="h-3.5 w-3.5" />全新重扫</Button><Button variant="danger" size="sm" onClick={onDelete} disabled={!["final", "failed"].includes(scan.status)} title={["final", "failed"].includes(scan.status) ? "永久删除扫描及其独占文件" : "运行中的扫描不能删除"}><Trash2 className="h-3.5 w-3.5" />删除扫描</Button></div></div>
        </div>
      </section>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Metric label="已证实高危" value={high} icon={AlertTriangle} tone="rose" />
        <Metric label="黑盒复现" value={reproduced} icon={ShieldX} tone="rose" />
        <Metric label="导出组件" value={exported} icon={Box} tone="cyan" />
        <Metric label="Deep Link" value={links} icon={Link2} tone="cyan" />
        <Metric label="待验证风险" value={verificationCandidates.length} icon={Bot} tone="violet" />
        <Metric label="覆盖项目" value={`${Math.round(coveragePercent)}%`} icon={Gauge} tone="emerald" />
      </div>
      <Card className="p-4 sm:p-6">
        <Tabs defaultValue="overview" onValueChange={(value) => {
          if (value === "versions") void loadVersionData()
        }}>
          <TabsList aria-label="扫描详情">
            <TabsTrigger value="overview">总览</TabsTrigger><TabsTrigger value="entries">攻击面 <span className="ml-1 text-xs text-slate-500">{entries.length}</span></TabsTrigger><TabsTrigger value="findings">已证实 Finding <span className="ml-1 text-xs text-slate-500">{findings.length}</span></TabsTrigger><TabsTrigger value="proof-backlog">待验证风险 <span className="ml-1 text-xs text-slate-500">{verificationCandidates.length}</span></TabsTrigger><TabsTrigger value="signals">静态线索 <span className="ml-1 text-xs text-slate-500">{staticSignals.length}</span></TabsTrigger><TabsTrigger value="versions">版本演进{versionData && <span className="ml-1 text-xs text-slate-500">{versionData.matches.length}</span>}</TabsTrigger><TabsTrigger value="coverage">覆盖矩阵</TabsTrigger><TabsTrigger value="tasks">探索任务</TabsTrigger><TabsTrigger value="proofs">验证链 <span className="ml-1 text-xs text-slate-500">{hypotheses.length}</span></TabsTrigger><TabsTrigger value="audits">AI 审计 <span className="ml-1 text-xs text-slate-500">{audits.length}</span></TabsTrigger>
          </TabsList>
          <TabsContent value="overview"><Overview scan={scan} health={health} coverage={coverage} /></TabsContent>
          <TabsContent value="entries"><EntryPoints entries={entries} /></TabsContent>
          <TabsContent value="findings"><Findings findings={findings} verificationCandidates={verificationCandidates} scanStatus={scan.status} onRefresh={onRefresh} /></TabsContent>
          <TabsContent value="proof-backlog"><ProofBacklog signals={verificationCandidates} tasks={tasks} onRefresh={onRefresh} /></TabsContent>
          <TabsContent value="signals"><Signals signals={staticSignals} onRefresh={onRefresh} /></TabsContent>
          <TabsContent value="versions">{versionLoading ? <LoadingState /> : versionLoadError ? <div role="alert" className="rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-700">{versionLoadError}<Button className="ml-3" variant="secondary" size="sm" onClick={() => void loadVersionData()}>重试</Button></div> : versionData ? <VersionEvolution scan={scan} snapshot={versionData.snapshot} diff={versionData.diff} matches={versionData.matches} entries={entries} onCreated={onVersionCreated} /> : <EmptyRow text="正在准备版本演进数据" />}</TabsContent>
          <TabsContent value="coverage"><CoverageMatrix coverage={coverage} /></TabsContent>
          <TabsContent value="tasks"><Tasks scan={scan} tasks={tasks} entries={entries} audits={audits} subscribeEvents={subscribeEvents} health={health} onRefresh={onRefresh} /></TabsContent>
          <TabsContent value="proofs"><HypothesisPipeline scanId={scan.id} scanStatus={scan.status} hypotheses={hypotheses} evaluations={evaluations} entries={entries} onRefresh={onRefresh} /></TabsContent>
          <TabsContent value="audits"><AgentAudits audits={audits} tasks={tasks} entries={entries} /></TabsContent>
        </Tabs>
      </Card>
    </div>
  )
}

function Overview({ scan, health, coverage }: { scan: Scan; health: Health | null; coverage: CoverageItem[] }) {
  const baselines = coverage.filter((item) => item.control_id.endsWith("-BASELINE"))
  return <div className="grid gap-6 xl:grid-cols-2">
    <DevicePoolPanel />
    <div className="space-y-6"><div><SectionTitle icon={ListChecks} title="MASVS 基线" description="APK-only 初始覆盖" /><div className="mt-4 space-y-3">{baselines.map((item) => <div key={item.id} className="rounded-xl border border-slate-200 bg-slate-50 p-3"><div className="mb-2 flex items-center justify-between gap-3"><span className="text-xs font-semibold text-slate-700">{item.domain.replace("MASVS-", "")}</span><Badge tone={statusTone(item.status)}>{statusLabel(item.status)}</Badge></div><p className="text-xs leading-relaxed text-slate-500">{item.gap_reason ?? item.title}</p></div>)}</div></div><div><SectionTitle icon={ServerCog} title="运行能力" description="缺失能力会形成覆盖缺口" /><div className="mt-4 grid grid-cols-2 gap-2">{health?.capabilities.map((item) => <div key={item.name} title={item.detail ?? undefined} className="flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-xs"><span className={cn("h-2 w-2 rounded-full", item.busy ? "bg-amber-400" : item.available ? "bg-emerald-400" : "bg-slate-300")} /><span className="truncate text-slate-600">{item.name}{item.busy ? " · 忙碌" : ""}</span></div>)}</div></div></div>
    {scan.error && <p className="text-rose-700">{scan.error}</p>}
  </div>
}

function DevicePoolPanel() {
  const [devices, setDevices] = useState<AdbDevice[]>([])
  const [serial, setSerial] = useState("")
  const [label, setLabel] = useState("")
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const refresh = useCallback(async (probe = false) => {
    try {
      const next = await api.devices(probe)
      setDevices((current) => sameJsonValue(current, next) ? current : next)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "读取设备池失败")
    }
  }, [])
  useEffect(() => {
    void refresh()
    const timer = window.setInterval(() => void refresh(), 15_000)
    return () => window.clearInterval(timer)
  }, [refresh])
  async function connect(event: FormEvent) {
    event.preventDefault()
    if (!serial.trim()) return
    setBusy("connect")
    setError(null)
    try {
      await api.connectDevice(serial.trim(), label.trim())
      setSerial("")
      setLabel("")
      await refresh()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "连接设备失败")
    } finally {
      setBusy(null)
    }
  }
  async function operate(device: AdbDevice, action: "drain" | "reconnect" | "remove") {
    setBusy(`${device.serial}:${action}`)
    setError(null)
    try {
      if (action === "drain") await api.drainDevice(device.serial)
      if (action === "reconnect") await api.reconnectDevice(device.serial)
      if (action === "remove") await api.removeDevice(device.serial)
      await refresh()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "设备操作失败")
    } finally {
      setBusy(null)
    }
  }
  return <div><SectionTitle icon={Smartphone} title="动态 ADB 设备池" description="扫描运行中也可扩容；每台设备一次只归属一个任务" />
    <form className="mt-3 grid gap-2 sm:grid-cols-[1fr_1fr_auto]" onSubmit={connect}><input className="field" value={serial} onChange={(event) => setSerial(event.target.value)} placeholder="serial 或 host:port" aria-label="ADB serial" /><input className="field" value={label} onChange={(event) => setLabel(event.target.value)} placeholder="备注（可选）" aria-label="设备备注" /><Button type="submit" size="sm" disabled={busy !== null || !serial.trim()}>{busy === "connect" ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}接入</Button></form>
    <div className="mt-3 space-y-2">{devices.map((device) => <div key={device.id} className="rounded-lg border border-slate-200 bg-slate-50 p-3"><div className="flex flex-wrap items-center justify-between gap-2"><div className="min-w-0"><p className="truncate font-mono text-xs font-semibold text-slate-800">{device.serial}</p><p className="mt-1 text-[11px] text-slate-500">{device.label ?? "未命名"} · Android {device.android_version ?? "?"} / API {device.api_level ?? "?"}</p></div><div className="flex flex-wrap gap-1"><Badge tone={device.busy ? "warning" : device.available ? "good" : device.state === "draining" ? "warning" : "neutral"}>{device.busy ? "任务占用" : device.state === "draining" ? "排空中" : device.available ? "可分配" : statusLabel(device.state)}</Badge>{device.compatibility_smoke_only && <Badge tone="warning">仅兼容性冒烟 · 不可裁决</Badge>}</div></div><div className="mt-2 flex flex-wrap gap-1"><Button variant="ghost" size="sm" onClick={() => void operate(device, "drain")} disabled={busy !== null || device.state === "draining"}>排空</Button><Button variant="ghost" size="sm" onClick={() => void operate(device, "reconnect")} disabled={busy !== null || device.busy}>重连</Button><Button variant="danger" size="sm" onClick={() => void operate(device, "remove")} disabled={busy !== null || device.busy}>移除</Button></div>{device.last_error && <p className="mt-2 text-[11px] leading-4 text-rose-700">{device.last_error}</p>}</div>)}{!devices.length && <p className="rounded-lg border border-dashed border-slate-300 p-3 text-xs text-slate-500">当前没有设备。接入 Android 16 / API 36+ 后即可加入裁决队列。</p>}</div>
    <div className="mt-2 flex gap-2"><Button variant="ghost" size="sm" onClick={() => void refresh(true)} disabled={busy !== null}><RefreshCw className="h-3.5 w-3.5" />主动探测</Button><span className="self-center text-[11px] text-slate-500">排空会停止新租约，正在运行的任务完成后才可移除。</span></div>{error && <p role="alert" className="mt-2 text-xs text-rose-700">{error}</p>}</div>
}

function EntryPoints({ entries }: { entries: EntryPoint[] }) {
  const [query, setQuery] = useState("")
  const [kind, setKind] = useState("all")
  const deferredQuery = useDeferredValue(query.trim().toLowerCase())
  const [visibleCount, setVisibleCount] = useState(200)
  useEffect(() => setVisibleCount(200), [deferredQuery, kind, entries])
  const filtered = useMemo(
    () => entries.filter((entry) => (kind === "all" || entry.kind === kind) && `${entry.name} ${entry.owner_component}`.toLowerCase().includes(deferredQuery)),
    [deferredQuery, entries, kind],
  )
  const visible = filtered.slice(0, visibleCount)
  return <div><div className="mb-5 flex flex-col gap-3 sm:flex-row"><label className="flex-1"><span className="sr-only">搜索入口</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索组件、URI 或 authority" className="field" /></label><label><span className="sr-only">入口类型</span><select value={kind} onChange={(event) => setKind(event.target.value)} className="field sm:w-48"><option value="all">全部入口</option><option value="activity">Activity</option><option value="service">Service</option><option value="receiver">Receiver</option><option value="provider">Provider</option><option value="deep_link">Deep Link</option></select></label></div><div className="overflow-x-auto rounded-xl border border-slate-200"><table className="w-full min-w-[760px] text-left text-sm"><thead className="bg-slate-50 text-xs text-slate-500"><tr><th className="px-4 py-3 font-medium">类型</th><th className="px-4 py-3 font-medium">入口</th><th className="px-4 py-3 font-medium">可达性</th><th className="px-4 py-3 font-medium">权限</th><th className="px-4 py-3 font-medium">判定依据</th></tr></thead><tbody className="divide-y divide-slate-200">{visible.map((entry) => <tr key={entry.id} className="hover:bg-slate-100"><td className="px-4 py-3"><EntryIcon kind={entry.kind} /></td><td className="max-w-md px-4 py-3"><p className="truncate font-mono text-xs text-slate-800" title={entry.name}>{entry.name}</p>{entry.owner_component && entry.owner_component !== entry.name && <p className="mt-1 truncate text-xs text-slate-600">handler · {entry.owner_component}</p>}</td><td className="px-4 py-3"><Badge tone={entry.exported ? "warning" : "good"}>{entry.exported ? "外部可达" : "私有"}</Badge></td><td className="px-4 py-3 text-xs text-slate-600">{entry.permission ?? "无"}{entry.permission_protection && <span className="block text-slate-600">{entry.permission_protection}</span>}</td><td className="px-4 py-3 text-xs text-slate-500">{entry.exported_reason}</td></tr>)}</tbody></table>{!filtered.length && <EmptyRow text="没有匹配的入口" />}</div>{visibleCount < filtered.length && <div className="mt-3 flex justify-center"><Button variant="secondary" size="sm" onClick={() => setVisibleCount((count) => count + 200)}>加载更多入口 · {filtered.length - visibleCount}</Button></div>}</div>
  }

function VersionEvolution({ scan, snapshot, diff, matches, entries, onCreated }: { scan: Scan; snapshot: SecuritySnapshot | null; diff: VersionDiff | null; matches: PatternMatch[]; entries: EntryPoint[]; onCreated: (scan: Scan) => Promise<void> }) {
  const [nextApk, setNextApk] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const entryNames = new Map(entries.map((entry) => [entry.id, entry.name]))
  const counts = diff?.summary.counts && typeof diff.summary.counts === "object"
    ? diff.summary.counts as Record<string, number>
    : {}
  async function uploadSuccessor(event: FormEvent) {
    event.preventDefault()
    if (!nextApk) return
    setUploading(true)
    setUploadError(null)
    try {
      const created = await api.upload(nextApk, "configured", scan.id)
      setNextApk(null)
      await onCreated(created)
    } catch (reason) {
      setUploadError(reason instanceof Error ? reason.message : "创建后继版本扫描失败")
    } finally {
      setUploading(false)
    }
  }
  return <div className="space-y-5">
    <div className="rounded-xl border border-cyan-200 bg-cyan-50 px-4 py-3 text-sm leading-relaxed text-cyan-950">
      安全快照只记录稳定的入口、权限、关键 API、校验与敏感汇点事实。建议显式上传后继版本；同签名历史版本的自动选择仅保留为兼容路径。
    </div>
    <form className="rounded-xl border border-violet-200 bg-violet-50 p-4" onSubmit={uploadSuccessor}><div className="flex flex-col gap-3 sm:flex-row sm:items-end"><label className="min-w-0 flex-1"><span className="mb-2 block text-sm font-semibold text-violet-950">上传后继 APK，并显式使用当前 Scan 作为基线</span><input type="file" accept=".apk,application/vnd.android.package-archive" className="field" onChange={(event) => setNextApk(event.target.files?.[0] ?? null)} disabled={uploading || scan.status !== "final"} /></label><Button type="submit" disabled={!nextApk || uploading || scan.status !== "final"}>{uploading ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <UploadCloud className="h-4 w-4" />}{uploading ? "正在创建" : "比较并复验新版本"}</Button></div><p className="mt-2 text-xs leading-5 text-violet-800">目标版本完成静态分析后才校验包名和签名；身份不连续时记录拒绝事件，不执行旧 PoC 回放。</p>{uploadError && <p role="alert" className="mt-2 text-xs text-rose-700">{uploadError}</p>}</form>
    <div className="grid gap-3 md:grid-cols-3">
      <Metric label="快照" value={snapshot ? "已生成" : "等待静态分析"} icon={Fingerprint} tone="cyan" />
      <Metric label="PoC 回放候选" value={diff?.replay_candidates.length ?? 0} icon={RefreshCw} tone="violet" />
      <Metric label="同类漏洞候选" value={matches.length} icon={Network} tone="rose" />
    </div>
    {snapshot && <div className="rounded-xl border border-slate-200 p-4"><p className="text-sm font-semibold text-slate-800">当前版本安全快照</p><p className="mt-2 font-mono text-xs text-slate-500">SHA256 {snapshot.snapshot_hash}</p><p className="mt-1 text-xs text-slate-500">签名身份 {snapshot.signer_digest ? shortHash(snapshot.signer_digest) : "未知"} · versionCode {snapshot.version_code ?? "—"}</p></div>}
    {diff ? <div className="rounded-xl border border-slate-200 p-4"><div className="flex flex-wrap items-center justify-between gap-2"><p className="text-sm font-semibold text-slate-800">相对版本 {String(diff.summary.baseline_version_name ?? diff.baseline_scan_id)}</p><Badge tone="good">语义 Diff 完成</Badge></div><div className="mt-3 flex flex-wrap gap-2">{Object.entries(counts).map(([category, count]) => <Badge key={category}>{category} {count}</Badge>)}</div><div className="mt-4 space-y-2">{diff.deltas.filter((item) => item.category !== "unchanged").map((item, index) => <div key={index} className="rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-600"><span className="font-semibold text-slate-800">{String(item.category)}</span> · {Array.isArray(item.changes) ? item.changes.join("、") : "入口变化"}</div>)}</div></div> : <EmptyRow text="尚无同包名、同签名的历史版本基线" />}
    <div><SectionTitle icon={Network} title="Finding 模式卡命中" description="这些只是待验证候选，不会直接计入 Finding" /><div className="mt-3 space-y-2">{matches.map((match) => <div key={match.id} className="rounded-xl border border-slate-200 p-3"><div className="flex items-center justify-between gap-3"><p className="truncate text-sm font-medium text-slate-800">{entryNames.get(match.entry_point_id) ?? match.entry_point_id}</p><Badge tone="warning">{match.score}%</Badge></div><p className="mt-2 text-xs text-slate-500">{match.reasons.join(" · ")}</p></div>)}{!matches.length && <EmptyRow text="当前版本没有模式卡候选" />}</div></div>
  </div>
}

function Findings({ findings, verificationCandidates, scanStatus, onRefresh }: { findings: Finding[]; verificationCandidates: Finding[]; scanStatus: string; onRefresh: () => Promise<void> }) {
  const sorted = [...findings].sort((a, b) => ["critical", "high", "medium", "low", "info"].indexOf(a.severity) - ["critical", "high", "medium", "low", "info"].indexOf(b.severity))
  const pending = [...verificationCandidates].sort((a, b) => ["critical", "high", "medium", "low", "info"].indexOf(a.severity) - ["critical", "high", "medium", "low", "info"].indexOf(b.severity))
  const isFinal = ["final", "failed"].includes(scanStatus)
  return <div className="space-y-6">
    <section className="space-y-3">
      <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm leading-relaxed text-emerald-950">这里只展示平台 Oracle 已证明具体安全影响、且所有 Evidence ID 均可核验的漏洞。静态规则与 AI 静态判断不会计入 Finding。</div>
      {!isFinal && <div className="rounded-xl border border-cyan-200 bg-cyan-50 px-4 py-3 text-sm leading-relaxed text-cyan-950">扫描尚未完成，后续动态证明可能继续增加 Finding。</div>}
      {sorted.map((finding) => <FindingCard key={finding.id} finding={finding} onRefresh={onRefresh} />)}
      {!findings.length && <EmptyRow text="尚无经过动态证据证明的 Finding" />}
    </section>
    {pending.length > 0 && <section className="space-y-3 border-t border-slate-200 pt-6">
      <div className="flex flex-col gap-3 rounded-xl border border-orange-200 bg-orange-50 px-4 py-4 sm:flex-row sm:items-center sm:justify-between">
        <div><div className="flex items-center gap-2"><Bot className="h-4 w-4 text-orange-700" /><h3 className="font-bold text-orange-950">待验证风险</h3><Badge tone="warning">{pending.length}</Badge></div><p className="mt-2 text-sm leading-6 text-orange-900">以下风险已有静态证据支持，但尚未获得平台危害 Oracle。它们不会计入上方已证实 Finding 数量；可在“待验证风险”Tab 中重新验证。</p></div>
      </div>
      {pending.map((finding) => <FindingCard key={`pending-${finding.id}`} finding={finding} onRefresh={onRefresh} />)}
    </section>}
  </div>
}

function Signals({ signals, onRefresh }: { signals: Finding[]; onRefresh: () => Promise<void> }) {
  const sorted = [...signals].sort((a, b) => ["critical", "high", "medium", "low", "info"].indexOf(a.severity) - ["critical", "high", "medium", "low", "info"].indexOf(b.severity))
  return <div className="space-y-3"><div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm leading-relaxed text-amber-950">这些是静态规则、AI 静态支持或尚未完成影响证明的调查线索，用于指导后续验证；它们不计入最终 Finding，也不代表漏洞已经成立。</div>{sorted.map((finding) => <FindingCard key={finding.id} finding={finding} onRefresh={onRefresh} />)}{!signals.length && <EmptyRow text="没有待验证线索" />}</div>
}

function ProofBacklog({ signals, tasks, onRefresh }: { signals: Finding[]; tasks: InvestigationTask[]; onRefresh: () => Promise<void> }) {
  const [retrying, setRetrying] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const tasksById = new Map(tasks.map((task) => [task.id, task]))
  const sorted = [...signals].sort((a, b) => ["critical", "high", "medium", "low", "info"].indexOf(a.severity) - ["critical", "high", "medium", "low", "info"].indexOf(b.severity))

  async function retry(task: InvestigationTask) {
    setRetrying(task.id)
    setError(null)
    try {
      await api.retryTask(task.id)
      await onRefresh()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "重新验证失败")
    } finally {
      setRetrying(null)
    }
  }

  return <div className="space-y-4">
    <div className="rounded-xl border border-orange-200 bg-orange-50 px-4 py-3 text-sm leading-relaxed text-orange-950">这里集中展示 Agent 已建立具体静态攻击路径、但尚未获得平台危害 Oracle 的风险候选。它们不会计入最终 Finding；接入 ADB 后可使用可选 Probe 快速路径、Agent 专用 PoC 或人工复现继续验证。</div>
    {error && <div role="alert" className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800">{error}</div>}
    {sorted.map((signal) => {
      const backlog = asRecord(signal.metadata_json.proof_backlog)
      const taskId = textValue(backlog?.task_id) ?? textValue(signal.metadata_json.task_id)
      const task = taskId ? tasksById.get(taskId) : undefined
      const automationState = textValue(backlog?.automation_state) ?? "manual_or_poc_required"
      const gaps = stringValues(backlog?.proof_gaps)
      const stateLabel = {
        attempted_not_proven: "已自动尝试，尚未证明危害",
        blocked_before_execution: "自动测试在执行前受阻",
        manual_or_poc_required: "需要专用 PoC 或人工复现",
      }[automationState] ?? automationState
      return <div key={signal.id} className="overflow-hidden rounded-xl border border-orange-200 bg-orange-50/40">
        <div className="flex flex-col gap-3 border-b border-orange-200 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
          <div><div className="flex flex-wrap items-center gap-2"><Badge tone="warning">待动态证明</Badge><Badge>{stateLabel}</Badge></div>{gaps.length > 0 && <p className="mt-2 text-xs leading-5 text-orange-900">{gaps.slice(0, 2).join("；")}</p>}</div>
          {task && isTerminalTask(task.status) && <Button variant="secondary" size="sm" onClick={() => retry(task)} disabled={retrying === task.id}>{retrying === task.id ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}重新验证</Button>}
        </div>
        <FindingCard finding={signal} onRefresh={onRefresh} />
      </div>
    })}
    {!sorted.length && <EmptyRow text="没有等待动态证明的风险候选" />}
  </div>
}

function isVerificationCandidate(signal: Finding) {
  const backlog = asRecord(signal.metadata_json.proof_backlog)
  return backlog?.status === "proof_required"
    || signal.status === "supported_static"
}

function FindingCard({ finding, onRefresh }: { finding: Finding; onRefresh: () => Promise<void> }) {
  const [open, setOpen] = useState(false)
  const [reviewOpen, setReviewOpen] = useState(false)
  return (
    <article className="content-auto rounded-xl border border-slate-200 bg-slate-50/70">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-start gap-4 p-4 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-700 sm:p-5"
        aria-expanded={open}
      >
        <Badge tone={severityTone[finding.severity]} className="mt-0.5 min-w-16 justify-center uppercase">{finding.severity}</Badge>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="font-semibold text-slate-900">{finding.title}</h3>
            <Badge tone={statusTone(finding.status)}>{statusLabel(finding.status)}</Badge>
          </div>
          <p className="mt-1.5 line-clamp-2 text-sm leading-relaxed text-slate-500">
            {markdownToPlainText(finding.description)}
          </p>
          <div className="mt-3 flex flex-wrap gap-3 text-[11px] text-slate-600">
            <span>{finding.masvs}</span>
            {finding.cwe && <span>{finding.cwe}</span>}
            <span>置信度 {finding.confidence}</span>
            <span>{finding.source}</span>
          </div>
        </div>
        <ChevronRight className={cn("mt-1 h-4 w-4 shrink-0 text-slate-600 transition-transform", open && "rotate-90")} />
      </button>
      {open && (
        <div className="border-t border-slate-200 px-4 py-5 sm:px-5">
          <div className="grid gap-6 xl:grid-cols-[minmax(0,1.4fr)_minmax(18rem,0.6fr)]">
            <div className="min-w-0">
              <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">风险说明</p>
              <MarkdownContent>{finding.description}</MarkdownContent>
            </div>
            <div className="min-w-0 rounded-xl border border-slate-200 bg-white p-4">
              <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">修复建议</p>
              <MarkdownContent>{finding.remediation}</MarkdownContent>
            </div>
          </div>
          {finding.evidence_ids.length > 0 && (
            <div className="mt-5">
              <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500">可核验证据</p>
              <div className="flex flex-wrap gap-2">
                {finding.evidence_ids.map((evidenceId) => (
                  <a key={evidenceId} href={`/api/v1/evidence/${evidenceId}/download`} className="rounded-lg border border-cyan-200 bg-cyan-50 px-2.5 py-1.5 font-mono text-[11px] text-cyan-900 hover:border-cyan-400 hover:underline">
                    {evidenceId}
                  </a>
                ))}
              </div>
            </div>
          )}
          <div className="mt-5 flex flex-wrap items-center justify-between gap-3">
            <p className="font-mono text-xs text-slate-600">rule · {finding.rule_id} · evidence {finding.evidence_ids.length}</p>
            <Button variant="secondary" size="sm" onClick={() => setReviewOpen(true)}>人工审核</Button>
          </div>
        </div>
      )}
      <ReviewDialog finding={finding} open={reviewOpen} onOpenChange={setReviewOpen} onReviewed={onRefresh} />
    </article>
  )
}

function ReviewDialog({ finding, open, onOpenChange, onReviewed }: { finding: Finding; open: boolean; onOpenChange: (open: boolean) => void; onReviewed: () => Promise<void> }) {
  const [status, setStatus] = useState<"accepted" | "false_positive" | "candidate">("accepted")
  const [note, setNote] = useState("")
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    if (open) setError(null)
  }, [open, finding.id])
  async function submit(event: FormEvent) {
    event.preventDefault()
    setSaving(true)
    setError(null)
    try {
      await api.review(finding.id, status, note)
      onOpenChange(false)
      setNote("")
      await onReviewed()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "保存审核失败")
    } finally {
      setSaving(false)
    }
  }
  return <Dialog open={open} onOpenChange={onOpenChange}><DialogContent><DialogTitle className="text-xl font-bold text-slate-950">审核 Finding</DialogTitle><DialogDescription className="mt-2 text-sm text-slate-600">Agent 和规则结论不会自动成为发布门禁，请记录人工判断依据。</DialogDescription><form className="mt-6 space-y-5" onSubmit={submit}><fieldset><legend className="mb-3 text-sm font-semibold text-slate-800">审核结论</legend><div className="grid grid-cols-3 gap-2">{([['accepted','接受'],['false_positive','误报'],['candidate','待确认']] as const).map(([value,label]) => <label key={value} className={cn("cursor-pointer rounded-lg border p-3 text-center text-sm", status === value ? "border-cyan-400 bg-cyan-400/10 text-cyan-800" : "border-slate-300 text-slate-600")}><input type="radio" name="status" value={value} checked={status === value} onChange={() => setStatus(value)} className="sr-only" />{label}</label>)}</div></fieldset><label className="block"><span className="mb-2 block text-sm font-semibold text-slate-800">审核备注 <span className="text-rose-700">*</span></span><textarea required minLength={1} maxLength={4000} value={note} onChange={(event) => setNote(event.target.value)} rows={5} className="field resize-y" placeholder="说明接受、误报或待确认的依据" /></label>{error && <p role="alert" className="text-sm text-rose-700">{error}</p>}<div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={saving}>取消</Button><Button type="submit" disabled={saving || !note.trim()}>{saving && <LoaderCircle className="h-4 w-4 animate-spin" />}保存审核</Button></div></form></DialogContent></Dialog>
}

function CoverageMatrix({ coverage }: { coverage: CoverageItem[] }) {
  const baseline = coverage.filter((item) => item.control_id.endsWith("-BASELINE"))
  const entryCoverage = coverage.filter((item) => item.entry_point_id)
  const [visibleCount, setVisibleCount] = useState(200)
  const stages = ["static", "deterministic_dynamic", "agent", "blackbox"]
  return <div className="space-y-8"><div><SectionTitle icon={ShieldCheck} title="MASVS 域覆盖" description="覆盖不代表无漏洞；缺口必须进入报告" /><div className="mt-4 overflow-x-auto rounded-xl border border-slate-200"><table className="w-full min-w-[850px] text-sm"><thead className="bg-slate-50 text-xs text-slate-500"><tr><th className="px-4 py-3 text-left font-medium">Domain</th>{stages.map((stage) => <th key={stage} className="px-3 py-3 text-center font-medium">{stage.replace("deterministic_dynamic", "确定性动态")}</th>)}<th className="px-4 py-3 text-left font-medium">缺口</th></tr></thead><tbody className="divide-y divide-slate-200">{baseline.map((item) => <tr key={item.id}><td className="px-4 py-3 font-semibold text-slate-700">{item.domain}</td>{stages.map((stage) => <td key={stage} className="px-3 py-3 text-center"><StageState value={String(item.stages[stage] ?? "pending")} /></td>)}<td className="max-w-xs px-4 py-3 text-xs leading-relaxed text-slate-500">{item.gap_reason ?? "—"}</td></tr>)}</tbody></table></div></div><div><SectionTitle icon={CircleDot} title="入口覆盖" description={`${entryCoverage.length} 个入口的逐项状态`} /><div className="mt-4 grid gap-2 md:grid-cols-2 xl:grid-cols-3">{entryCoverage.slice(0, visibleCount).map((item) => <div key={item.id} className="rounded-xl border border-slate-200 p-3"><div className="mb-2 flex items-center justify-between gap-3"><p className="truncate font-mono text-xs text-slate-700" title={item.title}>{item.title.replace("Entry point: ", "")}</p><Badge tone={statusTone(item.status)}>{statusLabel(item.status)}</Badge></div><p className="line-clamp-2 text-xs text-slate-600">{item.gap_reason ?? "全部计划阶段已记录"}</p></div>)}</div>{visibleCount < entryCoverage.length && <div className="mt-3 flex justify-center"><Button variant="secondary" size="sm" onClick={() => setVisibleCount((count) => count + 200)}>加载更多覆盖项 · {entryCoverage.length - visibleCount}</Button></div>}</div></div>
}

function HypothesisPipeline({ scanId, scanStatus, hypotheses, evaluations, entries, onRefresh }: { scanId: string; scanStatus: string; hypotheses: SecurityHypothesis[]; evaluations: BenchmarkEvaluation[]; entries: EntryPoint[]; onRefresh: () => Promise<void> }) {
  const [evaluating, setEvaluating] = useState(false)
  const [evaluationError, setEvaluationError] = useState<string | null>(null)
  const [visibleCount, setVisibleCount] = useState(100)
  const names = new Map(entries.map((entry) => [entry.id, entry.name]))
  const proven = hypotheses.filter((item) => item.status === "proven").length
  const challenged = hypotheses.filter((item) => ["challenged", "refuted"].includes(item.status)).length
  const harmProofs = hypotheses.flatMap((item) => item.proof_attempts).filter((item) => item.harm_demonstrated).length
  const canEvaluate = scanStatus === "final"
  return <div className="space-y-7">
    <div>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><SectionTitle icon={ShieldCheck} title="漏洞验证链" description="候选、反证、受控证明与平台裁决均绑定到稳定 Hypothesis ID" /><label title={canEvaluate ? "导入私有真值并评测最终结果" : "扫描完成后才能导入 Ground Truth"} className={cn("inline-flex h-9 items-center justify-center gap-2 rounded-lg border border-cyan-300 bg-cyan-50 px-3 text-xs font-semibold text-cyan-900", canEvaluate && !evaluating ? "cursor-pointer" : "pointer-events-none opacity-60")}><UploadCloud className="h-3.5 w-3.5" />{evaluating ? "正在评测" : canEvaluate ? "导入 Ground Truth JSON" : "扫描完成后可评测"}<input type="file" accept=".json,application/json" className="sr-only" disabled={evaluating || !canEvaluate} onChange={(event) => {
        const file = event.target.files?.[0]
        event.currentTarget.value = ""
        if (!file) return
        setEvaluating(true)
        setEvaluationError(null)
        void file.text().then((text) => api.evaluateGroundTruth(scanId, JSON.parse(text))).then(onRefresh).catch((reason: unknown) => setEvaluationError(reason instanceof Error ? reason.message : "评测文件处理失败")).finally(() => setEvaluating(false))
      }} /></label></div>
      {evaluationError && <p role="alert" className="mt-3 text-xs text-rose-700">{evaluationError}</p>}
      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        <TaskStateMetric label="平台已证明" value={proven} tone="border-emerald-200 bg-emerald-50 text-emerald-950" />
        <TaskStateMetric label="被质疑或反驳" value={challenged} tone="border-amber-200 bg-amber-50 text-amber-950" />
        <TaskStateMetric label="实际危害 Oracle 通过" value={harmProofs} tone="border-violet-200 bg-violet-50 text-violet-950" />
      </div>
    </div>
    {evaluations.length > 0 && <div>
      <SectionTitle icon={Gauge} title="私有真值评测" description="只计算平台确认并达到 ground truth 最低证明等级的 Finding" />
      <div className="mt-4 grid gap-3 md:grid-cols-2">{evaluations.map((evaluation) => {
        const metrics = recordValue(evaluation.result.metrics)
        const qualityGate = recordValue(evaluation.result.quality_gate)
        const qualityGatePassed = typeof qualityGate?.passed === "boolean" ? qualityGate.passed : null
        const provenance = recordValue(evaluation.result.data_provenance)
        const simulation = recordValue(evaluation.result.simulation)
        const synthetic = textValue(provenance?.kind) === "synthetic_demo"
        const omittedIds = Array.isArray(simulation?.omitted_ground_truth_ids) ? simulation.omitted_ground_truth_ids.filter((item): item is string => typeof item === "string") : []
        return <div key={evaluation.id} className={cn("rounded-xl border p-4", synthetic ? "border-amber-300 bg-amber-50/70" : "border-cyan-200 bg-cyan-50/60")}>
          <div className="flex items-center justify-between gap-3"><div><div className="flex flex-wrap items-center gap-2"><p className="font-semibold text-slate-900">{evaluation.name}</p>{synthetic && <Badge tone="warning">仿真数据</Badge>}{qualityGatePassed !== null && <Badge tone={qualityGatePassed ? "good" : "danger"}>{qualityGatePassed ? "100% 回归门禁通过" : "100% 回归门禁未通过"}</Badge>}</div><p className="mt-1 text-xs text-slate-600">{evaluation.investigator_backend}{evaluation.model ? ` · ${evaluation.model}` : ""}</p></div><Badge tone={synthetic ? "warning" : "info"}>{synthetic ? `召回 ${((numberValue(metrics?.recall) ?? 0) * 100).toFixed(2)}%` : `${numberValue(metrics?.score_100)?.toFixed(2) ?? "0.00"} 分`}</Badge></div>
          {synthetic && <div className="mt-3 rounded-lg border border-amber-300 bg-white/70 px-3 py-2 text-xs leading-5 text-amber-950">此卡仅用于汇报演练：未执行目标 APK、未连接真机，也没有生成 Finding 或 Evidence。仿真召回率为 {((numberValue(metrics?.recall) ?? 0) * 100).toFixed(2)}%；选择性漏报 {omittedIds.length} 项。</div>}
          <div className="mt-4 grid grid-cols-3 gap-2 text-center text-xs"><div className="rounded-lg bg-white p-2"><strong className="block text-base text-emerald-700">{numberValue(metrics?.true_positives) ?? 0}</strong>命中</div><div className="rounded-lg bg-white p-2"><strong className="block text-base text-rose-700">{numberValue(metrics?.false_positives) ?? 0}</strong>有害误报</div><div className="rounded-lg bg-white p-2"><strong className="block text-base text-amber-700">{numberValue(metrics?.false_negatives) ?? 0}</strong>漏报</div></div>
          {synthetic && omittedIds.length > 0 && <p className="mt-3 break-words text-xs leading-5 text-slate-600">仿真漏报：{omittedIds.join("、")}</p>}
        </div>
      })}</div>
    </div>}
    <div className="space-y-3">{hypotheses.slice(0, visibleCount).map((hypothesis) => {
      const latestArgument = hypothesis.arguments.at(-1)
      const latestSummary = markdownToPlainText(textValue(latestArgument?.payload.summary) ?? "") || undefined
      return <article key={hypothesis.id} className={cn("content-auto rounded-xl border bg-white p-4", hypothesis.status === "proven" ? "border-emerald-200" : "border-slate-200")}>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><Badge tone={statusTone(hypothesis.status)}>{statusLabel(hypothesis.status)}</Badge><Badge>{hypothesis.category}</Badge><span className="font-mono text-[11px] text-slate-400">{hypothesis.id}</span></div><h3 className="mt-3 font-semibold text-slate-950">{hypothesis.claim}</h3><p className="mt-2 break-all font-mono text-xs text-slate-500">{hypothesis.entry_point_ids.map((id) => names.get(id) ?? id).join(" · ")}</p></div><div className="text-right"><p className="text-2xl font-black text-slate-800">{hypothesis.confidence_score}</p><p className="text-[11px] text-slate-500">平台置信分</p></div></div>
        <div className="mt-4 grid gap-3 lg:grid-cols-2"><div className="rounded-lg border border-slate-200 bg-slate-50 p-3"><p className="text-xs font-bold text-slate-700">辩论记录 · {hypothesis.arguments.length}</p><p className="mt-2 text-xs leading-5 text-slate-600">{latestArgument ? `${latestArgument.role} / ${latestArgument.phase}${latestSummary ? `：${latestSummary}` : ""}` : "等待 Hunter 产生第一项结构化论证"}</p></div><div className="rounded-lg border border-slate-200 bg-slate-50 p-3"><p className="text-xs font-bold text-slate-700">Proof Attempt · {hypothesis.proof_attempts.length}</p><div className="mt-2 flex flex-wrap gap-2">{hypothesis.proof_attempts.length ? hypothesis.proof_attempts.map((proof) => <Badge key={proof.id} tone={proof.harm_demonstrated ? "good" : statusTone(proof.status)}>{proof.test_case_id} · {proof.harm_demonstrated ? "危害已证明" : statusLabel(proof.status)}</Badge>) : <span className="text-xs text-slate-600">尚未进入设备证明队列</span>}</div></div></div>
        <p className="mt-3 text-xs leading-5 text-slate-600">{hypothesis.impact || "等待平台确认实际安全影响。"}</p>
      </article>
    })}{!hypotheses.length && <EmptyRow text="扫描任务启动后将生成结构化漏洞假设" />}{visibleCount < hypotheses.length && <div className="flex justify-center py-3"><Button variant="secondary" size="sm" onClick={() => setVisibleCount((count) => count + 100)}>加载更多验证链 · {hypotheses.length - visibleCount}</Button></div>}</div>
  </div>
}

function mergeEventWindow(current: ScanEvent[], incoming: ScanEvent[], limit = 300) {
  const merged = new Map(current.map((event) => [event.id, event]))
  incoming.forEach((event) => merged.set(event.id, event))
  return [...merged.values()].sort((left, right) => left.id - right.id).slice(-limit)
}

function useTaskEventWindow(scanId: string, subscribeEvents: (subscriber: ScanEventSubscriber) => () => void) {
  const [events, setEvents] = useState<ScanEvent[]>([])
  useEffect(() => {
    const controller = new AbortController()
    let pending: ScanEvent[] = []
    let flushTimer: ReturnType<typeof setTimeout> | undefined
    const flush = () => {
      flushTimer = undefined
      if (!pending.length) return
      const batch = pending
      pending = []
      setEvents((current) => mergeEventWindow(current, batch))
    }
    const unsubscribe = subscribeEvents((event) => {
      if (!event.event_type.startsWith("exploration.")) return
      pending.push(event)
      if (!flushTimer) flushTimer = setTimeout(flush, 750)
    })
    void api.events(scanId, controller.signal, 0, 300, "summary")
      .then((history) => setEvents((current) => mergeEventWindow(history, current)))
      .catch((reason) => {
        if (!isAbortError(reason)) console.warn("failed to load task event window", reason)
      })
    return () => {
      controller.abort()
      unsubscribe()
      if (flushTimer) clearTimeout(flushTimer)
    }
  }, [scanId, subscribeEvents])
  return events
}

function TaskEventDetails({ events }: { events: ScanEvent[] }) {
  const [open, setOpen] = useState(false)
  const visibleEvents = events.slice(-100).reverse()
  return (
    <details className="group border-t border-slate-200 bg-white" onToggle={(event) => setOpen(event.currentTarget.open)}>
      <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-3 px-4 py-2 text-xs font-semibold text-slate-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-700 sm:px-5">
        <span>关键事件时间线 · {events.length}{events.length > 100 ? "（展开显示最近 100 条）" : ""}</span>
        <ChevronRight className="h-4 w-4 text-slate-400 transition-transform group-open:rotate-90" />
      </summary>
      {open && <ol className="max-h-[34rem] space-y-0 overflow-y-auto border-t border-slate-100 px-4 py-3 sm:px-5">
        {visibleEvents.map((event, index) => <ExplorationEventRow key={event.id} event={event} latest={index === 0} />)}
      </ol>}
    </details>
  )
}

function Tasks({ scan, tasks, entries, audits, subscribeEvents, health, onRefresh }: { scan: Scan; tasks: InvestigationTask[]; entries: EntryPoint[]; audits: AgentAudit[]; subscribeEvents: (subscriber: ScanEventSubscriber) => () => void; health: Health | null; onRefresh: () => Promise<void> }) {
  const events = useTaskEventWindow(scan.id, subscribeEvents)
  const names = useMemo(() => new Map(entries.map((item) => [item.id, item.name])), [entries])
  const auditCounts = useMemo(() => audits.reduce((counts, audit) => counts.set(audit.task_id, (counts.get(audit.task_id) ?? 0) + 1), new Map<string | null, number>()), [audits])
  const eventsByTask = useMemo(() => {
    const grouped = new Map<string, ScanEvent[]>()
    events.forEach((event) => {
      const taskId = textValue(event.data.task_id)
      if (!taskId) return
      const taskEvents = grouped.get(taskId) ?? []
      taskEvents.push(event)
      grouped.set(taskId, taskEvents)
    })
    return grouped
  }, [events])
  const [retrying, setRetrying] = useState<string | null>(null)
  const [controlSaving, setControlSaving] = useState<string | null>(null)
  const [rerunOpen, setRerunOpen] = useState(false)
  const [controlError, setControlError] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<InvestigationTask | null>(null)
  const [cancelTarget, setCancelTarget] = useState<InvestigationTask | null>(null)
  const [visibleTaskCount, setVisibleTaskCount] = useState(40)
  useEffect(() => setVisibleTaskCount(40), [scan.id])
  async function retry(task: InvestigationTask, contextMode: "continue" | "independent") {
    setRetrying(`${task.id}:${contextMode}`)
    setControlError(null)
    try {
      await api.reanalyzeTask(task.id, contextMode)
      await onRefresh()
    } catch (reason) {
      setControlError(reason instanceof Error ? reason.message : "重新分析失败")
    } finally {
      setRetrying(null)
    }
  }
  const agentControl = recordValue(scan.stats.agent_control)
  const configuredBackend = textValue(agentControl?.backend) ?? textValue(scan.stats.investigator) ?? "none"
  const backend: "codex" | "none" = configuredBackend === "codex" ? "codex" : "none"
  const masterEnabled = booleanValue(agentControl?.enabled) ?? backend !== "none"
  const deviceCapability = health?.capabilities.find((item) => item.name === "remote_android_device")
  const deviceBusy = Boolean(deviceCapability?.busy)
  const deviceReady = Boolean(deviceCapability?.available || deviceBusy)
  const codexReady = Boolean(health?.enabled_investigators.includes("codex") && health.capabilities.find((item) => item.name === "codex")?.available)
  const selectedBackendReady = backend === "codex" ? codexReady : false
  const incompleteCount = tasks.filter(taskNeedsSupplementalRerun).length
  async function updateMaster(enabled: boolean, selectedBackend: "codex" | "none" = backend) {
    setControlSaving("scan")
    setControlError(null)
    try {
      const fallback = selectedBackend === "none" ? "codex" : selectedBackend
      await api.updateScanAgentControl(scan.id, enabled, enabled ? fallback : selectedBackend)
      await onRefresh()
    } catch (reason) {
      setControlError(reason instanceof Error ? reason.message : "更新 AI 总开关失败")
    } finally {
      setControlSaving(null)
    }
  }
  async function updateTaskControl(task: InvestigationTask, enabled: boolean) {
    setControlSaving(task.id)
    setControlError(null)
    try {
      await api.updateTaskAgentControl(task.id, enabled)
      await onRefresh()
    } catch (reason) {
      setControlError(reason instanceof Error ? reason.message : "更新任务 AI 开关失败")
    } finally {
      setControlSaving(null)
    }
  }
  const stateCounts = tasks.reduce((counts, task) => {
    const state = taskVisualState(task).group
    counts[state] = (counts[state] ?? 0) + 1
    return counts
  }, {} as Record<string, number>)
  return (
    <div className="space-y-3">
      <div className="rounded-xl border border-violet-200 bg-violet-50/70 p-4">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
          <div>
            <div className="flex items-center gap-2"><Power className="h-4 w-4 text-violet-700" /><h3 className="text-sm font-bold text-violet-950">AI 探索控制</h3><Badge tone={masterEnabled ? "good" : "neutral"}>{masterEnabled ? "总开关已开启" : "总开关已关闭"}</Badge></div>
            <p className="mt-1 text-xs leading-5 text-violet-800">设置只影响尚未启动或之后重新分析的任务；运行中的模型调用保持启动时配置。</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label><span className="sr-only">AI 后端</span><select className="field h-9 min-w-44 py-1.5 text-xs" value={backend} disabled={controlSaving === "scan"} onChange={(event) => { const selected = event.target.value as "codex" | "none"; void updateMaster(selected === "none" ? false : masterEnabled, selected) }}><option value="codex" disabled={!codexReady}>Codex + DeepSeek{codexReady ? "" : " · 未就绪"}</option><option value="none">不使用 AI</option></select></label>
            <Button variant={masterEnabled ? "secondary" : "primary"} size="sm" onClick={() => void updateMaster(!masterEnabled)} disabled={controlSaving === "scan" || (!masterEnabled && !codexReady)}>{controlSaving === "scan" ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Power className="h-3.5 w-3.5" />}{masterEnabled ? "关闭全部 AI" : "开启全部 AI"}</Button>
            <Button variant="secondary" size="sm" onClick={() => setRerunOpen(true)} disabled={!["final", "failed"].includes(scan.status) || incompleteCount === 0}><RefreshCw className="h-3.5 w-3.5" />补扫信息不全项 · {incompleteCount}</Button>
          </div>
        </div>
        <div className="mt-3 flex flex-wrap gap-2 text-xs"><Badge tone={deviceBusy ? "warning" : deviceReady ? "good" : "warning"}>{deviceBusy ? "ADB 忙碌 · 扫描任务占用" : deviceReady ? "ADB 已就绪" : "ADB 当前不可用"}</Badge><Badge tone={masterEnabled && selectedBackendReady ? "good" : "warning"}>{masterEnabled ? selectedBackendReady ? "AI 后端已就绪" : "AI 后端未就绪" : "AI 已关闭"}</Badge><span className="text-violet-800">补扫会复用 Manifest、JADX/Smali 和静态 Evidence，只重新执行设备验证与 AI。</span></div>
        {controlError && <p role="alert" className="mt-3 text-xs text-rose-700">{controlError}</p>}
      </div>
      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5" aria-label="探索任务状态汇总">
        <TaskStateMetric label="等待判断" value={stateCounts.waiting ?? 0} tone="border-cyan-200 bg-cyan-50 text-cyan-900" />
        <TaskStateMetric label="正在分析" value={stateCounts.active ?? 0} tone="border-violet-200 bg-violet-50 text-violet-900" />
        <TaskStateMetric label="已判断" value={stateCounts.judged ?? 0} tone="border-emerald-200 bg-emerald-50 text-emerald-900" />
        <TaskStateMetric label="未形成判断" value={stateCounts.unresolved ?? 0} tone="border-amber-200 bg-amber-50 text-amber-950" />
        <TaskStateMetric label="已停止" value={stateCounts.stopped ?? 0} tone="border-slate-200 bg-slate-100 text-slate-800" />
      </div>
      {tasks.slice(0, visibleTaskCount).map((task) => {
        const visualState = taskVisualState(task)
        const taskEvents = eventsByTask.get(task.id) ?? []
        const latest = taskEvents.at(-1)
        const started = taskEvents.find((event) => event.event_type === "exploration.started")
        const lastPhased = taskEvents.slice().reverse().find((event) => textValue(event.data.phase))
        const lastSession = taskEvents.slice().reverse().find((event) => textValue(event.data.thread_id) || textValue(event.data.session_id))
        const backend = textValue(latest?.data.agent_backend) ?? textValue(started?.data.agent_backend) ?? textValue(task.result.agent_backend)
        const model = textValue(started?.data.model)
        const phase = textValue(lastPhased?.data.phase)
        const session = task.thread_id ?? textValue(lastSession?.data.thread_id) ?? textValue(lastSession?.data.session_id)
        const continuation = recordValue(task.result.manual_continuation)
        const continuationNumber = numberValue(continuation?.continuation_number)
        const independent = recordValue(task.result.independent_reanalysis)
        return (
          <article key={task.id} className={cn("content-auto overflow-hidden rounded-xl border bg-white shadow-sm", visualState.card)}>
            <div className={cn("flex flex-col gap-2 border-b px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-5", visualState.banner)}>
              <div className="flex items-center gap-2">
                {visualState.group === "active" ? <Activity className="h-4 w-4 animate-pulse motion-reduce:animate-none" /> : visualState.group === "judged" ? <Check className="h-4 w-4" /> : visualState.group === "unresolved" ? <AlertTriangle className="h-4 w-4" /> : visualState.group === "stopped" ? <X className="h-4 w-4" /> : <Clock3 className="h-4 w-4" />}
                <p className="text-sm font-bold">{visualState.label}</p>
              </div>
              <p className="text-xs opacity-80">{visualState.description}</p>
            </div>
            <div className="p-4 sm:p-5">
              <div className="flex flex-col gap-4 sm:flex-row sm:items-start">
                <div className={cn("grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-violet-500/10 text-violet-700", task.status === "running" && "animate-pulse motion-reduce:animate-none")}><Bot className="h-5 w-5" /></div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="font-semibold text-slate-900">{taskTypeLabel(task.task_type)}</h3>
                    <Badge tone={statusTone(task.status)}>{statusLabel(task.status)}</Badge>
                    <Badge>priority {task.priority}</Badge>
                    {backend && <Badge tone="info">{backend}{model ? ` · ${model}` : ""}</Badge>}
                    {Boolean(auditCounts.get(task.id)) && <Badge tone="info">AI 调用 {auditCounts.get(task.id)}</Badge>}
                    {continuationNumber && <Badge tone="warning">深度续跑 {continuationNumber}</Badge>}
                    {independent && <Badge tone="info">独立复核 · 不继承上下文</Badge>}
                  </div>
                  <p className="mt-2 truncate font-mono text-xs text-slate-500">{task.target_entry_ids.map((id) => names.get(id) ?? id).join(" · ")}</p>
                  {latest ? (
                    <div className="mt-4 rounded-lg border border-violet-200 bg-white px-3 py-3">
                      <div className="flex items-start gap-2">
                        <Activity className="mt-0.5 h-4 w-4 shrink-0 text-violet-600" />
                        <div className="min-w-0">
                          <p className="text-sm font-medium text-slate-800">{latest.message}</p>
                          <p className="mt-1 text-xs text-slate-500">{formatDate(latest.created_at)}{phase ? ` · ${explorationPhaseLabel(phase)}` : ""}</p>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <ul className="mt-3 space-y-1 text-xs leading-relaxed text-slate-500">{task.hypotheses.slice(0, 3).map((item) => <li key={item} className="flex gap-2"><span className="text-slate-700">—</span><span>{item}</span></li>)}</ul>
                  )}
                  {session && <p className="mt-3 truncate font-mono text-[11px] text-slate-500">session · {session}</p>}
                  {task.error && <p className="mt-3 text-xs text-amber-700">{task.error}</p>}
                  {task.status === "timed_out" && <div className="mt-3 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-950">本轮 20 分钟预算已用尽。可以继续深度探索；下一轮会获得新的 20 分钟预算，并装载该任务历次静态、ADB 和 AI Evidence。</div>}
                </div>
                <div className="flex shrink-0 items-center gap-3 text-xs text-slate-600">
                  <span>attempt {task.attempts}</span>
                  <Button variant="ghost" size="sm" onClick={() => void updateTaskControl(task, !taskAgentEnabled(task))} disabled={!masterEnabled || ["running", "cancel_requested"].includes(task.status) || controlSaving === task.id} title={!masterEnabled ? "先开启扫描级 AI 总开关" : "覆盖本任务的 AI 使用设置"}>{controlSaving === task.id ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Bot className="h-3.5 w-3.5" />}AI {taskAgentEnabled(task) ? "开" : "关"}</Button>
                  {isTerminalTask(task.status) && <Button variant={task.status === "timed_out" ? "primary" : "secondary"} size="sm" onClick={() => retry(task, "continue")} disabled={retrying !== null}>{retrying === `${task.id}:continue` ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}{task.status === "timed_out" ? "继续深度探索" : "沿用入口重跑"}</Button>}
                  {isTerminalTask(task.status) && <Button variant="secondary" size="sm" onClick={() => retry(task, "independent")} disabled={retrying !== null} title="新建任务，只复用 APK、Manifest、JADX/Smali 等静态产物；不读取原任务 Evidence、结论、Thread 或版本回放">{retrying === `${task.id}:independent` ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <ScanSearch className="h-3.5 w-3.5" />}独立复核</Button>}
                  {["queued", "awaiting_device", "running", "cancel_requested"].includes(task.status) && <Button variant="danger" size="sm" onClick={() => setCancelTarget(task)} disabled={task.status === "cancel_requested"}>{task.status === "cancel_requested" ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <X className="h-3.5 w-3.5" />}{task.status === "queued" ? "取消等待" : task.status === "cancel_requested" ? "正在停止" : "停止分析"}</Button>}
                  {["blocked_device", "completed", "not_reproduced", "inconclusive", "timed_out", "failed", "canceled", "cancel_requested"].includes(task.status) && <Button variant="danger" size="sm" onClick={() => setDeleteTarget(task)}><Trash2 className="h-3.5 w-3.5" />删除</Button>}
                </div>
              </div>
            </div>
            {taskEvents.length > 0 && <TaskEventDetails events={taskEvents} />}
          </article>
        )
      })}
      {visibleTaskCount < tasks.length && <div className="flex justify-center py-3"><Button variant="secondary" size="sm" onClick={() => setVisibleTaskCount((count) => count + 40)}>加载更多任务 · {tasks.length - visibleTaskCount}</Button></div>}
      {!tasks.length && <EmptyRow text="静态规划完成后将生成入口探索任务" />}
      <DeleteTaskDialog
        task={deleteTarget}
        target={deleteTarget?.target_entry_ids.map((id) => names.get(id) ?? id).join(" · ") ?? ""}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
        onDeleted={async () => { setDeleteTarget(null); await onRefresh() }}
      />
      <CancelTaskDialog
        task={cancelTarget}
        target={cancelTarget?.target_entry_ids.map((id) => names.get(id) ?? id).join(" · ") ?? ""}
        onOpenChange={(open) => !open && setCancelTarget(null)}
        onCancelled={async () => { setCancelTarget(null); await onRefresh() }}
      />
      <RerunIncompleteDialog scan={rerunOpen ? scan : null} count={incompleteCount} deviceReady={deviceReady} deviceBusy={deviceBusy} onOpenChange={setRerunOpen} onQueued={onRefresh} />
    </div>
  )
}

function TaskStateMetric({ label, value, tone }: { label: string; value: number; tone: string }) {
  return <div className={cn("flex items-center justify-between rounded-xl border px-3 py-2.5", tone)}><span className="text-xs font-semibold">{label}</span><span className="text-lg font-black tabular-nums">{value}</span></div>
}

function taskTypeLabel(taskType: string) {
  return {
    deep_link: "Deep Link handler 探索",
    static_review: "静态语义审计",
    adaptive_verification: "高权限批量验证",
  }[taskType] ?? "导出组件探索"
}

function taskVisualState(task: InvestigationTask) {
  if (task.status === "awaiting_device") {
    const queue = recordValue(task.result.device_queue)
    const position = numberValue(queue?.position_at_enqueue)
    return { group: "waiting", label: "等待云真机", description: position ? `入队时位于第 ${position} 位，可立即取消` : "已进入单设备队列，可立即取消", card: "border-cyan-300", banner: "border-cyan-200 bg-cyan-50 text-cyan-950" }
  }
  if (task.status === "queued") return { group: "waiting", label: "等待判断", description: "等待调度，尚未占用云真机或调用 AI", card: "border-cyan-200", banner: "border-cyan-200 bg-cyan-50 text-cyan-950" }
  if (task.status === "running") return { group: "active", label: "正在分析", description: "平台正在执行设备验证或 SDK 探索，并持续记录关键事件", card: "border-violet-300 shadow-[0_12px_35px_rgba(124,58,237,.10)]", banner: "border-violet-200 bg-violet-50 text-violet-950" }
  if (task.status === "cancel_requested") return { group: "active", label: "正在停止", description: "已发送中止请求，等待设备或模型运行时确认", card: "border-amber-300", banner: "border-amber-200 bg-amber-50 text-amber-950" }
  if (task.status === "timed_out") return { group: "unresolved", label: "本轮预算已用尽", description: "可复用历次证据继续下一轮深度探索", card: "border-amber-300", banner: "border-amber-200 bg-amber-50 text-amber-950" }
  if (task.status === "completed" && textValue(task.result.result) === "inconclusive") return { group: "unresolved", label: "信息不全", description: "平台结论为证据不足，可在能力恢复后补扫", card: "border-amber-200", banner: "border-amber-200 bg-amber-50 text-amber-950" }
  if (task.status === "completed" || task.status === "not_reproduced") return { group: "judged", label: "已判断", description: task.result.result ? `平台结论：${statusLabel(String(task.result.result))}` : "平台已完成证据校验", card: "border-emerald-200", banner: "border-emerald-200 bg-emerald-50 text-emerald-950" }
  if (task.status === "canceled") return { group: "stopped", label: "已停止", description: "用户主动终止，未产生新的最终结论", card: "border-slate-300", banner: "border-slate-200 bg-slate-100 text-slate-800" }
  return { group: "unresolved", label: "未形成判断", description: task.status === "blocked_device" ? "设备或 AI 能力阻塞，可修复后重试" : "证据、工具或预算不足", card: "border-amber-200", banner: "border-amber-200 bg-amber-50 text-amber-950" }
}

function taskAgentEnabled(task: InvestigationTask) {
  return booleanValue(task.preconditions.agent_enabled) ?? true
}

function taskNeedsSupplementalRerun(task: InvestigationTask) {
  if (["blocked_device", "inconclusive", "timed_out", "failed"].includes(task.status)) return true
  return task.status === "completed" && textValue(task.result.result) === "inconclusive"
}

function isTerminalTask(status: string) {
  return !["queued", "awaiting_device", "running", "cancel_requested"].includes(status)
}

function RerunIncompleteDialog({ scan, count, deviceReady, deviceBusy, onOpenChange, onQueued }: { scan: Scan | null; count: number; deviceReady: boolean; deviceBusy: boolean; onOpenChange: (open: boolean) => void; onQueued: () => Promise<void> }) {
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => setError(null), [scan?.id])
  async function rerun() {
    if (!scan) return
    setSubmitting(true)
    setError(null)
    try {
      await api.rerunIncomplete(scan.id)
      onOpenChange(false)
      await onQueued()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "补扫启动失败")
    } finally {
      setSubmitting(false)
    }
  }
  return (
    <Dialog open={Boolean(scan)} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogTitle className="text-xl font-bold text-slate-950">补扫所有信息不全项？</DialogTitle>
        <DialogDescription className="mt-2 text-sm leading-6 text-slate-600">将重新排队 {count} 个设备阻塞、执行失败、超时或平台结论为“证据不足”的任务。静态扫描和反编译结果会直接复用，不会再次运行 JADX。</DialogDescription>
        <div className={cn("mt-5 rounded-xl border p-4 text-sm", deviceBusy ? "border-cyan-200 bg-cyan-50 text-cyan-950" : deviceReady ? "border-emerald-200 bg-emerald-50 text-emerald-900" : "border-amber-200 bg-amber-50 text-amber-950")}>{deviceBusy ? "ADB 设备当前都被扫描任务占用；补扫可以正常入队，设备释放后会自动执行。" : deviceReady ? "ADB 当前已就绪，可以开始补充动态证据。" : "ADB 当前仍不可用；继续补扫可能再次得到证据不足。"} AI 是否执行由总开关和各任务开关共同决定。</div>
        {error && <p role="alert" className="mt-4 text-sm text-rose-700">{error}</p>}
        <div className="mt-6 flex justify-end gap-2"><Button variant="ghost" onClick={() => onOpenChange(false)} disabled={submitting}>取消</Button><Button onClick={rerun} disabled={submitting}>{submitting ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}{submitting ? "正在排队" : `确认补扫 ${count} 项`}</Button></div>
      </DialogContent>
    </Dialog>
  )
}

function CancelTaskDialog({ task, target, onOpenChange, onCancelled }: { task: InvestigationTask | null; target: string; onOpenChange: (open: boolean) => void; onCancelled: () => Promise<void> }) {
  const [cancelling, setCancelling] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => setError(null), [task?.id])
  async function cancel() {
    if (!task) return
    setCancelling(true)
    setError(null)
    try {
      await api.cancelTask(task.id)
      await onCancelled()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "停止失败")
    } finally {
      setCancelling(false)
    }
  }
  const waiting = task?.status === "queued" || task?.status === "awaiting_device"
  return (
    <Dialog open={Boolean(task)} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogTitle className="text-xl font-bold text-slate-950">{waiting ? "取消等待任务？" : "停止当前 AI 分析？"}</DialogTitle>
        <DialogDescription className="mt-2 text-sm leading-6 text-slate-600">{waiting ? "任务会从等待队列中取消，不会占用云真机或调用模型。" : "平台会中止当前 Codex turn，保留已经产生的 Evidence 和审计事件，但本次任务不会生成新的最终判断。"}</DialogDescription>
        {task && <div className="mt-5 rounded-xl border border-amber-200 bg-amber-50 p-4"><p className="font-semibold text-amber-950">{taskTypeLabel(task.task_type)}</p><p className="mt-1 break-all font-mono text-xs text-amber-800">{target || task.id}</p></div>}
        {error && <p role="alert" className="mt-4 text-sm text-rose-700">{error}</p>}
        <div className="mt-6 flex justify-end gap-2"><Button variant="ghost" onClick={() => onOpenChange(false)} disabled={cancelling}>继续分析</Button><Button variant="danger" onClick={cancel} disabled={cancelling}>{cancelling ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <X className="h-4 w-4" />}{cancelling ? "正在处理" : waiting ? "确认取消等待" : "确认停止分析"}</Button></div>
      </DialogContent>
    </Dialog>
  )
}

function DeleteTaskDialog({ task, target, onOpenChange, onDeleted }: { task: InvestigationTask | null; target: string; onOpenChange: (open: boolean) => void; onDeleted: () => Promise<void> }) {
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => setError(null), [task?.id])
  async function remove() {
    if (!task) return
    setDeleting(true)
    setError(null)
    try {
      await api.deleteTask(task.id)
      await onDeleted()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "删除失败")
    } finally {
      setDeleting(false)
    }
  }
  return (
    <Dialog open={Boolean(task)} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogTitle className="text-xl font-bold text-slate-950">删除已执行任务？</DialogTitle>
        <DialogDescription className="mt-2 text-sm leading-6 text-slate-600">任务将从探索任务列表移除。已经形成的 Hypothesis、辩论记录、Proof Attempt、Finding、Evidence 和 AI 审计均会保留，仍可在报告、验证链与“AI 审计”页中追溯。正在停止的任务会继续完成后台中止和设备清理，但不会重新出现在列表中。</DialogDescription>
        {task && <div className="mt-5 rounded-xl border border-rose-200 bg-rose-50 p-4"><p className="font-semibold text-rose-900">{taskTypeLabel(task.task_type)}</p><p className="mt-1 break-all font-mono text-xs text-rose-700">{target || task.id}</p></div>}
        {error && <p role="alert" className="mt-4 text-sm text-rose-700">{error}</p>}
        <div className="mt-6 flex justify-end gap-2"><Button variant="ghost" onClick={() => onOpenChange(false)} disabled={deleting}>取消</Button><Button variant="danger" onClick={remove} disabled={deleting}>{deleting ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}{deleting ? "正在删除" : "确认删除任务"}</Button></div>
      </DialogContent>
    </Dialog>
  )
}

function ExplorationEventRow({ event, latest }: { event: ScanEvent; latest: boolean }) {
  const source = textValue(event.data.source)
  const evidenceId = textValue(event.data.evidence_id)
  const detail = textValue(event.data.rationale_summary) ?? textValue(event.data.hypothesis)
  return (
    <li className="relative flex gap-3 py-2.5">
      <div className="relative flex w-4 shrink-0 justify-center">
        <span className={cn("mt-1.5 h-2 w-2 rounded-full", latest ? "bg-violet-600" : "bg-slate-300")} />
        <span className="absolute bottom-[-10px] top-4 w-px bg-slate-200" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2"><p className="text-xs font-medium text-slate-700">{event.message}</p>{source && <Badge>{explorationSourceLabel(source)}</Badge>}</div>
        {detail && <p className="mt-1 text-xs leading-5 text-slate-500">{detail}</p>}
        <p className="mt-1 font-mono text-[10px] text-slate-400">{formatDate(event.created_at)} · {event.event_type}{evidenceId ? ` · evidence ${shortHash(evidenceId)}` : ""}</p>
      </div>
    </li>
  )
}

function AgentAudits({ audits, tasks, entries }: { audits: AgentAudit[]; tasks: InvestigationTask[]; entries: EntryPoint[] }) {
  const [visibleCount, setVisibleCount] = useState(30)
  const [loadedAudits, setLoadedAudits] = useState<Record<string, AgentAudit>>({})
  const [loadingAuditId, setLoadingAuditId] = useState<string | null>(null)
  const [loadErrors, setLoadErrors] = useState<Record<string, string>>({})
  const tasksById = useMemo(() => new Map(tasks.map((task) => [task.id, task])), [tasks])
  const names = useMemo(() => new Map(entries.map((entry) => [entry.id, entry.name])), [entries])
  async function loadAudit(audit: AgentAudit) {
    setLoadingAuditId(audit.id)
    setLoadErrors((current) => ({ ...current, [audit.id]: "" }))
    try {
      const loaded = (await api.agentAudits(audit.scan_id, undefined, true, audit.id))[0]
      if (!loaded) throw new Error("审计记录不存在")
      setLoadedAudits((current) => ({ ...current, [audit.id]: loaded }))
    } catch (reason) {
      setLoadErrors((current) => ({
        ...current,
        [audit.id]: reason instanceof Error ? reason.message : "审计正文加载失败",
      }))
    } finally {
      setLoadingAuditId(null)
    }
  }
  if (!audits.length) return <EmptyRow text="本次扫描没有调用 AI，因此没有 AI 审计记录" />
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-cyan-200 bg-cyan-50 p-4 text-sm leading-6 text-cyan-950">
        每次模型调用的精确输入、SDK 关键事件、结构化原始输出、测试裁决和证据校验均保存为不可变 Evidence。列表只加载元数据；点击单条记录后才读取并校验该次调用的正文。
      </div>
      {audits.slice(0, visibleCount).map((summaryAudit) => {
        const audit = loadedAudits[summaryAudit.id] ?? summaryAudit
        const task = audit.task_id ? tasksById.get(audit.task_id) : undefined
        const target = task?.target_entry_ids.map((id) => names.get(id) ?? id).join(" · ")
        const current = Boolean(task?.turn_id && audit.turn_id === task.turn_id)
        return (
          <article key={audit.id} className="content-auto overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
            <div className="flex flex-col gap-4 border-b border-slate-200 p-4 sm:flex-row sm:items-start sm:justify-between">
              <div className="flex min-w-0 gap-3">
                <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-violet-50 text-violet-700"><ScrollText className="h-5 w-5" /></div>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="font-semibold text-slate-950">{auditPhaseLabel(audit.phase)}</h3>
                    <Badge tone={statusTone(audit.status)}>{statusLabel(audit.status)}</Badge>
                    <Badge tone={audit.integrity === "verified" ? "good" : audit.integrity === "failed" ? "danger" : "neutral"}>{audit.integrity === "verified" ? "SHA-256 已验证" : audit.integrity === "failed" ? "完整性异常" : "正文未加载"}</Badge>
                    <Badge tone={current ? "good" : "neutral"}>{current ? "当前最终调用" : "历史/过程调用"}</Badge>
                  </div>
                  <p className="mt-1 truncate text-sm text-slate-600">{target ?? audit.task_id ?? "未知任务"}</p>
                  <p className="mt-2 font-mono text-xs text-slate-500">{audit.backend} · {audit.provider}/{audit.model} · {audit.isolation} · attempt {audit.attempt}</p>
                </div>
              </div>
              <div className="shrink-0 text-right text-xs text-slate-500">
                <p>{formatDate(audit.started_at)}</p>
                <p className="mt-1 font-mono">audit {shortHash(audit.id)}</p>
                <Button className="mt-2" variant="secondary" size="sm" onClick={() => void loadAudit(audit)} disabled={loadingAuditId !== null}>{loadingAuditId === audit.id ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <ScrollText className="h-3.5 w-3.5" />}{audit.integrity === "not_checked" ? "加载并校验正文" : "重新校验"}</Button>
              </div>
            </div>
            {loadErrors[audit.id] && <div role="alert" className="m-4 rounded-lg border border-rose-200 bg-rose-50 p-3 text-xs text-rose-700">{loadErrors[audit.id]}</div>}
            {audit.integrity !== "not_checked" && <>
              <AuditConclusion audit={audit} current={current} taskResult={textValue(task?.result.result)} />
              <div className="grid gap-3 p-4 md:grid-cols-2">
                <AuditValue label="Thread ID" value={audit.thread_id ?? "—"} />
                <AuditValue label="Turn ID" value={audit.turn_id ?? "—"} />
              </div>
              {audit.integrity_errors.length > 0 && <div role="alert" className="mx-4 mb-4 rounded-lg border border-rose-200 bg-rose-50 p-3 text-xs text-rose-700">{audit.integrity_errors.join("；")}</div>}
              <div className="space-y-3 px-4 pb-4">
                <AuditArtifact title="模型精确输入" artifact={audit.artifacts.request} />
                <AuditArtifact title="SDK 关键事件" artifact={audit.artifacts.events} />
                <AuditArtifact title="模型结构化原始输出" artifact={audit.artifacts.response} />
                <AuditArtifact title="AI 申请测试的白名单裁决" artifact={audit.artifacts.test_validation} />
                <AuditArtifact title="平台证据校验与最终结论" artifact={audit.artifacts.validation} />
                <AuditArtifact title="用户中止记录" artifact={audit.artifacts.cancellation} />
                <AuditArtifact title="调用错误" artifact={audit.artifacts.error} />
              </div>
            </>}
          </article>
        )
      })}
      {visibleCount < audits.length && <div className="flex justify-center py-3"><Button variant="secondary" size="sm" onClick={() => setVisibleCount((count) => count + 30)}>加载更多审计 · {audits.length - visibleCount}</Button></div>}
    </div>
  )
}

function AuditConclusion({ audit, current, taskResult }: { audit: AgentAudit; current: boolean; taskResult?: string }) {
  const response = asRecord(audit.artifacts.response?.content)
  const validation = asRecord(audit.artifacts.validation?.content)
  const rawOutput = asRecord(response?.structured_output)
  const validatedOutput = asRecord(validation?.validated_output) ?? rawOutput
  if (!validatedOutput) return null

  // The immutable platform-validation artifact is the authority for this audit.
  // A task aggregate may briefly retain an older/inconclusive value during retries.
  const result = textValue(validation?.final_result) ?? (current ? taskResult : undefined) ?? textValue(validatedOutput.result) ?? "unknown"
  const claimedResult = textValue(validation?.claimed_result)
  const summary = textValue(validatedOutput.summary) ?? "模型未提供结论摘要。"
  const proposedSeverity = textValue(validatedOutput.severity_proposal) ?? "—"
  const severity = result === "refuted_static"
    ? "无风险"
    : result === "inconclusive"
    ? "未定"
    : (textValue(validation?.final_severity) ?? proposedSeverity).toUpperCase()
  const confidence = textValue(validatedOutput.confidence) ?? "—"
  const evidenceIds = stringValues(validation?.accepted_evidence_ids ?? validatedOutput.evidence_ids)
  const rejectedEvidenceIds = stringValues(validation?.rejected_evidence_ids)
  const gaps = stringValues(validatedOutput.coverage_gaps)
  const downgraded = validation?.downgraded === true
  const presentation = auditResultPresentation(result, current, audit.phase)
  const headingId = `audit-conclusion-${audit.id}`

  return (
    <section aria-labelledby={headingId} className={cn("mx-4 mt-4 overflow-hidden rounded-xl border", presentation.container)}>
      <div className="flex flex-col gap-4 p-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex min-w-0 gap-3">
          <div className={cn("grid h-11 w-11 shrink-0 place-items-center rounded-xl ring-1 ring-inset", presentation.iconContainer)}>
            {result === "refuted_static" || (current && result === "not_reproduced") ? <ShieldCheck className="h-5 w-5" /> : ["inconclusive", "unknown", "not_reproduced"].includes(result) ? <AlertTriangle className="h-5 w-5" /> : <ShieldX className="h-5 w-5" />}
          </div>
          <div className="min-w-0">
            <p className={cn("text-[11px] font-bold uppercase tracking-[0.16em]", presentation.eyebrow)}>{current ? "任务当前最终结论" : validation ? "历史平台校验记录" : "中间模型输出"}</p>
            <h4 id={headingId} className="mt-1 text-lg font-bold text-slate-950">{presentation.label}</h4>
            <MarkdownContent className="mt-3">{summary}</MarkdownContent>
          </div>
        </div>
        <div className="grid shrink-0 grid-cols-3 gap-2 sm:min-w-72">
          <ConclusionMetric label="风险等级" value={severity} />
          <ConclusionMetric label="置信度" value={confidenceLabel(confidence)} />
          <ConclusionMetric label="有效证据" value={String(evidenceIds.length)} />
        </div>
      </div>
      {(downgraded || gaps.length > 0 || rejectedEvidenceIds.length > 0) && (
        <div className="border-t border-current/10 bg-white/55 px-4 py-3">
          {downgraded && <div role="status" className="flex items-start gap-2 rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-950"><AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" /><span>平台将模型声明从“{auditResultPresentation(claimedResult ?? "unknown", false, audit.phase).label}”调整为“{presentation.label}”。</span></div>}
          <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-xs text-slate-600">
            {gaps.slice(0, 3).map((gap, index) => <span key={`${index}-${gap}`} className="flex items-start gap-1.5"><CircleDot className="mt-0.5 h-3 w-3 shrink-0" />{gap}</span>)}
            {rejectedEvidenceIds.length > 0 && <span>拒绝了 {rejectedEvidenceIds.length} 个无效 Evidence ID</span>}
          </div>
        </div>
      )}
      {result === "refuted_static" && (
        <div className="border-t border-emerald-200 bg-emerald-50 px-4 py-3 text-xs leading-5 text-emerald-950">
          该入口点在当前 APK 版本、既定攻击者模型和已核验证据下未发现可利用风险，相关假设已关闭；这不代表整个 APK 无风险。
        </div>
      )}
      {result === "supported_static" && (
        <div className="border-t border-orange-200 bg-orange-50 px-4 py-3 text-xs leading-5 text-orange-950">
          这是静态证据支持的待验证风险，所示等级是验证优先级；在平台 Oracle 证明具体安全影响前，它会显示在“待验证风险”，不会进入“已证实 Finding”。
        </div>
      )}
      {current && result === "inconclusive" && proposedSeverity !== "—" && (
        <div className="border-t border-amber-200 bg-amber-50 px-4 py-3 text-xs leading-5 text-amber-950">
          模型曾建议风险等级 {proposedSeverity.toUpperCase()}，但平台因证据不足未采纳；该值仅保留在原始审计中供后续补扫参考。
        </div>
      )}
    </section>
  )
}

function ConclusionMetric({ label, value }: { label: string; value: string }) {
  return <div className="rounded-lg border border-white/70 bg-white/75 px-2 py-2 text-center shadow-sm"><p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</p><p className="mt-1 text-xs font-bold text-slate-900">{value}</p></div>
}

function auditResultPresentation(result: string, current: boolean, phase?: string) {
  const prefix = current ? "" : "过程输出："
  if (result === "reproduced_blackbox") return { label: `${prefix}已完成黑盒复现`, container: "border-rose-200 bg-rose-50/80", iconContainer: "bg-rose-100 text-rose-700 ring-rose-200", eyebrow: "text-rose-700" }
  if (result === "supported_static") return { label: phase === "rescue_review" ? `${prefix}救援审查发现候选攻击链` : `${prefix}静态证据支持风险`, container: "border-orange-200 bg-orange-50/80", iconContainer: "bg-orange-100 text-orange-700 ring-orange-200", eyebrow: "text-orange-700" }
  if (result === "refuted_static") return { label: `${prefix}当前攻击模型下未发现可利用风险`, container: "border-emerald-200 bg-emerald-50/80", iconContainer: "bg-emerald-100 text-emerald-700 ring-emerald-200", eyebrow: "text-emerald-700" }
  if (result === "not_reproduced") return current
    ? { label: "当前测试未能复现", container: "border-emerald-200 bg-emerald-50/80", iconContainer: "bg-emerald-100 text-emerald-700 ring-emerald-200", eyebrow: "text-emerald-700" }
    : { label: "过程输出：尚未取得有效动态复现", container: "border-amber-200 bg-amber-50/80", iconContainer: "bg-amber-100 text-amber-800 ring-amber-200", eyebrow: "text-amber-800" }
  if (result === "inconclusive") return { label: current ? "本次任务未形成有效结论" : "历史调用当时未形成结论", container: "border-amber-200 bg-amber-50/80", iconContainer: "bg-amber-100 text-amber-800 ring-amber-200", eyebrow: "text-amber-800" }
  return { label: current ? `未识别的任务结果：${result}` : `未识别的过程输出：${result}`, container: "border-slate-200 bg-slate-50/80", iconContainer: "bg-slate-100 text-slate-700 ring-slate-200", eyebrow: "text-slate-700" }
}

function confidenceLabel(value: string) {
  return { high: "高", medium: "中", low: "低" }[value] ?? value
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined
}

function stringValues(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : []
}

function AuditArtifact({ title, artifact }: { title: string; artifact?: AgentAudit["artifacts"][string] }) {
  const [open, setOpen] = useState(false)
  if (!artifact) return null
  return (
    <details className="group rounded-lg border border-slate-200 bg-slate-50" onToggle={(event) => setOpen(event.currentTarget.open)}>
      <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-3 px-3 py-2 text-sm font-semibold text-slate-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-700">
        <span>{title}</span>
        <span className="font-mono text-[11px] font-normal text-slate-500">SHA256 {shortHash(artifact.sha256)}</span>
      </summary>
      {open && <div className="border-t border-slate-200 p-3">
        <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-white p-4 font-mono text-xs leading-6 text-slate-800 ring-1 ring-inset ring-slate-200">{formatAuditContent(artifact.content)}</pre>
        <a className="mt-3 inline-flex text-xs font-semibold text-cyan-800 underline-offset-4 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-700" href={`/api/v1/evidence/${artifact.evidence_id}/download`}>下载不可变 Evidence</a>
      </div>}
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
    exploration_round: "自适应深度探索",
    adaptive_verification: "高权限批量验证",
    final_evaluation: "最终证据判断",
    recovery_evaluation: "异常恢复判断",
  }[phase] ?? phase
}

function explorationPhaseLabel(phase: string) {
  return {
    static_only: "静态证据判断",
    test_planning: "首轮测试规划",
    exploration_round: "自适应探索",
    adaptive_verification: "高权限批量验证",
    final_evaluation: "最终证据判断",
    recovery_evaluation: "异常恢复判断",
  }[phase] ?? phase
}

function explorationSourceLabel(source: string) {
  return { sdk: "SDK", model: "AI", platform: "平台" }[source] ?? source
}

function textValue(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined
}

function booleanValue(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined
}

function recordValue(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined
}

function formatAuditContent(value: unknown) {
  if (value === null || value === undefined) return "内容不可用"
  if (typeof value === "string") return value
  return JSON.stringify(value, null, 2)
}

function FreshRunDialog({ scan, onOpenChange, onCreated }: { scan: Scan | null; onOpenChange: (open: boolean) => void; onCreated: (scan: Scan) => Promise<void> }) {
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => setError(null), [scan?.id])
  async function create() {
    if (!scan) return
    setCreating(true)
    setError(null)
    try {
      await onCreated(await api.freshRun(scan.id))
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "创建全新扫描失败")
    } finally {
      setCreating(false)
    }
  }
  return (
    <Dialog open={Boolean(scan)} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogTitle className="text-xl font-bold text-slate-950">从头重新扫描这个 APK？</DialogTitle>
        <DialogDescription className="mt-2 text-sm leading-6 text-slate-600">平台会复用经过 SHA-256 校验的原始 APK，但创建新的 Scan ID 和空白工作区。旧任务、Finding、Evidence、Agent 会话、版本 PoC 回放和模式卡都不会进入新扫描；原扫描完整保留，便于对照。</DialogDescription>
        {scan && <div className="mt-5 rounded-xl border border-cyan-200 bg-cyan-50 p-4"><p className="font-semibold text-cyan-950">{scan.package_name ?? scan.filename}</p><p className="mt-1 font-mono text-xs text-cyan-800">SHA256 {shortHash(scan.artifact_sha256)}</p></div>}
        {error && <p role="alert" className="mt-4 text-sm text-rose-700">{error}</p>}
        <div className="mt-6 flex justify-end gap-2"><Button variant="ghost" onClick={() => onOpenChange(false)} disabled={creating}>取消</Button><Button onClick={create} disabled={creating}>{creating ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <ScanSearch className="h-4 w-4" />}{creating ? "正在创建" : "确认全新重扫"}</Button></div>
      </DialogContent>
    </Dialog>
  )
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
  const maxUploadBytes = health?.max_upload_bytes
  const maxUploadLabel = maxUploadBytes
    ? `${(maxUploadBytes / 1024 / 1024).toLocaleString(undefined, { maximumFractionDigits: 2 })} MB`
    : "由服务端配置"
  async function submit(event: FormEvent) { event.preventDefault(); if (!file) return; setUploading(true); setError(null); try { const scan = await api.upload(file, investigator); setFile(null); setInvestigator("configured"); await onUploaded(scan) } catch (reason) { setError(reason instanceof Error ? reason.message : "上传失败") } finally { setUploading(false) } }
  function choose(candidate?: File) {
    if (inputRef.current) inputRef.current.value = ""
    if (!candidate) return
    setFile(null)
    if (!candidate.name.toLowerCase().endsWith(".apk")) {
      setError("首期仅支持单个可安装 .apk 文件")
      return
    }
    if (maxUploadBytes && candidate.size > maxUploadBytes) {
      setError(`APK 不能超过 ${maxUploadLabel}`)
      return
    }
    setError(null)
    setFile(candidate)
  }
  const defaultLabel = health?.default_investigator === "codex" ? "Codex + DeepSeek" : "仅静态与确定性动态"
  const codexReady = Boolean(health?.enabled_investigators.includes("codex") && health.capabilities.find((item) => item.name === "codex")?.available)
  return <Dialog open={open} onOpenChange={onOpenChange}><DialogContent><DialogTitle className="text-xl font-bold text-slate-950">新建 APK 安全扫描</DialogTitle><DialogDescription className="mt-2 text-sm leading-relaxed text-slate-600">APK 将保存在本机内容寻址存储中。AI 受单次任务范围约束，所有进入报告的结论仍须通过平台证据校验。</DialogDescription><form className="mt-6" onSubmit={submit}><button type="button" className={cn("grid min-h-52 w-full place-items-center rounded-2xl border border-dashed p-6 text-center transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-700", dragging ? "border-cyan-300 bg-cyan-400/10" : "border-slate-300 bg-slate-50 hover:border-slate-500")} onClick={() => { if (inputRef.current) inputRef.current.value = ""; inputRef.current?.click() }} onDragOver={(event) => { event.preventDefault(); setDragging(true) }} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); choose(event.dataTransfer.files[0]) }}><input ref={inputRef} type="file" accept=".apk,application/vnd.android.package-archive" className="sr-only" onChange={(event) => choose(event.target.files?.[0])} /><div>{file ? <><FileArchive className="mx-auto h-10 w-10 text-cyan-700" /><p className="mt-4 break-all font-semibold text-slate-900">{file.name}</p><p className="mt-2 text-xs text-slate-500">{(file.size / 1024 / 1024).toFixed(2)} MB · 点击更换</p></> : <><UploadCloud className="mx-auto h-10 w-10 text-slate-500" /><p className="mt-4 font-semibold text-slate-800">拖入 APK 或点击选择</p><p className="mt-2 text-xs text-slate-600">最大 {maxUploadLabel} · 不支持 AAB/XAPK/split APK</p></>}</div></button><label className="mt-5 block"><span className="mb-2 block text-sm font-semibold text-slate-800">语义探索后端</span><select className="field w-full" value={investigator} onChange={(event) => setInvestigator(event.target.value as InvestigatorChoice)}><option value="configured">服务默认 · {defaultLabel}</option><option value="codex" disabled={!codexReady}>Codex + DeepSeek · {codexReady ? "已就绪" : "未启用或依赖未就绪"}</option><option value="none">关闭 AI · 仅规则和确定性动态测试</option></select><span className="mt-2 block text-xs leading-relaxed text-slate-600">这是本次扫描的初始选择；扫描详情中仍可显式调整总开关、后端和逐任务开关。</span></label>{error && <p role="alert" className="mt-3 text-sm text-rose-700">{error}</p>}<div className="mt-6 flex justify-end gap-2"><Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>取消</Button><Button type="submit" disabled={!file || uploading}>{uploading ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <ScanSearch className="h-4 w-4" />}{uploading ? "正在接收" : "开始扫描"}</Button></div></form></DialogContent></Dialog>
}

function Metric({ label, value, icon: Icon, tone }: { label: string; value: number | string; icon: typeof AlertTriangle; tone: "rose" | "cyan" | "violet" | "emerald" }) {
  const colors = { rose: "bg-rose-500/10 text-rose-700", cyan: "bg-cyan-500/10 text-cyan-700", violet: "bg-violet-500/10 text-violet-700", emerald: "bg-emerald-500/10 text-emerald-700" }
  return <Card className="p-4"><div className={cn("mb-4 grid h-9 w-9 place-items-center rounded-lg", colors[tone])}><Icon className="h-4 w-4" /></div><p className="font-display text-2xl font-bold text-slate-950">{value}</p><p className="mt-1 text-xs text-slate-500">{label}</p></Card>
}

function SectionTitle({ icon: Icon, title, description }: { icon: typeof Activity; title: string; description: string }) { return <div className="flex items-center gap-3"><div className="grid h-9 w-9 place-items-center rounded-lg bg-slate-100 text-cyan-700"><Icon className="h-4 w-4" /></div><div><h3 className="text-sm font-semibold text-slate-900">{title}</h3><p className="text-xs text-slate-600">{description}</p></div></div> }
function ReportLink({ scanId, format, label }: { scanId: string; format: string; label: string }) { return <a href={`/api/v1/scans/${scanId}/report/${format}`} target="_blank" rel="noreferrer" className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-slate-300 px-3 text-xs font-semibold text-slate-700 hover:border-slate-500 hover:text-slate-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-700"><ArrowDownToLine className="h-3.5 w-3.5" />{label}</a> }
function EntryIcon({ kind }: { kind: string }) { const icons: Record<string, typeof Box> = { activity: Smartphone, activity_alias: Smartphone, service: ServerCog, receiver: Network, provider: Box, deep_link: Link2 }; const Icon = icons[kind] ?? Code2; return <span className="inline-flex items-center gap-2 text-xs text-slate-600"><Icon className="h-3.5 w-3.5 text-cyan-600" />{kind}</span> }
function StageState({ value }: { value: string }) { if (["completed", "covered", "attempted"].includes(value)) return <Check className="mx-auto h-4 w-4 text-emerald-600" aria-label={value} />; if (value === "not_applicable") return <span className="text-slate-400" aria-label={value}>—</span>; if (["blocked", "failed", "not_tested"].includes(value)) return <X className="mx-auto h-4 w-4 text-rose-600" aria-label={value} />; return <Clock3 className="mx-auto h-4 w-4 text-slate-600" aria-label={value} /> }
function EmptyRow({ text }: { text: string }) { return <div className="grid min-h-32 place-items-center p-6 text-sm text-slate-600">{text}</div> }
function LoadingState() { return <div className="grid min-h-[60vh] place-items-center"><div className="text-center"><LoaderCircle className="mx-auto h-7 w-7 animate-spin text-cyan-700 motion-reduce:animate-none" /><p className="mt-3 text-sm text-slate-500">正在加载审计数据</p></div></div> }
function EmptyState({ onUpload }: { onUpload: () => void }) { return <div className="grid min-h-[70vh] place-items-center"><div className="max-w-md text-center"><div className="mx-auto grid h-16 w-16 place-items-center rounded-2xl border border-cyan-400/20 bg-cyan-400/5 text-cyan-700"><Smartphone className="h-8 w-8" /></div><h2 className="font-display mt-6 text-2xl font-bold text-slate-950">从一个上线 APK 开始</h2><p className="mt-3 text-sm leading-7 text-slate-500">先建立确定性攻击面，再由选定的 AI 后端对导出组件和 Deep Link 逐项探索。每个结论都保留覆盖状态与证据链。</p><Button className="mt-6" onClick={onUpload}><UploadCloud className="h-4 w-4" />选择 APK</Button></div></div> }

export default App
