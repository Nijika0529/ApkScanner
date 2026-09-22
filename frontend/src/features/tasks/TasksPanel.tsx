import {
  Activity,
  AlertTriangle,
  Bot,
  Check,
  ChevronRight,
  Clock3,
  LoaderCircle,
  Pause,
  Play,
  Power,
  RefreshCw,
  ScanSearch,
  Trash2,
  X,
} from "lucide-react"
import { useEffect, useMemo, useState } from "react"
import { api } from "../../api"
import { EmptyRow } from "../../components/EmptyRow"
import {
  Badge,
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from "../../components/ui"
import {
  booleanValue,
  cn,
  formatDate,
  isAbortError,
  numberValue,
  recordValue,
  shortHash,
  statusLabel,
  statusTone,
  textValue,
} from "../../lib"
import type {
  AgentAudit,
  EntryPoint,
  Health,
  InvestigationTask,
  Scan,
  ScanEvent,
} from "../../types"
import { isTerminalTask, taskTypeLabel } from "./presentation"

export type ScanEventSubscriber = (event: ScanEvent) => void

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

export function Tasks({ scan, tasks, entries, audits, subscribeEvents, health, onRefresh }: { scan: Scan; tasks: InvestigationTask[]; entries: EntryPoint[]; audits: AgentAudit[]; subscribeEvents: (subscriber: ScanEventSubscriber) => () => void; health: Health | null; onRefresh: () => Promise<void> }) {
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
  const [executionError, setExecutionError] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<InvestigationTask | null>(null)
  const [cancelTarget, setCancelTarget] = useState<InvestigationTask | null>(null)
  const [stopScanOpen, setStopScanOpen] = useState(false)
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
  const executionControl = recordValue(scan.stats.execution_control)
  const executionState = textValue(executionControl?.state) ?? "running"
  const executionPaused = executionState === "paused"
  const executionStopping = executionState === "stopping"
  const scanActive = !["final", "failed"].includes(scan.status)
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
  async function updateExecution(action: "pause" | "resume") {
    setControlSaving("execution")
    setExecutionError(null)
    try {
      await api.updateScanExecutionControl(scan.id, action)
      await onRefresh()
    } catch (reason) {
      setExecutionError(reason instanceof Error ? reason.message : "更新任务调度状态失败")
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
      <div className="rounded-xl border border-slate-300 bg-white p-4 shadow-sm">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
          <div>
            <div className="flex flex-wrap items-center gap-2"><Activity className="h-4 w-4 text-slate-700" /><h3 className="text-sm font-bold text-slate-950">扫描任务控制</h3><Badge tone={executionStopping ? "warning" : executionPaused ? "warning" : scanActive ? "good" : "neutral"}>{executionStopping ? "正在结束" : executionPaused ? "调度已暂停" : scanActive ? "调度运行中" : executionState === "stopped" ? "已由用户结束" : "扫描已完成"}</Badge></div>
            <p className="mt-1 text-xs leading-5 text-slate-600">暂停后不再领取 queued 任务，已运行的任务会完成并释放设备；结束扫描会停止运行中、设备排队中和等待中的全部任务，并保留已有 Finding 与 Evidence。</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="secondary" size="sm" onClick={() => void updateExecution(executionPaused ? "resume" : "pause")} disabled={!scanActive || executionStopping || controlSaving === "execution"}>{controlSaving === "execution" ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : executionPaused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}{executionPaused ? "恢复任务调度" : "暂停新任务"}</Button>
            <Button variant="danger" size="sm" onClick={() => setStopScanOpen(true)} disabled={!scanActive || executionStopping || controlSaving === "execution"}><X className="h-3.5 w-3.5" />{executionStopping ? "正在结束扫描" : "结束整次扫描"}</Button>
          </div>
        </div>
        {executionError && <p role="alert" className="mt-3 text-xs text-rose-700">{executionError}</p>}
      </div>
      <div className="rounded-xl border border-violet-200 bg-violet-50/70 p-4">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
          <div>
            <div className="flex items-center gap-2"><Power className="h-4 w-4 text-violet-700" /><h3 className="text-sm font-bold text-violet-950">AI 后端设置</h3><Badge tone={masterEnabled ? "good" : "neutral"}>{masterEnabled ? "AI 已启用" : "AI 已禁用"}</Badge></div>
            <p className="mt-1 text-xs leading-5 text-violet-800">这里只决定尚未启动任务是否调用 AI，不会暂停任务调度；暂停或结束请使用上方“扫描任务控制”。</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label><span className="sr-only">AI 后端</span><select className="field h-9 min-w-44 py-1.5 text-xs" value={backend} disabled={controlSaving === "scan"} onChange={(event) => { const selected = event.target.value as "codex" | "none"; void updateMaster(selected === "none" ? false : masterEnabled, selected) }}><option value="codex" disabled={!codexReady}>Codex + DeepSeek{codexReady ? "" : " · 未就绪"}</option><option value="none">不使用 AI</option></select></label>
            <Button variant={masterEnabled ? "secondary" : "primary"} size="sm" onClick={() => void updateMaster(!masterEnabled)} disabled={controlSaving === "scan" || (!masterEnabled && !codexReady)}>{controlSaving === "scan" ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Power className="h-3.5 w-3.5" />}{masterEnabled ? "禁用后续 AI" : "启用 AI"}</Button>
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
      <StopScanDialog scan={stopScanOpen ? scan : null} tasks={tasks} onOpenChange={setStopScanOpen} onStopped={onRefresh} />
    </div>
  )
}

export function TaskStateMetric({ label, value, tone }: { label: string; value: number; tone: string }) {
  return <div className={cn("flex items-center justify-between rounded-xl border px-3 py-2.5", tone)}><span className="text-xs font-semibold">{label}</span><span className="text-lg font-black tabular-nums">{value}</span></div>
}

function compactTaskError(error: string | null, fallback: string) {
  const normalized = error?.replace(/\s+/g, " ").trim()
  if (!normalized) return fallback
  return normalized.length > 240 ? `${normalized.slice(0, 237)}...` : normalized
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
  if (task.status === "timed_out") return { group: "unresolved", label: "本轮预算已用尽", description: compactTaskError(task.error, "可复用历次证据继续下一轮深度探索"), card: "border-amber-300", banner: "border-amber-200 bg-amber-50 text-amber-950" }
  if (task.status === "failed") {
    const category = textValue(task.result.failure_category)
    return { group: "unresolved", label: category === "agent_structured_output_or_runtime" ? "Agent 结果无效" : "任务执行失败", description: compactTaskError(task.error, "任务 worker 异常退出，详情已记录到事件与审计证据"), card: "border-rose-300", banner: "border-rose-200 bg-rose-50 text-rose-950" }
  }
  if (task.status === "blocked_device") return { group: "unresolved", label: "设备不可用", description: compactTaskError(task.error, "当前没有通过健康检查的可分配设备，可连接设备后补扫"), card: "border-amber-300", banner: "border-amber-200 bg-amber-50 text-amber-950" }
  if (task.status === "inconclusive") return { group: "unresolved", label: "证据未收口", description: compactTaskError(task.error, "设备或 Agent 已执行，但现有证据不足以形成终态判断"), card: "border-amber-200", banner: "border-amber-200 bg-amber-50 text-amber-950" }
  if (task.status === "completed" && textValue(task.result.result) === "inconclusive") return { group: "unresolved", label: "信息不全", description: "平台结论为证据不足，可在能力恢复后补扫", card: "border-amber-200", banner: "border-amber-200 bg-amber-50 text-amber-950" }
  if (task.status === "completed" || task.status === "not_reproduced") return { group: "judged", label: "已判断", description: task.result.result ? `平台结论：${statusLabel(String(task.result.result))}` : "平台已完成证据校验", card: "border-emerald-200", banner: "border-emerald-200 bg-emerald-50 text-emerald-950" }
  if (task.status === "canceled") return { group: "stopped", label: "已停止", description: "用户主动终止，未产生新的最终结论", card: "border-slate-300", banner: "border-slate-200 bg-slate-100 text-slate-800" }
  return { group: "unresolved", label: "未形成判断", description: compactTaskError(task.error, `任务以 ${task.status} 状态结束，未产生平台结论`), card: "border-amber-200", banner: "border-amber-200 bg-amber-50 text-amber-950" }
}

function taskAgentEnabled(task: InvestigationTask) {
  return booleanValue(task.preconditions.agent_enabled) ?? true
}

function taskNeedsSupplementalRerun(task: InvestigationTask) {
  if (["blocked_device", "inconclusive", "timed_out", "failed"].includes(task.status)) return true
  return task.status === "completed" && textValue(task.result.result) === "inconclusive"
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

function StopScanDialog({ scan, tasks, onOpenChange, onStopped }: { scan: Scan | null; tasks: InvestigationTask[]; onOpenChange: (open: boolean) => void; onStopped: () => Promise<void> }) {
  const [stopping, setStopping] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => setError(null), [scan?.id])
  const activeCount = tasks.filter((task) => ["running", "awaiting_device", "cancel_requested"].includes(task.status)).length
  const queuedCount = tasks.filter((task) => task.status === "queued").length
  async function stop() {
    if (!scan) return
    setStopping(true)
    setError(null)
    try {
      await api.updateScanExecutionControl(scan.id, "stop")
      onOpenChange(false)
      await onStopped()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "结束扫描失败")
    } finally {
      setStopping(false)
    }
  }
  return (
    <Dialog open={Boolean(scan)} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogTitle className="text-xl font-bold text-slate-950">结束整次扫描？</DialogTitle>
        <DialogDescription className="mt-2 text-sm leading-6 text-slate-600">平台会停止 {activeCount} 个运行中或设备排队中的任务，并取消 {queuedCount} 个尚未启动的任务。已经生成的 Finding、Evidence、PoC 和审计事件会保留，停止完成后仍会生成一份终态报告。</DialogDescription>
        <div className="mt-5 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-950">这个操作不能直接恢复未完成任务；之后仍可对具体任务重新分析或发起补扫。</div>
        {error && <p role="alert" className="mt-4 text-sm text-rose-700">{error}</p>}
        <div className="mt-6 flex justify-end gap-2"><Button variant="ghost" onClick={() => onOpenChange(false)} disabled={stopping}>继续扫描</Button><Button variant="danger" onClick={stop} disabled={stopping}>{stopping ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <X className="h-4 w-4" />}{stopping ? "正在停止" : "确认结束扫描"}</Button></div>
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
