import type {
  AdbDevice,
  AgentAudit,
  ArtifactGraph,
  BenchmarkEvaluation,
  CoverageItem,
  EntryPoint,
  Finding,
  Health,
  InvestigationTask,
  InvestigatorChoice,
  IndexedArtifact,
  OperatorSession,
  PatternMatch,
  Scan,
  ScanDeleteResult,
  ScanRerunResult,
  ScanEvent,
  SecurityHypothesis,
  SecuritySnapshot,
  TaskDeleteResult,
  VersionDiff,
} from "./types"

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers)
  headers.set("X-APKScanner-Request", "console")
  const response = await fetch(path, { ...init, headers })
  if (!response.ok) {
    const detail = await response.json().catch(() => ({ detail: response.statusText }))
    const message =
      typeof detail.detail === "string"
        ? detail.detail
        : detail.detail
          ? JSON.stringify(detail.detail)
          : `Request failed: ${response.status}`
    throw new Error(message)
  }
  return response.json() as Promise<T>
}

async function optionalRequest<T>(path: string, signal?: AbortSignal): Promise<T | null> {
  const response = await fetch(path, {
    signal,
    headers: { "X-APKScanner-Request": "console" },
  })
  if (response.status === 404) return null
  if (!response.ok) throw new Error(`Request failed: ${response.status}`)
  return response.json() as Promise<T>
}

interface CacheEntry {
  expiresAt: number
  value: unknown
}

const getCache = new Map<string, CacheEntry>()
const MAX_GET_CACHE_ENTRIES = 128

function storeCachedValue(path: string, value: unknown, ttlMs: number) {
  // Map insertion order gives us a small LRU approximation without another
  // dependency. This prevents long review sessions from caching every scan.
  getCache.delete(path)
  getCache.set(path, { expiresAt: Date.now() + ttlMs, value })
  while (getCache.size > MAX_GET_CACHE_ENTRIES) {
    const oldest = getCache.keys().next().value
    if (oldest === undefined) break
    getCache.delete(oldest)
  }
}

function cachedValue<T>(path: string): T | undefined {
  const cached = getCache.get(path)
  if (!cached) return undefined
  if (cached.expiresAt <= Date.now()) {
    getCache.delete(path)
    return undefined
  }
  return cached.value as T
}

async function cachedRequest<T>(
  path: string,
  signal?: AbortSignal,
  ttlMs = 60_000,
): Promise<T> {
  if (signal?.aborted) throw new DOMException("Aborted", "AbortError")
  const cached = cachedValue<T>(path)
  if (cached !== undefined) return cached
  const value = await request<T>(path, { signal })
  if (!signal?.aborted) storeCachedValue(path, value, ttlMs)
  return value
}

async function cachedOptionalRequest<T>(
  path: string,
  signal?: AbortSignal,
  ttlMs = 5_000,
): Promise<T | null> {
  if (signal?.aborted) throw new DOMException("Aborted", "AbortError")
  const cached = getCache.get(path)
  if (cached && cached.expiresAt > Date.now()) return cached.value as T | null
  const value = await optionalRequest<T>(path, signal)
  if (!signal?.aborted) storeCachedValue(path, value, ttlMs)
  return value
}

function invalidateScanCache(scanId: string) {
  const marker = `/api/v1/scans/${scanId}`
  for (const key of getCache.keys()) {
    if (key.startsWith(marker)) getCache.delete(key)
  }
}

export const api = {
  health: () => request<Health>("/api/v1/health"),
  devices: (probe = false) =>
    request<AdbDevice[]>(`/api/v1/devices?probe=${probe ? "true" : "false"}`),
  connectDevice: (serial: string, label?: string) =>
    request<AdbDevice>("/api/v1/devices", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ serial, label: label || null, connect: true }),
    }),
  drainDevice: (serial: string) =>
    request<AdbDevice>(`/api/v1/devices/${encodeURIComponent(serial)}/drain`, { method: "POST" }),
  reconnectDevice: (serial: string) =>
    request<AdbDevice>(`/api/v1/devices/${encodeURIComponent(serial)}/reconnect`, { method: "POST" }),
  removeDevice: (serial: string) =>
    request<{ serial: string; deleted: true }>(`/api/v1/devices/${encodeURIComponent(serial)}`, { method: "DELETE" }),
  scans: () => request<Scan[]>("/api/v1/scans"),
  scan: (id: string, signal?: AbortSignal) =>
    request<Scan>(`/api/v1/scans/${id}`, { signal }),
  artifactGraph: (id: string, signal?: AbortSignal) =>
    cachedOptionalRequest<ArtifactGraph>(`/api/v1/scans/${id}/artifact-graph`, signal, 300_000),
  entries: (id: string, signal?: AbortSignal) =>
    cachedRequest<EntryPoint[]>(`/api/v1/scans/${id}/entries`, signal),
  securitySnapshot: (id: string, signal?: AbortSignal) =>
    cachedOptionalRequest<SecuritySnapshot>(`/api/v1/scans/${id}/security-snapshot`, signal),
  versionDiff: (id: string, signal?: AbortSignal) =>
    cachedOptionalRequest<VersionDiff>(`/api/v1/scans/${id}/version-diff`, signal),
  patternMatches: (id: string, signal?: AbortSignal) =>
    cachedRequest<PatternMatch[]>(`/api/v1/scans/${id}/pattern-matches`, signal, 10_000),
  findings: (id: string, signal?: AbortSignal) =>
    request<Finding[]>(`/api/v1/scans/${id}/findings`, { signal }),
  signals: (id: string, signal?: AbortSignal) =>
    request<Finding[]>(`/api/v1/scans/${id}/signals`, { signal }),
  coverage: (id: string, signal?: AbortSignal) =>
    request<CoverageItem[]>(`/api/v1/scans/${id}/coverage`, { signal }),
  tasks: (id: string, signal?: AbortSignal) =>
    request<InvestigationTask[]>(`/api/v1/scans/${id}/tasks`, { signal }),
  hypotheses: (id: string, signal?: AbortSignal) =>
    request<SecurityHypothesis[]>(`/api/v1/scans/${id}/hypotheses`, { signal }),
  evaluations: (id: string, signal?: AbortSignal) =>
    request<BenchmarkEvaluation[]>(`/api/v1/scans/${id}/evaluations`, { signal }),
  evaluateGroundTruth: (id: string, spec: unknown) =>
    request<BenchmarkEvaluation>(`/api/v1/scans/${id}/evaluations`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(spec),
    }),
  agentAudits: (id: string, signal?: AbortSignal, includeArtifacts = false, auditId?: string) => {
    const query = new URLSearchParams({
      include_artifacts: includeArtifacts ? "true" : "false",
    })
    if (auditId) query.set("audit_id", auditId)
    return request<AgentAudit[]>(`/api/v1/scans/${id}/agent-audits?${query}`, { signal })
  },
  events: (id: string, signal?: AbortSignal, after = 0, limit = 300, detail: "summary" | "full" = "full") =>
    request<ScanEvent[]>(`/api/v1/scans/${id}/events?detail=${detail}&after=${after}&limit=${limit}`, { signal }),
  invalidateScanCache,
  upload: async (file: File, investigator: InvestigatorChoice = "configured", baselineScanId?: string) => {
    const form = new FormData()
    form.append("apk", file)
    form.append("investigator", investigator)
    if (baselineScanId) form.append("baseline_scan_id", baselineScanId)
    return request<Scan>("/api/v1/scans", { method: "POST", body: form })
  },
  review: (findingId: string, status: "accepted" | "false_positive" | "candidate", note: string) =>
    request<Finding>(`/api/v1/findings/${findingId}/review`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, note }),
    }),
  retryTask: (taskId: string) =>
    request<InvestigationTask>(`/api/v1/tasks/${taskId}/rerun`, { method: "POST" }),
  reanalyzeTask: (taskId: string, contextMode: "continue" | "independent") =>
    request<InvestigationTask>(`/api/v1/tasks/${taskId}/reanalyses`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ context_mode: contextMode }),
    }),
  continueTask: (taskId: string) =>
    request<InvestigationTask>(`/api/v1/tasks/${taskId}/continue`, { method: "POST" }),
  updateScanAgentControl: (scanId: string, enabled: boolean, backend: "codex" | "none") =>
    request<Scan>(`/api/v1/scans/${scanId}/agent-control`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled, backend }),
    }),
  updateScanExecutionControl: (scanId: string, action: "pause" | "resume" | "stop") =>
    request<Scan>(`/api/v1/scans/${scanId}/execution-control`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action }),
    }),
  updateTaskAgentControl: (taskId: string, enabled: boolean) =>
    request<InvestigationTask>(`/api/v1/tasks/${taskId}/agent-control`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled }),
    }),
  rerunIncomplete: (scanId: string) =>
    request<ScanRerunResult>(`/api/v1/scans/${scanId}/rerun-incomplete`, { method: "POST" }),
  freshRun: (scanId: string) =>
    request<Scan>(`/api/v1/scans/${scanId}/fresh-run`, { method: "POST" }),
  cancelTask: (taskId: string) =>
    request<InvestigationTask>(`/api/v1/tasks/${taskId}/cancel`, { method: "POST" }),
  deleteTask: (taskId: string) =>
    request<TaskDeleteResult>(`/api/v1/tasks/${taskId}`, { method: "DELETE" }),
  deleteScan: (scanId: string) =>
    request<ScanDeleteResult>(`/api/v1/scans/${scanId}`, { method: "DELETE" }),
  operatorSessions: () => request<OperatorSession[]>("/api/v1/operator/sessions"),
  operatorSession: (sessionId: string) =>
    request<OperatorSession>(`/api/v1/operator/sessions/${sessionId}`),
  createOperatorSession: (payload: {
    instruction: string
    title?: string
    scan_id?: string
    finding_ids?: string[]
    device_mode?: "auto" | "none" | "required"
  }) => request<OperatorSession>("/api/v1/operator/sessions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  }),
  continueOperatorSession: (
    sessionId: string,
    instruction: string,
    deviceMode: "auto" | "none" | "required" = "auto",
  ) => request<OperatorSession>(`/api/v1/operator/sessions/${sessionId}/turns`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ instruction, device_mode: deviceMode }),
  }),
  cancelOperatorSession: (sessionId: string) =>
    request<{ session_id: string; cancel_requested: boolean }>(`/api/v1/operator/sessions/${sessionId}/cancel`, { method: "POST" }),
  operatorArtifacts: (query: { scanId?: string; findingId?: string; sessionId?: string } = {}) => {
    const params = new URLSearchParams()
    if (query.scanId) params.set("scan_id", query.scanId)
    if (query.findingId) params.set("finding_id", query.findingId)
    if (query.sessionId) params.set("operator_session_id", query.sessionId)
    return request<IndexedArtifact[]>(`/api/v1/operator/artifacts?${params}`)
  },
}
