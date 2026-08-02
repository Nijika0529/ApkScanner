import type {
  AdbDevice,
  AgentAudit,
  BenchmarkEvaluation,
  CoverageItem,
  EntryPoint,
  Finding,
  Health,
  InvestigationTask,
  InvestigatorChoice,
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
  entries: (id: string, signal?: AbortSignal) =>
    request<EntryPoint[]>(`/api/v1/scans/${id}/entries`, { signal }),
  securitySnapshot: (id: string, signal?: AbortSignal) =>
    optionalRequest<SecuritySnapshot>(`/api/v1/scans/${id}/security-snapshot`, signal),
  versionDiff: (id: string, signal?: AbortSignal) =>
    optionalRequest<VersionDiff>(`/api/v1/scans/${id}/version-diff`, signal),
  patternMatches: (id: string, signal?: AbortSignal) =>
    request<PatternMatch[]>(`/api/v1/scans/${id}/pattern-matches`, { signal }),
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
  agentAudits: (id: string, signal?: AbortSignal) =>
    request<AgentAudit[]>(`/api/v1/scans/${id}/agent-audits`, { signal }),
  events: (id: string, signal?: AbortSignal) =>
    request<ScanEvent[]>(`/api/v1/scans/${id}/events`, { signal }),
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
}
