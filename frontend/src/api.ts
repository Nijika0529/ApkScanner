import type {
  AgentAudit,
  BenchmarkEvaluation,
  CoverageItem,
  EntryPoint,
  Finding,
  Health,
  InvestigationTask,
  InvestigatorChoice,
  Scan,
  ScanDeleteResult,
  ScanRerunResult,
  ScanEvent,
  SecurityHypothesis,
  TaskDeleteResult,
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

export const api = {
  health: () => request<Health>("/api/v1/health"),
  scans: () => request<Scan[]>("/api/v1/scans"),
  scan: (id: string) => request<Scan>(`/api/v1/scans/${id}`),
  entries: (id: string) => request<EntryPoint[]>(`/api/v1/scans/${id}/entries`),
  findings: (id: string) => request<Finding[]>(`/api/v1/scans/${id}/findings`),
  coverage: (id: string) => request<CoverageItem[]>(`/api/v1/scans/${id}/coverage`),
  tasks: (id: string) => request<InvestigationTask[]>(`/api/v1/scans/${id}/tasks`),
  hypotheses: (id: string) =>
    request<SecurityHypothesis[]>(`/api/v1/scans/${id}/hypotheses`),
  evaluations: (id: string) =>
    request<BenchmarkEvaluation[]>(`/api/v1/scans/${id}/evaluations`),
  evaluateGroundTruth: (id: string, spec: unknown) =>
    request<BenchmarkEvaluation>(`/api/v1/scans/${id}/evaluations`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(spec),
    }),
  agentAudits: (id: string) => request<AgentAudit[]>(`/api/v1/scans/${id}/agent-audits`),
  events: (id: string) => request<ScanEvent[]>(`/api/v1/scans/${id}/events`),
  upload: async (file: File, investigator: InvestigatorChoice = "configured") => {
    const form = new FormData()
    form.append("apk", file)
    form.append("investigator", investigator)
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
  continueTask: (taskId: string) =>
    request<InvestigationTask>(`/api/v1/tasks/${taskId}/continue`, { method: "POST" }),
  updateScanAgentControl: (scanId: string, enabled: boolean, backend: "codex" | "opencode" | "none") =>
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
  cancelTask: (taskId: string) =>
    request<InvestigationTask>(`/api/v1/tasks/${taskId}/cancel`, { method: "POST" }),
  deleteTask: (taskId: string) =>
    request<TaskDeleteResult>(`/api/v1/tasks/${taskId}`, { method: "DELETE" }),
  deleteScan: (scanId: string) =>
    request<ScanDeleteResult>(`/api/v1/scans/${scanId}`, { method: "DELETE" }),
}
