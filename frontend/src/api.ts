import type {
  AgentAudit,
  CoverageItem,
  EntryPoint,
  Finding,
  Health,
  InvestigationTask,
  InvestigatorChoice,
  Scan,
  ScanDeleteResult,
  ScanEvent,
} from "./types"

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers)
  headers.set("X-APKScanner-Request", "console")
  const response = await fetch(path, { ...init, headers })
  if (!response.ok) {
    const detail = await response.json().catch(() => ({ detail: response.statusText }))
    throw new Error(detail.detail ?? `Request failed: ${response.status}`)
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
    request<InvestigationTask>(`/api/v1/tasks/${taskId}/retry`, { method: "POST" }),
  deleteScan: (scanId: string) =>
    request<ScanDeleteResult>(`/api/v1/scans/${scanId}`, { method: "DELETE" }),
}
