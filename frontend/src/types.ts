export type ScanStatus =
  | "queued"
  | "intake"
  | "static_running"
  | "static_complete"
  | "investigating"
  | "preliminary_ready"
  | "final"
  | "failed"

export interface Scan {
  id: string
  schema_version: string
  status: ScanStatus
  filename: string
  artifact_sha256: string
  package_name: string | null
  version_name: string | null
  version_code: string | null
  min_sdk: number | null
  target_sdk: number | null
  stats: Record<string, unknown>
  signing?: Record<string, unknown>
  tool_versions?: Record<string, unknown>
  error: string | null
  preliminary_at: string | null
  completed_at: string | null
  created_at: string
  updated_at: string
}

export interface EntryPoint {
  id: string
  kind: string
  name: string
  owner_component: string | null
  exported: boolean
  exported_reason: string
  permission: string | null
  permission_protection: string | null
  intent_filters: Array<Record<string, unknown>>
  deep_links: Array<Record<string, unknown>>
  code_anchors: Array<Record<string, unknown>>
  metadata_json: Record<string, unknown>
}

export interface Finding {
  id: string
  rule_id: string
  source: string
  title: string
  description: string
  remediation: string
  masvs: string
  cwe: string | null
  severity: "critical" | "high" | "medium" | "low" | "info"
  confidence: "high" | "medium" | "low"
  status: string
  entry_point_ids: string[]
  locations: Array<Record<string, unknown>>
  evidence_ids: string[]
  metadata_json: Record<string, unknown>
  review_note: string | null
  created_at: string
  updated_at: string
}

export interface CoverageItem {
  id: string
  control_id: string
  domain: string
  title: string
  status: string
  stages: Record<string, string | number>
  gap_reason: string | null
  entry_point_id: string | null
}

export interface InvestigationTask {
  id: string
  task_type: string
  status: string
  priority: number
  target_entry_ids: string[]
  hypotheses: string[]
  preconditions: Record<string, unknown>
  allowed_side_effects: string[]
  device_profile: Record<string, unknown>
  result: Record<string, unknown>
  thread_id: string | null
  turn_id: string | null
  attempts: number
  error: string | null
  started_at: string | null
  completed_at: string | null
  created_at: string
}

export interface ScanEvent {
  id: number
  event_type: string
  message: string
  data: Record<string, unknown>
  created_at: string
}

export interface AgentAuditArtifact {
  evidence_id: string
  sha256: string
  content: unknown
  created_at: string
}

export interface AgentAudit {
  id: string
  scan_id: string
  task_id: string | null
  attempt: number
  phase: string
  backend: string
  provider: string
  model: string
  isolation: string
  status: "running" | "completed" | "failed"
  thread_id: string | null
  turn_id: string | null
  usage: Record<string, unknown>
  artifacts: Record<string, AgentAuditArtifact>
  integrity: "verified" | "failed"
  integrity_errors: string[]
  started_at: string
  completed_at: string | null
}

export interface ScanDeleteResult {
  id: string
  deleted: true
  files_removed: number
  cleanup_warnings: string[]
}

export interface Capability {
  name: string
  available: boolean
  version: string | null
  detail: string | null
}

export interface Health {
  status: "ok"
  version: string
  default_investigator: "codex" | "opencode" | "none"
  enabled_investigators: Array<"codex" | "opencode">
  capabilities: Capability[]
}

export type InvestigatorChoice = "configured" | "codex" | "opencode" | "none"
