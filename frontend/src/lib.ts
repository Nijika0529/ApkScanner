import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function parseTimestamp(value: string) {
  // Platform timestamps are UTC. SQLite/Pydantic may serialize them without an
  // explicit offset, which `new Date` would otherwise read as local time and
  // display the raw UTC clock value.
  const hasOffset = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(value)
  return new Date(hasOffset ? value : `${value}Z`)
}

export function formatDate(value: string | null | undefined) {
  if (!value) return "—"
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(parseTimestamp(value))
}

export function shortHash(value: string) {
  return `${value.slice(0, 10)}…${value.slice(-6)}`
}

export function statusLabel(status: string) {
  const labels: Record<string, string> = {
    queued: "等待中",
    static_running: "静态扫描",
    investigating: "入口探索",
    running: "调用中",
    idle: "等待命令",
    canceling: "正在停止",
    interrupted: "已中断",
    cancel_requested: "正在停止",
    canceled: "已停止",
    cancelled: "已中止",
    preliminary_ready: "阶段报告",
    final: "已完成",
    failed: "失败",
    blocked_device: "设备阻塞",
    completed: "已完成",
    inconclusive: "证据不足",
    timed_out: "预算耗尽",
    not_reproduced: "未复现",
    candidate: "待确认",
    supported_static: "静态支持",
    static_path_supported: "完整静态链",
    runtime_observed_unverified: "运行已观察·待核验",
    oracle_gap: "Oracle 缺口",
    refuted_static: "静态反驳",
    reproduced_blackbox: "黑盒复现",
    accepted: "已接受",
    false_positive: "误报",
    challenged: "反方质疑",
    accepted_for_proof: "等待证明",
    proof_planned: "证明已规划",
    executing: "正在证明",
    proven: "危害已证明",
    refuted: "已反驳",
    confirmed: "已确认",
    pending: "待验证",
    covered: "已覆盖",
    partial: "部分覆盖",
    not_applicable: "不适用",
    not_tested: "未测试",
    tool_failed: "工具失败",
    degraded: "降级覆盖",
  }
  return labels[status] ?? status
}

export function statusTone(
  status: string,
): "neutral" | "good" | "warning" | "danger" | "info" {
  if (
    ["final", "completed", "covered", "accepted", "reproduced_blackbox", "proven"].includes(
      status,
    )
  )
    return "good"
  if (["failed", "critical", "high", "tool_failed"].includes(status)) return "danger"
  if (
    [
      "inconclusive",
      "timed_out",
      "blocked_device",
      "partial",
      "degraded",
      "preliminary_ready",
      "cancel_requested",
      "challenged",
      "supported_static",
      "static_path_supported",
    ].includes(status)
  )
    return "warning"
  if (
    [
      "investigating",
      "static_running",
      "running",
      "queued",
      "accepted_for_proof",
      "proof_planned",
      "executing",
      "runtime_observed_unverified",
      "oracle_gap",
    ].includes(status)
  )
    return "info"
  return "neutral"
}

export function isAbortError(reason: unknown) {
  return reason instanceof DOMException && reason.name === "AbortError"
}

export function textValue(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined
}

export function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined
}

export function booleanValue(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined
}

export function recordValue(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined
}
