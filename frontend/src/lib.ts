import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(value: string | null | undefined) {
  if (!value) return "—"
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value))
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
    reproduced_blackbox: "黑盒复现",
    observed_instrumented: "插桩观测",
    accepted: "已接受",
    false_positive: "误报",
    challenged: "反方质疑",
    accepted_for_proof: "等待证明",
    proof_planned: "证明已规划",
    executing: "正在证明",
    proven: "危害已证明",
    refuted: "已反驳",
    covered: "已覆盖",
    partial: "部分覆盖",
    not_tested: "未测试",
    tool_failed: "工具失败",
    degraded: "降级覆盖",
  }
  return labels[status] ?? status
}
