export function taskTypeLabel(taskType: string) {
  return {
    deep_link: "Deep Link handler 探索",
    static_review: "静态语义审计",
    adaptive_verification: "高权限批量验证",
    operator: "平台 Agent 操作",
  }[taskType] ?? "导出组件探索"
}

export function isTerminalTask(status: string) {
  return !["queued", "awaiting_device", "running", "cancel_requested"].includes(status)
}
