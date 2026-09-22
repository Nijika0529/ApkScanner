import { LoaderCircle, Plus, RefreshCw, Smartphone } from "lucide-react"
import { useCallback, useEffect, useState, type FormEvent } from "react"

import { api } from "../../api"
import { Badge, Button } from "../../components/ui"
import { statusLabel } from "../../lib"
import type { AdbDevice } from "../../types"

function sameJsonValue(left: unknown, right: unknown) {
  return left === right || JSON.stringify(left) === JSON.stringify(right)
}

export function DevicePoolPanel() {
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

  return <div>
    <div className="flex items-center gap-3"><div className="grid h-9 w-9 place-items-center rounded-lg bg-slate-100 text-cyan-700"><Smartphone className="h-4 w-4" /></div><div><h3 className="text-sm font-semibold text-slate-900">动态 ADB 设备池</h3><p className="text-xs text-slate-600">扫描运行中也可扩容；每台设备一次只归属一个任务</p></div></div>
    <form className="mt-3 grid gap-2 sm:grid-cols-[1fr_1fr_auto]" onSubmit={connect}><input className="field" value={serial} onChange={(event) => setSerial(event.target.value)} placeholder="serial 或 host:port" aria-label="ADB serial" /><input className="field" value={label} onChange={(event) => setLabel(event.target.value)} placeholder="备注（可选）" aria-label="设备备注" /><Button type="submit" size="sm" disabled={busy !== null || !serial.trim()}>{busy === "connect" ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}接入</Button></form>
    <div className="mt-3 space-y-2">{devices.map((device) => <div key={device.id} className="rounded-lg border border-slate-200 bg-slate-50 p-3"><div className="flex flex-wrap items-center justify-between gap-2"><div className="min-w-0"><p className="truncate font-mono text-xs font-semibold text-slate-800">{device.serial}</p><p className="mt-1 text-[11px] text-slate-500">{device.label ?? "未命名"} · Android {device.android_version ?? "?"} / API {device.api_level ?? "?"}</p></div><div className="flex flex-wrap gap-1"><Badge tone={device.busy ? "warning" : device.available ? "good" : device.state === "draining" ? "warning" : "neutral"}>{device.busy ? "任务占用" : device.state === "draining" ? "排空中" : device.available ? "可分配" : statusLabel(device.state)}</Badge>{device.release_gate_eligible ? <Badge tone="good">Android 16 正式裁决</Badge> : device.dynamic_verdict_eligible ? <Badge tone="warning">开发环境动态裁决</Badge> : <Badge tone="warning">仅兼容性冒烟</Badge>}</div></div><div className="mt-2 flex flex-wrap gap-1"><Button variant="ghost" size="sm" onClick={() => void operate(device, "drain")} disabled={busy !== null || device.state === "draining"}>排空</Button><Button variant="ghost" size="sm" onClick={() => void operate(device, "reconnect")} disabled={busy !== null || device.busy}>重连</Button><Button variant="danger" size="sm" onClick={() => void operate(device, "remove")} disabled={busy !== null || device.busy}>移除</Button></div>{device.last_error && <p className="mt-2 text-[11px] leading-4 text-rose-700">{device.last_error}</p>}</div>)}{!devices.length && <p className="rounded-lg border border-dashed border-slate-300 p-3 text-xs text-slate-500">当前没有设备。开发模式可接入低版本 Android 设备形成带环境范围的 Finding；正式发布门禁仍要求 Android 16 / API 36+。</p>}</div>
    <div className="mt-2 flex gap-2"><Button variant="ghost" size="sm" onClick={() => void refresh(true)} disabled={busy !== null}><RefreshCw className="h-3.5 w-3.5" />主动探测</Button><span className="self-center text-[11px] text-slate-500">排空会停止新租约，正在运行的任务完成后才可移除。</span></div>{error && <p role="alert" className="mt-2 text-xs text-rose-700">{error}</p>}
  </div>
}
