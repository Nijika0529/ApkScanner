from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..core.models import (
    AgentTurnRecord,
    DynamicExperimentCapsule,
    EntryPoint,
    Evidence,
    Finding,
    InvestigationTask,
    ProofAttempt,
    ScanEvent,
    SecurityHypothesis,
)

_DYNAMIC_EVIDENCE_PREFIXES = ("blackbox.", "dynamic_experiment.")


def build_scan_quality_summary(session: Session, scan_id: str) -> dict[str, Any]:
    """Build a cheap, evidence-backed scan funnel without reading artifact bodies."""

    entry_count = int(
        session.scalar(
            select(func.count(EntryPoint.id)).where(EntryPoint.scan_id == scan_id)
        )
        or 0
    )
    tasks = list(
        session.scalars(
            select(InvestigationTask).where(
                InvestigationTask.scan_id == scan_id,
                InvestigationTask.status != "deleted",
            )
        )
    )
    hypotheses = list(
        session.scalars(
            select(SecurityHypothesis).where(SecurityHypothesis.scan_id == scan_id)
        )
    )
    attempts = list(
        session.scalars(select(ProofAttempt).where(ProofAttempt.scan_id == scan_id))
    )
    findings = list(
        session.execute(
            select(Finding.id, Finding.status).where(Finding.scan_id == scan_id)
        )
    )
    evidence = list(
        session.execute(
            select(Evidence.id, Evidence.kind).where(
                Evidence.scan_id == scan_id,
                or_(
                    Evidence.kind.like("blackbox.%"),
                    Evidence.kind.like("dynamic_experiment.%"),
                    Evidence.kind == "poc.build_artifact",
                ),
            )
        )
    )
    turns = list(
        session.execute(
            select(
                AgentTurnRecord.phase,
                AgentTurnRecord.status,
                AgentTurnRecord.usage_json,
                AgentTurnRecord.started_at,
                AgentTurnRecord.completed_at,
            ).where(AgentTurnRecord.scan_id == scan_id)
        )
    )
    events = list(
        session.execute(
            select(ScanEvent.event_type, ScanEvent.data, ScanEvent.created_at).where(
                ScanEvent.scan_id == scan_id,
                or_(
                    ScanEvent.event_type.in_(
                        ("task.device_acquired", "task.device_released")
                    ),
                    ScanEvent.event_type.like("%.failed"),
                ),
            )
        )
    )
    experiments = list(
        session.execute(
            select(
                DynamicExperimentCapsule.task_id,
                DynamicExperimentCapsule.result_json,
                DynamicExperimentCapsule.error,
            ).where(
                DynamicExperimentCapsule.scan_id == scan_id,
            )
        )
    )

    evidence_by_id = {item.id: item.kind for item in evidence}
    attempts_by_hypothesis: dict[str, list[ProofAttempt]] = defaultdict(list)
    for attempt in attempts:
        attempts_by_hypothesis[attempt.hypothesis_id].append(attempt)

    finding_by_id = {item.id: item.status for item in findings}
    statically_supported = {
        item.id
        for item in hypotheses
        if item.support_evidence_ids
        or (
            item.final_finding_id
            and finding_by_id.get(item.final_finding_id) is not None
            and finding_by_id[item.final_finding_id]
            in {"supported_static", "reproduced_blackbox", "accepted"}
        )
    }
    proof_planned = set(attempts_by_hypothesis)
    device_executed = {
        attempt.hypothesis_id
        for attempt in attempts
        if any(
            (kind := evidence_by_id.get(evidence_id)) is not None
            and kind.startswith(_DYNAMIC_EVIDENCE_PREFIXES)
            for evidence_id in attempt.evidence_ids
        )
    }
    harm_proven = {
        attempt.hypothesis_id for attempt in attempts if attempt.harm_demonstrated
    }
    reproduced_findings = {
        item.id for item in findings if item.status == "reproduced_blackbox"
    }

    funnel = [
        _stage("entry_points", "攻击入口", entry_count),
        _stage("investigation_tasks", "探索任务", len(tasks)),
        _stage("hypotheses", "安全假设", len(hypotheses)),
        _stage("static_supported", "静态支持", len(statically_supported)),
        _stage("proof_planned", "已规划 Proof", len(proof_planned)),
        _stage("device_executed", "真机已执行", len(device_executed)),
        _stage("harm_proven", "危害已证明", len(harm_proven)),
        _stage("reproduced_findings", "动态 Finding", len(reproduced_findings)),
    ]

    phase_usage: dict[str, dict[str, float | int]] = defaultdict(
        lambda: {
            "calls": 0,
            "input_tokens": 0,
            "cached_input_tokens": 0,
            "output_tokens": 0,
            "duration_seconds": 0.0,
        }
    )
    for turn in turns:
        usage = _usage_values(turn.usage_json or {})
        phase = turn.phase or "unknown"
        bucket = phase_usage[phase]
        bucket["calls"] += 1
        for key in ("input_tokens", "cached_input_tokens", "output_tokens"):
            bucket[key] += usage[key]
        bucket["duration_seconds"] += _duration_seconds(turn.started_at, turn.completed_at)

    input_tokens = sum(int(item["input_tokens"]) for item in phase_usage.values())
    cached_input_tokens = sum(
        int(item["cached_input_tokens"]) for item in phase_usage.values()
    )
    output_tokens = sum(int(item["output_tokens"]) for item in phase_usage.values())
    device_wait_seconds = 0.0
    device_held_seconds = 0.0
    device_lease_count = 0
    for event in events:
        if event.event_type == "task.device_acquired":
            device_wait_seconds += _as_float((event.data or {}).get("wait_seconds"))
        elif event.event_type == "task.device_released":
            device_lease_count += 1
            device_held_seconds += _as_float((event.data or {}).get("held_seconds"))
    # Standalone/manual Capsules own a lease outside task.device_* events.
    for experiment in experiments:
        if experiment.task_id is not None:
            continue
        result = experiment.result_json or {}
        if result.get("device_held_seconds") is not None:
            device_lease_count += 1
        device_wait_seconds += _as_float(result.get("device_wait_seconds"))
        device_held_seconds += _as_float(result.get("device_held_seconds"))

    build_artifact_count = sum(item.kind == "poc.build_artifact" for item in evidence)
    merged_variants = sum(max(0, len(set(task.target_entry_ids or [])) - 1) for task in tasks)
    assigned_entry_variants = sum(len(set(task.target_entry_ids or [])) for task in tasks)

    failures = _failure_summary(tasks, attempts, experiments, events)
    proof_statuses = Counter(item.status for item in attempts)
    task_statuses = Counter(item.status for item in tasks)
    total_agent_seconds = sum(
        float(item["duration_seconds"]) for item in phase_usage.values()
    )

    latest_event_at = max(
        (item.created_at for item in events),
        key=lambda value: value.isoformat(),
        default=datetime.fromtimestamp(0, UTC),
    )

    return {
        "schema_version": "1.0",
        "scan_id": scan_id,
        # Keep unchanged snapshots byte-stable so event polling does not force a
        # React rerender merely because this endpoint was read again.
        "generated_at": latest_event_at.isoformat(),
        "funnel": funnel,
        "task_statuses": dict(sorted(task_statuses.items())),
        "proof_statuses": dict(sorted(proof_statuses.items())),
        "failure_reasons": failures,
        "cost": {
            "agent_calls": len(turns),
            "completed_agent_calls": sum(item.status == "completed" for item in turns),
            "input_tokens": input_tokens,
            "cached_input_tokens": cached_input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "agent_seconds": round(total_agent_seconds, 3),
            "device_lease_count": device_lease_count,
            "device_wait_seconds": round(device_wait_seconds, 3),
            "device_held_seconds": round(device_held_seconds, 3),
            "poc_builds": build_artifact_count,
            "dynamic_experiments": len(experiments),
        },
        "efficiency": {
            "static_to_proof_rate": _ratio(len(proof_planned), len(statically_supported)),
            "proof_to_device_rate": _ratio(len(device_executed), len(proof_planned)),
            "device_to_harm_rate": _ratio(len(harm_proven), len(device_executed)),
            "hypothesis_to_finding_rate": _ratio(
                len(reproduced_findings), len(hypotheses)
            ),
            "cached_input_rate": _ratio(cached_input_tokens, input_tokens),
            "merged_entry_variants": merged_variants,
            "assigned_entry_variants": assigned_entry_variants,
        },
        "phase_usage": [
            {
                "phase": phase,
                **{
                    key: round(value, 3) if isinstance(value, float) else value
                    for key, value in values.items()
                },
            }
            for phase, values in sorted(phase_usage.items())
        ],
    }


def _stage(key: str, label: str, count: int) -> dict[str, Any]:
    return {"key": key, "label": label, "count": count}


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(numerator / denominator, 4)


def _duration_seconds(started_at: datetime | None, completed_at: datetime | None) -> float:
    if started_at is None or completed_at is None:
        return 0.0
    try:
        return max(0.0, (completed_at - started_at).total_seconds())
    except TypeError:
        return 0.0


def _usage_values(usage: dict[str, Any]) -> dict[str, int]:
    input_tokens = _first_int(
        usage,
        ("input_tokens",),
        ("inputTokens",),
        ("prompt_tokens",),
        ("promptTokens",),
    )
    output_tokens = _first_int(
        usage,
        ("output_tokens",),
        ("outputTokens",),
        ("completion_tokens",),
        ("completionTokens",),
    )
    cached_input_tokens = _first_int(
        usage,
        ("cached_input_tokens",),
        ("cachedInputTokens",),
        ("input_tokens_details", "cached_tokens"),
        ("prompt_tokens_details", "cached_tokens"),
    )
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cached_input_tokens": min(input_tokens, cached_input_tokens),
    }


def _first_int(value: dict[str, Any], *paths: tuple[str, ...]) -> int:
    for path in paths:
        current: Any = value
        for key in path:
            if not isinstance(current, dict) or key not in current:
                current = None
                break
            current = current[key]
        if isinstance(current, (int, float)) and not isinstance(current, bool):
            return max(0, int(current))
    return 0


def _as_float(value: Any) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0.0, float(value))
    return 0.0


def _failure_summary(
    tasks: Iterable[InvestigationTask],
    attempts: Iterable[ProofAttempt],
    experiments: Iterable[DynamicExperimentCapsule],
    events: Iterable[ScanEvent],
) -> list[dict[str, Any]]:
    messages: list[str] = []
    for task in tasks:
        messages.extend(_object_failures(task.error, task.result or {}))
    for attempt in attempts:
        if attempt.error:
            messages.append(attempt.error)
        elif attempt.status == "inconclusive":
            messages.append("Proof completed without a satisfied or refuting Oracle")
    for experiment in experiments:
        if experiment.error:
            messages.append(experiment.error)
    for event in events:
        if not (
            event.event_type.endswith(".failed")
            or event.event_type in {"scan.failed", "task.failed"}
        ):
            continue
        error = (event.data or {}).get("error")
        if isinstance(error, str) and error.strip():
            messages.append(error)

    grouped: dict[str, list[str]] = defaultdict(list)
    seen: set[str] = set()
    for raw in messages:
        message = " ".join(str(raw).split())[:1000]
        normalized = message.lower()
        if not message or normalized in seen:
            continue
        seen.add(normalized)
        grouped[_classify_failure(normalized)].append(message)
    labels = {
        "schema_output": "模型结构化输出",
        "planning": "Proof 请求未被接受",
        "runtime_correlation": "运行期关联缺失",
        "provider": "模型服务调用",
        "poc_build": "PoC/Harness 构建",
        "install": "APK 安装",
        "launch_runtime": "启动或运行时",
        "device": "设备连接或租约",
        "oracle": "Oracle 未闭合",
        "timeout": "超时",
        "canceled": "人工停止",
        "other": "其他",
    }
    return [
        {
            "kind": kind,
            "label": labels[kind],
            "count": len(values),
            "examples": values[:3],
        }
        for kind, values in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0]))
    ]


def _object_failures(error: str | None, payload: Any) -> list[str]:
    values = [error] if error else []

    def visit(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                visit(child, str(child_key).lower())
        elif isinstance(value, list):
            for child in value:
                visit(child, key)
        elif isinstance(value, str) and any(
            marker in key for marker in ("error", "failure", "gap", "reason")
        ):
            values.append(value)

    visit(payload)
    return [value for value in values if isinstance(value, str) and value.strip()]


def _classify_failure(message: str) -> str:
    if "no_accepted_proof_request" in message:
        return "planning"
    if any(value in message for value in ("schema", "validation", "trailing json", "json-rpc")):
        return "schema_output"
    if any(
        value in message
        for value in (
            "poc_execution_receipt",
            "structured_result_missing",
            "request_observed=false",
            "durable_receipt",
        )
    ):
        return "runtime_correlation"
    # A timeout or Oracle error often includes a historical ADB command. Prefer
    # the actionable terminal cause over that incidental transport detail.
    if any(value in message for value in ("timeout", "timed out", "budget expired")):
        return "timeout"
    if any(value in message for value in ("oracle", "impact contract", "without a satisfied")):
        return "oracle"
    if any(value in message for value in ("provider", "responses api", "rate limit", "api key")):
        return "provider"
    if any(value in message for value in ("build", "compile", "d8", "aapt2", "apksigner")):
        return "poc_build"
    if any(value in message for value in ("install_failed", "install failed", "could not install")):
        return "install"
    if any(value in message for value in ("launch", "error type 3", "androidruntime", "dex verification")):
        return "launch_runtime"
    if any(value in message for value in ("device", "adb", "serial", "lease", "offline")):
        return "device"
    if any(value in message for value in ("cancel", "停止", "暂停")):
        return "canceled"
    return "other"
