from __future__ import annotations

from collections import defaultdict
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .artifacts import ArtifactStore
from .models import Evidence

AGENT_AUDIT_KINDS = {
    "agent.request",
    "agent.response",
    "agent.events",
    "agent.error",
    "agent.test_validation",
    "agent.validation",
}


def build_agent_audits(
    session: Session,
    store: ArtifactStore,
    scan_id: str,
) -> list[dict[str, Any]]:
    evidence = list(
        session.scalars(
            select(Evidence)
            .where(
                Evidence.scan_id == scan_id,
                Evidence.kind.in_(AGENT_AUDIT_KINDS),
            )
            .order_by(Evidence.created_at, Evidence.id)
        )
    )
    grouped: dict[str, list[Evidence]] = defaultdict(list)
    for item in evidence:
        audit_id = item.metadata_json.get("audit_id")
        if isinstance(audit_id, str):
            grouped[audit_id].append(item)

    audits = [_build_audit(store, audit_id, items) for audit_id, items in grouped.items()]
    return sorted(audits, key=lambda item: (item["started_at"], item["id"]))


def _build_audit(
    store: ArtifactStore,
    audit_id: str,
    evidence: list[Evidence],
) -> dict[str, Any]:
    first = evidence[0]
    metadata = first.metadata_json
    artifacts: dict[str, dict[str, Any]] = {}
    integrity_errors: list[str] = []
    for item in evidence:
        label = item.kind.removeprefix("agent.")
        try:
            content = store.read_json_artifact("evidence", item.path, item.sha256)
        except (OSError, ValueError, TypeError) as exc:
            content = None
            integrity_errors.append(f"{item.id}: {exc}")
        artifacts[label] = {
            "evidence_id": item.id,
            "sha256": item.sha256,
            "content": content,
            "created_at": item.created_at.isoformat(),
        }

    request = artifacts.get("request", {}).get("content")
    request_object = request if isinstance(request, dict) else {}
    response = artifacts.get("response", {}).get("content")
    status = (
        "failed"
        if "error" in artifacts
        else "completed"
        if "response" in artifacts
        else "running"
    )
    terminal = next(
        (
            item.created_at
            for item in reversed(evidence)
            if item.kind in {"agent.response", "agent.error", "agent.validation"}
        ),
        None,
    )
    response_object = response if isinstance(response, dict) else {}
    return {
        "id": audit_id,
        "scan_id": first.scan_id,
        # A completed task may be removed from the operational queue. Its
        # immutable request artifact still carries the original task ID.
        "task_id": first.task_id or request_object.get("task_id"),
        "attempt": int(metadata.get("attempt", 0)),
        "phase": str(metadata.get("phase", "unknown")),
        "backend": str(metadata.get("backend", "unknown")),
        "provider": str(metadata.get("provider", "unknown")),
        "model": str(metadata.get("model", "unknown")),
        "isolation": str(metadata.get("isolation", "unknown")),
        "status": status,
        "thread_id": response_object.get("thread_id"),
        "turn_id": response_object.get("turn_id"),
        "usage": response_object.get("usage") or {},
        "artifacts": artifacts,
        "integrity": "failed" if integrity_errors else "verified",
        "integrity_errors": integrity_errors,
        "started_at": first.created_at.isoformat(),
        "completed_at": terminal.isoformat() if terminal else None,
    }
