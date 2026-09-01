"""Per-entry disposition resolver — assigns a mandatory state to every entry point.

Runs after scan completion to replace ad-hoc "was it investigated?" ambiguity
with a deterministic 11-state disposition model.
"""

from __future__ import annotations

import re
from typing import Any

from ..core.enums import EntryDisposition

_SIGNATURE_PERMISSIONS = frozenset({"signature", "signatureorsystem"})
_DYNAMIC_TASK_TYPES = frozenset({"component", "deep_link"})
_CAPABILITY_FAILURE_STATUSES = frozenset(
    {"awaiting_device", "blocked_device", "timed_out", "failed", "canceled"}
)


def resolve_entry_dispositions(
    entries: list[dict[str, Any]],
    tasks: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    attack_chains: list[dict[str, Any]],
    *,
    codex_enabled: bool = False,
    device_available: bool = False,
) -> dict[str, str]:
    """Resolve a disposition for every entry point.

    Returns a dict mapping ``entry_id → disposition``.
    """
    # Build lookup indices
    tasks_by_entry: dict[str, list[dict[str, Any]]] = {}
    for task in tasks:
        if task.get("status") == "deleted":
            continue
        entry_ids = task.get("target_entry_ids")
        if entry_ids is None:
            # Compatibility for callers using the pre-persistence DTO name.
            entry_ids = task.get("entry_point_ids", [])
        for eid in entry_ids or []:
            tasks_by_entry.setdefault(eid, []).append(task)

    findings_by_entry: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        if finding.get("active", True) is not True:
            continue
        for eid in finding.get("entry_point_ids", []) or []:
            findings_by_entry.setdefault(eid, []).append(finding)

    chain_by_entry: dict[str, list[dict[str, Any]]] = {}
    for chain in attack_chains:
        explicitly_linked = set(chain.get("entry_point_ids", []) or [])
        for eid in explicitly_linked:
            chain_by_entry.setdefault(eid, []).append(chain)
        for cls in _chain_classes(chain):
            # Match chain class to entry owner component
            for entry in entries:
                if entry["id"] in explicitly_linked:
                    continue
                owner = entry.get("owner_component") or entry.get("name", "")
                if owner and _class_matches_owner(cls, owner):
                    chain_by_entry.setdefault(entry["id"], []).append(chain)

    dispositions: dict[str, str] = {}

    for entry in entries:
        eid = entry["id"]
        entry_tasks = tasks_by_entry.get(eid, [])
        entry_findings = findings_by_entry.get(eid, [])
        entry_chains = chain_by_entry.get(eid, [])

        dispositions[eid] = _resolve_one(
            entry,
            entry_tasks,
            entry_findings,
            entry_chains,
            codex_enabled=codex_enabled,
            device_available=device_available,
        )

    return dispositions


def _resolve_one(
    entry: dict[str, Any],
    tasks: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    *,
    codex_enabled: bool,
    device_available: bool,
) -> str:
    tasks = _latest_tasks_by_type(tasks)
    selected_task_ids = {str(task["id"]) for task in tasks if isinstance(task.get("id"), str)}
    findings = [
        finding
        for finding in findings
        if finding.get("proof_backed") is True
        or not isinstance(finding.get("task_id"), str)
        or finding.get("task_id") in selected_task_ids
    ]
    chains = [
        chain
        for chain in chains
        if not isinstance(chain.get("task_id"), str) or chain.get("task_id") in selected_task_ids
    ]
    metadata = entry.get("metadata_json") or {}

    # A successful ordinary-app proof is authoritative even if the static
    # manifest model is incomplete or an OEM changed the runtime surface.
    if any(
        finding.get("status") in {"accepted", "reproduced_blackbox"}
        and finding.get("proof_backed") is True
        for finding in findings
    ):
        return EntryDisposition.REPRODUCED_BLACKBOX.value

    # An entry can carry several independent hypotheses. Keep an open runtime/static
    # signal visible even when a different hypothesis has a negative receipt.
    if any(
        finding.get("status") in {"runtime_observed_unverified", "oracle_gap"}
        or finding.get("signal_tier") == "runtime_oracle_gap"
        for finding in findings
    ):
        return EntryDisposition.RUNTIME_OBSERVED_UNVERIFIED.value

    if any(finding.get("signal_tier") == "static_chain" for finding in findings):
        return EntryDisposition.STATICALLY_SUPPORTED.value

    # Current negative outcomes outrank weaker raw candidates, but historical
    # tasks from an independent reanalysis have already been discarded above.
    has_refuted = any(f.get("status") == "not_reproduced" for f in findings)
    has_dynamic_attempt = any(
        t.get("status") == "not_reproduced"
        for t in tasks
        if t.get("task_type") in _DYNAMIC_TASK_TYPES
    )

    if has_refuted:
        return EntryDisposition.DYNAMICALLY_REFUTED.value

    if has_dynamic_attempt:
        return EntryDisposition.DYNAMICALLY_NOT_REPRODUCED.value

    # Indirect scan-wide paths remain security candidates even when the entry's
    # ordinary-app direct invocation is statically blocked.
    if _has_caller_identity_guard(tasks, chains):
        return EntryDisposition.CALLER_IDENTITY_PROTECTED.value
    if chains:
        return EntryDisposition.ATTACK_CHAIN_CANDIDATE.value

    # Production callers attach the planner's direct-invocation closure so this
    # resolver does not independently guess framework/OEM permission strength.
    if entry.get("static_closure_evaluated") is True:
        closure = entry.get("static_closure")
        if isinstance(closure, dict):
            if closure.get("reason_code") in {"component_disabled", "not_exported"}:
                return EntryDisposition.STATICALLY_UNREACHABLE.value
            if closure.get("reason_code") == "strong_permission_guard":
                return EntryDisposition.PERMISSION_PROTECTED.value
    else:
        # Compatibility for standalone callers that predate planner closure
        # handoff. Production always takes the evaluated branch above.
        protection = (entry.get("permission_protection") or "").lower()
        protection_tokens = {token for token in re.split(r"[|,\s]+", protection) if token}
        if metadata.get("effective_enabled") is False:
            return EntryDisposition.STATICALLY_UNREACHABLE.value
        if not entry.get("exported", False) and entry.get("kind") != "static_surface":
            return EntryDisposition.STATICALLY_UNREACHABLE.value
        if protection_tokens & _SIGNATURE_PERMISSIONS:
            return EntryDisposition.PERMISSION_PROTECTED.value

    if not tasks:
        return EntryDisposition.UNINVESTIGATED.value

    # A missing capability and an attempted-but-blocked run are both explicit
    # coverage gaps; neither should be reported as a negative verdict.
    latest_task = max(tasks, key=_task_order_key)
    latest_agent_enabled = latest_task.get("agent_enabled", codex_enabled)
    if (
        not device_available
        or latest_agent_enabled is not True
        or latest_task.get("capability_gap") is True
        or latest_task.get("status") in _CAPABILITY_FAILURE_STATUSES
    ):
        return EntryDisposition.CAPABILITY_GAP.value

    return EntryDisposition.UNINVESTIGATED.value


def _latest_tasks_by_type(tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for task in tasks:
        task_type = str(task.get("task_type") or "unknown")
        current = latest.get(task_type)
        if current is None or _task_order_key(task) > _task_order_key(current):
            latest[task_type] = task
    return list(latest.values())


def _task_order_key(task: dict[str, Any]) -> tuple[float, int, str]:
    recency = task.get("recency")
    return (
        float(recency) if isinstance(recency, (int, float)) else 0.0,
        int(task.get("attempts") or 0),
        str(task.get("id") or ""),
    )


def _has_caller_identity_guard(
    tasks: list[dict[str, Any]],
    chains: list[dict[str, Any]],
) -> bool:
    """Check if any task or chain indicates caller identity verification."""
    for chain in chains:
        guards = chain.get("guard_markers", []) or chain.get("guards", [])
        if "binder_caller_identity_guard" in guards:
            return True
    return False


def _chain_classes(chain: dict[str, Any]) -> list[str]:
    """Extract class names from chain path entries."""
    path_entries = chain.get("path") or []
    return [
        entry["class_name"]
        for entry in path_entries
        if isinstance(entry, dict) and entry.get("class_name")
    ]


def _class_matches_owner(class_name: str, owner_component: str) -> bool:
    """Match exact component classes without suffix collisions.

    Android component names may be fully qualified, package-relative, or use
    ``package/.Class`` notation.  Nested implementation classes remain linked
    to their owner, while ``NotMainActivity`` must not match ``MainActivity``.
    """
    if "/" in owner_component:
        package_name, declared_class = owner_component.split("/", 1)
        owner = (
            f"{package_name}{declared_class}" if declared_class.startswith(".") else declared_class
        )
    else:
        owner = owner_component
    class_simple = class_name.rsplit(".", 1)[-1]
    owner_simple = owner.rsplit(".", 1)[-1].lstrip(".")
    if not owner_simple:
        return False
    if not owner.startswith(".") and "." in owner and "." in class_name:
        return class_name == owner or class_name.startswith(f"{owner}$")
    if class_simple == owner_simple or class_simple.startswith(f"{owner_simple}$"):
        return True
    return class_name == owner or class_name.startswith(f"{owner}$")


def disposition_summary(dispositions: dict[str, str]) -> dict[str, int]:
    """Count dispositions by type for coverage metrics."""
    counts: dict[str, int] = {}
    for disp in dispositions.values():
        counts[disp] = counts.get(disp, 0) + 1
    return counts


def disposition_coverage_rate(dispositions: dict[str, str]) -> float:
    """Fraction of entries with a disposition beyond 'uninvestigated'."""
    total = len(dispositions)
    if total == 0:
        return 0.0
    resolved = sum(1 for d in dispositions.values() if d != EntryDisposition.UNINVESTIGATED.value)
    return resolved / total
