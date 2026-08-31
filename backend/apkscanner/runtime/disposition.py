"""Per-entry disposition resolver — assigns a mandatory state to every entry point.

Runs after scan completion to replace ad-hoc "was it investigated?" ambiguity
with a deterministic 10-state disposition model.
"""

from __future__ import annotations

from typing import Any

from ..core.enums import EntryDisposition

_SIGNATURE_PERMISSIONS = frozenset({"signature", "signatureOrSystem"})


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
        for eid in task.get("entry_point_ids", []) or []:
            tasks_by_entry.setdefault(eid, []).append(task)

    findings_by_entry: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        for eid in finding.get("entry_point_ids", []) or []:
            findings_by_entry.setdefault(eid, []).append(finding)

    chain_by_entry: dict[str, list[dict[str, Any]]] = {}
    for chain in attack_chains:
        for cls in _chain_classes(chain):
            # Match chain class to entry owner component
            for entry in entries:
                owner = entry.get("owner_component") or entry.get("name", "")
                if owner and cls.endswith(owner.split(".")[-1]):
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
    exported = entry.get("exported", False)
    permission = entry.get("permission") or ""
    protection = (entry.get("permission_protection") or "").lower()

    # 1. Not exported → statically unreachable from external apps
    if not exported and entry.get("kind") != "deep_link":
        return EntryDisposition.STATICALLY_UNREACHABLE.value

    # 2. Signature-level permission → permission protected
    if protection in _SIGNATURE_PERMISSIONS:
        return EntryDisposition.PERMISSION_PROTECTED.value

    # 3. No tasks at all → uninvestigated
    if not tasks:
        return EntryDisposition.UNINVESTIGATED.value

    # 4. Check dynamic results
    has_reproduced = any(
        f.get("status") == "reproduced_blackbox" for f in findings
    )
    has_refuted = any(
        f.get("status") in {"refuted_static", "not_reproduced"} for f in findings
    )
    has_dynamic_attempt = any(
        t.get("status") in {"not_reproduced", "inconclusive"}
        for t in tasks
        if t.get("task_type") not in {"static_review", "adaptive_verification"}
    )

    if has_reproduced:
        return EntryDisposition.REPRODUCED_BLACKBOX.value

    if has_refuted:
        return EntryDisposition.DYNAMICALLY_REFUTED.value

    if has_dynamic_attempt:
        return EntryDisposition.DYNAMICALLY_NOT_REPRODUCED.value

    # 5. Caller identity check detected → identity protected
    if _has_caller_identity_guard(tasks, chains):
        return EntryDisposition.CALLER_IDENTITY_PROTECTED.value

    # 6. Has attack chain → candidate
    if chains:
        return EntryDisposition.ATTACK_CHAIN_CANDIDATE.value

    # 7. Has static findings → statically supported
    if findings:
        return EntryDisposition.STATICALLY_SUPPORTED.value

    # 8. Normal permission → permission protected
    if permission and "normal" not in protection:
        return EntryDisposition.PERMISSION_PROTECTED.value

    # 9. No device or codex → capability gap
    if not device_available or not codex_enabled:
        return EntryDisposition.CAPABILITY_GAP.value

    return EntryDisposition.UNINVESTIGATED.value


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
        return 1.0
    resolved = sum(
        1 for d in dispositions.values() if d != EntryDisposition.UNINVESTIGATED.value
    )
    return resolved / total