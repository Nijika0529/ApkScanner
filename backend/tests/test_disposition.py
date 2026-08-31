from apkscanner.runtime.disposition import (
    disposition_coverage_rate,
    disposition_summary,
    resolve_entry_dispositions,
)


def _entry(
    eid: str,
    name: str,
    *,
    exported: bool = True,
    kind: str = "activity",
    permission: str | None = None,
    protection: str | None = None,
    owner: str | None = None,
) -> dict:
    return {
        "id": eid,
        "name": name,
        "kind": kind,
        "exported": exported,
        "permission": permission,
        "permission_protection": protection,
        "owner_component": owner or name,
    }


def _task(
    tid: str,
    entry_ids: list[str],
    *,
    status: str = "completed",
    task_type: str = "component",
) -> dict:
    return {
        "id": tid,
        "entry_point_ids": entry_ids,
        "status": status,
        "task_type": task_type,
    }


def _finding(
    fid: str,
    entry_ids: list[str],
    *,
    status: str = "candidate",
) -> dict:
    return {"id": fid, "entry_point_ids": entry_ids, "status": status}


def _chain(
    classes: list[str],
    *,
    guard_markers: list[str] | None = None,
) -> dict:
    return {
        "path": [{"class_name": c} for c in classes],
        "guard_markers": guard_markers or [],
    }


# ── basic dispositions ────────────────────────────────────────────────


def test_unexported_entry_is_statically_unreachable() -> None:
    entries = [_entry("e1", "SecretActivity", exported=False)]
    result = resolve_entry_dispositions(entries, [], [], [])
    assert result["e1"] == "statically_unreachable"


def test_signature_permission_is_protected() -> None:
    entries = [_entry("e1", "AdminService", permission="vivo.permission.ADMIN", protection="signature")]
    result = resolve_entry_dispositions(entries, [], [], [])
    assert result["e1"] == "permission_protected"


def test_no_tasks_is_uninvestigated() -> None:
    entries = [_entry("e1", "ExportedActivity")]
    result = resolve_entry_dispositions(entries, [], [], [])
    assert result["e1"] == "uninvestigated"


def test_reproduced_blackbox() -> None:
    entries = [_entry("e1", "LeakyService")]
    tasks = [_task("t1", ["e1"])]
    findings = [_finding("f1", ["e1"], status="reproduced_blackbox")]
    result = resolve_entry_dispositions(entries, tasks, findings, [])
    assert result["e1"] == "reproduced_blackbox"


def test_refuted_by_dynamic() -> None:
    entries = [_entry("e1", "SafeService")]
    tasks = [_task("t1", ["e1"])]
    findings = [_finding("f1", ["e1"], status="not_reproduced")]
    result = resolve_entry_dispositions(entries, tasks, findings, [])
    assert result["e1"] == "dynamically_refuted"


def test_dynamic_attempt_without_repro() -> None:
    entries = [_entry("e1", "TestedService")]
    tasks = [_task("t1", ["e1"], status="not_reproduced")]
    result = resolve_entry_dispositions(
        entries, tasks, [], [], device_available=True, codex_enabled=True
    )
    assert result["e1"] == "dynamically_not_reproduced"


def test_attack_chain_candidate() -> None:
    entries = [_entry("e1", "RedirectActivity")]
    tasks = [_task("t1", ["e1"])]
    chains = [_chain(["com.example.RedirectActivity"])]
    result = resolve_entry_dispositions(
        entries, tasks, [], chains, device_available=True, codex_enabled=True
    )
    assert result["e1"] == "attack_chain_candidate"


def test_static_finding_without_chain() -> None:
    entries = [_entry("e1", "SuspiciousActivity")]
    tasks = [_task("t1", ["e1"])]
    findings = [_finding("f1", ["e1"], status="supported_static")]
    result = resolve_entry_dispositions(
        entries, tasks, findings, [], device_available=True, codex_enabled=True
    )
    assert result["e1"] == "statically_supported"


def test_caller_identity_guard() -> None:
    entries = [_entry("e1", "GuardedBinder")]
    tasks = [_task("t1", ["e1"])]
    chains = [_chain(["com.example.GuardedBinder"], guard_markers=["binder_caller_identity_guard"])]
    result = resolve_entry_dispositions(
        entries, tasks, [], chains, device_available=True, codex_enabled=True
    )
    assert result["e1"] == "caller_identity_protected"


def test_capability_gap_without_device() -> None:
    entries = [_entry("e1", "ExportedActivity")]
    tasks = [_task("t1", ["e1"])]
    result = resolve_entry_dispositions(
        entries, tasks, [], [], device_available=False, codex_enabled=True
    )
    assert result["e1"] == "capability_gap"


def test_capability_gap_without_codex() -> None:
    entries = [_entry("e1", "ExportedActivity")]
    tasks = [_task("t1", ["e1"])]
    result = resolve_entry_dispositions(
        entries, tasks, [], [], device_available=True, codex_enabled=False
    )
    assert result["e1"] == "capability_gap"


# ── multiple entries ──────────────────────────────────────────────────


def test_mixed_dispositions() -> None:
    entries = [
        _entry("e1", "SecretActivity", exported=False),
        _entry("e2", "AdminService", permission="x", protection="signature"),
        _entry("e3", "ExportedActivity"),
        _entry("e4", "LeakyService"),
        _entry("e5", "SafeService"),
        _entry("e6", "TestedService"),
    ]
    tasks = [
        _task("t3", ["e3"]),
        _task("t4", ["e4"]),
        _task("t5", ["e5"]),
        _task("t6", ["e6"], status="completed"),
    ]
    findings = [
        _finding("f4", ["e4"], status="reproduced_blackbox"),
        _finding("f5", ["e5"], status="not_reproduced"),
    ]

    result = resolve_entry_dispositions(
        entries, tasks, findings, [], device_available=True, codex_enabled=True
    )

    assert result["e1"] == "statically_unreachable"
    assert result["e2"] == "permission_protected"
    assert result["e3"] == "uninvestigated"
    assert result["e4"] == "reproduced_blackbox"
    assert result["e5"] == "dynamically_refuted"
    assert result["e6"] == "uninvestigated"


# ── metrics ───────────────────────────────────────────────────────────


def test_disposition_summary() -> None:
    dispos = {"e1": "statically_unreachable", "e2": "statically_unreachable", "e3": "uninvestigated"}
    summary = disposition_summary(dispos)
    assert summary == {"statically_unreachable": 2, "uninvestigated": 1}


def test_coverage_rate() -> None:
    dispos = {"e1": "statically_unreachable", "e2": "uninvestigated", "e3": "reproduced_blackbox"}
    rate = disposition_coverage_rate(dispos)
    assert rate == 2 / 3  # 2 out of 3 have a disposition beyond uninvestigated


def test_coverage_rate_empty() -> None:
    assert disposition_coverage_rate({}) == 1.0


def test_coverage_rate_all_investigated() -> None:
    dispos = {"e1": "statically_unreachable", "e2": "permission_protected"}
    assert disposition_coverage_rate(dispos) == 1.0