import pytest
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
    static_closure_evaluated: bool = False,
    static_closure: dict[str, str] | None = None,
) -> dict:
    payload = {
        "id": eid,
        "name": name,
        "kind": kind,
        "exported": exported,
        "permission": permission,
        "permission_protection": protection,
        "owner_component": owner or name,
    }
    if static_closure_evaluated:
        payload["static_closure_evaluated"] = True
        payload["static_closure"] = static_closure
    return payload


def _task(
    tid: str,
    entry_ids: list[str],
    *,
    status: str = "completed",
    task_type: str = "component",
    recency: float = 0.0,
    attempts: int = 0,
    agent_enabled: bool | None = None,
    capability_gap: bool = False,
) -> dict:
    payload = {
        "id": tid,
        "target_entry_ids": entry_ids,
        "status": status,
        "task_type": task_type,
        "recency": recency,
        "attempts": attempts,
        "capability_gap": capability_gap,
    }
    if agent_enabled is not None:
        payload["agent_enabled"] = agent_enabled
    return payload


def _finding(
    fid: str,
    entry_ids: list[str],
    *,
    status: str = "candidate",
    task_id: str | None = None,
    proof_backed: bool = False,
    active: bool = True,
    signal_tier: str | None = None,
) -> dict:
    payload = {
        "id": fid,
        "entry_point_ids": entry_ids,
        "status": status,
        "task_id": task_id,
        "proof_backed": proof_backed,
        "active": active,
    }
    if signal_tier is not None:
        payload["signal_tier"] = signal_tier
    return payload


def _chain(
    classes: list[str],
    *,
    guard_markers: list[str] | None = None,
    task_id: str | None = None,
) -> dict:
    payload = {
        "path": [{"class_name": c} for c in classes],
        "guard_markers": guard_markers or [],
    }
    if task_id is not None:
        payload["task_id"] = task_id
    return payload


# ── basic dispositions ────────────────────────────────────────────────


def test_unexported_entry_is_statically_unreachable() -> None:
    entries = [_entry("e1", "SecretActivity", exported=False)]
    result = resolve_entry_dispositions(entries, [], [], [])
    assert result["e1"] == "statically_unreachable"


def test_signature_permission_is_protected() -> None:
    entries = [
        _entry("e1", "AdminService", permission="vivo.permission.ADMIN", protection="signature")
    ]
    result = resolve_entry_dispositions(entries, [], [], [])
    assert result["e1"] == "permission_protected"


def test_compound_signature_or_system_permission_is_protected() -> None:
    entries = [
        _entry(
            "e1",
            "AdminService",
            permission="vendor.permission.ADMIN",
            protection="signatureOrSystem|privileged",
        )
    ]
    result = resolve_entry_dispositions(entries, [], [], [])
    assert result["e1"] == "permission_protected"


def test_evaluated_framework_strong_permission_closure_is_protected() -> None:
    entries = [
        _entry(
            "e1",
            "AutofillService",
            permission="android.permission.BIND_AUTOFILL_SERVICE",
            static_closure_evaluated=True,
            static_closure={"reason_code": "strong_permission_guard"},
        )
    ]
    result = resolve_entry_dispositions(entries, [], [], [])
    assert result["e1"] == "permission_protected"


@pytest.mark.parametrize(
    ("permission", "protection"),
    [
        ("com.vendor.permission.UNKNOWN", None),
        ("com.example.permission.RUNTIME", "dangerous"),
    ],
)
def test_evaluated_non_strong_permission_without_closure_is_not_protected(
    permission: str,
    protection: str | None,
) -> None:
    entries = [
        _entry(
            "e1",
            "ExportedService",
            permission=permission,
            protection=protection,
            static_closure_evaluated=True,
            static_closure=None,
        )
    ]
    tasks = [_task("t1", ["e1"], agent_enabled=True)]
    result = resolve_entry_dispositions(
        entries, tasks, [], [], device_available=True, codex_enabled=True
    )
    assert result["e1"] == "uninvestigated"


def test_unexported_deep_link_is_statically_unreachable() -> None:
    entries = [_entry("e1", "HiddenLink", exported=False, kind="deep_link")]
    result = resolve_entry_dispositions(entries, [], [], [])
    assert result["e1"] == "statically_unreachable"


def test_synthetic_static_surface_is_not_treated_as_android_component() -> None:
    entries = [_entry("e1", "NativeSurface", exported=False, kind="static_surface")]
    result = resolve_entry_dispositions(entries, [], [], [])
    assert result["e1"] == "uninvestigated"


def test_no_tasks_is_uninvestigated() -> None:
    entries = [_entry("e1", "ExportedActivity")]
    result = resolve_entry_dispositions(entries, [], [], [])
    assert result["e1"] == "uninvestigated"


def test_reproduced_blackbox() -> None:
    entries = [_entry("e1", "LeakyService")]
    tasks = [_task("t1", ["e1"])]
    findings = [_finding("f1", ["e1"], status="reproduced_blackbox", proof_backed=True)]
    result = resolve_entry_dispositions(entries, tasks, findings, [])
    assert result["e1"] == "reproduced_blackbox"


def test_reproduced_blackbox_overrides_static_permission_assumption() -> None:
    entries = [
        _entry(
            "e1",
            "LeakyService",
            permission="vendor.permission.ADMIN",
            protection="signature",
        )
    ]
    tasks = [_task("t1", ["e1"])]
    findings = [_finding("f1", ["e1"], status="reproduced_blackbox", proof_backed=True)]
    result = resolve_entry_dispositions(entries, tasks, findings, [])
    assert result["e1"] == "reproduced_blackbox"


def test_unproven_reproduced_status_does_not_promote_the_entry() -> None:
    entries = [_entry("e1", "LeakyService")]
    tasks = [_task("t1", ["e1"], agent_enabled=True)]
    findings = [_finding("f1", ["e1"], status="reproduced_blackbox")]
    result = resolve_entry_dispositions(
        entries, tasks, findings, [], device_available=True, codex_enabled=True
    )
    assert result["e1"] == "uninvestigated"


def test_refuted_by_dynamic() -> None:
    entries = [_entry("e1", "SafeService")]
    tasks = [_task("t1", ["e1"])]
    findings = [_finding("f1", ["e1"], status="not_reproduced")]
    result = resolve_entry_dispositions(entries, tasks, findings, [])
    assert result["e1"] == "dynamically_refuted"


@pytest.mark.parametrize("status", ["refuted_static", "false_positive", "inconclusive"])
def test_negative_finding_is_not_static_support(status: str) -> None:
    entries = [_entry("e1", "SafeService")]
    tasks = [_task("t1", ["e1"], agent_enabled=True)]
    findings = [_finding("f1", ["e1"], status=status)]
    result = resolve_entry_dispositions(
        entries, tasks, findings, [], device_available=True, codex_enabled=True
    )
    assert result["e1"] == "uninvestigated"


def test_inactive_static_finding_is_ignored() -> None:
    entries = [_entry("e1", "SafeService")]
    tasks = [_task("t1", ["e1"], agent_enabled=True)]
    findings = [_finding("f1", ["e1"], status="supported_static", active=False)]
    result = resolve_entry_dispositions(
        entries, tasks, findings, [], device_available=True, codex_enabled=True
    )
    assert result["e1"] == "uninvestigated"


def test_dynamic_attempt_without_repro() -> None:
    entries = [_entry("e1", "TestedService")]
    tasks = [_task("t1", ["e1"], status="not_reproduced")]
    result = resolve_entry_dispositions(
        entries, tasks, [], [], device_available=True, codex_enabled=True
    )
    assert result["e1"] == "dynamically_not_reproduced"


def test_inconclusive_dynamic_attempt_is_not_reported_as_not_reproduced() -> None:
    entries = [_entry("e1", "TestedService")]
    tasks = [_task("t1", ["e1"], status="inconclusive")]
    result = resolve_entry_dispositions(
        entries, tasks, [], [], device_available=True, codex_enabled=True
    )
    assert result["e1"] == "uninvestigated"


def test_latest_same_type_task_decides_and_old_task_findings_are_filtered() -> None:
    entries = [_entry("e1", "RetestedService")]
    tasks = [
        _task(
            "z-old",
            ["e1"],
            status="not_reproduced",
            recency=1.0,
            attempts=99,
            agent_enabled=True,
        ),
        _task(
            "a-new",
            ["e1"],
            status="completed",
            recency=2.0,
            attempts=1,
            agent_enabled=True,
        ),
    ]
    findings = [
        _finding(
            "f-old",
            ["e1"],
            status="supported_static",
            task_id="z-old",
        )
    ]
    result = resolve_entry_dispositions(
        entries, tasks, findings, [], device_available=True, codex_enabled=True
    )
    assert result["e1"] == "uninvestigated"


def test_attack_chain_candidate() -> None:
    entries = [_entry("e1", "RedirectActivity")]
    tasks = [_task("t1", ["e1"])]
    chains = [_chain(["com.example.RedirectActivity"])]
    result = resolve_entry_dispositions(
        entries, tasks, [], chains, device_available=True, codex_enabled=True
    )
    assert result["e1"] == "attack_chain_candidate"


def test_attack_chain_does_not_match_a_different_suffix_class() -> None:
    entries = [_entry("e1", "MainActivity")]
    tasks = [_task("t1", ["e1"])]
    chains = [_chain(["com.example.NotMainActivity"])]
    result = resolve_entry_dispositions(
        entries, tasks, [], chains, device_available=True, codex_enabled=True
    )
    assert result["e1"] == "uninvestigated"


def test_attack_chain_does_not_match_the_same_class_name_in_another_package() -> None:
    entries = [
        _entry(
            "e1",
            "com.example.target.MainActivity",
            owner="com.example.target.MainActivity",
        )
    ]
    tasks = [_task("t1", ["e1"])]
    chains = [_chain(["com.example.other.MainActivity"])]
    result = resolve_entry_dispositions(
        entries, tasks, [], chains, device_available=True, codex_enabled=True
    )
    assert result["e1"] == "uninvestigated"


def test_package_relative_owner_does_not_match_another_package() -> None:
    entries = [
        _entry(
            "e1",
            "com.example.target/.MainActivity",
            owner="com.example.target/.MainActivity",
        )
    ]
    tasks = [_task("t1", ["e1"])]
    chains = [_chain(["com.example.other.MainActivity"])]

    result = resolve_entry_dispositions(
        entries, tasks, [], chains, device_available=True, codex_enabled=True
    )

    assert result["e1"] == "uninvestigated"


def test_attack_chain_can_link_an_entry_explicitly() -> None:
    entries = [_entry("e1", "AliasName")]
    tasks = [_task("t1", ["e1"])]
    chain = {**_chain(["com.example.Implementation"]), "entry_point_ids": ["e1"]}
    result = resolve_entry_dispositions(
        entries, tasks, [], [chain], device_available=True, codex_enabled=True
    )
    assert result["e1"] == "attack_chain_candidate"


@pytest.mark.parametrize("reason_code", ["not_exported", "strong_permission_guard"])
def test_indirect_attack_chain_outranks_direct_static_closure(
    reason_code: str,
) -> None:
    entries = [
        _entry(
            "e1",
            "com.example.RedirectActivity",
            static_closure_evaluated=True,
            static_closure={"reason_code": reason_code},
        )
    ]
    tasks = [_task("t1", ["e1"], agent_enabled=True)]
    chains = [_chain(["com.example.RedirectActivity"], task_id="t1")]
    result = resolve_entry_dispositions(
        entries, tasks, [], chains, device_available=True, codex_enabled=True
    )
    assert result["e1"] == "attack_chain_candidate"


def test_static_finding_without_chain() -> None:
    entries = [_entry("e1", "SuspiciousActivity")]
    tasks = [_task("t1", ["e1"])]
    findings = [
        _finding(
            "f1",
            ["e1"],
            status="supported_static",
            signal_tier="static_chain",
        )
    ]
    result = resolve_entry_dispositions(
        entries, tasks, findings, [], device_available=True, codex_enabled=True
    )
    assert result["e1"] == "statically_supported"


def test_static_support_outranks_a_generic_attack_chain() -> None:
    entries = [_entry("e1", "com.example.SuspiciousActivity")]
    tasks = [_task("t1", ["e1"])]
    findings = [
        _finding(
            "f1",
            ["e1"],
            status="static_path_supported",
            signal_tier="static_chain",
        )
    ]
    chains = [_chain(["com.example.SuspiciousActivity"])]

    result = resolve_entry_dispositions(entries, tasks, findings, chains)

    assert result["e1"] == "statically_supported"


def test_legacy_ungated_static_status_is_not_treated_as_static_support() -> None:
    entries = [_entry("e1", "LegacyActivity")]
    tasks = [_task("t1", ["e1"], agent_enabled=True)]
    findings = [_finding("f1", ["e1"], status="supported_static")]

    result = resolve_entry_dispositions(
        entries, tasks, findings, [], device_available=True, codex_enabled=True
    )

    assert result["e1"] == "uninvestigated"


def test_raw_candidate_is_not_treated_as_static_support() -> None:
    entries = [_entry("e1", "SuspiciousActivity")]
    tasks = [_task("t1", ["e1"], agent_enabled=True)]
    findings = [_finding("f1", ["e1"], status="candidate")]

    result = resolve_entry_dispositions(
        entries, tasks, findings, [], device_available=True, codex_enabled=True
    )

    assert result["e1"] == "uninvestigated"


def test_runtime_observation_without_harm_oracle_has_its_own_disposition() -> None:
    entries = [_entry("e1", "ObservedActivity")]
    tasks = [_task("t1", ["e1"], agent_enabled=True)]
    findings = [
        _finding("f1", ["e1"], status="runtime_observed_unverified")
    ]

    result = resolve_entry_dispositions(
        entries, tasks, findings, [], device_available=True, codex_enabled=True
    )

    assert result["e1"] == "runtime_observed_unverified"


def test_open_runtime_signal_outranks_a_different_negative_hypothesis() -> None:
    entries = [_entry("e1", "ObservedActivity")]
    tasks = [_task("t1", ["e1"], status="not_reproduced", agent_enabled=True)]
    findings = [
        _finding("f-negative", ["e1"], status="not_reproduced"),
        _finding("f-open", ["e1"], status="oracle_gap", signal_tier="runtime_oracle_gap"),
    ]

    result = resolve_entry_dispositions(
        entries, tasks, findings, [], device_available=True, codex_enabled=True
    )

    assert result["e1"] == "runtime_observed_unverified"


def test_legacy_runtime_metadata_uses_the_canonical_signal_tier() -> None:
    entries = [_entry("e1", "LegacyObservedActivity")]
    tasks = [_task("t1", ["e1"], agent_enabled=True)]
    findings = [
        _finding(
            "f1",
            ["e1"],
            status="supported_static",
            signal_tier="runtime_oracle_gap",
        )
    ]

    result = resolve_entry_dispositions(
        entries, tasks, findings, [], device_available=True, codex_enabled=True
    )

    assert result["e1"] == "runtime_observed_unverified"


def test_reviewed_platform_proof_keeps_dynamic_disposition() -> None:
    entries = [_entry("e1", "ReviewedProofActivity")]
    tasks = [_task("t1", ["e1"])]
    findings = [
        _finding(
            "f1",
            ["e1"],
            status="accepted",
            proof_backed=True,
        )
    ]

    result = resolve_entry_dispositions(
        entries, tasks, findings, [], device_available=True, codex_enabled=True
    )

    assert result["e1"] == "reproduced_blackbox"


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


def test_capability_probe_failure_is_a_gap_even_when_configuration_is_enabled() -> None:
    entries = [_entry("e1", "ExportedActivity")]
    tasks = [
        _task(
            "t1",
            ["e1"],
            status="inconclusive",
            agent_enabled=True,
            capability_gap=True,
        )
    ]

    result = resolve_entry_dispositions(
        entries, tasks, [], [], device_available=True, codex_enabled=True
    )

    assert result["e1"] == "capability_gap"


@pytest.mark.parametrize(
    ("agent_enabled", "codex_enabled", "expected"),
    [
        (False, True, "capability_gap"),
        (True, False, "uninvestigated"),
    ],
)
def test_latest_task_agent_setting_overrides_global_capability_fallback(
    agent_enabled: bool,
    codex_enabled: bool,
    expected: str,
) -> None:
    entries = [_entry("e1", "ExportedActivity")]
    tasks = [
        _task(
            "old-component",
            ["e1"],
            task_type="component",
            recency=1.0,
            agent_enabled=not agent_enabled,
        ),
        _task(
            "new-deep-link",
            ["e1"],
            task_type="deep_link",
            recency=2.0,
            agent_enabled=agent_enabled,
        ),
    ]
    result = resolve_entry_dispositions(
        entries,
        tasks,
        [],
        [],
        device_available=True,
        codex_enabled=codex_enabled,
    )
    assert result["e1"] == expected


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
        _finding(
            "f4",
            ["e4"],
            status="reproduced_blackbox",
            proof_backed=True,
        ),
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
    dispos = {
        "e1": "statically_unreachable",
        "e2": "statically_unreachable",
        "e3": "uninvestigated",
    }
    summary = disposition_summary(dispos)
    assert summary == {"statically_unreachable": 2, "uninvestigated": 1}


def test_coverage_rate() -> None:
    dispos = {"e1": "statically_unreachable", "e2": "uninvestigated", "e3": "reproduced_blackbox"}
    rate = disposition_coverage_rate(dispos)
    assert rate == 2 / 3  # 2 out of 3 have a disposition beyond uninvestigated


def test_coverage_rate_empty() -> None:
    assert disposition_coverage_rate({}) == 0.0


def test_coverage_rate_all_investigated() -> None:
    dispos = {"e1": "statically_unreachable", "e2": "permission_protected"}
    assert disposition_coverage_rate(dispos) == 1.0
