from __future__ import annotations

import pytest
from apkscanner.models import EntryPoint
from apkscanner.orchestrator import ScanOrchestrator
from apkscanner.schemas import AgentRequestedTest


def _payload(result: str, evidence_ids: list[str]) -> dict:  # noqa: ANN401
    return {
        "result": result,
        "evidence_ids": evidence_ids,
        "coverage_gaps": [],
    }


def test_unknown_agent_evidence_is_removed_and_reproduction_is_downgraded() -> None:
    with pytest.raises(ValueError, match="did not cite"):
        ScanOrchestrator._validated_agent_payload(
            _payload("reproduced_blackbox", ["invented"]),
            [],
        )


def test_static_verdict_recovers_platform_issued_evidence_omitted_by_model() -> None:
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("supported_static", []),
        [{"id": "static", "kind": "static.apktool", "metadata": {}}],
    )

    assert result == "supported_static"
    assert payload["evidence_ids"] == ["static"]
    assert payload["coverage_gaps"] == [
        "Platform attached the issued static Evidence omitted by the model."
    ]


def test_blackbox_reproduction_requires_correlated_concrete_harm() -> None:
    evidence = [
        {
            "id": "probe",
            "kind": "blackbox.probe_app",
            "exit_code": 0,
            "metadata": {
                "caller_identity": "probe_app",
                "request_id": "request-1",
                "test_case_id": "agent-r1-1",
            },
        },
        {
            "id": "log",
            "kind": "blackbox.logcat",
            "exit_code": 0,
            "metadata": {
                "request_id": "request-1",
                "request_observed": True,
                "probe_success": True,
                "test_case_id": "agent-r1-1",
                "security_impact_observed": True,
            },
        },
    ]
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("reproduced_blackbox", ["probe", "log"]),
        evidence,
    )
    assert result == "reproduced_blackbox"
    assert payload["evidence_ids"] == ["probe", "log"]


def test_agent_poc_can_supply_the_correlated_ordinary_app_execution_pair() -> None:
    evidence = [
        {
            "id": "launch",
            "kind": "blackbox.poc_launch",
            "exit_code": 0,
            "metadata": {
                "caller_identity": "agent_poc_app",
                "request_id": "request-poc",
                "test_case_id": "agent-r1-1",
            },
        },
        {
            "id": "log",
            "kind": "blackbox.poc_logcat",
            "exit_code": 0,
            "metadata": {
                "request_id": "request-poc",
                "request_observed": True,
                "poc_success": True,
                "test_case_id": "agent-r1-1",
            },
        },
        {
            "id": "oracle",
            "kind": "blackbox.poc_ui_dump",
            "exit_code": 0,
            "metadata": {
                "test_case_id": "agent-r1-1",
                "security_impact_observed": True,
            },
        },
    ]

    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("reproduced_blackbox", ["launch", "log", "oracle"]),
        evidence,
    )

    assert result == "reproduced_blackbox"
    assert payload["evidence_ids"] == ["launch", "log", "oracle"]


def test_optional_jadx_absence_is_not_preserved_as_a_verdict_gap() -> None:
    payload = _payload("refuted_static", ["static"])
    payload["coverage_gaps"] = [
        "JADX decompilation was unavailable; Smali fallback was sufficient.",
        "No device available; static permission evidence is definitive.",
        "A device replay could validate the negative path.",
    ]

    validated, result = ScanOrchestrator._validated_agent_payload(
        payload,
        [{"id": "static", "kind": "static.apktool", "metadata": {}}],
    )

    assert result == "refuted_static"
    assert validated["coverage_gaps"] == [
        "A device replay could validate the negative path."
    ]


def test_unique_evidence_uuid_prefix_is_normalized_to_full_platform_id() -> None:
    evidence_id = "509102d0-1111-2222-3333-444444444444"

    validated, result = ScanOrchestrator._validated_agent_payload(
        _payload("refuted_static", ["509102d0"]),
        [{"id": evidence_id, "kind": "static.apktool", "metadata": {}}],
    )

    assert result == "refuted_static"
    assert validated["evidence_ids"] == [evidence_id]


def test_reachability_without_concrete_harm_keeps_a_static_positive_verdict() -> None:
    evidence = [
        {
            "id": "static",
            "kind": "static.apktool",
            "exit_code": 0,
            "metadata": {},
        },
        {
            "id": "probe",
            "kind": "blackbox.probe_app",
            "exit_code": 0,
            "metadata": {
                "caller_identity": "probe_app",
                "request_id": "request-1",
                "test_case_id": "agent-r1-1",
            },
        },
        {
            "id": "log",
            "kind": "blackbox.logcat",
            "exit_code": 0,
            "metadata": {
                "request_id": "request-1",
                "request_observed": True,
                "probe_success": True,
                "test_case_id": "agent-r1-1",
            },
        },
    ]
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("reproduced_blackbox", ["static", "probe", "log"]),
        evidence,
    )
    assert result == "supported_static"
    assert any("static-evidence strength" in gap for gap in payload["coverage_gaps"])


def test_each_hypothesis_assessment_is_validated_at_its_own_evidence_strength() -> None:
    hypothesis_id = "00000000-0000-0000-0000-000000000001"
    payload = _payload("supported_static", ["static"])
    payload["hypothesis_assessments"] = [
        {
            "hypothesis_id": hypothesis_id,
            "verdict": "reproduced_blackbox",
            "evidence_ids": ["static"],
            "proof_gaps": [],
        }
    ]

    validated, result = ScanOrchestrator._validated_agent_payload(
        payload,
        [{"id": "static", "kind": "static.apktool", "metadata": {}}],
    )

    assert result == "supported_static"
    assessment = validated["hypothesis_assessments"][0]
    assert assessment["verdict"] == "supported_static"
    assert any("static-evidence strength" in gap for gap in assessment["proof_gaps"])


def test_not_reproduced_requires_correlated_explicit_negative_oracle() -> None:
    evidence = [
        {
            "id": "static",
            "kind": "static.apktool",
            "exit_code": 0,
            "metadata": {},
        },
        {
            "id": "probe",
            "kind": "blackbox.probe_app",
            "exit_code": 0,
            "metadata": {
                "caller_identity": "probe_app",
                "request_id": "request-1",
                "test_case_id": "agent-r1-1",
            },
        },
        {
            "id": "log",
            "kind": "blackbox.logcat",
            "exit_code": 0,
            "metadata": {
                "request_id": "request-1",
                "request_observed": True,
                "probe_success": False,
                "test_case_id": "agent-r1-1",
            },
        },
    ]
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("not_reproduced", ["static", "probe", "log"]),
        evidence,
    )
    assert result == "refuted_static"

    evidence[1]["metadata"]["oracle_refuted"] = True
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("not_reproduced", ["static", "probe", "log"]),
        evidence,
    )
    assert result == "not_reproduced"
    assert payload["platform_severity"] is None


def test_blackbox_evidence_must_share_request_and_test_case_ids() -> None:
    evidence = [
        {
            "id": "static",
            "kind": "static.apktool",
            "exit_code": 0,
            "metadata": {},
        },
        {
            "id": "probe",
            "kind": "blackbox.probe_app",
            "exit_code": 0,
            "metadata": {
                "caller_identity": "probe_app",
                "request_id": "request-1",
                "test_case_id": "agent-r1-1",
            },
        },
        {
            "id": "log",
            "kind": "blackbox.logcat",
            "exit_code": 0,
            "metadata": {
                "request_id": "request-1",
                "request_observed": True,
                "probe_success": True,
                "test_case_id": "agent-r1-2",
                "security_impact_observed": True,
            },
        },
    ]
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("reproduced_blackbox", ["static", "probe", "log"]),
        evidence,
    )
    assert result == "supported_static"


def test_agent_requested_deep_link_must_preserve_declared_origin() -> None:
    entry = EntryPoint(
        id="11111111-1111-1111-1111-111111111111",
        scan_id="scan",
        kind="deep_link",
        name="https://example.test/open",
        owner_component="com.example.LinkActivity",
        exported=True,
        exported_reason="explicit_true",
        intent_filters=[],
        deep_links=[],
        metadata_json={},
    )
    allowed = AgentRequestedTest(
        hypothesis_id="22222222-2222-2222-2222-222222222222",
        entry_point_id=entry.id,
        state="guest",
        uri="https://example.test/open?next=%2Fadmin",
        extras={},
        rationale="Test redirect validation",
    )
    rejected = AgentRequestedTest(
        hypothesis_id="22222222-2222-2222-2222-222222222222",
        entry_point_id=entry.id,
        state="guest",
        uri="https://unrelated.test/open",
        extras={},
        rationale="Should not leave scope",
    )
    accepted, gaps = ScanOrchestrator._validate_requested_tests(
        [allowed, rejected], [entry]
    )
    assert accepted == [allowed]
    assert any("preserve" in gap for gap in gaps)


def test_activity_request_accepts_its_declared_deep_link_and_android_extra_key() -> None:
    entry = EntryPoint(
        id="11111111-1111-1111-1111-111111111111",
        scan_id="scan",
        kind="activity",
        name="com.example.LinkActivity",
        owner_component="com.example.LinkActivity",
        exported=True,
        exported_reason="explicit_true",
        intent_filters=[],
        deep_links=[
            {
                "scheme": "iqoo",
                "host": "com.iqoo.secure",
                "port": None,
                "path": "/smart_privacy",
                "uri_template": "iqoo://com.iqoo.secure/smart_privacy",
            }
        ],
        metadata_json={},
    )
    allowed = AgentRequestedTest(
        hypothesis_id="22222222-2222-2222-2222-222222222222",
        entry_point_id=entry.id,
        state="guest",
        uri="iqoo://com.iqoo.secure/smart_privacy?source=test",
        extras={":settings:fragment_args_key": "clipboard_privacy_protect"},
        rationale="Exercise the activity's declared deep link and framework-style extra",
    )
    rejected = allowed.model_copy(
        update={"uri": "iqoo://unrelated.example/smart_privacy"}
    )

    accepted, gaps = ScanOrchestrator._validate_requested_tests(
        [allowed, rejected],
        [entry],
        hypothesis_ids={allowed.hypothesis_id},
    )

    assert accepted == [allowed]
    assert any("preserve" in gap for gap in gaps)


def test_requested_test_deduplication_ignores_rationale_only_changes() -> None:
    entry = EntryPoint(
        id="11111111-1111-1111-1111-111111111111",
        scan_id="scan",
        kind="activity",
        name="com.example.ExportedActivity",
        owner_component="com.example.ExportedActivity",
        exported=True,
        exported_reason="explicit_true",
        intent_filters=[],
        deep_links=[],
        metadata_json={},
    )
    first = AgentRequestedTest(
        hypothesis_id="22222222-2222-2222-2222-222222222222",
        entry_point_id=entry.id,
        state="guest",
        uri=None,
        extras={"source": "external"},
        rationale="Candidate rationale",
    )
    duplicate = first.model_copy(update={"rationale": "Critic rationale"})

    accepted, gaps = ScanOrchestrator._validate_requested_tests(
        [first, duplicate],
        [entry],
        hypothesis_ids={first.hypothesis_id},
    )

    assert accepted == [first]
    assert gaps == []


def test_personal_lab_accepts_typed_provider_call_and_objective_oracle() -> None:
    entry = EntryPoint(
        id="11111111-1111-1111-1111-111111111111",
        scan_id="scan",
        kind="provider",
        name="com.example.ExportedProvider",
        owner_component="com.example.ExportedProvider",
        exported=True,
        metadata_json={"authorities": "com.example.provider"},
    )
    request = AgentRequestedTest(
        hypothesis_id="22222222-2222-2222-2222-222222222222",
        entry_point_id=entry.id,
        state="guest",
        uri="content://com.example.provider/items",
        extras={"account": "victim"},
        operation="call",
        method="getPrivateItems",
        argument="all",
        reset="preserve",
        oracle={
            "kind": "log_contains",
            "expected_text": "private-item",
            "impact": "none",
        },
        rationale="Call the exported provider as an ordinary application UID.",
    )

    accepted, gaps = ScanOrchestrator._validate_requested_tests(
        [request],
        [entry],
        hypothesis_ids={request.hypothesis_id},
        permission_profile="personal_lab",
    )

    assert accepted == [request]
    assert gaps == []


def test_provider_rows_oracle_rejects_a_non_query_operation() -> None:
    entry = EntryPoint(
        id="11111111-1111-1111-1111-111111111111",
        scan_id="scan",
        kind="provider",
        name="com.example.ExportedProvider",
        owner_component="com.example.ExportedProvider",
        exported=True,
        metadata_json={"authorities": "com.example.provider"},
    )
    request = AgentRequestedTest(
        hypothesis_id="22222222-2222-2222-2222-222222222222",
        entry_point_id=entry.id,
        state="guest",
        uri="content://com.example.provider/items",
        extras={},
        operation="call",
        method="getPrivateItems",
        oracle={
            "kind": "provider_rows",
            "minimum_rows": 1,
            "impact": "unauthorized_data_access",
        },
        rationale="A call result cannot satisfy a row-count predicate.",
    )

    accepted, gaps = ScanOrchestrator._validate_requested_tests(
        [request],
        [entry],
        hypothesis_ids={request.hypothesis_id},
    )

    assert accepted == []
    assert any("requires a provider query operation" in gap for gap in gaps)
