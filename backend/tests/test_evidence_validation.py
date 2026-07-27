from __future__ import annotations

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
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("reproduced_blackbox", ["invented"]),
        [],
    )
    assert result == "inconclusive"
    assert payload["evidence_ids"] == []
    assert any("Ignored 1" in gap for gap in payload["coverage_gaps"])


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


def test_reachability_without_concrete_harm_is_inconclusive() -> None:
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
            },
        },
    ]
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("reproduced_blackbox", ["probe", "log"]),
        evidence,
    )
    assert result == "inconclusive"
    assert payload["platform_severity"] is None
    assert any("concrete-harm Oracle" in gap for gap in payload["coverage_gaps"])


def test_not_reproduced_requires_correlated_explicit_negative_oracle() -> None:
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
                "probe_success": False,
                "test_case_id": "agent-r1-1",
            },
        },
    ]
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("not_reproduced", ["probe", "log"]),
        evidence,
    )
    assert result == "inconclusive"

    evidence[1]["metadata"]["oracle_refuted"] = True
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("not_reproduced", ["probe", "log"]),
        evidence,
    )
    assert result == "not_reproduced"
    assert payload["platform_severity"] is None


def test_blackbox_evidence_must_share_request_and_test_case_ids() -> None:
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
                "test_case_id": "agent-r1-2",
                "security_impact_observed": True,
            },
        },
    ]
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("reproduced_blackbox", ["probe", "log"]),
        evidence,
    )
    assert result == "inconclusive"
    assert payload["platform_severity"] is None


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
        entry_point_id=entry.id,
        state="guest",
        uri="https://example.test/open?next=%2Fadmin",
        extras={},
        rationale="Test redirect validation",
    )
    rejected = AgentRequestedTest(
        entry_point_id=entry.id,
        state="guest",
        uri="https://unrelated.test/open",
        extras={},
        rationale="Should not leave scope",
    )
    accepted, gaps = ScanOrchestrator._validate_requested_tests(
        [allowed, rejected], [entry], auth_available=False
    )
    assert accepted == [allowed]
    assert any("preserve" in gap for gap in gaps)
