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


def test_blackbox_reproduction_requires_probe_identity_and_log_evidence() -> None:
    evidence = [
        {
            "id": "probe",
            "kind": "blackbox.probe_app",
            "exit_code": 0,
            "metadata": {"caller_identity": "probe_app", "request_id": "request-1"},
        },
        {
            "id": "log",
            "kind": "blackbox.logcat",
            "exit_code": 0,
            "metadata": {
                "request_id": "request-1",
                "request_observed": True,
                "probe_success": True,
            },
        },
    ]
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("reproduced_blackbox", ["probe", "log"]),
        evidence,
    )
    assert result == "reproduced_blackbox"
    assert payload["evidence_ids"] == ["probe", "log"]


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
