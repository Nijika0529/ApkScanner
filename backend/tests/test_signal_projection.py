from __future__ import annotations

import pytest
from apkscanner.core.models import Evidence, Finding
from apkscanner.runtime.signal_projection import (
    evidence_supports_runtime_observation,
    project_runtime_observation_gap,
)


def _finding(status: str) -> Finding:
    return Finding(
        id="11111111-1111-1111-1111-111111111111",
        scan_id="22222222-2222-2222-2222-222222222222",
        dedupe_key=f"projection-{status}",
        rule_id="AGENT",
        title="Runtime projection",
        description="A platform runtime observation arrived after static analysis.",
        masvs="MASVS-PLATFORM",
        severity="medium",
        status=status,
    )


@pytest.mark.parametrize("status", ["refuted_static", "not_reproduced"])
def test_runtime_observation_reopens_non_human_negative_closure(status: str) -> None:
    finding = _finding(status)

    changed = project_runtime_observation_gap(
        finding,
        observation_id="33333333-3333-3333-3333-333333333333",
        evidence_ids=["44444444-4444-4444-4444-444444444444"],
        task_id="55555555-5555-5555-5555-555555555555",
        observation_kind="request.observed",
    )

    assert changed is True
    assert finding.status == "runtime_observed_unverified"
    assert finding.metadata_json["previous_closure"]["status"] == status


def test_runtime_observation_does_not_reopen_human_false_positive() -> None:
    finding = _finding("false_positive")

    changed = project_runtime_observation_gap(
        finding,
        observation_id="33333333-3333-3333-3333-333333333333",
        evidence_ids=["44444444-4444-4444-4444-444444444444"],
        task_id="55555555-5555-5555-5555-555555555555",
        observation_kind="request.observed",
    )

    assert changed is False
    assert finding.status == "false_positive"


@pytest.mark.parametrize(
    ("kind", "metadata", "expected"),
    [
        ("blackbox.logcat", {"request_observed": True}, True),
        ("dynamic_experiment.adb", {"runtime_crash_observed": True}, True),
        ("static.jadx", {"request_observed": True}, False),
        ("blackbox.logcat", {"request_observed": False}, False),
    ],
)
def test_runtime_observation_evidence_requires_platform_kind_and_positive_flag(
    kind: str,
    metadata: dict[str, bool],
    expected: bool,
) -> None:
    evidence = Evidence(
        id="66666666-6666-6666-6666-666666666666",
        scan_id="22222222-2222-2222-2222-222222222222",
        kind=kind,
        sha256="a" * 64,
        path="receipt.json",
        metadata_json=metadata,
    )

    assert evidence_supports_runtime_observation(evidence) is expected
