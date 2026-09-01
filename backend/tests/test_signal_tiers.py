from __future__ import annotations

import pytest
from apkscanner.runtime.signal_tiers import finding_signal_tier

VALID_STATIC_GATE = {
    "schema_version": "1.0",
    "eligible": True,
    "required_fields": [
        "source",
        "control",
        "sink",
        "reachable_path",
        "boundary",
        "security_impact",
        "missing_control",
    ],
    "static_evidence_ids": ["static-evidence"],
    "suppression_reasons": [],
}


@pytest.mark.parametrize(
    ("status", "metadata", "expected"),
    [
        (
            "runtime_observed_unverified",
            {},
            "runtime_oracle_gap",
        ),
        (
            "supported_static",
            {
                "adaptive_verification": {
                    "runtime_observed": True,
                    "model_verdict": "reproduced_blackbox",
                },
                "harm_demonstrated": False,
            },
            "runtime_oracle_gap",
        ),
        (
            "supported_static",
            {"platform_static_support_gate": VALID_STATIC_GATE},
            "static_chain",
        ),
        (
            "supported_static",
            {
                "signal_tier": "static_chain",
                "platform_static_support_gate": {"eligible": True},
            },
            "raw_candidate",
        ),
        (
            "supported_static",
            {
                "platform_static_support_gate": {
                    **VALID_STATIC_GATE,
                    "required_fields": [{"malformed": True}],
                }
            },
            "raw_candidate",
        ),
        (
            "supported_static",
            {},
            "raw_candidate",
        ),
        (
            "false_positive",
            {
                "adaptive_verification": {
                    "runtime_observed": True,
                    "model_verdict": "reproduced_blackbox",
                }
            },
            "raw_candidate",
        ),
    ],
)
def test_finding_signal_tier(
    status: str,
    metadata: dict,
    expected: str,
) -> None:
    assert finding_signal_tier(status, metadata) == expected
