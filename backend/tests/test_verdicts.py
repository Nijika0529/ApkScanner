from __future__ import annotations

import pytest
from apkscanner.core.enums import FindingStatus
from apkscanner.core.verdicts import (
    VerdictTransitionError,
    decide_human_review,
    decide_operator_verdict,
    normalize_signal_metadata,
)


def test_human_review_cannot_fabricate_or_erase_platform_proof() -> None:
    with pytest.raises(VerdictTransitionError, match="proof-backed"):
        decide_human_review(
            current_status=FindingStatus.CANDIDATE.value,
            requested_status=FindingStatus.ACCEPTED.value,
            has_harm_proof=False,
        )
    with pytest.raises(VerdictTransitionError, match="cannot be downgraded"):
        decide_human_review(
            current_status=FindingStatus.REPRODUCED_BLACKBOX.value,
            requested_status=FindingStatus.CANDIDATE.value,
            has_harm_proof=True,
        )

    decision = decide_human_review(
        current_status=FindingStatus.REPRODUCED_BLACKBOX.value,
        requested_status=FindingStatus.FALSE_POSITIVE.value,
        has_harm_proof=True,
    )
    assert decision.applied_status == FindingStatus.FALSE_POSITIVE.value


@pytest.mark.parametrize(
    ("requested", "runtime_observed", "expected"),
    [
        (
            FindingStatus.REPRODUCED_BLACKBOX.value,
            True,
            FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value,
        ),
        (
            FindingStatus.REPRODUCED_BLACKBOX.value,
            False,
            FindingStatus.INCONCLUSIVE.value,
        ),
        (
            FindingStatus.NOT_REPRODUCED.value,
            True,
            FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value,
        ),
    ],
)
def test_operator_proposals_are_bounded_by_platform_receipts(
    requested: str,
    runtime_observed: bool,
    expected: str,
) -> None:
    decision = decide_operator_verdict(
        current_status=FindingStatus.CANDIDATE.value,
        requested_status=requested,
        has_harm_proof=False,
        has_refutation_proof=False,
        runtime_observed=runtime_observed,
        existing_signal_tier="raw_candidate",
        preserve_human_closure=False,
        static_support_eligible=False,
        static_refutation_eligible=False,
    )
    assert decision.applied_status == expected
    assert decision.override_reason


def test_harm_receipt_wins_over_operator_downgrade() -> None:
    decision = decide_operator_verdict(
        current_status=FindingStatus.REPRODUCED_BLACKBOX.value,
        requested_status=FindingStatus.INCONCLUSIVE.value,
        has_harm_proof=True,
        has_refutation_proof=False,
        runtime_observed=False,
        existing_signal_tier="raw_candidate",
        preserve_human_closure=False,
        static_support_eligible=False,
        static_refutation_eligible=False,
    )
    assert decision.applied_status == FindingStatus.REPRODUCED_BLACKBOX.value
    assert decision.overridden is True


def test_signal_metadata_projection_clears_stale_oracle_fields() -> None:
    gap = normalize_signal_metadata(
        {},
        status=FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value,
        runtime_observed=True,
        operator_session_id="operator-1",
    )
    assert gap["signal_tier"] == "runtime_oracle_gap"
    assert gap["oracle_gap"]["operator_session_id"] == "operator-1"

    supported = normalize_signal_metadata(
        gap,
        status=FindingStatus.SUPPORTED_STATIC.value,
    )
    assert supported["signal_tier"] == "static_chain"
    assert "oracle_gap" not in supported
