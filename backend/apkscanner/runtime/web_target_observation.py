"""Platform-owned interpretation of target-side Web execution receipts.

Observer HTTP requests and JavaScript callbacks are client-authored. They must
not be used as a substitute for a target-side observation. This module keeps
the currently available target-UID log adapter explicit and fail-closed, so a
release APK that does not emit the fixture's ``onPageFinished`` log produces an
oracle gap instead of a guessed WebView confirmation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import parse_qs, urlsplit

from .device import AdbDeviceAdapter

_PAGE_FINISHED_URL = re.compile(r"\bonPageFinished\s+(https?://\S+)")
_ADAPTER_ID = "target_uid_on_page_finished_log_v1"
_LIMITATIONS = (
    "The target process emitted a main-frame URL log; this is not an OS WebView callback receipt.",
    "A main-frame URL log does not identify the calling iframe origin or prove a Bridge call.",
    "JavaScript callback values and native effects require separate provenance and effect evidence.",
)


@dataclass(frozen=True, slots=True)
class TargetWebObservation:
    """What a platform adapter can establish, including its negative space."""

    status: Literal["observed", "unverified"]
    trust_tier: Literal["target_uid_app_log", "none"]
    adapter_id: str | None
    main_frame_url: str | None
    target_uid: int | None
    frame_origin_verified: bool
    bridge_call_verified: bool
    gaps: tuple[str, ...]
    limitations: tuple[str, ...] = _LIMITATIONS

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "status": self.status,
            "trust_tier": self.trust_tier,
            "adapter_id": self.adapter_id,
            "main_frame_url": self.main_frame_url,
            "target_uid": self.target_uid,
            "frame_origin_verified": self.frame_origin_verified,
            "bridge_call_verified": self.bridge_call_verified,
            "gaps": list(self.gaps),
            "limitations": list(self.limitations),
        }


def target_observation_contract(frame: str) -> dict[str, Any]:
    """Describe the supported adapter without promising universal APK support."""

    return {
        "schema_version": "1.0",
        "required_for_execution": "correlated_target_main_frame_url",
        "supported_adapters": [_ADAPTER_ID],
        "adapter_scope": "target-app-emitted logcat line with a verified Linux UID",
        "missing_adapter_result": "oracle_gap",
        "iframe_calling_origin_supported": False,
        "selected_frame": frame,
        "not_proven": ["iframe_calling_origin", "bridge_invocation", "native_effect"],
    }


def _unverified(reason: str, *, adapter_id: str | None = None) -> TargetWebObservation:
    return TargetWebObservation(
        status="unverified",
        trust_tier="none",
        adapter_id=adapter_id,
        main_frame_url=None,
        target_uid=None,
        frame_origin_verified=False,
        bridge_call_verified=False,
        gaps=(reason,),
    )


def assess_target_web_observation(
    *,
    evidence_kind: str,
    stdout: str,
    oracle: Any,
    experiment_id: str,
    attack_nonce: str,
    observer_origin: str,
    frame: str,
) -> TargetWebObservation:
    """Check a trusted artifact for the one currently supported target adapter.

    The caller must separately validate artifact integrity, scan/task/device and
    request ownership, collection time, and PoC process identity. No callback or
    page request is accepted as target-side evidence here.
    """

    if evidence_kind != "blackbox.poc_target_logcat":
        return _unverified("No supported target-side Web observation adapter for this evidence kind")
    if not isinstance(oracle, dict) or oracle.get("kind") != "target_uid_log_contains":
        return _unverified("Target logcat evidence lacks the platform target-UID oracle", adapter_id=_ADAPTER_ID)
    if oracle.get("matched") is not True:
        return _unverified("Target-UID log oracle did not match", adapter_id=_ADAPTER_ID)
    observation = oracle.get("observation")
    target_uid = observation.get("target_uid") if isinstance(observation, dict) else None
    if isinstance(target_uid, bool) or not isinstance(target_uid, int) or target_uid <= 0:
        return _unverified("Target-UID log oracle has no valid numeric UID", adapter_id=_ADAPTER_ID)

    parsed_origin = urlsplit(observer_origin)
    if (
        parsed_origin.scheme not in {"http", "https"}
        or not parsed_origin.netloc
        or parsed_origin.username is not None
        or parsed_origin.password is not None
        or parsed_origin.path not in {"", "/"}
        or parsed_origin.query
        or parsed_origin.fragment
    ):
        return _unverified("Frozen observer origin is invalid", adapter_id=_ADAPTER_ID)

    expected_path = f"/web-observer/{experiment_id}/attack/page"
    matched_url: str | None = None
    for line in stdout.splitlines():
        if AdbDeviceAdapter._logcat_line_uid(line) != target_uid:
            continue
        match = _PAGE_FINISHED_URL.search(line)
        if match is None:
            continue
        candidate = match.group(1)
        parsed = urlsplit(candidate)
        try:
            query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
        except ValueError:
            continue
        if (
            parsed.scheme == parsed_origin.scheme
            and parsed.netloc == parsed_origin.netloc
            and parsed.username is None
            and parsed.password is None
            and parsed.path == expected_path
            and parsed.fragment == ""
            and query == {"nonce": [attack_nonce]}
        ):
            matched_url = candidate

    if matched_url is None:
        return _unverified(
            "No target-UID onPageFinished log matched the frozen observer origin, page, and nonce",
            adapter_id=_ADAPTER_ID,
        )
    gaps = (
        ("Target main-frame log does not verify the calling iframe origin",)
        if frame == "iframe" else ()
    )
    return TargetWebObservation(
        status="observed",
        trust_tier="target_uid_app_log",
        adapter_id=_ADAPTER_ID,
        main_frame_url=matched_url,
        target_uid=target_uid,
        frame_origin_verified=False,
        bridge_call_verified=False,
        gaps=gaps,
    )
