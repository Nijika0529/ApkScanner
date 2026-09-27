from __future__ import annotations

import pytest
from apkscanner.runtime.web_target_observation import assess_target_web_observation

_EXPERIMENT_ID = "11111111-1111-4111-8111-111111111111"
_NONCE = "A" * 24
_ORIGIN = "https://observer.example.test"
_URL = f"{_ORIGIN}/web-observer/{_EXPERIMENT_ID}/attack/page?nonce={_NONCE}"
_ORACLE = {
    "kind": "target_uid_log_contains",
    "matched": True,
    "observation": {"target_uid": 10123},
}


def _log(url: str, *, uid: int = 10123) -> str:
    return f"09-24 00:00:00.000 {uid} 1234 1234 I APKScannerWebView: onPageFinished {url}"


def _assess(stdout: str, *, frame: str = "top", oracle=None, kind: str = "blackbox.poc_target_logcat"):  # noqa: ANN001, ANN202
    return assess_target_web_observation(
        evidence_kind=kind,
        stdout=stdout,
        oracle=_ORACLE if oracle is None else oracle,
        experiment_id=_EXPERIMENT_ID,
        attack_nonce=_NONCE,
        observer_origin=_ORIGIN,
        frame=frame,
    )


def test_target_uid_log_adapter_confirms_only_app_emitted_main_frame_url() -> None:
    observation = _assess(_log(_URL))
    assert observation.status == "observed"
    assert observation.trust_tier == "target_uid_app_log"
    assert observation.main_frame_url == _URL
    assert observation.target_uid == 10123
    assert observation.frame_origin_verified is False
    assert observation.bridge_call_verified is False
    assert observation.gaps == ()
    assert observation.as_dict()["adapter_id"] == "target_uid_on_page_finished_log_v1"


def test_iframe_main_frame_log_does_not_verify_calling_frame_origin() -> None:
    observation = _assess(_log(_URL), frame="iframe")
    assert observation.status == "observed"
    assert observation.main_frame_url == _URL
    assert observation.frame_origin_verified is False
    assert "iframe origin" in observation.gaps[0]


@pytest.mark.parametrize(
    "stdout",
    [
        "",
        _log(_URL, uid=10124),
        _log(_URL.replace(_NONCE, "B" * 24)),
        _log(_URL.replace("observer.example.test", "observer.example.test.evil")),
        _log(_URL.replace("/attack/page", "/attack/frame")),
        _log(_URL + "&success=true"),
        _log(_URL + "#fake"),
    ],
)
def test_target_log_adapter_rejects_missing_or_misattributed_page(stdout: str) -> None:
    observation = _assess(stdout)
    assert observation.status == "unverified"
    assert observation.trust_tier == "none"
    assert observation.main_frame_url is None
    assert observation.gaps


def test_target_log_adapter_does_not_promote_client_or_unverified_log_source() -> None:
    assert _assess(_log(_URL), kind="web.experiment.event").status == "unverified"
    assert _assess(_log(_URL), oracle={**_ORACLE, "matched": False}).status == "unverified"
    assert _assess(
        _log(_URL),
        oracle={**_ORACLE, "observation": {"target_uid": True}},
    ).status == "unverified"
