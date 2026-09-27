from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

from apkscanner.core.db import Database
from apkscanner.core.models import (
    EntryPoint,
    Evidence,
    Finding,
    InvestigationTask,
    ProofAttempt,
    Scan,
    SecurityHypothesis,
)
from apkscanner.core.schemas import AdaptiveVerificationResult, SemanticProofAssessment
from apkscanner.infrastructure.artifacts import ArtifactStore
from apkscanner.runtime.orchestrator import ScanOrchestrator
from apkscanner.runtime.semantic_judge import judge_notification_is_model_only
from apkscanner.runtime.semantic_proof_policy import (
    CONTROLLED_CANARY_APK_SHA256,
    evaluate_semantic_proof,
    semantic_proposal_digest,
)
from apkscanner.runtime.static_source_receipts import capture_static_source_excerpt


def _fixture(tmp_path):  # noqa: ANN001
    scan_id = str(uuid4())
    task_id = str(uuid4())
    finding_id = str(uuid4())
    hypothesis_id = str(uuid4())
    experiment_id = "web-exp-12345678"
    nonce = "platform-nonce-1234567890"
    phase_nonce = "attack-phase-nonce-1234567890"
    request_id = "platform-request-12345678"
    serial = "device-serial-1"
    t0 = datetime(2026, 9, 24, 12, tzinfo=UTC)
    fixture_id = str(uuid4())
    target_package = "io.apkscanner.adaptivecases"
    target_apk_sha256 = CONTROLLED_CANARY_APK_SHA256
    target_token = "controlled-target-canary-8f2c-1234567890"
    token_sha256 = hashlib.sha256(target_token.encode()).hexdigest()
    attack_url = (
        f"https://ci-proof.example.test/web-observer/{experiment_id}/attack/page"
        f"?nonce={phase_nonce}"
    )
    attack_url_sha256 = hashlib.sha256(attack_url.encode()).hexdigest()
    finding = Finding(id=finding_id, scan_id=scan_id, dedupe_key="semantic-test")
    hypothesis = SecurityHypothesis(
        id=hypothesis_id,
        scan_id=scan_id,
        task_id=str(uuid4()),
        fingerprint="a" * 64,
        category="android.webview",
        claim="Attacker page receives a target-owned session value.",
        final_finding_id=finding_id,
    )

    def evidence(kind, text, seconds, *, metadata=None, evidence_task_id=task_id):
        evidence_id = str(uuid4())
        content = json.dumps({"body": text}, ensure_ascii=False).encode()
        path = tmp_path / f"{evidence_id}.json"
        path.write_bytes(content)
        return Evidence(
            id=evidence_id,
            scan_id=scan_id,
            task_id=evidence_task_id,
            kind=kind,
            path=str(path),
            sha256=hashlib.sha256(content).hexdigest(),
            metadata_json=metadata or {},
            created_at=t0 + timedelta(seconds=seconds),
        )

    def rewrite(item, document):  # noqa: ANN001, ANN202
        content = json.dumps(document, ensure_ascii=False).encode()
        path = tmp_path / f"{item.id}.json"
        path.write_bytes(content)
        item.path = str(path)
        item.sha256 = hashlib.sha256(content).hexdigest()

    scope = {
        "source": "platform_web_observer",
        "finding_id": finding_id,
        "hypothesis_id": hypothesis_id,
        "experiment_id": experiment_id,
        "nonce": nonce,
        "device_serial": serial,
    }
    plan = evidence("web.experiment.plan", f"frozen plan with {nonce}", 0, metadata=scope)
    state_metadata = {
        **scope,
        "fixture_id": fixture_id,
        "fixture_type": "canary",
        "target_state_source": "controlled_canary_seed_pending",
        "victim_state": "controlled canary fixture",
        "state_check_digest": "b" * 64,
        "expected_exit_code": 0,
        "fixture_state_verified": True,
    }
    fixture_state = evidence(
        "web.experiment.fixture_state", "Session active", -1, metadata=state_metadata,
    )
    fixture_state.exit_code = 0
    rewrite(fixture_state, {
        "exit_code": 0,
        "stdout": "Session active",
        "timed_out": False,
        "canceled": False,
        "metadata": state_metadata,
    })
    identity_scope = {
        **scope,
        "target_package": target_package,
    }
    identity_paths = evidence(
        "web.experiment.apk_identity_paths", "installed package path", -5,
        metadata=identity_scope,
    )
    identity_paths.exit_code = 0
    rewrite(identity_paths, {
        "stdout": "package:/data/app/base.apk",
        "exit_code": 0,
        "timed_out": False,
        "canceled": False,
        "metadata": identity_scope,
    })
    identity_hash = evidence(
        "web.experiment.apk_identity_hash", "installed package hash", -4,
        metadata=identity_scope,
    )
    identity_hash.exit_code = 0
    rewrite(identity_hash, {
        "stdout": f"{target_apk_sha256}  /data/app/base.apk",
        "exit_code": 0,
        "timed_out": False,
        "canceled": False,
        "metadata": identity_scope,
    })
    identity = evidence(
        "web.experiment.apk_identity", "installed APK matches scan SHA-256", -3,
        metadata={
            **identity_scope,
            "target_apk_sha256": target_apk_sha256,
            "verified": True,
        },
    )
    rewrite(identity, {
        "verified": True,
        "target_package": target_package,
        "target_apk_sha256": target_apk_sha256,
        "expected_sha256": target_apk_sha256,
        "installed_sha256": target_apk_sha256,
        "installed_apk_path": "/data/app/base.apk",
        "source_evidence_ids": [identity_paths.id, identity_hash.id],
    })
    seed_metadata = {
        **scope,
        "fixture_id": fixture_id,
        "target_package": target_package,
        "target_apk_sha256": target_apk_sha256,
        "apk_identity_evidence_id": identity.id,
        "token_sha256": token_sha256,
        "seed_verified": True,
    }
    seed = evidence("web.experiment.canary_seed", "seeded controlled canary", -2, metadata=seed_metadata)
    rewrite(seed, {
        "experiment_id": experiment_id,
        "fixture_id": fixture_id,
        "target_package": target_package,
        "target_apk_sha256": target_apk_sha256,
        "apk_identity_evidence_id": identity.id,
        "token_sha256": token_sha256,
        "seed_verified": True,
    })
    rewrite(plan, {
        "schema_version": "1.0",
        "experiment_id": experiment_id,
        "nonce": nonce,
        "target_package": target_package,
        "target_apk_sha256": target_apk_sha256,
        "attack_url": attack_url,
        "apk_identity_evidence_id": identity.id,
        "plan": {
            "finding_id": finding_id,
            "hypothesis_id": hypothesis_id,
            "bridge_name": "AccountBridge",
            "method": "getSessionToken",
            "victim_state": "controlled canary fixture",
            "fixture_id": fixture_id,
            "frame": "top",
        },
        "state_fixture": {
            "fixture_id": fixture_id,
            "fixture_type": "canary",
            "victim_state": "controlled canary fixture",
            "target_state_source": "controlled_canary_seed_pending",
            "state_check_evidence_id": fixture_state.id,
            "state_check_digest": "b" * 64,
            "verified": True,
        },
        "controlled_canary": {
            "seed_evidence_id": seed.id,
            "token_sha256": token_sha256,
            "seed_verified": True,
            "target_apk_sha256": target_apk_sha256,
            "apk_identity_evidence_id": identity.id,
            "mode": "controlled_dump_protected_fixture_only",
        },
    })
    execution = evidence(
        "web.experiment.execution",
        "ordinary application launched the target process",
        10,
        metadata={
            **scope,
            "ordinary_app_uid_verified": True,
            "target_process_observed": True,
            "webview_in_target_confirmed": True,
            "request_id": request_id,
            "final_url": "https://ci-proof.example.test/web-observer/web-exp-12345678/attack/page",
            "target_observation": {
                "status": "observed",
                "trust_tier": "target_uid_app_log",
                "adapter_id": "target_uid_on_page_finished_log_v1",
                "main_frame_url": "https://ci-proof.example.test/web-observer/web-exp-12345678/attack/page",
                "frame_origin_verified": False,
            },
        },
    )
    callback = evidence(
        "web.experiment.event",
        "bridge callback returned controlled account canary",
        15,
        metadata={
            **scope,
            "stage": "callback",
            "phase": "attack",
            "event_type": "bridge_return",
            "phase_nonce": phase_nonce,
            "received_at": (t0 + timedelta(seconds=15)).isoformat(),
        },
    )
    rewrite(callback, {
        "body": "bridge callback returned controlled account canary",
        "client_payload": {"value_sha256": token_sha256, "value_length": len(target_token)},
    })
    effect_metadata = {
        **scope,
        "fixture_id": fixture_id,
        "target_package": target_package,
        "target_apk_sha256": target_apk_sha256,
        "callback_evidence_id": callback.id,
        "seed_evidence_id": seed.id,
        "value_sha256": token_sha256,
        "effect_kind": "target_value_match",
        "bridge_call_verified": True,
        "bridge_url_sha256": attack_url_sha256,
        "target_owned_effect_validated": True,
    }
    effect = evidence(
        "web.experiment.target_effect",
        "target-side canary readback matched the attack callback",
        18,
        metadata=effect_metadata,
    )
    rewrite(effect, {
        "body": "target-side canary readback matched the attack callback",
        "effect_kind": "target_value_match",
        "experiment_id": experiment_id,
        "fixture_id": fixture_id,
        "target_package": target_package,
        "target_apk_sha256": target_apk_sha256,
        "seed_evidence_id": seed.id,
        "callback_evidence_id": callback.id,
        "value_sha256": token_sha256,
        "seed_verified": True,
        "target_readback_verified": True,
        "bridge_calls": 1,
        "bridge_url_sha256": attack_url_sha256,
        "bridge_call_verified": True,
        "callback_value_matched": True,
        "target_owned_effect_validated": True,
    })
    cleanup = evidence(
        "web.experiment.canary_cleanup", "controlled canary cleared", 19,
        metadata={
            **scope,
            "fixture_id": fixture_id,
            "cleared": True,
        },
    )
    rewrite(cleanup, {
        "experiment_id": experiment_id,
        "fixture_id": fixture_id,
        "seed_evidence_id": seed.id,
        "target_package": target_package,
        "target_apk_sha256": target_apk_sha256,
        "cleared": True,
    })
    control = evidence(
        "web.experiment.snapshot",
        "Chrome control reported bridge_missing",
        20,
        metadata={**scope, "controls_validated": True},
    )
    source = evidence(
        "static.source_excerpt",
        "getSessionToken returns target account canary",
        -100,
        metadata={
            "source": "platform_static_source",
            "finding_id": finding_id,
            "hypothesis_id": hypothesis_id,
            "static_output_usable": True,
        },
    )
    device_scope = {"device_serial": serial, "request_id": request_id}
    launch = evidence(
        "blackbox.poc_launch",
        "ordinary app launched attack URL",
        8,
        metadata={
            **device_scope,
            "caller_identity": "agent_poc_app",
            "launch_started_at": (t0 + timedelta(seconds=7)).isoformat(),
        },
    )
    launch.exit_code = 0
    process = evidence(
        "blackbox.poc_process",
        "PoC process 1234 remained active",
        9,
        metadata={**device_scope, "process_ids": [1234]},
    )
    process.exit_code = 0
    confirmation = evidence(
        "blackbox.poc_target_logcat",
        f"target UID onPageFinished URL contains {phase_nonce}",
        12,
        metadata={
            **device_scope,
            "oracle": {
                "kind": "target_uid_log_contains",
                "matched": True,
                "observation": {"target_uid": 10123},
            },
        },
    )
    target_process = evidence(
        "web.experiment.target_process",
        "target process 5678 observed",
        13,
        metadata=device_scope,
    )
    target_process.exit_code = 0
    execution.metadata_json = {
        **execution.metadata_json,
        "launch_evidence_id": launch.id,
        "process_evidence_id": process.id,
        "webview_confirmation_evidence_id": confirmation.id,
        "target_process_evidence_id": target_process.id,
    }
    assessment = SemanticProofAssessment(
        hypothesis_id=hypothesis_id,
        experiment_id=experiment_id,
        claim="An attacker page reads the target account session canary.",
        attacker="ordinary_app",
        victim_state="controlled canary fixture",
        boundary="Attacker-controlled WebView page crosses the native session boundary.",
        impact="unauthorized_data_access",
        provenance="The cited static method returns target account state, while the callback contains the matching canary.",
        alternatives_considered="The Chrome and quiet-page controls exclude page hardcoding, stale callback, and a direct Observer request.",
        execution=[
            {
                "evidence_id": execution.id,
                "excerpt": "ordinary application launched the target process",
            }
        ],
        effect=[
            {"evidence_id": callback.id, "excerpt": "bridge callback returned controlled account canary"},
            {"evidence_id": effect.id, "excerpt": "target-side canary readback matched the attack callback"},
            {"evidence_id": source.id, "excerpt": "getSessionToken returns target account canary"},
        ],
        controls=[
            {
                "evidence_id": control.id,
                "excerpt": "Chrome control reported bridge_missing",
            }
        ],
        replay_steps=["Open the frozen attack URL from an ordinary application."],
    )
    review = evidence(
        "semantic.judge.response",
        "Independent judge accepted the target provenance.",
        25,
        metadata={
            "source": "platform_semantic_judge",
            "read_only": True,
            "finding_id": finding_id,
            "proposal_digest": semantic_proposal_digest(assessment),
            "accepted": True,
            "frozen_evidence_ids": [
                plan.id, fixture_state.id, identity_paths.id, identity_hash.id,
                identity.id, seed.id, execution.id, callback.id,
                effect.id, cleanup.id, control.id, source.id,
            ],
        },
    )
    by_id = {
        item.id: item
        for item in (
            plan,
            fixture_state,
            identity_paths,
            identity_hash,
            identity,
            seed,
            execution,
            callback,
            effect,
            cleanup,
            control,
            source,
            review,
            launch,
            process,
            confirmation,
            target_process,
        )
    }
    return (
        {
            "finding": finding,
            "hypothesis": hypothesis,
            "proposal": assessment,
            "reviewed": assessment,
            "review_evidence": review,
            "evidence_by_id": by_id,
            "verifier_task_id": task_id,
            "device_serial": serial,
            "dynamic_verdict_eligible": True,
        },
        callback,
        control,
    )


def test_semantic_proof_requires_separate_judge_and_correlated_controls(tmp_path) -> None:  # noqa: ANN001
    inputs, callback, control = _fixture(tmp_path)
    accepted = evaluate_semantic_proof(**inputs)
    assert accepted.eligible is True
    assert accepted.nonce == "platform-nonce-1234567890"
    assert callback.id in accepted.evidence_ids

    assert evaluate_semantic_proof(**{**inputs, "review_evidence": None}).eligible is False
    control.metadata_json = {**control.metadata_json, "controls_validated": False}
    rejected = evaluate_semantic_proof(**inputs)
    assert rejected.eligible is False
    assert "missing_validated_negative_controls" in rejected.reasons


def test_static_source_and_page_callback_do_not_prove_target_value(tmp_path) -> None:  # noqa: ANN001
    inputs, _, _ = _fixture(tmp_path)
    effect = next(
        item for item in inputs["evidence_by_id"].values()
        if item.kind == "web.experiment.target_effect"
    )
    effect.metadata_json["target_owned_effect_validated"] = False
    denied = evaluate_semantic_proof(**inputs)
    assert denied.eligible is False
    assert any(reason.startswith("invalid_target_effect_receipt:") for reason in denied.reasons)
    assert "data_access_requires_independent_target_value" in denied.reasons


def test_fixture_label_cannot_substitute_for_a_verified_device_state(tmp_path) -> None:  # noqa: ANN001
    inputs, _, _ = _fixture(tmp_path)
    state = next(
        item for item in inputs["evidence_by_id"].values()
        if item.kind == "web.experiment.fixture_state"
    )
    state.metadata_json["fixture_state_verified"] = False
    denied = evaluate_semantic_proof(**inputs)
    assert "fixture_state_not_independently_verified" in denied.reasons
    state.metadata_json["fixture_state_verified"] = True
    state.task_id = str(uuid4())
    denied = evaluate_semantic_proof(**inputs)
    assert "fixture_state_not_independently_verified" in denied.reasons
    state.task_id = inputs["verifier_task_id"]
    reviewed = inputs["reviewed"].model_copy(update={"victim_state": "guest"})
    denied = evaluate_semantic_proof(**{**inputs, "reviewed": reviewed})
    assert "reviewed_victim_state_differs_from_frozen_plan" in denied.reasons


def test_hardcoded_callback_cannot_match_frozen_target_readback(tmp_path) -> None:  # noqa: ANN001
    inputs, callback, _ = _fixture(tmp_path)
    payload = json.loads((tmp_path / f"{callback.id}.json").read_text())
    payload["client_payload"]["value_sha256"] = hashlib.sha256(
        b"attacker-hardcoded-success-token-123456"
    ).hexdigest()
    raw = json.dumps(payload).encode()
    (tmp_path / f"{callback.id}.json").write_bytes(raw)
    callback.sha256 = hashlib.sha256(raw).hexdigest()
    denied = evaluate_semantic_proof(**inputs)
    assert denied.eligible is False
    assert any(
        reason.startswith("target_value_not_independently_validated:")
        for reason in denied.reasons
    )


def test_raw_callback_value_cannot_bypass_digest_only_receipt(tmp_path) -> None:  # noqa: ANN001
    inputs, callback, _ = _fixture(tmp_path)
    payload = json.loads((tmp_path / f"{callback.id}.json").read_text())
    payload["client_payload"]["value"] = "client-side-raw-token"
    raw = json.dumps(payload).encode()
    (tmp_path / f"{callback.id}.json").write_bytes(raw)
    callback.sha256 = hashlib.sha256(raw).hexdigest()
    denied = evaluate_semantic_proof(**inputs)
    assert denied.eligible is False
    assert any(
        reason.startswith("target_value_not_independently_validated:")
        for reason in denied.reasons
    )


def test_controlled_canary_rejects_wrong_installed_apk_hash(tmp_path) -> None:  # noqa: ANN001
    inputs, _, _ = _fixture(tmp_path)
    installed = next(
        item for item in inputs["evidence_by_id"].values()
        if item.kind == "web.experiment.apk_identity_hash"
    )
    payload = json.loads((tmp_path / f"{installed.id}.json").read_text())
    payload["stdout"] = f"{'c' * 64}  /data/app/base.apk"
    raw = json.dumps(payload).encode()
    (tmp_path / f"{installed.id}.json").write_bytes(raw)
    installed.sha256 = hashlib.sha256(raw).hexdigest()
    denied = evaluate_semantic_proof(**inputs)
    assert denied.eligible is False
    assert any(
        reason.startswith("target_value_not_independently_validated:")
        for reason in denied.reasons
    )


def test_controlled_canary_proof_requires_successful_cleanup(tmp_path) -> None:  # noqa: ANN001
    inputs, _, _ = _fixture(tmp_path)
    cleanup = next(
        item for item in inputs["evidence_by_id"].values()
        if item.kind == "web.experiment.canary_cleanup"
    )
    cleanup.metadata_json["cleared"] = False
    denied = evaluate_semantic_proof(**inputs)
    assert denied.eligible is False
    assert any(
        reason.startswith("target_value_not_independently_validated:")
        for reason in denied.reasons
    )


def test_void_or_state_change_claim_needs_a_pre_post_target_effect(tmp_path) -> None:  # noqa: ANN001
    inputs, _, _ = _fixture(tmp_path)
    state_claim = inputs["proposal"].model_copy(
        update={"impact": "unauthorized_state_change"}
    )
    review = inputs["review_evidence"]
    review.metadata_json["proposal_digest"] = semantic_proposal_digest(state_claim)
    denied = evaluate_semantic_proof(**{
        **inputs, "proposal": state_claim, "reviewed": state_claim,
    })
    assert denied.eligible is False
    assert "state_change_requires_independent_target_effect" in denied.reasons


def test_target_main_frame_log_does_not_verify_iframe_calling_origin(tmp_path) -> None:  # noqa: ANN001
    inputs, _, _ = _fixture(tmp_path)
    plan = next(
        item for item in inputs["evidence_by_id"].values()
        if item.kind == "web.experiment.plan"
    )
    payload = json.loads((tmp_path / f"{plan.id}.json").read_text())
    payload["plan"]["frame"] = "iframe"
    raw = json.dumps(payload).encode()
    (tmp_path / f"{plan.id}.json").write_bytes(raw)
    plan.sha256 = hashlib.sha256(raw).hexdigest()
    denied = evaluate_semantic_proof(**inputs)
    assert "calling_frame_origin_not_confirmed" in denied.reasons


def test_semantic_gate_binds_method_to_validated_frozen_web_request(tmp_path) -> None:  # noqa: ANN001
    inputs, _, _ = _fixture(tmp_path)
    accepted = evaluate_semantic_proof(**inputs)
    assert accepted.eligible is True
    assert accepted.bridge_method == "AccountBridge.getSessionToken"
    plan = next(
        item for item in inputs["evidence_by_id"].values()
        if item.kind == "web.experiment.plan"
    )
    payload = json.loads((tmp_path / f"{plan.id}.json").read_text())
    payload["plan"]["method"] = "setTransferEnabled"
    raw = json.dumps(payload).encode()
    (tmp_path / f"{plan.id}.json").write_bytes(raw)
    plan.sha256 = hashlib.sha256(raw).hexdigest()
    changed = evaluate_semantic_proof(**inputs)
    assert changed.eligible is True
    assert changed.bridge_method == "AccountBridge.setTransferEnabled"
    del payload["plan"]["method"]
    raw = json.dumps(payload).encode()
    (tmp_path / f"{plan.id}.json").write_bytes(raw)
    plan.sha256 = hashlib.sha256(raw).hexdigest()
    rejected = evaluate_semantic_proof(**inputs)
    assert rejected.eligible is False
    assert "frozen_web_request_invalid" in rejected.reasons


def test_remote_web_plan_requires_frozen_nonce_bound_deployment_receipt(tmp_path) -> None:  # noqa: ANN001
    inputs, _callback, control = _fixture(tmp_path)
    plan = next(
        item for item in inputs["evidence_by_id"].values()
        if item.kind == "web.experiment.plan"
    )
    deployment_id = "remote-deployment-1"
    origin = "https://ci-proof.example.test"
    plan_document = {
        **json.loads((tmp_path / f"{plan.id}.json").read_text()),
        "observer_transport": "ssh_reverse_https",
        "remote_deployment_id": deployment_id,
    }
    plan_raw = json.dumps(plan_document).encode()
    plan_path = tmp_path / "remote-plan.json"
    plan_path.write_bytes(plan_raw)
    plan.path = str(plan_path)
    plan.sha256 = hashlib.sha256(plan_raw).hexdigest()

    receipt_document = {
        "schema_version": "1.0",
        "action": "deploy",
        "experiment_id": inputs["proposal"].experiment_id,
        "deployment_id": deployment_id,
        "tunnel_id": "remote-tunnel-1",
        "root_nonce": plan.metadata_json["nonce"],
        "status": "healthy",
        "public_probe_ok": True,
        "public_base_url": origin,
    }
    receipt_raw = json.dumps(receipt_document).encode()
    receipt_path = tmp_path / "remote-receipt.json"
    receipt_path.write_bytes(receipt_raw)
    receipt = Evidence(
        id=str(uuid4()),
        scan_id=inputs["finding"].scan_id,
        task_id=inputs["verifier_task_id"],
        kind="web.experiment.remote_receipt",
        path=str(receipt_path),
        sha256=hashlib.sha256(receipt_raw).hexdigest(),
        metadata_json={
            **plan.metadata_json,
            "stage": "remote_deploy",
            "deployment_id": deployment_id,
            "tunnel_id": "remote-tunnel-1",
            "public_probe_ok": True,
        },
        created_at=plan.created_at - timedelta(seconds=1),
    )
    inputs["evidence_by_id"][receipt.id] = receipt
    snapshot_raw = json.dumps({
        "schema_version": "1.0",
        "experiment_id": inputs["proposal"].experiment_id,
        "controls_validated": True,
        "control_gaps": [],
        "body": "Chrome control reported bridge_missing",
    }).encode()
    snapshot_path = tmp_path / "remote-snapshot.json"
    snapshot_path.write_bytes(snapshot_raw)
    control.path = str(snapshot_path)
    control.sha256 = hashlib.sha256(snapshot_raw).hexdigest()
    health_document = {
        **receipt_document,
        "action": "health",
    }
    health_raw = json.dumps(health_document).encode()
    health_path = tmp_path / "remote-health.json"
    health_path.write_bytes(health_raw)
    health = Evidence(
        id=str(uuid4()),
        scan_id=receipt.scan_id,
        task_id=receipt.task_id,
        kind="web.experiment.remote_receipt",
        path=str(health_path),
        sha256=hashlib.sha256(health_raw).hexdigest(),
        metadata_json={**receipt.metadata_json, "stage": "remote_health"},
        created_at=control.created_at - timedelta(seconds=1),
    )
    inputs["evidence_by_id"][health.id] = health
    review = inputs["review_evidence"]
    review.metadata_json["frozen_evidence_ids"].extend((receipt.id, health.id))
    accepted = evaluate_semantic_proof(**inputs)
    assert accepted.eligible is True
    assert receipt.id in accepted.evidence_ids
    assert health.id in accepted.evidence_ids

    receipt.metadata_json["public_probe_ok"] = False
    denied = evaluate_semantic_proof(**inputs)
    assert denied.eligible is False
    assert "remote_deployment_receipt_not_attributable" in denied.reasons
    receipt.metadata_json["public_probe_ok"] = True
    health.metadata_json["public_probe_ok"] = False
    denied = evaluate_semantic_proof(**inputs)
    assert "remote_snapshot_health_receipt_not_attributable" in denied.reasons
    health.metadata_json["public_probe_ok"] = True
    review.metadata_json["frozen_evidence_ids"].remove(health.id)
    assert evaluate_semantic_proof(**inputs).eligible is False
    review.metadata_json["frozen_evidence_ids"].append(health.id)
    review.metadata_json["frozen_evidence_ids"].remove(receipt.id)
    assert evaluate_semantic_proof(**inputs).eligible is False


def test_semantic_proof_rejects_cross_experiment_and_fabricated_excerpt(tmp_path) -> None:  # noqa: ANN001
    inputs, callback, _ = _fixture(tmp_path)
    callback.metadata_json = {**callback.metadata_json, "nonce": "other-experiment-nonce"}
    rejected = evaluate_semantic_proof(**inputs)
    assert rejected.eligible is False
    assert any(reason.startswith("experiment_scope_mismatch:") for reason in rejected.reasons)

    inputs, callback, _ = _fixture(tmp_path)
    callback.path = str(tmp_path / "missing.json")
    rejected = evaluate_semantic_proof(**inputs)
    assert rejected.eligible is False
    assert any(reason.startswith("excerpt_not_in_artifact:") for reason in rejected.reasons)


def test_semantic_proof_keeps_unresolved_claim_as_oracle_gap(tmp_path) -> None:  # noqa: ANN001
    inputs, _, _ = _fixture(tmp_path)
    reviewed = inputs["reviewed"].model_copy(
        update={
            "unresolved_obligations": ["Target origin of the returned value is unknown"],
        }
    )
    rejected = evaluate_semantic_proof(**{**inputs, "reviewed": reviewed})
    assert rejected.eligible is False
    assert "unresolved_semantic_obligations" in rejected.reasons


def test_page_callback_cannot_substitute_for_target_webview_receipt(tmp_path) -> None:  # noqa: ANN001
    inputs, _, _ = _fixture(tmp_path)
    execution = next(
        item
        for item in inputs["evidence_by_id"].values()
        if item.kind == "web.experiment.execution"
    )
    execution.metadata_json = {
        **execution.metadata_json,
        "webview_in_target_confirmed": False,
    }
    rejected = evaluate_semantic_proof(**inputs)
    assert rejected.eligible is False
    assert "target_webview_load_not_confirmed" in rejected.reasons


def test_semantic_proof_rejects_other_hypothesis_evidence(tmp_path) -> None:  # noqa: ANN001
    inputs, callback, _ = _fixture(tmp_path)
    callback.metadata_json = {
        **callback.metadata_json,
        "hypothesis_id": str(uuid4()),
    }
    rejected = evaluate_semantic_proof(**inputs)
    assert rejected.eligible is False
    assert any(reason.startswith("experiment_scope_mismatch:") for reason in rejected.reasons)


def test_judge_cannot_cite_evidence_it_did_not_receive(tmp_path) -> None:  # noqa: ANN001
    inputs, callback, _ = _fixture(tmp_path)
    review = inputs["review_evidence"]
    review.metadata_json = {
        **review.metadata_json,
        "frozen_evidence_ids": [
            item for item in review.metadata_json["frozen_evidence_ids"] if item != callback.id
        ],
    }
    rejected = evaluate_semantic_proof(**inputs)
    assert rejected.eligible is False
    assert "judge_cited_evidence_outside_frozen_record" in rejected.reasons


def test_static_source_excerpt_is_bounded_to_indexed_scan_code(tmp_path) -> None:  # noqa: ANN001
    workspace = tmp_path / "scan-workspace"
    source_path = workspace / "jadx" / "sources" / "demo" / "Bridge.java"
    source_path.parent.mkdir(parents=True)
    source_path.write_text(
        "class Bridge {\n  String getSessionToken() {\n    return account.token;\n  }\n}\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
    captured = capture_static_source_excerpt(
        scan_workspace=workspace,
        relative_path="jadx/sources/demo/Bridge.java",
        line_start=3,
        expected_sha256=digest,
    )
    assert captured is not None
    assert "return account.token" in captured.text
    assert captured.source_sha256 == digest
    assert (
        capture_static_source_excerpt(
            scan_workspace=workspace,
            relative_path="jadx/../secrets.java",
            line_start=1,
        )
        is None
    )
    assert (
        capture_static_source_excerpt(
            scan_workspace=workspace,
            relative_path="jadx/sources/demo/Bridge.java",
            line_start=3,
            expected_sha256="0" * 64,
        )
        is None
    )
    outside = tmp_path / "outside.java"
    outside.write_text("secret", encoding="utf-8")
    (source_path.parent / "Escape.java").symlink_to(outside)
    assert (
        capture_static_source_excerpt(
            scan_workspace=workspace,
            relative_path="jadx/sources/demo/Escape.java",
            line_start=1,
        )
        is None
    )


def test_read_only_judge_rejects_all_tool_lifecycle_events() -> None:
    for item_type in ("commandExecution", "fileChange", "webSearch", "mcpToolCall"):
        notification = SimpleNamespace(method="item/started", payload={"item": {"type": item_type}})
        assert judge_notification_is_model_only(notification) is False
    assert judge_notification_is_model_only(
        SimpleNamespace(method="item/commandExecution/outputDelta", payload={})
    ) is False
    assert judge_notification_is_model_only(
        SimpleNamespace(method="item/agentMessage/textDelta", payload={})
    ) is True
    assert (
        judge_notification_is_model_only(
            SimpleNamespace(method="item/completed", payload={"item": {"type": "agentMessage"}})
        )
        is True
    )
    assert (
        judge_notification_is_model_only(SimpleNamespace(method="turn/diff/updated", payload={}))
        is False
    )


def test_adaptive_verifier_only_platform_gate_creates_semantic_proof(
    settings,
    tmp_path,  # noqa: ANN001
) -> None:
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    inputs, _, _ = _fixture(tmp_path)
    finding = inputs["finding"]
    hypothesis = inputs["hypothesis"]
    proposal = inputs["proposal"]
    task_id = inputs["verifier_task_id"]
    finding.rule_id = "AGENT-ENTRY-INVESTIGATION"
    finding.title = "Target bridge exposes account state"
    finding.description = "A controlled web page may read a target-owned value."
    finding.masvs = "MASVS-PLATFORM"
    finding.severity = "high"
    finding.confidence = "medium"
    finding.status = "runtime_observed_unverified"
    finding.metadata_json = {"hypothesis_id": hypothesis.id}
    review = inputs["review_evidence"]
    review_content = json.dumps(
        {
            "decision": {
                "finding_id": finding.id,
                "proposal_digest": semantic_proposal_digest(proposal),
                "accepted": True,
                "reason": "The target source, callback, and negative controls agree.",
                "assessment": proposal.model_dump(mode="json"),
            },
        }
    ).encode()
    (tmp_path / f"{review.id}.json").write_bytes(review_content)
    review.sha256 = hashlib.sha256(review_content).hexdigest()
    scan = Scan(
        id=finding.scan_id,
        filename="semantic-test.apk",
        package_name="io.apkscanner.adaptivecases",
        artifact_sha256=CONTROLLED_CANARY_APK_SHA256,
        artifact_path=str(tmp_path / "semantic-test.apk"),
        status="investigating",
    )
    source_task = InvestigationTask(
        id=hypothesis.task_id,
        scan_id=scan.id,
        task_type="deep_link",
        status="completed",
    )
    verifier_task = InvestigationTask(
        id=task_id,
        scan_id=scan.id,
        task_type="adaptive_verification",
        status="running",
    )
    source_file = (
        settings.data_dir / "workspaces" / scan.id / "jadx" / "sources" / "demo" / "Bridge.java"
    )
    source_file.parent.mkdir(parents=True)
    source_file.write_text(
        "class Bridge {\n  String getSessionToken() {\n    return account.token;\n  }\n}\n",
        encoding="utf-8",
    )
    entry = EntryPoint(
        id=str(uuid4()),
        scan_id=scan.id,
        kind="deep_link",
        name="demo.BridgeActivity",
        exported=True,
        code_anchors=[
            {
                "path": "jadx/sources/demo/Bridge.java",
                "line_start": 3,
                "line_end": 3,
                "sha256": hashlib.sha256(source_file.read_bytes()).hexdigest(),
            }
        ],
    )
    finding.entry_point_ids = [entry.id]
    with database.session_factory() as session:
        session.add_all([scan, source_task, verifier_task])
        session.flush()
        session.add_all([entry, finding])
        session.flush()
        session.add(hypothesis)
        session.flush()
        session.add_all(inputs["evidence_by_id"].values())
        response = orchestrator.evidence.json(
            session,
            scan_id=scan.id,
            task_id=task_id,
            kind="agent.response",
            value={"assessment": "proposed semantic proof"},
            summary="Model proposal",
        )
        session.commit()
        response_id = response.id

    source_receipts = orchestrator._materialize_semantic_source_receipts(
        scan_id=scan.id,
        task_id=task_id,
        finding_id=finding.id,
        hypothesis_id=hypothesis.id,
    )
    assert len(source_receipts) == 1
    assert source_receipts[0].kind == "static.source_excerpt"
    assert source_receipts[0].metadata_json["source"] == "platform_static_source"

    result = AdaptiveVerificationResult.model_validate(
        {
            "summary": "普通应用触发目标 WebView，独立审查已引用实验回执。",
            "assessments": [
                {
                    "finding_id": finding.id,
                    "verdict": "reproduced_blackbox",
                    "confidence": "high",
                    "runtime_observed": True,
                    "summary": "受控页面收到目标账户值。",
                    "semantic_proof": proposal.model_dump(mode="json"),
                }
            ],
        }
    )
    orchestrator._apply_adaptive_verifier_result(
        scan_id=scan.id,
        task_id=task_id,
        candidate_ids=[finding.id],
        result=result,
        thread_id="verifier-thread",
        turn_id="verifier-turn",
        response_evidence_id=response_id,
        android16_verdict_eligible=True,
        dynamic_verdict_eligible=True,
        release_gate_eligible=True,
        device_serial="device-serial-1",
    )
    with database.session_factory() as session:
        gap_finding = session.get(Finding, finding.id)
        assert gap_finding is not None
        assert gap_finding.status == "runtime_observed_unverified"
        assert session.query(ProofAttempt).filter_by(hypothesis_id=hypothesis.id).count() == 0
    orchestrator._apply_adaptive_verifier_result(
        scan_id=scan.id,
        task_id=task_id,
        candidate_ids=[finding.id],
        result=result,
        thread_id="verifier-thread",
        turn_id="verifier-turn",
        response_evidence_id=response_id,
        android16_verdict_eligible=True,
        dynamic_verdict_eligible=True,
        release_gate_eligible=True,
        semantic_judge_receipts={finding.id: review.id},
        device_serial="device-serial-1",
    )
    with database.session_factory() as session:
        persisted_finding = session.get(Finding, finding.id)
        attempts = list(session.query(ProofAttempt).filter_by(hypothesis_id=hypothesis.id))
        assert persisted_finding is not None
        assert persisted_finding.status == "reproduced_blackbox"
        assert persisted_finding.metadata_json["harm_demonstrated"] is True
        assert len(attempts) == 1
        assert attempts[0].prover == "platform_semantic_attestation"
        assert attempts[0].status == "proven"
        assert attempts[0].harm_demonstrated is True
        assert attempts[0].plan["bridge_method"] == "AccountBridge.getSessionToken"
        assert (
            persisted_finding.metadata_json["adaptive_verification"]["semantic_proof_gate"][
                "eligible"
            ]
            is True
        )
