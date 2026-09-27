from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import ValidationError

from ..core.models import Evidence, Finding, SecurityHypothesis
from ..core.schemas import (
    SemanticEvidenceCitation,
    SemanticProofAssessment,
    WebExperimentRequest,
)

_MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
_MAX_EXPERIMENT_AGE = timedelta(hours=2)
# This exact signed, non-debuggable fixture build enforces shell UID inside the
# DUMP-protected Provider. Older builds could grant DUMP to an ordinary APK.
CONTROLLED_CANARY_APK_SHA256 = "0beb75fd3f90dfcb0459cb978368210e8ce52737eb790f5e3749f473531575d1"
_WEB_KINDS = frozenset(
    {
        "web.experiment.plan",
        "web.experiment.execution",
        "web.experiment.event",
        "web.experiment.snapshot",
        "web.experiment.target_effect",
    }
)
_SELF_REPORT_KINDS = frozenset(
    {
        "agent.request",
        "agent.response",
        "agent.events",
        "runtime.observation",
    }
)


@dataclass(frozen=True, slots=True)
class SemanticProofGate:
    eligible: bool
    reasons: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    experiment_id: str
    nonce: str | None
    device_serial: str | None
    bridge_method: str | None = None


def semantic_proposal_digest(assessment: SemanticProofAssessment) -> str:
    """Bind the separate review to the exact experiment claim it considered."""

    payload = assessment.model_dump_json(exclude_none=False)
    return hashlib.sha256(payload.encode()).hexdigest()


def evidence_excerpt_matches(evidence: Evidence, citation: SemanticEvidenceCitation) -> bool:
    """Check cited text against immutable artifact bytes, not a model summary."""

    path = Path(evidence.path)
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_ARTIFACT_BYTES:
            return False
        raw = path.read_bytes()
    except OSError:
        return False
    if hashlib.sha256(raw).hexdigest() != evidence.sha256:
        return False
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if citation.excerpt in content:
        return True
    # EvidenceRecorder stores command stdout and HTTP bodies inside JSON. JSON
    # escapes newlines and quotes, while a citation may use the original text.
    try:
        document = json.loads(content)
    except json.JSONDecodeError:
        return False

    def contains(value: object) -> bool:
        if isinstance(value, str):
            return citation.excerpt in value
        if isinstance(value, list):
            return any(contains(item) for item in value)
        if isinstance(value, dict):
            return any(contains(item) for item in value.values())
        return False

    return contains(document)


def _evidence_json_object(evidence: Evidence) -> dict | None:
    """Read a platform artifact only when its stored digest still matches."""

    path = Path(evidence.path)
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_ARTIFACT_BYTES:
            return None
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != evidence.sha256:
            return None
        value = json.loads(raw)
    except (OSError, ValueError, UnicodeError):
        return None
    return value if isinstance(value, dict) else None


def _time(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return _time(datetime.fromisoformat(value))
    except ValueError:
        return None


def _controlled_apk_identity_sources(
    *,
    identity_id: object,
    evidence_by_id: Mapping[str, Evidence],
    frozen_ids: object,
    scan_id: str,
    task_id: str,
    finding_id: str,
    hypothesis_id: str,
    experiment_id: str,
    nonce: str | None,
    device_serial: str | None,
    target_package: str,
    target_apk_sha256: str,
    plan_created_at: datetime,
) -> tuple[str, ...] | None:
    """Recheck a target APK SHA against platform-owned device command bytes."""

    if not isinstance(identity_id, str) or not isinstance(frozen_ids, list):
        return None
    identity = evidence_by_id.get(identity_id)
    if identity is None or identity.id not in frozen_ids:
        return None
    meta = identity.metadata_json or {}
    doc = _evidence_json_object(identity)
    if (
        identity.kind != "web.experiment.apk_identity"
        or identity.scan_id != scan_id
        or identity.task_id != task_id
        or meta.get("source") != "platform_web_observer"
        or meta.get("finding_id") != finding_id
        or meta.get("hypothesis_id") != hypothesis_id
        or meta.get("experiment_id") != experiment_id
        or meta.get("nonce") != nonce
        or meta.get("device_serial") != device_serial
        or meta.get("target_package") != target_package
        or meta.get("target_apk_sha256") != target_apk_sha256
        or meta.get("verified") is not True
        or doc is None
        or doc.get("verified") is not True
        or doc.get("target_package") != target_package
        or doc.get("target_apk_sha256") != target_apk_sha256
        or doc.get("expected_sha256") != target_apk_sha256
        or doc.get("installed_sha256") != target_apk_sha256
        or not isinstance(doc.get("installed_apk_path"), str)
        or not doc["installed_apk_path"].startswith("/")
        or _time(identity.created_at) > _time(plan_created_at)
        or _time(plan_created_at) - _time(identity.created_at) > timedelta(minutes=3)
    ):
        return None
    source_ids = doc.get("source_evidence_ids")
    if not isinstance(source_ids, list) or len(source_ids) != 2:
        return None
    expected_kinds = (
        "web.experiment.apk_identity_paths",
        "web.experiment.apk_identity_hash",
    )
    source_docs: list[dict] = []
    for source_id, expected_kind in zip(source_ids, expected_kinds, strict=True):
        source = evidence_by_id.get(source_id) if isinstance(source_id, str) else None
        if source is None or source.id not in frozen_ids:
            return None
        source_meta = source.metadata_json or {}
        source_doc = _evidence_json_object(source)
        if (
            source.kind != expected_kind
            or source.scan_id != scan_id
            or source.task_id != task_id
            or source.exit_code != 0
            or source_meta.get("source") != "platform_web_observer"
            or source_meta.get("experiment_id") != experiment_id
            or source_meta.get("nonce") != nonce
            or source_meta.get("device_serial") != device_serial
            or source_meta.get("target_package") != target_package
            or source_doc is None
            or source_doc.get("metadata") != source_meta
            or source_doc.get("exit_code") != 0
            or source_doc.get("timed_out") is not False
            or source_doc.get("canceled") is not False
            or _time(source.created_at) > _time(identity.created_at)
        ):
            return None
        source_docs.append(source_doc)
    installed_path = doc["installed_apk_path"]
    path_lines = str(source_docs[0].get("stdout", "")).strip().splitlines()
    hash_parts = str(source_docs[1].get("stdout", "")).strip().split()
    if (
        path_lines != [f"package:{installed_path}"]
        or hash_parts != [target_apk_sha256, installed_path]
    ):
        return None
    return identity.id, *source_ids


def evaluate_semantic_proof(
    *,
    finding: Finding,
    hypothesis: SecurityHypothesis | None,
    proposal: SemanticProofAssessment,
    reviewed: SemanticProofAssessment | None,
    review_evidence: Evidence | None,
    evidence_by_id: Mapping[str, Evidence],
    verifier_task_id: str,
    device_serial: str | None,
    dynamic_verdict_eligible: bool,
) -> SemanticProofGate:
    """Apply hard facts after a separate read-only model reviewed frozen evidence.

    This gate deliberately does not attempt to decide whether a value is a token
    or whether a static source implies a security boundary. Those are the
    reviewer's semantic claims. It verifies that the claimed execution, effect,
    and controls are real, attributable receipts from one experiment.
    """

    reasons: list[str] = []
    if reviewed is None or review_evidence is None:
        reasons.append(
            "missing_independent_read_only_judge_receipt"
            if review_evidence is None
            else "independent_judge_rejected_or_incomplete"
        )
        return SemanticProofGate(
            False, tuple(reasons), (), proposal.experiment_id, None, device_serial
        )
    review_metadata = review_evidence.metadata_json or {}
    if (
        review_evidence.scan_id != finding.scan_id
        or review_evidence.task_id != verifier_task_id
        or review_evidence.kind != "semantic.judge.response"
        or review_metadata.get("source") != "platform_semantic_judge"
        or review_metadata.get("read_only") is not True
        or review_metadata.get("finding_id") != finding.id
        or review_metadata.get("proposal_digest") != semantic_proposal_digest(proposal)
        or review_metadata.get("accepted") is not True
    ):
        reasons.append("unattributable_or_rejected_judge_receipt")
    if (
        reviewed.hypothesis_id != proposal.hypothesis_id
        or reviewed.experiment_id != proposal.experiment_id
    ):
        reasons.append("judge_changed_experiment_identity")
    if reviewed.attacker != proposal.attacker or reviewed.impact != proposal.impact:
        reasons.append("judge_changed_claim_scope")
    if reviewed.unresolved_obligations:
        reasons.append("unresolved_semantic_obligations")
    if not dynamic_verdict_eligible or not device_serial:
        reasons.append("device_not_eligible_for_dynamic_verdict")
    if (
        hypothesis is None
        or hypothesis.id != reviewed.hypothesis_id
        or hypothesis.scan_id != finding.scan_id
        or not (
            hypothesis.final_finding_id == finding.id
            or (
                hypothesis.final_finding_id is None
                and (finding.metadata_json or {}).get("hypothesis_id") == hypothesis.id
            )
        )
    ):
        reasons.append("hypothesis_not_bound_to_finding")

    citations = [*reviewed.execution, *reviewed.effect, *reviewed.controls]
    citation_ids = tuple(dict.fromkeys(item.evidence_id for item in citations))
    frozen_ids = review_metadata.get("frozen_evidence_ids")
    if not isinstance(frozen_ids, list) or not set(citation_ids) <= {
        item for item in frozen_ids if isinstance(item, str)
    }:
        reasons.append("judge_cited_evidence_outside_frozen_record")
    cited: dict[str, Evidence] = {}
    for citation in citations:
        evidence = evidence_by_id.get(citation.evidence_id)
        if evidence is None or evidence.scan_id != finding.scan_id:
            reasons.append(f"missing_or_cross_scan_evidence:{citation.evidence_id}")
            continue
        if evidence.kind in _SELF_REPORT_KINDS:
            reasons.append(f"self_report_is_not_proof:{evidence.id}")
            continue
        if not evidence_excerpt_matches(evidence, citation):
            reasons.append(f"excerpt_not_in_artifact:{evidence.id}")
            continue
        cited[evidence.id] = evidence

    plans = [
        evidence
        for evidence in evidence_by_id.values()
        if evidence.kind == "web.experiment.plan"
        and evidence.scan_id == finding.scan_id
        and evidence.task_id == verifier_task_id
        and (evidence.metadata_json or {}).get("finding_id") == finding.id
        and (evidence.metadata_json or {}).get("experiment_id") == reviewed.experiment_id
    ]
    if len(plans) != 1:
        reasons.append("missing_or_ambiguous_frozen_web_plan")
        return SemanticProofGate(
            False,
            tuple(dict.fromkeys(reasons)),
            citation_ids,
            reviewed.experiment_id,
            None,
            device_serial,
        )
    plan = plans[0]
    if plan.id not in (frozen_ids if isinstance(frozen_ids, list) else []):
        reasons.append("judge_did_not_receive_frozen_plan")
    plan_metadata = plan.metadata_json or {}
    nonce = plan_metadata.get("nonce")
    if not isinstance(nonce, str) or len(nonce) < 16:
        reasons.append("invalid_platform_nonce")
    elif not evidence_excerpt_matches(
        plan,
        SemanticEvidenceCitation(evidence_id=plan.id, excerpt=nonce),
    ):
        reasons.append("frozen_plan_artifact_invalid")
    if plan_metadata.get("source") != "platform_web_observer":
        reasons.append("plan_not_platform_owned")
    if plan_metadata.get("hypothesis_id") != reviewed.hypothesis_id:
        reasons.append("plan_hypothesis_mismatch")
    if plan_metadata.get("device_serial") != device_serial:
        reasons.append("plan_device_mismatch")
    plan_document = _evidence_json_object(plan)
    if plan_document is None:
        reasons.append("frozen_plan_artifact_invalid")
    planned_request = plan_document.get("plan") if isinstance(plan_document, dict) else None
    if not isinstance(planned_request, dict):
        reasons.append("frozen_web_request_missing")
        planned_request = {}
    bridge_method: str | None = None
    try:
        frozen_request = WebExperimentRequest.model_validate(planned_request)
    except ValidationError:
        reasons.append("frozen_web_request_invalid")
    else:
        if (
            frozen_request.finding_id != finding.id
            or frozen_request.hypothesis_id != reviewed.hypothesis_id
        ):
            reasons.append("frozen_web_request_identity_mismatch")
        bridge_method = f"{frozen_request.bridge_name}.{frozen_request.method}"
    planned_state = planned_request.get("victim_state")
    fixture_id = planned_request.get("fixture_id")
    if planned_state != reviewed.victim_state:
        reasons.append("reviewed_victim_state_differs_from_frozen_plan")
    if fixture_id is None and (
        reviewed.impact == "unauthorized_data_access"
        or str(planned_state).strip().lower() != "guest"
    ):
        reasons.append("state_dependent_claim_lacks_executable_fixture")
    fixture_state_id: str | None = None
    if reviewed.impact == "unauthorized_data_access" and (
        planned_state != "controlled canary fixture"
        or not isinstance(plan_document, dict)
        or not isinstance(plan_document.get("state_fixture"), dict)
        or plan_document["state_fixture"].get("fixture_type") != "canary"
        or plan_document["state_fixture"].get("target_state_source")
        != "controlled_canary_seed_pending"
    ):
        reasons.append("data_access_target_state_oracle_unavailable")
    if fixture_id is not None:
        state = plan_document.get("state_fixture") if isinstance(plan_document, dict) else None
        if not isinstance(state, dict) or state.get("fixture_id") != fixture_id:
            reasons.append("fixture_not_bound_to_frozen_plan")
        else:
            candidate_id = state.get("state_check_evidence_id")
            candidate = evidence_by_id.get(candidate_id) if isinstance(candidate_id, str) else None
            state_metadata = candidate.metadata_json or {} if candidate is not None else {}
            state_document = _evidence_json_object(candidate) if candidate is not None else None
            if (
                candidate is None
                or candidate.id not in (frozen_ids if isinstance(frozen_ids, list) else [])
                or candidate.kind != "web.experiment.fixture_state"
                or candidate.scan_id != finding.scan_id
                or candidate.task_id != verifier_task_id
                or state.get("verified") is not True
                or state_metadata.get("fixture_state_verified") is not True
                or state_metadata.get("source") != "platform_web_observer"
                or state_metadata.get("experiment_id") != reviewed.experiment_id
                or state_metadata.get("nonce") != nonce
                or state_metadata.get("finding_id") != finding.id
                or state_metadata.get("hypothesis_id") != reviewed.hypothesis_id
                or state_metadata.get("device_serial") != device_serial
                or state_metadata.get("fixture_id") != fixture_id
                or state_metadata.get("fixture_type") != state.get("fixture_type")
                or state_metadata.get("victim_state") != planned_state
                or state_metadata.get("target_state_source") != state.get("target_state_source")
                or state_metadata.get("state_check_digest") != state.get("state_check_digest")
                or not isinstance(state.get("state_check_digest"), str)
                or len(state["state_check_digest"]) != 64
                or state_document is None
                or state_document.get("metadata") != state_metadata
                or state_document.get("exit_code") != state_metadata.get("expected_exit_code")
                or state_document.get("timed_out") is not False
                or state_document.get("canceled") is not False
                or candidate.exit_code != state_metadata.get("expected_exit_code")
                or _time(candidate.created_at) > _time(plan.created_at)
                or _time(plan.created_at) - _time(candidate.created_at) > timedelta(minutes=3)
            ):
                reasons.append("fixture_state_not_independently_verified")
            else:
                fixture_state_id = candidate.id
    remote_receipt_id: str | None = None
    remote_tunnel_id: str | None = None
    remote_mode = (
        plan_document is not None
        and plan_document.get("observer_transport") == "ssh_reverse_https"
    )
    if remote_mode:
        deployment_id = plan_document.get("remote_deployment_id")
        attack_url = plan_document.get("attack_url")
        attack_origin = None
        if isinstance(attack_url, str):
            parsed_attack = urlsplit(attack_url)
            if parsed_attack.scheme == "https" and parsed_attack.hostname:
                attack_origin = f"{parsed_attack.scheme}://{parsed_attack.netloc}"
        receipts = [
            item for item in evidence_by_id.values()
            if item.kind == "web.experiment.remote_receipt"
            and item.scan_id == finding.scan_id
            and item.task_id == verifier_task_id
            and (item.metadata_json or {}).get("stage") == "remote_deploy"
            and (item.metadata_json or {}).get("experiment_id") == reviewed.experiment_id
            and (item.metadata_json or {}).get("deployment_id") == deployment_id
        ]
        if len(receipts) != 1 or not isinstance(deployment_id, str) or not attack_origin:
            reasons.append("missing_or_ambiguous_remote_deployment_receipt")
        else:
            receipt = receipts[0]
            receipt_metadata = receipt.metadata_json or {}
            receipt_document = _evidence_json_object(receipt)
            if (
                receipt.id not in (frozen_ids if isinstance(frozen_ids, list) else [])
                or receipt_metadata.get("source") != "platform_web_observer"
                or receipt_metadata.get("finding_id") != finding.id
                or receipt_metadata.get("hypothesis_id") != reviewed.hypothesis_id
                or receipt_metadata.get("nonce") != nonce
                or receipt_metadata.get("device_serial") != device_serial
                or receipt_metadata.get("public_probe_ok") is not True
                or not isinstance(receipt_metadata.get("tunnel_id"), str)
                or not receipt_metadata["tunnel_id"]
                or _time(receipt.created_at) > _time(plan.created_at)
                or receipt_document is None
                or receipt_document.get("experiment_id") != reviewed.experiment_id
                or receipt_document.get("root_nonce") != nonce
                or receipt_document.get("deployment_id") != deployment_id
                or receipt_document.get("tunnel_id") != receipt_metadata.get("tunnel_id")
                or receipt_document.get("action") != "deploy"
                or receipt_document.get("status") != "healthy"
                or receipt_document.get("public_probe_ok") is not True
                or receipt_document.get("public_base_url") != attack_origin
            ):
                reasons.append("remote_deployment_receipt_not_attributable")
            else:
                remote_receipt_id = receipt.id
                remote_tunnel_id = receipt_metadata["tunnel_id"]
    elif plan_document is not None and plan_document.get("observer_transport") not in {
        None, "adb_reverse_http",
    }:
        reasons.append("unknown_web_observer_transport")

    scoped: dict[str, Evidence] = {}
    for evidence in cited.values():
        metadata = evidence.metadata_json or {}
        if evidence.kind not in _WEB_KINDS:
            # Static source evidence can support provenance, but it cannot be
            # execution, effect, or a control by itself.
            continue
        if (
            evidence.task_id != verifier_task_id
            or metadata.get("source") != "platform_web_observer"
            or metadata.get("finding_id") != finding.id
            or metadata.get("hypothesis_id") != reviewed.hypothesis_id
            or metadata.get("experiment_id") != reviewed.experiment_id
            or metadata.get("nonce") != nonce
            or metadata.get("device_serial") != device_serial
        ):
            reasons.append(f"experiment_scope_mismatch:{evidence.id}")
            continue
        if _time(evidence.created_at) < _time(plan.created_at) or (
            _time(evidence.created_at) - _time(plan.created_at) > _MAX_EXPERIMENT_AGE
        ):
            reasons.append(f"experiment_window_mismatch:{evidence.id}")
            continue
        scoped[evidence.id] = evidence

    execution = [
        scoped[item.evidence_id]
        for item in reviewed.execution
        if item.evidence_id in scoped
        and scoped[item.evidence_id].kind == "web.experiment.execution"
        and (scoped[item.evidence_id].metadata_json or {}).get("ordinary_app_uid_verified") is True
        and (scoped[item.evidence_id].metadata_json or {}).get("target_process_observed") is True
    ]
    callbacks = [
        scoped[item.evidence_id]
        for item in reviewed.effect
        if item.evidence_id in scoped
        and scoped[item.evidence_id].kind == "web.experiment.event"
        and (scoped[item.evidence_id].metadata_json or {}).get("stage") == "callback"
        and (scoped[item.evidence_id].metadata_json or {}).get("phase") == "attack"
        and (scoped[item.evidence_id].metadata_json or {}).get("event_type") == "bridge_return"
    ]
    controls = [
        scoped[item.evidence_id]
        for item in reviewed.controls
        if item.evidence_id in scoped
        and scoped[item.evidence_id].kind == "web.experiment.snapshot"
        and (scoped[item.evidence_id].metadata_json or {}).get("controls_validated") is True
    ]
    if not execution:
        reasons.append("missing_ordinary_app_target_execution")
    if not callbacks:
        reasons.append("missing_observed_attack_callback")
    if not controls:
        reasons.append("missing_validated_negative_controls")
    remote_health_ids: list[str] = []
    if remote_mode:
        for snapshot in controls:
            snapshot_document = _evidence_json_object(snapshot)
            if (
                snapshot_document is None
                or not isinstance(snapshot_document.get("control_gaps"), list)
                or snapshot_document["control_gaps"]
            ):
                reasons.append("remote_snapshot_has_control_or_transport_gap")
            health_receipts = sorted(
                (
                    item for item in evidence_by_id.values()
                    if item.kind == "web.experiment.remote_receipt"
                    and item.scan_id == finding.scan_id
                    and item.task_id == verifier_task_id
                    and (item.metadata_json or {}).get("stage") == "remote_health"
                    and (item.metadata_json or {}).get("experiment_id")
                    == reviewed.experiment_id
                    and (item.metadata_json or {}).get("deployment_id")
                    == plan_document.get("remote_deployment_id")
                    and _time(plan.created_at) <= _time(item.created_at)
                    <= _time(snapshot.created_at)
                ),
                key=lambda item: _time(item.created_at),
            )
            if not health_receipts:
                reasons.append("missing_remote_snapshot_health_receipt")
                continue
            latest_health = health_receipts[-1]
            health_metadata = latest_health.metadata_json or {}
            health_document = _evidence_json_object(latest_health)
            if (
                latest_health.id not in (
                    frozen_ids if isinstance(frozen_ids, list) else []
                )
                or
                health_metadata.get("source") != "platform_web_observer"
                or health_metadata.get("finding_id") != finding.id
                or health_metadata.get("hypothesis_id") != reviewed.hypothesis_id
                or health_metadata.get("nonce") != nonce
                or health_metadata.get("device_serial") != device_serial
                or health_metadata.get("tunnel_id") != remote_tunnel_id
                or health_metadata.get("public_probe_ok") is not True
                or health_document is None
                or health_document.get("action") != "health"
                or health_document.get("status") != "healthy"
                or health_document.get("experiment_id") != reviewed.experiment_id
                or health_document.get("deployment_id")
                != plan_document.get("remote_deployment_id")
                or health_document.get("root_nonce") != nonce
                or health_document.get("tunnel_id") != remote_tunnel_id
                or health_document.get("public_probe_ok") is not True
            ):
                reasons.append("remote_snapshot_health_receipt_not_attributable")
            else:
                remote_health_ids.append(latest_health.id)
    execution_sources: list[str] = []
    for receipt in execution:
        metadata = receipt.metadata_json or {}
        if metadata.get("webview_in_target_confirmed") is not True:
            reasons.append("target_webview_load_not_confirmed")
            continue
        target_observation = metadata.get("target_observation")
        if (
            not isinstance(target_observation, dict)
            or target_observation.get("status") != "observed"
            or target_observation.get("trust_tier") != "target_uid_app_log"
            or target_observation.get("adapter_id") != "target_uid_on_page_finished_log_v1"
            or target_observation.get("main_frame_url") != metadata.get("final_url")
        ):
            reasons.append("target_web_observation_adapter_not_verified")
        if planned_request.get("frame") == "iframe" and (
            not isinstance(target_observation, dict)
            or target_observation.get("frame_origin_verified") is not True
        ):
            reasons.append("calling_frame_origin_not_confirmed")
        reference_kinds = {
            "launch_evidence_id": "blackbox.poc_launch",
            "process_evidence_id": "blackbox.poc_process",
            "webview_confirmation_evidence_id": "blackbox.poc_target_logcat",
            "target_process_evidence_id": "web.experiment.target_process",
        }
        refs: dict[str, Evidence] = {}
        for field, kind in reference_kinds.items():
            item = evidence_by_id.get(metadata.get(field, ""))
            if (
                item is None
                or item.kind != kind
                or item.scan_id != finding.scan_id
                or item.task_id != verifier_task_id
                or (item.metadata_json or {}).get("device_serial") != device_serial
            ):
                reasons.append(f"invalid_execution_source:{field}")
                continue
            refs[field] = item
        if len(refs) != len(reference_kinds):
            continue
        launch = refs["launch_evidence_id"]
        process = refs["process_evidence_id"]
        confirmation = refs["webview_confirmation_evidence_id"]
        target_process = refs["target_process_evidence_id"]
        request_id = metadata.get("request_id")
        if (
            not isinstance(request_id, str)
            or not request_id
            or any(
                (item.metadata_json or {}).get("request_id") != request_id for item in refs.values()
            )
            or launch.exit_code != 0
            or process.exit_code != 0
            or target_process.exit_code != 0
            or launch.metadata_json.get("caller_identity")
            not in {"agent_poc_app", "platform_poc_app"}
            or not process.metadata_json.get("process_ids")
        ):
            reasons.append("ordinary_app_execution_sources_disagree")
        oracle = confirmation.metadata_json.get("oracle")
        if (
            not isinstance(oracle, dict)
            or oracle.get("kind") != "target_uid_log_contains"
            or oracle.get("matched") is not True
            or not isinstance(oracle.get("observation"), dict)
            or not isinstance(oracle["observation"].get("target_uid"), int)
        ):
            reasons.append("target_uid_page_load_oracle_missing")
        callback_phase_nonces = [
            (item.metadata_json or {}).get("phase_nonce") for item in callbacks
        ]
        if not any(
            isinstance(value, str)
            and len(value) >= 16
            and evidence_excerpt_matches(
                confirmation,
                SemanticEvidenceCitation(evidence_id=confirmation.id, excerpt=value),
            )
            for value in callback_phase_nonces
        ):
            reasons.append("target_page_load_nonce_not_in_oracle")
        if not evidence_excerpt_matches(
            confirmation,
            SemanticEvidenceCitation(
                evidence_id=confirmation.id,
                excerpt="onPageFinished",
            ),
        ):
            reasons.append("target_page_load_callback_not_in_oracle")
        launched_at = _timestamp(launch.metadata_json.get("launch_started_at"))
        callback_times = [
            _timestamp((item.metadata_json or {}).get("received_at")) for item in callbacks
        ]
        if (
            launched_at is None
            or launched_at < _time(plan.created_at)
            or launched_at - _time(plan.created_at) > _MAX_EXPERIMENT_AGE
            or any(item is None or launched_at > item for item in callback_times)
        ):
            reasons.append("effect_precedes_ordinary_app_launch")
        execution_sources.extend(item.id for item in refs.values())
    if scoped and any(
        _time(review_evidence.created_at) < _time(item.created_at) for item in scoped.values()
    ):
        reasons.append("judge_precedes_frozen_evidence")
    # Static code explains a possible flow, but it cannot establish the value
    # that reached the attack page. The target effect must have its own
    # platform-produced, experiment-bound readback or pre/post observation.
    static_provenance = [
        cited[item.evidence_id]
        for item in reviewed.effect
        if item.evidence_id in cited
        and cited[item.evidence_id].kind == "static.source_excerpt"
        and cited[item.evidence_id].task_id == verifier_task_id
        and (cited[item.evidence_id].metadata_json or {}).get("source")
        == "platform_static_source"
        and (cited[item.evidence_id].metadata_json or {}).get("finding_id") == finding.id
        and (cited[item.evidence_id].metadata_json or {}).get("hypothesis_id")
        == reviewed.hypothesis_id
    ]
    target_effects = [
        scoped[item.evidence_id]
        for item in reviewed.effect
        if item.evidence_id in scoped
        and scoped[item.evidence_id].kind == "web.experiment.target_effect"
    ]
    validated_effects: list[str] = []
    effect_sources: list[str] = []
    for receipt in target_effects:
        metadata = receipt.metadata_json or {}
        document = _evidence_json_object(receipt)
        effect_kind = metadata.get("effect_kind")
        common_valid = bool(
            metadata.get("target_owned_effect_validated") is True
            and document is not None
            and document.get("target_owned_effect_validated") is True
            and document.get("effect_kind") == effect_kind
            and document.get("experiment_id") == reviewed.experiment_id
            and document.get("fixture_id") == fixture_id
            and document.get("target_package") == (plan_document or {}).get("target_package")
            and document.get("target_apk_sha256") == (plan_document or {}).get(
                "target_apk_sha256"
            )
            and metadata.get("fixture_id") == fixture_id
            and metadata.get("target_package") == document.get("target_package")
            and metadata.get("target_apk_sha256") == document.get("target_apk_sha256")
            and isinstance(document.get("target_apk_sha256"), str)
            and len(document["target_apk_sha256"]) == 64
            and _time(receipt.created_at) >= max(
                (_time(item.created_at) for item in callbacks),
                default=_time(plan.created_at),
            )
        )
        if not common_valid:
            reasons.append(f"invalid_target_effect_receipt:{receipt.id}")
            continue
        if reviewed.impact == "unauthorized_data_access":
            controlled = (plan_document or {}).get("controlled_canary")
            attack_url = (plan_document or {}).get("attack_url")
            attack_url_sha256 = (
                hashlib.sha256(attack_url.encode()).hexdigest()
                if isinstance(attack_url, str) else None
            )
            identity_id = (plan_document or {}).get("apk_identity_evidence_id")
            identity_sources = _controlled_apk_identity_sources(
                identity_id=identity_id,
                evidence_by_id=evidence_by_id,
                frozen_ids=frozen_ids,
                scan_id=finding.scan_id,
                task_id=verifier_task_id,
                finding_id=finding.id,
                hypothesis_id=reviewed.hypothesis_id,
                experiment_id=reviewed.experiment_id,
                nonce=nonce if isinstance(nonce, str) else None,
                device_serial=device_serial,
                target_package=str((plan_document or {}).get("target_package") or ""),
                target_apk_sha256=str((plan_document or {}).get("target_apk_sha256") or ""),
                plan_created_at=plan.created_at,
            )
            callback_id = document.get("callback_evidence_id")
            callback = next((item for item in callbacks if item.id == callback_id), None)
            callback_document = _evidence_json_object(callback) if callback is not None else None
            payload = (
                callback_document.get("client_payload")
                if isinstance(callback_document, dict) else None
            )
            value_digest = payload.get("value_sha256") if isinstance(payload, dict) else None
            value_length = payload.get("value_length") if isinstance(payload, dict) else None
            seed_id = document.get("seed_evidence_id")
            seed = evidence_by_id.get(seed_id) if isinstance(seed_id, str) else None
            seed_document = _evidence_json_object(seed) if seed is not None else None
            seed_metadata = seed.metadata_json or {} if seed is not None else {}
            cleanup_candidates = [
                item for item in evidence_by_id.values()
                if item.kind == "web.experiment.canary_cleanup"
                and item.scan_id == finding.scan_id
                and item.task_id == verifier_task_id
                and item.id in (frozen_ids if isinstance(frozen_ids, list) else [])
                and (item.metadata_json or {}).get("source") == "platform_web_observer"
                and (item.metadata_json or {}).get("experiment_id") == reviewed.experiment_id
                and (item.metadata_json or {}).get("nonce") == nonce
                and (item.metadata_json or {}).get("device_serial") == device_serial
                and (item.metadata_json or {}).get("fixture_id") == fixture_id
                and (item.metadata_json or {}).get("cleared") is True
                and _time(receipt.created_at) <= _time(item.created_at)
                <= _time(review_evidence.created_at)
            ]
            cleanup = next(
                (
                    item for item in cleanup_candidates
                    if (cleanup_document := _evidence_json_object(item)) is not None
                    and cleanup_document.get("experiment_id") == reviewed.experiment_id
                    and cleanup_document.get("fixture_id") == fixture_id
                    and cleanup_document.get("seed_evidence_id") == seed_id
                    and cleanup_document.get("target_package")
                    == (plan_document or {}).get("target_package")
                    and cleanup_document.get("target_apk_sha256")
                    == document.get("target_apk_sha256")
                    and cleanup_document.get("cleared") is True
                ),
                None,
            )
            if (
                effect_kind != "target_value_match"
                or fixture_state_id is None
                or identity_sources is None
                or not isinstance(controlled, dict)
                or (plan_document or {}).get("target_package") != "io.apkscanner.adaptivecases"
                or (plan_document or {}).get("target_apk_sha256") != CONTROLLED_CANARY_APK_SHA256
                or planned_request.get("frame") != "top"
                or attack_url_sha256 is None
                or controlled.get("mode") != "controlled_dump_protected_fixture_only"
                or controlled.get("apk_identity_evidence_id") != identity_id
                or controlled.get("seed_evidence_id") != seed_id
                or controlled.get("token_sha256") != value_digest
                or controlled.get("target_apk_sha256") != document.get("target_apk_sha256")
                or controlled.get("seed_verified") is not True
                or document.get("value_sha256") != value_digest
                or metadata.get("value_sha256") != value_digest
                or metadata.get("callback_evidence_id") != callback_id
                or metadata.get("seed_evidence_id") != seed_id
                or document.get("seed_verified") is not True
                or document.get("target_readback_verified") is not True
                or document.get("bridge_call_verified") is not True
                or metadata.get("bridge_call_verified") is not True
                or not isinstance(document.get("bridge_calls"), int)
                or isinstance(document.get("bridge_calls"), bool)
                or document["bridge_calls"] < 1
                or document.get("bridge_url_sha256") != attack_url_sha256
                or metadata.get("bridge_url_sha256") != attack_url_sha256
                or document.get("callback_value_matched") is not True
                or not isinstance(value_digest, str)
                or len(value_digest) != 64
                or any(char not in "0123456789abcdef" for char in value_digest)
                or not isinstance(value_length, int)
                or isinstance(value_length, bool)
                or not 32 <= value_length <= 128
                or (isinstance(payload, dict) and "value" in payload)
                or not isinstance(seed_id, str)
                or seed_id not in (frozen_ids if isinstance(frozen_ids, list) else [])
                or seed is None
                or seed.kind != "web.experiment.canary_seed"
                or seed.scan_id != finding.scan_id
                or seed.task_id != verifier_task_id
                or seed_metadata.get("source") != "platform_web_observer"
                or seed_metadata.get("experiment_id") != reviewed.experiment_id
                or seed_metadata.get("nonce") != nonce
                or seed_metadata.get("finding_id") != finding.id
                or seed_metadata.get("hypothesis_id") != reviewed.hypothesis_id
                or seed_metadata.get("fixture_id") != fixture_id
                or seed_metadata.get("device_serial") != device_serial
                or seed_metadata.get("target_package") != (plan_document or {}).get(
                    "target_package"
                )
                or seed_metadata.get("target_apk_sha256") != document.get(
                    "target_apk_sha256"
                )
                or seed_metadata.get("apk_identity_evidence_id") != identity_id
                or seed_metadata.get("token_sha256") != value_digest
                or seed_metadata.get("seed_verified") is not True
                or seed_document is None
                or seed_document.get("token_sha256") != value_digest
                or seed_document.get("apk_identity_evidence_id") != identity_id
                or seed_document.get("seed_verified") is not True
                or cleanup is None
                or _time(seed.created_at) > _time(plan.created_at)
                or _time(seed.created_at) < _time(plan.created_at) - timedelta(minutes=3)
            ):
                reasons.append(f"target_value_not_independently_validated:{receipt.id}")
                continue
            effect_sources.extend((seed.id, cleanup.id, *identity_sources))
        else:
            before_id = document.get("before_evidence_id")
            after_id = document.get("after_evidence_id")
            before = evidence_by_id.get(before_id) if isinstance(before_id, str) else None
            after = evidence_by_id.get(after_id) if isinstance(after_id, str) else None
            before_document = _evidence_json_object(before) if before is not None else None
            after_document = _evidence_json_object(after) if after is not None else None
            before_hash = before_document.get("state_sha256") if before_document else None
            after_hash = after_document.get("state_sha256") if after_document else None
            source_valid = all(
                item is not None
                and item.scan_id == finding.scan_id
                and item.task_id == verifier_task_id
                and item.id in (frozen_ids if isinstance(frozen_ids, list) else [])
                and (item.metadata_json or {}).get("source") == "platform_web_observer"
                and (item.metadata_json or {}).get("experiment_id") == reviewed.experiment_id
                and (item.metadata_json or {}).get("nonce") == nonce
                and (item.metadata_json or {}).get("device_serial") == device_serial
                for item in (before, after)
            )
            if (
                effect_kind != "target_state_change"
                or not source_valid
                or before.kind != "web.experiment.target_state_baseline"
                or after.kind != "web.experiment.target_state_after"
                or not isinstance(before_hash, str)
                or not isinstance(after_hash, str)
                or len(before_hash) != 64
                or len(after_hash) != 64
                or before_hash == after_hash
                or document.get("before_state_sha256") != before_hash
                or document.get("after_state_sha256") != after_hash
                or _time(before.created_at) >= min(
                    (_time(item.created_at) for item in execution),
                    default=_time(plan.created_at),
                )
                or _time(after.created_at) <= max(
                    (_time(item.created_at) for item in callbacks),
                    default=_time(plan.created_at),
                )
                or _time(after.created_at) > _time(receipt.created_at)
            ):
                reasons.append(f"target_state_change_not_independently_validated:{receipt.id}")
                continue
            effect_sources.extend((before.id, after.id))
        validated_effects.append(receipt.id)
    if not static_provenance and not validated_effects:
        reasons.append("missing_independent_target_provenance")
    if not validated_effects:
        reasons.append(
            "data_access_requires_independent_target_value"
            if reviewed.impact == "unauthorized_data_access"
            else "state_change_requires_independent_target_effect"
        )
    if any(
        evidence.kind == "static.source_excerpt"
        and (evidence.metadata_json or {}).get("static_output_usable") is False
        for evidence in static_provenance
    ):
        reasons.append("unusable_static_provenance")
    if not reasons:
        citation_ids = tuple(
            dict.fromkeys(
                (
                    plan.id,
                    *([remote_receipt_id] if remote_receipt_id else []),
                    *remote_health_ids,
                    *([fixture_state_id] if fixture_state_id else []),
                    review_evidence.id,
                    *citation_ids,
                    *execution_sources,
                    *effect_sources,
                )
            )
        )
    return SemanticProofGate(
        eligible=not reasons,
        reasons=tuple(dict.fromkeys(reasons)),
        evidence_ids=citation_ids,
        experiment_id=reviewed.experiment_id,
        nonce=nonce if isinstance(nonce, str) else None,
        device_serial=device_serial,
        bridge_method=bridge_method,
    )
