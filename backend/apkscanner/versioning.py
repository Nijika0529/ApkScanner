from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from sqlalchemy import desc, select

from .enums import FindingStatus, TaskStatus
from .models import (
    EntryPoint,
    Evidence,
    Finding,
    InvestigationTask,
    PatternMatch,
    ProofAttempt,
    Scan,
    SecurityHypothesis,
    SecuritySnapshot,
    VersionDiff,
    VulnerabilityPattern,
)
from .repository import add_event

_SMALI_NOISE = re.compile(
    r"^\s*(?:\.line|\.local|\.end local|\.restart local|\.prologue|:[A-Za-z0-9_]+)"
)
_REGISTER = re.compile(r"\b[vp]\d+\b")
_APP_CALL = re.compile(r"(L[^;\s]+;)->([A-Za-z0-9_$<>]+)")
_QUOTED = re.compile(r'"([^"\\]{3,160})"')
_GUARD_TERMS = {
    "checkCallingPermission",
    "enforceCallingPermission",
    "checkCallingOrSelfPermission",
    "enforceCallingOrSelfPermission",
    "getCallingUid",
    "getCallingPid",
    "checkSignatures",
    "checkSignaturesCompat",
    "signature",
    "permission",
    "BiometricPrompt",
    "KeyguardManager",
}
_SINK_TERMS = {
    "startActivity",
    "startService",
    "bindService",
    "sendBroadcast",
    "query",
    "insert",
    "update",
    "delete",
    "openFile",
    "execSQL",
    "loadUrl",
    "addJavascriptInterface",
    "setResult",
    "transact",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _signer_digest(scan: Scan) -> str | None:
    signing = dict(scan.signing or {})
    candidates = signing.get("certificate_sha256") or signing.get("certificate_sha256_digest")
    if isinstance(candidates, list):
        normalized = sorted(str(item).replace(":", "").lower() for item in candidates)
        return _digest(normalized) if normalized else None
    if candidates:
        return str(candidates).replace(":", "").lower()
    return None


def _stable_key(entry: EntryPoint) -> str:
    owner = entry.owner_component or entry.name
    if entry.kind == "deep_link":
        owner = f"{owner}|{entry.name}"
    return f"{entry.kind}:{owner}"


def _normalize_source(content: str) -> tuple[str, list[str], list[str], list[str], list[str]]:
    normalized: list[str] = []
    calls: set[str] = set()
    strings: set[str] = set()
    guards: set[str] = set()
    sinks: set[str] = set()
    for raw in content.splitlines():
        if _SMALI_NOISE.match(raw):
            continue
        line = _REGISTER.sub("r", raw.strip())
        if not line or line.startswith("#"):
            continue
        normalized.append(line)
        calls.update(f"{owner}->{method}" for owner, method in _APP_CALL.findall(line))
        strings.update(_QUOTED.findall(line))
        guards.update(term for term in _GUARD_TERMS if term in line)
        sinks.update(term for term in _SINK_TERMS if term in line)
    return (
        "\n".join(normalized),
        sorted(calls),
        sorted(strings)[:200],
        sorted(guards),
        sorted(sinks),
    )


def _anchor_content(code_context: dict[str, Any]) -> str:
    chunks: list[str] = []
    for anchor in code_context.get("anchors", []):
        if isinstance(anchor, dict) and isinstance(anchor.get("content"), str):
            chunks.append(anchor["content"])
    return "\n".join(chunks)


class SecurityEvolutionService:
    """Version snapshots, semantic deltas, PoC replay plans, and pattern search."""

    def build_snapshot(
        self,
        session,  # noqa: ANN001
        *,
        scan: Scan,
        entries: list[EntryPoint],
        code_index: dict[str, Any],
    ) -> SecuritySnapshot:
        existing = session.scalar(
            select(SecuritySnapshot).where(SecuritySnapshot.scan_id == scan.id)
        )
        if existing is not None:
            return existing
        entry_facts: list[dict[str, Any]] = []
        for entry in entries:
            context = dict(code_index.get(entry.owner_component or entry.name, {}) or {})
            content = _anchor_content(context)
            normalized, calls, strings, guards, sinks = _normalize_source(content)
            manifest_fact = {
                "kind": entry.kind,
                "name": entry.name,
                "owner_component": entry.owner_component,
                "exported": entry.exported,
                "permission": entry.permission,
                "permission_protection": entry.permission_protection,
                "intent_filters": entry.intent_filters,
                "deep_links": entry.deep_links,
                "authorities": (entry.metadata_json or {}).get("authorities"),
                "grant_uri_permissions": (entry.metadata_json or {}).get("grant_uri_permissions"),
            }
            code_fact = {
                "direct_hash": hashlib.sha256(normalized.encode()).hexdigest(),
                "calls": calls[:500],
                "strings": strings,
                "guards": guards,
                "sinks": sinks,
                "source_status": context.get("status", "source_not_found"),
            }
            entry_facts.append(
                {
                    "entry_id": entry.id,
                    "stable_key": _stable_key(entry),
                    "manifest": manifest_fact,
                    "code": code_fact,
                    "security_fact_hash": _digest({"manifest": manifest_fact, "code": code_fact}),
                }
            )
        payload = {
            "schema_version": "1.0",
            "identity": {
                "package_name": scan.package_name,
                "version_name": scan.version_name,
                "version_code": scan.version_code,
                "signer_digest": _signer_digest(scan),
                "artifact_sha256": scan.artifact_sha256,
            },
            "entries": sorted(entry_facts, key=lambda item: item["stable_key"]),
        }
        hash_payload = {
            "schema_version": payload["schema_version"],
            "identity": {
                key: value for key, value in payload["identity"].items() if key != "artifact_sha256"
            },
            "entries": [
                {key: value for key, value in item.items() if key != "entry_id"}
                for item in payload["entries"]
            ],
        }
        semantic_hash = _digest(hash_payload)
        payload["semantic_hash"] = semantic_hash
        snapshot = SecuritySnapshot(
            scan_id=scan.id,
            package_name=scan.package_name or "",
            signer_digest=_signer_digest(scan),
            version_name=scan.version_name,
            version_code=scan.version_code,
            snapshot_hash=_digest(
                {
                    "semantic_hash": semantic_hash,
                    "scan_id": scan.id,
                }
            ),
            payload=payload,
        )
        session.add(snapshot)
        session.flush()
        return snapshot

    def build_version_diff(
        self,
        session,  # noqa: ANN001
        *,
        scan: Scan,
        snapshot: SecuritySnapshot,
    ) -> VersionDiff | None:
        history = list(
            session.scalars(
                select(SecuritySnapshot)
                .where(
                    SecuritySnapshot.package_name == snapshot.package_name,
                    SecuritySnapshot.signer_digest == snapshot.signer_digest,
                    SecuritySnapshot.scan_id != snapshot.scan_id,
                    SecuritySnapshot.created_at < snapshot.created_at,
                )
                .order_by(desc(SecuritySnapshot.created_at))
            )
        )
        baseline = history[0] if history else None
        if baseline is None:
            return None
        existing = session.scalar(
            select(VersionDiff).where(
                VersionDiff.baseline_scan_id == baseline.scan_id,
                VersionDiff.target_scan_id == scan.id,
            )
        )
        if existing is not None:
            return existing
        base_entries = list((baseline.payload or {}).get("entries", []))
        target_entries = list((snapshot.payload or {}).get("entries", []))
        mapping = self._map_entries(base_entries, target_entries)
        deltas = self._diff_entries(base_entries, target_entries, mapping)
        replay_candidates: list[dict[str, Any]] = []
        seen_replays: set[tuple[str, str, str]] = set()
        for historical in history:
            historical_entries = list((historical.payload or {}).get("entries", []))
            historical_mapping = self._map_entries(
                historical_entries,
                target_entries,
            )
            for candidate in self._replay_candidates(
                session,
                baseline_scan_id=historical.scan_id,
                mapping=historical_mapping,
                baseline_entries=historical_entries,
                target_entries=target_entries,
            ):
                source_hypothesis = candidate.get("source_hypothesis") or {}
                oracle = (candidate.get("plan") or {}).get("oracle") or {}
                replay_key = (
                    str(source_hypothesis.get("claim") or ""),
                    str(candidate.get("target_entry_id") or ""),
                    str(oracle.get("impact") or oracle.get("kind") or ""),
                )
                if replay_key in seen_replays:
                    continue
                seen_replays.add(replay_key)
                candidate["historical_scan_id"] = historical.scan_id
                replay_candidates.append(candidate)
        counts: dict[str, int] = defaultdict(int)
        for delta in deltas:
            counts[str(delta["category"])] += 1
        diff = VersionDiff(
            baseline_scan_id=baseline.scan_id,
            target_scan_id=scan.id,
            summary={
                "baseline_version_name": baseline.version_name,
                "baseline_version_code": baseline.version_code,
                "target_version_name": snapshot.version_name,
                "target_version_code": snapshot.version_code,
                "counts": dict(counts),
                "replay_candidate_count": len(replay_candidates),
            },
            entry_mapping=mapping,
            deltas=deltas,
            replay_candidates=replay_candidates,
        )
        session.add(diff)
        session.flush()
        return diff

    @staticmethod
    def _map_entries(
        baseline: list[dict[str, Any]],
        target: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        target_by_key = {item["stable_key"]: item for item in target}
        unused = {item["entry_id"]: item for item in target}
        mappings: list[dict[str, Any]] = []
        for old in baseline:
            match = target_by_key.get(old["stable_key"])
            reason = "stable_entry_identity"
            score = 100
            if match is None:
                candidates = [
                    item
                    for item in unused.values()
                    if item["manifest"]["kind"] == old["manifest"]["kind"]
                    and item["code"]["direct_hash"] == old["code"]["direct_hash"]
                ]
                if len(candidates) == 1:
                    match = candidates[0]
                    reason = "renamed_entry_same_normalized_code"
                    score = 90
            if match is not None:
                unused.pop(match["entry_id"], None)
                mappings.append(
                    {
                        "baseline_entry_id": old["entry_id"],
                        "target_entry_id": match["entry_id"],
                        "baseline_key": old["stable_key"],
                        "target_key": match["stable_key"],
                        "reason": reason,
                        "score": score,
                    }
                )
        return mappings

    @staticmethod
    def _diff_entries(
        baseline: list[dict[str, Any]],
        target: list[dict[str, Any]],
        mapping: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        old_by_id = {item["entry_id"]: item for item in baseline}
        new_by_id = {item["entry_id"]: item for item in target}
        mapped_old = {item["baseline_entry_id"] for item in mapping}
        mapped_new = {item["target_entry_id"] for item in mapping}
        deltas: list[dict[str, Any]] = []
        for pair in mapping:
            old = old_by_id[pair["baseline_entry_id"]]
            new = new_by_id[pair["target_entry_id"]]
            changes: list[str] = []
            old_manifest = old["manifest"]
            new_manifest = new["manifest"]
            if not old_manifest["exported"] and new_manifest["exported"]:
                changes.append("export_weakened")
            if old_manifest.get("permission") and not new_manifest.get("permission"):
                changes.append("permission_removed")
            if not old_manifest.get("permission") and new_manifest.get("permission"):
                changes.append("permission_added")
            if old_manifest.get("permission_protection") != new_manifest.get(
                "permission_protection"
            ):
                changes.append("permission_protection_changed")
            removed_guards = sorted(set(old["code"]["guards"]) - set(new["code"]["guards"]))
            added_guards = sorted(set(new["code"]["guards"]) - set(old["code"]["guards"]))
            if removed_guards:
                changes.append("guards_removed")
            if added_guards:
                changes.append("guards_added")
            if old["code"]["direct_hash"] != new["code"]["direct_hash"]:
                changes.append("code_changed")
            category = (
                "security_weakened"
                if any(
                    item in changes
                    for item in ("export_weakened", "permission_removed", "guards_removed")
                )
                else "security_hardened"
                if any(item in changes for item in ("guards_added", "permission_added"))
                else "implementation_changed"
                if changes
                else "unchanged"
            )
            deltas.append(
                {
                    **pair,
                    "category": category,
                    "changes": changes,
                    "removed_guards": removed_guards,
                    "added_guards": added_guards,
                }
            )
        for item in baseline:
            if item["entry_id"] not in mapped_old:
                deltas.append(
                    {
                        "baseline_entry_id": item["entry_id"],
                        "target_entry_id": None,
                        "category": "entry_removed",
                        "changes": ["entry_removed"],
                    }
                )
        for item in target:
            if item["entry_id"] not in mapped_new:
                deltas.append(
                    {
                        "baseline_entry_id": None,
                        "target_entry_id": item["entry_id"],
                        "category": "entry_added",
                        "changes": ["entry_added"],
                    }
                )
        return deltas

    @staticmethod
    def _replay_candidates(
        session,  # noqa: ANN001
        *,
        baseline_scan_id: str,
        mapping: list[dict[str, Any]],
        baseline_entries: list[dict[str, Any]],
        target_entries: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        target_for_old = {item["baseline_entry_id"]: item["target_entry_id"] for item in mapping}
        old_by_id = {item["entry_id"]: item for item in baseline_entries}
        new_by_id = {item["entry_id"]: item for item in target_entries}
        findings = list(
            session.scalars(
                select(Finding).where(
                    Finding.scan_id == baseline_scan_id,
                    Finding.status.in_(
                        [
                            FindingStatus.REPRODUCED_BLACKBOX.value,
                            FindingStatus.ACCEPTED.value,
                        ]
                    ),
                )
            )
        )
        candidates: list[dict[str, Any]] = []
        for finding in findings:
            metadata = dict(finding.metadata_json or {})
            attempt_ids = list(metadata.get("proof_attempt_ids") or [])
            attempts = (
                list(session.scalars(select(ProofAttempt).where(ProofAttempt.id.in_(attempt_ids))))
                if attempt_ids
                else []
            )
            for attempt in attempts:
                source_hypothesis = session.get(
                    SecurityHypothesis,
                    attempt.hypothesis_id,
                )
                old_entry_id = str((attempt.plan or {}).get("entry_point_id") or "")
                target_entry_id = target_for_old.get(old_entry_id)
                plan = dict(attempt.plan or {})
                poc = plan.get("poc")
                if not target_entry_id or not isinstance(poc, dict):
                    continue
                build_evidence = next(
                    (
                        item
                        for item in session.scalars(
                            select(Evidence)
                            .where(
                                Evidence.scan_id == baseline_scan_id,
                                Evidence.task_id == attempt.task_id,
                                Evidence.kind == "poc.build_artifact",
                            )
                            .order_by(desc(Evidence.created_at))
                        )
                        if (item.metadata_json or {}).get("hypothesis_id") == attempt.hypothesis_id
                    ),
                    None,
                )
                source_path = (
                    str((build_evidence.metadata_json or {}).get("source_path"))
                    if build_evidence is not None
                    and (build_evidence.metadata_json or {}).get("source_path")
                    else None
                )
                if not source_path:
                    continue
                candidates.append(
                    {
                        "source_finding_id": finding.id,
                        "source_proof_attempt_id": attempt.id,
                        "source_hypothesis": (
                            {
                                "claim": source_hypothesis.claim,
                                "category": source_hypothesis.category,
                            }
                            if source_hypothesis is not None
                            else {}
                        ),
                        "baseline_entry_id": old_entry_id,
                        "target_entry_id": target_entry_id,
                        "baseline_entry": old_by_id.get(old_entry_id, {}),
                        "target_entry": new_by_id.get(target_entry_id, {}),
                        "plan": plan,
                        "source_archive_path": source_path,
                        "source_archive_sha256": (
                            (build_evidence.metadata_json or {}).get("poc_source_sha256")
                            if build_evidence is not None
                            else None
                        ),
                        "status": "ready",
                    }
                )
        return candidates

    def apply_diff_and_patterns(
        self,
        session,  # noqa: ANN001
        *,
        scan: Scan,
        entries: list[EntryPoint],
        tasks: list[InvestigationTask],
        diff: VersionDiff | None,
    ) -> list[PatternMatch]:
        tasks_by_entry: dict[str, InvestigationTask] = {}
        for task in tasks:
            for entry_id in task.target_entry_ids:
                tasks_by_entry.setdefault(entry_id, task)
        if diff is not None:
            for replay in diff.replay_candidates:
                task = tasks_by_entry.get(str(replay.get("target_entry_id")))
                if task is None:
                    source_hypothesis = dict(replay.get("source_hypothesis") or {})
                    task = InvestigationTask(
                        scan_id=scan.id,
                        task_type="version_replay",
                        priority=100,
                        target_entry_ids=[str(replay["target_entry_id"])],
                        hypotheses=[
                            str(
                                source_hypothesis.get("claim")
                                or "Previously proven vulnerability remains reproducible."
                            )
                        ],
                        preconditions={
                            "historical_proof_replay": True,
                            "ordinary_app_caller": True,
                        },
                        allowed_side_effects=[
                            "install_target_apk",
                            "build_agent_poc_apk",
                            "install_agent_poc_apk",
                            "uninstall_agent_poc_apk",
                            "clear_application_data",
                            "adb_exploration",
                        ],
                        device_profile={},
                    )
                    session.add(task)
                    session.flush()
                    tasks.append(task)
                    tasks_by_entry[str(replay["target_entry_id"])] = task
                existing_replays = list((task.preconditions or {}).get("version_replays", []))
                if any(
                    item.get("source_proof_attempt_id") == replay.get("source_proof_attempt_id")
                    for item in existing_replays
                ):
                    continue
                source_claim = str((replay.get("source_hypothesis") or {}).get("claim") or "")
                if source_claim and source_claim not in task.hypotheses:
                    task.hypotheses = [*task.hypotheses, source_claim]
                task.preconditions = {
                    **dict(task.preconditions or {}),
                    "version_replays": [
                        *existing_replays,
                        replay,
                    ],
                }
                task.priority = max(task.priority, 100)
        matches = self.search_patterns(
            session,
            scan=scan,
            entries=entries,
        )
        for match in matches:
            task = tasks_by_entry.get(match.entry_point_id)
            if task is None:
                continue
            task.preconditions = {
                **dict(task.preconditions or {}),
                "pattern_matches": [
                    *list((task.preconditions or {}).get("pattern_matches", [])),
                    {
                        "pattern_match_id": match.id,
                        "pattern_id": match.pattern_id,
                        "score": match.score,
                        "reasons": match.reasons,
                    },
                ],
            }
            task.priority = max(task.priority, 95)
        return matches

    def create_pattern_from_finding(
        self,
        session,  # noqa: ANN001
        *,
        scan: Scan,
        finding: Finding,
    ) -> VulnerabilityPattern | None:
        if finding.status not in {
            FindingStatus.REPRODUCED_BLACKBOX.value,
            FindingStatus.ACCEPTED.value,
        }:
            return None
        snapshot = session.scalar(
            select(SecuritySnapshot).where(SecuritySnapshot.scan_id == scan.id)
        )
        if snapshot is None:
            return None
        entry_ids = set(finding.entry_point_ids or [])
        facts = [
            item
            for item in (snapshot.payload or {}).get("entries", [])
            if item.get("entry_id") in entry_ids
        ]
        if not facts:
            return None
        proof_attempt_ids = list((finding.metadata_json or {}).get("proof_attempt_ids") or [])
        attempts = (
            list(
                session.scalars(select(ProofAttempt).where(ProofAttempt.id.in_(proof_attempt_ids)))
            )
            if proof_attempt_ids
            else []
        )
        primary = facts[0]
        impact = next(
            (
                str(
                    (attempt.oracle or {}).get("impact")
                    or ((attempt.plan or {}).get("oracle") or {}).get("impact")
                )
                for attempt in attempts
                if (attempt.oracle or {}).get("impact")
                or ((attempt.plan or {}).get("oracle") or {}).get("impact")
            ),
            "unknown_impact",
        )
        kind = str(primary["manifest"]["kind"])
        vulnerability_class = f"{kind}:{impact}"
        key_calls = sorted(
            {
                call
                for fact in facts
                for call in fact["code"].get("calls", [])
                if any(term in call for term in _SINK_TERMS)
            }
        )[:30]
        guards = sorted({guard for fact in facts for guard in fact["code"].get("guards", [])})
        missing_guards = []
        if not primary["manifest"].get("permission"):
            missing_guards.append("manifest_permission")
        if not guards:
            missing_guards.append("caller_authorization")
        fingerprint_payload = {
            "vulnerability_class": vulnerability_class,
            "kind": kind,
            "key_calls": key_calls,
            "missing_guards": missing_guards,
        }
        fingerprint = _digest(fingerprint_payload)
        pattern = session.scalar(
            select(VulnerabilityPattern).where(VulnerabilityPattern.fingerprint == fingerprint)
        )
        proof_plan = dict(attempts[0].plan or {}) if attempts else {}
        if pattern is None:
            pattern = VulnerabilityPattern(
                fingerprint=fingerprint,
                source_finding_id=finding.id,
                source_scan_id=scan.id,
                vulnerability_class=vulnerability_class,
                title=finding.title,
                attacker_model={"principal": "ordinary_app_uid"},
                entry_signature={
                    "kind": kind,
                    "exported": primary["manifest"].get("exported"),
                    "permission_absent": not primary["manifest"].get("permission"),
                    "intent_shape": primary["manifest"].get("deep_links", []),
                },
                code_signature={
                    "key_calls": key_calls,
                    "guards_present": guards,
                    "sinks": primary["code"].get("sinks", []),
                },
                missing_guards=missing_guards,
                exclusion_conditions=[
                    "signature_or_privileged_permission_blocks ordinary_app_uid",
                    "platform proof Oracle does not demonstrate harm",
                ],
                proof_recipe={
                    "request": proof_plan,
                    "impact": impact,
                    "source_proof_attempt_ids": proof_attempt_ids,
                },
                metadata_json={"source_snapshot_hash": snapshot.snapshot_hash},
            )
            session.add(pattern)
            session.flush()
        return pattern

    def search_patterns(
        self,
        session,  # noqa: ANN001
        *,
        scan: Scan,
        entries: Iterable[EntryPoint],
        minimum_score: int = 55,
    ) -> list[PatternMatch]:
        snapshot = session.scalar(
            select(SecuritySnapshot).where(SecuritySnapshot.scan_id == scan.id)
        )
        if snapshot is None:
            return []
        facts_by_id = {
            item["entry_id"]: item for item in (snapshot.payload or {}).get("entries", [])
        }
        patterns = list(
            session.scalars(
                select(VulnerabilityPattern).where(VulnerabilityPattern.status == "validated")
            )
        )
        produced: list[PatternMatch] = []
        for pattern in patterns:
            expected = dict(pattern.entry_signature or {})
            expected_code = dict(pattern.code_signature or {})
            expected_calls = set(expected_code.get("key_calls", []))
            for entry in entries:
                fact = facts_by_id.get(entry.id)
                if fact is None or entry.kind != expected.get("kind"):
                    continue
                score = 35
                reasons = ["entry_kind_matches"]
                if expected.get("permission_absent") and not entry.permission:
                    score += 20
                    reasons.append("same_unprotected_manifest_boundary")
                actual_calls = set(fact["code"].get("calls", []))
                if expected_calls:
                    overlap = len(expected_calls & actual_calls) / len(expected_calls)
                    score += round(overlap * 35)
                    if overlap:
                        reasons.append(f"security_api_overlap={overlap:.2f}")
                if not set(fact["code"].get("guards", [])):
                    score += 10
                    reasons.append("caller_guard_not_observed")
                if score < minimum_score:
                    continue
                existing = session.scalar(
                    select(PatternMatch).where(
                        PatternMatch.pattern_id == pattern.id,
                        PatternMatch.scan_id == scan.id,
                        PatternMatch.entry_point_id == entry.id,
                    )
                )
                if existing is None:
                    existing = PatternMatch(
                        pattern_id=pattern.id,
                        scan_id=scan.id,
                        entry_point_id=entry.id,
                        score=min(score, 100),
                        reasons=reasons,
                        metadata_json={
                            "source_finding_id": pattern.source_finding_id,
                            "candidate_only": True,
                        },
                    )
                    session.add(existing)
                    session.flush()
                produced.append(existing)
        return produced

    @staticmethod
    def annotate_new_pattern_matches(
        session,  # noqa: ANN001
        *,
        scan_id: str,
        matches: Iterable[PatternMatch],
    ) -> None:
        queued = list(
            session.scalars(
                select(InvestigationTask).where(
                    InvestigationTask.scan_id == scan_id,
                    InvestigationTask.status == TaskStatus.QUEUED.value,
                )
            )
        )
        for match in matches:
            task = next(
                (
                    candidate
                    for candidate in queued
                    if match.entry_point_id in candidate.target_entry_ids
                ),
                None,
            )
            if task is None:
                continue
            task.preconditions = {
                **dict(task.preconditions or {}),
                "pattern_matches": [
                    *list((task.preconditions or {}).get("pattern_matches", [])),
                    {
                        "pattern_match_id": match.id,
                        "pattern_id": match.pattern_id,
                        "score": match.score,
                        "reasons": match.reasons,
                    },
                ],
            }
            task.priority = max(task.priority, 95)

    @staticmethod
    def record_static_events(
        session,  # noqa: ANN001
        *,
        scan_id: str,
        snapshot: SecuritySnapshot,
        diff: VersionDiff | None,
        pattern_matches: list[PatternMatch],
    ) -> None:
        add_event(
            session,
            scan_id,
            "security_snapshot.created",
            "版本安全快照已生成",
            {"snapshot_hash": snapshot.snapshot_hash},
        )
        if diff is not None:
            add_event(
                session,
                scan_id,
                "version_diff.completed",
                "版本语义安全 Diff 已完成",
                {
                    "baseline_scan_id": diff.baseline_scan_id,
                    **dict(diff.summary or {}),
                },
            )
        if pattern_matches:
            add_event(
                session,
                scan_id,
                "pattern_search.completed",
                "已发现需要验证的同类漏洞候选",
                {"count": len(pattern_matches)},
            )
