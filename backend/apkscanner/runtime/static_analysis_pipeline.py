from __future__ import annotations

import time
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..analysis.asc_xrefs import AscXrefExtractor, build_asc_queries, evidence_summary
from ..analysis.rules import BuiltinRuleEngine
from ..analysis.security_design import build_android_threat_model, finding_identity
from ..analysis.static_analysis import ApkInspector
from ..analysis.target_profiles import (
    active_profile_id,
    investigation_group,
    target_review_surfaces,
)
from ..core.config import Settings
from ..core.db import Database
from ..core.enums import (
    CoverageStatus,
    EntryPointKind,
    FindingStatus,
    ScanStatus,
)
from ..core.evidence import EvidenceRecorder
from ..core.models import CoverageItem, EntryPoint, Finding, Scan
from ..core.repository import add_event, now
from ..infrastructure.tools import TimeBudget
from .device import AdbDevicePool
from .planner import InvestigationPlanner
from .versioning import SecurityEvolutionService


class StaticAnalysisPipeline:
    """Materialize static facts, evidence, entry points, and investigation plans."""

    def __init__(
        self,
        *,
        settings: Settings,
        database: Database,
        inspector: ApkInspector,
        asc: AscXrefExtractor,
        rules: BuiltinRuleEngine,
        evidence: EvidenceRecorder,
        device_pool: AdbDevicePool,
        security_evolution: SecurityEvolutionService,
    ) -> None:
        self.settings = settings
        self.database = database
        self.inspector = inspector
        self.asc = asc
        self.rules = rules
        self.evidence = evidence
        self.device_pool = device_pool
        self.security_evolution = security_evolution

    def run(self, scan_id: str) -> None:
        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                raise LookupError(f"unknown scan {scan_id}")
            if scan.status in {
                ScanStatus.STATIC_COMPLETE.value,
                ScanStatus.PRELIMINARY_READY.value,
                ScanStatus.INVESTIGATING.value,
                ScanStatus.FINAL.value,
            }:
                return
            scan.status = ScanStatus.STATIC_RUNNING.value
            add_event(session, scan_id, "static.started", "Static analysis started")
            session.commit()

        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            assert scan is not None
            created_at = scan.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=UTC)
            preliminary_deadline = created_at + timedelta(
                seconds=self.settings.preliminary_after_seconds
            )
            preliminary_remaining = max(
                1, int((preliminary_deadline - datetime.now(UTC)).total_seconds())
            )
            preliminary_budget = TimeBudget.from_seconds(preliminary_remaining)
            phase_labels = {
                "static_cache": "静态缓存恢复",
                "static_cache_publish": "静态缓存发布",
                "decompilation": "APK 解包与反编译",
                "code_index": "组件代码索引",
                "android_attack_chains": "Android 攻击链索引",
                "native_analysis": "Native/JNI 资产分析",
                "embedded_artifacts": "内嵌 APK 与插件链",
                "rule_evaluation": "静态规则评估",
                "target_profile": "目标审计 Profile 规划",
                "asc_xrefs": "ASC 字节码交叉引用",
            }
            static_phase_started: dict[str, float] = {}

            def record_static_phase(
                phase: str,
                status: str,
                details: dict[str, Any] | None = None,
            ) -> None:
                label = phase_labels.get(phase, phase)
                payload = dict(details or {})
                if status == "started":
                    static_phase_started[phase] = time.monotonic()
                elif phase in static_phase_started and "elapsed_seconds" not in payload:
                    payload["elapsed_seconds"] = round(
                        time.monotonic() - static_phase_started[phase],
                        3,
                    )
                payload.update({"phase": phase, "status": status})
                scan.stats = {
                    **dict(scan.stats or {}),
                    "static_progress": {
                        "phase": phase,
                        "label": label,
                        "status": status,
                        **(
                            {"elapsed_seconds": payload["elapsed_seconds"]}
                            if payload.get("elapsed_seconds") is not None
                            else {}
                        ),
                    },
                }
                add_event(
                    session,
                    scan.id,
                    f"static.phase.{status}",
                    f"{label}{'开始' if status == 'started' else '完成'}",
                    payload,
                )
                session.commit()

            result = self.inspector.inspect(
                Path(scan.artifact_path),
                scan.id,
                preliminary_budget,
                _progress=record_static_phase,
            )
            record_static_phase("rule_evaluation", "started")
            findings, coverage = self.rules.evaluate(result)
            record_static_phase(
                "rule_evaluation",
                "completed",
                {"finding_count": len(findings)},
            )
            record_static_phase("target_profile", "started")
            static_review_surfaces = self.rules.static_review_surfaces(
                result.manifest,
                findings,
            )
            static_review_surfaces.extend(self.rules.embedded_artifact_review_surfaces(result))
            static_review_surfaces.extend(target_review_surfaces(result))
            for surface in static_review_surfaces:
                if surface.investigation_group is None:
                    surface.investigation_group = investigation_group(
                        package_name=result.manifest.package_name,
                        name=surface.name,
                        owner_component=surface.name,
                        static_family=surface.family,
                        artifact=surface.artifact,
                    )
            record_static_phase(
                "target_profile",
                "completed",
                {
                    "profile": active_profile_id(result.manifest.package_name),
                    "surface_count": len(static_review_surfaces),
                },
            )
            for surface in static_review_surfaces:
                self.inspector.add_static_surface_to_code_index(
                    result,
                    surface_name=surface.name,
                    locations=surface.locations,
                    attack_chains=surface.attack_chains,
                    package_name=(
                        str(surface.artifact.get("package_name"))
                        if surface.artifact and surface.artifact.get("package_name")
                        else None
                    ),
                )
                for finding in findings:
                    if (
                        finding.rule_id in surface.rule_ids
                        and surface.name not in finding.entry_names
                    ):
                        finding.entry_names.append(surface.name)
            if static_review_surfaces:
                self.inspector.persist_code_index(result)
            scan.package_name = result.manifest.package_name
            scan.version_name = result.manifest.version_name
            scan.version_code = result.manifest.version_code
            scan.min_sdk = result.manifest.min_sdk
            scan.target_sdk = result.manifest.target_sdk
            scan.signing = result.signing
            scan.tool_versions = result.tool_versions
            scan.stats = {
                **scan.stats,
                **result.file_inventory,
                "workspace": str(result.workspace),
                "static_finding_count": len(findings),
                "attack_chain_inventory": {
                    "total": len(result.attack_chains),
                    "review_required": sum(
                        item.get("review_required") is not False for item in result.attack_chains
                    ),
                    "families": dict(
                        Counter(
                            str(item.get("family") or "unknown") for item in result.attack_chains
                        )
                    ),
                    "kinds": dict(
                        Counter(
                            str(item.get("chain_kind") or "unknown")
                            for item in result.attack_chains
                        )
                    ),
                    "engine_versions": sorted(
                        {
                            str(item.get("engine_version"))
                            for item in result.attack_chains
                            if item.get("engine_version")
                        }
                    ),
                },
                "preliminary_deadline": preliminary_deadline.isoformat(),
                "target_audit_profile": active_profile_id(result.manifest.package_name),
                "decompilation": {
                    key: value
                    for key, value in result.decompilation.items()
                    if key != "failed_classes"
                },
            }
            entries: list[EntryPoint] = []
            for parsed in result.manifest.entries:
                code_context = result.code_index.get(
                    parsed.owner_component or parsed.name,
                    {},
                )
                public_anchors = [
                    {key: value for key, value in anchor.items() if key != "content"}
                    for anchor in code_context.get("anchors", [])
                    if isinstance(anchor, dict)
                ]
                profile_group = investigation_group(
                    package_name=result.manifest.package_name,
                    name=parsed.name,
                    owner_component=parsed.owner_component,
                )
                entry = EntryPoint(
                    scan_id=scan.id,
                    kind=parsed.kind,
                    name=parsed.name,
                    owner_component=parsed.owner_component,
                    exported=parsed.exported,
                    exported_reason=parsed.exported_reason,
                    permission=parsed.permission,
                    permission_protection=parsed.permission_protection,
                    intent_filters=parsed.intent_filters,
                    deep_links=parsed.deep_links,
                    code_anchors=public_anchors,
                    metadata_json={
                        **parsed.metadata,
                        **(
                            {"investigation_group": profile_group}
                            if profile_group is not None
                            else {}
                        ),
                        "decompilation": {
                            "status": code_context.get("status", "source_not_found"),
                            "target_in_jadx_failure_list": bool(
                                code_context.get("target_in_jadx_failure_list")
                            ),
                            "target_source_has_decompiler_errors": bool(
                                code_context.get("target_source_has_decompiler_errors")
                            ),
                            "global_status": code_context.get(
                                "global_decompilation_status",
                                result.decompilation.get("status"),
                            ),
                        },
                    },
                )
                session.add(entry)
                entries.append(entry)
            for surface in static_review_surfaces:
                code_context = result.code_index.get(surface.name, {})
                public_anchors = [
                    {key: value for key, value in anchor.items() if key != "content"}
                    for anchor in code_context.get("anchors", [])
                    if isinstance(anchor, dict)
                ]
                entry = EntryPoint(
                    scan_id=scan.id,
                    kind=EntryPointKind.STATIC_SURFACE.value,
                    name=surface.name,
                    owner_component=surface.name,
                    exported=False,
                    exported_reason="static_semantic_seed",
                    permission=None,
                    permission_protection=None,
                    intent_filters=[],
                    deep_links=[],
                    code_anchors=public_anchors,
                    metadata_json={
                        "effective_enabled": True,
                        "direct_invocation_applicable": False,
                        "static_review_family": surface.family,
                        "static_review_title": surface.title,
                        "static_review_severity": surface.severity,
                        "static_review_priority": surface.priority,
                        "static_review_rule_ids": surface.rule_ids,
                        "static_review_hypotheses": surface.hypotheses,
                        "static_review_locations": surface.locations,
                        "static_review_attack_chains": surface.attack_chains,
                        "static_review_artifact": surface.artifact,
                        "static_review_rollup": surface.rollup,
                        **(
                            {"static_review_site": surface.site}
                            if surface.site is not None
                            else {}
                        ),
                        **(
                            {"static_review_parent_surface": surface.parent_surface}
                            if surface.parent_surface
                            else {}
                        ),
                        **(
                            {"investigation_group": surface.investigation_group}
                            if surface.investigation_group is not None
                            else {}
                        ),
                        "decompilation": {
                            "status": code_context.get(
                                "status",
                                "source_not_found",
                            ),
                            "global_status": code_context.get(
                                "global_decompilation_status",
                                result.decompilation.get("status"),
                            ),
                        },
                    },
                )
                session.add(entry)
                entries.append(entry)
            session.flush()
            threat_model = build_android_threat_model(scan, entries)
            scan.stats = {
                **scan.stats,
                "threat_model": threat_model,
            }
            entry_ids_by_name: dict[str, list[str]] = defaultdict(list)
            for entry in entries:
                entry_ids_by_name[entry.name].append(entry.id)
            persisted_findings: list[Finding] = []
            for draft in findings:
                entry_ids = [
                    entry_id
                    for name in draft.entry_names
                    for entry_id in entry_ids_by_name.get(name, [])
                ]
                identity = finding_identity(
                    scan=scan,
                    rule_id=draft.rule_id,
                    category="static_signal",
                    entry_names=[
                        *draft.entry_names,
                        *[
                            str(location[key])
                            for location in draft.locations
                            for key in ("component", "path")
                            if location.get(key)
                        ],
                    ],
                    claim=draft.title,
                )
                persisted_finding = Finding(
                    scan_id=scan.id,
                    dedupe_key=draft.dedupe_key,
                    rule_id=draft.rule_id,
                    source=draft.source,
                    title=draft.title,
                    description=draft.description,
                    remediation=draft.remediation,
                    masvs=draft.masvs,
                    cwe=draft.cwe,
                    severity=draft.severity,
                    confidence=draft.confidence,
                    status=FindingStatus.CANDIDATE.value,
                    entry_point_ids=entry_ids,
                    locations=draft.locations,
                    metadata_json={**draft.metadata, "identity": identity},
                )
                session.add(persisted_finding)
                persisted_findings.append(persisted_finding)
            for item in coverage:
                session.add(
                    CoverageItem(
                        scan_id=scan.id,
                        control_id=item.control_id,
                        domain=item.domain,
                        title=item.title,
                        status=item.status,
                        stages=item.stages,
                        gap_reason=item.gap_reason,
                    )
                )
            entry_coverage: dict[str, CoverageItem] = {}
            for entry in entries:
                coverage_item = CoverageItem(
                    scan_id=scan.id,
                    control_id=f"ENTRY-{entry.id}",
                    domain="MASVS-PLATFORM",
                    title=f"Entry point: {entry.name}",
                    status=CoverageStatus.PARTIAL.value,
                    stages={
                        "static": "completed",
                        "deterministic_dynamic": "pending",
                        "agent": "pending",
                        "blackbox": "pending",
                    },
                    gap_reason="Dynamic and semantic investigation pending.",
                    entry_point_id=entry.id,
                )
                session.add(coverage_item)
                entry_coverage[entry.id] = coverage_item
            for tool, payload in result.tool_results.items():
                decompilation = (
                    {
                        key: value
                        for key, value in dict(payload.get("decompilation") or {}).items()
                        if key != "failed_classes"
                    }
                    if tool == "jadx"
                    else {}
                )
                timed_out = payload.get("timed_out") is True
                exit_code = payload.get("exit_code")
                output_usable = (
                    decompilation.get("output_usable") is True
                    if tool == "jadx"
                    else exit_code == 0 and not timed_out
                )
                tool_status = (
                    str(decompilation.get("status") or "unknown")
                    if tool == "jadx"
                    else "timed_out"
                    if timed_out
                    else "succeeded"
                    if exit_code == 0
                    else "tool_failed"
                )
                metadata = {
                    **decompilation,
                    "static_output_usable": output_usable,
                    "static_tool_status": tool_status,
                    "static_tool_timed_out": timed_out,
                    "static_tool_exit_code": exit_code,
                }
                self.evidence.json(
                    session,
                    scan_id=scan.id,
                    task_id=None,
                    kind=f"static.{tool}",
                    value=payload,
                    summary=self.static_tool_evidence_summary(tool, payload),
                    metadata=metadata,
                )
            self.run_asc_xrefs(
                session,
                scan,
                entries,
                preliminary_budget,
                progress=record_static_phase,
            )
            planner = InvestigationPlanner(
                android_version=self.settings.device_android_version,
                android_api=self.settings.device_android_api,
                adb_configured=self.device_pool.configured,
                device_reset_policy=self.settings.device_reset_policy,
                max_standalone_chain_sites=self.settings.max_standalone_chain_sites,
            )
            investigation_plan = planner.plan_with_decisions(scan.id, entries)
            tasks = investigation_plan.tasks
            static_closures = investigation_plan.static_closures
            coalescing_decisions = investigation_plan.coalescing_decisions
            closures_by_entry = {closure.entry_point_id: closure for closure in static_closures}
            for entry_id, closure in closures_by_entry.items():
                coverage_item = entry_coverage[entry_id]
                coverage_item.status = CoverageStatus.COVERED.value
                coverage_item.stages = {
                    "static": "completed",
                    "deterministic_dynamic": "not_applicable",
                    "agent": "not_applicable",
                    "blackbox": "not_applicable",
                    "indirect_chain": "retained_for_scan_wide_seed_exploration",
                }
                coverage_item.gap_reason = closure.reason
            for finding in persisted_findings:
                self.annotate_direct_reachability(
                    finding,
                    closures_by_entry,
                )
            session.add_all(tasks)
            session.flush()
            security_snapshot = self.security_evolution.build_snapshot(
                session,
                scan=scan,
                entries=entries,
                code_index=result.code_index,
            )
            fresh_run = (scan.stats or {}).get("fresh_run")
            isolated_fresh_run = isinstance(fresh_run, dict) and fresh_run.get("mode") == "isolated"
            if isolated_fresh_run:
                version_diff = None
                pattern_matches = []
                add_event(
                    session,
                    scan.id,
                    "planning.fresh_run.isolated",
                    "本轮为独立全新扫描，已禁用历史 PoC 回放与 Finding 模式卡注入",
                    {
                        "source_scan_id": fresh_run.get("source_scan_id"),
                        "reuse_apk_only": True,
                    },
                )
            else:
                version_diff = self.security_evolution.build_version_diff(
                    session,
                    scan=scan,
                    snapshot=security_snapshot,
                )
                pattern_matches = self.security_evolution.apply_diff_and_patterns(
                    session,
                    scan=scan,
                    entries=entries,
                    tasks=tasks,
                    diff=version_diff,
                )
            for replay_task in (task for task in tasks if task.task_type == "version_replay"):
                for entry_id in replay_task.target_entry_ids:
                    coverage_item = entry_coverage.get(entry_id)
                    if coverage_item is None:
                        continue
                    coverage_item.status = CoverageStatus.PARTIAL.value
                    coverage_item.stages = {
                        **dict(coverage_item.stages or {}),
                        "deterministic_dynamic": "pending",
                        "agent": "pending",
                        "blackbox": "pending",
                        "version_replay": "pending",
                        "indirect_chain": ("retained_for_scan_wide_seed_exploration"),
                    }
                    coverage_item.gap_reason = (
                        "普通应用直接入口已静态阻断；历史漏洞 PoC 仍需在"
                        "当前版本回放，以验证修复并防止回归。"
                    )
            self.security_evolution.record_static_events(
                session,
                scan_id=scan.id,
                snapshot=security_snapshot,
                diff=version_diff,
                pattern_matches=pattern_matches,
            )
            if static_closures:
                add_event(
                    session,
                    scan.id,
                    "planning.static_closed",
                    f"{len(static_closures)} 个入口的普通应用直接调用路径已静态判定为阻断",
                    {
                        "count": len(static_closures),
                        "threat_model": "ordinary_app_uid",
                        "scope": "direct_invocation_only",
                        "indirect_chain_targets_retained": True,
                        "decisions": [closure.as_dict() for closure in static_closures[:200]],
                        "truncated": len(static_closures) > 200,
                    },
                )
            if coalescing_decisions:
                avoided_task_count = sum(
                    int(item.get("avoided_task_count") or 0) for item in coalescing_decisions
                )
                add_event(
                    session,
                    scan.id,
                    "planning.tasks.coalesced",
                    f"同一攻击链的入口变体已归并，避免 {avoided_task_count} 个重复调查任务",
                    {
                        "profile": active_profile_id(result.manifest.package_name),
                        "group_count": len(coalescing_decisions),
                        "avoided_task_count": avoided_task_count,
                        "decisions": coalescing_decisions,
                    },
                )
            scan.status = ScanStatus.PRELIMINARY_READY.value
            scan.preliminary_at = now()
            dispatched_entry_ids = {
                entry_id for task in tasks for entry_id in task.target_entry_ids
            }
            scan.stats = {
                **scan.stats,
                "entry_point_count": len(entries),
                "task_count": len(tasks),
                "planning_raw_task_count": len(tasks)
                + sum(int(item.get("avoided_task_count") or 0) for item in coalescing_decisions),
                "coalesced_task_count": sum(
                    int(item.get("avoided_task_count") or 0) for item in coalescing_decisions
                ),
                "coalescing_group_count": len(coalescing_decisions),
                "static_closed_entry_count": len(static_closures),
                "agent_dispatched_entry_count": len(dispatched_entry_ids),
                "security_snapshot_hash": security_snapshot.snapshot_hash,
                "version_diff_id": version_diff.id if version_diff else None,
                "version_replay_candidate_count": (
                    len(version_diff.replay_candidates) if version_diff else 0
                ),
                "pattern_match_count": len(pattern_matches),
                "chain_site_count": investigation_plan.chain_site_total,
                "chain_site_dispatched_count": investigation_plan.chain_site_dispatched,
                "chain_site_merged_into_component_count": (
                    investigation_plan.chain_site_merged_into_component
                ),
                "chain_site_deferred_count": investigation_plan.chain_site_deferred,
            }
            if scan.preliminary_at > preliminary_deadline:
                late_by = int((scan.preliminary_at - preliminary_deadline).total_seconds())
                scan.stats = {**scan.stats, "preliminary_sla_late_seconds": late_by}
                add_event(
                    session,
                    scan.id,
                    "scan.preliminary_sla_missed",
                    "Preliminary-report deadline was missed",
                    {"late_seconds": late_by},
                )
            add_event(
                session,
                scan.id,
                "static.completed",
                "Static analysis and attack-surface planning completed",
                {
                    "entries": len(entries),
                    "findings": len(findings),
                    "tasks": len(tasks),
                    "static_closed_entries": len(static_closures),
                },
            )
            add_event(
                session,
                scan.id,
                "scan.preliminary_ready",
                "Preliminary report is ready; investigations may continue",
            )
            session.commit()

    @staticmethod
    def annotate_direct_reachability(
        finding: Finding,
        closures_by_entry: dict[str, Any],
    ) -> bool:
        """Record a blocked direct edge without closing indirect vulnerability chains."""

        linked_entries = set(finding.entry_point_ids)
        if not linked_entries or not linked_entries <= set(closures_by_entry):
            return False
        finding.metadata_json = {
            **finding.metadata_json,
            "direct_reachability_assessment": {
                "status": "blocked",
                "scope": "ordinary_app_direct_invocation_only",
                "indirect_chain_paths_evaluated": False,
                "threat_model": "ordinary_app_uid",
                "entry_decisions": [
                    closures_by_entry[entry_id].as_dict() for entry_id in sorted(linked_entries)
                ],
            },
        }
        return True

    def run_asc_xrefs(
        self,
        session,  # noqa: ANN001
        scan: Scan,
        entries: list[EntryPoint],
        budget,  # noqa: ANN001
        *,
        progress=None,  # noqa: ANN001
    ) -> None:
        """Record ASC bytecode-level inbound cross references as scan Evidence.

        Optional: disabled by default, and any failure (package missing, sandbox
        without ``multiprocessing``, tool error) becomes an unusable-tool receipt
        instead of failing the scan.
        """

        if not self.settings.asc_enabled:
            return
        if progress is not None:
            progress("asc_xrefs", "started", {"query_limit": self.settings.asc_max_queries})
        queries = build_asc_queries(
            entries,
            max_queries=self.settings.asc_max_queries,
        )
        try:
            extraction = self.asc.extract(
                Path(scan.artifact_path),
                queries,
                budget=budget,
            )
        except Exception as exc:  # defensive: extraction already isolates
            if progress is not None:
                progress(
                    "asc_xrefs",
                    "failed",
                    {"error": f"{type(exc).__name__}: {exc}"},
                )
            return
        payload = extraction.as_evidence_payload()
        usable = extraction.usable
        status = (
            "succeeded"
            if usable
            else "unavailable"
            if not extraction.references and not extraction.tool_version
            else "tool_failed"
        )
        metadata = {
            "static_output_usable": usable,
            "static_tool_status": status,
            "static_tool_timed_out": False,
            "static_tool_exit_code": 0 if usable else 1,
            "asc_transport": extraction.transport,
            "asc_tool_version": extraction.tool_version,
            "asc_reference_count": len(extraction.references),
            "asc_dex_entry_count": int(extraction.stats.get("dex_entry_count") or 0),
            "asc_error_count": len(extraction.errors),
        }
        self.evidence.json(
            session,
            scan_id=scan.id,
            task_id=None,
            kind="static.droidasc",
            value=payload,
            summary=evidence_summary(payload),
            metadata=metadata,
        )
        if progress is not None:
            progress(
                "asc_xrefs",
                "completed" if usable else "failed",
                {
                    "references": len(extraction.references),
                    "queries": len(extraction.queries),
                    "transport": extraction.transport,
                    "errors": extraction.errors[:3],
                },
            )

    @staticmethod
    def static_tool_evidence_summary(
        tool: str,
        payload: dict[str, Any],
    ) -> str:
        if tool != "jadx":
            return f"{tool} exited with {payload['exit_code']}"
        decompilation = payload.get("decompilation")
        if not isinstance(decompilation, dict):
            return f"jadx exited with {payload['exit_code']}"
        status = str(decompilation.get("status", "unknown"))
        generated = int(decompilation.get("generated_java_files", 0))
        errors = int(decompilation.get("reported_error_count", 0))
        return (
            f"jadx {status}: generated {generated} Java files; "
            f"{errors} errors reported (exit {payload['exit_code']})"
        )
