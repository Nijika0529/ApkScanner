from __future__ import annotations

import html
import json
from typing import Any

from sqlalchemy import case, select
from sqlalchemy.orm import Session, selectinload

from ..core.models import (
    BenchmarkEvaluation,
    CoverageItem,
    EntryPoint,
    Evidence,
    Finding,
    InvestigationTask,
    Scan,
    SecurityHypothesis,
)
from ..core.proof_receipts import evidence_backed_harm_attempts
from ..runtime.finding_policy import evidence_backed_signal_tiers, partition_findings


class ReportBuilder:
    def build(
        self,
        session: Session,
        scan: Scan,
        *,
        agent_audits: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        entries = list(
            session.scalars(
                select(EntryPoint)
                .where(EntryPoint.scan_id == scan.id)
                .order_by(EntryPoint.kind, EntryPoint.name)
            )
        )
        finding_records = list(
            session.scalars(
                select(Finding)
                .where(Finding.scan_id == scan.id)
                .order_by(
                    case(
                        (Finding.severity == "critical", 0),
                        (Finding.severity == "high", 1),
                        (Finding.severity == "medium", 2),
                        (Finding.severity == "low", 3),
                        else_=4,
                    ),
                    Finding.created_at,
                )
            )
        )
        findings, signals = partition_findings(session, finding_records)
        signal_tiers = evidence_backed_signal_tiers(session, signals)
        tasks = list(
            session.scalars(
                select(InvestigationTask)
                .where(
                    InvestigationTask.scan_id == scan.id,
                    InvestigationTask.status != "deleted",
                )
                .order_by(InvestigationTask.priority.desc())
            )
        )
        coverage = list(
            session.scalars(
                select(CoverageItem)
                .where(
                    CoverageItem.scan_id == scan.id,
                    CoverageItem.control_id != "ENGINE-MOBSF",
                )
                .order_by(CoverageItem.domain, CoverageItem.control_id)
            )
        )
        evidence = list(
            session.scalars(
                select(Evidence)
                .where(Evidence.scan_id == scan.id)
                .order_by(Evidence.created_at, Evidence.id)
            )
        )
        hypotheses = list(
            session.scalars(
                select(SecurityHypothesis)
                .where(SecurityHypothesis.scan_id == scan.id)
                .options(
                    selectinload(SecurityHypothesis.arguments),
                    selectinload(SecurityHypothesis.proof_attempts),
                )
                .order_by(SecurityHypothesis.created_at)
            )
        )
        evaluations = list(
            session.scalars(
                select(BenchmarkEvaluation)
                .where(BenchmarkEvaluation.scan_id == scan.id)
                .order_by(BenchmarkEvaluation.created_at)
            )
        )
        hypothesis_ids = {item.id for item in hypotheses}
        platform_harm_attempt_ids = {
            attempt.id
            for attempt in evidence_backed_harm_attempts(
                session,
                scan_id=scan.id,
                hypothesis_ids=hypothesis_ids,
            )
        }
        return {
            "schema_version": "1.0",
            "scan": {
                "id": scan.id,
                "status": scan.status,
                "filename": scan.filename,
                "artifact_sha256": scan.artifact_sha256,
                "package_name": scan.package_name,
                "version_name": scan.version_name,
                "version_code": scan.version_code,
                "min_sdk": scan.min_sdk,
                "target_sdk": scan.target_sdk,
                "signing": scan.signing,
                "tool_versions": scan.tool_versions,
                "stats": scan.stats,
                "error": scan.error,
                "preliminary_at": scan.preliminary_at.isoformat() if scan.preliminary_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "limitations": [
                    "APK-only analysis; source code and backend authorization are not available.",
                    "Dynamic behavior depends on the connected dedicated Android test device.",
                    "Cloud-device cleanup uses pm clear and cannot restore a full snapshot.",
                ],
            },
            "entry_points": [self._entry(item) for item in entries],
            "findings": [self._finding(item) for item in findings],
            "signals": [
                self._finding(
                    item,
                    signal_tier=signal_tiers[item.id],
                )
                for item in signals
            ],
            "tasks": [self._task(item) for item in tasks],
            "security_hypotheses": [
                self._security_hypothesis(
                    item,
                    platform_harm_attempt_ids=platform_harm_attempt_ids,
                )
                for item in hypotheses
            ],
            "benchmark_evaluations": [self._benchmark_evaluation(item) for item in evaluations],
            "agent_audits": agent_audits or [],
            "coverage": [self._coverage(item) for item in coverage],
            "evidence": [self._evidence(item) for item in evidence],
        }

    @staticmethod
    def _entry(item: EntryPoint) -> dict[str, Any]:
        return {
            "id": item.id,
            "kind": item.kind,
            "name": item.name,
            "owner_component": item.owner_component,
            "exported": item.exported,
            "exported_reason": item.exported_reason,
            "permission": item.permission,
            "permission_protection": item.permission_protection,
            "intent_filters": item.intent_filters,
            "deep_links": item.deep_links,
            "code_anchors": item.code_anchors,
            "metadata": item.metadata_json,
        }

    @staticmethod
    def _finding(
        item: Finding,
        *,
        signal_tier: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "id": item.id,
            "rule_id": item.rule_id,
            "source": item.source,
            "title": item.title,
            "description": item.description,
            "remediation": item.remediation,
            "masvs": item.masvs,
            "cwe": item.cwe,
            "severity": item.severity,
            "confidence": item.confidence,
            "status": item.status,
            "entry_point_ids": item.entry_point_ids,
            "locations": item.locations,
            "evidence_ids": item.evidence_ids,
            "metadata": item.metadata_json,
            "review_note": item.review_note,
        }
        if signal_tier is not None:
            payload["signal_tier"] = signal_tier
        return payload

    @staticmethod
    def _task(item: InvestigationTask) -> dict[str, Any]:
        return {
            "id": item.id,
            "type": item.task_type,
            "status": item.status,
            "priority": item.priority,
            "target_entry_ids": item.target_entry_ids,
            "hypotheses": item.hypotheses,
            "result": item.result,
            "thread_id": item.thread_id,
            "turn_id": item.turn_id,
            "attempts": item.attempts,
            "error": item.error,
        }

    @staticmethod
    def _security_hypothesis(
        item: SecurityHypothesis,
        *,
        platform_harm_attempt_ids: set[str],
    ) -> dict[str, Any]:
        return {
            "id": item.id,
            "task_id": item.task_id,
            "fingerprint": item.fingerprint,
            "category": item.category,
            "claim": item.claim,
            "attacker_model": item.attacker_model,
            "preconditions": item.preconditions,
            "impact": item.impact,
            "status": item.status,
            "confidence_score": item.confidence_score,
            "source_role": item.source_role,
            "entry_point_ids": item.entry_point_ids,
            "support_evidence_ids": item.support_evidence_ids,
            "refute_evidence_ids": item.refute_evidence_ids,
            "proof_obligations": item.proof_obligations,
            "final_finding_id": item.final_finding_id,
            "metadata": item.metadata_json,
            "arguments": [
                {
                    "id": argument.id,
                    "role": argument.role,
                    "position": argument.position,
                    "phase": argument.phase,
                    "backend": argument.backend,
                    "model": argument.model,
                    "payload": argument.payload,
                    "evidence_ids": argument.evidence_ids,
                    "created_at": argument.created_at.isoformat(),
                }
                for argument in item.arguments
            ],
            "proof_attempts": [
                {
                    "id": proof.id,
                    "test_case_id": proof.test_case_id,
                    "prover": proof.prover,
                    "status": proof.status,
                    "plan": proof.plan,
                    "proof_recipe": proof.proof_recipe,
                    "oracle": proof.oracle,
                    "evidence_ids": proof.evidence_ids,
                    "harm_demonstrated": proof.harm_demonstrated,
                    "platform_harm_proven": proof.id in platform_harm_attempt_ids,
                    "error": proof.error,
                    "started_at": (proof.started_at.isoformat() if proof.started_at else None),
                    "completed_at": (
                        proof.completed_at.isoformat() if proof.completed_at else None
                    ),
                }
                for proof in item.proof_attempts
            ],
        }

    @staticmethod
    def _benchmark_evaluation(item: BenchmarkEvaluation) -> dict[str, Any]:
        return {
            "id": item.id,
            "name": item.name,
            "artifact_sha256": item.artifact_sha256,
            "investigator_backend": item.investigator_backend,
            "model": item.model,
            "ground_truth": item.ground_truth,
            "result": item.result,
            "created_at": item.created_at.isoformat(),
        }

    @staticmethod
    def _coverage(item: CoverageItem) -> dict[str, Any]:
        return {
            "id": item.id,
            "control_id": item.control_id,
            "domain": item.domain,
            "title": item.title,
            "status": item.status,
            "stages": item.stages,
            "gap_reason": item.gap_reason,
            "entry_point_id": item.entry_point_id,
        }

    @staticmethod
    def _evidence(item: Evidence) -> dict[str, Any]:
        return {
            "id": item.id,
            "task_id": item.task_id,
            "kind": item.kind,
            "sha256": item.sha256,
            "command": item.command,
            "exit_code": item.exit_code,
            "summary": item.summary,
            "metadata": item.metadata_json,
            "created_at": item.created_at.isoformat(),
        }

    def sarif(self, report: dict[str, Any]) -> dict[str, Any]:
        findings = report["findings"]
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []
        level_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }
        for finding in findings:
            rule_id = finding["rule_id"]
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "shortDescription": {"text": finding["title"]},
                    "help": {"text": finding["remediation"]},
                    "properties": {
                        "masvs": finding["masvs"],
                        "cwe": finding["cwe"],
                        "confidence": finding["confidence"],
                    },
                },
            )
            locations = []
            for location in finding["locations"]:
                path = location.get("path", "AndroidManifest.xml")
                region = {}
                if location.get("line"):
                    region["startLine"] = location["line"]
                physical = {"artifactLocation": {"uri": path}}
                if region:
                    physical["region"] = region
                locations.append({"physicalLocation": physical})
            results.append(
                {
                    "ruleId": rule_id,
                    "level": level_map.get(finding["severity"], "warning"),
                    "message": {"text": finding["description"]},
                    "locations": locations,
                    "properties": {
                        "status": finding["status"],
                        "evidenceIds": finding["evidence_ids"],
                    },
                }
            )
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "APK Scanner",
                            "version": "0.1.0",
                            "informationUri": "https://mas.owasp.org/",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

    def html(self, report: dict[str, Any]) -> str:
        scan = report["scan"]
        finding_rows = "".join(
            "<tr>"
            f"<td>{html.escape(item['severity'])}</td>"
            f"<td>{html.escape(item['status'])}</td>"
            f"<td>{html.escape(item['title'])}</td>"
            f"<td>{html.escape(item['masvs'])}</td>"
            "</tr>"
            for item in report["findings"]
        )
        signal_sections: list[str] = []
        for tier, title, description in (
            (
                "runtime_oracle_gap",
                "运行已观察 · 缺 Oracle",
                "已观察目标行为，但尚无平台 ProofAttempt 证明具体安全影响。",
            ),
            (
                "static_chain",
                "完整静态攻击链 · 待证明",
                "已通过 source/control/sink/path/boundary/impact/control-gap 硬门槛。",
            ),
            (
                "raw_candidate",
                "原始与低证据线索",
                "规则/API 命中或已关闭记录，不代表漏洞成立。",
            ),
        ):
            tier_items = [
                item for item in report["signals"] if item.get("signal_tier") == tier
            ]
            if not tier_items:
                continue
            rows = "".join(
                "<tr>"
                f"<td>{html.escape(item['severity'])}</td>"
                f"<td>{html.escape(item['status'])}</td>"
                f"<td>{html.escape(item['title'])}</td>"
                f"<td>{html.escape(item['source'])}</td>"
                "</tr>"
                for item in tier_items
            )
            signal_sections.append(
                f"<h3>{html.escape(title)} ({len(tier_items)})</h3>"
                f"<p>{html.escape(description)}</p>"
                "<table><thead><tr><th>Severity</th><th>Status</th>"
                "<th>Title</th><th>Source</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )
        rendered_signal_sections = "".join(signal_sections) or "<p>没有待验证线索。</p>"
        audit_rows = "".join(
            "<tr>"
            f"<td>{html.escape(item['phase'])}</td>"
            f"<td>{html.escape(item['backend'])}</td>"
            f"<td>{html.escape(item['model'])}</td>"
            f"<td>{html.escape(item['status'])}</td>"
            f"<td>{html.escape(item['integrity'])}</td>"
            f"<td><code>{html.escape(item['turn_id'] or '—')}</code></td>"
            "</tr>"
            for item in report["agent_audits"]
        )
        hypothesis_rows = "".join(
            "<tr>"
            f"<td><code>{html.escape(item['id'])}</code></td>"
            f"<td>{html.escape(item['status'])}</td>"
            f"<td>{html.escape(item['claim'])}</td>"
            f"<td>{len(item['proof_attempts'])}</td>"
            f"<td>{sum(1 for proof in item['proof_attempts'] if proof.get('platform_harm_proven') is True)}</td>"
            "</tr>"
            for item in report["security_hypotheses"]
        )
        limitations = "".join(f"<li>{html.escape(item)}</li>" for item in scan["limitations"])
        report_json = (
            json.dumps(report, ensure_ascii=False)
            .replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
        )
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>APK Scanner Report</title>
<style>body{{font:14px system-ui;max-width:1100px;margin:40px auto;color:#17202a}}
table{{border-collapse:collapse;width:100%}}th,td{{padding:10px;border:1px solid #d9e2ec;text-align:left}}
th{{background:#eef4f7}}code{{background:#eef4f7;padding:2px 5px}}</style></head>
<body><h1>APK 安全扫描报告</h1><p><strong>{html.escape(scan["package_name"] or scan["filename"])}</strong>
 · {html.escape(scan["status"])} · <code>{scan["artifact_sha256"]}</code></p>
<h2>Finding</h2><table><thead><tr><th>Severity</th><th>Status</th><th>Title</th><th>MASVS</th></tr></thead>
<tbody>{finding_rows}</tbody></table>
<h2>待验证信号分层</h2>{rendered_signal_sections}
<h2>验证链</h2><table><thead><tr><th>Hypothesis ID</th><th>Status</th><th>Claim</th>
<th>Proof Attempts</th><th>Harm Proven</th></tr></thead><tbody>{hypothesis_rows}</tbody></table>
<h2>AI 审计</h2><table><thead><tr><th>Phase</th><th>Backend</th><th>Model</th><th>Status</th>
<th>Integrity</th><th>Turn</th></tr></thead><tbody>{audit_rows}</tbody></table>
<p>精确输入、结构化输出和平台校验内容保存在下方 <code>report-data</code> JSON 中。</p>
<h2>限制</h2><ul>{limitations}</ul>
<script type="application/json" id="report-data">{report_json}</script>
</body></html>"""
