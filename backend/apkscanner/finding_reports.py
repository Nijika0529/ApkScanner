from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .models import ProofAttempt, SecurityHypothesis


class FindingVerificationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["confirmed", "pending", "refuted", "inconclusive"]
    established_facts: list[str] = Field(default_factory=list, max_length=3)
    missing_proof: str | None = Field(default=None, max_length=800)
    next_step: str | None = Field(default=None, max_length=800)
    evidence_ids: list[str] = Field(default_factory=list, max_length=64)
    proof_attempt_ids: list[str] = Field(default_factory=list, max_length=64)


class FindingReport(BaseModel):
    """Compact, hypothesis-scoped report shown by every finding surface."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    kind: Literal["finding", "pending_risk"]
    title: str = Field(min_length=1, max_length=120)
    conclusion: str = Field(min_length=1, max_length=600)
    conditions: list[str] = Field(default_factory=list, max_length=2)
    attack_chain: list[str] = Field(default_factory=list, max_length=5)
    verification: FindingVerificationReport
    remediation: list[str] = Field(default_factory=list, max_length=2)
    task_id: str
    hypothesis_id: str


def _compact(value: Any, *, limit: int) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return f"{text[: max(0, limit - 1)].rstrip()}…"


def _unique_text(values: list[Any], *, count: int, limit: int) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = _compact(value, limit=limit)
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
        if len(result) >= count:
            break
    return result


def _title(hypothesis: SecurityHypothesis, *, confirmed: bool) -> str:
    claim = _compact(hypothesis.claim, limit=88)
    prefix = "已复现" if confirmed else "待验证"
    return _compact(f"{prefix}：{claim}", limit=120)


def _remediation(assessment: dict[str, Any]) -> list[str]:
    control = _compact(assessment.get("control"), limit=240)
    sink = _compact(assessment.get("sink"), limit=240)
    items = [
        "在入口处校验调用方身份、输入来源与授权状态，拒绝跨信任边界的未授权请求。",
    ]
    if sink:
        items.append(f"在敏感操作前增加业务授权与参数约束，并为 {sink} 建立可回归的负向测试。")
    elif control:
        items.append(f"修正或补齐关键控制：{control}。")
    else:
        items.append("修复后回放当前 PoC，并确认原攻击链无法再次达到敏感结果。")
    return items[:2]


def build_finding_report(
    *,
    task_id: str,
    hypothesis: SecurityHypothesis,
    assessment: dict[str, Any] | None,
    evidence_ids: list[str],
    attempts: list[ProofAttempt] | None = None,
    coverage_gaps: list[str] | None = None,
) -> FindingReport:
    """Build a deterministic report; prose shape never depends on a task-wide summary."""

    assessment = assessment or {}
    attempts = attempts or []
    confirmed = any(attempt.harm_demonstrated for attempt in attempts)
    attack_chain = _unique_text(
        [
            assessment.get("source"),
            assessment.get("reachable_path"),
            assessment.get("boundary"),
            assessment.get("control"),
            assessment.get("sink"),
        ],
        count=5,
        limit=300,
    )
    conditions = _unique_text(
        [*(hypothesis.preconditions or []), assessment.get("boundary")],
        count=2,
        limit=240,
    )
    proof_facts = _unique_text(
        [
            *[
                (attempt.plan or {}).get("rationale")
                for attempt in attempts
                if attempt.harm_demonstrated
            ],
            *[
                (attempt.oracle or {}).get("observed_fact")
                or (attempt.oracle or {}).get("security_impact")
                for attempt in attempts
                if attempt.harm_demonstrated
            ],
            assessment.get("reachable_path"),
            assessment.get("sink"),
        ],
        count=3,
        limit=360,
    )
    gaps = _unique_text(
        [*(assessment.get("proof_gaps") or []), *(coverage_gaps or [])],
        count=2,
        limit=500,
    )
    if confirmed:
        conclusion = _compact(
            "已通过真机执行观察到该攻击链产生独立安全影响："
            f"{hypothesis.impact or hypothesis.claim}",
            limit=600,
        )
        verification = FindingVerificationReport(
            status="confirmed",
            established_facts=proof_facts,
            evidence_ids=list(dict.fromkeys(evidence_ids))[:64],
            proof_attempt_ids=[attempt.id for attempt in attempts][:64],
        )
    else:
        conclusion = _compact(
            f"静态证据支持该风险链路，但尚未形成独立危害证明：{hypothesis.claim}",
            limit=600,
        )
        missing = gaps[0] if gaps else "缺少可重复的动态危害证据。"
        verification = FindingVerificationReport(
            status="pending",
            established_facts=proof_facts,
            missing_proof=missing,
            next_step=_compact(
                f"构造最小 PoC 到达 {assessment.get('sink') or '敏感操作'}，并采集独立 Oracle 结果。",
                limit=800,
            ),
            evidence_ids=list(dict.fromkeys(evidence_ids))[:64],
        )
    return FindingReport(
        kind="finding" if confirmed else "pending_risk",
        title=_title(hypothesis, confirmed=confirmed),
        conclusion=conclusion,
        conditions=conditions,
        attack_chain=attack_chain,
        verification=verification,
        remediation=_remediation(assessment),
        task_id=task_id,
        hypothesis_id=hypothesis.id,
    )


def render_finding_description(report: FindingReport) -> str:
    lines = [report.conclusion]
    if report.conditions:
        lines.append("触发条件：" + "；".join(report.conditions))
    if report.attack_chain:
        lines.append("攻击链：" + " → ".join(report.attack_chain))
    facts = report.verification.established_facts
    if facts:
        lines.append("验证事实：" + "；".join(facts))
    if report.verification.missing_proof:
        lines.append("待补证据：" + report.verification.missing_proof)
    if report.verification.next_step:
        lines.append("下一步：" + report.verification.next_step)
    return "\n".join(lines)


def render_finding_remediation(report: FindingReport) -> str:
    return "\n".join(f"{index}. {item}" for index, item in enumerate(report.remediation, 1))
