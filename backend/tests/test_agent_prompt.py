from __future__ import annotations

import pytest
from apkscanner.agent_prompt import developer_instructions
from apkscanner.schemas import AgentInvestigationResult, AgentRequestedTest
from pydantic import ValidationError


def _result(summary: str) -> AgentInvestigationResult:
    return AgentInvestigationResult(
        summary=summary,
        result="refuted_static",
        hypotheses_tested=[],
        test_cases=[],
        evidence_ids=[],
        severity_proposal="info",
        confidence="medium",
        coverage_gaps=[],
        followups=[],
        requested_tests=[],
    )


def test_final_agent_summary_requires_chinese_text() -> None:
    assert _result("静态证据表明调用路径受到权限检查保护。").summary.startswith("静态证据")
    with pytest.raises(ValidationError, match="string_pattern_mismatch"):
        _result("The caller path is protected by a permission check.")


def test_agent_instructions_require_chinese_but_preserve_identifiers() -> None:
    instructions = developer_instructions(direct_tool_access=True)

    assert "Simplified Chinese" in instructions
    assert "Evidence IDs" in instructions
    assert "class names" in instructions


def test_invalid_optional_requested_test_does_not_discard_static_verdict() -> None:
    payload = {
        "summary": "静态证据已经反驳普通第三方应用的攻击路径。",
        "result": "refuted_static",
        "hypotheses_tested": [],
        "test_cases": [],
        "evidence_ids": [],
        "severity_proposal": "info",
        "confidence": "high",
        "coverage_gaps": [],
        "followups": [],
        "requested_tests": [
            {
                "hypothesis_id": "00000000-0000-0000-0000-000000000001",
                "entry_point_id": "00000000-0000-0000-0000-000000000002",
                "state": "guest",
                "uri": None,
                "extras": {},
                "operation": "auto",
                "method": "bindOrTransact",
                "argument": "1",
                "rationale": "尝试调用 Service Binder。",
            }
        ],
    }

    result = AgentInvestigationResult.model_validate(payload)

    assert result.result == "refuted_static"
    assert result.requested_tests == []
    assert result.coverage_gaps == [
        "平台忽略了 1 个格式或能力不受支持的补充测试请求；静态证据结论仍予保留。"
    ]
    with pytest.raises(ValidationError, match="only valid for provider call"):
        AgentRequestedTest.model_validate(payload["requested_tests"][0])
