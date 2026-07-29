from __future__ import annotations

import pytest
from apkscanner.agent_prompt import developer_instructions, investigation_prompt
from apkscanner.models import EntryPoint, InvestigationTask, Scan
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


def test_agent_adb_policy_keeps_full_access_with_hard_safety_boundary() -> None:
    instructions = developer_instructions(
        direct_tool_access=True,
        workspace_write=True,
        adb_access=True,
    )

    assert "ADB is fully available" in instructions
    assert "platform_context.device.serial" in instructions
    assert "adb tcpip" in instructions
    assert "adb forward/reverse" in instructions
    assert "adb root" in instructions
    assert "uninstall temporary PoC APKs" in instructions
    assert "platform requested_test" in instructions
    assert "assigned coverage seed is a hard workflow scope" in instructions
    assert "Do not use a broad glob" in instructions
    assert "A zero-result search ends that proposed branch" in instructions
    assert "without discovering or invoking an Android SDK toolchain" in instructions


def _phase_prompt(phase: str, *, response_contract: str = "structured_result") -> str:
    scan = Scan(
        id="00000000-0000-0000-0000-000000000001",
        status="investigating",
        filename="sample.apk",
        package_name="com.example.sample",
        artifact_sha256="a" * 64,
        artifact_path="/tmp/sample.apk",
    )
    entry = EntryPoint(
        id="00000000-0000-0000-0000-000000000002",
        scan_id=scan.id,
        kind="activity",
        name="com.example.sample.MainActivity",
        owner_component="com.example.sample.MainActivity",
        exported=True,
    )
    task = InvestigationTask(
        id="00000000-0000-0000-0000-000000000003",
        scan_id=scan.id,
        task_type="component",
        target_entry_ids=[entry.id],
    )
    return investigation_prompt(
        scan,
        task,
        [entry],
        [],
        {"phase": phase},
        direct_tool_access=True,
        workspace_write=True,
        adb_access=True,
        response_contract=response_contract,
    )


def test_agent_round_prompts_have_distinct_non_conflicting_roles() -> None:
    planning = _phase_prompt("test_planning")
    continuation = _phase_prompt("exploration_round")
    critic = _phase_prompt("adversarial_review")
    final = _phase_prompt("final_evaluation")
    memo = _phase_prompt("test_planning", response_contract="analysis_memo")

    assert "seed-focused analysis pass" in planning
    assert "Do not enumerate or open unrelated exported components" in planning
    assert "scope boundary of this task" in planning
    assert "A zero-result reference search is proof" in planning
    assert "platform_context.agent_workspace.poc_root" in planning
    assert "manifest package, Activity class name, Java package" in planning
    assert "do not search for aapt, aapt2, d8, dx, sdkmanager" in planning
    assert "open the actual target source or Smali" in planning
    assert "not a fresh audit" in continuation
    assert "changed PoC, input, or Oracle" in continuation
    assert "return requested_tests=[], and do not reopen" in critic
    assert "does not need to regenerate hypothesis assessment receipts" in critic
    assert "terminal decision turn" in final
    assert "Do not assign the final platform verdict" in memo
    assert "Make an explicit evidence-weighted decision" not in memo
    assert "Unless the result is reproduced_blackbox" not in memo
    assert "optional platform-replay action channel" in planning


def test_requested_tests_can_be_omitted_when_no_platform_replay_is_needed() -> None:
    result = AgentInvestigationResult.model_validate(
        {
            "summary": "静态证据表明普通第三方应用无法跨越签名权限边界。",
            "result": "refuted_static",
            "hypotheses_tested": [],
            "test_cases": [],
            "evidence_ids": [],
            "severity_proposal": "info",
            "confidence": "high",
            "coverage_gaps": [],
            "followups": [],
        }
    )

    assert result.requested_tests == []


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
        "平台拒绝了 1 个格式或能力不受支持的补充测试请求；"
        "具体校验错误已保留，下一轮必须修正或改用其他验证策略。"
    ]
    assert result.rejected_requested_tests[0]["index"] == 0
    assert result.rejected_requested_tests[0]["request"]["method"] == "bindOrTransact"
    assert result.rejected_requested_tests[0]["errors"] == [
        {
            "location": "",
            "message": (
                "Value error, method and argument are only valid for provider call"
            ),
            "type": "value_error",
        }
    ]
    with pytest.raises(ValidationError, match="only valid for provider call"):
        AgentRequestedTest.model_validate(payload["requested_tests"][0])


@pytest.mark.parametrize(
    ("kind", "impact"),
    [
        ("reachability", "unauthorized_data_access"),
        ("log_contains", "unauthorized_data_access"),
        ("ui_text", "privileged_action"),
        ("provider_rows", "unauthorized_state_change"),
    ],
)
def test_oracle_rejects_impact_without_an_independent_predicate(
    kind: str,
    impact: str,
) -> None:
    payload = {"kind": kind, "impact": impact}
    if kind in {"ui_text", "log_contains"}:
        payload["expected_text"] = "sensitive"

    with pytest.raises(ValidationError, match="supports only these impacts"):
        AgentRequestedTest.model_validate(
            {
                "hypothesis_id": "00000000-0000-0000-0000-000000000001",
                "entry_point_id": "00000000-0000-0000-0000-000000000002",
                "state": "guest",
                "uri": None,
                "extras": {},
                "oracle": payload,
                "rationale": "验证平台 Oracle 约束。",
            }
        )
