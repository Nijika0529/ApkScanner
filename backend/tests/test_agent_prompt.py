from __future__ import annotations

import pytest
from apkscanner.core.models import EntryPoint, InvestigationTask, Scan
from apkscanner.core.schemas import (
    ADAPTIVE_VERIFIER_RESULT_JSON_SCHEMA,
    AGENT_RESULT_JSON_SCHEMA,
    AgentInvestigationResult,
    AgentPocSpec,
    AgentRequestedTest,
)
from apkscanner.runtime.agent_prompt import (
    adaptive_verification_prompt,
    adaptive_verifier_developer_instructions,
    developer_instructions,
    investigation_prompt,
)
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


def test_agent_output_schema_uses_provider_compatible_additional_properties() -> None:
    pending: list[object] = [
        AGENT_RESULT_JSON_SCHEMA,
        ADAPTIVE_VERIFIER_RESULT_JSON_SCHEMA,
    ]
    while pending:
        value = pending.pop()
        if isinstance(value, list):
            pending.extend(value)
            continue
        if not isinstance(value, dict):
            continue
        additional = value.get("additionalProperties")
        assert additional is None or isinstance(additional, bool)
        properties = value.get("properties")
        if value.get("type") == "object":
            assert isinstance(properties, dict) and properties
        if isinstance(properties, dict):
            assert value.get("required") == list(properties)
        pending.extend(value.values())


def test_agent_output_schemas_do_not_cap_exploration_collections() -> None:
    for name in (
        "hypotheses_tested",
        "hypothesis_assessments",
        "review_objections",
        "test_cases",
        "evidence_ids",
        "coverage_gaps",
        "followups",
        "requested_tests",
    ):
        assert "maxItems" not in AGENT_RESULT_JSON_SCHEMA["properties"][name]
    for name in ("assessments", "shared_observations", "cleanup_actions", "coverage_gaps"):
        assert "maxItems" not in ADAPTIVE_VERIFIER_RESULT_JSON_SCHEMA["properties"][name]


def test_agent_result_converts_closed_wire_extras_to_android_mapping() -> None:
    result = AgentInvestigationResult.model_validate(
        {
            **_result("平台将封闭的 wire extras 转换为 Android 参数。").model_dump(mode="json"),
            "requested_tests": [
                {
                    "hypothesis_id": "00000000-0000-0000-0000-000000000001",
                    "entry_point_id": "00000000-0000-0000-0000-000000000002",
                    "state": "guest",
                    "uri": None,
                    "extras": [
                        {
                            "key": "account",
                            "value_type": "string",
                            "string_value": "victim",
                            "integer_value": None,
                            "boolean_value": None,
                        },
                        {
                            "key": "enabled",
                            "value_type": "boolean",
                            "string_value": None,
                            "integer_value": None,
                            "boolean_value": True,
                        },
                    ],
                    "operation": "auto",
                    "method": None,
                    "argument": None,
                    "intent_action": None,
                    "categories": [],
                    "reset": "inherit",
                    "oracle": {
                        "kind": "reachability",
                        "expected_text": None,
                        "minimum_rows": None,
                        "impact": "none",
                        "refute_on_miss": False,
                    },
                    "rationale": "验证参数转换",
                    "poc": None,
                }
            ],
        }
    )

    assert result.requested_tests[0].extras == {"account": "victim", "enabled": True}


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
    assert "apkscanner-proof <proof-replay.json>" in instructions
    assert "Do not submit the same action again through requested_tests" in instructions
    assert "assigned coverage seed is a hard workflow scope" in instructions
    assert "Do not use a broad glob" in instructions
    assert "A zero-result search ends that proposed branch" in instructions
    assert "Treat raw ADB as a hypothesis probe, not an exploration loop" in instructions
    assert "After one ordinary-app replay answers a hypothesis" in instructions
    assert "A reproduced_blackbox receipt ends that hypothesis" in instructions
    assert "never reconstruct a task UUID" in instructions
    assert "Avoid redundant existence/path checks for unchanged PoC sources" in instructions
    assert "prefer a dedicated PoC or platform-generated proof Harness" in instructions
    assert "materially distinct fallback strategies" in instructions
    assert "submit a live proof replay" in instructions
    assert "without discovering or invoking an Android SDK toolchain" in instructions
    assert "poc_builder.source_build_available=true" in instructions


def test_adaptive_verifier_prompt_uses_semantic_oracles_and_direct_host_ssh() -> None:
    scan = Scan(
        id="00000000-0000-0000-0000-000000000001",
        filename="sample.apk",
        package_name="com.example.sample",
        artifact_sha256="a" * 64,
        artifact_path="/tmp/sample.apk",
    )
    candidate_id = "00000000-0000-0000-0000-000000000004"
    instructions = adaptive_verifier_developer_instructions(ssh_available=True)
    prompt = adaptive_verification_prompt(
        scan,
        [{"finding_id": candidate_id, "title": "JSB token leak"}],
        [],
        {"ssh": {"available": True}},
    )

    assert "ssh/scp" in instructions
    assert "~/.ssh" in instructions
    assert "Aliyun" in instructions
    assert "hard-coded token regex" in instructions
    assert "not a bounded platform-Oracle exercise" in instructions
    assert "no platform-imposed count limit" in instructions
    assert "at most 80" not in instructions
    assert "two PoC rebuild" not in instructions
    assert "targetSdk API 36 or newer" in instructions
    assert "legacy dx-based fallback" in instructions
    assert "Do not lower targetSdk to match the phone" in instructions
    assert "crafted ZIP" in instructions
    assert "target_file_sha256" in instructions
    assert "duplicate_of_finding_id" in instructions
    assert "每个 finding_id 必须且只能返回一条 assessment" in prompt
    assert "duplicate_of_finding_id" in prompt
    assert candidate_id in prompt
    assert "最终由你对返回值、token、账号能力" in prompt


def test_adaptive_verifier_retry_reuses_prior_runtime_evidence() -> None:
    scan = Scan(
        id="00000000-0000-0000-0000-000000000001",
        filename="sample.apk",
        package_name="com.example.sample",
        artifact_sha256="a" * 64,
        artifact_path="/tmp/sample.apk",
    )
    prompt = adaptive_verification_prompt(
        scan,
        [{"finding_id": "00000000-0000-0000-0000-000000000004"}],
        [{"id": "evidence-1", "kind": "agent.adb.gateway"}],
        {
            "recovery": {
                "is_retry": True,
                "previous_attempt_evidence_count": 1,
            }
        },
    )

    assert "恢复轮次" in prompt
    assert "不要重复已经成功的 Receiver、localhost、Binder、WebView" in prompt
    assert "previous_attempt_evidence_count" in prompt


def _phase_prompt(
    phase: str,
    *,
    response_contract: str = "structured_result",
    entry_kind: str = "activity",
) -> str:
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
        kind=entry_kind,
        name=(
            "sample://router/" if entry_kind == "deep_link" else "com.example.sample.MainActivity"
        ),
        owner_component="com.example.sample.MainActivity",
        exported=True,
        metadata_json=(
            {"path_kind": None, "uri_template": "sample://router/"}
            if entry_kind == "deep_link"
            else {}
        ),
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
    assert "A PoC log_contains Oracle records only the PoC's claim" in planning
    assert "live Proof Gateway rejects every impact=none replay" in planning
    assert "operation=binder_transact" in planning
    assert "proof_capabilities.ephemeral_app_harness" in planning
    assert "Never repeat an unchanged no-PoC Binder request" in planning
    assert "binder_reply may use unauthorized_data_access only" in planning
    assert "target_uid_log_contains supports impact=none only" in planning
    critic = _phase_prompt("adversarial_review")
    rescue_review = _phase_prompt("rescue_review")
    rescue_exploration = _phase_prompt("rescue_exploration")
    final = _phase_prompt("final_evaluation")
    memo = _phase_prompt("test_planning", response_contract="analysis_memo")

    assert "seed-focused analysis pass" in planning
    assert "Do not enumerate or open unrelated exported components" in planning
    assert "scope boundary of this task" in planning
    assert "A zero-result reference search is proof" in planning
    assert "catalog contains only the assigned seed" in planning
    assert "may still be examined freely" in planning
    assert "platform_context.agent_workspace.poc_root" in planning
    assert "harness_mode=platform_generated" in planning
    assert "attack_class" in planning
    assert "do not search for aapt, aapt2, d8, dx, sdkmanager" in planning
    assert "platform_context.poc_builder.source_build_available" in planning
    assert "open the actual target source or Smali" in planning
    assert "Do not read sibling application components" in planning
    assert "not a fresh audit" in continuation
    assert "changed PoC, input, or Oracle" in continuation
    assert "re-open only its exact cited source anchors" in critic
    assert "unique OBJ-prefixed ID" in critic
    assert "does not need to regenerate hypothesis assessment receipts" in critic
    assert "OBJ-1" in critic
    assert "Include every distinct objection" in critic
    assert "not a new APK audit" in critic
    assert "review_objections" in critic
    assert "platform_proven_hypotheses" in critic
    assert "Never object to, refute, or downgrade" in critic
    assert "previous model conclusion has been deliberately withheld" in rescue_review
    assert "absence of a discovered chain" in rescue_review
    assert "blind negative-closure review" in rescue_review
    assert "return requested_tests=[]" in rescue_review
    assert "platform_context.rescue.strategy" in rescue_exploration
    assert "smallest complete ordinary-app PoC" in rescue_exploration
    assert "Do not return requested_tests" in rescue_exploration
    assert "terminal decision turn" in final
    assert "objection_resolutions" in final
    assert "must remain reproduced_blackbox" in final
    assert "Do not assign the final platform verdict" in memo
    assert "Make an explicit evidence-weighted decision" not in memo
    assert "Unless the result is reproduced_blackbox" not in memo
    assert "execute a stateful multi-step experiment" in planning
    assert "never manufacture the expected value" in planning
    assert "apkscanner-proof" in planning
    assert "proof JSON hypothesis_id is mandatory" in planning
    assert "never use Thread.sleep" in planning


def test_deep_link_prompt_requires_route_matrix_and_pending_proof_semantics() -> None:
    planning = _phase_prompt("test_planning", entry_kind="deep_link")
    rescue = _phase_prompt("rescue_review", entry_kind="deep_link")

    assert "path_kind=null" in planning
    assert "nested JSON/URI values" in planning
    assert "empty explicit component start tests only component reachability" in planning
    assert "every bridge exposed to that page" in planning
    assert "needs_dynamic_proof" in planning
    assert "platform-correlated negative Oracle" in planning
    assert "intentionally has no workspace, PoC inventory" in rescue
    assert "must not be reported as a coverage gap" in rescue


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


def test_agent_result_repairs_unambiguous_structured_output_variance() -> None:
    hypothesis_id = "00000000-0000-0000-0000-000000000001"
    payload = {
        "summary": "静态证据反驳了该攻击链，模型返回格式存在可安全修复的偏差。",
        "result": "refuted_static",
        "hypotheses_tested": [hypothesis_id],
        "hypothesis_assessments": [
            {
                "hypothesis_id": hypothesis_id,
                "verdict": "refuted_static",
                "counterevidence": "调用前存在签名权限校验。",
                "proof_gaps": "",
            }
        ],
        "test_cases": [],
        "evidence_ids": [],
        "severity_proposal": "high",
        "confidence": "high",
        "coverage_gaps": [],
        "followups": [],
    }

    result = AgentInvestigationResult.model_validate(payload)

    assert result.severity_proposal == "info"
    assert result.hypothesis_assessments[0].counterevidence == [
        "调用前存在签名权限校验。"
    ]
    assert result.hypothesis_assessments[0].proof_gaps == []
    assert result.normalization_repairs == [
        {
            "location": "hypothesis_assessments.0.counterevidence",
            "repair": "string_wrapped_as_list",
            "original_type": "string",
        },
        {
            "location": "hypothesis_assessments.0.proof_gaps",
            "repair": "string_wrapped_as_list",
            "original_type": "string",
        },
        {
            "location": "severity_proposal",
            "repair": "forced_info_for_refuted_static",
            "original_value": "high",
        },
    ]


def test_agent_result_does_not_coerce_ambiguous_assessment_types() -> None:
    payload = _result("模型返回不可安全修复的字段类型。 ").model_dump(mode="json")
    payload["hypothesis_assessments"] = [
        {
            "hypothesis_id": "00000000-0000-0000-0000-000000000001",
            "verdict": "supported_static",
            "counterevidence": 42,
        }
    ]

    with pytest.raises(ValidationError, match="counterevidence"):
        AgentInvestigationResult.model_validate(payload)


def test_agent_result_restores_validation_audit_from_worker_protocol() -> None:
    result = _result("结构化结论已经由容器 worker 校验。")
    result.apply_model_validation_audit(
        {
            "rejected_requested_tests": [{"index": 2, "errors": []}],
            "normalization_repairs": [
                {
                    "location": "severity_proposal",
                    "repair": "forced_info_for_refuted_static",
                }
            ],
        }
    )

    assert result.rejected_requested_tests == [{"index": 2, "errors": []}]
    assert result.normalization_repairs == [
        {
            "location": "severity_proposal",
            "repair": "forced_info_for_refuted_static",
        }
    ]


def test_single_critic_turn_can_report_every_material_objection() -> None:
    payload = _result("Critic 只应保留可能改变最终结论的实质异议。").model_dump(mode="json")
    payload["review_objections"] = [
        {
            "objection_id": f"OBJ-{index}",
            "claim": f"异议 {index}",
            "basis": "候选证据不足。",
            "evidence_ids": [],
        }
        for index in range(1, 6)
    ]

    result = AgentInvestigationResult.model_validate(payload)

    assert len(result.review_objections) == 5


def test_poc_base_package_remains_inside_the_controlled_namespace() -> None:
    spec = AgentPocSpec(
        project_path="poc/base",
        package_name="io.apkscanner.runtime.poc",
        launch_component="io.apkscanner.runtime.poc.MainActivity",
    )

    assert spec.package_name == "io.apkscanner.runtime.poc"


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
            "message": ("Value error, method and argument are only valid for provider call"),
            "type": "value_error",
        }
    ]
    with pytest.raises(ValidationError, match="only valid for provider call"):
        AgentRequestedTest.model_validate(payload["requested_tests"][0])


def test_poc_log_oracle_recovers_an_omitted_expected_text() -> None:
    payload = {
        "summary": "静态证据支持风险，申请普通应用身份的设备验证。",
        "result": "supported_static",
        "hypotheses_tested": [],
        "test_cases": [],
        "evidence_ids": [],
        "severity_proposal": "high",
        "confidence": "high",
        "coverage_gaps": [],
        "followups": [],
        "requested_tests": [
            {
                "hypothesis_id": "00000000-0000-0000-0000-000000000001",
                "entry_point_id": "00000000-0000-0000-0000-000000000002",
                "state": "guest",
                "uri": "vulntest://open/",
                "extras": {},
                "operation": "auto",
                "oracle": {
                    "kind": "log_contains",
                    "impact": "none",
                },
                "poc": {
                    "project_path": "poc/deep_link",
                    "package_name": "io.apkscanner.runtime.poc.deep_link",
                    "launch_component": ("io.apkscanner.runtime.poc.deep_link.MainActivity"),
                },
                "rationale": "用独立 PoC 应用验证目标入口。",
            }
        ],
    }

    result = AgentInvestigationResult.model_validate(payload)

    assert result.rejected_requested_tests == []
    assert len(result.requested_tests) == 1
    assert result.requested_tests[0].oracle.expected_text == "security_impact_observed"


def test_agent_result_repairs_fields_from_the_wrong_execution_mode() -> None:
    payload = {
        "summary": "静态证据支持风险，申请普通应用身份的设备验证。",
        "result": "supported_static",
        "hypotheses_tested": [],
        "test_cases": [],
        "evidence_ids": [],
        "severity_proposal": "high",
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
                "oracle": {
                    "kind": "ui_text",
                    "expected_text": "完成",
                    "match_mode": "contains",
                    "reply_index": 2,
                    "impact": "unauthorized_state_change",
                },
                "poc": {
                    "project_path": "poc/custom_harness",
                    "package_name": "io.apkscanner.runtime.poc.custom_harness",
                    "launch_component": "io.apkscanner.runtime.poc.custom_harness.MainActivity",
                    "harness_mode": "custom",
                    "attack_class": "io.apkscanner.runtime.poc.custom_harness.Attack",
                },
                "rationale": "自定义 Activity 执行攻击并观察目标 UI。",
            }
        ],
    }

    result = AgentInvestigationResult.model_validate(payload)

    assert result.rejected_requested_tests == []
    assert len(result.requested_tests) == 1
    request = result.requested_tests[0]
    assert request.oracle.match_mode == "exact"
    assert request.oracle.reply_index == 0
    assert request.poc is not None
    assert request.poc.attack_class is None
    assert result.normalization_repairs == [
        {
            "location": "requested_tests.0.oracle.match_mode",
            "repair": "removed_binder_only_field",
            "original_value": "contains",
        },
        {
            "location": "requested_tests.0.oracle.reply_index",
            "repair": "removed_binder_only_field",
            "original_value": 2,
        },
        {
            "location": "requested_tests.0.poc.attack_class",
            "repair": "removed_platform_harness_only_field",
            "original_value": "io.apkscanner.runtime.poc.custom_harness.Attack",
        },
    ]


def test_agent_result_clears_target_path_from_non_file_oracle() -> None:
    payload = {
        "summary": "静态证据支持风险，申请目标界面验证。",
        "result": "supported_static",
        "hypotheses_tested": [],
        "test_cases": [],
        "evidence_ids": [],
        "severity_proposal": "high",
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
                "oracle": {
                    "kind": "ui_text",
                    "expected_text": "导入完成",
                    "target_path": "shared_prefs/session.xml",
                    "impact": "unauthorized_state_change",
                },
                "poc": None,
                "rationale": "验证目标应用中新出现的状态提示。",
            }
        ],
    }

    result = AgentInvestigationResult.model_validate(payload)

    assert result.rejected_requested_tests == []
    assert result.requested_tests[0].oracle.target_path is None
    assert result.normalization_repairs == [
        {
            "location": "requested_tests.0.oracle.target_path",
            "repair": "cleared_target_file_only_field",
            "original_value": "shared_prefs/session.xml",
        }
    ]


def test_content_provider_method_implies_call_operation() -> None:
    payload = {
        "summary": "静态证据支持风险，申请验证 Provider 自定义调用。",
        "result": "supported_static",
        "hypotheses_tested": [],
        "test_cases": [],
        "evidence_ids": [],
        "severity_proposal": "high",
        "confidence": "high",
        "coverage_gaps": [],
        "followups": [],
        "requested_tests": [
            {
                "hypothesis_id": "00000000-0000-0000-0000-000000000001",
                "entry_point_id": "00000000-0000-0000-0000-000000000002",
                "state": "guest",
                "uri": "content://io.apkscanner.vulntest.secret/items",
                "extras": {},
                "operation": "auto",
                "method": "getSecret",
                "argument": "all",
                "rationale": "调用导出 Provider 的自定义方法。",
            }
        ],
    }

    result = AgentInvestigationResult.model_validate(payload)

    assert result.rejected_requested_tests == []
    assert result.requested_tests[0].operation == "call"


@pytest.mark.parametrize(
    ("kind", "impact"),
    [
        ("reachability", "unauthorized_data_access"),
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
