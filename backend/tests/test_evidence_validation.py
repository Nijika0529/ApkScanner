from __future__ import annotations

import pytest
from apkscanner.core.models import EntryPoint
from apkscanner.core.schemas import AgentRequestedTest
from apkscanner.runtime.orchestrator import ScanOrchestrator


def _payload(result: str, evidence_ids: list[str]) -> dict:  # noqa: ANN401
    return {
        "result": result,
        "evidence_ids": evidence_ids,
        "coverage_gaps": [],
    }


def _complete_static_chain(hypothesis_id: str, verdict: str) -> dict:  # noqa: ANN401
    return {
        "hypothesis_id": hypothesis_id,
        "verdict": verdict,
        "source": "ExportedActivity intent extra",
        "control": "A caller-controlled URI is forwarded without validation.",
        "sink": "WebView.loadUrl",
        "reachable_path": "ExportedActivity -> RedirectHandler -> WebView.loadUrl",
        "boundary": "ordinary_app_uid -> target_app_process",
        "security_impact": "An ordinary app can make the target load attacker-controlled content.",
        "missing_control": "No caller authorization or destination allowlist is enforced.",
        "evidence_ids": ["static"],
        "proof_gaps": [],
    }


def _complete_static_refutation(
    hypothesis_id: str,
    evidence_id: str = "static",
) -> dict:
    return {
        "hypothesis_id": hypothesis_id,
        "verdict": "refuted_static",
        "control": "A signature permission rejects every ordinary application caller.",
        "reachable_path": "ordinary_app_uid -> signature permission guard -> blocked",
        "counterevidence": [
            "The manifest and call-site guard require a signature-level permission."
        ],
        "evidence_ids": [evidence_id],
        "proof_gaps": [],
    }


def test_unknown_agent_evidence_is_removed_and_reproduction_is_downgraded() -> None:
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("reproduced_blackbox", ["invented"]),
        [],
    )

    assert result == "inconclusive"
    assert payload["evidence_ids"] == []
    assert payload["coverage_gaps"] == [
        "Ignored 1 evidence ID(s) not issued for this scan and task.",
        (
            "The claimed verdict could not be validated against platform evidence; "
            "the finding was retained as inconclusive pending further proof."
        ),
    ]


@pytest.mark.parametrize("claimed_result", ["reproduced_blackbox", "not_reproduced"])
def test_non_verdict_smoke_cannot_close_a_dynamic_verdict(claimed_result: str) -> None:
    evidence = [
        {
            "id": "launch",
            "kind": "blackbox.poc_launch",
            "exit_code": 0,
            "metadata": {
                "caller_identity": "agent_poc_app",
                "request_id": "request-smoke",
                "test_case_id": "agent-r1-1",
                "dynamic_verdict_eligible": False,
                "verdict_scope": "non_verdict_smoke",
            },
        },
        {
            "id": "receipt",
            "kind": "blackbox.poc_logcat",
            "exit_code": 0,
            "metadata": {
                "request_id": "request-smoke",
                "test_case_id": "agent-r1-1",
                "request_observed": True,
                "poc_success": True,
                "impact_contract_satisfied": True,
                "oracle_refuted": True,
                "dynamic_verdict_eligible": False,
                "verdict_scope": "non_verdict_smoke",
            },
        },
    ]

    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload(claimed_result, ["launch", "receipt"]),
        evidence,
    )

    assert result == "inconclusive"
    assert any("non-verdict compatibility scope" in gap for gap in payload["coverage_gaps"])


def test_static_verdict_without_a_structured_assessment_remains_inconclusive() -> None:
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("supported_static", []),
        [{"id": "static", "kind": "static.apktool", "metadata": {}}],
    )

    assert result == "inconclusive"
    assert payload["evidence_ids"] == ["static"]
    assert payload["coverage_gaps"] == [
        "Platform attached the issued static Evidence omitted by the model.",
        (
            "No structured hypothesis assessment passed the platform static-support gate; "
            "the task remains an inconclusive candidate rather than a statically "
            "supported finding."
        ),
    ]


def test_blackbox_reproduction_requires_correlated_concrete_harm() -> None:
    evidence = [
        {
            "id": "probe",
            "kind": "blackbox.probe_app",
            "exit_code": 0,
            "metadata": {
                "caller_identity": "probe_app",
                "request_id": "request-1",
                "test_case_id": "agent-r1-1",
            },
        },
        {
            "id": "log",
            "kind": "blackbox.logcat",
            "exit_code": 0,
            "metadata": {
                "request_id": "request-1",
                "request_observed": True,
                "probe_success": True,
                "test_case_id": "agent-r1-1",
                "security_impact_observed": True,
                "impact_contract_satisfied": True,
            },
        },
    ]
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("reproduced_blackbox", ["probe", "log"]),
        evidence,
    )
    assert result == "reproduced_blackbox"
    assert payload["evidence_ids"] == ["probe", "log"]


def test_agent_poc_can_supply_the_correlated_ordinary_app_execution_pair() -> None:
    evidence = [
        {
            "id": "launch",
            "kind": "blackbox.poc_launch",
            "exit_code": 0,
            "metadata": {
                "caller_identity": "agent_poc_app",
                "request_id": "request-poc",
                "test_case_id": "agent-r1-1",
            },
        },
        {
            "id": "log",
            "kind": "blackbox.poc_logcat",
            "exit_code": 0,
            "metadata": {
                "request_id": "request-poc",
                "request_observed": True,
                "poc_success": True,
                "test_case_id": "agent-r1-1",
            },
        },
        {
            "id": "oracle",
            "kind": "blackbox.poc_ui_dump",
            "exit_code": 0,
            "metadata": {
                "test_case_id": "agent-r1-1",
                "security_impact_observed": True,
                "impact_contract_satisfied": True,
            },
        },
    ]

    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("reproduced_blackbox", ["launch", "log", "oracle"]),
        evidence,
    )

    assert result == "reproduced_blackbox"
    assert payload["evidence_ids"] == ["launch", "log", "oracle"]


def test_terminal_durable_receipt_can_supply_the_poc_execution_pair() -> None:
    evidence = [
        {
            "id": "launch",
            "kind": "blackbox.poc_launch",
            "exit_code": 0,
            "metadata": {
                "caller_identity": "platform_generated_poc",
                "request_id": "request-receipt",
                "test_case_id": "agent-r1-1",
            },
        },
        {
            "id": "receipt",
            "kind": "blackbox.poc_durable_receipt",
            "exit_code": 0,
            "metadata": {
                "request_id": "request-receipt",
                "request_observed": True,
                "receipt_terminal": True,
                "poc_success": True,
                "test_case_id": "agent-r1-1",
            },
        },
        {
            "id": "oracle",
            "kind": "blackbox.poc_ui_dump",
            "exit_code": 0,
            "metadata": {
                "request_id": "request-receipt",
                "test_case_id": "agent-r1-1",
                "security_impact_observed": True,
                "impact_contract_satisfied": True,
            },
        },
    ]

    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("reproduced_blackbox", ["launch", "receipt", "oracle"]),
        evidence,
    )

    assert result == "reproduced_blackbox"
    assert payload["evidence_ids"] == ["launch", "receipt", "oracle"]


def test_optional_jadx_absence_is_not_preserved_as_a_verdict_gap() -> None:
    payload = _payload("refuted_static", ["static"])
    payload["hypothesis_assessments"] = [
        _complete_static_refutation("00000000-0000-0000-0000-000000000001")
    ]
    payload["coverage_gaps"] = [
        "JADX decompilation was unavailable; Smali fallback was sufficient.",
        "No device available; static permission evidence is definitive.",
        "A device replay could validate the negative path.",
    ]

    validated, result = ScanOrchestrator._validated_agent_payload(
        payload,
        [{"id": "static", "kind": "static.apktool", "metadata": {}}],
    )

    assert result == "refuted_static"
    assert validated["coverage_gaps"] == ["A device replay could validate the negative path."]


def test_unique_evidence_uuid_prefix_is_normalized_to_full_platform_id() -> None:
    evidence_id = "509102d0-1111-2222-3333-444444444444"
    payload = _payload("refuted_static", ["509102d0"])
    payload["hypothesis_assessments"] = [
        _complete_static_refutation(
            "00000000-0000-0000-0000-000000000001",
            "509102d0",
        )
    ]

    validated, result = ScanOrchestrator._validated_agent_payload(
        payload,
        [{"id": evidence_id, "kind": "static.apktool", "metadata": {}}],
    )

    assert result == "refuted_static"
    assert validated["evidence_ids"] == [evidence_id]
    assert validated["hypothesis_assessments"][0]["evidence_ids"] == [evidence_id]


def test_static_refutation_requires_a_concrete_guard_or_blocked_edge() -> None:
    hypothesis_id = "00000000-0000-0000-0000-000000000001"
    payload = _payload("refuted_static", ["static"])
    payload["hypothesis_assessments"] = [
        {
            "hypothesis_id": hypothesis_id,
            "verdict": "refuted_static",
            "control": "safe",
            "reachable_path": "blocked",
            "counterevidence": ["looks fine"],
            "evidence_ids": ["static"],
            "proof_gaps": [],
        }
    ]

    validated, result = ScanOrchestrator._validated_agent_payload(
        payload,
        [{"id": "static", "kind": "static.jadx", "metadata": {}}],
    )

    assert result == "inconclusive"
    assessment = validated["hypothesis_assessments"][0]
    assert assessment["verdict"] == "candidate"
    assert assessment["suppression_reason"] == "static_refutation_gate_failed"
    assert set(assessment["suppression_reasons"]) == {
        "missing_concrete_counterevidence",
        "missing_guard_or_unreachable_edge",
    }


@pytest.mark.parametrize(
    ("assessment_reference", "evidence_ids", "expected_result"),
    [
        (
            "509102d0",
            ["509102d0-1111-2222-3333-444444444444"],
            "supported_static",
        ),
        (
            "509102d0",
            [
                "509102d0-1111-2222-3333-444444444444",
                "509102d0-aaaa-bbbb-cccc-dddddddddddd",
            ],
            "inconclusive",
        ),
        (None, ["509102d0-1111-2222-3333-444444444444"], "inconclusive"),
    ],
)
def test_static_gate_requires_an_unambiguous_explicit_evidence_reference(
    assessment_reference: str | None,
    evidence_ids: list[str],
    expected_result: str,
) -> None:
    hypothesis_id = "00000000-0000-0000-0000-000000000001"
    payload = _payload("supported_static", [])
    assessment = _complete_static_chain(hypothesis_id, "supported_static")
    assessment["evidence_ids"] = (
        [assessment_reference] if assessment_reference is not None else []
    )
    payload["hypothesis_assessments"] = [assessment]

    validated, result = ScanOrchestrator._validated_agent_payload(
        payload,
        [
            {"id": evidence_id, "kind": "static.jadx", "metadata": {}}
            for evidence_id in evidence_ids
        ],
    )

    assert result == expected_result
    gate = validated["hypothesis_assessments"][0]["platform_static_support_gate"]
    assert gate["eligible"] is (expected_result == "supported_static")


def test_reachability_without_a_structured_chain_stays_inconclusive() -> None:
    evidence = [
        {
            "id": "static",
            "kind": "static.apktool",
            "exit_code": 0,
            "metadata": {},
        },
        {
            "id": "probe",
            "kind": "blackbox.probe_app",
            "exit_code": 0,
            "metadata": {
                "caller_identity": "probe_app",
                "request_id": "request-1",
                "test_case_id": "agent-r1-1",
            },
        },
        {
            "id": "log",
            "kind": "blackbox.logcat",
            "exit_code": 0,
            "metadata": {
                "request_id": "request-1",
                "request_observed": True,
                "probe_success": True,
                "test_case_id": "agent-r1-1",
            },
        },
    ]
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("reproduced_blackbox", ["static", "probe", "log"]),
        evidence,
    )
    assert result == "inconclusive"
    assert any("static-evidence strength" in gap for gap in payload["coverage_gaps"])
    assert any("static-support gate" in gap for gap in payload["coverage_gaps"])


def test_each_hypothesis_assessment_is_validated_at_its_own_evidence_strength() -> None:
    hypothesis_id = "00000000-0000-0000-0000-000000000001"
    payload = _payload("supported_static", ["static"])
    payload["hypothesis_assessments"] = [
        {
            **_complete_static_chain(hypothesis_id, "reproduced_blackbox"),
        }
    ]

    validated, result = ScanOrchestrator._validated_agent_payload(
        payload,
        [{"id": "static", "kind": "static.apktool", "metadata": {}}],
    )

    assert result == "supported_static"
    assessment = validated["hypothesis_assessments"][0]
    assert assessment["verdict"] == "supported_static"
    assert any("static-evidence strength" in gap for gap in assessment["proof_gaps"])


def test_static_support_gate_rejects_unresolved_counterevidence() -> None:
    hypothesis_id = "00000000-0000-0000-0000-000000000001"
    payload = _payload("supported_static", ["static"])
    payload["hypothesis_assessments"] = [
        {
            **_complete_static_chain(hypothesis_id, "supported_static"),
            "counterevidence": ["The target may enforce a caller allowlist in native code."],
        }
    ]

    validated, result = ScanOrchestrator._validated_agent_payload(
        payload,
        [{"id": "static", "kind": "static.jadx", "metadata": {}}],
    )

    assert result == "inconclusive"
    assessment = validated["hypothesis_assessments"][0]
    assert assessment["verdict"] == "candidate"
    assert "unresolved_counterevidence" in assessment["suppression_reasons"]


def test_static_support_gate_rejects_junk_and_unanchored_chain_text() -> None:
    hypothesis_id = "00000000-0000-0000-0000-000000000001"
    payload = _payload("supported_static", ["static"])
    assessment = _complete_static_chain(hypothesis_id, "supported_static")
    assessment.update(
        {
            "source": "xxxxxxxxxxxxxxxx",
            "control": "xxxxxxxxxxxxxxxx",
            "sink": "yyyyyyyyyyyyyyyy",
            "reachable_path": "zzzzzzzzzzzzzzzz",
            "boundary": "bbbbbbbbbbbbbbbb",
            "security_impact": "iiiiiiiiiiiiiiiiiiiiiiii",
            "missing_control": "mmmmmmmmmmmmmmmm",
        }
    )
    payload["hypothesis_assessments"] = [assessment]

    validated, result = ScanOrchestrator._validated_agent_payload(
        payload,
        [{"id": "static", "kind": "static.jadx", "metadata": {}}],
    )

    assert result == "inconclusive"
    reasons = validated["hypothesis_assessments"][0]["suppression_reasons"]
    assert "unstructured_reachable_path" in reasons
    assert "unstructured_trust_boundary" in reasons
    assert "missing_source" in reasons
    assert "missing_sink" in reasons


def test_static_support_gate_accepts_a_substantive_chinese_chain() -> None:
    hypothesis_id = "00000000-0000-0000-0000-000000000001"
    payload = _payload("supported_static", ["static"])
    assessment = _complete_static_chain(hypothesis_id, "supported_static")
    assessment.update(
        {
            "source": "外部应用传入的恶意深链 URI 参数",
            "control": "该参数完全由外部调用者控制并且可以任意修改",
            "sink": "WebView.loadUrl 加载攻击者指定的 URL",
            "reachable_path": "外部应用 -> DeepLinkActivity -> WebView.loadUrl",
            "boundary": "外部普通应用 UID -> 目标应用进程的信任边界",
            "security_impact": "攻击者可诱导目标应用加载恶意页面并访问应用内受信任能力",
            "missing_control": "调用链没有校验调用者身份，也没有限制允许加载的目标域名",
        }
    )
    payload["hypothesis_assessments"] = [assessment]

    validated, result = ScanOrchestrator._validated_agent_payload(
        payload,
        [
            {
                "id": "static",
                "kind": "static.jadx",
                "exit_code": 1,
                "metadata": {
                    "static_output_usable": True,
                    "static_tool_status": "partial_success",
                },
            }
        ],
    )

    assert result == "supported_static"
    assert validated["hypothesis_assessments"][0]["platform_static_support_gate"][
        "eligible"
    ] is True


def test_static_support_gate_accepts_legacy_partial_output_marked_usable() -> None:
    hypothesis_id = "00000000-0000-0000-0000-000000000001"
    payload = _payload("supported_static", ["static"])
    payload["hypothesis_assessments"] = [
        _complete_static_chain(hypothesis_id, "supported_static")
    ]

    validated, result = ScanOrchestrator._validated_agent_payload(
        payload,
        [
            {
                "id": "static",
                "kind": "static.jadx",
                "exit_code": 124,
                "metadata": {
                    "status": "partial_timeout",
                    "output_usable": True,
                },
            }
        ],
    )

    assert result == "supported_static"
    assert validated["hypothesis_assessments"][0]["platform_static_support_gate"][
        "eligible"
    ] is True


@pytest.mark.parametrize(
    "evidence",
    [
        {
            "id": "static",
            "kind": "static.jadx",
            "exit_code": 1,
            "metadata": {
                "static_output_usable": False,
                "static_tool_status": "tool_failed",
            },
        },
        {
            "id": "static",
            "kind": "static.apktool",
            "exit_code": 124,
            "metadata": {"timed_out": True},
        },
    ],
)
def test_static_support_gate_rejects_unusable_tool_output(evidence: dict) -> None:
    hypothesis_id = "00000000-0000-0000-0000-000000000001"
    payload = _payload("supported_static", ["static"])
    payload["hypothesis_assessments"] = [
        _complete_static_chain(hypothesis_id, "supported_static")
    ]

    validated, result = ScanOrchestrator._validated_agent_payload(payload, [evidence])

    assert result == "inconclusive"
    assessment = validated["hypothesis_assessments"][0]
    assert assessment["verdict"] == "inconclusive"
    assert any(
        "could not be validated against platform evidence" in gap
        for gap in assessment["proof_gaps"]
    )


@pytest.mark.parametrize(
    ("disposition", "resolution_evidence_ids", "expected_result"),
    [
        ("sustained", ["static"], "inconclusive"),
        ("overruled", [], "inconclusive"),
        ("overruled", ["static"], "supported_static"),
    ],
)
def test_static_support_gate_requires_evidence_backed_critic_resolution(
    disposition: str,
    resolution_evidence_ids: list[str],
    expected_result: str,
) -> None:
    hypothesis_id = "00000000-0000-0000-0000-000000000001"
    payload = _payload("supported_static", ["static"])
    payload["hypothesis_assessments"] = [
        _complete_static_chain(hypothesis_id, "supported_static")
    ]
    payload["review_objections"] = [
        {
            "objection_id": "OBJ-guard",
            "hypothesis_id": hypothesis_id,
            "claim": "A guard may block the sink.",
            "basis": "The call path contains an authorization helper.",
            "evidence_ids": ["static"],
        }
    ]
    payload["objection_resolutions"] = [
        {
            "objection_id": "OBJ-guard",
            "disposition": disposition,
            "rationale": "The cited code either establishes or fails to establish the guard.",
            "evidence_ids": resolution_evidence_ids,
        }
    ]

    validated, result = ScanOrchestrator._validated_agent_payload(
        payload,
        [{"id": "static", "kind": "static.jadx", "metadata": {}}],
    )

    assert result == expected_result
    assessment = validated["hypothesis_assessments"][0]
    if expected_result == "supported_static":
        assert assessment["platform_static_support_gate"]["eligible"] is True
    else:
        assert "unresolved_critic_objection" in assessment["suppression_reasons"]


def test_unknown_hypothesis_cannot_bypass_the_structured_static_gate() -> None:
    unknown_id = "00000000-0000-0000-0000-000000000001"
    task_hypothesis_id = "00000000-0000-0000-0000-000000000002"
    payload = _payload("supported_static", ["static"])
    payload["hypothesis_assessments"] = [
        _complete_static_chain(unknown_id, "supported_static")
    ]

    validated, result = ScanOrchestrator._validated_agent_payload(
        payload,
        [{"id": "static", "kind": "static.jadx", "metadata": {}}],
    )
    assert result == "supported_static"

    validated = ScanOrchestrator._validated_hypothesis_payload(
        validated,
        [{"id": task_hypothesis_id}],
    )

    assert validated["result"] == "inconclusive"
    assert validated["hypothesis_assessments"] == []
    assert any("task-owned hypothesis" in gap for gap in validated["coverage_gaps"])


def test_invalid_negative_assessment_degrades_without_failing_proven_task() -> None:
    hypothesis_id = "00000000-0000-0000-0000-000000000001"
    payload = _payload("reproduced_blackbox", ["poc-launch", "poc-log", "oracle"])
    payload["hypothesis_assessments"] = [
        {
            "hypothesis_id": hypothesis_id,
            "verdict": "not_reproduced",
            "evidence_ids": [],
            "proof_gaps": [],
        }
    ]
    evidence = [
        {
            "id": "static",
            "kind": "static.apktool",
            "exit_code": 0,
            "metadata": {},
        },
        {
            "id": "poc-launch",
            "kind": "blackbox.poc_launch",
            "exit_code": 0,
            "metadata": {
                "caller_identity": "agent_poc_app",
                "request_id": "request-1",
                "test_case_id": "agent-r1-1",
            },
        },
        {
            "id": "poc-log",
            "kind": "blackbox.poc_logcat",
            "exit_code": 0,
            "metadata": {
                "request_id": "request-1",
                "request_observed": True,
                "poc_success": True,
                "security_impact_observed": True,
                "test_case_id": "agent-r1-1",
            },
        },
        {
            "id": "oracle",
            "kind": "blackbox.poc_ui_dump",
            "exit_code": 0,
            "metadata": {
                "test_case_id": "agent-r1-1",
                "impact_contract_satisfied": True,
            },
        },
    ]

    validated, result = ScanOrchestrator._validated_agent_payload(
        payload,
        evidence,
    )

    assert result == "reproduced_blackbox"
    assessment = validated["hypothesis_assessments"][0]
    assert assessment["verdict"] == "candidate"
    assert assessment["evidence_ids"] == ["static"]
    assert any("pending dynamic proof" in gap for gap in assessment["proof_gaps"])
    assert assessment["suppression_reason"] == "static_support_gate_failed"
    assert "missing_source" in assessment["suppression_reasons"]


def test_needs_dynamic_proof_preserves_a_source_backed_open_hypothesis() -> None:
    hypothesis_id = "00000000-0000-0000-0000-000000000001"
    payload = _payload("supported_static", ["static"])
    payload["hypothesis_assessments"] = [
        {
            **_complete_static_chain(hypothesis_id, "needs_dynamic_proof"),
            "proof_gaps": ["需要普通应用身份验证 WebView 最终加载地址。"],
        }
    ]

    validated, result = ScanOrchestrator._validated_agent_payload(
        payload,
        [{"id": "static", "kind": "static.jadx", "metadata": {}}],
    )

    assert result == "supported_static"
    assessment = validated["hypothesis_assessments"][0]
    assert assessment["verdict"] == "needs_dynamic_proof"
    assert assessment["evidence_ids"] == ["static"]


def test_not_reproduced_requires_correlated_explicit_negative_oracle() -> None:
    evidence = [
        {
            "id": "static",
            "kind": "static.apktool",
            "exit_code": 0,
            "metadata": {},
        },
        {
            "id": "probe",
            "kind": "blackbox.probe_app",
            "exit_code": 0,
            "metadata": {
                "caller_identity": "probe_app",
                "request_id": "request-1",
                "test_case_id": "agent-r1-1",
            },
        },
        {
            "id": "log",
            "kind": "blackbox.logcat",
            "exit_code": 0,
            "metadata": {
                "request_id": "request-1",
                "request_observed": True,
                "probe_success": False,
                "test_case_id": "agent-r1-1",
            },
        },
    ]
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("not_reproduced", ["static", "probe", "log"]),
        evidence,
    )
    assert result == "inconclusive"
    assert any("pending dynamic proof" in gap for gap in payload["coverage_gaps"])

    evidence[1]["metadata"]["oracle_refuted"] = True
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("not_reproduced", ["static", "probe", "log"]),
        evidence,
    )
    assert result == "not_reproduced"
    assert payload["platform_severity"] is None


def test_blackbox_evidence_must_share_request_and_test_case_ids() -> None:
    evidence = [
        {
            "id": "static",
            "kind": "static.apktool",
            "exit_code": 0,
            "metadata": {},
        },
        {
            "id": "probe",
            "kind": "blackbox.probe_app",
            "exit_code": 0,
            "metadata": {
                "caller_identity": "probe_app",
                "request_id": "request-1",
                "test_case_id": "agent-r1-1",
            },
        },
        {
            "id": "log",
            "kind": "blackbox.logcat",
            "exit_code": 0,
            "metadata": {
                "request_id": "request-1",
                "request_observed": True,
                "probe_success": True,
                "test_case_id": "agent-r1-2",
                "security_impact_observed": True,
                "impact_contract_satisfied": True,
            },
        },
    ]
    payload, result = ScanOrchestrator._validated_agent_payload(
        _payload("reproduced_blackbox", ["static", "probe", "log"]),
        evidence,
    )
    assert result == "inconclusive"


def test_agent_requested_deep_link_must_preserve_declared_origin() -> None:
    entry = EntryPoint(
        id="11111111-1111-1111-1111-111111111111",
        scan_id="scan",
        kind="deep_link",
        name="https://example.test/open",
        owner_component="com.example.LinkActivity",
        exported=True,
        exported_reason="explicit_true",
        intent_filters=[],
        deep_links=[],
        metadata_json={},
    )
    allowed = AgentRequestedTest(
        hypothesis_id="22222222-2222-2222-2222-222222222222",
        entry_point_id=entry.id,
        state="guest",
        uri="https://example.test/open?next=%2Fadmin",
        extras={},
        rationale="Test redirect validation",
    )
    rejected = AgentRequestedTest(
        hypothesis_id="22222222-2222-2222-2222-222222222222",
        entry_point_id=entry.id,
        state="guest",
        uri="https://unrelated.test/open",
        extras={},
        rationale="Should not leave scope",
    )
    accepted, gaps = ScanOrchestrator._validate_requested_tests([allowed, rejected], [entry])
    assert accepted == [allowed]
    assert any("preserve" in gap for gap in gaps)


def test_activity_request_accepts_its_declared_deep_link_and_android_extra_key() -> None:
    entry = EntryPoint(
        id="11111111-1111-1111-1111-111111111111",
        scan_id="scan",
        kind="activity",
        name="com.example.LinkActivity",
        owner_component="com.example.LinkActivity",
        exported=True,
        exported_reason="explicit_true",
        intent_filters=[],
        deep_links=[
            {
                "scheme": "iqoo",
                "host": "com.iqoo.secure",
                "port": None,
                "path": "/smart_privacy",
                "uri_template": "iqoo://com.iqoo.secure/smart_privacy",
            }
        ],
        metadata_json={},
    )
    allowed = AgentRequestedTest(
        hypothesis_id="22222222-2222-2222-2222-222222222222",
        entry_point_id=entry.id,
        state="guest",
        uri="iqoo://com.iqoo.secure/smart_privacy?source=test",
        extras={":settings:fragment_args_key": "clipboard_privacy_protect"},
        rationale="Exercise the activity's declared deep link and framework-style extra",
    )
    rejected = allowed.model_copy(update={"uri": "iqoo://unrelated.example/smart_privacy"})

    accepted, gaps = ScanOrchestrator._validate_requested_tests(
        [allowed, rejected],
        [entry],
        hypothesis_ids={allowed.hypothesis_id},
    )

    assert accepted == [allowed]
    assert any("preserve" in gap for gap in gaps)


def test_agent_requested_tests_are_not_truncated_by_a_per_round_count() -> None:
    entry = EntryPoint(
        id="11111111-1111-1111-1111-111111111111",
        scan_id="scan",
        kind="activity",
        name="com.example.ManyTestsActivity",
        owner_component="com.example.ManyTestsActivity",
        exported=True,
        exported_reason="explicit_true",
        intent_filters=[],
        deep_links=[],
        metadata_json={},
    )
    hypothesis_id = "22222222-2222-2222-2222-222222222222"
    requests = [
        AgentRequestedTest(
            hypothesis_id=hypothesis_id,
            entry_point_id=entry.id,
            state="guest",
            uri=None,
            extras={"variant": str(index)},
            rationale=f"Exercise materially distinct input {index}.",
        )
        for index in range(12)
    ]

    accepted, gaps = ScanOrchestrator._validate_requested_tests(
        requests,
        [entry],
        hypothesis_ids={hypothesis_id},
    )

    assert accepted == requests
    assert gaps == []


def test_requested_test_deduplication_ignores_rationale_only_changes() -> None:
    entry = EntryPoint(
        id="11111111-1111-1111-1111-111111111111",
        scan_id="scan",
        kind="activity",
        name="com.example.ExportedActivity",
        owner_component="com.example.ExportedActivity",
        exported=True,
        exported_reason="explicit_true",
        intent_filters=[],
        deep_links=[],
        metadata_json={},
    )
    first = AgentRequestedTest(
        hypothesis_id="22222222-2222-2222-2222-222222222222",
        entry_point_id=entry.id,
        state="guest",
        uri=None,
        extras={"source": "external"},
        rationale="Candidate rationale",
    )
    duplicate = first.model_copy(update={"rationale": "Critic rationale"})

    accepted, gaps = ScanOrchestrator._validate_requested_tests(
        [first, duplicate],
        [entry],
        hypothesis_ids={first.hypothesis_id},
    )

    assert accepted == [first]
    assert gaps == []


def test_personal_lab_accepts_typed_provider_call_and_objective_oracle() -> None:
    entry = EntryPoint(
        id="11111111-1111-1111-1111-111111111111",
        scan_id="scan",
        kind="provider",
        name="com.example.ExportedProvider",
        owner_component="com.example.ExportedProvider",
        exported=True,
        metadata_json={"authorities": "com.example.provider"},
    )
    request = AgentRequestedTest(
        hypothesis_id="22222222-2222-2222-2222-222222222222",
        entry_point_id=entry.id,
        state="guest",
        uri="content://com.example.provider/items",
        extras={"account": "victim"},
        operation="call",
        method="getPrivateItems",
        argument="all",
        reset="preserve",
        oracle={
            "kind": "log_contains",
            "expected_text": "private-item",
            "impact": "none",
        },
        rationale="Call the exported provider as an ordinary application UID.",
    )

    accepted, gaps = ScanOrchestrator._validate_requested_tests(
        [request],
        [entry],
        hypothesis_ids={request.hypothesis_id},
        permission_profile="personal_lab",
    )

    assert accepted == [request]
    assert gaps == []


def test_non_provider_request_ignores_provider_only_fields() -> None:
    entry = EntryPoint(
        id="11111111-1111-1111-1111-111111111111",
        scan_id="scan",
        kind="deep_link",
        name="vulntest://open/",
        owner_component="com.example.DeepLinkActivity",
        exported=True,
    )
    request = AgentRequestedTest(
        hypothesis_id="22222222-2222-2222-2222-222222222222",
        entry_point_id=entry.id,
        state="guest",
        uri="vulntest://open/?url=https://example.invalid",
        extras={},
        operation="call",
        method="accidentalProviderMethod",
        argument="unused",
        oracle={
            "kind": "provider_rows",
            "minimum_rows": 1,
            "impact": "unauthorized_data_access",
        },
        rationale="Replay the deep link from an ordinary application.",
    )

    accepted, gaps = ScanOrchestrator._validate_requested_tests(
        [request],
        [entry],
        hypothesis_ids={request.hypothesis_id},
    )

    assert gaps == []
    assert len(accepted) == 1
    assert accepted[0].operation == "auto"
    assert accepted[0].method is None
    assert accepted[0].argument is None
    assert accepted[0].oracle.kind == "reachability"
    assert accepted[0].oracle.impact == "none"


def test_service_request_preserves_platform_binder_transaction() -> None:
    entry = EntryPoint(
        id="11111111-1111-1111-1111-111111111111",
        scan_id="scan",
        kind="service",
        name="io.apkscanner.vulntest.CommandService",
        owner_component="io.apkscanner.vulntest.CommandService",
        exported=True,
    )
    request = AgentRequestedTest(
        hypothesis_id="22222222-2222-2222-2222-222222222222",
        entry_point_id=entry.id,
        state="guest",
        uri=None,
        extras={},
        operation="binder_transact",
        binder_transaction_code=1,
        binder_reply_type="string",
        oracle={
            "kind": "binder_reply",
            "expected_text": "service-secret=hunter2",
            "impact": "unauthorized_data_access",
        },
        rationale="Read a sensitive Binder reply as an ordinary application UID.",
    )

    accepted, gaps = ScanOrchestrator._validate_requested_tests(
        [request],
        [entry],
        hypothesis_ids={request.hypothesis_id},
    )

    assert gaps == []
    assert accepted == [request]
    assert accepted[0].operation == "binder_transact"


def test_service_request_preserves_platform_binder_script() -> None:
    entry = EntryPoint(
        id="11111111-1111-1111-1111-111111111111",
        scan_id="scan",
        kind="service",
        name="io.apkscanner.vulntest.CommandService",
        owner_component="io.apkscanner.vulntest.CommandService",
        exported=True,
    )
    request = AgentRequestedTest(
        hypothesis_id="22222222-2222-2222-2222-222222222222",
        entry_point_id=entry.id,
        state="guest",
        uri=None,
        extras={},
        operation="binder_script",
        binder_transaction_code=7,
        binder_script=[
            {
                "operation": "read_long",
                "string_value": None,
                "integer_value": None,
                "boolean_value": None,
            }
        ],
        oracle={
            "kind": "binder_reply",
            "expected_text": "87109624524081870",
            "impact": "unauthorized_data_access",
        },
        rationale="Read a long Binder reply as an ordinary application UID.",
    )

    accepted, gaps = ScanOrchestrator._validate_requested_tests(
        [request],
        [entry],
        hypothesis_ids={request.hypothesis_id},
    )

    assert gaps == []
    assert accepted == [request]
    assert accepted[0].operation == "binder_script"


def test_platform_binder_transaction_is_rejected_for_non_service_entry() -> None:
    request = AgentRequestedTest(
        hypothesis_id="22222222-2222-2222-2222-222222222222",
        entry_point_id="11111111-1111-1111-1111-111111111111",
        state="guest",
        uri=None,
        extras={},
        operation="binder_transact",
        binder_transaction_code=1,
        binder_reply_type="string",
        oracle={
            "kind": "binder_reply",
            "expected_text": "secret",
            "impact": "unauthorized_data_access",
        },
        rationale="This action belongs only to a Service.",
    )
    entry = EntryPoint(
        id=request.entry_point_id,
        scan_id="scan",
        kind="activity",
        name="com.example.MainActivity",
        owner_component="com.example.MainActivity",
        exported=True,
    )

    accepted, gaps = ScanOrchestrator._validate_requested_tests(
        [request],
        [entry],
        hypothesis_ids={request.hypothesis_id},
    )

    assert accepted == []
    assert any("allowed only for Service" in gap for gap in gaps)


def test_provider_rows_oracle_rejects_a_non_query_operation() -> None:
    entry = EntryPoint(
        id="11111111-1111-1111-1111-111111111111",
        scan_id="scan",
        kind="provider",
        name="com.example.ExportedProvider",
        owner_component="com.example.ExportedProvider",
        exported=True,
        metadata_json={"authorities": "com.example.provider"},
    )
    request = AgentRequestedTest(
        hypothesis_id="22222222-2222-2222-2222-222222222222",
        entry_point_id=entry.id,
        state="guest",
        uri="content://com.example.provider/items",
        extras={},
        operation="call",
        method="getPrivateItems",
        oracle={
            "kind": "provider_rows",
            "minimum_rows": 1,
            "impact": "unauthorized_data_access",
        },
        rationale="A call result cannot satisfy a row-count predicate.",
    )

    accepted, gaps = ScanOrchestrator._validate_requested_tests(
        [request],
        [entry],
        hypothesis_ids={request.hypothesis_id},
    )

    assert accepted == []
    assert any("requires a provider query operation" in gap for gap in gaps)
