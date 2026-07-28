from __future__ import annotations

import pytest
from apkscanner.benchmark import BenchmarkEvaluator
from apkscanner.db import Database
from apkscanner.models import EntryPoint, Evidence, Finding, Scan
from apkscanner.schemas import BenchmarkSpec
from pydantic import ValidationError


def test_private_benchmark_rewards_proven_harm_and_penalizes_confirmed_noise(
    settings,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="final",
            filename="private.apk",
            artifact_sha256="a" * 64,
            artifact_path=str(settings.data_dir / "private.apk"),
            stats={"investigator": "opencode"},
        )
        vulnerable_entry = EntryPoint(
            scan=scan,
            kind="deep_link",
            name="demo://example.test/open",
            exported=True,
        )
        static_only_entry = EntryPoint(
            scan=scan,
            kind="provider",
            name="com.example.DataProvider",
            exported=True,
        )
        session.add_all([scan, vulnerable_entry, static_only_entry])
        session.flush()
        proof_one = Evidence(
            scan_id=scan.id,
            kind="dynamic.oracle",
            sha256="1" * 64,
            path="proof-one.json",
        )
        proof_two = Evidence(
            scan_id=scan.id,
            kind="dynamic.log",
            sha256="2" * 64,
            path="proof-two.json",
        )
        session.add_all([proof_one, proof_two])
        session.flush()
        session.add_all(
            [
                Finding(
                    scan=scan,
                    dedupe_key="agent:dynamic",
                    rule_id="AGENT-ENTRY-INVESTIGATION",
                    source="opencode",
                    title="Agent investigation: deep link",
                    description="Unauthenticated route triggers the protected action.",
                    masvs="MASVS-PLATFORM",
                    severity="high",
                    status="reproduced_blackbox",
                    entry_point_ids=[vulnerable_entry.id],
                        evidence_ids=[proof_one.id, proof_two.id],
                    metadata_json={
                        "harm_demonstrated": True,
                        "model": "deepseek-v4-pro",
                    },
                ),
                Finding(
                    scan=scan,
                    dedupe_key="agent:static",
                    rule_id="AGENT-ENTRY-INVESTIGATION",
                    source="opencode",
                    title="Agent investigation: provider",
                    description="Provider looks exported but no harmful operation was demonstrated.",
                    masvs="MASVS-PLATFORM",
                    severity="medium",
                    status="supported_static",
                    entry_point_ids=[static_only_entry.id],
                    evidence_ids=["static-1"],
                ),
                Finding(
                    scan=scan,
                    dedupe_key="agent:noise",
                    rule_id="AGENT-ENTRY-INVESTIGATION",
                    source="opencode",
                    title="Unproven AI theory",
                    description="No evidence.",
                    masvs="MASVS-PLATFORM",
                    severity="high",
                    status="inconclusive",
                ),
                Finding(
                    scan=scan,
                    dedupe_key="agent:reachability-only",
                    rule_id="AGENT-ENTRY-INVESTIGATION",
                    source="opencode",
                    title="Reachable but no actual impact",
                    description="The route opened but no security harm was observed.",
                    masvs="MASVS-PLATFORM",
                    severity="high",
                    status="reproduced_blackbox",
                    metadata_json={"harm_demonstrated": False},
                ),
            ]
        )
        session.commit()
        scan_id = scan.id

    spec = BenchmarkSpec.model_validate(
        {
            "schema_version": "1.0",
            "name": "private-truth",
            "apk_sha256": "a" * 64,
            "vulnerabilities": [
                {
                    "id": "GT-1",
                    "title": "Deep-link auth bypass",
                    "harm": "Guest triggers a protected action.",
                    "severity": "high",
                    "minimum_proof": "dynamic",
                    "match": {
                        "rule_ids": ["AGENT-ENTRY-INVESTIGATION"],
                        "entry_names": ["demo://example.test/open"],
                        "title_contains": ["unauthenticated"],
                    },
                },
                {
                    "id": "GT-2",
                    "title": "Provider data modification",
                    "harm": "An untrusted app modifies protected provider data.",
                    "severity": "high",
                    "minimum_proof": "dynamic",
                    "match": {
                        "rule_ids": ["AGENT-ENTRY-INVESTIGATION"],
                        "entry_names": ["com.example.DataProvider"],
                    },
                },
            ],
        }
    )
    evaluation = BenchmarkEvaluator(settings, database).evaluate(scan_id, spec)
    metrics = evaluation.result["metrics"]
    assert metrics["true_positives"] == 1
    assert metrics["false_positives"] == 0
    assert metrics["false_negatives"] == 1
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 0.5
    assert metrics["score_100"] == 83.33
    assert metrics["unproven_ai_noise"] == 3
    assert evaluation.result["matches"][0]["ground_truth_id"] == "GT-1"
    assert evaluation.result["missed"][0]["ground_truth_id"] == "GT-2"
    assert evaluation.investigator_backend == "opencode"
    assert evaluation.model == "deepseek-v4-pro"
    assert evaluation.result["model_attribution"]["source"] == "finding_metadata"


def test_benchmark_uses_maximum_matching_instead_of_truth_file_order(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="final",
            filename="ambiguous.apk",
            artifact_sha256="c" * 64,
            artifact_path=str(settings.data_dir / "ambiguous.apk"),
        )
        session.add(scan)
        session.flush()
        specific_evidence = Evidence(
            scan_id=scan.id,
            kind="dynamic.oracle",
            sha256="3" * 64,
            path="specific.json",
        )
        generic_evidence = Evidence(
            scan_id=scan.id,
            kind="dynamic.oracle",
            sha256="4" * 64,
            path="generic.json",
        )
        session.add_all([specific_evidence, generic_evidence])
        session.flush()
        specific = Finding(
            scan=scan,
            dedupe_key="specific",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            source="opencode",
            title="Generic issue with a specific authorization bypass",
            description="generic specific",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="reproduced_blackbox",
            evidence_ids=[specific_evidence.id],
            metadata_json={"harm_demonstrated": True},
        )
        generic = Finding(
            scan=scan,
            dedupe_key="generic",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            source="opencode",
            title="Generic issue",
            description="generic",
            masvs="MASVS-PLATFORM",
            severity="medium",
            status="reproduced_blackbox",
            evidence_ids=[generic_evidence.id],
            metadata_json={"harm_demonstrated": True},
        )
        session.add_all([specific, generic])
        session.commit()
        scan_id = scan.id

    spec = BenchmarkSpec.model_validate(
        {
            "name": "ambiguous-matching",
            "vulnerabilities": [
                {
                    "id": "GT-GENERIC",
                    "title": "Generic issue",
                    "harm": "Generic impact",
                    "severity": "medium",
                    "minimum_proof": "dynamic",
                    "match": {"title_contains": ["generic"]},
                },
                {
                    "id": "GT-SPECIFIC",
                    "title": "Specific bypass",
                    "harm": "Authorization bypass",
                    "severity": "high",
                    "minimum_proof": "dynamic",
                    "match": {"title_contains": ["specific"]},
                },
            ],
        }
    )
    evaluation = BenchmarkEvaluator(settings, database).evaluate(scan_id, spec)
    assert evaluation.result["metrics"]["true_positives"] == 2
    assert evaluation.result["metrics"]["false_negatives"] == 0
    assert {
        item["ground_truth_id"]: item["finding_id"]
        for item in evaluation.result["matches"]
    } == {
        "GT-GENERIC": generic.id,
        "GT-SPECIFIC": specific.id,
    }


def test_ground_truth_requires_selectors_and_unique_ids() -> None:
    base = {
        "id": "GT-1",
        "title": "Issue",
        "harm": "Impact",
        "severity": "high",
        "minimum_proof": "dynamic",
        "match": {},
    }
    with pytest.raises(ValidationError, match="matching selector"):
        BenchmarkSpec.model_validate(
            {"name": "invalid-selector", "vulnerabilities": [base]}
        )
    with pytest.raises(ValidationError, match="must be unique"):
        BenchmarkSpec.model_validate(
            {
                "name": "duplicate-ids",
                "vulnerabilities": [
                    {**base, "match": {"rule_ids": ["RULE"]}},
                    {**base, "match": {"cwes": ["CWE-200"]}},
                ],
            }
        )


def test_benchmark_rejects_nonfinal_scan(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="running.apk",
            artifact_sha256="d" * 64,
            artifact_path=str(settings.data_dir / "running.apk"),
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id
    spec = BenchmarkSpec.model_validate(
        {
            "name": "too-early",
            "vulnerabilities": [
                {
                    "id": "GT-1",
                    "title": "Issue",
                    "harm": "Impact",
                    "severity": "high",
                    "match": {"rule_ids": ["RULE"]},
                }
            ],
        }
    )
    with pytest.raises(ValueError, match="completed final scan"):
        BenchmarkEvaluator(settings, database).evaluate(scan_id, spec)
