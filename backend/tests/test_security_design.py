from __future__ import annotations

from apkscanner.analysis.security_design import build_android_threat_model, finding_identity
from apkscanner.core.models import EntryPoint, Scan


def _scan(scan_id: str, artifact: str, version: str) -> Scan:
    return Scan(
        id=scan_id,
        filename="fixture.apk",
        artifact_sha256=artifact,
        artifact_path="/tmp/fixture.apk",
        package_name="com.example.fixture",
        version_name=version,
        min_sdk=24,
        target_sdk=35,
        signing={"certificate_sha256": ["AA:BB"]},
    )


def test_android_threat_model_is_deterministic_and_explicit() -> None:
    scan = _scan("00000000-0000-0000-0000-000000000001", "a" * 64, "1")
    entries = [
        EntryPoint(
            id="00000000-0000-0000-0000-000000000011",
            scan_id=scan.id,
            kind="activity",
            name="com.example.fixture.OpenActivity",
            exported=True,
            permission=None,
        ),
        EntryPoint(
            id="00000000-0000-0000-0000-000000000012",
            scan_id=scan.id,
            kind="provider",
            name="com.example.fixture.PrivateProvider",
            exported=False,
            permission=None,
        ),
    ]

    first = build_android_threat_model(scan, entries)
    second = build_android_threat_model(scan, reversed(entries))

    assert first["digest"] == second["digest"]
    assert first["attacker"]["identity"] == "untrusted_third_party_app"
    assert "adb_shell" in first["attacker"]["excluded_privileges"]
    assert first["attack_surface"]["exported_without_signature_guard_count"] == 1
    assert first["evidence_policy"]["reachability_alone_is_harm"] is False


def test_finding_identity_is_stable_across_versions_but_occurrence_is_not() -> None:
    first_scan = _scan("00000000-0000-0000-0000-000000000001", "a" * 64, "1")
    second_scan = _scan("00000000-0000-0000-0000-000000000002", "b" * 64, "2")

    first = finding_identity(
        scan=first_scan,
        rule_id="AGENT-ENTRY-INVESTIGATION",
        category="android.exported_component",
        entry_names=["com.example.fixture.OpenActivity"],
        claim="Guest caller can change protected state.",
    )
    second = finding_identity(
        scan=second_scan,
        rule_id="AGENT-ENTRY-INVESTIGATION",
        category="android.exported_component",
        entry_names=["com.example.fixture.OpenActivity"],
        claim="Guest caller can change protected state.",
    )

    assert first["finding_id"] == second["finding_id"]
    assert first["semantic_fingerprint"] == second["semantic_fingerprint"]
    assert first["occurrence_id"] != second["occurrence_id"]
