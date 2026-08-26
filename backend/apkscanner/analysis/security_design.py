from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterable
from typing import Any

from ..core.models import EntryPoint, Scan


def _canonical_digest(value: Any) -> str:
    material = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode()).hexdigest()


def build_android_threat_model(
    scan: Scan,
    entries: Iterable[EntryPoint],
) -> dict[str, Any]:
    """Build the sealed, scan-wide security assumptions agents must reason from."""

    entry_list = list(entries)
    exported = [entry for entry in entry_list if entry.exported]
    unguarded = [
        entry
        for entry in exported
        if not entry.permission
        or str(entry.permission_protection or "").lower()
        not in {"signature", "signatureorsystem", "internal"}
    ]
    kind_counts = Counter(entry.kind for entry in entry_list)
    model: dict[str, Any] = {
        "schema_version": "1.0",
        "subject": {
            "package": scan.package_name,
            "version": scan.version_name,
            "min_sdk": scan.min_sdk,
            "target_sdk": scan.target_sdk,
        },
        "attacker": {
            "identity": "untrusted_third_party_app",
            "privileges": ["ordinary_app_uid", "guest_application_state"],
            "excluded_privileges": ["root", "system_uid", "adb_shell", "instrumentation"],
            "capabilities": [
                "send_explicit_or_implicit_intents",
                "invoke_exported_binders_or_content_providers",
                "open_declared_deep_links",
                "supply_untrusted_ipc_inputs",
            ],
        },
        "assets": [
            "application_private_data",
            "authenticated_user_actions",
            "privileged_platform_operations",
            "security_sensitive_configuration",
            "availability_of_security_sensitive_components",
        ],
        "trust_boundaries": [
            "android_component_export_boundary",
            "binder_or_content_provider_caller_boundary",
            "deep_link_and_uri_input_boundary",
            "application_authentication_and_authorization_boundary",
        ],
        "attack_surface": {
            "entry_point_count": len(entry_list),
            "exported_count": len(exported),
            "exported_without_signature_guard_count": len(unguarded),
            "kind_counts": dict(sorted(kind_counts.items())),
            "representative_entries": [
                {
                    "kind": entry.kind,
                    "name": entry.name,
                    "permission": entry.permission,
                    "permission_protection": entry.permission_protection,
                }
                for entry in sorted(
                    unguarded,
                    key=lambda item: (item.kind, item.name),
                )[:25]
            ],
        },
        "security_objectives": [
            "Untrusted callers cannot read sensitive data without authorization.",
            "Untrusted callers cannot cause privileged or authenticated state changes.",
            "Externally supplied IPC and URI inputs cannot cross a security boundary unchecked.",
            "Externally reachable behavior cannot produce a concrete unauthorized security impact.",
        ],
        "evidence_policy": {
            "static_analysis_role": "candidate_generation_and_path_reasoning",
            "final_finding_requirement": (
                "A final Finding requires a platform-correlated ordinary-app-UID replay "
                "and an objective security-impact Oracle."
            ),
            "reachability_alone_is_harm": False,
            "model_self_report_is_proof": False,
            "adb_shell_is_ordinary_app_proof": False,
        },
        "normal_degradation": [
            "Partial JADX output is expected; Apktool, Smali, manifest, resources, and archive "
            "content remain valid analysis inputs.",
            "Missing optional tooling does not establish or refute a hypothesis.",
        ],
    }
    model["digest"] = _canonical_digest(model)
    return model


def finding_identity(
    *,
    scan: Scan,
    rule_id: str,
    category: str,
    entry_names: Iterable[str],
    claim: str = "",
) -> dict[str, str]:
    """Return stable semantic identity plus a scan-specific occurrence identity."""

    certificates = scan.signing.get("certificate_sha256", []) if scan.signing else []
    signer = (
        sorted(str(value).lower() for value in certificates)[0]
        if isinstance(certificates, list) and certificates
        else "unknown-signer"
    )
    semantic_material = {
        "package": scan.package_name or "unknown-package",
        "signer": signer,
        "rule_id": rule_id,
        "category": category,
        "entry_names": sorted(set(entry_names)),
        "claim": " ".join(claim.lower().split()),
    }
    stable_id = _canonical_digest(semantic_material)
    occurrence_id = _canonical_digest(
        {
            "finding_id": stable_id,
            "scan_id": scan.id,
            "artifact_sha256": scan.artifact_sha256,
        }
    )
    return {
        "schema_version": "1.0",
        "finding_id": stable_id,
        "occurrence_id": occurrence_id,
        "semantic_fingerprint": stable_id,
    }
