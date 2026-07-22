from __future__ import annotations

from apkscanner.manifest import parse_manifest

from .conftest import MANIFEST


def test_manifest_effective_exports_and_deep_link_cartesian_product() -> None:
    document = parse_manifest(MANIFEST)
    components = {entry.name: entry for entry in document.entries if entry.kind != "deep_link"}
    assert document.package_name == "com.example.vulnerable"
    assert document.target_sdk == 35
    assert components["com.example.vulnerable.DeepLinkActivity"].exported is True
    assert components["com.example.vulnerable.TrustedService"].permission_protection == "signature"
    assert components["com.example.vulnerable.RiskReceiver"].exported is True
    assert components["com.example.vulnerable.RiskReceiver"].exported_reason == "missing_required_attribute_with_filter"
    links = [entry for entry in document.entries if entry.kind == "deep_link"]
    assert len(links) == 4
    assert {entry.name for entry in links} == {
        "demo://example.test/open",
        "demo://m.example.test/open",
        "https://example.test/open",
        "https://m.example.test/open",
    }


def test_signature_permission_is_inherited_by_component() -> None:
    document = parse_manifest(MANIFEST)
    service = next(entry for entry in document.entries if entry.kind == "service")
    assert service.permission == "com.example.vulnerable.TRUSTED"
    assert service.permission_protection == "signature"
