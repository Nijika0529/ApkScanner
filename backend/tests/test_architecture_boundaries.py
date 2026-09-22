from __future__ import annotations

import ast
from pathlib import Path

import apkscanner


def _project_dependencies(directory: Path) -> list[tuple[Path, str]]:
    dependencies: list[tuple[Path, str]] = []
    for path in directory.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.level >= 2:
                    dependencies.append((path, node.module.split(".", 1)[0]))
                elif node.module.startswith("apkscanner."):
                    dependencies.append((path, node.module.split(".")[1]))
            elif isinstance(node, ast.Import):
                dependencies.extend(
                    (path, imported.name.split(".")[1])
                    for imported in node.names
                    if imported.name.startswith("apkscanner.")
                )
    return dependencies


def test_core_does_not_depend_on_outer_application_layers() -> None:
    package_root = Path(apkscanner.__file__).parent
    violations = [
        f"{path.name} -> {dependency}"
        for path, dependency in _project_dependencies(package_root / "core")
        if dependency in {"analysis", "infrastructure", "platform", "runtime"}
    ]
    assert violations == []


def test_analysis_uses_infrastructure_ports_not_platform_adapters() -> None:
    package_root = Path(apkscanner.__file__).parent
    violations = [
        f"{path.name} -> {dependency}"
        for path, dependency in _project_dependencies(package_root / "analysis")
        if dependency in {"platform", "runtime"}
    ]
    assert violations == []


def test_infrastructure_does_not_depend_on_application_layers() -> None:
    package_root = Path(apkscanner.__file__).parent
    violations = [
        f"{path.name} -> {dependency}"
        for path, dependency in _project_dependencies(package_root / "infrastructure")
        if dependency in {"analysis", "platform", "runtime"}
    ]
    assert violations == []


def test_runtime_does_not_depend_on_platform_delivery_layer() -> None:
    package_root = Path(apkscanner.__file__).parent
    violations = [
        f"{path.name} -> {dependency}"
        for path, dependency in _project_dependencies(package_root / "runtime")
        if dependency == "platform"
    ]
    assert violations == []


def test_platform_does_not_reach_into_private_live_proof_api() -> None:
    package_root = Path(apkscanner.__file__).parent
    platform_source = "\n".join(
        path.read_text(encoding="utf-8") for path in (package_root / "platform").glob("*.py")
    )
    assert "_LiveProofContext" not in platform_source
    assert "._register_live_proof_context" not in platform_source
    assert "._unregister_live_proof_context" not in platform_source
    assert "._ensure_live_proof_endpoint" not in platform_source
