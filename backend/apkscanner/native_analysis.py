from __future__ import annotations

import hashlib
import json
import re
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .fast_text_search import files_containing_any
from .permissions import ensure_private_directory
from .tools import TimeBudget, ToolRunner

NATIVE_INDEX_SCHEMA_VERSION = "1.0"

_ELF_TYPES = {
    0: "NONE",
    1: "REL",
    2: "EXEC",
    3: "DYN",
    4: "CORE",
}
_ELF_MACHINES = {
    3: "Intel 80386",
    8: "MIPS",
    40: "ARM",
    62: "AMD x86-64",
    183: "AArch64",
    243: "RISC-V",
}
_SECURITY_RELEVANT_SYMBOLS = re.compile(
    r"^(?:"
    r"RegisterNatives|FindClass|GetMethodID|GetStaticMethodID|"
    r"dlopen|android_dlopen_ext|dlsym|dlclose|"
    r"system|popen|execv(?:e|p)?|posix_spawn|fork|ptrace|"
    r"mmap|mprotect|memfd_create|open(?:at)?|read|write|"
    r"connect|bind|listen|accept|send|recv|"
    r"EVP_|AES_|RSA_|HMAC_|SHA(?:1|2|256|512)|MD5|"
    r"sqlite3_|SSL_|BIO_"
    r")"
)


@dataclass(slots=True)
class _JavaBridge:
    class_name: str
    source_path: str
    loads: list[dict[str, str]]
    methods: list[dict[str, str]]


class NativeArtifactAnalyzer:
    """Build a deterministic Java/JNI/ELF view for one APK artifact."""

    def __init__(self, runner: ToolRunner):
        self.runner = runner

    def analyze(
        self,
        *,
        apk_path: Path,
        workspace: Path,
        artifact_id: str,
        artifact_sha256: str,
        package_name: str,
        native_libraries: list[str],
        failed_java_classes: set[str] | None = None,
        budget: TimeBudget | None = None,
    ) -> dict[str, Any]:
        native_root = workspace / "native"
        ensure_private_directory(native_root)
        libraries = self._extract_and_summarize(
            apk_path=apk_path,
            native_root=native_root,
            archive_paths=native_libraries,
            workspace=workspace,
            budget=budget,
        )
        bridges = self._discover_java_bridges(
            workspace,
            failed_java_classes=failed_java_classes or set(),
        )
        nodes, edges, links = self._build_graph(
            artifact_id=artifact_id,
            package_name=package_name,
            libraries=libraries,
            bridges=bridges,
        )
        ownership_counts: dict[str, int] = {}
        for node in nodes:
            if node.get("kind") != "java_native_bridge":
                continue
            ownership = str(node.get("ownership") or "unknown")
            ownership_counts[ownership] = ownership_counts.get(ownership, 0) + 1
        linked_methods = {
            (
                str(edge.get("from")),
                str(edge.get("method_name")),
                str(edge.get("argument_descriptor")),
            )
            for edge in edges
            if edge.get("relation") in {"binds_to_jni", "possible_dynamic_registration"}
        }
        method_count = sum(len(bridge.methods) for bridge in bridges)
        index = {
            "schema_version": NATIVE_INDEX_SCHEMA_VERSION,
            "artifact_id": artifact_id,
            "artifact_sha256": artifact_sha256,
            "summary": {
                "native_library_count": len(libraries),
                "valid_elf_count": sum(
                    1 for library in libraries if library["elf"].get("valid")
                ),
                "java_bridge_class_count": len(bridges),
                "java_native_method_count": method_count,
                "linked_java_native_method_count": len(linked_methods),
                "jni_export_count": sum(
                    int(library["jni"].get("export_count") or 0)
                    for library in libraries
                ),
                "dynamic_registration_library_count": sum(
                    1 for library in libraries if library["jni"].get("dynamic_registration")
                ),
                "java_bridge_ownership": ownership_counts,
            },
            "libraries": libraries,
            "java_bridges": [
                {
                    "class_name": bridge.class_name,
                    "source_path": bridge.source_path,
                    "ownership": self._class_ownership(bridge.class_name, package_name),
                    "loads": bridge.loads,
                    "native_methods": bridge.methods,
                }
                for bridge in bridges
            ],
            "links": links,
            "graph": {"nodes": nodes, "edges": edges},
        }
        (native_root / "index.json").write_text(
            json.dumps(index, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return index

    def _extract_and_summarize(
        self,
        *,
        apk_path: Path,
        native_root: Path,
        archive_paths: list[str],
        workspace: Path,
        budget: TimeBudget | None,
    ) -> list[dict[str, Any]]:
        libraries: list[dict[str, Any]] = []
        summaries = native_root / "summaries"
        ensure_private_directory(summaries)
        with zipfile.ZipFile(apk_path) as archive:
            for archive_path in archive_paths:
                normalized = PurePosixPath(archive_path)
                destination = native_root.joinpath(*normalized.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256()
                with archive.open(archive_path) as source, destination.open("wb") as target:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        digest.update(chunk)
                        target.write(chunk)
                summary = self._elf_summary(destination, budget)
                sha256 = digest.hexdigest()
                abi = normalized.parts[1] if len(normalized.parts) >= 3 else "unknown"
                library = {
                    "archive_path": archive_path,
                    "extracted_path": str(destination.relative_to(workspace)),
                    "summary_path": str(
                        (summaries / f"{sha256}.json").relative_to(workspace)
                    ),
                    "sha256": sha256,
                    "size": destination.stat().st_size,
                    "abi": abi,
                    **summary,
                }
                (summaries / f"{sha256}.json").write_text(
                    json.dumps(library, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                libraries.append(library)
        return libraries

    def _elf_summary(self, path: Path, budget: TimeBudget | None) -> dict[str, Any]:
        header = self._minimal_elf_header(path)
        if not header.get("valid"):
            return {
                "elf": header,
                "dependencies": [],
                "symbols": self._empty_symbols(),
                "jni": self._empty_jni(),
                "hardening": {},
            }
        tool = next(
            (name for name in ("llvm-readelf", "readelf") if self.runner.available(name)),
            None,
        )
        if tool is None:
            return {
                "elf": {**header, "inspection_tool": None},
                "dependencies": [],
                "symbols": self._empty_symbols(),
                "jni": self._empty_jni(),
                "hardening": {},
            }
        timeout = 90 if budget is None else budget.remaining(90)
        if timeout <= 0:
            return {
                "elf": {**header, "inspection_tool": tool, "inspection_status": "budget_exhausted"},
                "dependencies": [],
                "symbols": self._empty_symbols(),
                "jni": self._empty_jni(),
                "hardening": {},
            }
        result = self.runner.run(
            [tool, "-hW", "-lW", "-SW", "-dW", "-nW", "-sW", str(path)],
            timeout=timeout,
        )
        text = f"{result.stdout}\n{result.stderr}"
        if result.exit_code != 0:
            return {
                "elf": {
                    **header,
                    "inspection_tool": tool,
                    "inspection_status": "tool_failed",
                    "inspection_error": result.stderr.strip()[:1000],
                },
                "dependencies": [],
                "symbols": self._empty_symbols(),
                "jni": self._empty_jni(),
                "hardening": {},
            }
        parsed_header = self._parse_readelf_header(text)
        exported, imported = self._parse_symbols(text)
        jni_exports = sorted(
            symbol
            for symbol in exported
            if symbol.startswith("Java_") or symbol in {"JNI_OnLoad", "JNI_OnUnload"}
        )
        relevant = sorted(
            symbol
            for symbol in {*exported, *imported}
            if _SECURITY_RELEVANT_SYMBOLS.search(symbol)
        )
        dependencies = sorted(
            set(re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", text))
        )
        soname = self._first_match(r"\(SONAME\).*?\[([^\]]+)\]", text)
        build_id = self._first_match(r"Build ID:\s*([0-9a-fA-F]+)", text)
        dynamic_registration = (
            "JNI_OnLoad" in exported
            or "RegisterNatives" in imported
            or "RegisterNatives" in text
        )
        return {
            "elf": {
                **header,
                **parsed_header,
                "soname": soname,
                "build_id": build_id,
                "inspection_tool": tool,
                "inspection_status": "complete",
            },
            "dependencies": dependencies,
            "symbols": {
                "exported_count": len(exported),
                "imported_count": len(imported),
                "exported_sample": exported[:120],
                "imported_sample": imported[:120],
                "security_relevant": relevant,
            },
            "jni": {
                "export_count": len(jni_exports),
                "exports": jni_exports,
                "has_jni_onload": "JNI_OnLoad" in exported,
                "has_jni_onunload": "JNI_OnUnload" in exported,
                "dynamic_registration": dynamic_registration,
                "registration_evidence": [
                    evidence
                    for evidence, present in (
                        ("JNI_OnLoad", "JNI_OnLoad" in exported),
                        ("RegisterNatives", "RegisterNatives" in imported or "RegisterNatives" in text),
                    )
                    if present
                ],
            },
            "hardening": {
                "gnu_relro": "GNU_RELRO" in text,
                "bind_now": bool(re.search(r"\(BIND_NOW\)|FLAGS.*\bNOW\b", text)),
                "stack_canary": "__stack_chk_fail" in imported,
                "fortify": any(symbol.endswith("_chk") for symbol in imported),
                "executable_stack": self._executable_stack(text),
                "stripped": ".symtab" not in text,
            },
        }

    @staticmethod
    def _minimal_elf_header(path: Path) -> dict[str, Any]:
        with path.open("rb") as handle:
            raw = handle.read(64)
        if len(raw) < 20 or raw[:4] != b"\x7fELF":
            return {"valid": False, "error": "not_elf"}
        bits = {1: 32, 2: 64}.get(raw[4])
        byte_order = {1: "little", 2: "big"}.get(raw[5])
        if bits is None or byte_order is None:
            return {"valid": False, "error": "unsupported_elf_ident"}
        endian = "<" if byte_order == "little" else ">"
        elf_type, machine = struct.unpack(f"{endian}HH", raw[16:20])
        return {
            "valid": True,
            "bits": bits,
            "endianness": byte_order,
            "type": _ELF_TYPES.get(elf_type, str(elf_type)),
            "machine": _ELF_MACHINES.get(machine, str(machine)),
            "os_abi": raw[7],
        }

    @staticmethod
    def _parse_readelf_header(text: str) -> dict[str, Any]:
        values: dict[str, Any] = {}
        mapping = {
            "Class": "class",
            "Data": "data",
            "Type": "type_description",
            "Machine": "machine_description",
            "Entry point address": "entry_point",
        }
        for label, key in mapping.items():
            match = re.search(rf"^\s*{re.escape(label)}:\s*(.+)$", text, re.MULTILINE)
            if match:
                values[key] = match.group(1).strip()
        return values

    @staticmethod
    def _parse_symbols(text: str) -> tuple[list[str], list[str]]:
        exported: set[str] = set()
        imported: set[str] = set()
        pattern = re.compile(
            r"^\s*\d+:\s+[0-9a-fA-F]+\s+\d+\s+\S+\s+"
            r"(?P<bind>GLOBAL|WEAK)\s+(?P<visibility>DEFAULT|PROTECTED)\s+"
            r"(?P<index>\S+)\s+(?P<name>\S+)",
            re.MULTILINE,
        )
        for match in pattern.finditer(text):
            name = match.group("name").split("@", 1)[0]
            if not name or name == "0":
                continue
            if match.group("index") == "UND":
                imported.add(name)
            else:
                exported.add(name)
        return sorted(exported), sorted(imported)

    @staticmethod
    def _first_match(pattern: str, text: str) -> str | None:
        match = re.search(pattern, text)
        return match.group(1) if match else None

    @staticmethod
    def _executable_stack(text: str) -> bool | None:
        line = NativeArtifactAnalyzer._first_match(r"^\s*GNU_STACK\s+(.+)$", text)
        if line is None:
            return None
        fields = line.split()
        return any("E" in value for value in fields[-3:])

    @staticmethod
    def _empty_symbols() -> dict[str, Any]:
        return {
            "exported_count": 0,
            "imported_count": 0,
            "exported_sample": [],
            "imported_sample": [],
            "security_relevant": [],
        }

    @staticmethod
    def _empty_jni() -> dict[str, Any]:
        return {
            "export_count": 0,
            "exports": [],
            "has_jni_onload": False,
            "has_jni_onunload": False,
            "dynamic_registration": False,
            "registration_evidence": [],
        }

    @classmethod
    def _discover_java_bridges(
        cls,
        workspace: Path,
        *,
        failed_java_classes: set[str],
    ) -> list[_JavaBridge]:
        bridges: dict[str, _JavaBridge] = {}
        jadx = workspace / "jadx"
        java_root = jadx / "sources" if (jadx / "sources").is_dir() else jadx
        if java_root.is_dir():
            java_paths = files_containing_any(
                java_root,
                literals=(
                    "native",
                    "System.load(",
                    "loadLibrary",
                    "getRuntime().load(",
                ),
                suffixes=(".java",),
            )
            if java_paths is None:
                java_paths = sorted(java_root.rglob("*.java"))
            for path in java_paths:
                text = path.read_text(encoding="utf-8", errors="replace")
                package = cls._first_match(r"\bpackage\s+([A-Za-z_$][\w.$]*)\s*;", text) or ""
                class_name = cls._first_match(
                    r"\b(?:class|interface|enum)\s+([A-Za-z_$][\w$]*)",
                    text,
                ) or path.stem
                qualified = f"{package}.{class_name}" if package else class_name
                loads = cls._java_load_calls(text)
                methods = cls._java_native_methods(text)
                if loads or methods:
                    bridges[qualified] = _JavaBridge(
                        class_name=qualified,
                        source_path=str(path.relative_to(workspace)),
                        loads=loads,
                        methods=methods,
                    )
        if bridges and not failed_java_classes:
            return sorted(bridges.values(), key=lambda item: item.class_name)
        for parent in (workspace / "apktool", workspace / "archive"):
            if not parent.is_dir():
                continue
            if bridges:
                smali_paths = {
                    candidate
                    for class_name in failed_java_classes
                    for smali_root in parent.glob("smali*")
                    for candidate in [
                        smali_root.joinpath(*class_name.split(".")).with_suffix(".smali")
                    ]
                    if candidate.is_file()
                }
            else:
                optimized = files_containing_any(
                    parent,
                    literals=("native", "Ljava/lang/System;->load"),
                    suffixes=(".smali",),
                )
                smali_paths = (
                    set(parent.rglob("*.smali"))
                    if optimized is None
                    else set(optimized)
                )
            for path in sorted(smali_paths):
                text = path.read_text(encoding="utf-8", errors="replace")
                class_match = re.search(r"^\.class[^\n]*\sL([^;]+);", text, re.MULTILINE)
                if class_match is None:
                    continue
                qualified = class_match.group(1).replace("/", ".")
                loads = cls._smali_load_calls(text)
                methods = [
                    {
                        "name": match.group(1),
                        "return_type": match.group(3),
                        "parameters": match.group(2),
                        "argument_descriptor": match.group(2),
                        "declaration": match.group(0).strip(),
                    }
                    for match in re.finditer(
                        r"^\.method[^\n]*\bnative\b[^\n]*\s([\w$<>]+)\(([^)]*)\)(\S+)",
                        text,
                        re.MULTILINE,
                    )
                ]
                if loads or methods:
                    existing = bridges.get(qualified)
                    if existing is None:
                        bridges[qualified] = _JavaBridge(
                            class_name=qualified,
                            source_path=str(path.relative_to(workspace)),
                            loads=loads,
                            methods=methods,
                        )
                    else:
                        existing.loads = list(
                            {
                                (item["kind"], item["value"]): item
                                for item in [*existing.loads, *loads]
                            }.values()
                        )
                        existing.methods = list(
                            {
                                (
                                    item["name"],
                                    item.get("argument_descriptor", ""),
                                ): item
                                for item in [*existing.methods, *methods]
                            }.values()
                        )
        return sorted(bridges.values(), key=lambda item: item.class_name)

    @staticmethod
    def _java_load_calls(text: str) -> list[dict[str, str]]:
        calls: list[dict[str, str]] = []
        patterns = (
            ("load_library", r"(?:System|Runtime\.getRuntime\(\))\.loadLibrary\s*\(\s*[\"']([^\"']+)[\"']"),
            ("load_path", r"(?:System|Runtime\.getRuntime\(\))\.load\s*\(\s*[\"']([^\"']+)[\"']"),
        )
        for kind, pattern in patterns:
            calls.extend(
                {"kind": kind, "value": match.group(1)}
                for match in re.finditer(pattern, text)
            )
        return list({(item["kind"], item["value"]): item for item in calls}.values())

    @staticmethod
    def _java_native_methods(text: str) -> list[dict[str, str]]:
        methods: list[dict[str, str]] = []
        pattern = re.compile(
            r"(?P<declaration>(?:public|protected|private|static|final|synchronized|\s)+"
            r"native\s+(?P<return>[\w.$<>?\[\]]+)\s+"
            r"(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<parameters>[^)]*)\))"
        )
        for match in pattern.finditer(text):
            parameters = " ".join(match.group("parameters").split())
            methods.append(
                {
                    "name": match.group("name"),
                    "return_type": match.group("return"),
                    "parameters": parameters,
                    "argument_descriptor": NativeArtifactAnalyzer._java_arguments_descriptor(
                        parameters
                    ),
                    "declaration": " ".join(match.group("declaration").split()),
                }
            )
        return methods

    @classmethod
    def _java_arguments_descriptor(cls, parameters: str) -> str:
        if not parameters.strip():
            return ""
        values: list[str] = []
        current: list[str] = []
        generic_depth = 0
        for character in parameters:
            if character == "<":
                generic_depth += 1
            elif character == ">":
                generic_depth = max(0, generic_depth - 1)
            if character == "," and generic_depth == 0:
                values.append("".join(current))
                current = []
            else:
                current.append(character)
        values.append("".join(current))
        return "".join(cls._java_type_descriptor(value) for value in values)

    @staticmethod
    def _java_type_descriptor(declaration: str) -> str:
        cleaned = re.sub(r"@[A-Za-z_$][\w.$]*(?:\([^)]*\))?", "", declaration)
        cleaned = re.sub(r"\b(?:final|volatile|transient)\b", "", cleaned)
        cleaned = re.sub(r"<[^<>]*>", "", cleaned)
        parts = cleaned.strip().split()
        java_type = parts[0] if parts else "java.lang.Object"
        dimensions = java_type.count("[]") + (1 if java_type.endswith("...") else 0)
        java_type = java_type.replace("[]", "").removesuffix("...")
        primitive = {
            "boolean": "Z",
            "byte": "B",
            "char": "C",
            "short": "S",
            "int": "I",
            "long": "J",
            "float": "F",
            "double": "D",
        }.get(java_type)
        descriptor = primitive or f"L{java_type.replace('.', '/')};"
        return "[" * dimensions + descriptor

    @staticmethod
    def _smali_load_calls(text: str) -> list[dict[str, str]]:
        calls: list[dict[str, str]] = []
        pattern = re.compile(
            r"const-string\s+(?P<register>v\d+),\s*\"(?P<value>[^\"]+)\""
            r"(?:(?!const-string)[\s\S]){0,400}?"
            r"invoke-static\s+\{(?P=register)\},\s*Ljava/lang/System;->"
            r"(?P<method>loadLibrary|load)\(Ljava/lang/String;\)V"
        )
        for match in pattern.finditer(text):
            calls.append(
                {
                    "kind": "load_library" if match.group("method") == "loadLibrary" else "load_path",
                    "value": match.group("value"),
                }
            )
        return calls

    @classmethod
    def _build_graph(
        cls,
        *,
        artifact_id: str,
        package_name: str,
        libraries: list[dict[str, Any]],
        bridges: list[_JavaBridge],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        links: list[dict[str, Any]] = []
        library_nodes: dict[str, dict[str, Any]] = {}
        library_keys: dict[str, list[dict[str, Any]]] = {}
        for library in libraries:
            archive_path = str(library["archive_path"])
            node_id = f"native/{archive_path}"
            symbol_details = dict(library["symbols"])
            node = {
                "id": node_id,
                "path": library["extracted_path"],
                "kind": "native_library",
                "name": PurePosixPath(archive_path).name,
                "sha256": library["sha256"],
                "abi": library["abi"],
                "archive_path": archive_path,
                "summary_path": library["summary_path"],
                "elf": library["elf"],
                "dependencies": library["dependencies"],
                "symbols": {
                    "exported_count": symbol_details.get("exported_count", 0),
                    "imported_count": symbol_details.get("imported_count", 0),
                    "exported_sample": list(symbol_details.get("exported_sample") or [])[:20],
                    "imported_sample": list(symbol_details.get("imported_sample") or [])[:20],
                    "security_relevant": symbol_details.get("security_relevant") or [],
                },
                "jni": library["jni"],
                "hardening": library["hardening"],
            }
            nodes.append(node)
            library_nodes[node_id] = node
            basename = PurePosixPath(archive_path).name
            key = basename[3:-3] if basename.startswith("lib") and basename.endswith(".so") else basename
            library_keys.setdefault(key, []).append(node)
            library_keys.setdefault(basename, []).append(node)
            soname = str((library.get("elf") or {}).get("soname") or "")
            if soname:
                library_keys.setdefault(soname, []).append(node)
            edges.append(
                {
                    "from": artifact_id,
                    "to": node_id,
                    "relation": "contains_native_library",
                    "archive_path": archive_path,
                }
            )
        bridges = sorted(
            bridges,
            key=lambda bridge: (
                {"application": 0, "vendor": 1, "third_party": 2}.get(
                    cls._class_ownership(bridge.class_name, package_name),
                    3,
                ),
                bridge.class_name,
            ),
        )
        for bridge in bridges:
            ownership = cls._class_ownership(bridge.class_name, package_name)
            class_id = f"java/{bridge.class_name}"
            nodes.append(
                {
                    "id": class_id,
                    "path": bridge.source_path,
                    "kind": "java_native_bridge",
                    "name": bridge.class_name,
                    "class_name": bridge.class_name,
                    "ownership": ownership,
                    "loads": bridge.loads,
                    "native_method_count": len(bridge.methods),
                }
            )
            edges.append(
                {"from": artifact_id, "to": class_id, "relation": "declares_native_bridge"}
            )
            loaded_nodes: list[dict[str, Any]] = []
            for load in bridge.loads:
                value = str(load["value"])
                candidates = library_keys.get(value, [])
                if load["kind"] == "load_path":
                    candidates = library_keys.get(PurePosixPath(value).name, candidates)
                for library_node in cls._unique_nodes(candidates):
                    loaded_nodes.append(library_node)
                    edges.append(
                        {
                            "from": class_id,
                            "to": library_node["id"],
                            "relation": "loads_native_library",
                            "load_kind": load["kind"],
                            "load_value": value,
                        }
                    )
                    links.append(
                        {
                            "relation": "loads_native_library",
                            "class_name": bridge.class_name,
                            "ownership": ownership,
                            "source_path": bridge.source_path,
                            "library_id": library_node["id"],
                            "library_name": library_node["name"],
                            "abi": library_node["abi"],
                            "confidence": "high",
                        }
                    )
            loaded_nodes = cls._unique_nodes(loaded_nodes)
            search_nodes = loaded_nodes or list(library_nodes.values())
            overload_counts: dict[str, int] = {}
            for method in bridge.methods:
                name = str(method["name"])
                overload_counts[name] = overload_counts.get(name, 0) + 1
            for method in bridge.methods:
                method_name = str(method["name"])
                argument_descriptor = str(method.get("argument_descriptor") or "")
                signature_key = hashlib.sha256(
                    f"{method_name}:{argument_descriptor}".encode()
                ).hexdigest()[:10]
                expected = cls._jni_symbol_prefix(bridge.class_name, method_name)
                expected_long = (
                    f"{expected}__{cls._jni_mangle(argument_descriptor)}"
                    if argument_descriptor
                    else None
                )
                matched = False
                for library_node in search_nodes:
                    for symbol in library_node["jni"].get("exports") or []:
                        if overload_counts[method_name] > 1:
                            symbol_matches = expected_long is not None and symbol == expected_long
                        else:
                            symbol_matches = symbol == expected or (
                                expected_long is not None and symbol == expected_long
                            )
                        if not symbol_matches:
                            continue
                        matched = True
                        edges.append(
                            {
                                "from": class_id,
                                "to": library_node["id"],
                                "relation": "binds_to_jni",
                                "method_name": method_name,
                                "argument_descriptor": argument_descriptor,
                                "method_signature_key": signature_key,
                                "jni_symbol": symbol,
                                "confidence": "high",
                            }
                        )
                        links.append(
                            {
                                "relation": "binds_to_jni",
                                "class_name": bridge.class_name,
                                "ownership": ownership,
                                "method_name": method_name,
                                "source_path": bridge.source_path,
                                "jni_symbol": symbol,
                                "library_id": library_node["id"],
                                "library_name": library_node["name"],
                                "abi": library_node["abi"],
                                "confidence": "high",
                            }
                        )
                if matched:
                    continue
                for library_node in loaded_nodes:
                    if not library_node["jni"].get("dynamic_registration"):
                        continue
                    edges.append(
                        {
                            "from": class_id,
                            "to": library_node["id"],
                            "relation": "possible_dynamic_registration",
                            "method_name": method_name,
                            "argument_descriptor": argument_descriptor,
                            "method_signature_key": signature_key,
                            "jni_symbol": None,
                            "confidence": "medium",
                        }
                    )
                    links.append(
                        {
                            "relation": "possible_dynamic_registration",
                            "class_name": bridge.class_name,
                            "ownership": ownership,
                            "method_name": method_name,
                            "source_path": bridge.source_path,
                            "jni_symbol": None,
                            "library_id": library_node["id"],
                            "library_name": library_node["name"],
                            "abi": library_node["abi"],
                            "confidence": "medium",
                        }
                    )
        for node in nodes:
            if node.get("kind") != "native_library":
                continue
            jni = dict(node.get("jni") or {})
            jni.pop("exports", None)
            node["jni"] = jni
        return nodes, cls._dedupe_edges(edges), links

    @staticmethod
    def _class_ownership(class_name: str, package_name: str) -> str:
        if package_name and (
            class_name == package_name or class_name.startswith(f"{package_name}.")
        ):
            return "application"
        namespace = ".".join(package_name.split(".")[:2])
        if namespace and (
            class_name == namespace or class_name.startswith(f"{namespace}.")
        ):
            return "vendor"
        return "third_party"

    @staticmethod
    def _unique_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return list({str(node["id"]): node for node in nodes}.values())

    @staticmethod
    def _dedupe_edges(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
        unique: dict[str, dict[str, Any]] = {}
        for edge in edges:
            key = json.dumps(edge, sort_keys=True, separators=(",", ":"))
            unique[key] = edge
        return list(unique.values())

    @classmethod
    def _jni_symbol_prefix(cls, class_name: str, method_name: str) -> str:
        return f"Java_{cls._jni_mangle(class_name)}_{cls._jni_mangle(method_name)}"

    @staticmethod
    def _jni_mangle(value: str) -> str:
        output: list[str] = []
        for character in value:
            if character in {".", "/"}:
                output.append("_")
            elif character == "_":
                output.append("_1")
            elif character == ";":
                output.append("_2")
            elif character == "[":
                output.append("_3")
            elif character.isascii() and character.isalnum():
                output.append(character)
            else:
                output.append(f"_0{ord(character):04x}")
        return "".join(output)
