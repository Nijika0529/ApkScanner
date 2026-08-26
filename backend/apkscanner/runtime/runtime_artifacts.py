from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from sqlalchemy import select

from ..analysis.static_analysis import ApkInspector
from ..core.config import Settings
from ..core.db import Database
from ..core.enums import CoverageStatus, EntryPointKind, ScanStatus
from ..core.evidence import EvidenceRecorder
from ..core.models import CoverageItem, EntryPoint, RuntimeArtifact, Scan
from ..core.permissions import ensure_private_directory, ensure_private_file
from ..core.repository import add_event
from ..core.schemas import RuntimeArtifactCaptureRequest
from ..platform.artifacts import ArtifactStore
from ..platform.tools import CommandResult
from .device import AdbDeviceAdapter, AdbDevicePool
from .planner import InvestigationPlanner


def _now() -> datetime:
    return datetime.now(UTC)


class RuntimeArtifactService:
    """Collect a device-created plugin APK and attach its analysis to its host scan."""

    def __init__(
        self,
        settings: Settings,
        database: Database,
        store: ArtifactStore,
        inspector: ApkInspector,
        evidence: EvidenceRecorder,
        device_pool: AdbDevicePool,
    ) -> None:
        self.settings = settings
        self.database = database
        self.store = store
        self.inspector = inspector
        self.evidence = evidence
        self.device_pool = device_pool
        self._graph_lock = threading.Lock()

    def capture(
        self,
        runtime_artifact_id: str,
        request: RuntimeArtifactCaptureRequest,
    ) -> RuntimeArtifact:
        capture_root = self.settings.data_dir / "runtime-captures"
        ensure_private_directory(capture_root)
        cancel_event = threading.Event()
        with tempfile.TemporaryDirectory(prefix="capture-", dir=capture_root) as temporary:
            local_apk = Path(temporary) / "runtime-plugin.apk"
            with self.device_pool.task_lease(
                f"runtime-artifact:{runtime_artifact_id}",
                priority=105,
                cancel_event=cancel_event,
                preferred_serial=request.preferred_serial,
            ) as lease:
                adapter = lease["device"]
                assert isinstance(adapter, AdbDeviceAdapter)
                self._mark_status(
                    runtime_artifact_id,
                    "capturing",
                    {"device_serial": adapter.serial},
                )
                if request.source_mode == "run_as":
                    assert request.package_name is not None
                    command_result = self._capture_run_as(
                        adapter,
                        request.package_name,
                        request.remote_path,
                        local_apk,
                    )
                else:
                    command_result = adapter.execute_gateway(
                        ["pull", request.remote_path, str(local_apk)],
                        timeout=120,
                        policy="adaptive",
                    )
                self._record_capture_command(runtime_artifact_id, command_result)
                if command_result.exit_code != 0 or not local_apk.is_file():
                    detail = command_result.stderr.strip() or command_result.stdout.strip()
                    raise RuntimeError(detail or "runtime artifact capture failed")
                ensure_private_file(local_apk)
            if local_apk.stat().st_size > self.settings.max_upload_bytes:
                raise ValueError("runtime plugin APK exceeds the configured artifact size limit")
            sha256, stored_path, size_bytes = self.store.put_file(
                "artifacts",
                local_apk,
                suffix=".apk",
            )
            self._mark_captured(
                runtime_artifact_id,
                sha256=sha256,
                stored_path=stored_path,
                size_bytes=size_bytes,
            )
            reused = self._reuse_existing_analysis(runtime_artifact_id, request)
            if reused is not None:
                return reused
            return self._analyze(runtime_artifact_id, request)

    def mark_failed(self, runtime_artifact_id: str, error: str) -> None:
        with self.database.session_factory() as session:
            artifact = session.get(RuntimeArtifact, runtime_artifact_id)
            if artifact is None:
                return
            artifact.status = "failed"
            artifact.error = error
            artifact.completed_at = _now()
            add_event(
                session,
                artifact.scan_id,
                "runtime_artifact.failed",
                "运行时插件采集或分析失败",
                {"runtime_artifact_id": artifact.id, "error": error},
            )
            session.commit()

    def get(self, runtime_artifact_id: str) -> RuntimeArtifact:
        with self.database.session_factory() as session:
            artifact = session.get(RuntimeArtifact, runtime_artifact_id)
            if artifact is None:
                raise LookupError(runtime_artifact_id)
            session.expunge(artifact)
            return artifact

    def _capture_run_as(
        self,
        adapter: AdbDeviceAdapter,
        package_name: str,
        remote_path: str,
        destination: Path,
    ) -> CommandResult:
        if not adapter.package_safe(package_name):
            raise ValueError("run-as package name is invalid")
        normalized = PurePosixPath(remote_path)
        if normalized.is_absolute() or ".." in normalized.parts or not normalized.parts:
            raise ValueError("run-as artifact path must be relative to the application data root")
        executable = shutil.which(self.settings.host_adb_executable)
        if executable is None:
            return CommandResult(
                argv=["adb", "exec-out", "run-as", package_name, "cat", remote_path],
                exit_code=127,
                stdout="",
                stderr="host adb executable is unavailable",
            )
        argv = [
            executable,
            "-s",
            str(adapter.serial),
            "exec-out",
            "run-as",
            package_name,
            "cat",
            str(normalized),
        ]
        reported = ["adb", "exec-out", "run-as", package_name, "cat", str(normalized)]
        with destination.open("wb") as output:
            process = subprocess.Popen(
                argv,
                stdout=output,
                stderr=subprocess.PIPE,
            )
            try:
                _stdout, stderr = process.communicate(timeout=120)
            except subprocess.TimeoutExpired:
                process.kill()
                _stdout, stderr = process.communicate()
                return CommandResult(
                    argv=reported,
                    exit_code=124,
                    stdout="",
                    stderr=(stderr or b"").decode(errors="replace"),
                    timed_out=True,
                )
        return CommandResult(
            argv=reported,
            exit_code=process.returncode,
            stdout=(
                f"captured {destination.stat().st_size} bytes"
                if process.returncode == 0 and destination.exists()
                else ""
            ),
            stderr=(stderr or b"").decode(errors="replace"),
        )

    def _record_capture_command(
        self,
        runtime_artifact_id: str,
        result: CommandResult,
    ) -> None:
        with self.database.session_factory() as session:
            artifact = session.get(RuntimeArtifact, runtime_artifact_id)
            assert artifact is not None
            evidence = self.evidence.command(
                session,
                scan_id=artifact.scan_id,
                task_id=artifact.task_id,
                kind="runtime_artifact.capture",
                result=result,
                metadata={"runtime_artifact_id": artifact.id},
            )
            artifact.result_json = {
                **dict(artifact.result_json or {}),
                "capture_evidence_id": evidence.id,
            }
            session.commit()

    def _mark_status(
        self,
        runtime_artifact_id: str,
        status: str,
        result: dict[str, Any] | None = None,
    ) -> None:
        with self.database.session_factory() as session:
            artifact = session.get(RuntimeArtifact, runtime_artifact_id)
            if artifact is None:
                raise LookupError(runtime_artifact_id)
            artifact.status = status
            artifact.error = None
            if result:
                artifact.result_json = {**dict(artifact.result_json or {}), **result}
            session.commit()

    def _mark_captured(
        self,
        runtime_artifact_id: str,
        *,
        sha256: str,
        stored_path: Path,
        size_bytes: int,
    ) -> None:
        with self.database.session_factory() as session:
            artifact = session.get(RuntimeArtifact, runtime_artifact_id)
            assert artifact is not None
            artifact.status = "analyzing"
            artifact.sha256 = sha256
            artifact.stored_path = str(stored_path)
            artifact.size_bytes = size_bytes
            add_event(
                session,
                artifact.scan_id,
                "runtime_artifact.captured",
                "已从设备采集运行时插件并写入内容寻址存储",
                {
                    "runtime_artifact_id": artifact.id,
                    "sha256": sha256,
                    "size_bytes": size_bytes,
                },
            )
            session.commit()

    def _analyze(
        self,
        runtime_artifact_id: str,
        request: RuntimeArtifactCaptureRequest,
    ) -> RuntimeArtifact:
        with self.database.session_factory() as session:
            artifact = session.get(RuntimeArtifact, runtime_artifact_id)
            assert artifact is not None and artifact.sha256 is not None
            scan = session.get(Scan, artifact.scan_id)
            if scan is None:
                raise LookupError(artifact.scan_id)
            scan_workspace_value = (scan.stats or {}).get("workspace")
            if not isinstance(scan_workspace_value, str):
                raise ValueError("host scan static workspace is unavailable")
            scan_workspace = Path(scan_workspace_value)
            graph_path = scan_workspace / "artifact_graph.json"
            if not graph_path.is_file():
                raise ValueError("host scan artifact graph is unavailable")
            stored_path = self.store.verify_content_addressed(
                "artifacts",
                artifact.stored_path,
                artifact.sha256,
            )
            child_workspace = scan_workspace / "runtime-artifacts" / artifact.sha256
            ensure_private_directory(child_workspace)
            scan_id = scan.id
            source_label = str((artifact.source_json or {}).get("remote_path") or "runtime.apk")

        result = self.inspector.inspect(
            stored_path,
            scan_id,
            _workspace=child_workspace,
            _artifact_origin=f"runtime:{source_label}",
        )
        graph = dict(result.artifact_graph)
        root_id = str(graph["root_id"])
        plugin_entries = self.inspector._embedded_plugin_entries(
            workspace=child_workspace,
            analysis_root=child_workspace,
            graph_analysis_root=".",
            child_root_id=root_id,
            package_name=result.manifest.package_name,
            application_class=result.manifest.application.get("name"),
        )
        for node in plugin_entries:
            graph["nodes"].append(node)
            graph["edges"].append(
                {
                    "from": root_id,
                    "to": node["id"],
                    "relation": "declares_plugin_entry",
                    "confidence": node["confidence"],
                }
            )
        prefix = f"runtime-artifacts/{self._require_sha(runtime_artifact_id)}"
        rebased = self.inspector._rebase_artifact_graph(graph, prefix)
        runtime_root_id = str(rebased["root_id"])
        runtime_root = next(
            node for node in rebased["nodes"] if str(node.get("id")) == runtime_root_id
        )
        runtime_root["origin"] = {
            "kind": "runtime_plugin",
            "capture_id": runtime_artifact_id,
            "source_mode": request.source_mode,
            "remote_path": request.remote_path,
        }
        rebased_plugin_ids = [
            str(node["id"])
            for node in rebased["nodes"]
            if node.get("kind") == "embedded_plugin_entry"
        ]
        loader_id = self._merge_graph(
            graph_path=scan_workspace / "artifact_graph.json",
            child_graph=rebased,
            runtime_root_id=runtime_root_id,
            plugin_entry_ids=rebased_plugin_ids,
            request=request,
            runtime_artifact_id=runtime_artifact_id,
        )
        entry_ids, task_ids = self._persist_entries_and_tasks(
            runtime_artifact_id=runtime_artifact_id,
            result=result,
            plugin_nodes=plugin_entries,
            request=request,
            graph_node_id=runtime_root_id,
            loader_node_id=loader_id,
        )
        with self.database.session_factory() as session:
            artifact = session.get(RuntimeArtifact, runtime_artifact_id)
            assert artifact is not None
            artifact.status = "completed"
            artifact.package_name = result.manifest.package_name
            artifact.version_name = result.manifest.version_name
            artifact.version_code = result.manifest.version_code
            artifact.graph_node_id = runtime_root_id
            artifact.entry_point_ids = entry_ids
            artifact.investigation_task_ids = task_ids
            artifact.result_json = {
                **dict(artifact.result_json or {}),
                "analysis_workspace": str(result.workspace),
                "static_cache_hit": bool(result.decompilation.get("cache_hit")),
                "loader_node_id": loader_id,
                "plugin_entry_node_ids": rebased_plugin_ids,
                "artifact_graph_path": str(scan_workspace / "artifact_graph.json"),
                "schedule_investigations": request.schedule_investigations,
            }
            artifact.completed_at = _now()
            artifact.error = None
            add_event(
                session,
                artifact.scan_id,
                "runtime_artifact.completed",
                "运行时插件已完成静态分析并关联到宿主资产图谱",
                {
                    "runtime_artifact_id": artifact.id,
                    "sha256": artifact.sha256,
                    "entry_point_ids": entry_ids,
                    "investigation_task_ids": task_ids,
                },
            )
            session.commit()
            session.refresh(artifact)
            session.expunge(artifact)
            return artifact

    def _reuse_existing_analysis(
        self,
        runtime_artifact_id: str,
        request: RuntimeArtifactCaptureRequest,
    ) -> RuntimeArtifact | None:
        """Reuse one plugin analysis while retaining a newly observed loader edge."""

        with self.database.session_factory() as session:
            artifact = session.get(RuntimeArtifact, runtime_artifact_id)
            assert artifact is not None and artifact.sha256 is not None
            prior = session.scalar(
                select(RuntimeArtifact)
                .where(
                    RuntimeArtifact.scan_id == artifact.scan_id,
                    RuntimeArtifact.sha256 == artifact.sha256,
                    RuntimeArtifact.status == "completed",
                    RuntimeArtifact.id != artifact.id,
                )
                .order_by(RuntimeArtifact.completed_at)
            )
            if prior is None or prior.graph_node_id is None:
                return None
            scan = session.get(Scan, artifact.scan_id)
            assert scan is not None
            workspace = (scan.stats or {}).get("workspace")
            if not isinstance(workspace, str):
                return None
            prior_result = dict(prior.result_json or {})
            plugin_entry_ids = [
                str(value) for value in prior_result.get("plugin_entry_node_ids", [])
            ]
            prior_id = prior.id
            prior_root_id = prior.graph_node_id
            prior_entry_ids = list(prior.entry_point_ids or [])
            prior_task_ids = list(prior.investigation_task_ids or [])
            prior_package_name = prior.package_name
            prior_version_name = prior.version_name
            prior_version_code = prior.version_code
            prior_workspace = prior_result.get("analysis_workspace")

        loader_id = self._merge_graph(
            graph_path=Path(workspace) / "artifact_graph.json",
            child_graph={"nodes": [], "edges": []},
            runtime_root_id=prior_root_id,
            plugin_entry_ids=plugin_entry_ids,
            request=request,
            runtime_artifact_id=runtime_artifact_id,
        )
        with self.database.session_factory() as session:
            artifact = session.get(RuntimeArtifact, runtime_artifact_id)
            assert artifact is not None
            artifact.status = "completed"
            artifact.package_name = prior_package_name
            artifact.version_name = prior_version_name
            artifact.version_code = prior_version_code
            artifact.graph_node_id = prior_root_id
            artifact.entry_point_ids = prior_entry_ids
            artifact.investigation_task_ids = prior_task_ids
            artifact.result_json = {
                **dict(artifact.result_json or {}),
                "analysis_workspace": prior_workspace,
                "static_cache_hit": True,
                "analysis_reused_from_runtime_artifact_id": prior_id,
                "loader_node_id": loader_id,
                "plugin_entry_node_ids": plugin_entry_ids,
                "artifact_graph_path": str(Path(workspace) / "artifact_graph.json"),
                "schedule_investigations": request.schedule_investigations,
            }
            artifact.completed_at = _now()
            artifact.error = None
            add_event(
                session,
                artifact.scan_id,
                "runtime_artifact.reused",
                "运行时插件内容未变化，已复用静态结果和既有调查任务",
                {
                    "runtime_artifact_id": artifact.id,
                    "reused_from": prior_id,
                    "sha256": artifact.sha256,
                },
            )
            session.commit()
            session.refresh(artifact)
            session.expunge(artifact)
            return artifact

    def _require_sha(self, runtime_artifact_id: str) -> str:
        with self.database.session_factory() as session:
            value = session.scalar(
                select(RuntimeArtifact.sha256).where(RuntimeArtifact.id == runtime_artifact_id)
            )
            if not isinstance(value, str):
                raise ValueError("runtime artifact digest is unavailable")
            return value

    def _merge_graph(
        self,
        *,
        graph_path: Path,
        child_graph: dict[str, Any],
        runtime_root_id: str,
        plugin_entry_ids: list[str],
        request: RuntimeArtifactCaptureRequest,
        runtime_artifact_id: str,
    ) -> str:
        with self._graph_lock:
            graph = json.loads(graph_path.read_text(encoding="utf-8"))
            node_by_id = {str(node.get("id")): node for node in graph.get("nodes", [])}
            for node in child_graph.get("nodes", []):
                node_id = str(node.get("id"))
                if node_id not in node_by_id:
                    graph.setdefault("nodes", []).append(node)
                    node_by_id[node_id] = node
            known_edges = {
                (str(edge.get("from")), str(edge.get("to")), str(edge.get("relation")))
                for edge in graph.get("edges", [])
            }
            for edge in child_graph.get("edges", []):
                key = (
                    str(edge.get("from")),
                    str(edge.get("to")),
                    str(edge.get("relation")),
                )
                if key not in known_edges:
                    graph.setdefault("edges", []).append(edge)
                    known_edges.add(key)

            loader_id = self._resolve_loader_node(graph, request)
            if loader_id is None and request.loader_anchor:
                anchor_payload = json.dumps(request.loader_anchor, sort_keys=True)
                loader_id = "runtime-loaders/" + hashlib.sha256(
                    f"{runtime_artifact_id}:{anchor_payload}".encode()
                ).hexdigest()[:16]
                graph["nodes"].append(
                    {
                        "id": loader_id,
                        "path": str(request.loader_anchor.get("path") or "runtime"),
                        "kind": "runtime_plugin_loader_reference",
                        "name": str(
                            request.loader_anchor.get("name")
                            or PurePosixPath(request.remote_path).name
                        ),
                        "references": [request.loader_anchor],
                    }
                )
                root_id = str(graph.get("root_id") or "target.apk")
                graph["edges"].append(
                    {
                        "from": root_id,
                        "to": loader_id,
                        "relation": "declares_runtime_plugin_loader",
                    }
                )
            source_id = loader_id or str(graph.get("root_id") or "target.apk")
            relation = "loads_runtime_apk" if loader_id else "acquires_runtime_apk"
            runtime_edge = (source_id, runtime_root_id, relation)
            if runtime_edge not in known_edges:
                graph["edges"].append(
                    {
                        "from": source_id,
                        "to": runtime_root_id,
                        "relation": relation,
                        "capture_id": runtime_artifact_id,
                        "confidence": "high",
                    }
                )
            for plugin_entry_id in plugin_entry_ids:
                key = (source_id, plugin_entry_id, "may_invoke_plugin_entry")
                if key not in known_edges:
                    graph["edges"].append(
                        {
                            "from": source_id,
                            "to": plugin_entry_id,
                            "relation": "may_invoke_plugin_entry",
                            "capture_id": runtime_artifact_id,
                            "confidence": "medium",
                        }
                    )
            graph["schema_version"] = "1.3"
            graph["summary"] = self.inspector._artifact_graph_summary(graph)
            temporary = graph_path.with_suffix(".json.runtime.tmp")
            temporary.write_text(
                json.dumps(graph, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            temporary.replace(graph_path)
            return source_id

    @staticmethod
    def _resolve_loader_node(
        graph: dict[str, Any],
        request: RuntimeArtifactCaptureRequest,
    ) -> str | None:
        nodes = list(graph.get("nodes") or [])
        by_id = {str(node.get("id")): node for node in nodes}
        if request.loader_node_id is not None:
            if request.loader_node_id not in by_id:
                raise ValueError("declared runtime loader node does not exist in the host graph")
            return request.loader_node_id
        basename = PurePosixPath(request.remote_path).name.lower()
        for node in nodes:
            if node.get("kind") not in {
                "plugin_loader_reference",
                "runtime_plugin_loader_reference",
            }:
                continue
            values = {
                str(node.get("name") or "").lower(),
                PurePosixPath(str(node.get("archive_path") or "")).name.lower(),
            }
            if basename and basename in values:
                return str(node["id"])
        return None

    def _persist_entries_and_tasks(
        self,
        *,
        runtime_artifact_id: str,
        result: Any,
        plugin_nodes: list[dict[str, Any]],
        request: RuntimeArtifactCaptureRequest,
        graph_node_id: str,
        loader_node_id: str,
    ) -> tuple[list[str], list[str]]:
        with self.database.session_factory() as session:
            artifact = session.get(RuntimeArtifact, runtime_artifact_id)
            assert artifact is not None and artifact.sha256 is not None
            scan = session.get(Scan, artifact.scan_id)
            assert scan is not None
            existing = list(
                session.scalars(
                    select(EntryPoint).where(EntryPoint.scan_id == scan.id)
                )
            )
            existing_by_key = {
                (
                    str((entry.metadata_json or {}).get("runtime_artifact_sha256") or ""),
                    entry.kind,
                    entry.name,
                ): entry
                for entry in existing
            }
            entries: list[EntryPoint] = []
            for parsed in result.manifest.entries:
                key = (artifact.sha256, parsed.kind, parsed.name)
                entry = existing_by_key.get(key)
                if entry is None:
                    code_context = result.code_index.get(
                        parsed.owner_component or parsed.name,
                        {},
                    )
                    entry = EntryPoint(
                        scan_id=scan.id,
                        kind=parsed.kind,
                        name=parsed.name,
                        owner_component=parsed.owner_component,
                        exported=parsed.exported,
                        exported_reason=parsed.exported_reason,
                        permission=parsed.permission,
                        permission_protection=parsed.permission_protection,
                        intent_filters=parsed.intent_filters,
                        deep_links=parsed.deep_links,
                        code_anchors=[
                            {key: value for key, value in anchor.items() if key != "content"}
                            for anchor in code_context.get("anchors", [])
                            if isinstance(anchor, dict)
                        ],
                        metadata_json={
                            **parsed.metadata,
                            "runtime_artifact_id": artifact.id,
                            "runtime_artifact_sha256": artifact.sha256,
                            "artifact_graph_node_id": graph_node_id,
                            "host_loader_node_id": loader_node_id,
                        },
                    )
                    session.add(entry)
                entries.append(entry)
            for node in plugin_nodes:
                name = str(node.get("name") or node.get("class_name") or "plugin-entry")
                key = (artifact.sha256, EntryPointKind.STATIC_SURFACE.value, name)
                entry = existing_by_key.get(key)
                if entry is None:
                    entry = EntryPoint(
                        scan_id=scan.id,
                        kind=EntryPointKind.STATIC_SURFACE.value,
                        name=name,
                        owner_component=name,
                        exported=False,
                        exported_reason="runtime_plugin_entry",
                        permission=None,
                        permission_protection=None,
                        intent_filters=[],
                        deep_links=[],
                        code_anchors=[
                            {
                                "path": node.get("source_path"),
                                "line": node.get("line"),
                                "artifact": graph_node_id,
                            }
                        ],
                        metadata_json={
                            "runtime_artifact_id": artifact.id,
                            "runtime_artifact_sha256": artifact.sha256,
                            "artifact_graph_node_id": graph_node_id,
                            "host_loader_node_id": loader_node_id,
                            "static_review_family": "runtime_plugin",
                            "static_review_priority": 96,
                            "static_review_hypotheses": [
                                "The host can invoke this runtime plugin entry with its own identity.",
                                "Attacker-controlled host input can reach a sensitive plugin operation.",
                            ],
                            "plugin_entry_evidence": list(node.get("evidence") or []),
                        },
                    )
                    session.add(entry)
                entries.append(entry)
            session.flush()

            task_ids: list[str] = []
            if request.schedule_investigations and entries:
                planner = InvestigationPlanner(
                    android_version=self.settings.device_android_version,
                    android_api=self.settings.device_android_api,
                    adb_configured=self.device_pool.configured,
                    device_reset_policy=self.settings.device_reset_policy,
                )
                plan = planner.plan_with_decisions(scan.id, entries)
                for task in plan.tasks:
                    task.result = {
                        **dict(task.result or {}),
                        "runtime_artifact_id": artifact.id,
                        "runtime_artifact_sha256": artifact.sha256,
                    }
                    session.add(task)
                session.flush()
                task_ids = [task.id for task in plan.tasks]
                if task_ids:
                    scan.status = ScanStatus.INVESTIGATING.value
                    scan.completed_at = None
            existing_coverage_ids = set(
                session.scalars(
                    select(CoverageItem.entry_point_id).where(
                        CoverageItem.scan_id == scan.id,
                        CoverageItem.entry_point_id.in_([entry.id for entry in entries]),
                    )
                )
            )
            for entry in entries:
                if entry.id in existing_coverage_ids:
                    continue
                session.add(
                    CoverageItem(
                        scan_id=scan.id,
                        control_id=f"ENTRY-{entry.id}",
                        domain="MASVS-PLATFORM",
                        title=f"Runtime plugin entry: {entry.name}",
                        status=CoverageStatus.PARTIAL.value,
                        stages={
                            "static": "completed",
                            "agent": "pending" if request.schedule_investigations else "not_scheduled",
                            "blackbox": "pending",
                        },
                        gap_reason="Runtime plugin investigation pending.",
                        entry_point_id=entry.id,
                    )
                )
            session.commit()
            return [entry.id for entry in entries], task_ids
