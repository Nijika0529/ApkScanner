from __future__ import annotations

import json

from apkscanner.artifacts import ArtifactStore
from apkscanner.db import Database
from apkscanner.device import AdbDevicePool
from apkscanner.evidence import EvidenceRecorder
from apkscanner.models import RuntimeArtifact, Scan
from apkscanner.runtime_artifacts import RuntimeArtifactService
from apkscanner.schemas import RuntimeArtifactCaptureRequest
from apkscanner.static_analysis import ApkInspector


def test_runtime_artifact_reuses_analysis_and_only_adds_a_new_loader_edge(
    settings,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    inspector = ApkInspector(settings)
    service = RuntimeArtifactService(
        settings,
        database,
        store,
        inspector,
        EvidenceRecorder(store),
        AdbDevicePool([]),
    )
    workspace = settings.data_dir / "workspaces" / "runtime-reuse"
    workspace.mkdir(parents=True)
    runtime_root = "runtime-artifacts/" + "a" * 64 + "/artifact.apk"
    graph_path = workspace / "artifact_graph.json"
    graph_path.write_text(
        json.dumps(
            {
                "schema_version": "1.2",
                "root_id": "target.apk",
                "nodes": [
                    {"id": "target.apk", "path": "target.apk", "kind": "apk"},
                    {"id": runtime_root, "path": runtime_root, "kind": "apk"},
                ],
                "edges": [],
                "summary": {"apk_count": 2},
            }
        ),
        encoding="utf-8",
    )
    with database.session_factory() as session:
        scan = Scan(
            filename="host.apk",
            artifact_sha256="b" * 64,
            artifact_path="host.apk",
            stats={"workspace": str(workspace)},
        )
        session.add(scan)
        session.flush()
        prior = RuntimeArtifact(
            scan_id=scan.id,
            status="completed",
            sha256="a" * 64,
            graph_node_id=runtime_root,
            package_name="com.example.plugin",
            entry_point_ids=["entry-1"],
            investigation_task_ids=["task-1"],
            result_json={
                "analysis_workspace": str(workspace / "runtime-artifacts" / ("a" * 64)),
                "plugin_entry_node_ids": [],
            },
        )
        current = RuntimeArtifact(
            scan_id=scan.id,
            status="analyzing",
            sha256="a" * 64,
        )
        session.add_all([prior, current])
        session.commit()
        current_id = current.id
        prior_id = prior.id

    reused = service._reuse_existing_analysis(
        current_id,
        RuntimeArtifactCaptureRequest(
            source_mode="device_path",
            remote_path="/data/local/tmp/plugin.apk",
            loader_anchor={"name": "Zeus loader", "path": "jadx/Zeus.java", "line": 42},
        ),
    )
    assert reused is not None
    assert reused.status == "completed"
    assert reused.investigation_task_ids == ["task-1"]
    assert reused.result_json["analysis_reused_from_runtime_artifact_id"] == prior_id
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    assert sum(
        edge.get("relation") == "loads_runtime_apk" and edge.get("to") == runtime_root
        for edge in graph["edges"]
    ) == 1
