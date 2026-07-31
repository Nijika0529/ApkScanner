from __future__ import annotations

from collections import Counter
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import desc, select

from .capabilities import CapabilityRegistry
from .models import Scan
from .repository import add_event


class TestEntrySeed(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{2,63}$")
    kind: Literal["scan_clone", "capability"]
    scan_id: str | None = None
    capability_id: str | None = None
    input: dict[str, Any] = Field(default_factory=dict)
    depends_on: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_target(self) -> TestEntrySeed:
        if self.kind == "scan_clone" and not self.scan_id:
            raise ValueError("scan_clone requires scan_id")
        if self.kind == "capability" and not self.capability_id:
            raise ValueError("capability entry requires capability_id")
        return self


class CampaignPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    name: str = Field(min_length=1, max_length=256)
    entries: list[TestEntrySeed] = Field(min_length=1, max_length=64)
    max_parallel_scans: int = Field(default=1, ge=1, le=8)
    total_budget_seconds: int = Field(default=86_400, ge=60, le=7 * 86_400)

    @model_validator(mode="after")
    def validate_graph(self) -> CampaignPlan:
        ids = [entry.id for entry in self.entries]
        if len(ids) != len(set(ids)):
            raise ValueError("campaign entry IDs must be unique")
        known = set(ids)
        graph = {entry.id: set(entry.depends_on) for entry in self.entries}
        for entry_id, dependencies in graph.items():
            if entry_id in dependencies or not dependencies <= known:
                raise ValueError("campaign dependencies are invalid")
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node: str) -> None:
            if node in visiting:
                raise ValueError("campaign dependencies contain a cycle")
            if node in visited:
                return
            visiting.add(node)
            for dependency in graph[node]:
                visit(dependency)
            visiting.remove(node)
            visited.add(node)

        for node in graph:
            visit(node)
        return self


class SupervisorService:
    """Narrow control plane intended for a future platform-monitoring Agent."""

    def __init__(self, orchestrator, registry: CapabilityRegistry) -> None:  # noqa: ANN001
        self.orchestrator = orchestrator
        self.registry = registry

    def snapshot(self) -> dict[str, Any]:
        with self.orchestrator.database.session_factory() as session:
            scans = list(session.scalars(select(Scan).order_by(desc(Scan.created_at)).limit(100)))
        statuses = Counter(scan.status for scan in scans)
        return {
            "schema_version": "1.0",
            "scans": {
                "status_counts": dict(statuses),
                "latest": [
                    {
                        "id": scan.id,
                        "filename": scan.filename,
                        "package_name": scan.package_name,
                        "status": scan.status,
                        "updated_at": scan.updated_at.isoformat(),
                    }
                    for scan in scans[:20]
                ],
            },
            "devices": self.orchestrator.device_pool.snapshot(),
            "codex": {
                "containers": self.orchestrator.codex.executor.snapshot(),
            },
            "capabilities": self.registry.catalog(),
        }

    def validate_plan(self, plan: CampaignPlan) -> dict[str, Any]:
        errors: list[dict[str, str]] = []
        catalog = {item["id"]: item for item in self.registry.catalog()}
        with self.orchestrator.database.session_factory() as session:
            for entry in plan.entries:
                if entry.kind == "scan_clone" and session.get(Scan, entry.scan_id) is None:
                    errors.append({"entry_id": entry.id, "detail": "source scan does not exist"})
                if entry.kind == "capability":
                    capability = catalog.get(entry.capability_id or "")
                    if capability is None:
                        errors.append({"entry_id": entry.id, "detail": "capability is unknown"})
                    elif not capability["available"]:
                        errors.append({"entry_id": entry.id, "detail": "capability is unavailable"})
        return {"valid": not errors, "errors": errors, "entry_count": len(plan.entries)}

    def launch(self, plan: CampaignPlan) -> dict[str, Any]:
        validation = self.validate_plan(plan)
        if not validation["valid"]:
            raise ValueError("campaign plan is not executable")
        scan_ids: list[str] = []
        capability_results: list[dict[str, Any]] = []
        with self.orchestrator.database.session_factory() as session:
            for entry in plan.entries:
                if entry.kind == "capability":
                    capability_results.append(
                        self.registry.invoke(entry.capability_id or "", entry.input).model_dump(
                            mode="json"
                        )
                    )
                    continue
                source = session.get(Scan, entry.scan_id)
                assert source is not None
                clone = Scan(
                    filename=source.filename,
                    artifact_sha256=source.artifact_sha256,
                    artifact_path=source.artifact_path,
                    stats={
                        "upload_bytes": (source.stats or {}).get("upload_bytes"),
                        "investigator": self.orchestrator.resolve_investigator(),
                        "campaign": {
                            "name": plan.name,
                            "entry_id": entry.id,
                            "source_scan_id": source.id,
                            "total_budget_seconds": plan.total_budget_seconds,
                        },
                    },
                )
                session.add(clone)
                session.flush()
                add_event(
                    session,
                    clone.id,
                    "campaign.entry.created",
                    "监督控制面已生成隔离扫描入口",
                    {"campaign": plan.name, "entry_id": entry.id, "source_scan_id": source.id},
                )
                scan_ids.append(clone.id)
            session.commit()
        return {
            "campaign": plan.name,
            "scan_ids": scan_ids,
            "capability_results": capability_results,
            "max_parallel_scans": plan.max_parallel_scans,
        }
