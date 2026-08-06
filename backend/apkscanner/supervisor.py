from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import desc, select

from .capabilities import CapabilityRegistry
from .models import CampaignEntryRecord, CampaignRun, InvestigationTask, Scan
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
    goal: str = Field(default="", max_length=8_000)
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


class CampaignAppendRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entries: list[TestEntrySeed] = Field(min_length=1, max_length=64)


class SupervisorService:
    """Persistent first-party control loop for goal-directed platform campaigns."""

    def __init__(self, orchestrator, registry: CapabilityRegistry) -> None:  # noqa: ANN001
        self.orchestrator = orchestrator
        self.registry = registry

    def snapshot(self) -> dict[str, Any]:
        with self.orchestrator.database.session_factory() as session:
            scans = list(session.scalars(select(Scan).order_by(desc(Scan.created_at)).limit(100)))
            campaigns = list(
                session.scalars(
                    select(CampaignRun).order_by(desc(CampaignRun.created_at)).limit(20)
                )
            )
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
            "campaigns": [self._campaign_payload(item.id) for item in campaigns],
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
        with self.orchestrator.database.session_factory() as session:
            campaign = CampaignRun(
                name=plan.name,
                goal=plan.goal or plan.name,
                status="running",
                plan_json=plan.model_dump(mode="json"),
                max_parallel_scans=plan.max_parallel_scans,
                total_budget_seconds=plan.total_budget_seconds,
            )
            session.add(campaign)
            session.flush()
            for entry in plan.entries:
                session.add(
                    CampaignEntryRecord(
                        campaign_id=campaign.id,
                        entry_key=entry.id,
                        kind=entry.kind,
                        status="pending",
                        depends_on=list(entry.depends_on),
                        source_scan_id=entry.scan_id,
                        capability_id=entry.capability_id,
                        input_json=entry.input,
                    )
                )
            session.commit()
            campaign_id = campaign.id
        advanced = self.advance(campaign_id)
        return {**advanced, "campaign": plan.name, "campaign_id": campaign_id}

    def advance_all(self) -> list[str]:
        """Reconcile every active campaign and return newly launched scan IDs."""

        with self.orchestrator.database.session_factory() as session:
            campaign_ids = list(
                session.scalars(
                    select(CampaignRun.id).where(
                        CampaignRun.status.in_({"running", "canceling", "timed_out"}),
                        CampaignRun.completed_at.is_(None),
                    )
                )
            )
        launched: list[str] = []
        for campaign_id in campaign_ids:
            launched.extend(self.advance(campaign_id)["scan_ids"])
        return launched

    def advance(self, campaign_id: str) -> dict[str, Any]:
        """Advance ready DAG nodes while honoring dependencies, cancellation, and budget."""

        scan_ids: list[str] = []
        capability_results: list[dict[str, Any]] = []
        now_value = datetime.now(UTC)
        with self.orchestrator.database.session_factory() as session:
            campaign = session.get(CampaignRun, campaign_id)
            if campaign is None:
                raise LookupError("campaign does not exist")
            entries = list(
                session.scalars(
                    select(CampaignEntryRecord)
                    .where(CampaignEntryRecord.campaign_id == campaign_id)
                    .order_by(CampaignEntryRecord.created_at)
                )
            )
            by_key = {entry.entry_key: entry for entry in entries}
            started_at = campaign.started_at
            if started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=UTC)
            deadline = started_at + timedelta(seconds=campaign.total_budget_seconds)
            if now_value >= deadline and campaign.status not in {"completed", "failed", "canceled"}:
                campaign.status = "timed_out"
                campaign.cancel_requested = True
            if campaign.cancel_requested:
                if campaign.status != "timed_out":
                    campaign.status = "canceling"
                for entry in entries:
                    if entry.status in {"pending", "blocked"}:
                        entry.status = "canceled"
                        entry.completed_at = now_value
            for entry in entries:
                if entry.status != "running" or entry.launched_scan_id is None:
                    continue
                scan = session.get(Scan, entry.launched_scan_id)
                if scan is None or scan.status == "failed":
                    entry.status = "failed"
                    entry.error = "launched scan failed or disappeared"
                    entry.completed_at = now_value
                elif scan.status == "final":
                    entry.status = "completed"
                    entry.result_json = {"scan_id": scan.id, "scan_status": scan.status}
                    entry.completed_at = now_value
            for entry in entries:
                if entry.status != "pending":
                    continue
                dependencies = [by_key[value] for value in entry.depends_on]
                if any(item.status in {"failed", "blocked", "canceled"} for item in dependencies):
                    entry.status = "blocked"
                    entry.error = "a campaign dependency did not complete successfully"
                    entry.completed_at = now_value
            running_scans = sum(
                entry.status == "running" and entry.kind == "scan_clone" for entry in entries
            )
            for entry in entries:
                if campaign.status != "running" or entry.status != "pending":
                    continue
                if not all(by_key[value].status == "completed" for value in entry.depends_on):
                    continue
                if entry.kind == "capability":
                    entry.status = "running"
                    entry.started_at = now_value
                    try:
                        result = self.registry.invoke(
                            entry.capability_id or "",
                            entry.input_json,
                        ).model_dump(mode="json")
                    except Exception as exc:
                        entry.status = "failed"
                        entry.error = str(exc)[:4_000]
                    else:
                        entry.status = "completed"
                        entry.result_json = result
                        capability_results.append(result)
                    entry.completed_at = datetime.now(UTC)
                    continue
                if running_scans >= campaign.max_parallel_scans:
                    continue
                source = session.get(Scan, entry.source_scan_id)
                if source is None:
                    entry.status = "failed"
                    entry.error = "source scan disappeared"
                    entry.completed_at = now_value
                    continue
                clone = Scan(
                    filename=source.filename,
                    artifact_sha256=source.artifact_sha256,
                    artifact_path=source.artifact_path,
                    stats={
                        "upload_bytes": (source.stats or {}).get("upload_bytes"),
                        "investigator": self.orchestrator.resolve_investigator(),
                        "execution_control": {"state": "running"},
                        "campaign": {
                            "id": campaign.id,
                            "name": campaign.name,
                            "goal": campaign.goal,
                            "entry_id": entry.entry_key,
                            "source_scan_id": source.id,
                            "total_budget_seconds": campaign.total_budget_seconds,
                        },
                    },
                )
                session.add(clone)
                session.flush()
                entry.status = "running"
                entry.started_at = now_value
                entry.launched_scan_id = clone.id
                add_event(
                    session,
                    clone.id,
                    "campaign.entry.created",
                    "监督控制面已按依赖生成隔离扫描入口",
                    {
                        "campaign_id": campaign.id,
                        "campaign": campaign.name,
                        "entry_id": entry.entry_key,
                        "source_scan_id": source.id,
                    },
                )
                scan_ids.append(clone.id)
                running_scans += 1
            terminal = {"completed", "failed", "blocked", "canceled"}
            if entries and all(entry.status in terminal for entry in entries):
                counts = Counter(entry.status for entry in entries)
                if campaign.status == "timed_out":
                    pass
                elif campaign.cancel_requested:
                    campaign.status = "canceled"
                elif counts.get("failed") or counts.get("blocked"):
                    campaign.status = "completed_with_errors"
                else:
                    campaign.status = "completed"
                campaign.completed_at = now_value
                campaign.result_json = {"entry_status_counts": dict(counts)}
            session.commit()
        return {
            **self._campaign_payload(campaign_id),
            "scan_ids": scan_ids,
            "capability_results": capability_results,
        }

    def list_campaigns(self) -> list[dict[str, Any]]:
        with self.orchestrator.database.session_factory() as session:
            ids = list(
                session.scalars(
                    select(CampaignRun.id).order_by(desc(CampaignRun.created_at)).limit(100)
                )
            )
        return [self._campaign_payload(campaign_id) for campaign_id in ids]

    def get_campaign(self, campaign_id: str) -> dict[str, Any]:
        return self._campaign_payload(campaign_id)

    def cancel(self, campaign_id: str) -> dict[str, Any]:
        with self.orchestrator.database.session_factory() as session:
            campaign = session.get(CampaignRun, campaign_id)
            if campaign is None:
                raise LookupError("campaign does not exist")
            campaign.cancel_requested = True
            campaign.status = "canceling"
            running_task_ids = list(
                session.scalars(
                    select(InvestigationTask.id)
                    .join(Scan, Scan.id == InvestigationTask.scan_id)
                    .join(
                        CampaignEntryRecord,
                        CampaignEntryRecord.launched_scan_id == Scan.id,
                    )
                    .where(
                        CampaignEntryRecord.campaign_id == campaign_id,
                        CampaignEntryRecord.status == "running",
                    )
                )
            )
            session.commit()
        for task_id in running_task_ids:
            self.orchestrator.request_task_cancellation(task_id)
        return self.advance(campaign_id)

    def continue_campaign(self, campaign_id: str) -> dict[str, Any]:
        with self.orchestrator.database.session_factory() as session:
            campaign = session.get(CampaignRun, campaign_id)
            if campaign is None:
                raise LookupError("campaign does not exist")
            if campaign.status == "completed":
                raise ValueError("a completed campaign has no pending work")
            campaign.cancel_requested = False
            campaign.status = "running"
            campaign.started_at = datetime.now(UTC)
            campaign.completed_at = None
            for entry in session.scalars(
                select(CampaignEntryRecord).where(
                    CampaignEntryRecord.campaign_id == campaign_id,
                    CampaignEntryRecord.status.in_({"failed", "blocked", "canceled"}),
                )
            ):
                entry.status = "pending"
                entry.error = None
                entry.launched_scan_id = None
                entry.result_json = {}
                entry.started_at = None
                entry.completed_at = None
            session.commit()
        return self.advance(campaign_id)

    def append_entries(
        self,
        campaign_id: str,
        request: CampaignAppendRequest,
    ) -> dict[str, Any]:
        with self.orchestrator.database.session_factory() as session:
            campaign = session.get(CampaignRun, campaign_id)
            if campaign is None:
                raise LookupError("campaign does not exist")
            current_plan = CampaignPlan.model_validate(campaign.plan_json)
            combined_plan = CampaignPlan(
                **{
                    **current_plan.model_dump(mode="python"),
                    "entries": [*current_plan.entries, *request.entries],
                }
            )
            validation = self.validate_plan(combined_plan)
            if not validation["valid"]:
                raise ValueError("appended campaign entries are not executable")
            existing_keys = set(
                session.scalars(
                    select(CampaignEntryRecord.entry_key).where(
                        CampaignEntryRecord.campaign_id == campaign_id
                    )
                )
            )
            if existing_keys & {entry.id for entry in request.entries}:
                raise ValueError("appended campaign entry IDs must be new")
            for entry in request.entries:
                session.add(
                    CampaignEntryRecord(
                        campaign_id=campaign_id,
                        entry_key=entry.id,
                        kind=entry.kind,
                        status="pending",
                        depends_on=list(entry.depends_on),
                        source_scan_id=entry.scan_id,
                        capability_id=entry.capability_id,
                        input_json=entry.input,
                    )
                )
            campaign.plan_json = combined_plan.model_dump(mode="json")
            campaign.status = "running"
            campaign.cancel_requested = False
            campaign.completed_at = None
            session.commit()
        return self.advance(campaign_id)

    def _campaign_payload(self, campaign_id: str) -> dict[str, Any]:
        with self.orchestrator.database.session_factory() as session:
            campaign = session.get(CampaignRun, campaign_id)
            if campaign is None:
                raise LookupError("campaign does not exist")
            entries = list(
                session.scalars(
                    select(CampaignEntryRecord)
                    .where(CampaignEntryRecord.campaign_id == campaign_id)
                    .order_by(CampaignEntryRecord.created_at)
                )
            )
            return {
                "schema_version": "1.0",
                "id": campaign.id,
                "campaign": campaign.name,
                "goal": campaign.goal,
                "status": campaign.status,
                "cancel_requested": campaign.cancel_requested,
                "max_parallel_scans": campaign.max_parallel_scans,
                "total_budget_seconds": campaign.total_budget_seconds,
                "created_at": campaign.created_at.isoformat(),
                "completed_at": (
                    campaign.completed_at.isoformat() if campaign.completed_at else None
                ),
                "entries": [
                    {
                        "id": entry.id,
                        "entry_id": entry.entry_key,
                        "kind": entry.kind,
                        "status": entry.status,
                        "depends_on": entry.depends_on,
                        "source_scan_id": entry.source_scan_id,
                        "scan_id": entry.launched_scan_id,
                        "capability_id": entry.capability_id,
                        "result": entry.result_json,
                        "error": entry.error,
                    }
                    for entry in entries
                ],
                "result": campaign.result_json,
            }
