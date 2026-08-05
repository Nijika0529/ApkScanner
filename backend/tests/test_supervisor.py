from types import SimpleNamespace

from apkscanner.db import Database
from apkscanner.models import CampaignRun, Scan
from apkscanner.supervisor import CampaignPlan, SupervisorService


class _Registry:
    @staticmethod
    def catalog():
        return [{"id": "fixture.prepare", "available": True}]

    @staticmethod
    def invoke(capability_id, input_value):  # noqa: ANN001
        assert capability_id == "fixture.prepare"
        return SimpleNamespace(
            model_dump=lambda mode: {  # noqa: ARG005
                "capability_id": capability_id,
                "status": "completed",
                "output": input_value,
            }
        )


def test_persistent_campaign_advances_dependency_dag(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    orchestrator = SimpleNamespace(
        database=database,
        resolve_investigator=lambda: "codex",
        request_task_cancellation=lambda _task_id: True,
        device_pool=SimpleNamespace(snapshot=lambda: {}),
        codex=SimpleNamespace(executor=SimpleNamespace(snapshot=lambda: {})),
    )
    supervisor = SupervisorService(orchestrator, _Registry())
    with database.session_factory() as session:
        source = Scan(
            status="final",
            filename="fixture.apk",
            artifact_sha256="a" * 64,
            artifact_path="fixture.apk",
            stats={"upload_bytes": 3},
        )
        session.add(source)
        session.commit()
        source_id = source.id

    launched = supervisor.launch(
        CampaignPlan.model_validate(
            {
                "name": "persistent-dag",
                "goal": "rescan then prepare a dependent fixture",
                "entries": [
                    {"id": "rescan", "kind": "scan_clone", "scan_id": source_id},
                    {
                        "id": "prepare_fixture",
                        "kind": "capability",
                        "capability_id": "fixture.prepare",
                        "input": {"canary": "campaign-canary"},
                        "depends_on": ["rescan"],
                    },
                ],
            }
        )
    )
    assert len(launched["scan_ids"]) == 1
    assert [item["status"] for item in launched["entries"]] == ["running", "pending"]

    with database.session_factory() as session:
        clone = session.get(Scan, launched["scan_ids"][0])
        assert clone is not None
        clone.status = "final"
        session.commit()

    resumed_service = SupervisorService(orchestrator, _Registry())
    completed = resumed_service.advance(launched["campaign_id"])
    assert completed["status"] == "completed"
    assert [item["status"] for item in completed["entries"]] == [
        "completed",
        "completed",
    ]
    with database.session_factory() as session:
        assert session.get(CampaignRun, launched["campaign_id"]).goal.startswith("rescan")
