from __future__ import annotations

import argparse
import json
import os
import signal
import threading
import time
from types import SimpleNamespace

import pytest
from apkscanner import cli
from apkscanner.core.db import Database
from apkscanner.core.models import BenchmarkEvaluation, InvestigationTask, Scan, ScanEvent
from sqlalchemy import select


@pytest.mark.parametrize(("passed", "expected_code"), [(True, 0), (False, 1)])
def test_benchmark_cli_exit_code_follows_quality_gate(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    passed: bool,
    expected_code: int,
) -> None:
    result = {"quality_gate": {"passed": passed}}
    monkeypatch.setattr(cli, "_create_and_run_scan", lambda _args: (None, None, None, "scan-1"))
    monkeypatch.setattr(cli, "_load_benchmark_spec", lambda _path: object())

    class Evaluator:
        def __init__(self, _settings, _database) -> None:  # noqa: ANN001
            pass

        def evaluate(self, _scan_id, _spec):  # noqa: ANN001, ANN201
            return SimpleNamespace(id="eval-1", result=result)

    monkeypatch.setattr(cli, "BenchmarkEvaluator", Evaluator)

    exit_code = cli.benchmark_command(argparse.Namespace(truth="truth.json"))

    assert exit_code == expected_code
    payload = json.loads(capsys.readouterr().out)
    assert payload["scan_id"] == "scan-1"
    assert payload["quality_gate"]["passed"] is passed


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX SIGTERM")
@pytest.mark.parametrize("command", ["scan", "benchmark"])
def test_foreground_sigterm_persists_failed_without_evaluation(
    settings, fixture_apk, monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    released = threading.Event()
    scheduled: list[threading.Timer] = []

    class Orchestrator:
        shutdown_calls = 0

        def resolve_investigator(self, _value: str) -> str:
            return "codex"

        def _run_sync(self, scan_id: str) -> None:
            with database.session_factory() as session:
                session.add(
                    InvestigationTask(scan_id=scan_id, task_type="component", status="running")
                )
                session.commit()
            timer = threading.Timer(0.05, lambda: os.kill(os.getpid(), signal.SIGTERM))
            scheduled.append(timer)
            timer.start()
            released.wait(timeout=5)

        def shutdown(self) -> None:
            self.shutdown_calls += 1
            released.set()

    orchestrator = Orchestrator()
    monkeypatch.setattr(cli, "_runtime", lambda: (settings, database, None, orchestrator))
    monkeypatch.setattr(
        cli,
        "_load_benchmark_spec",
        lambda _path: pytest.fail("SIGTERM scan must not enter benchmark evaluation"),
    )
    previous = signal.getsignal(signal.SIGTERM)
    try:
        with pytest.raises(SystemExit) as caught:
            handler = cli.benchmark_command if command == "benchmark" else cli.scan_command
            handler(
                argparse.Namespace(apk=str(fixture_apk), investigator="codex", truth="truth.json")
            )
    finally:
        released.set()
        for timer in scheduled:
            timer.join(timeout=1)

    assert caught.value.code == 143
    assert caught.value.force_exit is False
    assert signal.getsignal(signal.SIGTERM) == previous
    assert orchestrator.shutdown_calls == 1
    with database.session_factory() as session:
        scan = session.scalar(select(Scan))
        assert scan is not None
        assert scan.status == "failed"
        assert scan.completed_at is not None
        assert scan.stats["execution_control"]["reason"] == "cli_sigterm"
        assert scan.stats["cli_termination"]["worker_stopped"] is True
        assert session.scalar(select(InvestigationTask)).status == "failed"
        assert session.scalar(select(ScanEvent).where(ScanEvent.event_type == "scan.failed"))
        assert session.scalar(select(BenchmarkEvaluation)) is None


def test_foreground_sigterm_wait_is_bounded_when_worker_ignores_shutdown(
    settings, monkeypatch: pytest.MonkeyPatch,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(filename="fixture.apk", artifact_sha256="a" * 64, artifact_path="/tmp/x")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    released = threading.Event()
    started = threading.Event()

    class Orchestrator:
        def _run_sync(self, _scan_id: str) -> None:
            started.set()
            released.wait(timeout=5)

        def shutdown(self) -> None:
            pass

    monkeypatch.setattr(cli, "_CLI_TERMINATION_GRACE_SECONDS", 0.1)
    sigterm = threading.Event()
    timer = threading.Timer(0.02, sigterm.set)
    timer.start()
    begin = time.monotonic()
    try:
        with pytest.raises(SystemExit) as caught:
            cli._run_foreground_scan(Orchestrator(), database, scan_id, sigterm)
    finally:
        released.set()
        timer.join(timeout=1)
    assert caught.value.code == 143
    assert caught.value.force_exit is True
    assert started.is_set()
    assert time.monotonic() - begin < 1.0
    with database.session_factory() as session:
        persisted = session.get(Scan, scan_id)
        assert persisted.status == "failed"
        assert persisted.stats["cli_termination"]["worker_stopped"] is False
        assert persisted.stats["cli_termination"]["cleanup_completed"] is False
        assert persisted.stats["cli_termination"]["container_inventory_complete"] is False


def test_foreground_sigterm_records_cleanup_and_worker_errors(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(filename="fixture.apk", artifact_sha256="a" * 64, artifact_path="/tmp/x")
        session.add(scan)
        session.commit()
        scan_id = scan.id

    class Executor:
        def snapshot(self) -> list[dict[str, str]]:
            return [{"scan_id": scan_id, "name": "apk-scanner-residual"}]

    class Orchestrator:
        codex = SimpleNamespace(executor=Executor())

        def shutdown(self) -> None:
            raise RuntimeError("docker rm failed")

    cli._terminate_foreground_scan(
        Orchestrator(), database, scan_id, None, [RuntimeError("worker cleanup failed")]
    )
    with database.session_factory() as session:
        persisted = session.get(Scan, scan_id)
        assert persisted.status == "failed"
        termination = persisted.stats["cli_termination"]
        assert termination["cleanup_completed"] is False
        assert termination["cleanup_error"] == "docker rm failed"
        assert termination["worker_error"] == "worker cleanup failed"
        assert termination["remaining_containers"][0]["name"] == "apk-scanner-residual"


def test_cli_main_forces_exit_only_after_bounded_sigterm_cleanup(monkeypatch) -> None:  # noqa: ANN001
    class ForcedExit(Exception):
        pass

    def handler(_args):  # noqa: ANN001, ANN202
        raise cli._ForegroundTerminated(force_exit=True)

    exit_codes: list[int] = []

    def fake_exit(code: int) -> None:
        exit_codes.append(code)
        raise ForcedExit

    monkeypatch.setattr(
        cli,
        "build_parser",
        lambda: SimpleNamespace(parse_args=lambda: SimpleNamespace(handler=handler)),
    )
    monkeypatch.setattr(cli.os, "_exit", fake_exit)
    with pytest.raises(ForcedExit):
        cli.main()
    assert exit_codes == [143]
