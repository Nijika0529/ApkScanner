from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import yaml
from sqlalchemy import select

from .core.config import Settings
from .core.db import Database
from .core.enums import ScanStatus, TaskStatus
from .core.models import EntryPoint, InvestigationTask, Scan
from .core.repository import add_event, now
from .core.schemas import BenchmarkSpec
from .infrastructure.artifacts import ArtifactStore
from .infrastructure.tools import discover_tools
from .platform.reports import ReportBuilder
from .runtime.benchmark import BenchmarkEvaluator
from .runtime.orchestrator import ScanOrchestrator

_CLI_TERMINATION_GRACE_SECONDS = 45


class _ForegroundTerminated(SystemExit):
    def __init__(self, *, force_exit: bool) -> None:
        super().__init__(128 + signal.SIGTERM)
        self.force_exit = force_exit


def _runtime() -> tuple[Settings, Database, ArtifactStore, ScanOrchestrator]:
    settings = Settings.from_env()
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    return settings, database, store, ScanOrchestrator(settings, database, store)


def _import_apk(source: Path, settings: Settings) -> tuple[str, Path, int]:
    if not source.is_file() or source.suffix.lower() != ".apk":
        raise ValueError("scan input must be an existing .apk file")
    digest = hashlib.sha256()
    size = 0
    with source.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > settings.max_upload_bytes:
                raise ValueError("APK exceeds the configured upload limit")
            digest.update(chunk)
    sha256 = digest.hexdigest()
    directory = settings.data_dir / "artifacts" / sha256[:2]
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{sha256}.apk"
    if not target.exists():
        shutil.copyfile(source, target)
    return sha256, target, size


def _create_and_run_scan(
    args: argparse.Namespace,
) -> tuple[Settings, Database, ScanOrchestrator, str]:
    with _foreground_sigterm_event() as sigterm:
        settings, database, _store, orchestrator = _runtime()
        investigator = orchestrator.resolve_investigator(args.investigator)
        source = Path(args.apk).resolve()
        sha256, target, size = _import_apk(source, settings)
        with database.session_factory() as session:
            scan = Scan(
                filename=source.name,
                artifact_sha256=sha256,
                artifact_path=str(target),
                stats={
                    "upload_bytes": size,
                    "source": "cli",
                    "investigator": investigator,
                    "execution_control": {"state": "running"},
                },
            )
            session.add(scan)
            session.commit()
            scan_id = scan.id
        _run_foreground_scan(orchestrator, database, scan_id, sigterm)
        return settings, database, orchestrator, scan_id


@contextmanager
def _foreground_sigterm_event():  # noqa: ANN202
    """Turn SIGTERM into a cooperative foreground stop without doing I/O in a handler."""

    requested = threading.Event()
    if threading.current_thread() is not threading.main_thread():
        yield requested
        return
    previous = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda _signum, _frame: requested.set())
    try:
        yield requested
    finally:
        signal.signal(signal.SIGTERM, previous)


def _run_foreground_scan(
    orchestrator: ScanOrchestrator,
    database: Database,
    scan_id: str,
    sigterm: threading.Event,
) -> None:
    errors: list[BaseException] = []

    def run() -> None:
        try:
            orchestrator._run_sync(scan_id)
        except BaseException as exc:
            errors.append(exc)

    worker: threading.Thread | None = None
    if not sigterm.is_set():
        worker = threading.Thread(target=run, name=f"cli-scan-{scan_id}", daemon=True)
        worker.start()
    while worker is not None and worker.is_alive() and not sigterm.is_set():
        worker.join(timeout=0.2)
    if sigterm.is_set():
        force_exit = _terminate_foreground_scan(orchestrator, database, scan_id, worker, errors)
        raise _ForegroundTerminated(force_exit=force_exit)
    if errors:
        _persist_cli_scan_failure(
            database,
            scan_id,
            reason=f"foreground worker exited unexpectedly: {errors[0]}",
            termination=None,
        )
        raise errors[0]


def _terminate_foreground_scan(
    orchestrator: ScanOrchestrator,
    database: Database,
    scan_id: str,
    worker: threading.Thread | None,
    worker_errors: list[BaseException],
) -> bool:
    shutdown_errors: list[BaseException] = []

    def shutdown() -> None:
        try:
            orchestrator.shutdown()
        except BaseException as exc:
            shutdown_errors.append(exc)

    cleanup = threading.Thread(target=shutdown, name=f"cli-cleanup-{scan_id}", daemon=True)
    cleanup.start()
    deadline = time.monotonic() + _CLI_TERMINATION_GRACE_SECONDS
    for active in (worker, cleanup):
        if active is not None and active.is_alive():
            active.join(timeout=max(0.0, deadline - time.monotonic()))
    stopped = worker is None or not worker.is_alive()
    cleanup_completed = stopped and not cleanup.is_alive() and not shutdown_errors and not worker_errors
    executor = getattr(getattr(orchestrator, "codex", None), "executor", None)
    # snapshot takes the executor lock; a timed-out docker rm may still hold it.
    # Do not defeat the grace deadline merely to inspect a residual container.
    remaining_containers = (
        executor.snapshot()
        if executor is not None and stopped and not cleanup.is_alive()
        else []
    )
    inventory_complete = stopped and not cleanup.is_alive()
    if remaining_containers:
        cleanup_completed = False
    _persist_cli_scan_failure(
        database,
        scan_id,
        reason="foreground CLI received SIGTERM",
        termination={
            "signal": "SIGTERM",
            "worker_stopped": stopped,
            "cleanup_completed": cleanup_completed,
            "cleanup_error": str(shutdown_errors[0])[:300] if shutdown_errors else None,
            "worker_error": str(worker_errors[0])[:300] if worker_errors else None,
            "remaining_containers": remaining_containers,
            "container_inventory_complete": inventory_complete,
        },
    )
    # Daemon scan threads can still own non-daemon thread-pool workers; the CLI
    # entry point must bypass interpreter shutdown hooks after the grace period.
    return not stopped or cleanup.is_alive()


def _persist_cli_scan_failure(
    database: Database,
    scan_id: str,
    *,
    reason: str,
    termination: dict[str, object] | None,
) -> None:
    failed_at = now()
    with database.session_factory() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise RuntimeError("foreground scan disappeared before failure could be recorded")
        scan.status = ScanStatus.FAILED.value
        scan.error = reason
        scan.completed_at = failed_at
        stats = dict(scan.stats or {})
        stats["execution_control"] = {
            **dict(stats.get("execution_control") or {}),
            "state": "failed",
            "reason": "cli_sigterm" if termination is not None else "cli_worker_error",
        }
        if termination is not None:
            stats["cli_termination"] = termination
        scan.stats = stats
        for task in session.scalars(
            select(InvestigationTask).where(
                InvestigationTask.scan_id == scan_id,
                InvestigationTask.status.in_(
                    {
                        TaskStatus.QUEUED.value,
                        TaskStatus.AWAITING_DEVICE.value,
                        TaskStatus.BLOCKED_DEVICE.value,
                        TaskStatus.RUNNING.value,
                        TaskStatus.CANCEL_REQUESTED.value,
                    }
                ),
            )
        ):
            task.status = TaskStatus.FAILED.value
            task.error = reason
            task.completed_at = failed_at
        add_event(session, scan_id, "scan.failed", reason, {"source": "foreground_cli"})
        session.commit()


def scan_command(args: argparse.Namespace) -> int:
    _settings, database, _orchestrator, scan_id = _create_and_run_scan(args)
    with database.session_factory() as session:
        scan = session.get(Scan, scan_id)
        assert scan is not None
        report = ReportBuilder().build(session, scan)
    print(json.dumps({"scan_id": scan_id, "status": report["scan"]["status"], "stats": report["scan"]["stats"]}, ensure_ascii=False, indent=2))
    return 0 if report["scan"]["status"] == "final" else 1


def _load_benchmark_spec(path: str) -> BenchmarkSpec:
    source = Path(path).resolve()
    if not source.is_file():
        raise ValueError("ground-truth file does not exist")
    with source.open(encoding="utf-8") as stream:
        value = (
            yaml.safe_load(stream)
            if source.suffix.lower() in {".yaml", ".yml"}
            else json.load(stream)
        )
    return BenchmarkSpec.model_validate(value)


def evaluate_command(args: argparse.Namespace) -> int:
    settings, database, _store, _orchestrator = _runtime()
    evaluation = BenchmarkEvaluator(settings, database).evaluate(
        args.scan_id,
        _load_benchmark_spec(args.truth),
    )
    print(json.dumps(evaluation.result, ensure_ascii=False, indent=2))
    return 0


def simulate_evaluation_command(args: argparse.Namespace) -> int:
    settings, database, _store, _orchestrator = _runtime()
    evaluation = BenchmarkEvaluator(settings, database).simulate(
        args.scan_id,
        _load_benchmark_spec(args.truth),
        detected_ids=set(args.detected_id) if args.detected_id is not None else None,
        omitted_ids=set(args.omit_id) if args.omit_id is not None else None,
        target_recall=args.target_recall,
        seed=args.seed,
    )
    print(
        json.dumps(
            {
                "scan_id": args.scan_id,
                "evaluation_id": evaluation.id,
                **evaluation.result,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def benchmark_command(args: argparse.Namespace) -> int:
    settings, database, _orchestrator, scan_id = _create_and_run_scan(args)
    evaluation = BenchmarkEvaluator(settings, database).evaluate(
        scan_id,
        _load_benchmark_spec(args.truth),
    )
    print(
        json.dumps(
            {
                "scan_id": scan_id,
                "evaluation_id": evaluation.id,
                **evaluation.result,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if evaluation.result.get("quality_gate", {}).get("passed") is True else 1


def capabilities_command(args: argparse.Namespace) -> int:
    _settings, _database, _store, orchestrator = _runtime()
    payload = {
        "default_investigator": orchestrator.resolve_investigator(),
        "enabled_investigators": [
            name
            for name in ("codex",)
            if orchestrator.settings.investigator_enabled(name)
        ],
        "tools": discover_tools(orchestrator.runner),
        "codex": orchestrator.codex.capability(deep=args.deep),
        "device": orchestrator.device_pool.capability(),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def context_command(args: argparse.Namespace) -> int:
    _settings, database, _store, _orchestrator = _runtime()
    with database.session_factory() as session:
        task = session.get(InvestigationTask, args.task_id)
        if task is None:
            print("Task not found", file=sys.stderr)
            return 2
        scan = session.get(Scan, task.scan_id)
        entries = list(
            session.scalars(select(EntryPoint).where(EntryPoint.id.in_(task.target_entry_ids)))
        )
        payload = {
            "scan": {
                "id": scan.id,
                "package_name": scan.package_name,
                "artifact_sha256": scan.artifact_sha256,
                "workspace": str(_settings.data_dir / "workspaces" / scan.id),
            },
            "task": {
                "id": task.id,
                "type": task.task_type,
                "hypotheses": task.hypotheses,
                "preconditions": task.preconditions,
                "allowed_side_effects": task.allowed_side_effects,
            },
            "entries": [
                {
                    "id": entry.id,
                    "kind": entry.kind,
                    "name": entry.name,
                    "owner": entry.owner_component,
                    "permission": entry.permission,
                    "deep_links": entry.deep_links,
                    "metadata": entry.metadata_json,
                }
                for entry in entries
            ],
        }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def serve_command(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("apkscanner.main:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scanctl", description="APK Scanner local control CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve", help="Run the local API and Web console")
    serve.add_argument("--port", type=int, default=8000)
    # Default stays loopback; bind 0.0.0.0 explicitly to expose the console to a
    # host-side browser (for example Windows reaching a WSL service).
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--reload", action="store_true")
    serve.set_defaults(handler=serve_command)
    scan = subparsers.add_parser("scan", help="Run a foreground APK scan")
    scan.add_argument("apk")
    scan.add_argument(
        "--investigator",
        choices=("configured", "codex", "none"),
        default="configured",
        help="AI investigator backend for this scan",
    )
    scan.set_defaults(handler=scan_command)
    benchmark = subparsers.add_parser(
        "benchmark",
        help="Scan an APK and score only evidence-confirmed findings against private ground truth",
    )
    benchmark.add_argument("apk")
    benchmark.add_argument("--truth", required=True)
    benchmark.add_argument(
        "--investigator",
        choices=("configured", "codex", "none"),
        default="configured",
    )
    benchmark.set_defaults(handler=benchmark_command)
    evaluate = subparsers.add_parser(
        "evaluate",
        help="Score an existing scan against a private ground-truth JSON or YAML file",
    )
    evaluate.add_argument("--scan-id", required=True)
    evaluate.add_argument("--truth", required=True)
    evaluate.set_defaults(handler=evaluate_command)
    simulate = subparsers.add_parser(
        "simulate-evaluation",
        help=(
            "Create a clearly labelled synthetic recall scenario for a completed scan "
            "without fabricating Findings or Evidence"
        ),
    )
    simulate.add_argument("--scan-id", required=True)
    simulate.add_argument("--truth", required=True)
    selectors = simulate.add_mutually_exclusive_group(required=True)
    selectors.add_argument(
        "--detected-id",
        action="append",
        help="Ground-truth ID to mark as synthetically detected; repeat as needed",
    )
    selectors.add_argument(
        "--omit-id",
        action="append",
        help="Ground-truth ID to mark as synthetically missed; repeat as needed",
    )
    selectors.add_argument(
        "--target-recall",
        type=float,
        help="Deterministically select enough ground-truth items for this recall (0..1)",
    )
    simulate.add_argument(
        "--seed",
        default="apkscanner-demo-v1",
        help="Stable seed used by target-recall selection",
    )
    simulate.set_defaults(handler=simulate_evaluation_command)
    capabilities = subparsers.add_parser("capabilities", help="Inspect scanner capabilities")
    capabilities.add_argument(
        "--deep",
        action="store_true",
        help="Probe configured AI provider accounts and models",
    )
    capabilities.set_defaults(handler=capabilities_command)
    context = subparsers.add_parser("context", help="Print a task's bounded investigation context")
    context.add_argument("--task-id", required=True)
    context.set_defaults(handler=context_command)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        raise SystemExit(args.handler(args))
    except _ForegroundTerminated as exc:
        if exc.force_exit:
            print("foreground SIGTERM cleanup timed out; scan is persisted as failed", file=sys.stderr)
            sys.stderr.flush()
            os._exit(exc.code)
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
