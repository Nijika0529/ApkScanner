from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

import yaml
from sqlalchemy import select

from .artifacts import ArtifactStore
from .auth import CredentialStore, load_auth_flow
from .benchmark import BenchmarkEvaluator
from .config import Settings
from .db import Database
from .models import EntryPoint, InvestigationTask, Scan
from .orchestrator import ScanOrchestrator
from .reports import ReportBuilder
from .schemas import BenchmarkSpec
from .tools import discover_tools


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
            },
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id
    orchestrator._run_sync(scan_id)  # CLI owns this foreground worker.
    return settings, database, orchestrator, scan_id


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
    return 0


def capabilities_command(args: argparse.Namespace) -> int:
    _settings, _database, _store, orchestrator = _runtime()
    payload = {
        "default_investigator": orchestrator.resolve_investigator(),
        "enabled_investigators": [
            name
            for name in ("codex", "opencode")
            if orchestrator.settings.investigator_enabled(name)
        ],
        "tools": discover_tools(orchestrator.runner),
        "codex": orchestrator.codex.capability(deep=args.deep),
        "opencode": orchestrator.opencode.capability(deep=args.deep),
        "device": orchestrator.device.capability(),
        "authentication": orchestrator.device.auth_capability(),
        "frida": orchestrator.frida.capability(deep=args.deep),
        "mobsf": orchestrator.mobsf.capability(),
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


def auth_status_command(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    flow = load_auth_flow(settings.auth_flow_path)
    if flow is None:
        print(
            json.dumps(
                {"available": False, "detail": "APKSCANNER_AUTH_FLOW is not configured"},
                ensure_ascii=False,
                indent=2,
            )
        )
        return 1
    store = CredentialStore()
    secrets = {name: store.get(flow.profile, name) is not None for name in flow.required_secrets}
    print(
        json.dumps(
            {
                "available": all(secrets.values()),
                "profile": flow.profile,
                "package": flow.package,
                "steps": len(flow.steps),
                "secrets": secrets,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if all(secrets.values()) else 1


def auth_set_secret_command(args: argparse.Namespace) -> int:
    _validate_secret_name(args.profile, args.name)
    if args.stdin:
        value = sys.stdin.read().removesuffix("\n").removesuffix("\r")
    else:
        value = getpass.getpass(f"Value for {args.profile}/{args.name}: ")
    if not value:
        raise ValueError("secret value cannot be empty")
    CredentialStore().set(args.profile, args.name, value)
    print(f"Stored {args.profile}/{args.name} in the operating-system keyring.")
    return 0


def auth_delete_secret_command(args: argparse.Namespace) -> int:
    _validate_secret_name(args.profile, args.name)
    CredentialStore().delete(args.profile, args.name)
    print(f"Deleted {args.profile}/{args.name} from the operating-system keyring, if present.")
    return 0


def _validate_secret_name(profile: str, name: str) -> None:
    pattern = r"[A-Za-z0-9_.-]{1,128}"
    if not re.fullmatch(pattern, profile) or not re.fullmatch(pattern, name):
        raise ValueError("profile and secret name may contain only letters, digits, _ . and -")


def serve_command(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("apkscanner.main:app", host="127.0.0.1", port=args.port, reload=args.reload)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scanctl", description="APK Scanner local control CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve", help="Run the local API and Web console")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--reload", action="store_true")
    serve.set_defaults(handler=serve_command)
    scan = subparsers.add_parser("scan", help="Run a foreground APK scan")
    scan.add_argument("apk")
    scan.add_argument(
        "--investigator",
        choices=("configured", "codex", "opencode", "none"),
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
        choices=("configured", "codex", "opencode", "none"),
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
    auth_status = subparsers.add_parser(
        "auth-status", help="Check the configured login flow and keyring references"
    )
    auth_status.set_defaults(handler=auth_status_command)
    auth_set = subparsers.add_parser(
        "auth-set-secret", help="Store a login-flow secret in the OS keyring"
    )
    auth_set.add_argument("name")
    auth_set.add_argument("--profile", default="default-single-account")
    auth_set.add_argument("--stdin", action="store_true", help="Read the value from standard input")
    auth_set.set_defaults(handler=auth_set_secret_command)
    auth_delete = subparsers.add_parser(
        "auth-delete-secret", help="Delete a login-flow secret from the OS keyring"
    )
    auth_delete.add_argument("name")
    auth_delete.add_argument("--profile", default="default-single-account")
    auth_delete.set_defaults(handler=auth_delete_secret_command)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        raise SystemExit(args.handler(args))
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
