#!/usr/bin/env python3
"""Exercise platform Web observer pages through an ordinary-UID fixture on a leased phone.

The script uses a throwaway scanner database, preserves the target app's data,
and removes the temporary attacker app through the existing PoC executor.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import threading
from contextlib import nullcontext
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from apkscanner.core.config import Settings  # noqa: E402
from apkscanner.core.db import Database  # noqa: E402
from apkscanner.core.models import (  # noqa: E402
    Evidence,
    Finding,
    InvestigationTask,
    Scan,
    ValidationFixture,
)
from apkscanner.core.schemas import (  # noqa: E402
    AgentOracleSpec,
    AgentPocSpec,
    WebExperimentRequest,
    WebExperimentSnapshotRequest,
)
from apkscanner.infrastructure.artifacts import ArtifactStore  # noqa: E402
from apkscanner.infrastructure.tools import TimeBudget  # noqa: E402
from apkscanner.runtime.live_proof import LiveProofContext  # noqa: E402
from apkscanner.runtime.orchestrator import ScanOrchestrator  # noqa: E402
from sqlalchemy import select  # noqa: E402

TARGET_APK = ROOT / "testapk/adaptivecases.apk"
ATTACKER_APK = ROOT / "testapk/webobserverattacker.apk"
ATTACKER_PACKAGE = "io.apkscanner.poc.webobserverattacker"


def _run_case(orchestrator, context, *, name, host, frame, fixture_id=None):  # noqa: ANN001, ANN202
    with orchestrator.database.session_factory() as session:
        finding = Finding(
            scan_id=context.scan_id,
            dedupe_key=f"web-smoke-{name}",
            rule_id="WEB-SMOKE",
            title=f"Web observer smoke: {name}",
            description="Controlled WebView bridge experiment on a local fixture.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="supported_static",
        )
        session.add(finding)
        session.commit()
        finding_id = finding.id
    plan = orchestrator.begin_web_experiment(
        context.task_id,
        context.token,
        WebExperimentRequest(
            finding_id=finding_id,
            hypothesis_id=context.hypotheses[0]["id"],
            bridge_name="AccountBridge",
            method="getSessionToken",
            frame=frame,
            entry_scheme="adaptivecases",
            entry_host=host,
            entry_path="",
            entry_query_keys=["url"],
            victim_state="controlled canary fixture" if fixture_id else "guest",
            fixture_id=fixture_id,
        ),
    )
    attack_url = plan["attack_url"]
    phase_nonce = parse_qs(urlsplit(attack_url).query)["nonce"][0]
    deep_link = f"adaptivecases://{host}?" + urlencode({"url": attack_url})
    spec = AgentPocSpec(
        project_path="poc/webobserverattacker",
        package_name=ATTACKER_PACKAGE,
        launch_component=".LaunchActivity",
        log_tag="APKSCANNER_POC",
        timeout_seconds=18,
    )
    probe = context.device.execute_poc(
        ATTACKER_APK,
        spec,
        target_package_name=context.package_name,
        state="guest",
        budget=context.budget,
        extras={"target_uri": deep_link},
        oracle=AgentOracleSpec(
            kind="target_uid_log_contains",
            expected_text=phase_nonce,
            impact="none",
        ),
        build_metadata={
            "caller_identity": "platform_poc_app",
            "compile_api": 36,
            "min_api": 26,
            "target_api": 36,
            "durable_receipt_supported": False,
        },
    )
    orchestrator._record_commands(
        context.scan_id,
        context.task_id,
        probe.commands,
        context.evidence_summaries,
    )
    request_id = probe.summary["request_id"]
    with orchestrator.database.session_factory() as session:
        receipts = {
            item.kind: item
            for item in session.scalars(
                select(Evidence).where(
                    Evidence.scan_id == context.scan_id,
                    Evidence.task_id == context.task_id,
                )
            )
            if item.metadata_json.get("request_id") == request_id
        }
    receipt_ids = {
        "launch_evidence_id": receipts.get("blackbox.poc_launch").id if receipts.get("blackbox.poc_launch") else None,
        "process_evidence_id": receipts.get("blackbox.poc_process").id if receipts.get("blackbox.poc_process") else None,
        "target_evidence_id": receipts.get("blackbox.poc_target_logcat").id if receipts.get("blackbox.poc_target_logcat") else None,
    }
    snapshot = orchestrator.snapshot_web_experiment(
        context.task_id,
        context.token,
        plan["experiment_id"],
        WebExperimentSnapshotRequest(**receipt_ids),
    )
    events = orchestrator._web_exploit_observer.events(
        plan["experiment_id"], task_id=context.task_id
    )
    attack_callbacks = [
        item for item in events if item["phase"] == "attack" and item["stage"] == "callback"
    ]
    callback_type = attack_callbacks[0]["event_type"] if attack_callbacks else None
    expected_callback = "bridge_missing" if name == "safe-no-bridge" else "bridge_return"
    passed = bool(
        snapshot["attack_page_observed"]
        and snapshot["controls_validated"]
        and snapshot["execution_evidence_id"]
        and snapshot["coverage_matrix"]["final_url"]
        and callback_type == expected_callback
        and (name == "safe-no-bridge" or attack_callbacks[0].get("client_payload", {}).get("value"))
        and (fixture_id is None or (
            plan.get("state_fixture", {}).get("verified") is True
            and snapshot["effect_evidence_id"] is not None
            and snapshot["coverage_matrix"]["target_effect_validated"] is True
        ))
    )
    return {
        "case": name,
        "passed": passed,
        "experiment_id": plan["experiment_id"],
        "observer_transport": plan.get("observer_transport", "adb_reverse_http"),
        "observer_origin": (
            f"{urlsplit(attack_url).scheme}://{urlsplit(attack_url).netloc}"
        ),
        "remote_deployment_id": plan.get("remote_deployment_id"),
        "request_id": request_id,
        "attack_callback_type": callback_type,
        "attack_value_present": bool(
            attack_callbacks and attack_callbacks[0].get("client_payload", {}).get("value")
        ),
        "attack_page_observed": snapshot["attack_page_observed"],
        "controls_validated": snapshot["controls_validated"],
        "control_gaps": snapshot["control_gaps"],
        "execution_correlated": snapshot["execution_evidence_id"] is not None,
        "fixture_state_verified": snapshot["coverage_matrix"]["fixture_state_verified"],
        "target_effect_validated": snapshot["coverage_matrix"]["target_effect_validated"],
        "effect_evidence_id": snapshot["effect_evidence_id"],
        "coverage_cases": snapshot["coverage_matrix"]["cases"],
        "final_url_confirmed": snapshot["coverage_matrix"]["final_url"] is not None,
        "gaps": snapshot["gaps"],
        "evidence_ids": [*snapshot["event_evidence_ids"], snapshot["snapshot_evidence_id"]],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True, help="Exact ADB serial of the leased device")
    parser.add_argument(
        "--case",
        choices=("bridge-top", "safe-no-bridge", "bridge-iframe", "bridge-redirect"),
        help="Run one matrix case for focused diagnosis (default: all)",
    )
    parser.add_argument(
        "--retain-artifacts",
        action="store_true",
        help="Keep the throwaway DB and evidence under /tmp for judge replay",
    )
    parser.add_argument(
        "--controlled-canary",
        action="store_true",
        help="Seed and verify the protected target-owned canary (requires --case bridge-top)",
    )
    parser.add_argument(
        "--remote-observer",
        action="store_true",
        help="Use the explicitly configured HTTPS/SSH observer instead of ADB reverse",
    )
    parser.add_argument(
        "--remote-ssh-config",
        type=Path,
        default=ROOT / ".data/remote-observer-ssh.conf",
        help="Dedicated SSH config for the remote observer",
    )
    parser.add_argument(
        "--remote-ssh-alias",
        help="Allowlisted Host entry from the dedicated observer SSH config",
    )
    parser.add_argument(
        "--remote-origin",
        help="Public HTTPS origin whose /web-observer/ route is tunnelled locally",
    )
    parser.add_argument("--remote-loopback-port", type=int, default=15880)
    args = parser.parse_args()
    if args.remote_observer and (not args.remote_ssh_alias or not args.remote_origin):
        parser.error(
            "--remote-observer requires --remote-ssh-alias and --remote-origin"
        )
    if args.controlled_canary and args.case != "bridge-top":
        parser.error("--controlled-canary requires --case bridge-top")
    if not TARGET_APK.is_file() or not ATTACKER_APK.is_file():
        parser.error("build adaptivecases.apk and webobserverattacker.apk first")
    workspace_manager = (
        nullcontext(tempfile.mkdtemp(prefix="apkscanner-web-smoke-"))
        if args.retain_artifacts
        else tempfile.TemporaryDirectory(prefix="apkscanner-web-smoke-")
    )
    with workspace_manager as temporary:
        data_dir = Path(temporary)
        settings = Settings(
            data_dir=data_dir,
            database_url=f"sqlite:///{data_dir / 'scan.db'}",
            sqlite_synchronous="OFF",
            adb_serial=args.serial,
            adb_serials=(args.serial,),
            device_android_api=36,
            web_observer_remote_enabled=args.remote_observer,
            web_observer_ssh_alias=(args.remote_ssh_alias if args.remote_observer else None),
            web_observer_allowed_ssh_aliases=(
                (args.remote_ssh_alias,) if args.remote_observer else ()
            ),
            web_observer_ssh_config=(
                args.remote_ssh_config if args.remote_observer else None
            ),
            web_observer_public_base_url=(
                args.remote_origin if args.remote_observer else None
            ),
            web_observer_remote_loopback_port=args.remote_loopback_port,
        )
        settings.ensure_directories()
        database = Database(settings)
        database.create_all()
        orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
        device = orchestrator.device
        install = device._adb(["install", "-r", str(TARGET_APK)], timeout=120)
        if install.exit_code != 0:
            print(json.dumps({"install_error": install.stderr or install.stdout}))
            return 1
        target_sha = hashlib.sha256(TARGET_APK.read_bytes()).hexdigest()
        with database.session_factory() as session:
            scan = Scan(
                status="investigating",
                filename=TARGET_APK.name,
                artifact_sha256=target_sha,
                artifact_path=str(TARGET_APK),
                package_name="io.apkscanner.adaptivecases",
            )
            task = InvestigationTask(scan=scan, task_type="component", status="running")
            session.add_all([scan, task])
            session.commit()
            scan_id, task_id = scan.id, task.id
            fixture_id = None
            if args.controlled_canary:
                fixture = ValidationFixture(
                    scan_id=scan_id,
                    task_id=task_id,
                    name="protected-web-canary",
                    fixture_type="canary",
                    payload={
                        "state_check": {
                            "id": "target-installed",
                            "title": "Confirm the controlled target package is installed",
                            "phase": "assert",
                            "adb_args": ["shell", "pm", "path", "io.apkscanner.adaptivecases"],
                            "stdout_contains": ["package:"],
                        },
                    },
                )
                session.add(fixture)
                session.commit()
                fixture_id = fixture.id
        workspace = data_dir / "task"
        workspace.mkdir()
        (workspace / "context.json").write_text("{}", encoding="utf-8")
        context = LiveProofContext(
            token="web-smoke-token",
            scan_id=scan_id,
            task_id=task_id,
            package_name="io.apkscanner.adaptivecases",
            workspace=workspace,
            entries=[],
            default_entry_id="",
            hypotheses=[{"id": str(uuid4())}],
            budget=TimeBudget.from_seconds(360),
            evidence_summaries=[],
            cancel_event=threading.Event(),
            round_index=0,
            device=device,
        )
        orchestrator.register_live_proof_context(context)
        try:
            case_specs = (
                ("bridge-top", "web", "top"),
                ("safe-no-bridge", "safeweb", "top"),
                ("bridge-iframe", "web", "iframe"),
                ("bridge-redirect", "web", "redirect"),
            )
            results = [
                _run_case(
                    orchestrator,
                    context,
                    name=name,
                    host=host,
                    frame=frame,
                    fixture_id=fixture_id,
                )
                for name, host, frame in case_specs
                if args.case is None or args.case == name
            ]
            print(json.dumps({
                "device_serial": args.serial,
                "target_apk_sha256": target_sha,
                "artifact_directory": str(data_dir) if args.retain_artifacts else None,
                "scan_id": scan_id,
                "task_id": task_id,
                "results": results,
            }, indent=2))
            return 0 if all(item["passed"] for item in results) else 1
        finally:
            orchestrator.unregister_live_proof_context(task_id, context.token)
            if orchestrator._live_proof_server is not None:
                orchestrator._live_proof_server.shutdown()
                orchestrator._live_proof_server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
