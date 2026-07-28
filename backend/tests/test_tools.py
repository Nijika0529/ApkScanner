from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest
from apkscanner.tools import CommandResult, TimeBudget, ToolRunner


def test_explicit_zero_timeout_does_not_fall_back_to_default(monkeypatch) -> None:  # noqa: ANN001
    observed: dict[str, int | None] = {}
    runner = ToolRunner(timeout_seconds=600)

    def fake_run(*_args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        observed["timeout"] = kwargs.get("timeout")
        return CommandResult([], 0, "", "")

    monkeypatch.setattr(runner, "_run_cancelable", fake_run)
    result = runner.run(
        [sys.executable, "-c", "pass"],
        timeout=0,
    )
    assert result.exit_code == 0
    assert observed["timeout"] == 0


def test_time_budget_can_exclude_shared_resource_queue_wait() -> None:
    budget = TimeBudget(deadline=100.0)
    assert budget.extend(12.5).deadline == 112.5
    assert budget.extend(12.5, maximum_deadline=105.0).deadline == 105.0
    assert budget.deadline == 100.0


def test_tool_runner_cancels_an_active_process_group() -> None:
    runner = ToolRunner(timeout_seconds=10)
    cancel_event = threading.Event()
    result_holder = []

    def run_command() -> None:
        result_holder.append(
            runner.run(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                cancel_event=cancel_event,
            )
        )

    started_at = time.monotonic()
    worker = threading.Thread(target=run_command)
    worker.start()
    time.sleep(0.15)
    cancel_event.set()
    worker.join(timeout=3)

    assert not worker.is_alive()
    assert time.monotonic() - started_at < 3
    assert result_holder[0].exit_code == 130
    assert result_holder[0].canceled is True


@pytest.mark.skipif(sys.platform != "linux", reason="uses Linux /proc process-state checks")
def test_tool_runner_timeout_kills_the_spawned_process_group() -> None:
    runner = ToolRunner(timeout_seconds=10)
    child_script = "import os, time; print(os.getpid(), flush=True); time.sleep(30)"
    parent_script = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {child_script!r}]); "
        "time.sleep(30)"
    )
    result = runner.run(
        [sys.executable, "-c", parent_script],
        timeout=0.2,
    )

    assert result.timed_out is True
    child_pid = int(result.stdout.strip())
    assert not _process_is_running(child_pid)


@pytest.mark.skipif(sys.platform != "linux", reason="uses Linux /proc process-state checks")
def test_tool_runner_cancellation_kills_the_spawned_process_group() -> None:
    runner = ToolRunner(timeout_seconds=10)
    cancel_event = threading.Event()
    result_holder = []
    child_script = "import os, time; print(os.getpid(), flush=True); time.sleep(30)"
    parent_script = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {child_script!r}]); "
        "time.sleep(30)"
    )

    def run_command() -> None:
        result_holder.append(
            runner.run(
                [sys.executable, "-c", parent_script],
                cancel_event=cancel_event,
            )
        )

    worker = threading.Thread(target=run_command)
    worker.start()
    time.sleep(0.2)
    cancel_event.set()
    worker.join(timeout=3)

    assert not worker.is_alive()
    assert result_holder and result_holder[0].canceled is True
    child_pid = int(result_holder[0].stdout.strip())
    assert not _process_is_running(child_pid)


def _process_is_running(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()[2]
    except (FileNotFoundError, ProcessLookupError):
        return False
    return state != "Z"
