from __future__ import annotations

import subprocess
import sys
import threading
import time

from apkscanner.tools import TimeBudget, ToolRunner


def test_explicit_zero_timeout_does_not_fall_back_to_default(monkeypatch) -> None:  # noqa: ANN001
    observed: dict[str, int | None] = {}

    def fake_run(*_args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        observed["timeout"] = kwargs.get("timeout")
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = ToolRunner(timeout_seconds=600).run(
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
