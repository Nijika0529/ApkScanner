from __future__ import annotations

import sys
import threading
import time

from apkscanner.tools import ToolRunner


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
