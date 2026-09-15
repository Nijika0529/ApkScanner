from __future__ import annotations

import threading
import time
from dataclasses import replace

import pytest
from apkscanner.runtime.codex_runner import CodexInvestigator
from apkscanner.runtime.concurrency import ResizableSemaphore

SCAN_ID = "00000000-0000-0000-0000-000000000201"
OTHER_SCAN_ID = "00000000-0000-0000-0000-000000000202"


def test_resizable_semaphore_bounds_concurrent_holders() -> None:
    semaphore = ResizableSemaphore(2)
    assert semaphore.limit == 2
    assert semaphore.acquire(timeout=0.1) is True
    assert semaphore.acquire(timeout=0.1) is True
    assert semaphore.in_use == 2

    started = time.monotonic()
    assert semaphore.acquire(timeout=0.2) is False
    assert time.monotonic() - started >= 0.15

    semaphore.release()
    assert semaphore.acquire(timeout=0.1) is True
    assert semaphore.in_use == 2


def test_resizable_semaphore_raise_wakes_waiter_immediately() -> None:
    semaphore = ResizableSemaphore(1)
    assert semaphore.acquire(timeout=0.1) is True
    acquired: list[bool] = []

    def waiter() -> None:
        acquired.append(semaphore.acquire(timeout=2.0))

    thread = threading.Thread(target=waiter)
    thread.start()
    time.sleep(0.05)
    assert acquired == []

    assert semaphore.set_limit(2) == 2
    thread.join(timeout=2.0)
    assert acquired == [True]
    assert semaphore.in_use == 2


def test_resizable_semaphore_lowering_never_preempts_holders() -> None:
    semaphore = ResizableSemaphore(3)
    assert all(semaphore.acquire(timeout=0.1) for _ in range(3))

    assert semaphore.set_limit(1) == 1
    assert semaphore.in_use == 3
    assert semaphore.acquire(timeout=0.05) is False

    semaphore.release()
    semaphore.release()
    assert semaphore.in_use == 1
    assert semaphore.acquire(timeout=0.05) is False
    semaphore.release()
    assert semaphore.in_use == 0
    assert semaphore.acquire(timeout=0.05) is True


def test_resizable_semaphore_rejects_invalid_limits_and_over_release() -> None:
    with pytest.raises(ValueError):
        ResizableSemaphore(0)
    semaphore = ResizableSemaphore(1)
    with pytest.raises(ValueError):
        semaphore.set_limit(0)
    with pytest.raises(ValueError):
        semaphore.release()


def test_scan_session_limit_follows_device_bound_concurrency(settings) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        codex_max_sessions=8,
        codex_max_sessions_per_scan=2,
    )
    configured.ensure_directories()
    investigator = CodexInvestigator(configured)
    try:
        assert investigator._effective_scan_session_limit(SCAN_ID) == 2

        investigator.set_scan_session_limit(SCAN_ID, 5)
        assert investigator._effective_scan_session_limit(SCAN_ID) == 5
        # Scan ceilings stay independent from each other.
        assert investigator._effective_scan_session_limit(OTHER_SCAN_ID) == 2

        # The global Codex worker budget remains a hard upper bound.
        investigator.set_scan_session_limit(SCAN_ID, 32)
        assert investigator._effective_scan_session_limit(SCAN_ID) == 8

        investigator.set_scan_session_limit(SCAN_ID, None)
        assert investigator._effective_scan_session_limit(SCAN_ID) == 2
    finally:
        investigator.shutdown()
