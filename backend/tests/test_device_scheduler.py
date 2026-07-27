from __future__ import annotations

import threading
from dataclasses import replace

from apkscanner.device import (
    AdbDeviceAdapter,
    DeviceLeaseCancelledError,
    SingleDeviceScheduler,
)


def test_single_device_scheduler_orders_waiters_by_priority_then_fifo() -> None:
    scheduler = SingleDeviceScheduler()
    active_acquired = threading.Event()
    release_active = threading.Event()
    low_queued = threading.Event()
    high_queued = threading.Event()
    acquisition_order: list[str] = []

    def hold_active() -> None:
        with scheduler.lease(
            "active",
            priority=50,
            cancel_event=threading.Event(),
            on_acquired=lambda _waited: active_acquired.set(),
        ):
            assert release_active.wait(timeout=5)

    def wait_for_device(
        task_id: str,
        priority: int,
        queued: threading.Event,
    ) -> None:
        with scheduler.lease(
            task_id,
            priority=priority,
            cancel_event=threading.Event(),
            on_queued=lambda _position: queued.set(),
        ):
            acquisition_order.append(task_id)

    active = threading.Thread(target=hold_active)
    active.start()
    assert active_acquired.wait(timeout=5)

    low = threading.Thread(target=wait_for_device, args=("low", 70, low_queued))
    high = threading.Thread(target=wait_for_device, args=("high", 95, high_queued))
    low.start()
    assert low_queued.wait(timeout=5)
    high.start()
    assert high_queued.wait(timeout=5)

    snapshot = scheduler.snapshot()
    assert [item["task_id"] for item in snapshot["waiting"]] == ["high", "low"]
    release_active.set()
    for worker in (active, low, high):
        worker.join(timeout=5)
        assert not worker.is_alive()
    assert acquisition_order == ["high", "low"]
    assert scheduler.snapshot() == {"active_task_id": None, "waiting": []}


def test_waiting_device_lease_can_be_cancelled_without_acquiring() -> None:
    scheduler = SingleDeviceScheduler()
    active_acquired = threading.Event()
    release_active = threading.Event()
    waiting_queued = threading.Event()
    cancel_event = threading.Event()
    cancelled: list[bool] = []
    acquired: list[bool] = []

    def hold_active() -> None:
        with scheduler.lease(
            "active",
            priority=50,
            cancel_event=threading.Event(),
            on_acquired=lambda _waited: active_acquired.set(),
        ):
            assert release_active.wait(timeout=5)

    def wait_and_cancel() -> None:
        try:
            with scheduler.lease(
                "waiting",
                priority=90,
                cancel_event=cancel_event,
                on_queued=lambda _position: waiting_queued.set(),
            ):
                acquired.append(True)
        except DeviceLeaseCancelledError:
            cancelled.append(True)

    active = threading.Thread(target=hold_active)
    active.start()
    assert active_acquired.wait(timeout=5)
    waiting = threading.Thread(target=wait_and_cancel)
    waiting.start()
    assert waiting_queued.wait(timeout=5)

    cancel_event.set()
    scheduler.wake_waiters()
    waiting.join(timeout=5)
    assert not waiting.is_alive()
    assert cancelled == [True]
    assert acquired == []
    assert scheduler.snapshot()["waiting"] == []

    release_active.set()
    active.join(timeout=5)
    assert not active.is_alive()


def test_health_capability_does_not_enter_an_active_device_session(settings) -> None:  # noqa: ANN001
    class NoAdbRunner:
        @staticmethod
        def available(_name: str) -> bool:
            return True

        @staticmethod
        def run(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN205
            raise AssertionError("health check must not run ADB during an active lease")

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        NoAdbRunner(),  # type: ignore[arg-type]
    )
    acquired = threading.Event()
    release = threading.Event()

    def hold_device() -> None:
        with adapter.task_lease(
            "active",
            priority=90,
            cancel_event=threading.Event(),
            on_acquired=lambda _waited: acquired.set(),
        ):
            assert release.wait(timeout=5)

    worker = threading.Thread(target=hold_device)
    worker.start()
    assert acquired.wait(timeout=5)
    capability = adapter.capability(non_blocking=True)
    assert capability["available"] is True
    assert capability["busy"] is True
    assert capability["active_task_id"] == "active"
    release.set()
    worker.join(timeout=5)
    assert not worker.is_alive()
