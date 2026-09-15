"""Process-wide resource tokens whose capacity can follow the live device pool.

The investigation pool admits tasks from a snapshot of the connected ADB devices,
but the device pool changes while a scan is running (``POST /api/v1/devices``,
draining, reconnect).  ``threading.BoundedSemaphore`` fixes its capacity at
construction time, so a device-bound admission policy needs a token whose limit
can be re-sized between admission decisions.
"""

from __future__ import annotations

import threading
import time


class ResizableSemaphore:
    """Counting semaphore with a runtime-adjustable limit.

    Lowering the limit never preempts holders: in-flight acquisitions finish and
    the surplus drains as permits are released.  Raising the limit wakes queued
    waiters immediately.
    """

    def __init__(self, limit: int) -> None:
        if int(limit) < 1:
            raise ValueError("semaphore limit must be at least 1")
        self._condition = threading.Condition()
        self._limit = int(limit)
        self._in_use = 0

    @property
    def limit(self) -> int:
        with self._condition:
            return self._limit

    @property
    def in_use(self) -> int:
        with self._condition:
            return self._in_use

    def set_limit(self, limit: int) -> int:
        """Apply a new capacity and return it; queued waiters are re-evaluated."""
        limit = int(limit)
        if limit < 1:
            raise ValueError("semaphore limit must be at least 1")
        with self._condition:
            if limit == self._limit:
                return limit
            self._limit = limit
            self._condition.notify_all()
            return limit

    def acquire(self, timeout: float | None = None) -> bool:
        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        with self._condition:
            while self._in_use >= self._limit:
                if deadline is None:
                    self._condition.wait()
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            self._in_use += 1
            return True

    def release(self) -> None:
        with self._condition:
            if self._in_use <= 0:
                raise ValueError("semaphore released too many times")
            self._in_use -= 1
            self._condition.notify()
