from __future__ import annotations

import signal
import threading


def main() -> None:
    stopping = threading.Event()

    def stop(_signum: int, _frame: object) -> None:
        stopping.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping.wait(60):
        pass


if __name__ == "__main__":
    main()
