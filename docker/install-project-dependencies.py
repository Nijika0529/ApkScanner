from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path


def main() -> None:
    configuration = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    build_requirements = configuration["build-system"]["requires"]
    runtime_requirements = configuration["project"]["dependencies"]
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-cache-dir",
            *build_requirements,
            *runtime_requirements,
        ],
        check=True,
    )


if __name__ == "__main__":
    main()
