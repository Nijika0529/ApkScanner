from __future__ import annotations

from typing import Literal

GATEWAY_ENVIRONMENT_NAMES = frozenset(
    {
        "APKSCANNER_ADB_TASK_ID",
        "APKSCANNER_ADB_GATEWAY_URL",
        "APKSCANNER_ADB_TOKEN",
        "APKSCANNER_ADB_POLICY",
        "APKSCANNER_PROOF_TASK_ID",
        "APKSCANNER_PROOF_REPLAY_URL",
        "APKSCANNER_PROOF_TOKEN",
        "APKSCANNER_OBSERVATION_URL",
        "APKSCANNER_OBSERVATION_TOKEN",
    }
)


def task_gateway_environment(
    *,
    task_id: str,
    base_url: str,
    token: str,
    adb_policy: Literal["scoped", "adaptive"] | None = None,
    proof_replay: bool,
) -> dict[str, str]:
    """Build the only environment contract accepted by a Codex worker."""

    base = base_url.rstrip("/")
    values = {
        "APKSCANNER_ADB_TASK_ID": task_id,
        "APKSCANNER_ADB_GATEWAY_URL": f"{base}/api/v1/internal/tasks/{task_id}/adb",
        "APKSCANNER_ADB_TOKEN": token,
        "APKSCANNER_OBSERVATION_URL": (
            f"{base}/api/v1/internal/tasks/{task_id}/observations"
        ),
        "APKSCANNER_OBSERVATION_TOKEN": token,
    }
    if adb_policy is not None:
        values["APKSCANNER_ADB_POLICY"] = adb_policy
    if proof_replay:
        values.update(
            {
                "APKSCANNER_PROOF_TASK_ID": task_id,
                "APKSCANNER_PROOF_REPLAY_URL": (
                    f"{base}/api/v1/internal/tasks/{task_id}/proof-replay"
                ),
                "APKSCANNER_PROOF_TOKEN": token,
            }
        )
    unknown = set(values) - GATEWAY_ENVIRONMENT_NAMES
    if unknown:  # pragma: no cover - protects future edits to this builder.
        raise RuntimeError(f"gateway contract emitted unknown names: {sorted(unknown)}")
    return values
