from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from .artifacts import ArtifactStore
from .models import Evidence
from .tools import CommandResult


class EvidenceRecorder:
    def __init__(self, store: ArtifactStore):
        self.store = store

    def command(
        self,
        session: Session,
        *,
        scan_id: str,
        task_id: str | None,
        kind: str,
        result: CommandResult,
        metadata: dict[str, Any] | None = None,
    ) -> Evidence:
        payload = {
            "argv": result.argv,
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timed_out": result.timed_out,
            "canceled": result.canceled,
            "metadata": metadata or {},
        }
        digest, path = self.store.put_json("evidence", payload)
        evidence = Evidence(
            scan_id=scan_id,
            task_id=task_id,
            kind=kind,
            sha256=digest,
            path=str(path),
            command=result.argv,
            exit_code=result.exit_code,
            summary=self._summary(result),
            metadata_json=metadata or {},
        )
        session.add(evidence)
        session.flush()
        return evidence

    def json(
        self,
        session: Session,
        *,
        scan_id: str,
        task_id: str | None,
        kind: str,
        value: Any,
        summary: str,
        metadata: dict[str, Any] | None = None,
    ) -> Evidence:
        digest, path = self.store.put_bytes(
            "evidence",
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode(),
            suffix=".json",
        )
        evidence = Evidence(
            scan_id=scan_id,
            task_id=task_id,
            kind=kind,
            sha256=digest,
            path=str(path),
            summary=summary,
            metadata_json=metadata or {},
        )
        session.add(evidence)
        session.flush()
        return evidence

    @staticmethod
    def _summary(result: CommandResult) -> str:
        stream = result.stdout.strip() or result.stderr.strip()
        first_line = stream.splitlines()[0] if stream else "no output"
        return f"exit={result.exit_code}: {first_line[:500]}"
