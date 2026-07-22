from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from .config import Settings
from .rules import FindingDraft


@dataclass(slots=True)
class MobSFResult:
    report: dict[str, Any]
    findings: list[FindingDraft]
    metadata: dict[str, Any]


class MobSFAdapter:
    """Optional broad static scanner. Built-ins remain available when MobSF is absent."""

    def __init__(self, settings: Settings):
        self.settings = settings

    @property
    def configured(self) -> bool:
        return bool(self.settings.mobsf_url and self.settings.mobsf_api_key)

    def capability(self) -> dict[str, Any]:
        if not self.configured:
            return {
                "available": False,
                "detail": "APKSCANNER_MOBSF_URL and APKSCANNER_MOBSF_API_KEY are not configured",
            }
        try:
            base_url = self._base_url()
        except ValueError as exc:
            return {"available": False, "detail": str(exc)}
        return {"available": True, "endpoint": base_url}

    def scan(self, apk_path: Path, timeout_seconds: int | None = None) -> MobSFResult:
        if not self.configured:
            raise RuntimeError("MobSF is not configured")
        headers = {"Authorization": self.settings.mobsf_api_key or ""}
        requested = (
            self.settings.mobsf_timeout_seconds
            if timeout_seconds is None
            else timeout_seconds
        )
        per_request = max(
            1,
            min(self.settings.mobsf_timeout_seconds, requested) // 3,
        )
        timeout = httpx.Timeout(per_request)
        with httpx.Client(base_url=self._base_url(), headers=headers, timeout=timeout) as client:
            with apk_path.open("rb") as stream:
                upload = self._json(
                    client.post(
                        "/api/v1/upload",
                        files={"file": (apk_path.name, stream, "application/vnd.android.package-archive")},
                    )
                )
            required = ("hash", "scan_type", "file_name")
            missing = [name for name in required if not upload.get(name)]
            if missing:
                raise RuntimeError(f"MobSF upload response is missing: {', '.join(missing)}")
            scan_payload = {name: upload[name] for name in required}
            scan_response = self._json(client.post("/api/v1/scan", data=scan_payload))
            report = self._json(
                client.post("/api/v1/report_json", data={"hash": upload["hash"]}),
                max_bytes=100_000_000,
            )
        return MobSFResult(
            report=report,
            findings=self.normalize_findings(report),
            metadata={
                "hash": upload["hash"],
                "scan_type": upload["scan_type"],
                "file_name": upload["file_name"],
                "scan_response": {
                    key: scan_response.get(key)
                    for key in ("app_name", "package_name", "version_name", "status")
                    if key in scan_response
                },
            },
        )

    @staticmethod
    def normalize_findings(report: dict[str, Any]) -> list[FindingDraft]:
        candidates: list[tuple[str, dict[str, Any]]] = []
        manifest = report.get("manifest_analysis")
        if isinstance(manifest, dict):
            candidates.extend(
                ("manifest", item)
                for item in manifest.get("manifest_findings", [])
                if isinstance(item, dict)
            )
        elif isinstance(manifest, list):
            candidates.extend(("manifest", item) for item in manifest if isinstance(item, dict))

        code = report.get("code_analysis")
        if isinstance(code, dict) and isinstance(code.get("findings"), dict):
            for rule, value in code["findings"].items():
                if not isinstance(value, dict):
                    continue
                metadata = value.get("metadata") if isinstance(value.get("metadata"), dict) else {}
                candidates.append(
                    (
                        "code",
                        {
                            "rule": rule,
                            "title": metadata.get("description") or rule,
                            "description": metadata.get("description") or rule,
                            "severity": metadata.get("severity"),
                            "files": value.get("files"),
                            "cwe": metadata.get("cwe"),
                            "masvs": metadata.get("masvs"),
                        },
                    )
                )
        binary = report.get("binary_analysis")
        if isinstance(binary, list):
            candidates.extend(("binary", item) for item in binary if isinstance(item, dict))

        normalized: list[FindingDraft] = []
        seen: set[str] = set()
        for category, item in candidates[:2000]:
            rule = str(item.get("rule") or item.get("name") or item.get("title") or "UNKNOWN")
            stable_rule = re.sub(r"[^A-Za-z0-9_.-]+", "-", rule).strip("-")[:160] or "UNKNOWN"
            title = _plain(item.get("title") or item.get("description") or rule, 1000)
            description = _plain(item.get("description") or title, 8000)
            severity = str(item.get("severity") or "info").lower()
            severity = {
                "secure": "info",
                "warning": "medium",
                "error": "high",
                "informational": "info",
            }.get(severity, severity)
            if severity not in {"critical", "high", "medium", "low", "info"}:
                severity = "info"
            locations = _locations(item)
            signature = f"{category}:{stable_rule}:{title}:{locations[:3]}"
            if signature in seen:
                continue
            seen.add(signature)
            normalized.append(
                FindingDraft(
                    rule_id=f"MOBSF-{stable_rule}",
                    source="mobsf",
                    title=title,
                    description=description,
                    remediation=_plain(
                        item.get("remediation")
                        or "Review the referenced code or manifest configuration and apply the least-privilege fix.",
                        4000,
                    ),
                    masvs=_masvs(item),
                    severity=severity,
                    confidence="medium",
                    cwe=_plain(item.get("cwe"), 64) or None,
                    locations=locations,
                    metadata={"category": category, "upstream_rule": rule},
                )
            )
        return normalized

    def _base_url(self) -> str:
        value = (self.settings.mobsf_url or "").rstrip("/")
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("APKSCANNER_MOBSF_URL must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password:
            raise ValueError("MobSF credentials must not be embedded in the URL")
        return value

    @staticmethod
    def _json(response: httpx.Response, *, max_bytes: int = 10_000_000) -> dict[str, Any]:
        response.raise_for_status()
        if len(response.content) > max_bytes:
            raise RuntimeError("MobSF response exceeds the configured safety limit")
        payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError("MobSF returned a non-object JSON response")
        return payload


def _plain(value: Any, limit: int) -> str:
    if value is None:
        return ""
    text = re.sub(r"<[^>]+>", " ", str(value))
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _locations(item: dict[str, Any]) -> list[dict[str, Any]]:
    values: list[Any] = []
    for key in ("component", "files", "file", "path"):
        value = item.get(key)
        if isinstance(value, dict):
            values.extend(value.keys())
        elif isinstance(value, list):
            values.extend(value)
        elif value:
            values.append(value)
    return [{"path": _plain(value, 1000)} for value in values[:25] if _plain(value, 1000)]


def _masvs(item: dict[str, Any]) -> str:
    raw = str(item.get("masvs") or "").upper()
    for domain in (
        "MASVS-STORAGE",
        "MASVS-CRYPTO",
        "MASVS-AUTH",
        "MASVS-NETWORK",
        "MASVS-PLATFORM",
        "MASVS-CODE",
        "MASVS-RESILIENCE",
        "MASVS-PRIVACY",
    ):
        if domain in raw:
            return domain
    return "MASVS-CODE"
