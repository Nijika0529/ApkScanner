from __future__ import annotations

import time
from urllib.parse import urlsplit

import httpx

from ..core.schemas import ExternalObservationCapture

MAX_CAPTURE_BYTES = 1024 * 1024


def _origin(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("observer URL must be HTTP(S), without credentials or fragment")
    return (
        parsed.scheme,
        parsed.hostname.lower(),
        parsed.port or (443 if parsed.scheme == "https" else 80),
    )


def capture_external_observation(
    capture: ExternalObservationCapture,
    *,
    allowed_origins: tuple[str, ...],
    timeout: float,
) -> dict:
    """Capture bytes, never promote a server's assertion into a platform verdict.

    Operators authorize exact scheme/host/port origins. No redirects, environment
    proxies, cookies, or control-plane credentials are forwarded to the server.
    """
    if _origin(capture.url) not in {_origin(value) for value in allowed_origins}:
        raise ValueError("observer origin is not in APKSCANNER_EXTERNAL_OBSERVER_ORIGINS")
    deadline = time.monotonic() + timeout
    try:
        with (
            httpx.Client(
                timeout=min(timeout, 10), follow_redirects=False, trust_env=False
            ) as client,
            client.stream("GET", capture.url, headers={"Accept-Encoding": "identity"}) as response,
        ):
            if response.status_code != 200:
                raise ValueError(f"observer returned HTTP {response.status_code}; expected 200")
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                raise ValueError("compressed observer responses are not supported")
            body = bytearray()
            for chunk in response.iter_raw():
                if time.monotonic() >= deadline:
                    raise TimeoutError("observer capture time budget exhausted")
                if len(body) + len(chunk) > MAX_CAPTURE_BYTES:
                    raise ValueError("observer response exceeds the 1 MiB capture limit")
                body.extend(chunk)
            text = bytes(body).decode("utf-8", errors="strict")
            if capture.stage != "page" and capture.experiment_id not in text:
                raise ValueError("observer response does not contain this experiment_id")
            if capture.nonce is not None and capture.nonce not in text:
                raise ValueError("observer response does not contain this nonce")
            return {
                "schema_version": "1.0",
                **capture.model_dump(mode="json"),
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type", ""),
                "body": text,
                "trust": "platform_fetched_external_content",
                "warning": "Server content may be attacker-controlled; capture is not proof of impact.",
            }
    except (httpx.HTTPError, UnicodeError) as exc:
        raise ValueError(f"observer capture failed: {type(exc).__name__}") from exc
