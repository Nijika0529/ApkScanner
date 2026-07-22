from __future__ import annotations

from apkscanner.main import create_app
from fastapi.testclient import TestClient


def test_local_api_requires_console_marker_for_mutations(settings) -> None:  # noqa: ANN001
    app = create_app(settings)
    with TestClient(app) as client:
        assert client.get("/api/v1/health").status_code == 200
        blocked = client.post(
            "/api/v1/scans",
            files={"apk": ("sample.apk", b"not-an-apk", "application/octet-stream")},
        )
        assert blocked.status_code == 403
        accepted_request = client.post(
            "/api/v1/scans",
            headers={"X-APKScanner-Request": "console"},
            files={"apk": ("sample.txt", b"not-an-apk", "application/octet-stream")},
        )
        assert accepted_request.status_code == 415
