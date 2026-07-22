from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .api import router
from .artifacts import ArtifactStore
from .config import Settings
from .db import Database
from .enums import ScanStatus
from .models import Scan
from .orchestrator import ScanOrchestrator


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or Settings.from_env()
    app_settings.ensure_directories()
    database = Database(app_settings)
    database.create_all()
    store = ArtifactStore(app_settings)
    orchestrator = ScanOrchestrator(app_settings, database, store)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        application.state.background_tasks = set()
        with database.session_factory() as session:
            resumable = list(
                session.scalars(
                    select(Scan.id).where(
                        Scan.status.in_(
                            {
                                ScanStatus.QUEUED.value,
                                ScanStatus.STATIC_RUNNING.value,
                                ScanStatus.STATIC_COMPLETE.value,
                                ScanStatus.INVESTIGATING.value,
                                ScanStatus.PRELIMINARY_READY.value,
                            }
                        )
                    )
                )
            )
        for scan_id in resumable:
            task = asyncio.create_task(orchestrator.submit(scan_id), name=f"resume-{scan_id}")
            application.state.background_tasks.add(task)
            task.add_done_callback(application.state.background_tasks.discard)
        yield
        pending = list(application.state.background_tasks)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    app = FastAPI(
        title="APK Scanner",
        version="0.1.0",
        description="Evidence-first APK security scanning and Codex investigation control plane",
        lifespan=lifespan,
    )
    app.state.settings = app_settings
    app.state.database = database
    app.state.store = store
    app.state.orchestrator = orchestrator
    app.state.background_tasks = set()
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["127.0.0.1", "localhost", "[::1]", "testserver"],
    )

    @app.middleware("http")
    async def protect_local_mutations(request, call_next):  # noqa: ANN001, ANN202
        mutating_api = request.url.path.startswith("/api/") and request.method in {
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }
        if mutating_api and request.headers.get("x-apkscanner-request") != "console":
            return JSONResponse(
                {"detail": "Missing local-console request marker"}, status_code=403
            )
        return await call_next(request)

    app.include_router(router)

    frontend_dist = app_settings.frontend_dist
    if frontend_dist and frontend_dist.exists():
        assets = frontend_dist / "assets"
        if assets.exists():
            app.mount("/assets", StaticFiles(directory=assets), name="assets")

        @app.get("/{route:path}", include_in_schema=False)
        def frontend(route: str):  # noqa: ANN202
            candidate = (frontend_dist / route).resolve()
            if candidate.is_relative_to(frontend_dist) and candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(frontend_dist / "index.html")

    return app


app = create_app()
