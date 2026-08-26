from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .core.config import Settings
from .core.db import Database
from .core.enums import ScanStatus
from .core.models import Scan
from .platform.api import router
from .platform.artifacts import ArtifactStore
from .platform.capabilities import CapabilityRegistry
from .platform.operator_service import PlatformOperatorService
from .runtime.orchestrator import ScanOrchestrator
from .runtime.supervisor import SupervisorService


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or Settings.from_env()
    app_settings.ensure_directories()
    database = Database(app_settings)
    database.create_all()
    store = ArtifactStore(app_settings)
    orchestrator = ScanOrchestrator(app_settings, database, store)
    capability_registry = CapabilityRegistry(orchestrator)
    supervisor = SupervisorService(orchestrator, capability_registry)
    platform_operator = PlatformOperatorService(database, store, orchestrator)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        application.state.background_tasks = set()
        orchestrator.recover_interrupted_device_tasks()

        async def reconcile_campaigns() -> None:
            while True:
                try:
                    launched = await asyncio.to_thread(supervisor.advance_all)
                    for launched_scan_id in launched:
                        task = asyncio.create_task(
                            orchestrator.submit(launched_scan_id),
                            name=f"campaign-scan-{launched_scan_id}",
                        )
                        application.state.background_tasks.add(task)
                        task.add_done_callback(application.state.background_tasks.discard)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    # A malformed external capability must not kill the persistent
                    # supervisor; its campaign entry records the failure on reconcile.
                    pass
                await asyncio.sleep(2)

        supervisor_task = asyncio.create_task(
            reconcile_campaigns(),
            name="campaign-supervisor",
        )
        application.state.background_tasks.add(supervisor_task)
        supervisor_task.add_done_callback(application.state.background_tasks.discard)
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
        supervisor_task.cancel()
        await asyncio.gather(supervisor_task, return_exceptions=True)
        orchestrator.shutdown()
        pending = list(application.state.background_tasks)
        if pending:
            _done, still_pending = await asyncio.wait(pending, timeout=10)
            pending = list(still_pending)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    app = FastAPI(
        title="APK Scanner",
        version="0.1.0",
        description="Evidence-first APK security scanning and pluggable AI investigation control plane",
        lifespan=lifespan,
    )
    app.state.settings = app_settings
    app.state.database = database
    app.state.store = store
    app.state.orchestrator = orchestrator
    app.state.capability_registry = capability_registry
    app.state.supervisor = supervisor
    app.state.platform_operator = platform_operator
    app.state.background_tasks = set()
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=os.environ.get(
            "APKSCANNER_ALLOWED_HOSTS",
            "127.0.0.1,localhost,[::1],testserver",
        ).split(","),
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
            # Asset filenames are content-hashed, but index.html selects the
            # current hashes and must be revalidated after every local rebuild.
            return FileResponse(
                frontend_dist / "index.html",
                headers={"Cache-Control": "no-cache"},
            )

    return app


app = create_app()
