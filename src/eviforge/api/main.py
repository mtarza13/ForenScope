from __future__ import annotations

from fastapi import FastAPI

from eviforge.api.routes.auth import router as auth_router
from eviforge.api.routes.cases import router as cases_router
from eviforge.api.routes.health import router as health_router


def create_app() -> FastAPI:
    app = FastAPI(title="EviForge")

    app.include_router(health_router)
    app.include_router(auth_router, prefix="/auth", tags=["auth"])
    app.include_router(cases_router, prefix="/cases", tags=["cases"])
    
    from eviforge.api.routes.evidence import router as evidence_router
    app.include_router(evidence_router, prefix="/cases", tags=["evidence"])

    return app


app = create_app()
