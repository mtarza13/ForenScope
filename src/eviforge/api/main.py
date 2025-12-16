from __future__ import annotations

from fastapi import FastAPI

from eviforge.api.routes.auth import router as auth_router
from eviforge.api.routes.cases import router as cases_router
from eviforge.api.routes.evidence import router as evidence_router
from eviforge.api.routes.health import router as health_router
from eviforge.api.routes.jobs import router as jobs_router
from eviforge.api.routes.iocs import router as iocs_router
from eviforge.api.routes.webdev import router as web_router

from eviforge.api.routes.artifacts import router as artifacts_router


from contextlib import asynccontextmanager
from eviforge.config import load_settings
from eviforge.core.db import create_session_factory

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure DB tables exist
    settings = load_settings()
    create_session_factory(settings.database_url)
    yield
    # Shutdown

def create_app() -> FastAPI:
    app = FastAPI(title="EviForge", lifespan=lifespan)

    # API
    app.include_router(health_router, prefix="/api")
    app.include_router(auth_router, prefix="/api")
    app.include_router(cases_router, prefix="/api/cases", tags=["cases"])
    app.include_router(evidence_router, prefix="/api/cases", tags=["evidence"])
    app.include_router(jobs_router, prefix="/api/jobs", tags=["jobs"])
    app.include_router(artifacts_router, prefix="/api", tags=["artifacts"])
    app.include_router(iocs_router, prefix="/api")

    # Web UI
    app.include_router(web_router, prefix="/web", tags=["web"])

    from fastapi.staticfiles import StaticFiles
    from pathlib import Path
    static_dir = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    return app


app = create_app()

# Internal revision 0

# Internal revision 3

# Internal revision 10

# Internal revision 14

# Internal revision 17

# Internal revision 19

# Internal revision 23

# Internal revision 24

# Internal revision 34

# Internal revision 37

# Internal revision 47

# Internal revision 50

# Internal revision 54

# Internal revision 64

# Internal revision 67

# Internal revision 69

# Internal revision 73

# Internal revision 77

# Internal revision 78

# Internal revision 82

# Rev 1

# Rev 4

# Rev 7

# Rev 8

# Rev 11

# Rev 22

# Rev 24

# Rev 30

# Rev 36

# Rev 51

# Rev 55

# Rev 69

# Rev 71

# Rev 72
