from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text
from redis import Redis

from eviforge.config import load_settings
from eviforge.core.db import create_session_factory

router = APIRouter()


@router.get("/health", tags=["health"])
def health():
    settings = load_settings()
    status = {"status": "ok", "db": "unknown", "redis": "unknown"}
    
    # Check DB
    try:
        SessionLocal = create_session_factory(settings.database_url)
        with SessionLocal() as session:
            session.execute(text("SELECT 1"))
        status["db"] = "connected"
    except Exception as e:
        status["db"] = f"error: {str(e)}"

    # Check Redis
    try:
        r = Redis.from_url(settings.redis_url)
        if r.ping():
            status["redis"] = "connected"
    except Exception as e:
        status["redis"] = f"error: {str(e)}"


    return status


@router.get("/health/tools", tags=["health"])
def health_tools():
    from eviforge.doctor import run_doctor
    return run_doctor()

