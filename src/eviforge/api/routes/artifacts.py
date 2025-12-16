from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse

from eviforge.config import load_settings
from eviforge.core.auth import ack_dependency, get_current_active_user, User
from eviforge.core.audit import audit_from_user
from eviforge.core.db import create_session_factory

router = APIRouter(dependencies=[Depends(ack_dependency), Depends(get_current_active_user)])


def _safe_artifact_path(case_id: str, safe_path: str) -> Path:
    if not safe_path or safe_path.startswith("/"):
        raise HTTPException(status_code=400, detail="Invalid path")
    if "\\" in safe_path:
        raise HTTPException(status_code=400, detail="Invalid path")

    # disallow traversal
    parts = [p for p in safe_path.split("/") if p]
    if any(p in (".", "..") for p in parts):
        raise HTTPException(status_code=400, detail="Invalid path")

    settings = load_settings()
    case_root = (settings.vault_dir / case_id).resolve()
    artifacts_root = (case_root / "artifacts").resolve()

    target = (artifacts_root / "/".join(parts)).resolve()
    if artifacts_root not in target.parents and target != artifacts_root:
        raise HTTPException(status_code=403, detail="Access denied")

    return target


@router.get("/artifacts/{case_id}/{safe_path:path}")
def get_artifact(
    request: Request,
    case_id: str,
    safe_path: str,
    current_user: User = Depends(get_current_active_user),
):
    target = _safe_artifact_path(case_id, safe_path)
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    try:
        settings = load_settings()
        SessionLocal = create_session_factory(settings.database_url)
        with SessionLocal() as session:
            audit_from_user(
                session,
                action="artifact.download",
                user=current_user,
                request=request,
                case_id=case_id,
                details={"path": safe_path},
            )
            session.commit()
    except Exception:
        pass
    return FileResponse(path=str(target), filename=target.name)
