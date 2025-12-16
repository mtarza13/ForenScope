from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from eviforge.core.auth import ack_dependency, get_current_active_user, require_roles, User
from eviforge.config import load_settings
from eviforge.core.db import create_session_factory
from eviforge.core.models import Case, Evidence
from eviforge.core.ingest import ingest_file
from eviforge.core.audit import audit_from_user

router = APIRouter(dependencies=[Depends(ack_dependency), Depends(get_current_active_user)])


class IngestRequest(BaseModel):
    filename: str  # File must be in the configured /import directory


@router.post("/{case_id}/evidence")
def ingest_evidence(request: Request, case_id: str, req: IngestRequest, _user: User = Depends(require_roles("admin", "analyst"))):
    settings = load_settings()
    
    # Restrict ingest to the /import directory (mapped via docker)
    # or allow absolute paths if running locally in dev mode
    # For MVP safety, let's look in expected import path first.
    
    # We'll assume an environment variable or default for imports, or just use a convention.
    # Docker compose maps ./../import -> /import.
    import_root = Path("/import")
    if not import_root.exists():
        # Fallback for local dev (cwd/import)
        import_root = Path.cwd() / "import"
        
    filename = req.filename.strip()
    # Enforce safe filename (no path separators)
    if not filename or filename != Path(filename).name or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    source_path = (import_root / filename).resolve()
    
    # Security check: ensure we haven't traversed out of import_root (unless we want to allow arbitrary paths? User provided "read-only" constraint).
    # Since this is local tool, maybe arbitrary paths are fine?
    # "Evidence ingest (copy default)"
    # Prompt says: "bind mount `./import` for user evidence imports"
    # So we should default to looking there.
    
    try:
        import_root_resolved = import_root.resolve()
    except Exception:
        import_root_resolved = import_root

    if import_root_resolved not in source_path.parents and source_path != import_root_resolved:
        raise HTTPException(status_code=403, detail="Access denied")

    if not source_path.exists() or not source_path.is_file():
        raise HTTPException(status_code=404, detail=f"File not found in import directory: {filename}")
        
    SessionLocal = create_session_factory(settings.database_url)
    with SessionLocal() as session:
        # Verify case exists
        case = session.get(Case, case_id)
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        
        try:
            evidence = ingest_file(session, settings, case_id, source_path, user=_user.username)

            try:
                audit_from_user(
                    session,
                    action="evidence.ingest",
                    user=_user,
                    request=request,
                    case_id=case_id,
                    evidence_id=evidence.id,
                    details={"filename": filename, "sha256": evidence.sha256, "md5": evidence.md5, "size": evidence.size_bytes},
                )
            except Exception:
                pass

            session.commit()
            return {
                "id": evidence.id,
                "name": Path(evidence.path).name,
                "md5": evidence.md5,
                "sha256": evidence.sha256,
                "size": evidence.size_bytes
            }
        except Exception as e:
            session.rollback()
            raise HTTPException(status_code=500, detail=str(e))


@router.get("/{case_id}/evidence")
def list_case_evidence(case_id: str):
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    
    with SessionLocal() as session:
        ev_items = session.query(Evidence).filter(Evidence.case_id == case_id).order_by(Evidence.ingested_at.desc()).all()
        
        res = []
        for ev in ev_items:
            res.append({
                "id": ev.id,
                "filename": Path(ev.path).name,
                "size": ev.size_bytes,
                "ingested_at": ev.ingested_at.isoformat(),
                "hashes": {"sha256": ev.sha256, "md5": ev.md5},
                "vault_relpath": ev.path
            })
        return res
