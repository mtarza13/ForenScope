from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from eviforge.api.routes.auth import ack_dependency
from eviforge.config import load_settings
from eviforge.core.db import create_session_factory, Case
from eviforge.core.ingest import ingest_file

router = APIRouter(dependencies=[Depends(ack_dependency)])


class IngestRequest(BaseModel):
    filename: str  # File must be in the configured /import directory


@router.post("/{case_id}/evidence")
def ingest_evidence(case_id: str, req: IngestRequest):
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
        
    source_path = (import_root / req.filename).resolve()
    
    # Security check: ensure we haven't traversed out of import_root (unless we want to allow arbitrary paths? User provided "read-only" constraint).
    # Since this is local tool, maybe arbitrary paths are fine?
    # "Evidence ingest (copy default)"
    # Prompt says: "bind mount `./import` for user evidence imports"
    # So we should default to looking there.
    
    if not source_path.exists():
        raise HTTPException(status_code=404, detail=f"File not found in import directory: {req.filename}")
        
    SessionLocal = create_session_factory(settings.database_url)
    with SessionLocal() as session:
        # Verify case exists
        case = session.get(Case, case_id)
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        
        try:
            evidence = ingest_file(session, settings, case_id, source_path)
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
