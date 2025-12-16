from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from eviforge.api.routes.auth import ack_dependency
from eviforge.config import load_settings
from eviforge.core.db import Case, create_session_factory

router = APIRouter(dependencies=[Depends(ack_dependency)])


class CaseCreate(BaseModel):
    name: str


@router.get("")
def list_cases():
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    with SessionLocal() as session:
        rows = session.query(Case).order_by(Case.created_at.desc()).all()
        return [{"id": c.id, "name": c.name, "created_at": c.created_at.isoformat()} for c in rows]


@router.post("")
def create_case(req: CaseCreate):
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    
    # Ensure vault root exists
    settings.vault_dir.mkdir(parents=True, exist_ok=True)
    
    with SessionLocal() as session:
        case = Case(name=req.name)
        session.add(case)
        session.flush()  # get ID
        
        # Initialize vault for this case
        case_vault = settings.vault_dir / case.id
        (case_vault / "evidence").mkdir(parents=True, exist_ok=True)
        (case_vault / "artifacts").mkdir(parents=True, exist_ok=True)
        (case_vault / "manifests").mkdir(parents=True, exist_ok=True)
        
        # Log creation
        from eviforge.core.custody import log_action
        log_action(session, case.id, "system", "Case Created", f"Case '{req.name}' initialized")
        
        session.commit()
        return {"id": case.id, "name": case.name, "created_at": case.created_at.isoformat()}
