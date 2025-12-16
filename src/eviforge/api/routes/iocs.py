from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime

from eviforge.core.db import create_session_factory
from eviforge.core.models import IOC, Case, IOCMatch, Entity, Finding
from eviforge.config import load_settings
from eviforge.core.auth import ack_dependency, get_current_active_user, require_roles, User

router = APIRouter(prefix="/cases/{case_id}/iocs", tags=["iocs"], dependencies=[Depends(ack_dependency), Depends(get_current_active_user)])

class IOCCreate(BaseModel):
    type: str # ip, domain, md5
    value: str
    confidence: str = "high"
    tags: Optional[str] = None

class IOCResponse(IOCCreate):
    id: str
    created_at: datetime

    class Config:
        from_attributes = True

@router.post("/", response_model=IOCResponse)
def add_ioc(case_id: str, ioc: IOCCreate, _user: User = Depends(require_roles("admin", "analyst"))):
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    
    with SessionLocal() as session:
        # Check case existence
        case = session.get(Case, case_id)
        if not case:
             raise HTTPException(status_code=404, detail="Case not found")
             
        # Add IOC
        new_ioc = IOC(
            case_id=case_id,
            type=ioc.type,
            value=ioc.value,
            confidence=ioc.confidence,
            tags=ioc.tags
        )
        session.add(new_ioc)
        session.commit()
        session.refresh(new_ioc)
        
        # Trigger Match (Sync for UX?)
        # For now, let's trigger match immediately so UI updates
        from eviforge.core.indexer import Indexer
        idx = Indexer(session)
        idx.match_iocs(case_id)
        
        return new_ioc

@router.get("/", response_model=List[IOCResponse])
def list_iocs(case_id: str):
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    
    with SessionLocal() as session:
        iocs = session.query(IOC).filter(IOC.case_id == case_id).all()
        return iocs

@router.get("/matches")
def list_matches(case_id: str):
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    
    with SessionLocal() as session:
        # Join Matches with IOC and Entity for context
        results = session.query(IOCMatch, IOC, Entity).join(IOC, IOCMatch.ioc_id == IOC.id).outerjoin(Entity, IOCMatch.entity_id == Entity.id).filter(IOCMatch.case_id == case_id).all()
        
        out = []
        for match, ioc, ent in results:
            out.append({
                "id": match.id,
                "ioc_value": ioc.value,
                "ioc_type": ioc.type,
                "entity_value": ent.value if ent else "N/A",
                "evidence_id": match.evidence_id,
                "created_at": match.created_at
            })
        return out
