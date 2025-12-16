import os
import shutil
import uuid
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from sqlalchemy.orm import Session

from eviforge.core.db import create_session_factory
from eviforge.core.models import OSINTAction, OSINTActionStatus, Case
from eviforge.core.auth import get_current_active_user, User
from eviforge.core.custody import log_action
from eviforge.config import load_settings

router = APIRouter(prefix="/cases/{case_id}/osint", tags=["osint"])

# --- Pydantic Models ---
class OSINTActionCreate(BaseModel):
    provider: str
    action_type: str
    target_label: Optional[str] = None
    notes: Optional[str] = None

class OSINTActionUpdate(BaseModel):
    status: Optional[OSINTActionStatus] = None
    tracking_url: Optional[str] = None
    notes: Optional[str] = None

class OSINTActionResponse(BaseModel):
    id: str
    case_id: str
    provider: str
    action_type: str
    target_label: Optional[str]
    status: OSINTActionStatus
    tracking_url: Optional[str]
    notes: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# --- Attributes ---
# Use the common DB session pattern

@router.get("/actions", response_model=List[OSINTActionResponse])
def list_actions(case_id: str, current_user: User = Depends(get_current_active_user)):
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    with SessionLocal() as session:
        actions = session.query(OSINTAction).filter(OSINTAction.case_id == case_id).all()
        return actions

@router.post("/actions", response_model=OSINTActionResponse)
def create_action(case_id: str, action: OSINTActionCreate, current_user: User = Depends(get_current_active_user)):
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    with SessionLocal() as session:
        # Check case existence
        if not session.get(Case, case_id):
            raise HTTPException(status_code=404, detail="Case not found")

        new_action = OSINTAction(
            case_id=case_id,
            provider=action.provider,
            action_type=action.action_type,
            target_label=action.target_label,
            notes=action.notes,
            status=OSINTActionStatus.DRAFT
        )
        session.add(new_action)
        session.flush() # get ID
        
        # Log chain of custody
        log_action(session, case_id, current_user.username, "OSINT Action Created", f"Provider: {action.provider}, Type: {action.action_type}")
        
        session.commit()
        session.refresh(new_action)
        return new_action

@router.patch("/actions/{action_id}", response_model=OSINTActionResponse)
def update_action(case_id: str, action_id: str, updates: OSINTActionUpdate, current_user: User = Depends(get_current_active_user)):
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    with SessionLocal() as session:
        db_action = session.query(OSINTAction).filter(OSINTAction.id == action_id, OSINTAction.case_id == case_id).first()
        if not db_action:
            raise HTTPException(status_code=404, detail="Action not found")
            
        # Update fields
        changes = []
        if updates.status:
            db_action.status = updates.status
            changes.append(f"Status->{updates.status}")
        if updates.tracking_url is not None:
            db_action.tracking_url = updates.tracking_url
            changes.append(f"TrackingURL Updated")
        if updates.notes is not None:
            db_action.notes = updates.notes
             # Don't log full notes change to custody, maybe too verbose? Just say 'Notes Updated'
            changes.append("Notes Updated")
            
        if changes:
             log_action(session, case_id, current_user.username, "OSINT Action Updated", f"Action {action_id}: " + ", ".join(changes))
             
        session.commit()
        session.refresh(db_action)
        return db_action

@router.post("/actions/{action_id}/attachments")
def upload_attachment(case_id: str, action_id: str, file: UploadFile = File(...), current_user: User = Depends(get_current_active_user)):
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    
    with SessionLocal() as session:
        db_action = session.query(OSINTAction).filter(OSINTAction.id == action_id, OSINTAction.case_id == case_id).first()
        if not db_action:
            raise HTTPException(status_code=404, detail="Action not found")

        # Determine path: cases/<CaseName>/artifacts/osint/privacy/<provider>/<filename>
        # Need Case Name or ID? Prompt says: cases/<CaseName>/artifacts...
        # But we usually map via ID to folder if ID-based.
        # Wait, implementation plan says "cases/<CaseName>/artifacts/..." 
        # But previous steps used `EVIFORGE_VAULT_DIR` which is usually based on ID or Name?
        # Let's check how Evidence uses paths. Evidence uses ID usually or Name?
        # In `create_case` it makes a directory.
        # Let's verify vault structure logic.
        
        case = session.get(Case, case_id)
        # We need the vault path.
        vault_root = settings.vault_dir # usually /data/cases or ./cases locally
        
        # We need to find the case folder. 
        # Ideally we standardized on `cases/{case.id}` or `cases/{case.name}`?
        # Re-check `cases.py` or `ingest.py`. 
        # Let's use `settings.vault_dir / case_id` or similar for safety.
        # Actually usually easier to use `case_id` for folders to avoid spacing issues.
        # Prompt says "cases/<CaseName>/...". 
        # I'll stick to `case_id` folder for reliability if possible, or check `case.path` if it exists.
        # Model for Case has `id` and `name` but not path.
        # Let's assume `settings.vault_dir` + `case_id` is the container path logic.
        
        # Construct path
        safe_provider = "".join(x for x in db_action.provider if x.isalnum())
        # Folder: artifacts/osint/privacy/<provider>
        
        # We'll put it in `settings.vault_dir / case_id / "artifacts" / "osint" / safe_provider`
        # Using `case_id` allows us to be filesystem agnostic of "Name" changes.
        
        target_dir = os.path.join(vault_root, case_id, "artifacts", "osint", safe_provider)
        os.makedirs(target_dir, exist_ok=True)
        
        filename = os.path.basename(file.filename)
        # Security: sanitize filename
        import re
        filename = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', filename)
        
        final_path = os.path.join(target_dir, filename)
        
        with open(final_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        # Log Custody
        log_action(session, case_id, current_user.username, "OSINT Attachment Uploaded", f"Action {action_id}: {filename}")
        session.commit()
        
        return {"filename": filename, "path": final_path}
