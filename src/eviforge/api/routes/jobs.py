from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from eviforge.core.auth import ack_dependency, get_current_active_user, User
from eviforge.config import load_settings
from eviforge.core.db import create_session_factory
from eviforge.core.models import Job, JobStatus

router = APIRouter(dependencies=[Depends(ack_dependency), Depends(get_current_active_user)])

class JobResponse(BaseModel):
    id: str
    case_id: str
    evidence_id: Optional[str] = None
    tool: str
    status: JobStatus
    queued_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    result_preview: Optional[dict[str, Any]] = None
    output_files: list[str] = []
    error: Optional[str] = None

    class Config:
        from_attributes = True


@router.get("/{job_id}", response_model=JobResponse)
def get_job_details(job_id: str, current_user: User = Depends(get_current_active_user)):
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    
    with SessionLocal() as session:
        job = session.get(Job, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        
        import json

        preview = None
        if job.result_preview_json:
            try:
                preview = json.loads(job.result_preview_json)
            except Exception:
                preview = None

        output_files: list[str] = []
        if job.output_files_json:
            try:
                output_files = json.loads(job.output_files_json) or []
            except Exception:
                output_files = []

        return JobResponse(
            id=job.id,
            case_id=job.case_id,
            evidence_id=job.evidence_id,
            tool=job.tool_name,
            status=job.status,
            queued_at=job.queued_at,
            started_at=job.started_at,
            completed_at=job.completed_at,
            stdout=job.stdout_text,
            stderr=job.stderr_text,
            result_preview=preview,
            output_files=output_files,
            error=job.error_message,
        )
