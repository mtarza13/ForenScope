from __future__ import annotations

from typing import Any
import json
import uuid
from datetime import datetime

from redis import Redis
from rq import Queue
from sqlalchemy.orm import Session

from eviforge.core.models import Job, JobStatus
from eviforge.core.db import utcnow
from eviforge.config import Settings


def enqueue_job(
    session: Session,
    settings: Settings,
    case_id: str,
    tool_name: str,
    params: dict[str, Any] | None = None
) -> Job:
    """
    Create a Job record and enqueue it in Redis.
    """
    if params is None:
        params = {}
    
    # Ensure case_id is available to the module
    params["case_id"] = case_id

    evidence_id = params.get("evidence_id")

    job_id = str(uuid.uuid4())
    
    # 1. Create DB Record
    job = Job(
        id=job_id,
        case_id=case_id,
        evidence_id=evidence_id,
        tool_name=tool_name,
        status=JobStatus.PENDING,
        queued_at=utcnow(),
        created_at=utcnow(),
        params_json=json.dumps(params, sort_keys=True),
    )
    session.add(job)
    session.flush() # Ensure ID is reserved

    # 2. Enqueue in Redis
    # We pass the job_id to the worker so it can look up the DB record
    # The actual function to call is a generic 'run_module' wrapper
    redis_conn = Redis.from_url(settings.redis_url)
    q = Queue(connection=redis_conn)
    
    # We enqueue 'eviforge.worker.execute_module_task'
    # This function must be importable by the worker
    rq_job = q.enqueue(
        "eviforge.worker.execute_module_task",
        job_id,
        job_timeout="1h",
    )

    job.rq_job_id = rq_job.id
    
    return job


def update_job_status(
    session: Session,
    job_id: str,
    status: JobStatus,
    result: dict | None = None,
    error: str | None = None
) -> None:
    """
    Update the status of a job.
    """
    job = session.get(Job, job_id)
    if not job:
        return
        
    job.status = status
    if result is not None:
        job.result_json = json.dumps(result)
    if error is not None:
        job.error_message = error
        
    if status in (JobStatus.COMPLETED, JobStatus.FAILED):
        job.completed_at = utcnow()
        
    session.add(job)
    session.commit()
