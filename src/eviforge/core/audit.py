from __future__ import annotations

import json
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from eviforge.core.db import utcnow
from eviforge.core.models import AuditLog, User


def write_audit_log(
    session: Session,
    *,
    action: str,
    actor: str,
    actor_role: str | None = None,
    case_id: str | None = None,
    evidence_id: str | None = None,
    job_id: str | None = None,
    request: Request | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    ip = None
    user_agent = None
    if request is not None:
        ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

    row = AuditLog(
        ts=utcnow(),
        action=action,
        actor=actor,
        actor_role=actor_role,
        case_id=case_id,
        evidence_id=evidence_id,
        job_id=job_id,
        ip=ip,
        user_agent=user_agent,
        details_json=json.dumps(details or {}, sort_keys=True),
    )
    session.add(row)


def audit_from_user(
    session: Session,
    *,
    action: str,
    user: User,
    request: Request | None = None,
    case_id: str | None = None,
    evidence_id: str | None = None,
    job_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    write_audit_log(
        session,
        action=action,
        actor=user.username,
        actor_role=user.role,
        request=request,
        case_id=case_id,
        evidence_id=evidence_id,
        job_id=job_id,
        details=details,
    )
