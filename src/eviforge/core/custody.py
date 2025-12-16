from __future__ import annotations

import hashlib
from datetime import datetime
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from eviforge.core.models import ChainOfCustody
from eviforge.core.db import utcnow


def calculate_entry_hash(
    case_id: str,
    user: str,
    action: str,
    details: str,
    timestamp: datetime,
    prev_hash: str | None
) -> str:
    """
    Calculate SHA256 hash for a custody entry to ensure tamper-evidence.
    Hash = SHA256(case_id + user + action + details + iso_timestamp + prev_hash)
    """
    payload = f"{case_id}{user}{action}{details}{timestamp.isoformat()}{prev_hash or ''}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_action(
    session: Session,
    case_id: str,
    user: str,
    action: str,
    details: str = ""
) -> ChainOfCustody:
    """
    Append a new entry to the chain of custody for a specific case.
    """
    # Find the last entry for this case to get the previous hash
    last_entry = session.execute(
         select(ChainOfCustody)
         .where(ChainOfCustody.case_id == case_id)
         .order_by(ChainOfCustody.timestamp.desc())
         .limit(1)
    ).scalar_one_or_none()

    prev_hash = last_entry.curr_hash if last_entry else None
    ts = utcnow()
    
    curr_hash = calculate_entry_hash(case_id, user, action, details, ts, prev_hash)

    entry = ChainOfCustody(
        case_id=case_id,
        user=user,
        action=action,
        details=details,
        timestamp=ts,
        prev_hash=prev_hash,
        curr_hash=curr_hash
    )
    
    session.add(entry)
    return entry
