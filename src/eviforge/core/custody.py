from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from eviforge.core.db import utcnow
from eviforge.core.models import ChainOfCustody


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


# --- File-based custody log (vault/<case_id>/chain_of_custody.log) ---


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class CustodyEntry:
    ts: str
    actor: str
    action: str
    details: dict[str, Any]
    prev_hash: str
    entry_hash: str


GENESIS_HASH = "0" * 64


def compute_entry_hash(payload: dict[str, Any]) -> str:
    return sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def iter_entries(log_path: Path) -> Iterable[CustodyEntry]:
    if not log_path.exists():
        return
    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            yield CustodyEntry(
                ts=obj["ts"],
                actor=obj["actor"],
                action=obj["action"],
                details=obj.get("details", {}),
                prev_hash=obj["prev_hash"],
                entry_hash=obj["entry_hash"],
            )


def last_entry_hash(log_path: Path) -> str | None:
    if not log_path.exists():
        return None
    last = None
    for last in iter_entries(log_path):
        pass
    return None if last is None else last.entry_hash


def append_entry(log_path: Path, *, actor: str, action: str, details: dict[str, Any]) -> CustodyEntry:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    prev_hash = last_entry_hash(log_path) or GENESIS_HASH

    payload = {
        "ts": _utc_now_iso(),
        "actor": actor,
        "action": action,
        "details": details,
        "prev_hash": prev_hash,
    }
    entry_hash = compute_entry_hash(payload)
    record = {**payload, "entry_hash": entry_hash}

    with log_path.open("a", encoding="utf-8") as f:
        f.write(_canonical_json(record) + "\n")

    return CustodyEntry(
        ts=payload["ts"],
        actor=actor,
        action=action,
        details=details,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )


def verify_chain(log_path: Path) -> tuple[bool, str]:
    prev = GENESIS_HASH
    index = 0
    for index, entry in enumerate(iter_entries(log_path), start=1):
        if entry.prev_hash != prev:
            return False, f"prev_hash mismatch at entry {index}"
        payload = {
            "ts": entry.ts,
            "actor": entry.actor,
            "action": entry.action,
            "details": entry.details,
            "prev_hash": entry.prev_hash,
        }
        expected = compute_entry_hash(payload)
        if entry.entry_hash != expected:
            return False, f"entry_hash mismatch at entry {index}"
        prev = entry.entry_hash
    return True, f"ok ({index} entries)"
