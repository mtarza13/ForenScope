from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class CustodyEntry:
    timestamp: str
    actor: str
    action: str
    details: dict[str, Any]
    prev_hash: str
    entry_hash: str

    def to_json(self) -> str:
        return _canonical_json(
            {
                "timestamp": self.timestamp,
                "actor": self.actor,
                "action": self.action,
                "details": self.details,
                "prev_hash": self.prev_hash,
                "entry_hash": self.entry_hash,
            }
        )


def compute_entry_hash(
    *,
    timestamp: str,
    actor: str,
    action: str,
    details: dict[str, Any],
    prev_hash: str,
) -> str:
    payload = {"timestamp": timestamp, "actor": actor, "action": action, "details": details, "prev_hash": prev_hash}
    return _sha256_hex(_canonical_json(payload).encode("utf-8"))


def read_entries(log_path: Path) -> list[CustodyEntry]:
    if not log_path.exists():
        return []
    entries: list[CustodyEntry] = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        entries.append(
            CustodyEntry(
                timestamp=obj["timestamp"],
                actor=obj["actor"],
                action=obj["action"],
                details=obj.get("details", {}),
                prev_hash=obj["prev_hash"],
                entry_hash=obj["entry_hash"],
            )
        )
    return entries


def verify_hash_chain(entries: Iterable[CustodyEntry]) -> tuple[bool, str | None]:
    prev_hash = "0" * 64
    for idx, entry in enumerate(entries):
        if entry.prev_hash != prev_hash:
            return False, f"prev_hash mismatch at index {idx}"
        expected = compute_entry_hash(
            timestamp=entry.timestamp,
            actor=entry.actor,
            action=entry.action,
            details=entry.details,
            prev_hash=entry.prev_hash,
        )
        if entry.entry_hash != expected:
            return False, f"entry_hash mismatch at index {idx}"
        prev_hash = entry.entry_hash
    return True, None


def append_entry(log_path: Path, *, actor: str, action: str, details: dict[str, Any]) -> CustodyEntry:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entries = read_entries(log_path)
    ok, reason = verify_hash_chain(entries)
    if not ok:
        raise ValueError(f"Chain-of-custody log failed verification: {reason}")
    prev_hash = entries[-1].entry_hash if entries else "0" * 64
    timestamp = datetime.now(timezone.utc).isoformat()
    entry_hash = compute_entry_hash(
        timestamp=timestamp,
        actor=actor,
        action=action,
        details=details,
        prev_hash=prev_hash,
    )
    entry = CustodyEntry(
        timestamp=timestamp,
        actor=actor,
        action=action,
        details=details,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    with log_path.open("a", encoding="utf-8") as f:
        f.write(entry.to_json() + "\n")
    return entry
