from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from .json_utils import canonical_json
from .db import connect


def record_action(db_path: Path, *, timestamp: str, actor: str, action: str, details: dict[str, Any]) -> None:
    conn = connect(db_path)
    try:
        conn.execute(
            "INSERT INTO actions(timestamp, actor, action, details_json) VALUES(?,?,?,?)",
            (timestamp, actor, action, canonical_json(details)),
        )
        conn.commit()
    finally:
        conn.close()


def fetch_actions(db_path: Path, *, limit: int | None = None) -> list[sqlite3.Row]:
    conn = connect(db_path)
    try:
        q = "SELECT id, timestamp, actor, action, details_json FROM actions ORDER BY id"
        if limit is not None:
            q += " LIMIT ?"
            rows = conn.execute(q, (int(limit),)).fetchall()
        else:
            rows = conn.execute(q).fetchall()
        return list(rows)
    finally:
        conn.close()
