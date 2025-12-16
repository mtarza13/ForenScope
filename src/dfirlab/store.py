from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from .db import connect, init_db
from .json_utils import canonical_json


def fetch_evidence(db_path: Path, *, label: str | None = None) -> list[sqlite3.Row]:
    init_db(db_path)
    conn = connect(db_path)
    try:
        if label:
            return list(conn.execute("SELECT * FROM evidence WHERE label=? ORDER BY id", (label,)).fetchall())
        return list(conn.execute("SELECT * FROM evidence ORDER BY id").fetchall())
    finally:
        conn.close()


def fetch_items(db_path: Path, *, label: str | None = None) -> list[sqlite3.Row]:
    init_db(db_path)
    conn = connect(db_path)
    try:
        if label:
            return list(
                conn.execute(
                    """
                    SELECT
                      items.id AS item_id,
                      evidence.label AS evidence_label,
                      evidence.kind AS evidence_kind,
                      evidence.mode AS evidence_mode,
                      evidence.source AS evidence_source,
                      items.rel_path,
                      items.abs_path,
                      items.size,
                      items.mtime,
                      items.ctime,
                      items.atime,
                      items.sha256,
                      items.md5,
                      items.type_guess
                    FROM items
                    JOIN evidence ON evidence.id = items.evidence_id
                    WHERE evidence.label = ?
                    ORDER BY items.id
                    """,
                    (label,),
                ).fetchall()
            )
        return list(
            conn.execute(
                """
                SELECT
                  items.id AS item_id,
                  evidence.label AS evidence_label,
                  evidence.kind AS evidence_kind,
                  evidence.mode AS evidence_mode,
                  evidence.source AS evidence_source,
                  items.rel_path,
                  items.abs_path,
                  items.size,
                  items.mtime,
                  items.ctime,
                  items.atime,
                  items.sha256,
                  items.md5,
                  items.type_guess
                FROM items
                JOIN evidence ON evidence.id = items.evidence_id
                ORDER BY items.id
                """
            ).fetchall()
        )
    finally:
        conn.close()


def insert_finding(
    db_path: Path,
    *,
    item_id: int | None,
    kind: str,
    severity: str,
    title: str,
    details: dict[str, Any],
    created_at: str,
) -> int:
    init_db(db_path)
    conn = connect(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO findings(item_id,kind,severity,title,details_json,created_at) VALUES(?,?,?,?,?,?)",
            (item_id, kind, severity, title, canonical_json(details), created_at),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()
