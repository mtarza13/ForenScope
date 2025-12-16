from __future__ import annotations

import sqlite3
from pathlib import Path


CORE_SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS case_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL DEFAULT 'files' CHECK(kind IN ('files','image')),
  label TEXT NOT NULL UNIQUE,
  source TEXT NOT NULL,
  mode TEXT NOT NULL CHECK(mode IN ('copy','reference')),
  source_kind TEXT NOT NULL DEFAULT 'path' CHECK(source_kind IN ('path','archive','image')),
  vault_path TEXT,
  ingested_at TEXT NOT NULL,
  manifest_path TEXT NOT NULL,
  last_verified_at TEXT,
  last_verify_ok INTEGER,
  last_verify_report_path TEXT
);

CREATE TABLE IF NOT EXISTS custody_cache (
  id INTEGER PRIMARY KEY CHECK (id=1),
  last_entry_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
  rel_path TEXT NOT NULL,
  abs_path TEXT NOT NULL,
  size INTEGER NOT NULL,
  mtime REAL,
  ctime REAL,
  atime REAL,
  sha256 TEXT,
  md5 TEXT,
  type_guess TEXT,
  UNIQUE(evidence_id, rel_path)
);

CREATE TABLE IF NOT EXISTS tags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS item_tags (
  item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY (item_id, tag_id)
);

CREATE TABLE IF NOT EXISTS bookmarks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  note TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id INTEGER REFERENCES items(id) ON DELETE SET NULL,
  kind TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  details_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  details_json TEXT NOT NULL
);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path) -> None:
    conn = connect(db_path)
    try:
        conn.executescript(CORE_SCHEMA_SQL)
        _migrate(conn)
        _ensure_fts(conn)
        conn.commit()
    finally:
        conn.close()


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {str(r["name"]) for r in rows}


def _add_column_if_missing(conn: sqlite3.Connection, table: str, ddl: str, *, column: str) -> None:
    existing = _columns(conn, table)
    if column in existing:
        return
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def _migrate(conn: sqlite3.Connection) -> None:
    # Keep migrations minimal and additive.
    _add_column_if_missing(conn, "evidence", "kind TEXT NOT NULL DEFAULT 'files' CHECK(kind IN ('files','image'))", column="kind")
    _add_column_if_missing(conn, "evidence", "source_kind TEXT NOT NULL DEFAULT 'path' CHECK(source_kind IN ('path','archive','image'))", column="source_kind")
    _add_column_if_missing(conn, "evidence", "vault_path TEXT", column="vault_path")
    _add_column_if_missing(conn, "evidence", "last_verified_at TEXT", column="last_verified_at")
    _add_column_if_missing(conn, "evidence", "last_verify_ok INTEGER", column="last_verify_ok")
    _add_column_if_missing(conn, "evidence", "last_verify_report_path TEXT", column="last_verify_report_path")


def _ensure_fts(conn: sqlite3.Connection) -> None:
    # Prefer FTS5 when available; skip silently if not compiled in.
    try:
        conn.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS fts_items USING fts5(
              item_id UNINDEXED,
              rel_path,
              label,
              content
            )
            """
        )
    except sqlite3.OperationalError:
        return
