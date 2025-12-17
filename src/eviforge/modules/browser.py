from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

from eviforge.config import load_settings
from eviforge.core.db import create_session_factory
from eviforge.core.models import Evidence
from eviforge.modules.base import ForensicModule


def _is_sqlite(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(16).startswith(b"SQLite format 3")
    except Exception:
        return False


def _chrome_time_to_iso(microseconds_since_1601: int | None) -> str | None:
    if not microseconds_since_1601:
        return None
    base = datetime(1601, 1, 1, tzinfo=timezone.utc)
    try:
        return (base + timedelta(microseconds=int(microseconds_since_1601))).isoformat()
    except Exception:
        return None


def _firefox_time_to_iso(microseconds_since_epoch: int | None) -> str | None:
    if not microseconds_since_epoch:
        return None
    try:
        return datetime.fromtimestamp(int(microseconds_since_epoch) / 1_000_000, tz=timezone.utc).isoformat()
    except Exception:
        return None


class BrowserModule(ForensicModule):
    @property
    def name(self) -> str:
        return "browser"

    @property
    def description(self) -> str:
        return "Parse browser SQLite artifacts (Chromium/Firefox best-effort; no decryption)."

    def run(self, case_id: str, evidence_id: str | None, **kwargs) -> Dict[str, Any]:
        if not evidence_id:
            raise ValueError("Missing evidence_id")

        settings = load_settings()
        SessionLocal = create_session_factory(settings.database_url)

        with SessionLocal() as session:
            ev = session.get(Evidence, evidence_id)
            if not ev:
                raise ValueError(f"Evidence {evidence_id} not found")
            file_path = settings.vault_dir / ev.path

        if not file_path.exists():
            raise FileNotFoundError(f"Evidence file not found at {file_path}")

        if not _is_sqlite(file_path):
            return {"status": "skipped", "reason": "Not a SQLite database"}

        limit = int(kwargs.get("limit", 500))
        history: list[dict[str, Any]] = []
        tables: list[str] = []

        with tempfile.NamedTemporaryFile(prefix=f"eviforge_browser_{evidence_id}_", suffix=".sqlite", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            shutil.copy2(file_path, tmp_path)
            conn = sqlite3.connect(str(tmp_path))
            try:
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = sorted([r[0] for r in cur.fetchall() if r and r[0]])

                # Chromium: urls table
                try:
                    cur.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT ?", (limit,))
                    for url, title, visit_count, last_visit_time in cur.fetchall():
                        history.append(
                            {
                                "browser": "chromium",
                                "url": url,
                                "title": title,
                                "visit_count": int(visit_count or 0),
                                "last_visit_time_raw": last_visit_time,
                                "last_visit_time": _chrome_time_to_iso(last_visit_time),
                            }
                        )
                except Exception:
                    pass

                # Firefox: moz_places
                try:
                    cur.execute(
                        "SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT ?",
                        (limit,),
                    )
                    for url, title, visit_count, last_visit_date in cur.fetchall():
                        history.append(
                            {
                                "browser": "firefox",
                                "url": url,
                                "title": title,
                                "visit_count": int(visit_count or 0),
                                "last_visit_time_raw": last_visit_date,
                                "last_visit_time": _firefox_time_to_iso(last_visit_date),
                            }
                        )
                except Exception:
                    pass
            finally:
                conn.close()
        finally:
            try:
                tmp_path.unlink(missing_ok=True)  # py3.11+
            except Exception:
                pass

        case_vault = settings.vault_dir / case_id
        artifact_dir = case_vault / "artifacts" / "browser"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        output_file = artifact_dir / f"{evidence_id}.json"
        output_file.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "success",
                    "evidence_id": evidence_id,
                    "tables": tables,
                    "history_count": len(history),
                    "history": history,
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        return {"status": "success", "history_count": len(history), "output_file": str(output_file)}

