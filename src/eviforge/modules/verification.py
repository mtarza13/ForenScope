from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict

from eviforge.config import load_settings
from eviforge.core.db import create_session_factory
from eviforge.core.models import Evidence
from eviforge.modules.base import ForensicModule


class VerifyModule(ForensicModule):
    @property
    def name(self) -> str:
        return "verify"

    @property
    def description(self) -> str:
        return "Verify evidence integrity against stored hashes (MD5 + SHA-256)."

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
            stored_sha256 = ev.sha256
            stored_md5 = ev.md5

        if not file_path.exists():
            raise FileNotFoundError(f"Evidence file not found at {file_path}")

        # Re-hash
        h_sha256 = hashlib.sha256()
        h_md5 = hashlib.md5()
        with file_path.open("rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h_sha256.update(chunk)
                h_md5.update(chunk)

        current_sha256 = h_sha256.hexdigest()
        current_md5 = h_md5.hexdigest()

        ok = (stored_sha256 == current_sha256) and (stored_md5 == current_md5)
        result = {
            "schema_version": 1,
            "status": "success",
            "evidence_id": evidence_id,
            "integrity_ok": ok,
            "stored": {"sha256": stored_sha256, "md5": stored_md5},
            "current": {"sha256": current_sha256, "md5": current_md5},
        }

        case_vault = settings.vault_dir / case_id
        artifact_dir = case_vault / "artifacts" / "verification"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        output_file = artifact_dir / f"{evidence_id}.json"
        output_file.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        return {"status": "success", "integrity_ok": ok, "output_file": str(output_file)}

