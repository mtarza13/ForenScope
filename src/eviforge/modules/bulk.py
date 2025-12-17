from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict

from eviforge.config import load_settings
from eviforge.core.db import create_session_factory
from eviforge.core.models import Evidence
from eviforge.modules.base import ForensicModule


class BulkExtractorModule(ForensicModule):
    @property
    def name(self) -> str:
        return "bulk"

    @property
    def description(self) -> str:
        return "Run bulk_extractor (feature extraction) on an evidence file (optional integration)."

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

        bulk = shutil.which("bulk_extractor")
        if not bulk:
            return {
                "status": "skipped",
                "reason": "bulk_extractor not found in PATH (integration not enabled)",
                "how_to_enable": "Install bulk_extractor in the worker/tools container or on the host PATH.",
            }

        case_vault = settings.vault_dir / case_id
        artifact_dir = case_vault / "artifacts" / "bulk_extractor"
        output_dir = artifact_dir / evidence_id
        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = [bulk, "-o", str(output_dir), "-q", str(file_path)]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            return {
                "status": "failed",
                "error": f"bulk_extractor failed (exit={e.returncode})",
                "stderr": (e.stderr or "")[:2000],
                "cmd": cmd,
            }

        # Summarize output: list feature files and sizes.
        files: list[dict[str, Any]] = []
        for p in sorted(output_dir.rglob("*")):
            if not p.is_file():
                continue
            try:
                st = p.stat()
                files.append(
                    {
                        "rel_path": str(p.relative_to(artifact_dir)),
                        "size": int(st.st_size),
                    }
                )
            except Exception:
                continue

        summary = {
            "tool": "bulk_extractor",
            "cmd": cmd,
            "stdout": (res.stdout or "")[:2000],
            "stderr": (res.stderr or "")[:2000],
            "output_dir": str(output_dir),
            "files": files,
        }

        artifact_dir.mkdir(parents=True, exist_ok=True)
        output_file = artifact_dir / f"{evidence_id}_summary.json"
        output_file.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        return {
            "status": "success",
            "output_file": str(output_file),
            "output_dir": str(output_dir),
            "files_count": len(files),
        }

