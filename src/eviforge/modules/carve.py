from typing import Any, Dict
import json
import shutil
import subprocess
from pathlib import Path

from eviforge.modules.base import ForensicModule
from eviforge.config import load_settings
from eviforge.core.db import create_session_factory
from eviforge.core.models import Evidence

class CarveModule(ForensicModule):
    @property
    def name(self) -> str:
        return "carve"

    @property
    def description(self) -> str:
        return "Carve files using Foremost"

    def run(self, case_id: str, evidence_id: str, **kwargs) -> Dict[str, Any]:
        settings = load_settings()
        SessionLocal = create_session_factory(settings.database_url)
        
        with SessionLocal() as session:
            ev = session.get(Evidence, evidence_id)
            if not ev:
                raise ValueError(f"Evidence {evidence_id} not found")
            file_path = settings.vault_dir / ev.path
            
        if not file_path.exists():
             raise FileNotFoundError(f"Evidence file not found at {file_path}")

        # Artifact Dir
        case_vault = settings.vault_dir / case_id
        artifact_dir = case_vault / "artifacts" / "carve"
        output_subdir = artifact_dir / evidence_id
        output_subdir.mkdir(parents=True, exist_ok=True)

        foremost = shutil.which("foremost")
        if not foremost:
            return {
                "status": "skipped",
                "reason": "foremost not found in PATH (integration not enabled)",
                "how_to_enable": "Install foremost in the worker/tools container or on the host PATH.",
            }

        try:
            # Foremost
            # foremost -i <input> -o <output>
            # -T timestamp the directory? No we want predictable path
            # It will create 'output_subdir/audit.txt'
            
            cmd = [foremost, "-i", str(file_path), "-o", str(output_subdir)]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            
        except subprocess.CalledProcessError as e:
            return {"status": "failed", "error": f"Foremost failed (exit={e.returncode})", "stderr": (e.stderr or "")[:2000]}

        # Summarize results
        # Foremost creates directories like jpg/, png/ inside output_subdir
        recovered_stats = {}
        total = 0
        for p in output_subdir.glob("*"):
            if p.is_dir():
                count = len(list(p.glob("*")))
                recovered_stats[p.name] = count
                total += count

        summary = {
            "tool": "foremost",
            "cmd": cmd,
            "total_recovered": total,
            "types": recovered_stats,
            "output_dir": str(output_subdir)
        }
        
        output_file = artifact_dir / f"{evidence_id}_summary.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        return {
            "status": "success",
            "recovered": total,
            "output_file": str(output_file)
        }
