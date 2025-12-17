from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from eviforge.config import load_settings
from eviforge.core.db import create_session_factory
from eviforge.core.models import Evidence
from eviforge.modules.base import ForensicModule


KNOWN_HIVES = {"NTUSER.DAT", "SYSTEM", "SOFTWARE", "SAM", "SECURITY", "USRCLASS.DAT", "AMCACHE.HVE"}


def _try_open(reg, key_path: str):
    try:
        return reg.open(key_path)
    except Exception:
        return None


class RegistryModule(ForensicModule):
    @property
    def name(self) -> str:
        return "registry"

    @property
    def description(self) -> str:
        return "Parse Windows Registry hives (optional dependency: python-registry)."

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

        hive_name = file_path.name.upper()
        if hive_name not in KNOWN_HIVES:
            return {"status": "skipped", "reason": "Not a recognized Registry hive filename", "filename": file_path.name}

        try:
            from Registry import Registry  # type: ignore
        except Exception:
            return {
                "status": "skipped",
                "reason": "python-registry not installed (integration not enabled)",
                "how_to_enable": "Install python-registry in the worker environment (or run docker worker image).",
            }

        results: dict[str, Any] = {"hive": hive_name, "extracted": {}}
        try:
            reg = Registry.Registry(str(file_path))
        except Exception as e:
            return {"status": "failed", "error": f"Registry parse failed: {e}"}

        # Targeted extraction only (keep output bounded).
        if hive_name in {"NTUSER.DAT", "SOFTWARE"}:
            for key_path in (
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            ):
                k = _try_open(reg, key_path)
                if not k:
                    continue
                vals = []
                for v in k.values():
                    try:
                        vals.append({"name": v.name(), "value": str(v.value())[:500]})
                    except Exception:
                        continue
                results["extracted"][key_path] = vals

        if hive_name == "SOFTWARE":
            k = _try_open(reg, r"Microsoft\Windows NT\CurrentVersion")
            if k:
                meta = {}
                for wanted in ("ProductName", "CurrentBuild", "CurrentVersion", "RegisteredOwner", "InstallationType"):
                    try:
                        meta[wanted] = str(k.value(wanted).value())[:500]
                    except Exception:
                        continue
                results["extracted"]["CurrentVersion"] = meta

        if hive_name == "SYSTEM":
            sel = _try_open(reg, r"Select")
            if sel:
                select = {}
                for wanted in ("Current", "Default", "LastKnownGood"):
                    try:
                        select[wanted] = int(sel.value(wanted).value())
                    except Exception:
                        continue
                results["extracted"]["Select"] = select

        case_vault = settings.vault_dir / case_id
        artifact_dir = case_vault / "artifacts" / "registry"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        output_file = artifact_dir / f"{evidence_id}.json"
        output_file.write_text(json.dumps(results, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        return {
            "status": "success",
            "keys_extracted": list(results.get("extracted", {}).keys()),
            "output_file": str(output_file),
        }

