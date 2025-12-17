from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

from eviforge.config import load_settings
from eviforge.core.db import create_session_factory
from eviforge.core.models import Evidence
from eviforge.modules.base import ForensicModule


def _repo_root() -> Path:
    # .../src/eviforge/modules/yara.py -> repo root is 3 parents up.
    return Path(__file__).resolve().parents[3]


def _default_rules_dir() -> Path:
    # Prefer Docker path, then repo path, then data_dir path.
    candidates = [
        Path(os.getenv("EVIFORGE_YARA_RULES_DIR", "")).expanduser(),
        Path("/app/rules/yara"),
        _repo_root() / "rules" / "yara",
        load_settings().data_dir / "rules" / "yara",
    ]
    for c in candidates:
        if str(c) and c.exists() and c.is_dir():
            return c
    return candidates[2]  # repo default


def _iter_rule_files(rules_dir: Path) -> list[Path]:
    out: list[Path] = []
    for pat in ("*.yar", "*.yara"):
        out.extend(sorted(rules_dir.glob(pat)))
    return out


class YaraModule(ForensicModule):
    @property
    def name(self) -> str:
        return "yara"

    @property
    def description(self) -> str:
        return "Scan evidence with YARA rules (optional integration; local rules only)."

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

        rules_dir = _default_rules_dir()
        rule_files = _iter_rule_files(rules_dir)
        if not rule_files:
            return {
                "status": "skipped",
                "reason": "No YARA rules found",
                "rules_dir": str(rules_dir),
                "how_to_enable": "Place .yar/.yara rules in the rules directory or set EVIFORGE_YARA_RULES_DIR.",
            }

        try:
            import yara  # type: ignore
        except Exception:
            return {
                "status": "skipped",
                "reason": "yara-python not installed (integration not enabled)",
                "rules_dir": str(rules_dir),
                "how_to_enable": "Install yara-python in the worker environment (or run the docker worker image).",
            }

        # Compile rules
        filepaths = {p.name: str(p) for p in rule_files}
        try:
            rules = yara.compile(filepaths=filepaths)
        except Exception as e:
            return {
                "status": "failed",
                "error": f"Failed to compile YARA rules: {e}",
                "rules_dir": str(rules_dir),
            }

        max_files = int(kwargs.get("max_files", 2000))
        max_file_size_mb = int(kwargs.get("max_file_size_mb", 200))
        max_file_size = max_file_size_mb * 1024 * 1024

        targets: list[Path] = []
        if file_path.is_file():
            targets = [file_path]
        else:
            for p in sorted(file_path.rglob("*")):
                if not p.is_file():
                    continue
                targets.append(p)
                if len(targets) >= max_files:
                    break

        matches_out: list[dict[str, Any]] = []
        skipped_large = 0
        for p in targets:
            try:
                if p.stat().st_size > max_file_size:
                    skipped_large += 1
                    continue
            except Exception:
                continue
            try:
                matches = rules.match(str(p))
            except Exception:
                continue
            for m in matches:
                matches_out.append(
                    {
                        "target": str(p.relative_to(settings.vault_dir)),
                        "rule": m.rule,
                        "tags": list(m.tags),
                        "meta": dict(m.meta),
                        "strings_sample": [(s[0], s[1], str(s[2])) for s in (m.strings or [])[:10]],
                    }
                )

        case_vault = settings.vault_dir / case_id
        artifact_dir = case_vault / "artifacts" / "yara"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        output_file = artifact_dir / f"{evidence_id}.json"

        payload = {
            "schema_version": 1,
            "status": "success",
            "evidence_id": evidence_id,
            "rules_dir": str(rules_dir),
            "rule_files": [p.name for p in rule_files],
            "yara_version": getattr(yara, "__version__", None),
            "targets_scanned": len(targets) - skipped_large,
            "targets_skipped_large": skipped_large,
            "matches": matches_out,
        }

        output_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return {
            "status": "success",
            "matches_count": len(matches_out),
            "output_file": str(output_file),
        }
