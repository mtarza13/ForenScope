from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .custody import append_entry
from .db import init_db


@dataclass(frozen=True)
class Case:
    path: Path
    case_name: str
    case_id: str
    created_at: str
    investigator: str
    org: str

    @property
    def case_json_path(self) -> Path:
        return self.path / "case.json"

    @property
    def custody_log_path(self) -> Path:
        return self.path / "chain_of_custody.log"

    @property
    def db_path(self) -> Path:
        return self.path / "db" / "dfirlab.sqlite"


def _case_layout_dirs(case_path: Path) -> list[Path]:
    return [
        case_path / "vault" / "evidence",
        case_path / "vault" / "images",
        case_path / "vault" / "manifests",
        case_path / "db",
        case_path / "artifacts" / "verification",
        case_path / "artifacts" / "triage",
        case_path / "artifacts" / "inventory",
        case_path / "artifacts" / "timeline",
        case_path / "artifacts" / "carve",
        case_path / "artifacts" / "bulk_extractor",
        case_path / "artifacts" / "exif",
        case_path / "artifacts" / "registry",
        case_path / "artifacts" / "evtx",
        case_path / "artifacts" / "browser",
        case_path / "artifacts" / "email",
        case_path / "artifacts" / "memory",
        case_path / "artifacts" / "pcap",
        case_path / "artifacts" / "ids",
        case_path / "artifacts" / "yara",
        case_path / "artifacts" / "search",
        case_path / "artifacts" / "reports",
    ]


def create_case(
    *,
    root: Path,
    case_name: str,
    investigator: str,
    org: str,
    actor: str,
) -> Case:
    if not case_name or case_name.strip() != case_name:
        raise ValueError("CASE_NAME must be non-empty and not start/end with whitespace.")
    if any(sep in case_name for sep in ("/", "\\", "..")):
        raise ValueError("CASE_NAME must not contain path separators.")

    case_path = root / case_name
    case_path.mkdir(parents=True, exist_ok=False)
    for d in _case_layout_dirs(case_path):
        d.mkdir(parents=True, exist_ok=True)

    case_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    payload: dict[str, Any] = {
        "schema_version": 1,
        "dfirlab_version": __version__,
        "case_name": case_name,
        "case_id": case_id,
        "created_at": created_at,
        "investigator": investigator,
        "org": org,
    }
    (case_path / "case.json").write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    init_db(case_path / "db" / "dfirlab.sqlite")
    append_entry(
        case_path / "chain_of_custody.log",
        actor=actor,
        action="case_init",
        details={"case_name": case_name, "case_id": case_id, "investigator": investigator, "org": org},
    )
    return Case(path=case_path, case_name=case_name, case_id=case_id, created_at=created_at, investigator=investigator, org=org)


def load_case(case_path: Path) -> Case:
    data = json.loads((case_path / "case.json").read_text(encoding="utf-8"))
    return Case(
        path=case_path,
        case_name=data["case_name"],
        case_id=data["case_id"],
        created_at=data["created_at"],
        investigator=data.get("investigator", ""),
        org=data.get("org", ""),
    )


def ensure_case_layout(case_path: Path) -> None:
    for d in _case_layout_dirs(case_path):
        d.mkdir(parents=True, exist_ok=True)
