from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .actions import record_action
from .case import ensure_case_layout, load_case
from .custody import append_entry
from .db import init_db
from .paths import resolve_item_path
from .store import fetch_items
from .time_utils import now_utc_iso


@dataclass(frozen=True)
class InventoryResult:
    label: str | None
    total_items: int
    json_path: Path
    csv_path: Path
    created_at: str


def build_inventory(*, case_path: Path, label: str | None, actor: str) -> InventoryResult:
    case_path = case_path.resolve()
    _ = load_case(case_path)
    ensure_case_layout(case_path)
    db_path = case_path / "db" / "dfirlab.sqlite"
    init_db(db_path)

    created_at = now_utc_iso()
    safe_ts = created_at.replace(":", "").replace("+", "").replace("-", "")
    items = fetch_items(db_path, label=label)
    payload: list[dict[str, Any]] = []
    for r in items:
        resolved_path = resolve_item_path(case_path, r)
        payload.append(
            {
                "item_id": int(r["item_id"]),
                "evidence_label": str(r["evidence_label"]),
                "evidence_kind": str(r["evidence_kind"]),
                "rel_path": str(r["rel_path"]),
                "abs_path": str(resolved_path),
                "size": int(r["size"]),
                "mtime": r["mtime"],
                "ctime": r["ctime"],
                "atime": r["atime"],
                "sha256": r["sha256"],
                "md5": r["md5"],
                "type_guess": r["type_guess"],
            }
        )

    out_dir = case_path / "artifacts" / "inventory"
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"inventory_{label or 'ALL'}_{safe_ts}"
    json_path = out_dir / f"{stem}.json"
    csv_path = out_dir / f"{stem}.csv"

    json_path.write_text(json.dumps({"schema_version": 1, "created_at": created_at, "label": label, "items": payload}, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with csv_path.open("w", encoding="utf-8", newline="") as f:
        fieldnames = ["item_id", "evidence_label", "evidence_kind", "rel_path", "abs_path", "size", "mtime", "ctime", "atime", "sha256", "md5", "type_guess"]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in payload:
            w.writerow(row)

    append_entry(
        case_path / "chain_of_custody.log",
        actor=actor,
        action="inventory",
        details={"label": label, "total_items": len(payload), "json_path": str(json_path), "csv_path": str(csv_path)},
    )
    record_action(
        db_path,
        timestamp=created_at,
        actor=actor,
        action="inventory",
        details={"label": label, "total_items": len(payload), "json_path": str(json_path), "csv_path": str(csv_path)},
    )

    return InventoryResult(label=label, total_items=len(payload), json_path=json_path, csv_path=csv_path, created_at=created_at)
