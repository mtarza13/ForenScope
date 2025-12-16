from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .actions import record_action
from .case import ensure_case_layout, load_case
from .custody import append_entry
from .db import init_db
from .store import fetch_items
from .time_utils import now_utc_iso


def _ns_to_iso(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc).isoformat()


@dataclass(frozen=True)
class TimelineResult:
    label: str | None
    total_events: int
    json_path: Path
    csv_path: Path
    created_at: str


def build_timeline(*, case_path: Path, label: str | None, actor: str) -> TimelineResult:
    case_path = case_path.resolve()
    _ = load_case(case_path)
    ensure_case_layout(case_path)
    db_path = case_path / "db" / "dfirlab.sqlite"
    init_db(db_path)

    created_at = now_utc_iso()
    safe_ts = created_at.replace(":", "").replace("+", "").replace("-", "")
    items = fetch_items(db_path, label=label)

    events: list[dict[str, Any]] = []
    for r in items:
        for tname in ("mtime", "ctime", "atime"):
            raw = r[tname]
            if raw is None:
                continue
            try:
                ns = int(raw)
            except Exception:
                continue
            if ns <= 0:
                continue
            events.append(
                {
                    "timestamp_ns": ns,
                    "timestamp": _ns_to_iso(ns),
                    "time_type": tname,
                    "item_id": int(r["item_id"]),
                    "evidence_label": str(r["evidence_label"]),
                    "rel_path": str(r["rel_path"]),
                    "size": int(r["size"]),
                    "sha256": r["sha256"],
                    "type_guess": r["type_guess"],
                }
            )

    events.sort(key=lambda e: (int(e["timestamp_ns"]), int(e["item_id"]), str(e["time_type"])))

    out_dir = case_path / "artifacts" / "timeline"
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"timeline_{label or 'ALL'}_{safe_ts}"
    json_path = out_dir / f"{stem}.json"
    csv_path = out_dir / f"{stem}.csv"

    json_path.write_text(json.dumps({"schema_version": 1, "created_at": created_at, "label": label, "events": events}, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with csv_path.open("w", encoding="utf-8", newline="") as f:
        fieldnames = ["timestamp", "timestamp_ns", "time_type", "item_id", "evidence_label", "rel_path", "size", "sha256", "type_guess"]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for e in events:
            w.writerow(e)

    append_entry(
        case_path / "chain_of_custody.log",
        actor=actor,
        action="timeline",
        details={"label": label, "total_events": len(events), "json_path": str(json_path), "csv_path": str(csv_path)},
    )
    record_action(
        db_path,
        timestamp=created_at,
        actor=actor,
        action="timeline",
        details={"label": label, "total_events": len(events), "json_path": str(json_path), "csv_path": str(csv_path)},
    )

    return TimelineResult(label=label, total_events=len(events), json_path=json_path, csv_path=csv_path, created_at=created_at)
