from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .actions import record_action
from .case import ensure_case_layout, load_case
from .config import config_dir
from .custody import append_entry
from .db import init_db
from .entropy import file_entropy
from .paths import resolve_item_path
from .store import fetch_items, insert_finding
from .time_utils import now_utc_iso


EXECUTABLE_EXTS = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".com",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".jar",
    ".hta",
    ".wsf",
    ".vbe",
    ".scf",
}

ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab"}

SUSPICIOUS_EXTS = EXECUTABLE_EXTS | {
    ".lnk",
    ".url",
    ".iso",
    ".img",
    ".vhd",
    ".vhdx",
    ".docm",
    ".xlsm",
    ".pptm",
    ".rtf",
    ".chm",
    ".xll",
    ".iqy",
}

BROWSER_FILENAMES = {
    "history",
    "cookies",
    "login data",
    "web data",
    "favicons",
    "places.sqlite",
    "cookies.sqlite",
    "formhistory.sqlite",
    "key4.db",
    "logins.json",
}

REGISTRY_FILENAMES = {"system", "software", "sam", "security", "ntuser.dat", "usrclass.dat", "amcache.hve"}

EMAIL_EXTS = {".pst", ".ost", ".eml", ".mbox", ".msg", ".olm"}


def _load_hashset(path: Path) -> set[str]:
    hashes: set[str] = set()
    if not path.exists():
        return hashes
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        hashes.add(line.lower())
    return hashes


@dataclass(frozen=True)
class TriageResult:
    label: str | None
    created_at: str
    json_path: Path
    summary: dict[str, Any]


def run_triage(
    *,
    case_path: Path,
    label: str | None,
    actor: str,
    entropy_top: int = 50,
    entropy_threshold: float = 7.2,
    known_bad_sha256: Path | None = None,
    known_bad_md5: Path | None = None,
) -> TriageResult:
    case_path = case_path.resolve()
    _ = load_case(case_path)
    ensure_case_layout(case_path)
    db_path = case_path / "db" / "dfirlab.sqlite"
    init_db(db_path)

    created_at = now_utc_iso()
    safe_ts = created_at.replace(":", "").replace("+", "").replace("-", "")

    items = fetch_items(db_path, label=label)
    sha256_set = _load_hashset(known_bad_sha256) if known_bad_sha256 else _load_hashset(config_dir() / "hashsets" / "known_bad_sha256.txt")
    md5_set = _load_hashset(known_bad_md5) if known_bad_md5 else _load_hashset(config_dir() / "hashsets" / "known_bad_md5.txt")

    executables: list[dict[str, Any]] = []
    archives: list[dict[str, Any]] = []
    suspicious_ext: list[dict[str, Any]] = []
    browser_hits: list[dict[str, Any]] = []
    registry_hits: list[dict[str, Any]] = []
    evtx_hits: list[dict[str, Any]] = []
    email_hits: list[dict[str, Any]] = []
    known_bad: list[dict[str, Any]] = []
    entropy_rows: list[dict[str, Any]] = []
    recent_rows: list[dict[str, Any]] = []

    for r in items:
        rel_path = str(r["rel_path"])
        name = Path(rel_path).name
        ext = Path(rel_path).suffix.lower()
        item_id = int(r["item_id"])
        sha256 = (r["sha256"] or "").lower()
        md5 = (r["md5"] or "").lower()
        type_guess = r["type_guess"]
        size = int(r["size"])

        if ext in EXECUTABLE_EXTS or type_guess in {"application/x-dosexec", "application/x-elf"}:
            executables.append({"item_id": item_id, "rel_path": rel_path, "size": size, "sha256": sha256, "type_guess": type_guess})
        if ext in ARCHIVE_EXTS or type_guess in {"application/zip", "application/x-rar", "application/x-7z-compressed"}:
            archives.append({"item_id": item_id, "rel_path": rel_path, "size": size, "sha256": sha256, "type_guess": type_guess})
        if ext in SUSPICIOUS_EXTS:
            suspicious_ext.append({"item_id": item_id, "rel_path": rel_path, "size": size, "sha256": sha256, "type_guess": type_guess})

        if name.lower() in BROWSER_FILENAMES:
            browser_hits.append({"item_id": item_id, "rel_path": rel_path, "size": size})
        if name.lower() in REGISTRY_FILENAMES:
            registry_hits.append({"item_id": item_id, "rel_path": rel_path, "size": size})
        if ext == ".evtx":
            evtx_hits.append({"item_id": item_id, "rel_path": rel_path, "size": size})
        if ext in EMAIL_EXTS:
            email_hits.append({"item_id": item_id, "rel_path": rel_path, "size": size})

        if (sha256 and sha256 in sha256_set) or (md5 and md5 in md5_set):
            known_bad.append(
                {
                    "item_id": item_id,
                    "rel_path": rel_path,
                    "size": size,
                    "sha256": sha256,
                    "md5": md5,
                    "matched": "sha256" if sha256 in sha256_set else "md5",
                }
            )

        abs_path = resolve_item_path(case_path, r)
        if abs_path.is_symlink():
            continue
        if not abs_path.exists():
            continue
        # Fast entropy heuristic (read-limited).
        if size > 0:
            ent = file_entropy(abs_path)
            entropy_rows.append({"item_id": item_id, "rel_path": rel_path, "size": size, "entropy": ent, "sha256": sha256})

        mtime = r["mtime"]
        if mtime is not None:
            try:
                recent_rows.append({"item_id": item_id, "rel_path": rel_path, "mtime_ns": int(mtime), "size": size, "sha256": sha256})
            except Exception:
                pass

    entropy_rows.sort(key=lambda x: (-float(x["entropy"]), -int(x["size"]), int(x["item_id"])))
    entropy_top_rows = entropy_rows[: max(0, int(entropy_top))]

    recent_rows.sort(key=lambda x: (-int(x["mtime_ns"]), int(x["item_id"])))
    recent_top_rows = recent_rows[:20]

    # Persist key findings (avoid spamming DB with low-signal categories).
    for row in known_bad:
        insert_finding(
            db_path,
            item_id=int(row["item_id"]),
            kind="hash_match",
            severity="high",
            title="Known-bad hash match (local hashset)",
            details=row,
            created_at=created_at,
        )
    for row in suspicious_ext[:200]:
        insert_finding(
            db_path,
            item_id=int(row["item_id"]),
            kind="suspicious_extension",
            severity="medium",
            title=f"Suspicious extension: {Path(str(row['rel_path'])).suffix.lower()}",
            details=row,
            created_at=created_at,
        )
    for row in entropy_top_rows:
        if float(row["entropy"]) >= float(entropy_threshold):
            insert_finding(
                db_path,
                item_id=int(row["item_id"]),
                kind="high_entropy",
                severity="medium",
                title=f"High entropy file (>= {entropy_threshold:.2f})",
                details=row,
                created_at=created_at,
            )

    insert_finding(
        db_path,
        item_id=None,
        kind="triage_summary",
        severity="info",
        title="Triage summary",
        details={
            "label": label,
            "counts": {
                "items": len(items),
                "executables": len(executables),
                "archives": len(archives),
                "suspicious_extensions": len(suspicious_ext),
                "browser_artifacts": len(browser_hits),
                "registry_hives": len(registry_hits),
                "evtx_logs": len(evtx_hits),
                "email_containers": len(email_hits),
                "known_bad_matches": len(known_bad),
            },
        },
        created_at=created_at,
    )

    report = {
        "schema_version": 1,
        "created_at": created_at,
        "label": label,
        "counts": {
            "items": len(items),
            "executables": len(executables),
            "archives": len(archives),
            "suspicious_extensions": len(suspicious_ext),
            "browser_artifacts": len(browser_hits),
            "registry_hives": len(registry_hits),
            "evtx_logs": len(evtx_hits),
            "email_containers": len(email_hits),
            "known_bad_matches": len(known_bad),
        },
        "top": {
            "known_bad": known_bad,
            "high_entropy": entropy_top_rows,
            "recent_mtime": recent_top_rows,
        },
        "presence": {
            "browser_artifacts": browser_hits[:50],
            "registry_hives": registry_hits[:50],
            "evtx_logs": evtx_hits[:50],
            "email_containers": email_hits[:50],
        },
        "lists": {
            "executables": executables[:200],
            "archives": archives[:200],
            "suspicious_extensions": suspicious_ext[:200],
        },
        "hashsets": {
            "sha256_path": str(known_bad_sha256) if known_bad_sha256 else str(config_dir() / "hashsets" / "known_bad_sha256.txt"),
            "md5_path": str(known_bad_md5) if known_bad_md5 else str(config_dir() / "hashsets" / "known_bad_md5.txt"),
        },
    }

    out_dir = case_path / "artifacts" / "triage"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"triage_{label or 'ALL'}_{safe_ts}.json"
    json_path.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    append_entry(
        case_path / "chain_of_custody.log",
        actor=actor,
        action="triage",
        details={"label": label, "report_path": str(json_path), "known_bad_matches": len(known_bad), "high_entropy_computed": len(entropy_rows)},
    )
    record_action(
        db_path,
        timestamp=created_at,
        actor=actor,
        action="triage",
        details={"label": label, "report_path": str(json_path), "known_bad_matches": len(known_bad), "high_entropy_computed": len(entropy_rows)},
    )

    return TriageResult(label=label, created_at=created_at, json_path=json_path, summary=report["counts"])
