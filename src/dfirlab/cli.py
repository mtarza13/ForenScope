from __future__ import annotations

import argparse
import getpass
import json
import logging
import sys
from pathlib import Path

from .config import AUTH_STATEMENT, acknowledge_authorization, load_authorization
from .case import create_case, load_case
from .custody import read_entries, verify_hash_chain
from .evidence import import_image, ingest, verify_case
from .inventory import build_inventory
from .logging_utils import configure_logging
from .malware_helpers import run_entropy, run_strings
from .timeline import build_timeline
from .triage import run_triage

LOG = logging.getLogger("dfirlab")


def _default_actor() -> str:
    return getpass.getuser()


def _ensure_authorized(ack_text: str | None) -> None:
    state = load_authorization()
    if state.acknowledged:
        return
    if ack_text is not None:
        acknowledge_authorization(statement=ack_text)
        return
    sys.stderr.write("Authorization required (first run)\n")
    sys.stderr.write(f'Type this exactly to proceed:\n  "{AUTH_STATEMENT}"\n\n> ')
    typed = sys.stdin.readline()
    acknowledge_authorization(statement=typed.strip())


def _cmd_init(args: argparse.Namespace) -> int:
    case = create_case(
        root=Path(args.root).resolve(),
        case_name=args.case_name,
        investigator=args.investigator,
        org=args.org,
        actor=args.actor,
    )
    sys.stdout.write(str(case.path) + "\n")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    if not root.exists():
        sys.stderr.write(f"Root not found: {root}\n")
        return 2
    rows: list[dict[str, str]] = []
    for p in sorted(root.iterdir()):
        if not p.is_dir():
            continue
        cj = p / "case.json"
        if not cj.exists():
            continue
        try:
            data = json.loads(cj.read_text(encoding="utf-8"))
        except Exception:
            continue
        rows.append({"case_name": data.get("case_name", p.name), "created_at": data.get("created_at", ""), "path": str(p)})
    if args.json:
        sys.stdout.write(json.dumps(rows, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
        return 0
    for r in rows:
        sys.stdout.write(f'{r["case_name"]}\t{r["created_at"]}\t{r["path"]}\n')
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    case_path = Path(args.case_path).resolve()
    try:
        case = load_case(case_path)
    except Exception as e:
        sys.stderr.write(f"Failed to load case: {e}\n")
        return 2

    try:
        from .actions import record_action
        from .db import init_db
        from .time_utils import now_utc_iso
        from .custody import append_entry

        init_db(case.db_path)
        # Read-only action still recorded in custody log for defensibility.
        append_entry(case.custody_log_path, actor=args.actor, action="case_show", details={"json": bool(args.json)})
        record_action(case.db_path, timestamp=now_utc_iso(), actor=args.actor, action="case_show", details={"json": bool(args.json)})
    except Exception:
        # Best effort; case_show should not fail due to DB.
        pass

    custody_entries = read_entries(case.custody_log_path)
    custody_ok, custody_reason = verify_hash_chain(custody_entries)
    out = {
        "case": {
            "path": str(case.path),
            "case_name": case.case_name,
            "case_id": case.case_id,
            "created_at": case.created_at,
            "investigator": case.investigator,
            "org": case.org,
        },
        "custody": {
            "entries": len(custody_entries),
            "verified": custody_ok,
            "reason": custody_reason,
            "last_entry_hash": custody_entries[-1].entry_hash if custody_entries else None,
        },
    }
    if args.json:
        sys.stdout.write(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
        return 0
    sys.stdout.write(f"Case: {case.case_name} ({case.case_id})\n")
    sys.stdout.write(f"Path: {case.path}\n")
    sys.stdout.write(f"Created: {case.created_at}\n")
    sys.stdout.write(f"Investigator: {case.investigator}\n")
    sys.stdout.write(f"Org: {case.org}\n")
    sys.stdout.write(f"Custody entries: {len(custody_entries)} (verified={custody_ok})\n")
    if not custody_ok:
        sys.stdout.write(f"Custody verification reason: {custody_reason}\n")
    return 0


def _cmd_ingest(args: argparse.Namespace) -> int:
    mode = "reference" if args.reference else "copy"
    res = ingest(
        case_path=Path(args.case_path),
        source=Path(args.source),
        label=args.label,
        mode=mode,
        actor=args.actor,
    )
    sys.stdout.write(json.dumps({"label": res.label, "mode": res.mode, "files": res.files, "manifest_path": str(res.manifest_path)}, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    return 0


def _cmd_import_image(args: argparse.Namespace) -> int:
    mode = "copy" if args.copy else "reference"
    res = import_image(
        case_path=Path(args.case_path),
        image=Path(args.image),
        label=args.label,
        mode=mode,
        actor=args.actor,
    )
    sys.stdout.write(json.dumps({"label": res.label, "mode": res.mode, "segments": res.files, "manifest_path": str(res.manifest_path)}, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    results = verify_case(case_path=Path(args.case_path), label=args.label, actor=args.actor)
    payload = [
        {"label": r.label, "ok": r.ok, "total": r.total, "missing": r.missing, "mismatched": r.mismatched, "verified_at": r.verified_at, "report_path": str(r.report_path)}
        for r in results
    ]
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    return 0 if all(r.ok for r in results) else 3


def _cmd_inventory(args: argparse.Namespace) -> int:
    res = build_inventory(case_path=Path(args.case_path), label=args.label, actor=args.actor)
    sys.stdout.write(
        json.dumps(
            {"label": res.label, "total_items": res.total_items, "json_path": str(res.json_path), "csv_path": str(res.csv_path), "created_at": res.created_at},
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )
    return 0


def _cmd_timeline(args: argparse.Namespace) -> int:
    res = build_timeline(case_path=Path(args.case_path), label=args.label, actor=args.actor)
    sys.stdout.write(
        json.dumps(
            {"label": res.label, "total_events": res.total_events, "json_path": str(res.json_path), "csv_path": str(res.csv_path), "created_at": res.created_at},
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )
    return 0


def _cmd_triage(args: argparse.Namespace) -> int:
    sha256_path = Path(args.known_bad_sha256).expanduser() if args.known_bad_sha256 else None
    md5_path = Path(args.known_bad_md5).expanduser() if args.known_bad_md5 else None
    res = run_triage(
        case_path=Path(args.case_path),
        label=args.label,
        actor=args.actor,
        entropy_top=int(args.entropy_top),
        entropy_threshold=float(args.entropy_threshold),
        known_bad_sha256=sha256_path,
        known_bad_md5=md5_path,
    )
    sys.stdout.write(json.dumps({"label": res.label, "created_at": res.created_at, "report_path": str(res.json_path), "summary": res.summary}, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    return 0


def _cmd_entropy(args: argparse.Namespace) -> int:
    res = run_entropy(case_path=Path(args.case_path), label=args.label, actor=args.actor, top=int(args.top), threshold=float(args.threshold))
    sys.stdout.write(json.dumps({"label": res.label, "created_at": res.created_at, "report_path": str(res.json_path), "top_n": len(res.top)}, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    return 0


def _cmd_strings(args: argparse.Namespace) -> int:
    item_ids = [int(x.strip()) for x in args.item_ids.split(",") if x.strip()] if args.item_ids else None
    res = run_strings(
        case_path=Path(args.case_path),
        label=args.label,
        actor=args.actor,
        min_len=int(args.min_len),
        max_bytes_per_file=int(args.max_bytes_per_file),
        per_file_limit=int(args.per_file_limit),
        max_files=int(args.max_files),
        item_ids=item_ids,
    )
    sys.stdout.write(json.dumps({"label": res.label, "created_at": res.created_at, "report_path": str(res.json_path), "files_processed": res.files_processed}, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dfir", description="dfirlab: offline-first DFIR case + evidence suite")
    p.add_argument("--log-level", default="INFO")
    p.add_argument(
        "--acknowledge",
        metavar="TEXT",
        help="Required first-run authorization acknowledgement text (exact match).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init", help="Initialize a new case")
    sp.add_argument("case_name")
    sp.add_argument("--root", default="./cases")
    sp.add_argument("--investigator", required=True)
    sp.add_argument("--org", required=True)
    sp.add_argument("--actor", default=_default_actor(), help="Recorded actor name for chain-of-custody")
    sp.set_defaults(func=_cmd_init)

    sp = sub.add_parser("list", help="List cases under a root folder")
    sp.add_argument("--root", default="./cases")
    sp.add_argument("--json", action="store_true", help="Emit JSON")
    sp.set_defaults(func=_cmd_list)

    sp = sub.add_parser("show", help="Show a case")
    sp.add_argument("case_path")
    sp.add_argument("--json", action="store_true", help="Emit JSON")
    sp.add_argument("--actor", default=_default_actor(), help="Recorded actor name for chain-of-custody")
    sp.set_defaults(func=_cmd_show)

    sp = sub.add_parser("ingest", help="Ingest evidence (copy or reference) and create a manifest")
    sp.add_argument("case_path")
    sp.add_argument("--source", required=True, help="Path to folder/file or a ZIP/TAR archive")
    sp.add_argument("--label", required=True, help="Evidence label (used for vault paths and manifests)")
    mx = sp.add_mutually_exclusive_group()
    mx.add_argument("--copy", action="store_true", help="Copy into case vault (default)")
    mx.add_argument("--reference", action="store_true", help="Reference source path without copying")
    sp.add_argument("--actor", default=_default_actor(), help="Recorded actor name for chain-of-custody")
    sp.set_defaults(func=_cmd_ingest)

    sp = sub.add_parser("import-image", help="Import a disk image (E01/DD) read-only, with hashing/manifest")
    sp.add_argument("case_path")
    sp.add_argument("--image", required=True, help="Path to image file (E01/DD/RAW/IMG); multi-segment EWF supported")
    sp.add_argument("--label", required=True, help="Image label (used for vault paths and manifests)")
    mx = sp.add_mutually_exclusive_group()
    mx.add_argument("--copy", action="store_true", help="Copy image into case vault/images/<label>/")
    mx.add_argument("--reference", action="store_true", help="Reference image path without copying (default)")
    sp.add_argument("--actor", default=_default_actor(), help="Recorded actor name for chain-of-custody")
    sp.set_defaults(func=_cmd_import_image)

    sp = sub.add_parser("verify", help="Verify evidence against stored manifest(s)")
    sp.add_argument("case_path")
    sp.add_argument("--label", help="Verify a single evidence label (default: all)")
    sp.add_argument("--actor", default=_default_actor(), help="Recorded actor name for chain-of-custody")
    sp.set_defaults(func=_cmd_verify)

    sp = sub.add_parser("inventory", help="Generate an inventory (CSV+JSON) from the case database")
    sp.add_argument("case_path")
    sp.add_argument("--label", help="Evidence label (default: all)")
    sp.add_argument("--actor", default=_default_actor(), help="Recorded actor name for chain-of-custody")
    sp.set_defaults(func=_cmd_inventory)

    sp = sub.add_parser("timeline", help="Generate a baseline MAC timeline (CSV+JSON)")
    sp.add_argument("case_path")
    sp.add_argument("--label", help="Evidence label (default: all)")
    sp.add_argument("--actor", default=_default_actor(), help="Recorded actor name for chain-of-custody")
    sp.set_defaults(func=_cmd_timeline)

    sp = sub.add_parser("triage", help="Fast artifact-first triage on ingested evidence")
    sp.add_argument("case_path")
    sp.add_argument("--label", help="Evidence label (default: all)")
    sp.add_argument("--entropy-top", default="50", help="Compute and report top N entropy files (default: 50)")
    sp.add_argument("--entropy-threshold", default="7.2", help="Insert high-entropy findings at/above this threshold (default: 7.2)")
    sp.add_argument("--known-bad-sha256", help="Path to local SHA-256 hashset file (one per line)")
    sp.add_argument("--known-bad-md5", help="Path to local MD5 hashset file (one per line)")
    sp.add_argument("--actor", default=_default_actor(), help="Recorded actor name for chain-of-custody")
    sp.set_defaults(func=_cmd_triage)

    sp = sub.add_parser("entropy", help="Compute file entropy (defensive triage helper)")
    sp.add_argument("case_path")
    sp.add_argument("--label", help="Evidence label (default: all)")
    sp.add_argument("--top", default="100", help="Report top N files by entropy (default: 100)")
    sp.add_argument("--threshold", default="7.2", help="Insert findings at/above this threshold (default: 7.2)")
    sp.add_argument("--actor", default=_default_actor(), help="Recorded actor name for chain-of-custody")
    sp.set_defaults(func=_cmd_entropy)

    sp = sub.add_parser("strings", help="Extract printable strings (defensive triage helper)")
    sp.add_argument("case_path")
    sp.add_argument("--label", help="Evidence label (default: all)")
    sp.add_argument("--min-len", default="6", help="Minimum string length (default: 6)")
    sp.add_argument("--max-bytes-per-file", default=str(5 * 1024 * 1024), help="Maximum bytes to read per file (default: 5MiB)")
    sp.add_argument("--per-file-limit", default="200", help="Max strings kept per file per encoding (default: 200)")
    sp.add_argument("--max-files", default="50", help="Maximum files to process (default: 50)")
    sp.add_argument("--item-ids", help="Comma-separated item IDs to process (default: first N matching filters)")
    sp.add_argument("--actor", default=_default_actor(), help="Recorded actor name for chain-of-custody")
    sp.set_defaults(func=_cmd_strings)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.log_level)
    try:
        _ensure_authorized(args.acknowledge)
        return int(args.func(args))
    except KeyboardInterrupt:
        sys.stderr.write("Interrupted.\n")
        return 130
    except Exception as e:
        LOG.exception("Unhandled error")
        sys.stderr.write(f"Error: {e}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
