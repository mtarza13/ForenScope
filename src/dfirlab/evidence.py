from __future__ import annotations

import json
import os
import shutil
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .actions import record_action
from .case import ensure_case_layout
from .custody import append_entry
from .db import connect, init_db
from .hashing import Hashes, hash_file, hash_symlink
from .manifest import ManifestEntry, iter_manifest, write_manifest
from .time_utils import now_utc_iso
from .utils import ensure_within_directory, guess_type, relpath_posix, validate_label, walk_files


@dataclass(frozen=True)
class IngestResult:
    evidence_id: int
    label: str
    mode: str
    manifest_path: Path
    files: int


def _is_archive(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".zip") or name.endswith(".tar") or name.endswith(".tar.gz") or name.endswith(".tgz") or name.endswith(".tar.bz2") or name.endswith(".tbz2")


def _safe_extract_zip(zip_path: Path, dest: Path) -> None:
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            member_name = member.filename
            # Skip directory entries handled implicitly.
            if member_name.endswith("/"):
                continue
            out_path = dest / Path(member_name)
            ensure_within_directory(out_path, dest)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member, "r") as src, out_path.open("wb") as dst:
                shutil.copyfileobj(src, dst)


def _safe_extract_tar(tar_path: Path, dest: Path) -> None:
    mode = "r:*"
    with tarfile.open(tar_path, mode) as tf:
        for member in tf.getmembers():
            if member.isdir():
                out_dir = dest / Path(member.name)
                ensure_within_directory(out_dir, dest)
                out_dir.mkdir(parents=True, exist_ok=True)
                continue
            if not (member.isreg() or member.issym() or member.islnk()):
                continue
            out_path = dest / Path(member.name)
            ensure_within_directory(out_path, dest)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if member.issym() or member.islnk():
                target = member.linkname
                try:
                    os.symlink(target, out_path)
                except OSError:
                    out_path.write_text(target + "\n", encoding="utf-8")
                continue
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, out_path.open("wb") as dst:
                shutil.copyfileobj(src, dst)


def _hash_path(path: Path) -> Hashes:
    if path.is_symlink():
        return hash_symlink(path)
    return hash_file(path)


def _stat_times_ns(path: Path) -> tuple[int | None, int | None, int | None]:
    try:
        st = path.lstat()
    except OSError:
        return None, None, None
    mtime = getattr(st, "st_mtime_ns", None)
    ctime = getattr(st, "st_ctime_ns", None)
    atime = getattr(st, "st_atime_ns", None)
    return mtime, ctime, atime


def _enumerate_for_manifest(*, root_dir: Path, label: str) -> list[ManifestEntry]:
    entries: list[ManifestEntry] = []
    for we in walk_files(root_dir):
        if not (we.is_file or we.is_symlink):
            continue
        rel_path = relpath_posix(we.path, root_dir)
        mtime, ctime, atime = _stat_times_ns(we.path)
        size = int(we.path.lstat().st_size) if we.path.exists() or we.is_symlink else 0
        h = _hash_path(we.path)
        entries.append(
            ManifestEntry(
                rel_path=rel_path,
                size=size,
                mtime=mtime,
                ctime=ctime,
                atime=atime,
                sha256=h.sha256,
                md5=h.md5,
                type_guess=guess_type(we.path),
                source_label=label,
            )
        )
    return entries


def _manifest_entry_for_single_path(*, root_dir: Path, path: Path, label: str) -> ManifestEntry:
    rel_path = relpath_posix(path, root_dir)
    mtime, ctime, atime = _stat_times_ns(path)
    size = int(path.lstat().st_size)
    h = _hash_path(path)
    return ManifestEntry(
        rel_path=rel_path,
        size=size,
        mtime=mtime,
        ctime=ctime,
        atime=atime,
        sha256=h.sha256,
        md5=h.md5,
        type_guess=guess_type(path),
        source_label=label,
    )


def ingest(
    *,
    case_path: Path,
    source: Path,
    label: str,
    mode: str,
    actor: str,
) -> IngestResult:
    label = validate_label(label)
    source = source.resolve()
    case_path = case_path.resolve()
    ensure_case_layout(case_path)
    if not source.exists():
        raise FileNotFoundError(f"Source not found: {source}")
    if mode not in {"copy", "reference"}:
        raise ValueError("mode must be 'copy' or 'reference'")

    vault_evidence_dir = case_path / "vault" / "evidence" / label
    manifest_path = case_path / "vault" / "manifests" / f"{label}.manifest.jsonl"
    init_db(case_path / "db" / "dfirlab.sqlite")

    source_kind = "path"
    root_for_manifest: Path
    entries: list[ManifestEntry]
    if mode == "copy":
        if vault_evidence_dir.exists() and any(vault_evidence_dir.iterdir()):
            raise FileExistsError(f"Evidence label already exists and is non-empty: {vault_evidence_dir}")
        vault_evidence_dir.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            for we in walk_files(source):
                rel = relpath_posix(we.path, source)
                dest_path = vault_evidence_dir / rel
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                if we.is_dir and not we.is_symlink:
                    dest_path.mkdir(parents=True, exist_ok=True)
                    continue
                if we.is_file or we.is_symlink:
                    shutil.copy2(we.path, dest_path, follow_symlinks=False)
            root_for_manifest = vault_evidence_dir
        elif _is_archive(source):
            source_kind = "archive"
            src_dir = vault_evidence_dir / ".source"
            src_dir.mkdir(parents=True, exist_ok=True)
            copied_archive = src_dir / source.name
            shutil.copy2(source, copied_archive, follow_symlinks=False)
            if source.name.lower().endswith(".zip"):
                _safe_extract_zip(copied_archive, vault_evidence_dir)
            else:
                _safe_extract_tar(copied_archive, vault_evidence_dir)
            root_for_manifest = vault_evidence_dir
        else:
            dest_path = vault_evidence_dir / source.name
            shutil.copy2(source, dest_path, follow_symlinks=False)
            root_for_manifest = vault_evidence_dir
        entries = _enumerate_for_manifest(root_dir=root_for_manifest, label=label)
    else:
        # reference mode: do not copy; manifest is based on the source path.
        if source.is_dir():
            root_for_manifest = source
            entries = _enumerate_for_manifest(root_dir=root_for_manifest, label=label)
        else:
            root_for_manifest = source.parent
            entries = [_manifest_entry_for_single_path(root_dir=root_for_manifest, path=source, label=label)]

    write_manifest(entries, manifest_path)
    ingested_at = now_utc_iso()

    conn = connect(case_path / "db" / "dfirlab.sqlite")
    try:
        cur = conn.execute(
            """
            INSERT INTO evidence(kind,label,source,mode,source_kind,vault_path,ingested_at,manifest_path)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                "files",
                label,
                str(source),
                mode,
                source_kind,
                str(vault_evidence_dir) if mode == "copy" else None,
                ingested_at,
                str(manifest_path),
            ),
        )
        evidence_id = int(cur.lastrowid)
        # Items: store absolute path on disk as used for hashing.
        for e in entries:
            abs_path = str((root_for_manifest / Path(e.rel_path)).absolute())
            conn.execute(
                """
                INSERT OR REPLACE INTO items(evidence_id,rel_path,abs_path,size,mtime,ctime,atime,sha256,md5,type_guess)
                VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    evidence_id,
                    e.rel_path,
                    abs_path,
                    int(e.size),
                    e.mtime,
                    e.ctime,
                    e.atime,
                    e.sha256,
                    e.md5,
                    e.type_guess,
                ),
            )
        conn.commit()
    finally:
        conn.close()

    append_entry(
        case_path / "chain_of_custody.log",
        actor=actor,
        action="ingest",
        details={"label": label, "mode": mode, "source": str(source), "source_kind": source_kind, "files": len(entries)},
    )
    record_action(
        case_path / "db" / "dfirlab.sqlite",
        timestamp=ingested_at,
        actor=actor,
        action="ingest",
        details={"label": label, "mode": mode, "source": str(source), "source_kind": source_kind, "files": len(entries)},
    )
    return IngestResult(evidence_id=evidence_id, label=label, mode=mode, manifest_path=manifest_path, files=len(entries))


def import_image(
    *,
    case_path: Path,
    image: Path,
    label: str,
    mode: str,
    actor: str,
) -> IngestResult:
    label = validate_label(label)
    image = image.resolve()
    case_path = case_path.resolve()
    ensure_case_layout(case_path)
    if not image.exists():
        raise FileNotFoundError(f"Image not found: {image}")
    if mode not in {"copy", "reference"}:
        raise ValueError("mode must be 'copy' or 'reference'")

    vault_image_dir = case_path / "vault" / "images" / label
    manifest_path = case_path / "vault" / "manifests" / f"{label}.manifest.jsonl"
    init_db(case_path / "db" / "dfirlab.sqlite")

    # Multi-segment EWF: include siblings like .E02, .E03...
    segments: list[Path] = []
    if image.suffix.lower().startswith(".e") and len(image.suffix) == 4 and image.suffix[2:].isdigit():
        base = image.name[:-4]
        segs = sorted(image.parent.glob(base + ".[Ee][0-9][0-9]"))
        segments = [p.resolve() for p in segs] if segs else [image]
    else:
        segments = [image]

    root_for_manifest: Path
    if mode == "copy":
        if vault_image_dir.exists() and any(vault_image_dir.iterdir()):
            raise FileExistsError(f"Image label already exists and is non-empty: {vault_image_dir}")
        vault_image_dir.mkdir(parents=True, exist_ok=True)
        for seg in segments:
            shutil.copy2(seg, vault_image_dir / seg.name, follow_symlinks=False)
        root_for_manifest = vault_image_dir
    else:
        root_for_manifest = image.parent

    entries: list[ManifestEntry] = []
    for seg in segments:
        seg_path = root_for_manifest / seg.name
        mtime, ctime, atime = _stat_times_ns(seg_path)
        size = int(seg_path.lstat().st_size)
        h = _hash_path(seg_path)
        entries.append(
            ManifestEntry(
                rel_path=seg.name,
                size=size,
                mtime=mtime,
                ctime=ctime,
                atime=atime,
                sha256=h.sha256,
                md5=h.md5,
                type_guess="image",
                source_label=label,
            )
        )

    write_manifest(entries, manifest_path)
    ingested_at = now_utc_iso()

    conn = connect(case_path / "db" / "dfirlab.sqlite")
    try:
        cur = conn.execute(
            """
            INSERT INTO evidence(kind,label,source,mode,source_kind,vault_path,ingested_at,manifest_path)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                "image",
                label,
                str(image),
                mode,
                "image",
                str(vault_image_dir) if mode == "copy" else None,
                ingested_at,
                str(manifest_path),
            ),
        )
        evidence_id = int(cur.lastrowid)
        for e in entries:
            abs_path = str((root_for_manifest / e.rel_path).absolute())
            conn.execute(
                """
                INSERT OR REPLACE INTO items(evidence_id,rel_path,abs_path,size,mtime,ctime,atime,sha256,md5,type_guess)
                VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    evidence_id,
                    e.rel_path,
                    abs_path,
                    int(e.size),
                    e.mtime,
                    e.ctime,
                    e.atime,
                    e.sha256,
                    e.md5,
                    e.type_guess,
                ),
            )
        conn.commit()
    finally:
        conn.close()

    append_entry(
        case_path / "chain_of_custody.log",
        actor=actor,
        action="import_image",
        details={"label": label, "mode": mode, "image": str(image), "segments": [p.name for p in segments]},
    )
    record_action(
        case_path / "db" / "dfirlab.sqlite",
        timestamp=ingested_at,
        actor=actor,
        action="import_image",
        details={"label": label, "mode": mode, "image": str(image), "segments": [p.name for p in segments]},
    )
    return IngestResult(evidence_id=evidence_id, label=label, mode=mode, manifest_path=manifest_path, files=len(entries))


@dataclass(frozen=True)
class VerifyResult:
    label: str
    ok: bool
    total: int
    missing: int
    mismatched: int
    verified_at: str
    report_path: Path


def verify_case(
    *,
    case_path: Path,
    label: str | None,
    actor: str,
) -> list[VerifyResult]:
    case_path = case_path.resolve()
    ensure_case_layout(case_path)
    db_path = case_path / "db" / "dfirlab.sqlite"
    init_db(db_path)
    conn = connect(db_path)
    try:
        if label:
            rows = conn.execute("SELECT * FROM evidence WHERE label=?", (label,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM evidence ORDER BY id").fetchall()
        evidences = list(rows)
    finally:
        conn.close()

    results: list[VerifyResult] = []
    for ev in evidences:
        ev_label = str(ev["label"])
        manifest_path = Path(str(ev["manifest_path"]))
        mode = str(ev["mode"])
        kind = str(ev["kind"])
        source = Path(str(ev["source"]))
        vault_path = Path(str(ev["vault_path"])) if ev["vault_path"] else None
        source_kind = str(ev["source_kind"])

        if kind == "files":
            if mode == "copy":
                root_dir = case_path / "vault" / "evidence" / ev_label
            else:
                # reference: source may be dir or file/archive.
                root_dir = source if source.is_dir() else source.parent
        else:
            if mode == "copy":
                root_dir = case_path / "vault" / "images" / ev_label
            else:
                root_dir = source.parent

        verified_at = now_utc_iso()
        failures: list[dict[str, Any]] = []
        total = 0
        missing = 0
        mismatched = 0
        for entry in iter_manifest(manifest_path):
            total += 1
            path = root_dir / Path(entry.rel_path)
            if not path.exists() and not path.is_symlink():
                missing += 1
                failures.append({"rel_path": entry.rel_path, "status": "missing"})
                continue
            h = _hash_path(path)
            if h.sha256 != entry.sha256 or h.md5 != entry.md5:
                mismatched += 1
                failures.append(
                    {
                        "rel_path": entry.rel_path,
                        "status": "mismatch",
                        "expected_sha256": entry.sha256,
                        "actual_sha256": h.sha256,
                        "expected_md5": entry.md5,
                        "actual_md5": h.md5,
                    }
                )

        ok = (missing == 0 and mismatched == 0)
        report = {
            "schema_version": 1,
            "verified_at": verified_at,
            "label": ev_label,
            "kind": kind,
            "mode": mode,
            "source": str(source),
            "source_kind": source_kind,
            "root_dir": str(root_dir),
            "manifest_path": str(manifest_path),
            "total": total,
            "missing": missing,
            "mismatched": mismatched,
            "ok": ok,
            "failures": failures,
        }
        report_path = case_path / "artifacts" / "verification" / f"verify_{ev_label}_{verified_at.replace(':', '').replace('+', '')}.json"
        report_path.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")

        conn2 = connect(db_path)
        try:
            conn2.execute(
                "UPDATE evidence SET last_verified_at=?, last_verify_ok=?, last_verify_report_path=? WHERE label=?",
                (verified_at, int(ok), str(report_path), ev_label),
            )
            conn2.commit()
        finally:
            conn2.close()

        append_entry(
            case_path / "chain_of_custody.log",
            actor=actor,
            action="verify",
            details={"label": ev_label, "ok": ok, "total": total, "missing": missing, "mismatched": mismatched},
        )
        record_action(
            db_path,
            timestamp=verified_at,
            actor=actor,
            action="verify",
            details={"label": ev_label, "ok": ok, "total": total, "missing": missing, "mismatched": mismatched, "report_path": str(report_path)},
        )

        results.append(
            VerifyResult(
                label=ev_label,
                ok=ok,
                total=total,
                missing=missing,
                mismatched=mismatched,
                verified_at=verified_at,
                report_path=report_path,
            )
        )
    return results
