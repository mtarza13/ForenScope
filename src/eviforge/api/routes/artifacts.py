from __future__ import annotations

import csv
import json
import os
from urllib.parse import quote
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse

from eviforge.config import load_settings
from eviforge.core.auth import ack_dependency, get_current_active_user, User
from eviforge.core.audit import audit_from_user
from eviforge.core.db import create_session_factory, get_setting

router = APIRouter(dependencies=[Depends(ack_dependency), Depends(get_current_active_user)])


def _artifacts_root(case_id: str) -> Path:
    settings = load_settings()
    case_root = (settings.vault_dir / case_id).resolve()
    return (case_root / "artifacts").resolve()


def _safe_artifact_path(case_id: str, safe_path: str, *, allow_root: bool = False) -> Path:
    safe_path = (safe_path or "").strip()
    if not safe_path:
        if allow_root:
            return _artifacts_root(case_id)
        raise HTTPException(status_code=400, detail="Invalid path")
    if safe_path.startswith("/"):
        raise HTTPException(status_code=400, detail="Invalid path")
    if "\\" in safe_path:
        raise HTTPException(status_code=400, detail="Invalid path")

    # disallow traversal
    parts = [p for p in safe_path.split("/") if p]
    if any(p in (".", "..") for p in parts):
        raise HTTPException(status_code=400, detail="Invalid path")

    artifacts_root = _artifacts_root(case_id)

    target = (artifacts_root / "/".join(parts)).resolve()
    if artifacts_root not in target.parents and target != artifacts_root:
        raise HTTPException(status_code=403, detail="Access denied")

    return target


@router.get("/artifacts/{case_id}/{safe_path:path}")
def get_artifact(
    request: Request,
    case_id: str,
    safe_path: str,
    current_user: User = Depends(get_current_active_user),
):
    target = _safe_artifact_path(case_id, safe_path)
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    try:
        settings = load_settings()
        SessionLocal = create_session_factory(settings.database_url)
        with SessionLocal() as session:
            audit_from_user(
                session,
                action="artifact.download",
                user=current_user,
                request=request,
                case_id=case_id,
                details={"path": safe_path},
            )
            session.commit()
    except Exception:
        pass
    return FileResponse(path=str(target), filename=target.name)


@router.get("/cases/{case_id}/artifacts/tree")
def list_artifacts_tree(
    request: Request,
    case_id: str,
    path: str | None = None,
    current_user: User = Depends(get_current_active_user),
):
    rel = (path or "").strip()
    artifacts_root = _artifacts_root(case_id)
    target = _safe_artifact_path(case_id, rel, allow_root=True)
    if not target.exists():
        raise HTTPException(status_code=404, detail="Artifacts path not found")
    if not target.is_dir():
        raise HTTPException(status_code=400, detail="Not a directory")

    items: list[dict] = []
    for child in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        try:
            stat = child.stat()
        except Exception:
            continue
        try:
            child_rel = child.relative_to(artifacts_root).as_posix()
        except Exception:
            continue
        items.append(
            {
                "name": child.name,
                "path": child_rel,
                "type": "dir" if child.is_dir() else "file",
                "size": None if child.is_dir() else stat.st_size,
                "mtime": int(stat.st_mtime),
            }
        )

    try:
        settings = load_settings()
        SessionLocal = create_session_factory(settings.database_url)
        with SessionLocal() as session:
            audit_from_user(
                session,
                action="artifact.tree",
                user=current_user,
                request=request,
                case_id=case_id,
                details={"path": rel},
            )
            session.commit()
    except Exception:
        pass

    return {"path": rel, "items": items}


def _looks_binary(sample: bytes) -> bool:
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    # Heuristic: too many non-text bytes.
    text_chars = b"\n\r\t\b" + bytes(range(32, 127))
    nontext = sum(1 for b in sample if b not in text_chars)
    return (nontext / max(1, len(sample))) > 0.2


@router.get("/cases/{case_id}/artifacts/file")
def preview_artifact_file(
    request: Request,
    case_id: str,
    path: str,
    current_user: User = Depends(get_current_active_user),
):
    rel = (path or "").strip()
    target = _safe_artifact_path(case_id, rel)
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    max_env = os.getenv("EVIFORGE_MAX_ARTIFACT_PREVIEW_BYTES")
    max_bytes: int | None = int(max_env) if max_env else None
    if max_bytes is None:
        try:
            settings = load_settings()
            SessionLocal = create_session_factory(settings.database_url)
            with SessionLocal() as s:
                v = get_setting(s, "max_artifact_preview_bytes")
            if isinstance(v, int) and v > 0:
                max_bytes = v
        except Exception:
            max_bytes = None
    if max_bytes is None:
        max_bytes = 1024 * 1024  # 1 MiB
    size = target.stat().st_size
    download_url = f"/api/artifacts/{quote(case_id)}/{quote(rel)}"

    if size > max_bytes:
        return {"path": rel, "kind": "too_large", "size": size, "download_url": download_url}

    raw = target.read_bytes()
    if _looks_binary(raw[:4096]):
        return {"path": rel, "kind": "binary", "size": size, "download_url": download_url}

    ext = target.suffix.lower()
    text = raw.decode("utf-8", errors="replace")

    kind = "text"
    payload: dict = {"path": rel, "kind": kind, "size": size, "download_url": download_url}

    try:
        if ext == ".json":
            kind = "json"
            payload["kind"] = kind
            payload["data"] = json.loads(text) if text.strip() else None
        elif ext == ".jsonl":
            kind = "jsonl"
            payload["kind"] = kind
            rows = []
            for i, line in enumerate(text.splitlines(), start=1):
                if i > 200:
                    payload["truncated"] = True
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    rows.append({"_raw": line})
            payload["data"] = rows
        elif ext == ".csv":
            kind = "csv"
            payload["kind"] = kind
            reader = csv.reader(text.splitlines())
            out_rows = []
            for i, row in enumerate(reader, start=1):
                if i > 200:
                    payload["truncated"] = True
                    break
                out_rows.append(row)
            payload["rows"] = out_rows
        else:
            lines = text.splitlines()
            if len(lines) > 400:
                payload["truncated"] = True
                lines = lines[:400]
            payload["text"] = "\n".join(lines)
    except Exception:
        payload["kind"] = "text"
        payload["text"] = text[: max_bytes]

    try:
        settings = load_settings()
        SessionLocal = create_session_factory(settings.database_url)
        with SessionLocal() as session:
            audit_from_user(
                session,
                action="artifact.preview",
                user=current_user,
                request=request,
                case_id=case_id,
                details={"path": rel},
            )
            session.commit()
    except Exception:
        pass

    return payload
