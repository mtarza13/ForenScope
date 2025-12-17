from __future__ import annotations

import os
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

from eviforge.core.auth import ack_dependency, get_current_active_user, require_roles, User
from eviforge.config import load_settings
from eviforge.core.db import create_session_factory, get_setting
from eviforge.core.models import Case, Evidence
from eviforge.core.ingest import ingest_file
from eviforge.core.audit import audit_from_user

router = APIRouter(dependencies=[Depends(ack_dependency), Depends(get_current_active_user)])


class IngestRequest(BaseModel):
    filename: str  # File must be in the configured /import directory


def _get_import_root() -> Path:
    import_root = Path(os.getenv("EVIFORGE_IMPORT_DIR", "/import"))
    if not import_root.exists():
        import_root = Path.cwd() / "import"
    return import_root


def _safe_leaf_filename(raw: str) -> str:
    filename = raw.strip()
    if not filename or filename != Path(filename).name or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    return filename


def _ingest_from_import(
    request: Request, *, case_id: str, filename: str, user: User
) -> dict:
    settings = load_settings()

    import_root = _get_import_root()
    filename = _safe_leaf_filename(filename)
    source_path = (import_root / filename).resolve()

    try:
        import_root_resolved = import_root.resolve()
    except Exception:
        import_root_resolved = import_root

    if import_root_resolved not in source_path.parents and source_path != import_root_resolved:
        raise HTTPException(status_code=403, detail="Access denied")

    if not source_path.exists() or not source_path.is_file():
        raise HTTPException(status_code=404, detail=f"File not found in import directory: {filename}")
        
    SessionLocal = create_session_factory(settings.database_url)
    with SessionLocal() as session:
        # Verify case exists
        case = session.get(Case, case_id)
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        
        try:
            evidence = ingest_file(session, settings, case_id, source_path, user=user.username)

            try:
                audit_from_user(
                    session,
                    action="evidence.ingest",
                    user=user,
                    request=request,
                    case_id=case_id,
                    evidence_id=evidence.id,
                    details={"filename": filename, "sha256": evidence.sha256, "md5": evidence.md5, "size": evidence.size_bytes},
                )
            except Exception:
                pass

            session.commit()
            return {
                "id": evidence.id,
                "name": Path(evidence.path).name,
                "md5": evidence.md5,
                "sha256": evidence.sha256,
                "size": evidence.size_bytes
            }
        except Exception as e:
            session.rollback()
            raise HTTPException(status_code=500, detail=str(e))


@router.post("/{case_id}/evidence")
def ingest_evidence(request: Request, case_id: str, req: IngestRequest, _user: User = Depends(require_roles("admin", "analyst"))):
    return _ingest_from_import(request, case_id=case_id, filename=req.filename, user=_user)


@router.post("/{case_id}/evidence/ingest")
def ingest_evidence_alias(request: Request, case_id: str, req: IngestRequest, _user: User = Depends(require_roles("admin", "analyst"))):
    # Alias for API clients that expect /evidence/ingest
    return _ingest_from_import(request, case_id=case_id, filename=req.filename, user=_user)


@router.post("/{case_id}/evidence/upload")
def upload_evidence(
    request: Request,
    case_id: str,
    file: UploadFile = File(...),
    _user: User = Depends(require_roles("admin", "analyst")),
):
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)

    # Uploads can be huge; encourage ingest from /import for very large files.
    max_env = os.getenv("EVIFORGE_MAX_UPLOAD_BYTES")
    max_bytes: int | None = int(max_env) if max_env else None
    if max_bytes is None:
        try:
            with SessionLocal() as s:
                v = get_setting(s, "max_upload_bytes")
            if isinstance(v, int) and v > 0:
                max_bytes = v
        except Exception:
            max_bytes = None
    if max_bytes is None:
        max_bytes = 1024 * 1024 * 1024  # 1 GiB default

    safe_name = Path(file.filename or "").name
    if not safe_name:
        raise HTTPException(status_code=400, detail="Missing filename")

    upload_dir = settings.data_dir / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = upload_dir / f"{uuid.uuid4()}.upload"
    total = 0

    try:
        with tmp_path.open("wb") as out:
            while True:
                chunk = file.file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise HTTPException(status_code=413, detail=f"Upload too large (>{max_bytes} bytes). Use /import ingest instead.")
                out.write(chunk)
    finally:
        try:
            file.file.close()
        except Exception:
            pass

    with SessionLocal() as session:
        case = session.get(Case, case_id)
        if not case:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass
            raise HTTPException(status_code=404, detail="Case not found")

        try:
            evidence = ingest_file(session, settings, case_id, tmp_path, user=_user.username)
            try:
                audit_from_user(
                    session,
                    action="evidence.upload",
                    user=_user,
                    request=request,
                    case_id=case_id,
                    evidence_id=evidence.id,
                    details={"filename": safe_name, "size": evidence.size_bytes, "sha256": evidence.sha256, "md5": evidence.md5},
                )
            except Exception:
                pass
            session.commit()
            return {
                "id": evidence.id,
                "name": Path(evidence.path).name,
                "md5": evidence.md5,
                "sha256": evidence.sha256,
                "size": evidence.size_bytes,
            }
        except HTTPException:
            session.rollback()
            raise
        except Exception as e:
            session.rollback()
            raise HTTPException(status_code=500, detail=str(e))
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass


@router.get("/{case_id}/evidence")
def list_case_evidence(case_id: str):
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    
    with SessionLocal() as session:
        ev_items = session.query(Evidence).filter(Evidence.case_id == case_id).order_by(Evidence.ingested_at.desc()).all()
        
        res = []
        for ev in ev_items:
            res.append({
                "id": ev.id,
                "filename": Path(ev.path).name,
                "size": ev.size_bytes,
                "ingested_at": ev.ingested_at.isoformat(),
                "hashes": {"sha256": ev.sha256, "md5": ev.md5},
                "vault_relpath": ev.path
            })
        return res


@router.get("/{case_id}/evidence/{evidence_id}")
def get_evidence_details(case_id: str, evidence_id: str):
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)

    with SessionLocal() as session:
        ev = session.get(Evidence, evidence_id)
        if not ev or ev.case_id != case_id:
            raise HTTPException(status_code=404, detail="Evidence not found")

        manifest_path = settings.vault_dir / case_id / "manifests" / f"{evidence_id}.manifest.jsonl"
        manifest_rel = None
        if manifest_path.exists():
            try:
                manifest_rel = str(manifest_path.relative_to(settings.vault_dir / case_id))
            except Exception:
                manifest_rel = str(manifest_path)

        return {
            "id": ev.id,
            "case_id": ev.case_id,
            "filename": Path(ev.path).name,
            "vault_relpath": ev.path,
            "size": ev.size_bytes,
            "ingested_at": ev.ingested_at.isoformat(),
            "hashes": {"sha256": ev.sha256, "md5": ev.md5},
            "manifest": {"available": manifest_rel is not None, "path": manifest_rel},
        }


@router.get("/{case_id}/evidence/{evidence_id}/download")
def download_evidence(
    request: Request,
    case_id: str,
    evidence_id: str,
    _user: User = Depends(require_roles("admin")),
):
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)

    with SessionLocal() as session:
        ev = session.get(Evidence, evidence_id)
        if not ev or ev.case_id != case_id:
            raise HTTPException(status_code=404, detail="Evidence not found")

        case_root = (settings.vault_dir / case_id).resolve()
        evidence_root = (case_root / "evidence").resolve()
        target = (settings.vault_dir / ev.path).resolve()

        if evidence_root not in target.parents:
            raise HTTPException(status_code=403, detail="Access denied")
        if not target.exists() or not target.is_file():
            raise HTTPException(status_code=404, detail="Evidence file missing from vault")

        try:
            audit_from_user(
                session,
                action="evidence.download",
                user=_user,
                request=request,
                case_id=case_id,
                evidence_id=evidence_id,
                details={"path": ev.path},
            )
            session.commit()
        except Exception:
            pass

        return FileResponse(path=str(target), filename=target.name)
