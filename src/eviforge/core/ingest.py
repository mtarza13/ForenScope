from __future__ import annotations

import hashlib
import shutil
import uuid
from pathlib import Path

from sqlalchemy.orm import Session

from eviforge.core.models import Evidence
from eviforge.core.custody import log_action
from eviforge.config import Settings


def calculate_hashes(file_path: Path) -> tuple[str, str]:
    """Calculate MD5 and SHA256 hashes of a file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    
    with file_path.open("rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha256.update(chunk)
            
    return md5.hexdigest(), sha256.hexdigest()


def ingest_file(
    session: Session,
    settings: Settings,
    case_id: str,
    source_path: Path,
    user: str = "system"
) -> Evidence:
    """
    Ingest a file into the case vault.
    1. Calculate source hashes.
    2. Copy to vault/{case_id}/evidence/{uuid}/{filename}.
    3. Verify destination hashes.
    4. Create Evidence record.
    5. Log custody action.
    """
    if not source_path.exists():
        raise FileNotFoundError(f"Source file not found: {source_path}")

    # 1. Calculate source hashes
    src_md5, src_sha256 = calculate_hashes(source_path)
    file_size = source_path.stat().st_size
    
    # Prepare destination
    evidence_id = str(uuid.uuid4())
    dest_dir = settings.vault_dir / case_id / "evidence" / evidence_id
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / source_path.name
    
    # 2. Copy file (read-only destination ideally, but fs permissions later)
    shutil.copy2(source_path, dest_path)
    
    # 3. Verify copy
    dest_md5, dest_sha256 = calculate_hashes(dest_path)
    if dest_md5 != src_md5 or dest_sha256 != src_sha256:
        # Rollback
        shutil.rmtree(dest_dir)
        raise ValueError("Integrity check failed: Destination hashes do not match source hashes.")
        
    # 4. Create Record
    evidence = Evidence(
        id=evidence_id,
        case_id=case_id,
        path=str(dest_path.relative_to(settings.vault_dir)), # Store relative path for portability
        size_bytes=file_size,
        md5=src_md5,
        sha256=src_sha256
    )
    session.add(evidence)
    
    # 5. Log Action
    log_action(
        session, 
        case_id, 
        user, 
        "Evidence Ingested", 
        f"File: {source_path.name}, SHA256: {src_sha256}, UUID: {evidence_id}"
    )
    
    return evidence
