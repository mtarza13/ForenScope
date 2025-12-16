from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Hashes:
    sha256: str
    md5: str


def hash_bytes(data: bytes) -> Hashes:
    return Hashes(sha256=hashlib.sha256(data).hexdigest(), md5=hashlib.md5(data).hexdigest())


def hash_file(path: Path, *, chunk_size: int = 4 * 1024 * 1024) -> Hashes:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
            md5.update(chunk)
    return Hashes(sha256=sha256.hexdigest(), md5=md5.hexdigest())


def hash_symlink(path: Path) -> Hashes:
    target = os.readlink(path)
    return hash_bytes(target.encode("utf-8", errors="surrogateescape"))
