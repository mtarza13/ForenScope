from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO, Iterable


def _hash_stream(stream: BinaryIO, algorithms: Iterable[str], chunk_size: int = 1024 * 1024) -> dict[str, str]:
    hashers = {name: hashlib.new(name) for name in algorithms}
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        for h in hashers.values():
            h.update(chunk)
    return {name: h.hexdigest() for name, h in hashers.items()}


def hash_file(path: Path) -> dict[str, str]:
    with path.open("rb") as f:
        return _hash_stream(f, algorithms=("sha256", "md5"))
