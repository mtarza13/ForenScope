from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator

from .json_utils import canonical_json


@dataclass(frozen=True)
class ManifestEntry:
    rel_path: str
    size: int
    mtime: int | None
    ctime: int | None
    atime: int | None
    sha256: str
    md5: str
    type_guess: str
    source_label: str


def write_manifest(entries: Iterable[ManifestEntry], manifest_path: Path) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    sorted_entries = sorted(entries, key=lambda e: e.rel_path)
    with manifest_path.open("w", encoding="utf-8") as f:
        for e in sorted_entries:
            f.write(canonical_json(asdict(e)) + "\n")


def iter_manifest(manifest_path: Path) -> Iterator[ManifestEntry]:
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        yield ManifestEntry(
            rel_path=obj["rel_path"],
            size=int(obj["size"]),
            mtime=obj.get("mtime"),
            ctime=obj.get("ctime"),
            atime=obj.get("atime"),
            sha256=obj["sha256"],
            md5=obj["md5"],
            type_guess=obj.get("type_guess", "unknown"),
            source_label=obj.get("source_label", ""),
        )
