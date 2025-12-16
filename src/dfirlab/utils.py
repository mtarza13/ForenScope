from __future__ import annotations

import mimetypes
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator


LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,127}$")


def validate_label(label: str) -> str:
    if not label or label.strip() != label:
        raise ValueError("Label must be non-empty and must not start/end with whitespace.")
    if "/" in label or "\\" in label or ".." in label:
        raise ValueError("Label must not contain path separators or '..'.")
    if not LABEL_RE.match(label):
        raise ValueError("Label may contain letters, numbers, space, '_', '-', '.', and must start with alnum.")
    return label


def relpath_posix(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def ensure_within_directory(path: Path, directory: Path) -> None:
    directory_resolved = directory.resolve()
    path_resolved = path.resolve()
    if directory_resolved != path_resolved and directory_resolved not in path_resolved.parents:
        raise ValueError(f"Path escapes destination directory: {path}")


def guess_type(path: Path) -> str:
    if path.is_symlink():
        return "symlink"
    mime, _enc = mimetypes.guess_type(str(path))
    if mime:
        return mime
    try:
        with path.open("rb") as f:
            head = f.read(16)
    except OSError:
        return "unknown"
    if head.startswith(b"MZ"):
        return "application/x-dosexec"
    if head.startswith(b"\x7fELF"):
        return "application/x-elf"
    if head.startswith(b"PK\x03\x04"):
        return "application/zip"
    if head.startswith(b"Rar!\x1a\x07\x00") or head.startswith(b"Rar!\x1a\x07\x01\x00"):
        return "application/x-rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "application/x-7z-compressed"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if head[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if head.startswith(b"%PDF"):
        return "application/pdf"
    return "unknown"


@dataclass(frozen=True)
class WalkEntry:
    path: Path
    is_symlink: bool
    is_file: bool
    is_dir: bool
    mode: int


def walk_files(root: Path) -> Iterator[WalkEntry]:
    # Deterministic, does not follow symlinks (includes symlink dirs as entries).
    try:
        entries = sorted(root.iterdir(), key=lambda p: p.name)
    except OSError:
        return
    for p in entries:
        try:
            st = p.lstat()
        except OSError:
            continue
        mode = st.st_mode
        is_symlink = stat.S_ISLNK(mode)
        is_dir = stat.S_ISDIR(mode)
        is_file = stat.S_ISREG(mode)
        yield WalkEntry(path=p, is_symlink=is_symlink, is_file=is_file, is_dir=is_dir, mode=mode)
        if is_dir and not is_symlink:
            yield from walk_files(p)


def is_probably_text(path: Path, *, sample_bytes: int = 8192) -> bool:
    try:
        with path.open("rb") as f:
            sample = f.read(sample_bytes)
    except OSError:
        return False
    if b"\x00" in sample:
        return False
    # If most bytes are printable-ish, treat as text.
    if not sample:
        return True
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
    return (printable / len(sample)) > 0.8
