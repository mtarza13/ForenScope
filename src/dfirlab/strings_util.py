from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


PRINTABLE = set(range(32, 127)) | {9, 10, 13}


@dataclass(frozen=True)
class StringsResult:
    ascii_strings: list[str]
    utf16le_strings: list[str]
    total_ascii: int
    total_utf16le: int


def _extract_ascii(data: bytes, *, min_len: int, limit: int) -> tuple[list[str], int]:
    out: list[str] = []
    buf: bytearray = bytearray()
    total = 0
    for b in data:
        if b in PRINTABLE:
            buf.append(b)
            continue
        if len(buf) >= min_len:
            total += 1
            if len(out) < limit:
                out.append(buf.decode("ascii", errors="ignore"))
        buf.clear()
    if len(buf) >= min_len:
        total += 1
        if len(out) < limit:
            out.append(buf.decode("ascii", errors="ignore"))
    return out, total


def _extract_utf16le(data: bytes, *, min_len: int, limit: int) -> tuple[list[str], int]:
    # Very small heuristic: look for sequences like b'A\\x00B\\x00...'
    out: list[str] = []
    total = 0
    buf_chars: list[int] = []
    i = 0
    n = len(data)
    while i + 1 < n:
        lo = data[i]
        hi = data[i + 1]
        if hi == 0 and lo in PRINTABLE:
            buf_chars.append(lo)
            i += 2
            continue
        if len(buf_chars) >= min_len:
            total += 1
            if len(out) < limit:
                out.append(bytes(buf_chars).decode("ascii", errors="ignore"))
        buf_chars = []
        i += 2
    if len(buf_chars) >= min_len:
        total += 1
        if len(out) < limit:
            out.append(bytes(buf_chars).decode("ascii", errors="ignore"))
    return out, total


def extract_strings(
    path: Path,
    *,
    min_len: int = 6,
    max_bytes: int = 5 * 1024 * 1024,
    per_file_limit: int = 200,
) -> StringsResult:
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
    except OSError:
        return StringsResult(ascii_strings=[], utf16le_strings=[], total_ascii=0, total_utf16le=0)
    ascii_strings, total_ascii = _extract_ascii(data, min_len=min_len, limit=per_file_limit)
    utf16le_strings, total_utf16le = _extract_utf16le(data, min_len=min_len, limit=per_file_limit)
    return StringsResult(
        ascii_strings=ascii_strings,
        utf16le_strings=utf16le_strings,
        total_ascii=total_ascii,
        total_utf16le=total_utf16le,
    )
