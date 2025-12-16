from __future__ import annotations

import re


_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(s: str | None, *, limit: int = 65536) -> str | None:
    if s is None:
        return None
    s = _CONTROL_CHARS.sub("", s)
    if len(s) > limit:
        return s[:limit] + "\n[...truncated...]\n"
    return s
