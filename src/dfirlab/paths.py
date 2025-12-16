from __future__ import annotations

from pathlib import Path
from typing import Any


def _get(item: Any, key: str) -> Any:
    try:
        return item[key]
    except Exception:
        return None


def resolve_item_path(case_path: Path, item: Any) -> Path:
    """
    Resolve an item's on-disk path in a portable way.

    `item` is typically a sqlite3.Row from store.fetch_items().
    """
    case_path = case_path.resolve()
    rel_path = str(item["rel_path"])
    label = str(item["evidence_label"])
    kind = str(_get(item, "evidence_kind") or "")
    mode = str(_get(item, "evidence_mode") or "")
    source = _get(item, "evidence_source")
    abs_path_str = _get(item, "abs_path")

    if abs_path_str:
        p = Path(str(abs_path_str))
        if p.is_absolute() and p.exists():
            return p
        if not p.is_absolute():
            candidate = case_path / p
            if candidate.exists() or candidate.is_symlink():
                return candidate

    if mode == "copy":
        if kind == "image":
            return case_path / "vault" / "images" / label / rel_path
        return case_path / "vault" / "evidence" / label / rel_path

    if source:
        src = Path(str(source))
        if src.is_dir():
            return src / rel_path
        return src.parent / rel_path

    # Fallback to expected vault layout.
    return case_path / "vault" / "evidence" / label / rel_path
