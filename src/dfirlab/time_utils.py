from __future__ import annotations

from datetime import datetime, timezone


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ns_to_iso(ns: int | None) -> str | None:
    if ns is None:
        return None
    return datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc).isoformat()


def coerce_stat_time_to_ns(value: float | int | None) -> int | None:
    if value is None:
        return None
    # Heuristic: values larger than ~2001-09-09 in ns scale.
    if isinstance(value, int) and value > 10_000_000_000:
        return value
    if isinstance(value, float) and value > 10_000_000_000:
        return int(value)
    return int(float(value) * 1_000_000_000)
