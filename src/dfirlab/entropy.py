from __future__ import annotations

import math
from pathlib import Path


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = len(data)
    for c in counts:
        if c == 0:
            continue
        p = c / length
        entropy -= p * math.log2(p)
    return float(entropy)


def file_entropy(path: Path, *, max_bytes: int = 1024 * 1024) -> float:
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
    except OSError:
        return 0.0
    return shannon_entropy(data)
