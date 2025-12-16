from __future__ import annotations

import logging
import os


def configure_logging(level: str | None = None) -> None:
    chosen = (level or os.environ.get("DFIRLAB_LOG_LEVEL") or "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, chosen, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
