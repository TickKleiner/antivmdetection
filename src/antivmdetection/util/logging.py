"""Logging helpers."""
from __future__ import annotations

import logging
from typing import Optional


def setup_logging(level: Optional[str] = None) -> None:
    if level is None:
        level = "INFO"
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
