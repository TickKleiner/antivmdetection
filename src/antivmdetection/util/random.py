"""Centralized randomness utilities."""
from __future__ import annotations

import os
import random
from typing import Optional

ENV_SEED_KEY = "ANTIVMDETECTION_SEED"


def build_rng(seed: Optional[int] = None) -> random.Random:
    """Return a deterministic RNG if a seed is provided."""
    if seed is None:
        env = os.getenv(ENV_SEED_KEY)
        if env:
            try:
                seed = int(env)
            except ValueError:
                pass
    rng = random.Random()
    if seed is not None:
        rng.seed(seed)
    return rng
