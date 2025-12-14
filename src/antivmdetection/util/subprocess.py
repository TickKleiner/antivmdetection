"""Safe subprocess wrappers."""
from __future__ import annotations

import subprocess
from typing import Iterable, Sequence


def run(cmd: Sequence[str] | Iterable[str], **kwargs) -> subprocess.CompletedProcess:
    """Wrapper that defaults to shell=False and raises on failure by default."""
    kwargs.setdefault("shell", False)
    kwargs.setdefault("check", True)
    return subprocess.run(cmd, **kwargs)
