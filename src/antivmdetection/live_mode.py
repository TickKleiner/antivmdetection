"""Bridging helpers for running the legacy Linux script."""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, Set, Tuple

from .model import GenerationArtifacts

LOGGER = logging.getLogger(__name__)
LEGACY_SCRIPT = Path(__file__).resolve().parents[2] / "antivmdetect.py"
LEGACY_WORKDIR = LEGACY_SCRIPT.parent


def run_live_linux_legacy(*, seed: Optional[int], output_dir: Path) -> GenerationArtifacts:
    if not LEGACY_SCRIPT.exists():
        raise FileNotFoundError(LEGACY_SCRIPT)

    env = os.environ.copy()
    if seed is not None:
        env["ANTIVMDETECTION_SEED"] = str(seed)
    before = _snapshot_outputs()

    LOGGER.info("Invoking legacy script at %s", LEGACY_SCRIPT)
    process = subprocess.Popen(
        [sys.executable, str(LEGACY_SCRIPT)],
        cwd=LEGACY_WORKDIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    host_name: Optional[str] = None
    guest_name: Optional[str] = None
    dsdt_name: Optional[str] = None

    assert process.stdout is not None
    for line in process.stdout:
        text = line.rstrip()
        LOGGER.info("legacy | %s", text)
        host_name = host_name or _parse_named_output(text, "template shell script")
        guest_name = guest_name or _parse_named_output(text, "Powershell file")
        dsdt_name = dsdt_name or _parse_named_output(text, "DSDT")

    return_code = process.wait()
    if return_code != 0:
        raise RuntimeError(f"Legacy script failed with exit code {return_code}")

    after = _snapshot_outputs()
    new_files = after - before

    host_path = _resolve_artifact(host_name, ".sh", new_files)
    guest_path = _resolve_artifact(guest_name, ".ps1", new_files)
    dsdt_path = _resolve_artifact(dsdt_name, ".bin", new_files)

    output_dir = output_dir.resolve()
    final_host, final_guest, final_dsdt = _maybe_move_outputs(output_dir, host_path, guest_path, dsdt_path)

    return GenerationArtifacts(host_script=final_host, guest_script=final_guest, dsdt_blob=final_dsdt)


def _snapshot_outputs() -> Set[Path]:
    files: Set[Path] = set()
    for path in LEGACY_WORKDIR.iterdir():
        if path.is_file() and _looks_like_output(path):
            files.add(path.resolve())
    return files


def _looks_like_output(path: Path) -> bool:
    if path.suffix in {".sh", ".ps1"}:
        return True
    if path.suffix == ".bin" and path.name.startswith("DSDT_"):
        return True
    return False


def _parse_named_output(message: str, needle: str) -> Optional[str]:
    if needle not in message:
        return None
    if "named:" in message:
        return message.split("named:", 1)[1].strip()
    if "named," in message:
        return message.split("named,", 1)[1].strip()
    return None


def _resolve_artifact(name: Optional[str], suffix: str, new_files: Set[Path]) -> Optional[Path]:
    if name:
        candidate = (LEGACY_WORKDIR / name).resolve()
        if candidate.exists():
            return candidate
    matches = [path for path in new_files if path.suffix == suffix]
    if matches:
        matches.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return matches[0]
    return None


def _maybe_move_outputs(
    output_dir: Path,
    host: Optional[Path],
    guest: Optional[Path],
    dsdt: Optional[Path],
) -> Tuple[Optional[Path], Optional[Path], Optional[Path]]:
    resolved_output = output_dir.resolve()
    if resolved_output == LEGACY_WORKDIR.resolve():
        return host, guest, dsdt

    resolved_output.mkdir(parents=True, exist_ok=True)
    return (
        _move_one(host, resolved_output),
        _move_one(guest, resolved_output),
        _move_one(dsdt, resolved_output),
    )


def _move_one(path: Optional[Path], output_dir: Path) -> Optional[Path]:
    if path is None:
        return None
    target = output_dir / path.name
    LOGGER.debug("Moving %s -> %s", path, target)
    shutil.move(str(path), target)
    return target
