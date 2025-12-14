"""Command-line interface for anti-VM detection tooling."""
from __future__ import annotations

import argparse
import logging
import os
import platform
import sys
from pathlib import Path
from typing import Optional

from . import model
from .collectors import linux_hw, snapshot as snapshot_io, windows_hw
from .generators import guest as guest_gen
from .generators import host as host_gen
from .util.logging import setup_logging
from .util.random import build_rng, ENV_SEED_KEY

LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="antivmdetection",
        description="Generate host/guest modifications to evade simple VM detection heuristics",
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="Seed for deterministic randomness (default: system entropy)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path.cwd(),
        help="Directory to place generated artifacts (default: current working directory)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate arguments and report actions without touching the system",
    )
    snapshot_group = parser.add_mutually_exclusive_group()
    snapshot_group.add_argument(
        "--collect-snapshot",
        type=Path,
        help="Collect hardware data into the given JSON file (Linux only)",
    )
    snapshot_group.add_argument(
        "--from-snapshot",
        type=Path,
        help="Generate outputs from a previously collected snapshot",
    )
    return parser


def _collect_snapshot(*, rng):
    system = platform.system().lower()
    if system == "linux":
        LOGGER.info("Collecting snapshot on Linux host")
        return linux_hw.collect_live_snapshot(rng=rng)
    if system == "windows":
        LOGGER.info("Collecting snapshot on Windows host")
        return windows_hw.collect_live_snapshot(rng=rng)
    raise RuntimeError(f"Unsupported platform for live collection: {system}")


def _generate_from_snapshot(snapshot: model.HardwareSnapshot, output_dir: Path) -> model.GenerationArtifacts:
    output_dir = output_dir.resolve()
    host_artifacts = host_gen.generate_host_outputs(snapshot, output_dir)
    guest_artifacts = guest_gen.generate_guest_outputs(snapshot, output_dir)
    return model.GenerationArtifacts(
        host_script=host_artifacts.host_script,
        guest_script=guest_artifacts.guest_script,
        dsdt_blob=host_artifacts.dsdt_blob,
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging()

    LOGGER.debug("Parsed arguments: %s", args)

    rng = None
    if args.seed is not None or os.getenv(ENV_SEED_KEY):
        rng = build_rng(args.seed)

    if args.dry_run:
        LOGGER.info("Dry run: would execute with seed=%s, output_dir=%s", args.seed, args.output_dir)
        return 0

    try:
        if args.collect_snapshot is not None:
            snapshot = _collect_snapshot(rng=rng)
            snapshot_io.save_snapshot(snapshot, args.collect_snapshot)
            LOGGER.info("Snapshot saved to %s", args.collect_snapshot)
            return 0

        if args.from_snapshot is not None:
            snapshot = snapshot_io.load_snapshot(args.from_snapshot)
            artifacts = _generate_from_snapshot(snapshot, args.output_dir)
            LOGGER.info(
                "Generated from snapshot (host_script=%s, guest_script=%s, dsdt=%s)",
                artifacts.host_script,
                artifacts.guest_script,
                artifacts.dsdt_blob,
            )
            return 0

        snapshot = _collect_snapshot(rng=rng)
        artifacts = _generate_from_snapshot(snapshot, args.output_dir)
        LOGGER.info(
            "Live run completed (host_script=%s, guest_script=%s, dsdt=%s)",
            artifacts.host_script,
            artifacts.guest_script,
            artifacts.dsdt_blob,
        )
        return 0
    except RuntimeError as exc:
        LOGGER.error("%s", exc)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
