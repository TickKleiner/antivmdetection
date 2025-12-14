"""Helpers for saving/loading snapshot files."""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict

from ..model import (
    AcpiTables,
    CdromInfo,
    DiskInfo,
    GuestData,
    HardwareSnapshot,
    HostData,
    SnapshotMetadata,
    SnapshotResources,
)


def save_snapshot(snapshot: HardwareSnapshot, path: Path) -> None:
    payload = asdict(snapshot)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_snapshot(path: Path) -> HardwareSnapshot:
    data: Dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    disk = data.get("disk")
    cdrom = data.get("cdrom")
    acpi = data.get("acpi")
    host = data.get("host")
    guest = data.get("guest")
    resources = data.get("resources")
    metadata = data.get("metadata") or {}
    snapshot = HardwareSnapshot(
        dmi=data.get("dmi") or {},
        disk=DiskInfo(**disk) if isinstance(disk, dict) else None,
        cdrom=CdromInfo(**cdrom) if isinstance(cdrom, dict) else None,
        acpi=AcpiTables(**acpi) if isinstance(acpi, dict) else None,
        host=HostData(**host) if isinstance(host, dict) else None,
        guest=GuestData(**guest) if isinstance(guest, dict) else None,
        resources=SnapshotResources(**resources) if isinstance(resources, dict) else None,
        metadata=SnapshotMetadata(**metadata),
    )
    return snapshot
