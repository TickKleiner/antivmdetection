from __future__ import annotations

import json
from pathlib import Path

from antivmdetection.collectors.snapshot import load_snapshot, save_snapshot


FIXTURE = Path(__file__).parent / "fixtures" / "sample_snapshot.json"


def test_load_snapshot_parses_fields() -> None:
    snapshot = load_snapshot(FIXTURE)

    assert snapshot.dmi["DmiBIOSVendor"] == "string:Acme"
    assert snapshot.disk is not None
    assert snapshot.disk.serial_number == "ACME1234567890"
    assert snapshot.cdrom is not None
    assert snapshot.cdrom.atapi_vendor_id == "ACME"
    assert snapshot.acpi is not None
    assert snapshot.acpi.dsdt == ["ACME", "OEMID", "TABLEID", "REV", "CREATOR", "0001"]
    assert snapshot.metadata.created_from == "unit-test"


def test_save_snapshot_round_trip(tmp_path: Path) -> None:
    snapshot = load_snapshot(FIXTURE)
    destination = tmp_path / "nested" / "snapshot.json"

    save_snapshot(snapshot, destination)

    original = json.loads(FIXTURE.read_text())
    saved = json.loads(destination.read_text())
    assert saved == original
