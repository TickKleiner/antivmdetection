from __future__ import annotations

import os
import time
from pathlib import Path

from antivmdetection import live_mode


def test_parse_named_output_matches_expected_formats() -> None:
    host_line = "[*] Finished: A template shell script has been created named: host_script.sh"
    guest_line = "[*] Finished: A Powershell file has been created, named: guest_script.ps1"

    assert live_mode._parse_named_output(host_line, "template shell script") == "host_script.sh"
    assert live_mode._parse_named_output(guest_line, "Powershell file") == "guest_script.ps1"
    assert live_mode._parse_named_output("no match here", "template shell script") is None


def test_looks_like_output_filters_extensions() -> None:
    assert live_mode._looks_like_output(Path("result.sh"))
    assert live_mode._looks_like_output(Path("DSDT_sample.bin"))
    assert not live_mode._looks_like_output(Path("random.bin"))
    assert not live_mode._looks_like_output(Path("notes.txt"))


def test_resolve_artifact_prefers_named_candidate(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(live_mode, "LEGACY_WORKDIR", tmp_path)
    named = tmp_path / "custom.ps1"
    named.write_text("content")
    new_files = {named.resolve()}

    resolved = live_mode._resolve_artifact("custom.ps1", ".ps1", new_files)

    assert resolved == named.resolve()


def test_resolve_artifact_falls_back_to_newest(tmp_path: Path) -> None:
    older = tmp_path / "older.sh"
    newer = tmp_path / "newer.sh"
    older.write_text("old")
    newer.write_text("new")

    past = time.time() - 60
    os.utime(older, (past, past))

    resolved = live_mode._resolve_artifact(None, ".sh", {older.resolve(), newer.resolve()})

    assert resolved == newer.resolve()


def test_maybe_move_outputs_moves_into_target(tmp_path: Path) -> None:
    host = tmp_path / "host.sh"
    guest = tmp_path / "guest.ps1"
    dsdt = tmp_path / "DSDT_acme.bin"
    host.write_text("host")
    guest.write_text("guest")
    dsdt.write_text("dsdt")

    destination = tmp_path / "output"
    moved_host, moved_guest, moved_dsdt = live_mode._maybe_move_outputs(destination, host, guest, dsdt)

    assert moved_host == destination / host.name
    assert moved_guest == destination / guest.name
    assert moved_dsdt == destination / dsdt.name
    assert moved_host.exists()
    assert moved_guest.exists()
    assert moved_dsdt.exists()
    assert not host.exists()
    assert not guest.exists()
    assert not dsdt.exists()
