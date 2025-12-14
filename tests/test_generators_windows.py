import pathlib

from antivmdetection.collectors import snapshot as snapshot_io
from antivmdetection.generators import guest as guest_gen
from antivmdetection.generators import host as host_gen
from antivmdetection.model import HardwareSnapshot


def _load_sample_snapshot() -> HardwareSnapshot:
    path = pathlib.Path("tests/fixtures/sample_snapshot.json")
    return snapshot_io.load_snapshot(path)


def test_guest_script_includes_admin_and_identity_blocks(tmp_path):
    snapshot = _load_sample_snapshot()
    artifacts = guest_gen.generate_guest_outputs(snapshot, tmp_path)
    content = artifacts.guest_script.read_text(encoding="utf-8")

    assert "Administrator privileges are required for this script" in content
    assert "WriteAllBytes('Volumeid.exe'" in content
    assert "Rename($computer)" in content
    assert "kummerspeck" in content


def test_guest_script_handles_missing_resources(tmp_path):
    snapshot = _load_sample_snapshot()
    snapshot.resources = None

    artifacts = guest_gen.generate_guest_outputs(snapshot, tmp_path)
    content = artifacts.guest_script.read_text(encoding="utf-8")

    assert "Volumeid.exe not provided" in content
    assert "./volumeid.exe" not in content


def test_host_script_has_admin_block_on_windows(monkeypatch, tmp_path):
    snapshot = HardwareSnapshot(dmi={"DmiSystemProduct": "string:TestBox"})
    monkeypatch.setattr(host_gen.platform, "system", lambda: "Windows")

    artifacts = host_gen.generate_host_outputs(snapshot, tmp_path)
    content = artifacts.host_script.read_text(encoding="utf-8")

    assert "Administrator privileges are required for this script" in content
    assert "Start-Process -FilePath \"powershell.exe\"" in content
