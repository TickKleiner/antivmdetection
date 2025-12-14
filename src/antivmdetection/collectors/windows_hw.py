"""Windows hardware collectors (live mode)."""
from __future__ import annotations

import base64
import datetime as dt
import json
import logging
import os
import platform
import random
import re
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import netifaces

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
from ..util.random import ENV_SEED_KEY, build_rng

LOGGER = logging.getLogger(__name__)

STRING_DEFAULT = "string:** No value to retrieve **"
VALUE_DEFAULT = "** No value to retrieve **"


def collect_live_snapshot(*, rng: Optional[random.Random] = None) -> HardwareSnapshot:
    """Collect hardware information directly on a Windows host."""
    _ensure_windows()
    rng = _maybe_rng(rng)

    dmi_info = _collect_dmi_info(rng)
    disk_info = _collect_disk_info(rng)
    cdrom_info = _collect_cdrom_info(rng)
    acpi = _collect_acpi_tables(dmi_info, rng)
    host = _collect_host_data(rng)
    guest = _collect_guest_data(rng, acpi)
    resources = _collect_resources()

    metadata = SnapshotMetadata(
        created_from="windows-live",
        created_at=dt.datetime.utcnow().isoformat() + "Z",
        host_identifier=platform.node(),
    )
    return HardwareSnapshot(
        dmi=dmi_info,
        disk=disk_info,
        cdrom=cdrom_info,
        acpi=acpi,
        host=host,
        guest=guest,
        resources=resources,
        metadata=metadata,
    )


def _ensure_windows() -> None:
    if platform.system().lower() != "windows":
        raise RuntimeError("Windows live collection is only available on Windows hosts")


def _collect_dmi_info(rng: Optional[random.Random]) -> Dict[str, str]:
    info: Dict[str, str] = {}

    bios = _ps_single(
        "Win32_BIOS",
        [
            "Manufacturer",
            "SMBIOSBIOSVersion",
            "ReleaseDate",
            "SMBIOSMajorVersion",
            "SMBIOSMinorVersion",
            "BIOSVersion",
        ],
    )
    bios_vendor = _safe_string(bios, "Manufacturer")
    _set_with_default(info, "DmiBIOSVendor", f"string:{bios_vendor}" if bios_vendor else None, STRING_DEFAULT)
    bios_version_raw = _safe_string(bios, "SMBIOSBIOSVersion") or _first_list_value(bios, "BIOSVersion")
    bios_version = f"string:{bios_version_raw.replace(' ', '')}" if bios_version_raw else None
    _set_with_default(info, "DmiBIOSVersion", bios_version, STRING_DEFAULT)
    bios_release = _parse_wmi_date(_safe_string(bios, "ReleaseDate"))
    _set_with_default(info, "DmiBIOSReleaseDate", f"string:{bios_release}" if bios_release else None, STRING_DEFAULT)
    major = _safe_value(bios, "SMBIOSMajorVersion")
    minor = _safe_value(bios, "SMBIOSMinorVersion")
    _set_with_default(info, "DmiBIOSReleaseMajor", str(major) if major is not None else None, VALUE_DEFAULT)
    _set_with_default(info, "DmiBIOSReleaseMinor", str(minor) if minor is not None else None, VALUE_DEFAULT)
    _set_with_default(info, "DmiBIOSFirmwareMajor", None, VALUE_DEFAULT)
    _set_with_default(info, "DmiBIOSFirmwareMinor", None, VALUE_DEFAULT)

    board = _ps_single("Win32_BaseBoard", ["Manufacturer", "Product", "Version", "SerialNumber", "Tag"])
    board_vendor = _safe_string(board, "Manufacturer")
    _set_with_default(info, "DmiBoardVendor", f"string:{board_vendor.replace(' ', '')}" if board_vendor else None, STRING_DEFAULT)
    board_product = _safe_string(board, "Product")
    _set_with_default(info, "DmiBoardProduct", f"string:{board_product.replace(' ', '')}" if board_product else None, STRING_DEFAULT)
    board_version = _safe_string(board, "Version")
    _set_with_default(info, "DmiBoardVersion", f"string:{board_version.replace(' ', '')}" if board_version else None, STRING_DEFAULT)
    board_serial = _safe_string(board, "SerialNumber")
    _set_with_default(info, "DmiBoardSerial", _serial_randomize(board_serial, rng) if board_serial else None, VALUE_DEFAULT)
    board_asset = _safe_string(board, "Tag")
    _set_with_default(info, "DmiBoardAssetTag", f"string:{board_asset}" if board_asset else None, STRING_DEFAULT)
    _set_with_default(info, "DmiBoardLocInChass", None, STRING_DEFAULT)
    _set_with_default(info, "DmiBoardBoardType", None, VALUE_DEFAULT)

    system_product = _ps_single(
        "Win32_ComputerSystemProduct",
        ["UUID", "IdentifyingNumber", "Name", "Vendor", "Version", "SKUNumber"],
    )
    sku = _safe_string(system_product, "SKUNumber")
    _set_with_default(info, "DmiSystemSKU", sku, VALUE_DEFAULT)
    system_version = _safe_string(system_product, "Version")
    _set_with_default(info, "DmiSystemVersion", f"string:{system_version.replace(' ', '')}" if system_version else None, STRING_DEFAULT)
    system_name = _safe_string(system_product, "Name")
    _set_with_default(info, "DmiSystemProduct", f"string:{system_name.replace(' ', '')}" if system_name else None, STRING_DEFAULT)
    system_vendor = _safe_string(system_product, "Vendor")
    _set_with_default(info, "DmiSystemVendor", f"string:{system_vendor.replace(' ', '')}" if system_vendor else None, STRING_DEFAULT)
    system_serial = _safe_string(system_product, "IdentifyingNumber")
    _set_with_default(info, "DmiSystemSerial", f"string:{_serial_randomize(system_serial, rng)}" if system_serial else None, STRING_DEFAULT)

    family_data = _ps_single("Win32_ComputerSystem", ["SystemFamily"])
    system_family = _safe_string(family_data, "SystemFamily")
    _set_with_default(info, "DmiSystemFamily", f"string:{system_family}" if system_family else None, "Not Specified")
    info["DmiSystemUuid"] = uuid.UUID(int=rng.getrandbits(128)).hex.upper() if rng else (uuid.uuid4().hex or "").upper()

    chassis = _ps_single("Win32_SystemEnclosure", ["Manufacturer", "SMBIOSAssetTag", "SerialNumber", "Version", "ChassisTypes"])
    chassis_vendor = _safe_string(chassis, "Manufacturer")
    _set_with_default(info, "DmiChassisVendor", f"string:{chassis_vendor.replace(' ', '')}" if chassis_vendor else None, STRING_DEFAULT)
    chassis_version = _safe_string(chassis, "Version")
    _set_with_default(info, "DmiChassisVersion", f"string:{chassis_version.replace(' ', '')}" if chassis_version else None, STRING_DEFAULT)
    chassis_asset = _safe_string(chassis, "SMBIOSAssetTag")
    _set_with_default(info, "DmiChassisAssetTag", f"string:{chassis_asset}" if chassis_asset else None, STRING_DEFAULT)
    chassis_serial = _safe_string(chassis, "SerialNumber")
    _set_with_default(info, "DmiChassisSerial", f"string:{_serial_randomize(chassis_serial, rng)}" if chassis_serial else None, STRING_DEFAULT)
    chassis_types = chassis.get("ChassisTypes") if isinstance(chassis, dict) else None
    chassis_type = chassis_types[0] if isinstance(chassis_types, list) and chassis_types else chassis_types
    _set_with_default(info, "DmiChassisType", str(chassis_type) if chassis_type else None, VALUE_DEFAULT)

    cpu = _ps_single("Win32_Processor", ["Name", "Manufacturer"])
    cpu_name = _safe_string(cpu, "Name")
    cpu_vendor = _safe_string(cpu, "Manufacturer")
    _set_with_default(info, "DmiProcVersion", f"string:{cpu_name.replace(' ', '')}" if cpu_name else None, STRING_DEFAULT)
    _set_with_default(info, "DmiProcManufacturer", f"string:{cpu_vendor.replace(' ', '')}" if cpu_vendor else None, STRING_DEFAULT)

    _set_with_default(info, "DmiOEMVBoxVer", info.get("DmiOEMVBoxVer"), VALUE_DEFAULT)
    _set_with_default(info, "DmiOEMVBoxRev", info.get("DmiOEMVBoxRev"), VALUE_DEFAULT)

    return info


def _collect_disk_info(rng: Optional[random.Random]) -> DiskInfo:
    info = DiskInfo()
    disk = _ps_single("Win32_DiskDrive", ["SerialNumber", "FirmwareRevision", "FirmwareVersion", "Model"])
    if disk:
        serial = _safe_string(disk, "SerialNumber")
        if serial:
            info.serial_number = _serial_randomize(serial, rng)
        fw = _safe_string(disk, "FirmwareRevision") or _safe_string(disk, "FirmwareVersion")
        if fw:
            info.firmware_revision = fw
        model = _safe_string(disk, "Model")
        if model:
            info.model_number = model
    return info


def _collect_cdrom_info(rng: Optional[random.Random]) -> CdromInfo:
    info = CdromInfo()
    cdrom = _ps_single("Win32_CDROMDrive", ["SerialNumber", "MfrAssignedRevisionLevel", "Name", "Manufacturer"])
    if cdrom:
        serial = _safe_string(cdrom, "SerialNumber")
        if serial:
            info.atapi_serial = _serial_randomize(serial, rng)
        revision = _safe_string(cdrom, "MfrAssignedRevisionLevel")
        if revision:
            info.atapi_revision = revision.replace(" ", "")
        product = _safe_string(cdrom, "Name")
        if product:
            info.atapi_product_id = product
        vendor = _safe_string(cdrom, "Manufacturer")
        if vendor:
            info.atapi_vendor_id = vendor

    if not any([info.atapi_serial, info.atapi_revision, info.atapi_product_id, info.atapi_vendor_id]):
        LOGGER.info("No CD-ROM information detected on Windows host")

    return info


def _collect_acpi_tables(dmi: Dict[str, str], rng: Optional[random.Random]) -> AcpiTables:
    acpidump_path = Path("acpidump.exe")
    if acpidump_path.exists():
        acpi = _collect_acpi_with_acpidump(acpidump_path)
        if acpi:
            return acpi
        LOGGER.warning("acpidump.exe found but collection failed; falling back to synthetic ACPI tables")
    else:
        LOGGER.warning("acpidump.exe not found; using synthetic ACPI tables on Windows")
    return _synthetic_acpi_tables(dmi, rng)


def _collect_acpi_with_acpidump(acpidump_path: Path) -> Optional[AcpiTables]:
    summary = subprocess.run([str(acpidump_path), "-s"], capture_output=True, text=True, check=False)
    if summary.returncode != 0 or not summary.stdout:
        LOGGER.debug("acpidump.exe -s failed (%s): %s", summary.returncode, summary.stderr.strip())
        return None
    dsdt_tokens = _parse_table_tokens(summary.stdout, "DSDT")
    facp_tokens = _parse_table_tokens(summary.stdout, "FACP")
    ssdt_ids = _parse_ssdt_ids(summary.stdout)
    dsdt_blob = _extract_dsdt_blob(acpidump_path)
    return AcpiTables(dsdt=dsdt_tokens, facp=facp_tokens, rsdt=[], ssdt=ssdt_ids, dsdt_blob_b64=dsdt_blob)


def _parse_table_tokens(text: str, signature: str) -> List[str]:
    for line in text.splitlines():
        if signature not in line:
            continue
        match = re.search(r"\(([^)]*)\)", line)
        if not match:
            continue
        tokens = [tok for tok in match.group(1).split() if tok]
        if signature == "DSDT" and len(tokens) > 5:
            try:
                tokens[5] = re.sub("[^0-9]", "", tokens[5])
            except Exception:
                pass
        return tokens
    return []


def _parse_ssdt_ids(text: str) -> List[str]:
    ids: List[str] = []
    for line in text.splitlines():
        if "SSDT" not in line:
            continue
        match = re.search(r"SSDT[^\\(]*\\(([^)]*)\\)", line)
        if match:
            parts = [p for p in match.group(1).split() if p]
            ids.extend(parts[:3])
            if len(ids) >= 3:
                break
    return ids[:3]


def _extract_dsdt_blob(acpidump_path: Path) -> Optional[str]:
    with tempfile.TemporaryDirectory() as tmp:
        result = subprocess.run([str(acpidump_path), "-b"], cwd=tmp, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            LOGGER.debug("acpidump.exe -b failed (%s): %s", result.returncode, result.stderr.strip())
            return None
        candidates = list(Path(tmp).glob("DSDT.*")) + list(Path(tmp).glob("dsdt.*")) + list(Path(tmp).glob("*DSDT*"))
        if not candidates:
            return None
        dsdt_bytes = candidates[0].read_bytes()
        return base64.b64encode(dsdt_bytes).decode("utf-8")


def _synthetic_acpi_tables(dmi: Dict[str, str], rng: Optional[random.Random]) -> AcpiTables:
    def _strip_prefix(value: Optional[str]) -> str:
        if not value:
            return ""
        return value.replace("string:", "").replace(" ", "").replace("_", "").upper()

    manu = _strip_prefix(dmi.get("DmiSystemVendor")) or "OEMID"
    product = _strip_prefix(dmi.get("DmiSystemProduct")) or "TABLEID"
    creator = _strip_prefix(dmi.get("DmiBoardVendor")) or "INTL"
    rev = re.sub("[^0-9]", "", dmi.get("DmiBIOSReleaseDate", ""))[-8:]
    if not rev:
        rev = "0001"
    dsdt = [manu[:6], manu[:6], product[:6], product[:6], creator[:4], rev[:8]]
    facp = ["FACP", manu[:6], product[:6], rev[:4]]
    ssdt = _synthetic_ssdt_ids(rng)
    return AcpiTables(dsdt=dsdt, facp=facp, rsdt=[], ssdt=ssdt, dsdt_blob_b64=None)


def _synthetic_ssdt_ids(rng: Optional[random.Random]) -> List[str]:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    rand = rng or random
    ids = []
    for prefix in ("SSDT", "SLIC", "MCFG"):
        suffix = "".join(rand.choice(alphabet) for _ in range(2))
        ids.append(f"{prefix}{suffix}")
    return ids


def _collect_host_data(rng: Optional[random.Random]) -> HostData:
    cpu_brand = _collect_cpu_brand()
    mac_address = _generate_mac_address(rng, fallback=None)
    devman_arch = _detect_devman_architecture()
    return HostData(cpu_brand=cpu_brand, mac_address=mac_address, devman_arch=devman_arch)


def _collect_guest_data(rng: Optional[random.Random], acpi: Optional[AcpiTables]) -> GuestData:
    ssdt_ids = acpi.ssdt if acpi and acpi.ssdt else _synthetic_ssdt_ids(rng)
    dac_type, chip_type = _collect_video_strings()
    return GuestData(
        install_date_hex=_random_install_date_hex(rng),
        machine_guid=_random_machine_guid(rng),
        product_id=_random_product_id(rng),
        ssdt_ids=ssdt_ids,
        dac_type=dac_type,
        chip_type=chip_type,
    )


def _collect_cpu_brand() -> Optional[str]:
    cpu = _ps_single("Win32_Processor", ["Name"])
    brand = _safe_string(cpu, "Name") or platform.processor()
    if brand and len(brand) < 47:
        brand = brand.ljust(47, " ")
    return brand


def _generate_mac_address(rng: Optional[random.Random], fallback: Optional[str]) -> Optional[str]:
    try:
        gateway = netifaces.gateways()
        default_iface = gateway["default"][netifaces.AF_INET][1]
        macme = netifaces.ifaddresses(default_iface)[netifaces.AF_LINK][0]["addr"]
        parts = re.split("[:-]", macme)
        if len(parts) < 3:
            raise ValueError("Unexpected MAC format")
        mac_seed = parts[0] + parts[1] + parts[2]
        pattern = re.compile(r"^([0-9A-Fa-f]{2}){6}$")
        while True:
            rand = rng or random
            candidate = mac_seed + f"{rand.randint(0,255):02x}{rand.randint(0,255):02x}{rand.randint(0,255):02x}"
            if pattern.match(candidate):
                return candidate
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Unable to generate MAC from default interface: %s", exc)
    return fallback


def _detect_devman_architecture() -> Optional[str]:
    path = Path("DevManView.exe")
    if not path.exists():
        return None
    try:
        header = path.read_bytes()
        pe_offset = int.from_bytes(header[0x3C:0x40], byteorder="little", signed=False)
        machine = int.from_bytes(header[pe_offset + 4 : pe_offset + 6], byteorder="little", signed=False)
        if machine == 0x8664:
            return "64"
        if machine == 0x014C:
            return "32"
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Unable to detect DevManView architecture: %s", exc)
    return None


def _collect_video_strings() -> tuple[Optional[str], Optional[str]]:
    video = _ps_single("Win32_VideoController", ["AdapterDACType", "VideoProcessor", "Name", "AdapterCompatibility"])
    if not video:
        return None, None
    dac_type = (_safe_string(video, "AdapterDACType") or _safe_string(video, "AdapterCompatibility") or "").strip()
    chip_type = (_safe_string(video, "VideoProcessor") or _safe_string(video, "Name") or "").strip()
    return (dac_type or None, chip_type or None)


def _random_install_date_hex(rng: Optional[random.Random]) -> str:
    fmt = "%m/%d/%Y %I:%M %p"
    start = "1/1/2012 5:30 PM"
    end = time.strftime(fmt)
    rand = rng.random() if rng else random.random()
    stime = time.mktime(time.strptime(start, fmt))
    etime = time.mktime(time.strptime(end, fmt))
    ptime = stime + rand * (etime - stime)
    return hex(int(ptime))


def _random_product_id(rng: Optional[random.Random]) -> str:
    serial = [5, 3, 7, 5]
    segments: List[str] = []
    for digits in serial:
        numbers = []
        for _ in range(digits):
            numbers.append(str((rng or random).randint(0, 9)))
        segments.append("".join(numbers))
    return "{0}-{1}-{2}-{3}".format(segments[0], segments[1], segments[2], segments[3])


def _random_machine_guid(rng: Optional[random.Random]) -> str:
    if rng is None:
        return str(uuid.uuid4())
    return str(uuid.UUID(int=rng.getrandbits(128)))


def _collect_resources() -> SnapshotResources:
    devman_b64 = _read_base64(Path("DevManView.exe"))
    volumeid_b64 = _read_base64(Path("Volumeid.exe"))
    clipboard_b64 = _read_base64(Path("clipboard_buffer")) if Path("clipboard_buffer").exists() else None
    computer_list = _read_lines(Path("computer.lst"))
    user_list = _read_lines(Path("user.lst"))
    return SnapshotResources(
        devmanview_b64=devman_b64,
        volumeid_b64=volumeid_b64,
        computer_list=computer_list,
        user_list=user_list,
        clipboard_b64=clipboard_b64,
    )


def _serial_randomize(source: str, rng: Optional[random.Random]) -> str:
    cleaned = source.replace("/", "")
    if rng is None:
        pool = uuid.uuid4().hex.upper()
    else:
        alphabet = "0123456789ABCDEF"
        pool = "".join(rng.choice(alphabet) for _ in range(32))
    randomized = pool[: len(cleaned)]
    if "/" not in source:
        return randomized
    positions = [match.start(0) for match in re.finditer("/", source)]
    for idx in positions:
        randomized = randomized[:idx] + "/" + randomized[idx:]
    return randomized


def _maybe_rng(rng: Optional[random.Random]) -> Optional[random.Random]:
    if rng is not None:
        return rng
    env_seed = os.getenv(ENV_SEED_KEY)
    if env_seed is not None:
        try:
            seed_value = int(env_seed)
        except ValueError:
            seed_value = None
        return build_rng(seed_value)
    return None


def _powershell_json(command: str) -> Optional[Any]:
    cmd = ["powershell", "-NoProfile", "-Command", f"{command} | ConvertTo-Json -Depth 4 -Compress"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        LOGGER.debug("PowerShell command failed (%s): %s", result.returncode, result.stderr.strip())
        return None
    output = result.stdout.strip()
    if not output:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        LOGGER.debug("Unable to parse PowerShell output: %s", exc)
        return None


def _ps_single(class_name: str, props: List[str]) -> Optional[Dict[str, Any]]:
    select_props = ", ".join(props)
    data = _powershell_json(f"Get-CimInstance -ClassName {class_name} | Select-Object -Property {select_props}")
    if isinstance(data, list):
        return data[0] if data else None
    if isinstance(data, dict):
        return data
    return None


def _safe_string(obj: Optional[Dict[str, Any]], key: str) -> Optional[str]:
    if isinstance(obj, dict):
        value = obj.get(key)
        if value is None:
            return None
        if isinstance(value, list):
            return str(value[0]) if value else None
        return str(value)
    return None


def _safe_value(obj: Optional[Dict[str, Any]], key: str) -> Optional[Any]:
    if isinstance(obj, dict):
        return obj.get(key)
    return None


def _first_list_value(obj: Optional[Dict[str, Any]], key: str) -> Optional[str]:
    if not isinstance(obj, dict):
        return None
    value = obj.get(key)
    if isinstance(value, list) and value:
        return str(value[0])
    return None


def _parse_wmi_date(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    match = re.match(r"(?P<year>\d{4})(?P<month>\d{2})(?P<day>\d{2})", value)
    if not match:
        return None
    return f"{match.group('month')}/{match.group('day')}/{match.group('year')}"


def _set_with_default(info: Dict[str, str], key: str, value: Optional[str], default: str) -> None:
    if value:
        info[key] = value
    elif key not in info:
        info[key] = default


def _read_base64(path: Path) -> Optional[str]:
    try:
        return base64.b64encode(path.read_bytes()).decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Unable to read %s: %s", path, exc)
        return None


def _read_lines(path: Path) -> List[str]:
    try:
        return [line.rstrip("\\n") for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Unable to read list from %s: %s", path, exc)
        return []
