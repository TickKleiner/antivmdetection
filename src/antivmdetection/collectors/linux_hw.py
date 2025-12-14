"""Linux hardware collectors (live mode)."""
from __future__ import annotations

import base64
import datetime as dt
import logging
import os
import platform
import random
import re
import subprocess
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import dmidecode
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
from ..util.random import build_rng, ENV_SEED_KEY

LOGGER = logging.getLogger(__name__)

DEPENDENCIES = [
    "/usr/bin/cd-drive",
    "/usr/bin/acpidump",
    "/usr/bin/glxinfo",
    "/usr/sbin/smartctl",
    "DevManView.exe",
    "Volumeid.exe",
    "computer.lst",
    "user.lst",
]


def collect_live_snapshot(*, rng: Optional[random.Random] = None) -> HardwareSnapshot:
    if os.geteuid() != 0:
        raise RuntimeError("Root privileges are required to collect hardware data on Linux")

    _check_dependencies()
    rng = _maybe_rng(rng)

    dmi_info = _collect_dmi_info(rng)
    disk_info = _collect_disk_info(rng)
    cdrom_info = _collect_cdrom_info(rng)
    acpi = _collect_acpi_tables()
    cpu_brand = _collect_cpu_brand()
    mac_address = _generate_mac_address(rng)
    devman_arch = _detect_devman_architecture()
    ssdt_ids = _collect_ssdt_ids()
    dac_type, chip_type = _collect_video_strings()
    install_date_hex = _random_install_date_hex(rng)
    product_id = _random_product_id(rng)
    machine_guid = _random_machine_guid(rng)
    resources = _collect_resources()
    metadata = SnapshotMetadata(
        created_from="linux-live",
        created_at=dt.datetime.utcnow().isoformat() + "Z",
        host_identifier=platform.node(),
    )

    guest = GuestData(
        install_date_hex=install_date_hex,
        machine_guid=machine_guid,
        product_id=product_id,
        ssdt_ids=ssdt_ids,
        dac_type=dac_type,
        chip_type=chip_type,
    )
    host = HostData(cpu_brand=cpu_brand, mac_address=mac_address, devman_arch=devman_arch)

    snapshot = HardwareSnapshot(
        dmi=dmi_info,
        disk=disk_info,
        cdrom=cdrom_info,
        acpi=acpi,
        host=host,
        guest=guest,
        resources=resources,
        metadata=metadata,
    )
    return snapshot


def _check_dependencies() -> None:
    missing: List[str] = []
    for dep in DEPENDENCIES:
        if not Path(dep).exists():
            missing.append(dep)
    if missing:
        raise RuntimeError(f"Dependencies are missing, please install or place the following: {', '.join(missing)}")


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


def _collect_dmi_info(rng: Optional[random.Random]) -> Dict[str, str]:
    dmi_info: Dict[str, str] = {}
    biosversion: Optional[str] = None
    system_family: Optional[str] = None
    system_serial: Optional[str] = None
    serial_number: Optional[str] = None
    chassi_serial: Optional[str] = None
    chassi_type: Optional[str] = None

    try:
        for v in dmidecode.get_by_type(0):
            if isinstance(v, dict) and v.get("DMIType") == 0:
                dmi_info["DmiBIOSVendor"] = "string:" + v["Vendor"]
                dmi_info["DmiBIOSVersion"] = "string:" + v["Version"].replace(" ", "")
                biosversion = v.get("BIOS Revision")
                dmi_info["DmiBIOSReleaseDate"] = "string:" + v["Release Date"]
    except Exception as exc:  # noqa: BLE001
        LOGGER.debug("BIOS decode failed: %s", exc)
        dmi_info["DmiBIOSReleaseDate"] = "string:** No value to retrieve **"

    try:
        major, minor = (biosversion or "").split(".", 1)
        dmi_info["DmiBIOSReleaseMajor"] = major
        dmi_info["DmiBIOSReleaseMinor"] = minor
    except Exception:
        dmi_info["DmiBIOSReleaseMajor"] = "** No value to retrieve **"
        dmi_info["DmiBIOSReleaseMinor"] = "** No value to retrieve **"

    dmi_firmware = subprocess.getoutput("dmidecode t0")
    try:
        fw_major, fw_minor = re.search(r"Firmware Revision: ([0-9A-Za-z. ]*)", dmi_firmware).group(1).split(".", 1)  # type: ignore[union-attr]
        dmi_info["DmiBIOSFirmwareMajor"] = fw_major
        dmi_info["DmiBIOSFirmwareMinor"] = fw_minor
    except Exception:
        dmi_info["DmiBIOSFirmwareMajor"] = "** No value to retrieve **"
        dmi_info["DmiBIOSFirmwareMinor"] = "** No value to retrieve **"

    for v in dmidecode.get_by_type(2):
        if isinstance(v, dict) and v.get("DMIType") == 2:
            serial_number = v.get("Serial Number")
            dmi_info["DmiBoardVersion"] = "string:" + v["Version"].replace(" ", "")
            dmi_info["DmiBoardProduct"] = "string:" + v["Product Name"].replace(" ", "")
            dmi_info["DmiBoardVendor"] = "string:" + v["Manufacturer"].replace(" ", "")

    try:
        if serial_number:
            dmi_info["DmiBoardSerial"] = _serial_randomize(serial_number, rng)
        else:
            dmi_info["DmiBoardSerial"] = "** No value to retrieve **"
    except Exception:
        dmi_info["DmiBoardSerial"] = "** No value to retrieve **"

    dmi_board = subprocess.getoutput("dmidecode -t2")
    try:
        asset_tag = re.search(r"Asset Tag: ([0-9A-Za-z ]*)", dmi_board).group(1)  # type: ignore[union-attr]
    except Exception:
        asset_tag = "** No value to retrieve **"
    dmi_info["DmiBoardAssetTag"] = "string:" + asset_tag

    try:
        loc_chassis = re.search(r"Location In Chassis: ([0-9A-Za-z ]*)", dmi_board).group(1)  # type: ignore[union-attr]
    except Exception:
        loc_chassis = "** No value to retrieve **"
    dmi_info["DmiBoardLocInChass"] = "string:" + loc_chassis.replace(" ", "")

    board_dict = {
        "Unknown": 1,
        "Other": 2,
        "Server Blade": 3,
        "Connectivity Switch": 4,
        "System Management Module": 5,
        "Processor Module": 6,
        "I/O Module": 7,
        "Memory Module": 8,
        "Daughter board": 9,
        "Motherboard": 10,
        "Processor/Memory Module": 11,
        "Processor/IO Module": 12,
        "Interconnect board": 13,
    }
    try:
        board_type = re.search(r"Type: ([0-9A-Za-z ]+)", dmi_board).group(1)  # type: ignore[union-attr]
        dmi_info["DmiBoardBoardType"] = str(board_dict.get(board_type, board_type))
    except Exception:
        dmi_info["DmiBoardBoardType"] = "** No value to retrieve **"

    for v in dmidecode.get_by_type(1):
        if isinstance(v, dict) and v.get("DMIType") == 1:
            dmi_info["DmiSystemSKU"] = v.get("SKU Number", "** No value to retrieve **")
            system_family = v.get("Family")
            system_serial = v.get("Serial Number")
            dmi_info["DmiSystemVersion"] = "string:" + v.get("Version", "").replace(" ", "")
            dmi_info["DmiSystemProduct"] = "string:" + v.get("Product Name", "").replace(" ", "")
            dmi_info["DmiSystemVendor"] = "string:" + v.get("Manufacturer", "").replace(" ", "")

    dmi_info["DmiSystemFamily"] = "string:" + system_family if system_family else "Not Specified"
    dmi_info["DmiSystemUuid"] = (
        uuid.UUID(int=rng.getrandbits(128)).hex.upper() if rng else (uuid.uuid4().hex or "").upper()
    )

    if system_serial:
        dmi_info["DmiSystemSerial"] = "string:" + _serial_randomize(system_serial, rng)
    else:
        dmi_info["DmiSystemSerial"] = "string:** No value to retrieve **"

    for v in dmidecode.get_by_type(3):
        dmi_info["DmiChassisVendor"] = "string:" + v.get("Manufacturer", "").replace(" ", "")
        chassi_serial = v.get("Serial Number", "")
        dmi_info["DmiChassisVersion"] = "string:" + v.get("Version", "").replace(" ", "")
        chassi_type = v.get("Type")

    chassi_dict = {
        "Other": 1,
        "Unknown": 2,
        "Desktop": 3,
        "Low Profile Desktop": 4,
        "Pizza Box": 5,
        "Mini Tower": 6,
        "Tower": 7,
        "Portable": 8,
        "Laptop": 9,
        "Notebook": 10,
        "Hand Held": 11,
        "Docking Station": 12,
        "All in One": 13,
        "Sub Notebook": 14,
        "Space-saving": 15,
        "Lunch Box": 16,
        "Main Server Chassis": 17,
        "Expansion Chassis": 18,
        "SubChassis": 19,
        "Bus Expansion Chassis": 20,
        "Peripheral Chassis": 21,
        "RAID Chassis": 22,
        "Rack Mount Chassis": 23,
        "Sealed-case PC": 24,
        "Multi-system chassis": 25,
        "Compact PCI": 26,
        "Advanced TCA": 27,
        "Blade": 28,
        "Blade Enclosure": 29,
        "Tablet": 30,
        "Convertible": 31,
        "Detachable": 32,
        "IoT Gateway": 33,
        "Embedded PC": 34,
        "Mini PC": 35,
        "Stick PC": 36,
    }
    dmi_info["DmiChassisType"] = str(chassi_dict.get(chassi_type, chassi_type))

    chassi = subprocess.getoutput("dmidecode -t3")
    try:
        dmi_info["DmiChassisAssetTag"] = "string:" + re.search(r"Asset Tag: ([0-9A-Za-z ]*)", chassi).group(1)  # type: ignore[union-attr]
    except Exception:
        dmi_info["DmiChassisAssetTag"] = "** No value to retrieve **"

    if chassi_serial:
        dmi_info["DmiChassisSerial"] = "string:" + _serial_randomize(chassi_serial, rng)
    else:
        dmi_info["DmiChassisSerial"] = "string:** No value to retrieve **"

    for v in dmidecode.get_by_type(4):
        dmi_info["DmiProcVersion"] = "string:" + v.get("Version", "").replace(" ", "")
        dmi_info["DmiProcManufacturer"] = "string:" + v.get("Manufacturer", "").replace(" ", "")

    try:
        for v in dmidecode.get_by_type(11):
            oem_ver = v["Strings"]["3"]
            oem_rev = v["Strings"]["2"]
            dmi_info["DmiOEMVBoxVer"] = "string:" + oem_ver
            dmi_info["DmiOEMVBoxRev"] = "string:" + oem_rev
    except Exception:
        dmi_info["DmiOEMVBoxVer"] = "** No value to retrieve **"
        dmi_info["DmiOEMVBoxRev"] = "** No value to retrieve **"

    return dmi_info


def _collect_disk_info(rng: Optional[random.Random]) -> DiskInfo:
    disk_info = DiskInfo()
    disk_name = subprocess.getoutput("df -P / | tail -n 1 | awk '/.*/ { print $1 }'")
    if "/cow" in disk_name:
        disk_name = "/dev/sdb"

    if not Path(disk_name).exists():
        return disk_info

    try:
        disk_serial = subprocess.getoutput(
            f"smartctl -i {disk_name} | grep -o 'Serial Number:  [A-Za-z0-9_\\+\\/ .\"-]*' | awk '{{print $3}}'"
        )
        if disk_serial and "SG_IO" not in disk_serial:
            disk_info.serial_number = _serial_randomize(disk_serial, rng)
        else:
            LOGGER.warning("Unable to acquire disk serial number, using fallback")
            disk_info.serial_number = _serial_randomize("HUA721010KLA330", rng)
        if disk_info.serial_number and len(disk_info.serial_number) > 20:
            disk_info.serial_number = disk_info.serial_number[:20]
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Error reading disk serial: %s", exc)

    try:
        disk_fwrev = subprocess.getoutput(
            f"smartctl -i {disk_name} | grep -o 'Firmware Version: [A-Za-z0-9_\\+\\/ .\"-]*' | awk '{{print $3}}'"
        )
        if disk_fwrev and "SG_IO" not in disk_fwrev:
            disk_info.firmware_revision = disk_fwrev
        else:
            LOGGER.warning("Unable to acquire disk firmware revision, using fallback")
            disk_info.firmware_revision = _serial_randomize("LMP07L3Q", rng)
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Error reading disk firmware: %s", exc)

    try:
        disk_modelno = subprocess.getoutput(
            f"smartctl -i {disk_name} | grep -o 'Model Family: [A-Za-z0-9_\\+\\/ .\"-]*' | awk '{{print $3}}'"
        )
        if disk_modelno and "SG_IO" not in disk_modelno:
            disk_info.model_number = disk_modelno
        else:
            LOGGER.warning("Unable to acquire disk model number, using fallback")
            vendor_part1 = _serial_randomize("F8E36628D278", rng)
            vendor_part2 = _serial_randomize("611D3", rng)
            disk_info.model_number = f"SAMSUNG {vendor_part1}-{vendor_part2}"
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Error reading disk model: %s", exc)

    return disk_info


def _collect_cdrom_info(rng: Optional[random.Random]) -> CdromInfo:
    info = CdromInfo()
    if not os.path.islink("/dev/cdrom"):
        return info

    cdrom_serial = subprocess.getoutput(
        "hdparm -i /dev/cdrom | grep -o 'SerialNo=[A-Za-z0-9_\\+\\/ .\"-]*' | awk -F= '{print $2}'"
    )
    if cdrom_serial:
        info.atapi_serial = _serial_randomize(cdrom_serial, rng)
    else:
        info.atapi_serial = "** No value to retrieve **"

    info.atapi_revision = subprocess.getoutput("cd-drive | grep Revision | grep  ':' | awk {' print $3 \" \" $4'}").replace(
        " ", ""
    )
    info.atapi_product_id = subprocess.getoutput("cd-drive | grep Model | grep  ':' | awk {' print $3 \" \" $4'}")
    info.atapi_vendor_id = subprocess.getoutput("cd-drive | grep Vendor | grep  ':' | awk {' print $3 '}")
    return info


def _collect_acpi_tables() -> AcpiTables:
    dsdt = subprocess.getoutput('acpidump -s | grep DSDT | grep -o "\\(([A-Za-z0-9].*)\\)" | tr -d "()"')
    facp = subprocess.getoutput('acpidump -s | grep FACP | grep -o "\\(([A-Za-z0-9].*)\\)" | tr -d "()"')

    if "option requires" in dsdt:
        release = subprocess.getoutput("lsb_release -r | awk {' print $2 '}")
        raise RuntimeError(f"The version of acpidump included in {release} is not supported")

    dsdt_list = list(filter(None, dsdt.split(" ")))
    facp_list = list(filter(None, facp.split(" ")))

    if dsdt_list and isinstance(dsdt_list[0], str):
        try:
            dsdt_list[5] = re.sub("[^0-9]", "", dsdt_list[5])
        except Exception:
            pass

    rsdt_ids = []
    acpi = AcpiTables(dsdt=dsdt_list, facp=facp_list, rsdt=rsdt_ids)

    dsdt_path = Path("/sys/firmware/acpi/tables/DSDT")
    if dsdt_path.exists():
        dsdt_blob = dsdt_path.read_bytes()
        acpi.dsdt_blob_b64 = base64.b64encode(dsdt_blob).decode("utf-8")

    return acpi


def _collect_cpu_brand() -> str:
    cpu_brand = subprocess.getoutput("cat /proc/cpuinfo | grep -m 1 'model name' | cut -d  ':' -f2 | sed 's/^ *//'")
    if len(cpu_brand) < 47:
        cpu_brand = cpu_brand.ljust(47, " ")
    return cpu_brand


def _generate_mac_address(rng: Optional[random.Random]) -> str:
    gateway = netifaces.gateways()
    default_iface = gateway["default"][netifaces.AF_INET][1]
    macme = netifaces.ifaddresses(default_iface)[netifaces.AF_LINK][0]["addr"]
    parts = macme.split(":")
    mac_seed = parts[0] + parts[1] + parts[2]
    pattern = re.compile(r"^([0-9A-Fa-f]{2}){5}([0-9A-Fa-f]{2})$")
    while True:
        rand = rng or random
        big_mac = mac_seed + "%02x:%02x:%02x" % (rand.randint(0, 255), rand.randint(0, 255), rand.randint(0, 255))
        le_big_mac = re.sub(":", "", big_mac)
        if pattern.match(le_big_mac):
            return le_big_mac


def _detect_devman_architecture() -> Optional[str]:
    try:
        output = subprocess.getoutput("file -b DevManView.exe | grep -o '80386\\|64' | sed 's/80386/32/'")
        return output.strip() if output else None
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Unable to detect DevManView architecture: %s", exc)
    return None


def _collect_ssdt_ids() -> List[str]:
    ssdt1 = subprocess.getoutput("sudo acpidump -s | grep SSDT | grep -o '\\(([A-Za-z0-9].*)\\)' | head -n 1 | awk {' print $2 '}")
    ssdt2 = subprocess.getoutput("sudo acpidump -s | grep SSDT | grep -o '\\(([A-Za-z0-9].*)\\)' | head -n 1 | awk {' print $3 '}")
    ssdt3 = subprocess.getoutput("sudo acpidump -s | grep SSDT | grep -o '\\(([A-Za-z0-9].*)\\)' | head -n 1 | awk {' print $4 '}")
    return [value for value in (ssdt1, ssdt2, ssdt3) if value]


def _collect_video_strings() -> tuple[Optional[str], Optional[str]]:
    dactype1 = subprocess.getoutput("lspci | grep -i VGA | cut -d ':' -f3 | awk {' print $1 '}")
    dactype2 = subprocess.getoutput("lspci | grep -i VGA | cut -d ':' -f3 | awk {' print $2 '}")
    dac_type = (dactype1 + " " + dactype2).strip() if dactype1 or dactype2 else None

    chip1 = subprocess.getoutput(
        "glxinfo -B | grep 'OpenGL renderer string' | cut -d ':' -f2 | sed  's/Mesa DRI//' | awk {' print $1 '} "
    )
    chip2 = subprocess.getoutput(
        "glxinfo -B | grep 'OpenGL renderer string' | cut -d ':' -f2 | sed  's/Mesa DRI//' | awk {' print $2 '} "
    )

    if "Error: unable to open display" in chip1:
        LOGGER.warning("Unable to retrieve GLX info; falling back to lshw for vendor strings")
        chip1 = subprocess.getoutput("lshw -c video | grep -i vendor: | awk ' { print  $2 } '")
        chip2 = subprocess.getoutput("lshw -c video | grep -i vendor: | awk ' { print  $3 } '")

    if "Ivybridge" in chip2:
        chip2 = "Sandybridge/Ivybridge"

    chip_type = (chip1 + " " + chip2).strip() if chip1 or chip2 else None
    return dac_type, chip_type


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


def _read_base64(path: Path) -> Optional[str]:
    try:
        return base64.b64encode(path.read_bytes()).decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Unable to read %s: %s", path, exc)
        return None


def _read_lines(path: Path) -> List[str]:
    try:
        return [line.rstrip("\n") for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Unable to read list from %s: %s", path, exc)
        return []
