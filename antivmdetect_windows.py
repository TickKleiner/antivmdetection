#!/usr/bin/env python3
"""
Windows-only helper to generate VirtualBox extradata templates without WSL.

The helper keeps the original behaviour but reorganises the logic into
smaller, named functions to make future maintenance easier.
"""

import base64
import ctypes
import os
import random
import re
import shutil
import subprocess
import sys
import uuid
from typing import Dict, List


DEPENDENCIES = [
    "VBoxManage.exe",
    "DevManView.exe",
    "Volumeid.exe",
    "computer.lst",
    "user.lst",
]


def serial_randomize(start: int = 0, string_length: int = 10) -> str:
    """Return a random serial-like string.

    The string is derived from a UUID and stripped of dashes to keep parity
    with the Linux implementation.
    """

    rand = str(uuid.uuid4()).upper()
    rand = re.sub('-', '', rand)
    return rand[start:string_length]


def require_admin() -> None:
    """Exit if the current process does not have administrative privileges."""

    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return
    except Exception:
        pass
    sys.exit("\n[*] Please run this script from an elevated PowerShell prompt.\n")


def check_dependencies() -> None:
    """Ensure the required binaries and data files are present."""

    missing = [dep for dep in DEPENDENCIES if not os.path.exists(dep) and not shutil.which(dep)]
    if missing:
        sys.exit("\n[*] Dependencies are missing: {}\n".format(", ".join(missing)))


def wmic_csv(query: str) -> List[Dict[str, str]]:
    """Run a WMIC query and return the parsed CSV output."""

    lines = subprocess.getoutput(query).splitlines()
    if len(lines) < 2:
        return []

    header = [h for h in lines[0].split(',') if h]
    results: List[Dict[str, str]] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        parts = line.split(',')
        if len(parts) < len(header):
            continue
        results.append(dict(zip(header, parts)))
    return results


def collect_dmi_info() -> Dict[str, str]:
    """Gather hardware identifiers using WMIC with sensible fallbacks."""

    info: Dict[str, str] = {}
    bios = wmic_csv("wmic bios get Manufacturer,SMBIOSBIOSVersion,ReleaseDate /format:csv")
    if bios:
        row = bios[0]
        info['DmiBIOSVendor'] = "string:" + row.get('Manufacturer', '')
        info['DmiBIOSVersion'] = "string:" + row.get('SMBIOSBIOSVersion', '').replace(" ", "")
        info['DmiBIOSReleaseDate'] = "string:" + row.get('ReleaseDate', '')
    info['DmiBIOSReleaseMajor'] = '** No value to retrieve **'
    info['DmiBIOSReleaseMinor'] = '** No value to retrieve **'
    info['DmiBIOSFirmwareMajor'] = '** No value to retrieve **'
    info['DmiBIOSFirmwareMinor'] = '** No value to retrieve **'

    board = wmic_csv("wmic baseboard get Product,Manufacturer,SerialNumber,Version /format:csv")
    serial_number = ''
    if board:
        row = board[0]
        serial_number = row.get('SerialNumber', '')
        info['DmiBoardVersion'] = "string:" + row.get('Version', '').replace(" ", "")
        info['DmiBoardProduct'] = "string:" + row.get('Product', '').replace(" ", "")
        info['DmiBoardVendor'] = "string:" + row.get('Manufacturer', '').replace(" ", "")
    info['DmiBoardSerial'] = serial_randomize(0, len(serial_number)) if serial_number else '** No value to retrieve **'
    info['DmiBoardAssetTag'] = '** No value to retrieve **'
    info['DmiBoardLocInChass'] = '** No value to retrieve **'
    info['DmiBoardBoardType'] = '** No value to retrieve **'

    system_rows = wmic_csv("wmic computersystem get Model,Manufacturer,SystemSKUNumber,SystemFamily,Name /format:csv")
    system_family = ''
    system_serial = ''
    if system_rows:
        row = system_rows[0]
        system_family = row.get('SystemFamily', '')
        system_serial = row.get('Name', '')
        model = row.get('Model', '')
        info['DmiSystemSKU'] = row.get('SystemSKUNumber', '')
        info['DmiSystemVersion'] = "string:" + model.replace(" ", "")
        info['DmiSystemProduct'] = "string:" + model.replace(" ", "")
        info['DmiSystemVendor'] = "string:" + row.get('Manufacturer', '').replace(" ", "")
    info['DmiSystemFamily'] = "string:" + system_family if system_family else "Not Specified"
    info['DmiSystemUuid'] = str(uuid.uuid4()).upper()
    info['DmiSystemSerial'] = "string:" + (serial_randomize(0, len(system_serial)) if system_serial else serial_randomize())

    enclosure = wmic_csv("wmic systemenclosure get Manufacturer,SerialNumber,SMBIOSAssetTag /format:csv")
    chassi_serial = ''
    if enclosure:
        row = enclosure[0]
        chassi_serial = row.get('SerialNumber', '')
        info['DmiChassisVendor'] = "string:" + row.get('Manufacturer', '').replace(" ", "")
        info['DmiChassisVersion'] = "string:"
        info['DmiChassisType'] = 'Unknown'
        info['DmiChassisAssetTag'] = "string:" + row.get('SMBIOSAssetTag', '')
    info['DmiChassisSerial'] = "string:" + (serial_randomize(0, len(chassi_serial)) if chassi_serial else serial_randomize())

    cpu = wmic_csv("wmic cpu get Name,Manufacturer /format:csv")
    if cpu:
        row = cpu[0]
        info['DmiProcVersion'] = "string:" + row.get('Name', '').replace(" ", "")
        info['DmiProcManufacturer'] = "string:" + row.get('Manufacturer', '').replace(" ", "")

    info['DmiOEMVBoxVer'] = '** No value to retrieve **'
    info['DmiOEMVBoxRev'] = '** No value to retrieve **'
    return info


def gather_disk_info() -> Dict[str, str]:
    """Collect disk metadata from WMIC, adding randomness where needed."""

    disk = wmic_csv("wmic diskdrive get Model,SerialNumber,FirmwareRevision /format:csv")
    if not disk:
        return {}

    row = disk[0]
    serial = row.get('SerialNumber', '') or serial_randomize()
    return {
        'SerialNumber': serial_randomize(0, len(serial)),
        'FirmwareRevision': row.get('FirmwareRevision', '') or '** No value to retrieve **',
        'ModelNumber': row.get('Model', '') or '** No value to retrieve **'
    }


def random_mac_from_host() -> str:
    """Derive a MAC address prefix from the host and randomise the suffix."""

    mac_output = subprocess.getoutput('getmac /FO CSV /NH')
    candidate = mac_output.split(',')[0].replace('"', '') if mac_output else ''
    base = re.sub('[^0-9A-Fa-f]', '', candidate)[:6]
    if len(base) < 6:
        base = '080027'
    while True:
        suffix = "%02x%02x%02x" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
        )
        mac = base + suffix
        if re.match(r'^([0-9A-Fa-f]{12})$', mac):
            return mac


def _write_extradata_lines(
    host_file,
    prefix: str,
    values: Dict[str, str],
) -> None:
    """Write VBoxManage extradata commands, commenting missing values."""

    for key, value in sorted(values.items()):
        path = f"VBoxManage setextradata \"$VmName\" \"{prefix}/{key}\""
        if '** No value to retrieve **' in str(value):
            host_file.write(f"# {path} '{value}'\n")
        else:
            host_file.write(f"{path} '{value}'\n")


def write_host_script(dmi_info: Dict[str, str], disk_info: Dict[str, str], dsdt_name: str | None = None) -> str:
    """Write a host-side PowerShell script containing VBoxManage commands."""

    name_of_file = dmi_info.get('DmiSystemProduct', '').replace(' ', '').replace('string:', '')
    if name_of_file:
        file_name = name_of_file + '_host.ps1'
    else:
        file_name = 'VirtualBoxHost.ps1'

    with open(file_name, 'w') as host:
        host.write("param([Parameter(Mandatory=$true)][string]$VmName)\n")
        host.write("$ErrorActionPreference = 'Stop'\n")
        _write_extradata_lines(host, "VBoxInternal/Devices/pcbios/0/Config", dmi_info)
        _write_extradata_lines(host, "VBoxInternal/Devices/ahci/0/Config/Port0", disk_info)
        if dsdt_name and os.path.isfile(dsdt_name):
            host.write(
                "VBoxManage setextradata \"$VmName\" \"VBoxInternal/Devices/acpi/0/Config/CustomTable\" "
                f"\"$PSScriptRoot\\{dsdt_name}\"\n"
            )
        host.write(f"VBoxManage modifyvm \"$VmName\" --macaddress1 {random_mac_from_host()}\n")

    return file_name


def _encode_file_to_base64(path: str) -> str:
    with open(path, "rb") as file:
        return base64.b64encode(file.read()).decode("utf-8")


def create_guest_script() -> str:
    """Emit a minimal guest PowerShell script restoring required artifacts."""

    encoded_payloads = {
        "Volumeid.exe": _encode_file_to_base64("Volumeid.exe"),
        "computer.lst": _encode_file_to_base64("computer.lst"),
        "user.lst": _encode_file_to_base64("user.lst"),
    }

    file_name = 'guest_modifications.ps1'
    with open(file_name, 'w') as guest:
        guest.write("# Guest modifications generated from Windows host\n")
        for filename, payload in encoded_payloads.items():
            var_name = filename.replace('.', '_')
            guest.write(f'$base64_{var_name} = "{payload}"\n')
            guest.write(
                f"[IO.File]::WriteAllBytes('{filename}',"
                f"[System.Convert]::FromBase64String($base64_{var_name}))\n"
            )
        guest.write("Write-Host 'Please execute the original guest customization steps inside the VM.'\n")

    return file_name


def main():
    require_admin()
    check_dependencies()
    print('[*] Creating VirtualBox modifications from Windows host ..')

    dmi_info = collect_dmi_info()
    disk_info = gather_disk_info()

    host_script = write_host_script(dmi_info, disk_info)
    guest_script = create_guest_script()

    print(f"[*] Finished: A template PowerShell script has been created named: {host_script}")
    print(f"[*] Finished: A guest helper script has been created named: {guest_script}")


if __name__ == "__main__":
    main()
