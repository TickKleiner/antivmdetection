"""Host-side output generation."""
from __future__ import annotations

import base64
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional

from ..model import GenerationArtifacts, HardwareSnapshot

LOGGER = logging.getLogger(__name__)


def generate_host_outputs(snapshot: HardwareSnapshot, output_dir: Path) -> GenerationArtifacts:
    if snapshot.dmi is None:
        raise RuntimeError("Missing DMI information in snapshot")

    output_dir.mkdir(parents=True, exist_ok=True)

    file_name = _host_script_name(snapshot.dmi)
    host_path = output_dir / file_name
    dsdt_name = _dsdt_name(snapshot)
    dsdt_path = _write_dsdt(snapshot, output_dir, dsdt_name)

    lines: List[str] = []
    lines.append(f"#Script generated on: {time.strftime('%H:%M:%S')}")
    lines.append(
        """ if [ $# -eq 0 ]
  then
    echo "[*] Please add vm name!"
    echo "[*] Available vms:"
    VBoxManage list vms | awk -F'"' {' print $2 '} | sed 's/"//g'
    exit
fi """
    )

    for key, value in sorted(snapshot.dmi.items()):
        if value is None:
            continue
        if "** No value to retrieve **" in value:
            lines.append(f'# VBoxManage setextradata "$1" VBoxInternal/Devices/pcbios/0/Config/{key}\t{value}')
        else:
            lines.append(f"VBoxManage setextradata \"$1\" VBoxInternal/Devices/pcbios/0/Config/{key}\t'{value}'")

    lines.extend(_disk_block(snapshot))
    lines.extend(_cdrom_block(snapshot))
    lines.extend(_acpi_block(snapshot))
    if dsdt_name:
        lines.append(f'if [ ! -f "{dsdt_name}" ]; then echo "[WARNING] Unable to find the DSDT file!"; fi')
        lines.append(
            f'VBoxManage setextradata "$1" "VBoxInternal/Devices/acpi/0/Config/CustomTable"\t "$PWD"/{dsdt_name}'
        )

    if snapshot.host and snapshot.host.mac_address:
        lines.append(f'VBoxManage modifyvm "$1" --macaddress1\t{snapshot.host.mac_address}')

    if snapshot.host and snapshot.host.cpu_brand:
        lines.extend(_cpu_brand_block(snapshot.host.cpu_brand))

    lines.extend(_warning_block(snapshot.host.devman_arch if snapshot.host else None))

    host_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return GenerationArtifacts(host_script=host_path, guest_script=None, dsdt_blob=dsdt_path)


def _host_script_name(dmi: Dict[str, str]) -> str:
    name_of_file = dmi.get("DmiSystemProduct", "").replace(" ", "").replace("string:", "")
    if name_of_file:
        return (
            dmi.get("DmiSystemProduct", "").replace(" ", "").replace("/", "_").replace(",", "_").replace("string:", "")
            + ".sh"
        )
    return f"{dmi.get('DmiChassisType', '')}_{dmi.get('DmiBoardProduct', '').replace('string:', '')}.sh"


def _disk_block(snapshot: HardwareSnapshot) -> List[str]:
    disk_lines: List[str] = []
    disk_lines.append('controller=`VBoxManage showvminfo "$1" --machinereadable | grep SATA`')
    disk = snapshot.disk
    if disk is None:
        return disk_lines

    def emit(prefix: str, key: str, value: Optional[str]) -> None:
        if value is None:
            return
        if "** No value to retrieve **" in value:
            disk_lines.append(
                f'# VBoxManage setextradata "$1" VBoxInternal/Devices/{prefix}/Config/PrimaryMaster/{key}\t{value}'
            )
        else:
            disk_lines.append(
                f"VBoxManage setextradata \"$1\" VBoxInternal/Devices/{prefix}/Config/PrimaryMaster/{key}\t'{value}'"
            )

    disk_lines.append('if [[ -z "$controller" ]]; then')
    emit("piix3ide/0", "SerialNumber", disk.serial_number)
    emit("piix3ide/0", "FirmwareRevision", disk.firmware_revision)
    emit("piix3ide/0", "ModelNumber", disk.model_number)
    disk_lines.append("else")
    if disk.serial_number:
        disk_lines.append(
            f"VBoxManage setextradata \"$1\" VBoxInternal/Devices/ahci/0/Config/Port0/SerialNumber\t'{disk.serial_number}'"
        )
    if disk.firmware_revision:
        disk_lines.append(
            f"VBoxManage setextradata \"$1\" VBoxInternal/Devices/ahci/0/Config/Port0/FirmwareRevision\t'{disk.firmware_revision}'"
        )
    if disk.model_number:
        disk_lines.append(
            f"VBoxManage setextradata \"$1\" VBoxInternal/Devices/ahci/0/Config/Port0/ModelNumber\t'{disk.model_number}'"
        )
    disk_lines.append("fi")
    return disk_lines


def _cdrom_block(snapshot: HardwareSnapshot) -> List[str]:
    cd_lines: List[str] = []
    cd = snapshot.cdrom
    if cd is None or all(value is None for value in cd.__dict__.values()):
        cd_lines.append("# No CD-ROM detected: ** No values to retrieve **")
        return cd_lines

    cd_lines.append('if [[ -z "$controller" ]]; then')
    for key, value in {
        "ATAPISerialNumber": cd.atapi_serial,
        "ATAPIRevision": cd.atapi_revision,
        "ATAPIProductId": cd.atapi_product_id,
        "ATAPIVendorId": cd.atapi_vendor_id,
    }.items():
        if value is None:
            continue
        if "** No value to retrieve **" in value:
            cd_lines.append(
                f'# VBoxManage setextradata "$1" VBoxInternal/Devices/piix3ide/0/Config/PrimarySlave/{key}\t{value}'
            )
        else:
            cd_lines.append(
                f"VBoxManage setextradata \"$1\" VBoxInternal/Devices/piix3ide/0/Config/PrimarySlave/{key}\t'{value}'"
            )

    cd_lines.append("else")
    for key, value in {
        "ATAPISerialNumber": cd.atapi_serial,
        "ATAPIRevision": cd.atapi_revision,
        "ATAPIProductId": cd.atapi_product_id,
        "ATAPIVendorId": cd.atapi_vendor_id,
    }.items():
        if value is None:
            continue
        if "** No value to retrieve **" in value:
            cd_lines.append(
                f'# VBoxManage setextradata "$1" VBoxInternal/Devices/ahci/0/Config/Port1/{key}\t{value}'
            )
        else:
            cd_lines.append(
                f"VBoxManage setextradata \"$1\" VBoxInternal/Devices/ahci/0/Config/Port1/{key}\t'{value}'"
            )
    cd_lines.append("fi")
    return cd_lines


def _acpi_block(snapshot: HardwareSnapshot) -> List[str]:
    acpi_lines: List[str] = []
    acpi = snapshot.acpi
    if acpi is None:
        return acpi_lines
    dsdt = acpi.dsdt or []
    if len(dsdt) > 5:
        acpi_lines.append(f"VBoxManage setextradata \"$1\" VBoxInternal/Devices/acpi/0/Config/AcpiOemId\t'{dsdt[1]}'")
        acpi_lines.append(f"VBoxManage setextradata \"$1\" VBoxInternal/Devices/acpi/0/Config/AcpiCreatorId\t'{dsdt[4]}'")
        acpi_lines.append(f"VBoxManage setextradata \"$1\" VBoxInternal/Devices/acpi/0/Config/AcpiCreatorRev\t'{dsdt[5]}'")
    return acpi_lines


def _cpu_brand_block(cpu_brand: str) -> List[str]:
    lines: List[str] = []
    eax_values = ("80000002", "80000003", "80000004")
    registers = ("eax", "ebx", "ecx", "edx")
    i = 4
    while i <= 47:
        for e in eax_values:
            for r in registers:
                k = i - 4
                chunk = cpu_brand[k:i]
                if chunk:
                    rebrand = _chunk_to_hex(chunk)
                    lines.append(f"VBoxManage setextradata \"$1\" VBoxInternal/CPUM/HostCPUID/{e}/{r}  0x{rebrand}\t")
                i = i + 4
    return lines


def _chunk_to_hex(chunk: str) -> str:
    data = chunk.encode("utf-8")
    padded = data + b"\x00" * (4 - len(data))
    value = int.from_bytes(padded, byteorder="little", signed=False)
    return f"{value:08x}"


def _warning_block(devman_arch: Optional[str]) -> List[str]:
    lines: List[str] = []
    lines.append('cpu_count=$(VBoxManage showvminfo --machinereadable "$1" | grep cpus=[0-9]* | sed "s/cpus=//")')
    lines.append('if [ $cpu_count -lt "2" ]; then echo "[WARNING] CPU count is less than 2. Consider adding more!"; fi')
    lines.append('memory_size=$(VBoxManage showvminfo --machinereadable "$1" | grep memory=[0-9]* | sed "s/memory=//")')
    lines.append('if [ $memory_size -lt "2048" ]; then echo "[WARNING] Memory size is 2GB or less. Consider adding more memory!"; fi')
    lines.append('net_used=$(VBoxManage showvminfo "$1" | grep NIC | grep -v disabled | grep -o "vboxnet.")')
    lines.append(
        'hostint_ip=$(VBoxManage list hostonlyifs | grep "$net_used\\|IPAddress:" | sed -n \'2p\' | awk {\' print $2 \'} | grep \'192.168.56.1\')'
    )
    lines.append(
        'if [ "$hostint_ip" == \'192.168.56.1\' ]; then echo "[WARNING] You are using the default IP/IP-range. Consider changing the IP and the range used!"; fi'
    )
    lines.append(
        'virtualization_type=$(VBoxManage showvminfo --machinereadable "$1" | grep -i ^paravirtprovider | cut -d "=" -f2 | sed \'s/"//g\')'
    )
    lines.append("if [ ! $virtualization_type == 'none' ]; then echo \"[WARNING] Please switch paravirtualization interface to: None!\"; fi")
    lines.append('audio=$(VBoxManage showvminfo --machinereadable "$1" | grep audio | cut -d "=" -f2 | sed \'s/"//g\' | head -1)')
    lines.append('if [ $audio == \'none\' ]; then echo "[WARNING] Please consider adding an audio device!"; fi')
    if devman_arch:
        lines.append(f"arc_devman={devman_arch}")
        lines.append(
            'devman_arc=$(VBoxManage showvminfo --machinereadable "$1" | grep ostype | cut -d "=" -f2 | grep -o "(.*)" | sed \'s/(//;s/)//;s/-bit//\')'
        )
        lines.append(
            'if [ $devman_arc != $arc_devman ]; then echo "[WARNING] Please use the DevManView version that coresponds to the guest architecture: $devman_arc "; fi'
        )
    return lines


def _dsdt_name(snapshot: HardwareSnapshot) -> Optional[str]:
    acpi = snapshot.acpi
    if acpi is None:
        return None
    dmi = snapshot.dmi or {}
    name_of_dsdt = dmi.get("DmiSystemProduct", "").replace(" ", "").replace("string:", "")
    if name_of_dsdt:
        return "DSDT_" + dmi.get("DmiSystemProduct", "").replace(" ", "").replace("/", "_").replace("string:", "") + ".bin"
    return "DSDT_" + dmi.get("DmiChassisType", "") + "_" + dmi.get("DmiBoardProduct", "").replace("string:", "") + ".bin"


def _write_dsdt(snapshot: HardwareSnapshot, output_dir: Path, dsdt_name: Optional[str]) -> Optional[Path]:
    acpi = snapshot.acpi
    if acpi is None or not acpi.dsdt_blob_b64 or dsdt_name is None:
        return None
    dsdt_path = output_dir / dsdt_name
    dsdt_bytes = base64.b64decode(acpi.dsdt_blob_b64.encode("utf-8"))
    dsdt_path.write_bytes(dsdt_bytes)
    return dsdt_path
