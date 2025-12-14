"""Guest-side output generation."""
from __future__ import annotations

import base64
import logging
from pathlib import Path
from typing import Dict, List, Optional

from ..model import GenerationArtifacts, HardwareSnapshot

LOGGER = logging.getLogger(__name__)
CRLF = "\r\n"


def generate_guest_outputs(snapshot: HardwareSnapshot, output_dir: Path) -> GenerationArtifacts:
    if snapshot.dmi is None:
        raise RuntimeError("Missing DMI information in snapshot")

    output_dir.mkdir(parents=True, exist_ok=True)
    file_name = _guest_script_name(snapshot.dmi)
    guest_path = output_dir / file_name

    acpi = snapshot.acpi
    dsdt = acpi.dsdt if acpi else []
    facp = acpi.facp if acpi else []
    ssdt_ids = snapshot.guest.ssdt_ids if snapshot.guest else []
    resources = snapshot.resources
    has_lists = bool(resources and resources.computer_list and resources.user_list)
    has_volumeid = bool(resources and resources.volumeid_b64)
    if not has_volumeid:
        LOGGER.warning("Volumeid.exe missing in snapshot resources; volume ID spoofing will be skipped")
    if not has_lists:
        LOGGER.warning("computer.lst/user.lst missing in snapshot resources; using fallback names for rename and file generation")

    manu_prefill = _manu_prefix(dsdt, double_underscore=True)
    manu = _manu_prefix(dsdt, double_underscore=False)
    version = "$version = (Get-WmiObject win32_operatingsystem).version"
    lines: List[str] = [version]
    lines.extend(_windows_admin_block())

    lines.extend(_dsdt_block(dsdt, manu_prefill))
    lines.extend(_fadt_block(manu, facp))
    lines.extend(_rsdt_block(manu, dsdt))
    lines.extend(_ssdt_block(ssdt_ids))

    dmi = snapshot.dmi
    lines.append(
        f'New-ItemProperty -Path HKLM:\\HARDWARE\\DESCRIPTION\\System -Name SystemBiosVersion -Value "{_safe(dsdt, 1)} - {_safe(dsdt,0)}" -PropertyType "String" -force'
    )
    lines.append(
        f'New-ItemProperty -Path HKLM:\\HARDWARE\\DESCRIPTION\\System -Name VideoBiosVersion -Value "{_safe(dsdt,0)}" -PropertyType "String" -force'
    )
    lines.append(_system_bios_date_line(dmi))

    if snapshot.guest:
        lines.append(
            f'New-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" -Name InstallDate -Value "{snapshot.guest.install_date_hex}" -PropertyType "DWord" -force'
        )
        lines.append(
            f'New-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Internet Explorer\\SQM" -Name InstallDate -Value "{snapshot.guest.install_date_hex}" -PropertyType "DWord" -force'
        )
        lines.append(
            f'New-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Cryptography -Name MachineGuid -Value "{snapshot.guest.machine_guid}" -PropertyType "String" -force'
        )

    lines.append('if ($version  -like \'10.0*\') {')
    if snapshot.guest:
        lines.extend(_video_block(snapshot.guest.dac_type, snapshot.guest.chip_type))
    lines.append("}")

    lines.extend(_devman_block(snapshot.resources.devmanview_b64 if snapshot.resources else None))
    lines.extend(_clipboard_block(snapshot.resources.clipboard_b64 if snapshot.resources else None))
    lines.extend(_notepad_block())
    lines.extend(_waldo_block())

    if snapshot.guest:
        lines.extend(_product_id_block(snapshot.guest.product_id))

    if has_volumeid:
        lines.extend(_volumeid_block(snapshot.resources.volumeid_b64 if snapshot.resources else None))
    else:
        lines.append('Write-Warning "Volumeid.exe not provided in snapshot resources; skipping volume ID spoofing."')

    lines.extend(_computer_user_blocks(snapshot.resources, has_volumeid=has_volumeid, has_lists=has_lists))
    lines.extend(_powershell_blob_block(has_lists=has_lists))
    lines.extend(_assoc_block())
    lines.extend(_sanitize_block())
    lines.append('[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")')
    lines.append('[System.Windows.Forms.MessageBox]::Show("The computer needs to reboot")')
    lines.append("Restart-Computer")

    guest_path.write_text(CRLF.join(lines) + CRLF, encoding="utf-8")
    return GenerationArtifacts(host_script=None, guest_script=guest_path, dsdt_blob=None)


def _guest_script_name(dmi: Dict[str, str]) -> str:
    name_of_ps1 = dmi.get("DmiSystemProduct", "").replace(" ", "").replace("string:", "")
    if name_of_ps1:
        return (
            dmi.get("DmiSystemProduct", "").replace(" ", "").replace("/", "_").replace("string:", "")
            + ".ps1"
        )
    return f"{dmi.get('DmiChassisType', '')}_{dmi.get('DmiBoardProduct', '').replace('string:', '')}.ps1"


def _windows_admin_block() -> List[str]:
    return [
        "# Ensure we are running with elevation before touching ACPI/registry",
        "$isAdministrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
        "if (-not $isAdministrator) {",
        '    Write-Warning "Administrator privileges are required for this script. Relaunching elevated..."',
        "    $argsList = @()",
        "    if ($MyInvocation.UnboundArguments) { $argsList += $MyInvocation.UnboundArguments }",
        '    if ($PSCommandPath) { $argsList = @("-File", "`"$PSCommandPath`"") + $argsList }',
        '    Start-Process -FilePath "powershell.exe" -ArgumentList $argsList -Verb RunAs -ErrorAction Stop',
        "    exit",
        "}",
    ]


def _manu_prefix(dsdt: List[str], double_underscore: bool) -> str:
    manufacturer = _safe(dsdt, 1)
    if double_underscore and ("DELL" in manufacturer or "INTEL" in manufacturer):
        return manufacturer + "__"
    if not double_underscore and "INTEL" in manufacturer:
        return manufacturer + "_"
    return manufacturer


def _safe(items: List[str], idx: int, default: str = "") -> str:
    try:
        return items[idx]
    except Exception:
        return default


def _dsdt_block(dsdt: List[str], manu: str) -> List[str]:
    if not manu:
        LOGGER.warning("Missing DSDT manufacturer in snapshot; skipping DSDT rewrite")
        return []

    lines: List[str] = []
    lines.append(f'Copy-Item -Path HKLM:\\HARDWARE\\ACPI\\DSDT\\VBOX__ -Destination HKLM:\\HARDWARE\\ACPI\\DSDT\\{manu} -Recurse')
    lines.append('Remove-Item -Path HKLM:\\HARDWARE\\ACPI\\DSDT\\VBOX__ -Recurse')

    table_id = _safe(dsdt, 2).strip()
    entry_id = _safe(dsdt, 3).strip()
    if not table_id or not entry_id:
        LOGGER.warning("Missing DSDT table identifiers; skipping table renames")
        return lines

    lines.append(
        f'Copy-Item -Path HKLM:\\HARDWARE\\ACPI\\DSDT\\{manu}\\VBOXBIOS -Destination HKLM:\\HARDWARE\\ACPI\\DSDT\\{manu}\\{table_id}___ -Recurse'
    )
    lines.append(f'Remove-Item -Path HKLM:\\HARDWARE\\ACPI\\DSDT\\{manu}\\VBOXBIOS -Recurse')
    lines.append(
        f'Copy-Item -Path HKLM:\\HARDWARE\\ACPI\\DSDT\\{manu}\\{table_id}___\\00000002 -Destination HKLM:\\HARDWARE\\ACPI\\DSDT\\{manu}\\{table_id}___\\{entry_id} -Recurse'
    )
    lines.append(f'Remove-Item -Path HKLM:\\HARDWARE\\ACPI\\DSDT\\{manu}\\{table_id}___\\00000002 -Recurse')
    return lines


def _fadt_block(manu: str, facp: List[str]) -> List[str]:
    table_id = _safe(facp, 2).strip()
    entry_id = _safe(facp, 3).strip()
    if not (manu and table_id and entry_id):
        LOGGER.warning("Missing FADT identifiers; skipping FADT rename block")
        return []

    lines: List[str] = []
    lines.append("if ($version -like '10.0*') {")
    lines.append('$oddity = "HKLM:\\HARDWARE\\ACPI\\FADT\\" + (Get-ChildItem "HKLM:\\HARDWARE\\ACPI\\FADT" -Name)')
    lines.append('if ($oddity -ne "HKLM:\\HARDWARE\\ACPI\\FADT\\' + manu + '") {')
    lines.append('Invoke-Expression ("Copy-Item -Path " + $oddity + " -Destination HKLM:\\HARDWARE\\ACPI\\FADT\\' + manu + ' -Recurse")')
    lines.append('Invoke-Expression ("Remove-Item -Path " + $oddity + " -Recurse")')
    lines.append("}")
    lines.append(
        f'Copy-Item -Path HKLM:\\HARDWARE\\ACPI\\FADT\\{manu}\\VBOXFACP -Destination HKLM:\\HARDWARE\\ACPI\\FADT\\{manu}\\{table_id}___ -Recurse'
    )
    lines.append(f'Remove-Item -Path HKLM:\\HARDWARE\\ACPI\\FADT\\{manu}\\VBOXFACP -Recurse')
    lines.append(
        f'Copy-Item -Path HKLM:\\HARDWARE\\ACPI\\FADT\\{manu}\\{table_id}___\\00000001 -Destination HKLM:\\HARDWARE\\ACPI\\FADT\\{manu}\\{table_id}___\\{entry_id} -Recurse'
    )
    lines.append(
        f'Remove-Item -Path HKLM:\\HARDWARE\\ACPI\\FADT\\{manu}\\{table_id}___\\00000001 -Recurse'
    )
    lines.append("}else{")
    lines.append(
        f'Copy-Item -Path HKLM:\\HARDWARE\\ACPI\\FADT\\{manu}\\VBOXFACP -Destination HKLM:\\HARDWARE\\ACPI\\FADT\\{manu}\\{table_id}___ -Recurse'
    )
    lines.append(f'Remove-Item -Path HKLM:\\HARDWARE\\ACPI\\FADT\\{manu}\\VBOXFACP -Recurse')
    lines.append(
        f'Copy-Item -Path HKLM:\\HARDWARE\\ACPI\\FADT\\{manu}\\{table_id}___\\00000001 -Destination HKLM:\\HARDWARE\\ACPI\\FADT\\{manu}\\{table_id}___\\{entry_id} -Recurse'
    )
    lines.append(
        f'Remove-Item -Path HKLM:\\HARDWARE\\ACPI\\FADT\\{manu}\\{table_id}___\\00000001 -Recurse'
    )
    lines.append("}")
    return lines


def _rsdt_block(manu: str, dsdt: List[str]) -> List[str]:
    table_id = _safe(dsdt, 2).strip()
    entry_id = _safe(dsdt, 3).strip()
    if not (manu and table_id and entry_id):
        LOGGER.warning("Missing RSDT identifiers; skipping RSDT rename block")
        return []

    lines: List[str] = []
    lines.append("if ($version -like '10.0*') {")
    lines.append('$noproblem = "HKLM:\\HARDWARE\\ACPI\\RSDT\\" + (Get-ChildItem "HKLM:\\HARDWARE\\ACPI\\RSDT" -Name)')
    lines.append('if ($noproblem  -ne "HKLM:\\HARDWARE\\ACPI\\RSDT\\' + manu + '") {')
    lines.append('Invoke-Expression ("Copy-Item -Path " + $noproblem + " -Destination HKLM:\\HARDWARE\\ACPI\\RSDT\\' + manu + ' -Recurse")')
    lines.append('Invoke-Expression ("Remove-Item -Path " + $noproblem + " -Recurse")')
    lines.append("}")
    lines.append('$cinnamon = "HKLM:\\HARDWARE\\ACPI\\RSDT\\" + (Get-ChildItem "HKLM:\\HARDWARE\\ACPI\\RSDT" -Name)')
    lines.append('$the_mero = "HKLM:\\HARDWARE\\ACPI\\RSDT\\" + (Get-ChildItem "HKLM:\\HARDWARE\\ACPI\\RSDT" -Name) + "\\" + (Get-ChildItem $cinnamon -Name)')
    lines.append(
        f'Invoke-Expression ("Copy-Item -Path " + $the_mero + " -Destination HKLM:\\HARDWARE\\ACPI\\RSDT\\{manu}\\{table_id}___ -Recurse")'
    )
    lines.append('Invoke-Expression ("Remove-Item -Path " + $the_mero + " -Recurse")')
    lines.append(
        f'Copy-Item -Path HKLM:\\HARDWARE\\ACPI\\RSDT\\{manu}\\{table_id}___\\00000001 -Destination HKLM:\\HARDWARE\\ACPI\\RSDT\\{manu}\\{table_id}___\\{entry_id} -Recurse'
    )
    lines.append(
        f'Remove-Item -Path HKLM:\\HARDWARE\\ACPI\\RSDT\\{manu}\\{table_id}___\\00000001 -Recurse'
    )
    lines.append("}else{")
    lines.append(
        f'$check_exist = (Test-Path HKLM:\\HARDWARE\\ACPI\\RSDT\\{manu}\\{table_id}___\\00000001)'
    )
    lines.append("if ($check_exist) {")
    lines.append(
        f'Copy-Item -Path HKLM:\\HARDWARE\\ACPI\\RSDT\\{manu}\\{table_id}___\\00000001 -Destination HKLM:\\HARDWARE\\ACPI\\RSDT\\{manu}\\{table_id}___\\{entry_id} -Recurse'
    )
    lines.append(
        f'Remove-Item -Path HKLM:\\HARDWARE\\ACPI\\RSDT\\{manu}\\{table_id}___\\00000001 -Recurse'
    )
    lines.append("}else{")
    lines.append(
        f'Copy-Item -Path HKLM:\\HARDWARE\\ACPI\\RSDT\\{manu}\\{table_id}\\00000001 -Destination HKLM:\\HARDWARE\\ACPI\\RSDT\\{manu}\\{table_id}\\{entry_id} -Recurse'
    )
    lines.append(
        f'Remove-Item -Path HKLM:\\HARDWARE\\ACPI\\RSDT\\{manu}\\{table_id}\\00000001 -Recurse'
    )
    lines.append("}}")
    return lines


def _ssdt_block(ssdt_ids: List[str]) -> List[str]:
    if not ssdt_ids:
        return []
    s1 = _safe(ssdt_ids, 0).strip()
    s2 = _safe(ssdt_ids, 1).strip()
    s3 = _safe(ssdt_ids, 2).strip()
    if not (s1 and s2 and s3):
        LOGGER.warning("Missing SSDT identifiers; skipping SSDT rename block")
        return []
    lines: List[str] = []
    lines.append("if ($version  -like '10.0*') {")
    lines.append('$check_exist = (Test-Path HKLM:\\HARDWARE\\ACPI\\SSDT)')
    lines.append("if ($check_exist) {")
    lines.append(f'Copy-Item -Path HKLM:\\HARDWARE\\ACPI\\SSDT\\VBOX__ -Destination HKLM:\\HARDWARE\\ACPI\\SSDT\\{s1} -Recurse')
    lines.append(f'Remove-Item -Path HKLM:\\HARDWARE\\ACPI\\SSDT\\VBOX__ -Recurse')
    lines.append(
        f'Copy-Item -Path HKLM:\\HARDWARE\\ACPI\\SSDT\\{s1}\\VBOXCPUT -Destination HKLM:\\HARDWARE\\ACPI\\SSDT\\{s1}\\{s2}___ -Recurse'
    )
    lines.append(f'Remove-Item -Path HKLM:\\HARDWARE\\ACPI\\SSDT\\{s1}\\VBOXCPUT -Recurse')
    lines.append(
        f'Copy-Item -Path HKLM:\\HARDWARE\\ACPI\\SSDT\\{s1}\\{s2}___\\00000002 -Destination HKLM:\\HARDWARE\\ACPI\\SSDT\\{s1}\\{s2}___\\{s3} -Recurse'
    )
    lines.append(
        f'Remove-Item -Path HKLM:\\HARDWARE\\ACPI\\SSDT\\{s1}\\{s2}___\\00000002 -Recurse'
    )
    lines.append("}")
    lines.append("}")
    return lines


def _system_bios_date_line(dmi: Dict[str, str]) -> str:
    d_month, d_day, d_year = ("", "", "")
    try:
        month, day, year = dmi.get("DmiBIOSReleaseDate", "").split("/")
        d_month = month.replace("string:", "")
        d_day = day
        d_year = year[2:] if len(year) > 2 else year
    except Exception:
        pass
    return f'New-ItemProperty -Path HKLM:\\HARDWARE\\DESCRIPTION\\System -Name SystemBiosDate -Value "{d_month}/{d_day}/{d_year}" -PropertyType "String" -force'


def _video_block(dac_type: Optional[str], chip_type: Optional[str]) -> List[str]:
    lines: List[str] = []
    if dac_type:
        lines.append('$DacType = ((Get-ItemProperty -path \'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Video\\*\\0000\')."HardwareInformation.DacType")')
        lines.append("if ($DacType -eq 'Oracle Corporation') {")
        lines.append(f'New-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Video\\*\\0000 -Name HardwareInformation.DacType -Value "{dac_type}" -PropertyType "String" -force }}')
        lines.append('$DacType = ((Get-ItemProperty -path \'HKLM:\\SYSTEM\\ControlSet001\\Control\\Class\\*\\0016\')."HardwareInformation.DacType")')
        lines.append("if ($DacType -eq 'Oracle Corporation') {")
        lines.append(f'New-ItemProperty -Path HKLM:\\SYSTEM\\ControlSet001\\Control\\Class\\*\\0016 -Name HardwareInformation.DacType -Value "{dac_type}" -PropertyType "String" -force }}')
    if chip_type:
        lines.append('$ChipType = ((Get-ItemProperty -path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Video\\*\\0000)."HardwareInformation.ChipType")')
        lines.append("if ($ChipType -eq 'VirtualBox VESA BIOS') {")
        lines.append(f'New-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Video\\*\\0000 -Name HardwareInformation.ChipType -Value "{chip_type}" -PropertyType "String" -force }}')
        lines.append('$ChipType = ((Get-ItemProperty -path HKLM:\\SYSTEM\\ControlSet001\\Control\\Class\\*\\0016)."HardwareInformation.ChipType")')
        lines.append("if ($ChipType -eq 'VirtualBox VESA BIOS') {")
        lines.append(f'New-ItemProperty -Path HKLM:\\SYSTEM\\ControlSet001\\Control\\Class\\*\\0016 -Name HardwareInformation.ChipType -Value "{chip_type}" -PropertyType "String" -force }}')
        lines.append('$BiosString = ((Get-ItemProperty -path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Video\\*\\0000)."HardwareInformation.BiosString")')
        lines.append("if ($BiosString -eq 'Oracle VM VirtualBox VBE Adapte') {")
        lines.append(f'New-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Video\\*\\0000 -Name HardwareInformation.BiosString -Value "{chip_type}" -PropertyType "String" -force }}')
        lines.append('$BiosString = ((Get-ItemProperty -path HKLM:\\SYSTEM\\ControlSet001\\Control\\Class\\*\\0016)."HardwareInformation.BiosString")')
        lines.append("if ($BiosString -eq 'Oracle VM VirtualBox VBE Adapte') {")
        lines.append(f'New-ItemProperty -Path HKLM:\\SYSTEM\\ControlSet001\\Control\\Class\\*\\0016 -Name HardwareInformation.BiosString -Value "{chip_type}" -PropertyType "String" -force }}')
    return lines


def _devman_block(devman_b64: Optional[str]) -> List[str]:
    if not devman_b64:
        return []
    lines: List[str] = []
    lines.append(f"$base64_devmanview = '{devman_b64}'")
    lines.append(
        "[IO.File]::WriteAllBytes('DevManView.exe',[System.Convert]::FromBase64String($base64_devmanview))"
    )
    lines.append("$devman = @'")
    lines.append('        ./DevManView.exe /uninstall *"DEV_CAFE"* /use_wildcard')
    lines.append("'@")
    lines.append("Invoke-Expression -Command:$devman")
    return lines


def _clipboard_block(clipboard_b64: Optional[str]) -> List[str]:
    if clipboard_b64:
        lines: List[str] = []
        lines.append(f"$base64_clipboard = '{clipboard_b64}'")
        lines.append('[IO.File]::WriteAllBytes("clipboard_buffer",[System.Convert]::FromBase64String($base64_clipboard))')
        lines.append("$clippy = Get-Random -InputObject (get-content clipboard_buffer)")
        lines.append('Invoke-Expression "echo $clippy | clip"')
        lines.append("Remove-Item clipboard_buffer")
        return lines
    lines = []
    lines.append("[Reflection.Assembly]::LoadWithPartialName(\"System.Web\")")
    lines.append("$length = Get-Random -minimum 5 -maximum 115")
    lines.append("$none = Get-Random -minimum 5 -maximum $length")
    lines.append("$clipboard = [System.Web.Security.Membership]::GeneratePassword($length, $none)")
    lines.append("Invoke-Expression 'echo $clipboard | clip'")
    return lines


def _notepad_block() -> List[str]:
    lines: List[str] = []
    lines.append('$location = "$ENV:userprofile\\Desktop", "$ENV:userprofile\\Documents", "$ENV:homedrive", "$ENV:userprofile\\Downloads", "$ENV:userprofile\\Pictures"')
    lines.append("$notepad = @()")
    lines.append("foreach ($x in $location){")
    lines.append(" Get-ChildItem $x | where {$_.extension -eq \".txt\"} | % {")
    lines.append("     $notepad += $_.FullName")
    lines.append(" }")
    lines.append("}")
    lines.append("$notepad = $notepad | Sort-Object -unique {Get-Random}")
    lines.append("")
    lines.append("$a = 0")
    lines.append("foreach ($knackered in $notepad) {")
    lines.append("    if ($a -le 3) {")
    lines.append('     Start-Process "C:\\windows\\system32\\notepad.exe" -ArgumentList $knackered -WindowStyle Minimized')
    lines.append("     $a++")
    lines.append("     }")
    lines.append("}")
    return lines


def _waldo_block() -> List[str]:
    lines: List[str] = []
    lines.append("if (Test-Path \"kummerspeck\") {")
    lines.append('  Remove-Item "kummerspeck"')
    lines.append('  Remove-Item "DevManView.exe"')
    lines.append('  [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")')
    lines.append('  [System.Windows.Forms.MessageBox]::Show("You are now ready to infected!")')
    lines.append("  exit")
    lines.append("} ")
    return lines


def _product_id_block(product_id: Optional[str]) -> List[str]:
    if product_id is None:
        return []
    lines: List[str] = []
    lines.append(
        f'New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" -Name ProductId -Value "{product_id}" -PropertyType "String" -force'
    )
    lines.append(
        f'New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Internet Explorer\\Registration" -Name ProductId -Value "{product_id}" -PropertyType "String" -force'
    )
    lines.append(
        f'New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\DefaultProductKey" -Name ProductId -Value "{product_id}" -PropertyType "String" -force'
    )
    lines.append('$slmgr="cscript $ENV:windir\\system32\\slmgr.vbs /cpky"')
    lines.append("iex $slmgr")
    lines.append(f'$newProductId = "{product_id}"')
    lines.append(_digital_product_id_block())
    return lines


def _digital_product_id_block() -> str:
    return """
$newProductId = $newProductId.ToCharArray()

$convert = ""
foreach ($x in $newProductId) {
 $convert += $x -as [int]
}
$newNewProductId = $convert -split "(..)" | ? { $_ }

$convertID = @()
foreach ($x in $newNewProductId) {
 $convertID += [Convert]::ToString($x,16)
}

$data = (Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" -Name DigitalProductId).DigitalProductId

$convertData = ""
foreach ($x in $data) {
 $convertData += [Convert]::ToString($x,16)
}

$con1 = $convertData.Substring(0,62)
$con2 = $convertData.Substring(62)
$con2 = $con2 -split "(..)" | ? { $_}
$static = @("A4","00","00","00","03","00","00","00")

# Finalize
$hexDigitalProductId = $static + $convertID + $con2

$hexHexDigitalProductId = @()
foreach ($xxx in $hexDigitalProductId) {
   $hexHexDigitalProductId += "0x$xxx"
}

Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" -Name DigitalProductId  -Value ([byte[]] $hexHexDigitalProductId)
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Internet Explorer\\Registration" -Name DigitalProductId  -Value ([byte[]] $hexHexDigitalProductId)
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\DefaultProductKey" -Name DigitalProductId  -Value ([byte[]] $hexHexDigitalProductId)

# Agree on the Volumeid EULA - Reference: https://peter.hahndorf.eu/blog/WorkAroundSysinternalsLicenseP.html
$check_exist = (Test-Path HKCU:\\Software\\Sysinternals)
if (-Not $check_exist) {
    New-Item -Path HKCU:\\Software\\Sysinternals
    New-Item -Path HKCU:\\Software\\Sysinternals\\VolumeId
    New-ItemProperty -Path HKCU:\\Software\\Sysinternals\\VolumeId -Name EulaAccepted -Value "1" -PropertyType "Dword" -force
}
""".strip()


def _volumeid_block(volumeid_b64: Optional[str]) -> List[str]:
    if not volumeid_b64:
        return []
    lines: List[str] = []
    lines.append(f"$base64_volumeid = '{volumeid_b64}'")
    lines.append("[IO.File]::WriteAllBytes('Volumeid.exe',[System.Convert]::FromBase64String($base64_volumeid))")
    return lines


def _format_ps_array(values: List[str]) -> str:
    return ", ".join(f'"{value}"' for value in values)


def _computer_user_blocks(resources, *, has_volumeid: bool, has_lists: bool) -> List[str]:
    computer_fallback = ["DESKTOP-001", "WORKSTATION-02", "LAPTOP-15"]
    user_fallback = ["user01", "analyst", "student"]
    lines: List[str] = []
    if has_lists and resources and resources.computer_list:
        comp_b64 = base64.b64encode("\n".join(resources.computer_list).encode("utf-8")).decode("utf-8")
        lines.append(f"$base64_computer = '{comp_b64}'")
        lines.append("[IO.File]::WriteAllBytes('computer.lst',[System.Convert]::FromBase64String($base64_computer))")
    if has_lists and resources and resources.user_list:
        user_b64 = base64.b64encode("\n".join(resources.user_list).encode("utf-8")).decode("utf-8")
        lines.append(f"$base64_user = '{user_b64}'")
        lines.append("[IO.File]::WriteAllBytes('user.lst',[System.Convert]::FromBase64String($base64_user))")

    computer_names = resources.computer_list if has_lists and resources and resources.computer_list else computer_fallback
    user_names = resources.user_list if has_lists and resources and resources.user_list else user_fallback
    lines.append(f"$computerNames = @({_format_ps_array(computer_names)})")
    lines.append('if (Test-Path "computer.lst") { $computerNames = Get-Content "computer.lst" }')
    lines.append(f"$userNames = @({_format_ps_array(user_names)})")
    lines.append('if (Test-Path "user.lst") { $userNames = Get-Content "user.lst" }')

    if has_volumeid:
        lines.append('if (Test-Path "Volumeid.exe") {')
        lines.append("    $result = \"\"")
        lines.append('    $char_set = "ABCDEF0123456789".ToCharArray()')
        lines.append("    for ($x = 0; $x -lt 8; $x++) {")
        lines.append("     $result += $char_set | Get-Random")
        lines.append("    }")
        lines.append("")
        lines.append("    $volid1 = $result.Substring(0,4)")
        lines.append("    $volid2 = $result.Substring(4)")
        lines.append('    $weltschmerz = "c:"')
        lines.append('    $dieweltschmerz = "$weltschmerz $volid1-$volid2"')
        lines.append('    Invoke-Expression "./volumeid.exe $dieweltschmerz"')
        lines.append("} else {")
        lines.append('    Write-Warning "Volumeid.exe missing on disk; skipping volume ID spoofing."')
        lines.append("}")
    else:
        lines.append('Write-Warning "Volumeid.exe not provided; skipping volume ID spoofing."')

    lines.append("$computer = Get-Random -InputObject $computerNames")
    lines.append("(Get-WmiObject Win32_ComputerSystem).Rename($computer)")
    lines.append("$user = Get-Random -InputObject $userNames")
    lines.append('$current_user = $ENV:username')
    lines.append('(Get-WmiObject Win32_UserAccount -Filter "Name=\'$current_user\'").Rename($user)')
    lines.append("New-Item kummerspeck -type file")
    return lines


def _powershell_blob_block(has_lists: bool) -> List[str]:
    prefix = ""
    if not has_lists:
        prefix = "# computer.lst not provided; using fallback names for generated files\r\n"
    ps_blob = prefix + r"""
# Pop-up
 # Windows 10 (Enterprise..) does not ask for confirmation by default
 if ($version -notlike '10.0*') {
  [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
  [System.Windows.Forms.MessageBox]::Show("Before you continue, please make sure that you have disabled 'Delete File confirmation dialog' (Right-click Recycle Bin -> Properties)")
 }
# RandomDate function
function RandomDate {
  $days = Get-Random -minimum 300 -maximum 2190
  $hours = Get-Random -minimum 5 -maximum 24
  $minutes = Get-Random -minimum 20 -maximum 60
  $seconds = Get-Random -minimum 12 -maximum 60
  return $days,$hours,$minutes,$seconds
}

# Name sources for creating artifacts
 $nameSource = @("report","notes","document","resume","presentation")
 if (Test-Path "computer.lst") {
  $nameSource = Get-Content computer.lst
 }

# Generate files
function GenFiles([string]$status) {
 $TimeStamp = RandomDate
 $ext = Get-Random -input ".pdf",".txt",".docx",".doc",".xls", ".xlsx",".zip",".png",".jpg", ".jpeg", ".gif", ".bmp", ".html", ".htm", ".ppt", ".pptx"
 $namely = Get-Random -InputObject $nameSource
 
 if ($version -notlike '10.0*') {
  $location = Get-Random -input "$ENV:userprofile\\Desktop\\", "$ENV:userprofile\\Documents\\", "$ENV:homedrive\\", "$ENV:userprofile\\Downloads\\", "$ENV:userprofile\\Pictures\\"
 } else {
  $location = Get-Random -input "$ENV:userprofile\\Desktop\\", "$ENV:userprofile\\Documents\\", "$ENV:userprofile\\Downloads\\", "$ENV:userprofile\\Pictures\\"
 }
 $length = Get-Random -minimum 300 -maximum 4534350
 $buffer = New-Object Byte[] $length
 
 New-Item $location$namely$ext -type file -value $buffer
 Get-ChildItem $location$namely$ext | % {$_.CreationTime = ((get-date).AddDays(-$TimeStamp[0]).AddHours(-$TimeStamp[1]).AddMinutes(-$TimeStamp[2]).AddSeconds(-$TimeStamp[3])) }
 Get-ChildItem $location$namely$ext | % {$_.LastWriteTime = ((get-date).AddDays(-$TimeStamp[0]).AddHours(-$TimeStamp[1]).AddMinutes(-$TimeStamp[2]).AddSeconds(-$TimeStamp[3])) }

 if ($status -eq "delete"){
# Now thrown them away!
  $shell = new-object -comobject "Shell.Application"
  $item = $shell.Namespace(0).ParseName("$location$namely$ext")
  $item.InvokeVerb("delete")
  }
}

# Generate files and then throw them away
 $amount = Get-Random -minimum 10 -maximum 30
 for ($x=0; $x -le $amount; $x++) {
   GenFiles delete
 }

# Generate files, but these we keep
 $amount = Get-Random -minimum 15 -maximum 45
for ($x=0; $x -le $amount; $x++) {
   GenFiles
 }
# Set new background image (will only be visible after reboot)
 $image = Get-ChildItem -recurse c:\\Windows\\Web\\Wallpaper -name -include *.jpg | Get-Random -Count 1
 Set-Itemproperty -path "HKCU:Control Panel\\Desktop" -name WallPaper -value C:\\Windows\\Web\\Wallpaper\\$image
    """.strip()
    return [ps_blob]


def _assoc_block() -> List[str]:
    assocblob = """
$assoc_ext = @('.divx=WMP11.AssocFile.WAV','.mkv=WMP11.AssocFile.WAV','.m4p=WMP11.AssocFile.WAV','.skype=WMP11.AssocFile.WAV','.flac=WMP11.AssocFile.WAV','.psd=WMP11.AssocFile.WAV','.torrent=WMP11.AssocFile.WAV')
$cmd = 'cmd /c'
$associ = 'assoc'

foreach ($z in $assoc_ext) {
 Invoke-Expression $cmd$associ$z
}
""".strip()
    return [assocblob]


def _sanitize_block() -> List[str]:
    lines: List[str] = []
    lines.append("Remove-Item Volumeid.exe, user.lst, computer.lst, DevManView.exe -ErrorAction SilentlyContinue")
    lines.append("Remove-Item -Path HKCU:\\Software\\Sysinternals\\VolumeID -Recurse -ErrorAction SilentlyContinue")
    lines.append("Remove-Item -Path HKCU:\\Software\\Sysinternals -Recurse -ErrorAction SilentlyContinue")
    return lines
