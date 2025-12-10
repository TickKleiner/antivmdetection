import ctypes
import ctypes.wintypes
import platform
import re
import subprocess
from typing import Dict, Tuple


def _clean_string(value: str) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _fallback_randomized(length: int, randomizer) -> str:
    if length <= 0:
        length = 10
    return randomizer(0, length)


def _get_wmi_output(class_name: str, fields: Tuple[str, ...]) -> Tuple[Dict[str, str], ...]:
    results = []
    try:
        import wmi  # type: ignore

        connection = wmi.WMI()
        for entry in connection.query(f"SELECT {', '.join(fields)} FROM {class_name}"):
            collected = {}
            for field in fields:
                collected[field] = _clean_string(getattr(entry, field, ""))
            results.append(collected)
    except Exception:
        try:
            powershell_fields = ','.join(fields)
            command = [
                "powershell",
                "-NoProfile",
                "-Command",
                f"Get-WmiObject -Class {class_name} | Select-Object {powershell_fields} | ConvertTo-Json"
            ]
            output = subprocess.check_output(command, encoding="utf-8", errors="ignore")
            objects = []
            try:
                import json

                parsed = json.loads(output)
                if isinstance(parsed, dict):
                    objects = [parsed]
                elif isinstance(parsed, list):
                    objects = parsed
            except Exception:
                objects = []

            for obj in objects:
                collected = {}
                for field in fields:
                    collected[field] = _clean_string(obj.get(field, "")) if isinstance(obj, dict) else ""
                results.append(collected)
        except Exception:
            return tuple()
    return tuple(results)


def _query_deviceiocontrol(device: str, control_code: int, buffer_size: int = 1024) -> str:
    result = ""
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        OPEN_EXISTING = 3

        handle = kernel32.CreateFileW(
            ctypes.c_wchar_p(device),
            ctypes.c_uint32(GENERIC_READ),
            ctypes.c_uint32(FILE_SHARE_READ),
            None,
            ctypes.c_uint32(OPEN_EXISTING),
            ctypes.c_uint32(0),
            None,
        )
        if handle == ctypes.c_void_p(-1).value:
            return result

        output_buffer = ctypes.create_string_buffer(buffer_size)
        bytes_returned = ctypes.wintypes.DWORD()
        success = kernel32.DeviceIoControl(
            handle,
            ctypes.c_uint32(control_code),
            None,
            0,
            output_buffer,
            buffer_size,
            ctypes.byref(bytes_returned),
            None,
        )
        if success:
            result = output_buffer.raw[: bytes_returned.value].decode("utf-8", errors="ignore")
    except Exception:
        result = ""
    return result


def _trim_and_randomize(value: str, randomizer, max_length: int = None) -> str:
    cleaned = _clean_string(value)
    if cleaned:
        if max_length is not None:
            cleaned = cleaned[:max_length]
        return cleaned
    return _fallback_randomized(max_length or 10, randomizer)


def get_disk_metadata(randomizer) -> Dict[str, str]:
    metadata = {
        "SerialNumber": "** No value to retrieve **",
        "FirmwareRevision": "** No value to retrieve **",
        "ModelNumber": "** No value to retrieve **",
        "VendorId": "** No value to retrieve **",
    }

    if platform.system().lower().startswith("win"):
        entries = _get_wmi_output("Win32_DiskDrive", ("SerialNumber", "FirmwareRevision", "Model", "Manufacturer"))
        if entries:
            disk = entries[0]
            metadata["SerialNumber"] = _trim_and_randomize(disk.get("SerialNumber", ""), randomizer, 20)
            metadata["FirmwareRevision"] = _trim_and_randomize(disk.get("FirmwareRevision", ""), randomizer)
            metadata["ModelNumber"] = _trim_and_randomize(disk.get("Model", ""), randomizer)
            manufacturer = disk.get("Manufacturer", "")
            if not manufacturer and metadata["ModelNumber"] != "** No value to retrieve **":
                manufacturer = metadata["ModelNumber"].split(" ")[0]
            metadata["VendorId"] = _trim_and_randomize(manufacturer, randomizer)
            return metadata

        device_path = r"\\.\PhysicalDrive0"
        control_codes = [
            0x00070040,  # IOCTL_STORAGE_QUERY_PROPERTY
            0x004d0040,  # IOCTL_SCSI_GET_INQUIRY_DATA
        ]
        for code in control_codes:
            raw = _query_deviceiocontrol(device_path, code)
            if raw:
                parts = re.split(r"\x00+", raw)
                usable = [p for p in parts if p]
                if usable:
                    metadata["SerialNumber"] = _trim_and_randomize(usable[0], randomizer, 20)
                    if len(usable) > 1:
                        metadata["FirmwareRevision"] = _trim_and_randomize(usable[1], randomizer)
                    if len(usable) > 2:
                        metadata["ModelNumber"] = _trim_and_randomize(usable[2], randomizer)
                    if len(usable) > 3:
                        metadata["VendorId"] = _trim_and_randomize(usable[3], randomizer)
                    return metadata

    return metadata


def get_cdrom_metadata(randomizer) -> Dict[str, str]:
    metadata = {
        "ATAPISerialNumber": "** No value to retrieve **",
        "ATAPIRevision": "** No value to retrieve **",
        "ATAPIProductId": "** No value to retrieve **",
        "ATAPIVendorId": "** No value to retrieve **",
    }

    if platform.system().lower().startswith("win"):
        entries = _get_wmi_output(
            "Win32_CDROMDrive",
            ("SerialNumber", "FirmwareRevision", "Name", "Manufacturer"),
        )
        if entries:
            cdrom = entries[0]
            metadata["ATAPISerialNumber"] = _trim_and_randomize(cdrom.get("SerialNumber", ""), randomizer)
            metadata["ATAPIRevision"] = _trim_and_randomize(cdrom.get("FirmwareRevision", ""), randomizer)
            metadata["ATAPIProductId"] = _trim_and_randomize(cdrom.get("Name", ""), randomizer)
            metadata["ATAPIVendorId"] = _trim_and_randomize(cdrom.get("Manufacturer", ""), randomizer)
            return metadata

        device_path = r"\\.\CDROM0"
        for code in (0x00070040, 0x004d0040):
            raw = _query_deviceiocontrol(device_path, code)
            if raw:
                parts = re.split(r"\x00+", raw)
                usable = [p for p in parts if p]
                if usable:
                    metadata["ATAPISerialNumber"] = _trim_and_randomize(usable[0], randomizer)
                    if len(usable) > 1:
                        metadata["ATAPIRevision"] = _trim_and_randomize(usable[1], randomizer)
                    if len(usable) > 2:
                        metadata["ATAPIProductId"] = _trim_and_randomize(usable[2], randomizer)
                    if len(usable) > 3:
                        metadata["ATAPIVendorId"] = _trim_and_randomize(usable[3], randomizer)
                    return metadata

    return metadata
