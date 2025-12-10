import platform
import re
import subprocess
import uuid
from abc import ABC, abstractmethod
from typing import Dict, Optional


DEFAULT_VALUE = "** No value to retrieve **"


def serial_randomize(start: int = 0, string_length: int = 10) -> str:
    rand = str(uuid.uuid4()).upper()
    rand = re.sub('-', '', rand)
    return rand[start:string_length]


def _clean_value(value: Optional[str], prefix: str = "string:", remove_spaces: bool = False) -> str:
    if value:
        value_str = str(value)
        if remove_spaces:
            value_str = value_str.replace(" ", "")
        return f"{prefix}{value_str}"
    return DEFAULT_VALUE


class HardwareProvider(ABC):
    @abstractmethod
    def get_bios_info(self) -> Dict[str, str]:
        raise NotImplementedError

    @abstractmethod
    def get_board_info(self) -> Dict[str, str]:
        raise NotImplementedError

    @abstractmethod
    def get_system_info(self) -> Dict[str, str]:
        raise NotImplementedError

    @abstractmethod
    def get_chassis_info(self) -> Dict[str, str]:
        raise NotImplementedError


class LinuxDmidecodeProvider(HardwareProvider):
    def __init__(self) -> None:
        import dmidecode

        self.dmidecode = dmidecode

    def get_bios_info(self) -> Dict[str, str]:
        dmi_info: Dict[str, str] = {}
        biosversion: Optional[str] = None

        try:
            for v in self.dmidecode.get_by_type(0):
                if isinstance(v, dict) and v.get('DMIType') == 0:
                    dmi_info['DmiBIOSVendor'] = _clean_value(v.get('Vendor'))
                    dmi_info['DmiBIOSVersion'] = _clean_value(v.get('Version'), remove_spaces=True)
                    biosversion = v.get('BIOS Revision')
                    dmi_info['DmiBIOSReleaseDate'] = _clean_value(v.get('Release Date'))
        except Exception:
            dmi_info['DmiBIOSReleaseDate'] = _clean_value(None)

        try:
            if biosversion:
                release_major, release_minor = biosversion.split('.', 1)
                dmi_info['DmiBIOSReleaseMajor'] = release_major
                dmi_info['DmiBIOSReleaseMinor'] = release_minor
            else:
                raise ValueError
        except Exception:
            dmi_info['DmiBIOSReleaseMajor'] = DEFAULT_VALUE
            dmi_info['DmiBIOSReleaseMinor'] = DEFAULT_VALUE

        dmi_firmware = subprocess.getoutput("dmidecode t0")
        try:
            firmware_major, firmware_minor = re.search(
                "Firmware Revision: ([0-9A-Za-z. ]*)", dmi_firmware
            ).group(1).split('.', 1)
            dmi_info['DmiBIOSFirmwareMajor'] = firmware_major
            dmi_info['DmiBIOSFirmwareMinor'] = firmware_minor
        except Exception:
            dmi_info['DmiBIOSFirmwareMajor'] = DEFAULT_VALUE
            dmi_info['DmiBIOSFirmwareMinor'] = DEFAULT_VALUE

        return dmi_info

    def get_board_info(self) -> Dict[str, str]:
        dmi_info: Dict[str, str] = {}
        serial_number: Optional[str] = None

        for v in self.dmidecode.get_by_type(2):
            if isinstance(v, dict) and v.get('DMIType') == 2:
                serial_number = v.get('Serial Number')
                dmi_info['DmiBoardVersion'] = _clean_value(v.get('Version'), remove_spaces=True)
                dmi_info['DmiBoardProduct'] = _clean_value(v.get('Product Name'), remove_spaces=True)
                dmi_info['DmiBoardVendor'] = _clean_value(v.get('Manufacturer'), remove_spaces=True)

        try:
            if serial_number:
                s_number = []
                new_serial = serial_number
                if '/' in serial_number:
                    for slash in re.finditer('/', serial_number):
                        s_number.append(slash.start(0))
                    new_serial = re.sub('/', '', serial_number)
                    new_serial = serial_randomize(0, len(new_serial))
                    for char in s_number:
                        new_serial = new_serial[:char] + '/' + new_serial[char:]
                else:
                    new_serial = serial_randomize(0, len(serial_number))
            else:
                new_serial = DEFAULT_VALUE
        except Exception:
            new_serial = DEFAULT_VALUE

        dmi_info['DmiBoardSerial'] = new_serial

        dmi_board = subprocess.getoutput("dmidecode -t2")
        try:
            asset_tag = re.search("Asset Tag: ([0-9A-Za-z ]*)", dmi_board).group(1)
        except Exception:
            asset_tag = DEFAULT_VALUE

        dmi_info['DmiBoardAssetTag'] = _clean_value(asset_tag)

        try:
            loc_chassis = re.search("Location In Chassis: ([0-9A-Za-z ]*)", dmi_board).group(1)
        except Exception:
            loc_chassis = DEFAULT_VALUE

        dmi_info['DmiBoardLocInChass'] = _clean_value(loc_chassis, remove_spaces=True)

        board_dict = {
            'Unknown': 1,
            'Other': 2,
            'Server Blade': 3,
            'Connectivity Switch': 4,
            'System Management Module': 5,
            'Processor Module': 6,
            'I/O Module': 7,
            'Memory Module': 8,
            'Daughter board': 9,
            'Motherboard': 10,
            'Processor/Memory Module': 11,
            'Processor/IO Module': 12,
            'Interconnect board': 13,
        }

        try:
            board_type = re.search("Type: ([0-9A-Za-z ]+)", dmi_board).group(1)
            board_type = str(board_dict.get(board_type, DEFAULT_VALUE))
        except Exception:
            board_type = DEFAULT_VALUE

        dmi_info['DmiBoardBoardType'] = board_type

        return dmi_info

    def get_system_info(self) -> Dict[str, str]:
        dmi_info: Dict[str, str] = {}
        system_family: Optional[str] = None
        system_serial: Optional[str] = None

        for v in self.dmidecode.get_by_type(1):
            if isinstance(v, dict) and v.get('DMIType') == 1:
                dmi_info['DmiSystemSKU'] = v.get('SKU Number', DEFAULT_VALUE)
                system_family = v.get('Family')
                system_serial = v.get('Serial Number')
                dmi_info['DmiSystemVersion'] = _clean_value(v.get('Version'), remove_spaces=True)
                dmi_info['DmiSystemProduct'] = _clean_value(v.get('Product Name'), remove_spaces=True)
                dmi_info['DmiSystemVendor'] = _clean_value(v.get('Manufacturer'), remove_spaces=True)

        if not system_family:
            dmi_info['DmiSystemFamily'] = "Not Specified"
        else:
            dmi_info['DmiSystemFamily'] = _clean_value(system_family)

        dmi_info['DmiSystemUuid'] = str(uuid.uuid4()).upper()

        if system_serial:
            dmi_info['DmiSystemSerial'] = _clean_value(serial_randomize(0, len(system_serial)))
        else:
            dmi_info['DmiSystemSerial'] = DEFAULT_VALUE

        return dmi_info

    def get_chassis_info(self) -> Dict[str, str]:
        dmi_info: Dict[str, str] = {}
        chassi_serial: Optional[str] = None

        for v in self.dmidecode.get_by_type(3):
            if isinstance(v, dict):
                dmi_info['DmiChassisVendor'] = _clean_value(v.get('Manufacturer'), remove_spaces=True)
                chassi_serial = v.get('Serial Number')
                dmi_info['DmiChassisVersion'] = _clean_value(v.get('Version'), remove_spaces=True)
                dmi_info['DmiChassisType'] = v.get('Type')

        chassi_dict = {
            'Other': 1,
            'Unknown': 2,
            'Desktop': 3,
            'Low Profile Desktop': 4,
            'Pizza Box': 5,
            'Mini Tower': 6,
            'Tower': 7,
            'Portable': 8,
            'Laptop': 9,
            'Notebook': 10,
            'Hand Held': 11,
            'Docking Station': 12,
            'All in One': 13,
            'Sub Notebook': 14,
            'Space-saving': 15,
            'Lunch Box': 16,
            'Main Server Chassis': 17,
            'Expansion Chassis': 18,
            'SubChassis': 19,
            'Bus Expansion Chassis': 20,
            'Peripheral Chassis': 21,
            'RAID Chassis': 22,
            'Rack Mount Chassis': 23,
            'Sealed-case PC': 24,
            'Multi-system chassis': 25,
            'Compact PCI': 26,
            'Advanced TCA': 27,
            'Blade': 28,
            'Blade Enclosure': 29,
            'Tablet': 30,
            'Convertible': 31,
            'Detachable': 32,
            'IoT Gateway': 33,
            'Embedded PC': 34,
            'Mini PC': 35,
            'Stick PC': 36,
        }

        mapped_type = chassi_dict.get(dmi_info.get('DmiChassisType')) if dmi_info.get('DmiChassisType') else None
        dmi_info['DmiChassisType'] = str(mapped_type) if mapped_type else DEFAULT_VALUE

        chassi_output = subprocess.getoutput("dmidecode -t3")
        try:
            dmi_info['DmiChassisAssetTag'] = _clean_value(
                re.search("Asset Tag: ([0-9A-Za-z ]*)", chassi_output).group(1)
            )
        except Exception:
            dmi_info['DmiChassisAssetTag'] = DEFAULT_VALUE

        if chassi_serial:
            dmi_info['DmiChassisSerial'] = _clean_value(serial_randomize(0, len(chassi_serial)))
        else:
            dmi_info['DmiChassisSerial'] = DEFAULT_VALUE

        return dmi_info


class WindowsWmiProvider(HardwareProvider):
    def __init__(self) -> None:
        import wmi

        self.conn = wmi.WMI()

    def get_bios_info(self) -> Dict[str, str]:
        dmi_info: Dict[str, str] = {}
        bios = self.conn.Win32_BIOS()[0]

        dmi_info['DmiBIOSVendor'] = _clean_value(getattr(bios, 'Manufacturer', None))
        dmi_info['DmiBIOSVersion'] = _clean_value(getattr(bios, 'SMBIOSBIOSVersion', None), remove_spaces=True)

        release_date = getattr(bios, 'ReleaseDate', None)
        formatted_date = self._format_wmi_date(release_date)
        dmi_info['DmiBIOSReleaseDate'] = _clean_value(formatted_date)

        dmi_info['DmiBIOSReleaseMajor'] = str(getattr(bios, 'SMBIOSMajorVersion', DEFAULT_VALUE))
        dmi_info['DmiBIOSReleaseMinor'] = str(getattr(bios, 'SMBIOSMinorVersion', DEFAULT_VALUE))

        dmi_info['DmiBIOSFirmwareMajor'] = DEFAULT_VALUE
        dmi_info['DmiBIOSFirmwareMinor'] = DEFAULT_VALUE

        return dmi_info

    def get_board_info(self) -> Dict[str, str]:
        dmi_info: Dict[str, str] = {}
        board = self.conn.Win32_BaseBoard()[0]

        dmi_info['DmiBoardVersion'] = _clean_value(getattr(board, 'Version', None), remove_spaces=True)
        dmi_info['DmiBoardProduct'] = _clean_value(getattr(board, 'Product', None), remove_spaces=True)
        dmi_info['DmiBoardVendor'] = _clean_value(getattr(board, 'Manufacturer', None), remove_spaces=True)

        serial_number = getattr(board, 'SerialNumber', None)
        if serial_number:
            dmi_info['DmiBoardSerial'] = serial_randomize(0, len(serial_number))
        else:
            dmi_info['DmiBoardSerial'] = DEFAULT_VALUE

        asset_tag = getattr(board, 'Tag', None) or getattr(board, 'PartNumber', None)
        dmi_info['DmiBoardAssetTag'] = _clean_value(asset_tag)

        location = getattr(board, 'LocationInChassis', None)
        dmi_info['DmiBoardLocInChass'] = _clean_value(location, remove_spaces=True)

        board_type = getattr(board, 'BoardType', None)
        dmi_info['DmiBoardBoardType'] = str(board_type) if board_type else DEFAULT_VALUE

        return dmi_info

    def get_system_info(self) -> Dict[str, str]:
        dmi_info: Dict[str, str] = {}
        cs = self.conn.Win32_ComputerSystem()[0]

        dmi_info['DmiSystemSKU'] = getattr(cs, 'SystemSKUNumber', DEFAULT_VALUE)
        system_family = getattr(cs, 'SystemFamily', None)
        system_serial = getattr(cs, 'SerialNumber', None)
        dmi_info['DmiSystemVersion'] = _clean_value(getattr(cs, 'Model', None), remove_spaces=True)
        dmi_info['DmiSystemProduct'] = _clean_value(getattr(cs, 'Model', None), remove_spaces=True)
        dmi_info['DmiSystemVendor'] = _clean_value(getattr(cs, 'Manufacturer', None), remove_spaces=True)

        if not system_family:
            dmi_info['DmiSystemFamily'] = "Not Specified"
        else:
            dmi_info['DmiSystemFamily'] = _clean_value(system_family)

        uuid_value = getattr(cs, 'UUID', None)
        if uuid_value:
            dmi_info['DmiSystemUuid'] = str(uuid_value).upper()
        else:
            dmi_info['DmiSystemUuid'] = str(uuid.uuid4()).upper()

        if system_serial:
            dmi_info['DmiSystemSerial'] = _clean_value(serial_randomize(0, len(system_serial)))
        else:
            dmi_info['DmiSystemSerial'] = DEFAULT_VALUE

        return dmi_info

    def get_chassis_info(self) -> Dict[str, str]:
        dmi_info: Dict[str, str] = {}
        enclosure = self.conn.Win32_SystemEnclosure()[0]

        dmi_info['DmiChassisVendor'] = _clean_value(getattr(enclosure, 'Manufacturer', None), remove_spaces=True)
        dmi_info['DmiChassisVersion'] = _clean_value(getattr(enclosure, 'Version', None), remove_spaces=True)

        chassis_types = getattr(enclosure, 'ChassisTypes', [])
        if chassis_types:
            dmi_info['DmiChassisType'] = str(chassis_types[0])
        else:
            dmi_info['DmiChassisType'] = DEFAULT_VALUE

        dmi_info['DmiChassisAssetTag'] = _clean_value(getattr(enclosure, 'SMBIOSAssetTag', None))

        serial_number = getattr(enclosure, 'SerialNumber', None)
        if serial_number:
            dmi_info['DmiChassisSerial'] = _clean_value(serial_randomize(0, len(serial_number)))
        else:
            dmi_info['DmiChassisSerial'] = DEFAULT_VALUE

        return dmi_info

    @staticmethod
    def _format_wmi_date(date_str: Optional[str]) -> Optional[str]:
        if not date_str:
            return None
        try:
            cleaned = str(date_str)
            return f"{cleaned[4:6]}/{cleaned[6:8]}/{cleaned[0:4]}"
        except Exception:
            return None


def get_hardware_provider() -> HardwareProvider:
    if platform.system().lower().startswith('win'):
        return WindowsWmiProvider()
    return LinuxDmidecodeProvider()
