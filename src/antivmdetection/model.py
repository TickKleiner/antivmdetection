"""Typed data models used across collectors and generators."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class DiskInfo:
    serial_number: Optional[str] = None
    firmware_revision: Optional[str] = None
    model_number: Optional[str] = None


@dataclass
class CdromInfo:
    atapi_serial: Optional[str] = None
    atapi_revision: Optional[str] = None
    atapi_product_id: Optional[str] = None
    atapi_vendor_id: Optional[str] = None


@dataclass
class AcpiTables:
    dsdt: List[str] = field(default_factory=list)
    facp: List[str] = field(default_factory=list)
    rsdt: List[str] = field(default_factory=list)
    ssdt: List[str] = field(default_factory=list)
    dsdt_blob_b64: Optional[str] = None


@dataclass
class HostData:
    cpu_brand: Optional[str] = None
    mac_address: Optional[str] = None
    devman_arch: Optional[str] = None


@dataclass
class GuestData:
    install_date_hex: Optional[str] = None
    machine_guid: Optional[str] = None
    product_id: Optional[str] = None
    ssdt_ids: List[str] = field(default_factory=list)
    dac_type: Optional[str] = None
    chip_type: Optional[str] = None


@dataclass
class SnapshotResources:
    devmanview_b64: Optional[str] = None
    volumeid_b64: Optional[str] = None
    computer_list: List[str] = field(default_factory=list)
    user_list: List[str] = field(default_factory=list)
    clipboard_b64: Optional[str] = None


@dataclass
class SnapshotMetadata:
    created_from: str = "unknown"
    created_at: Optional[str] = None
    host_identifier: Optional[str] = None


@dataclass
class HardwareSnapshot:
    dmi: Dict[str, str] = field(default_factory=dict)
    disk: Optional[DiskInfo] = None
    cdrom: Optional[CdromInfo] = None
    acpi: Optional[AcpiTables] = None
    host: Optional[HostData] = None
    guest: Optional[GuestData] = None
    resources: Optional[SnapshotResources] = None
    metadata: SnapshotMetadata = field(default_factory=SnapshotMetadata)


@dataclass
class GenerationArtifacts:
    host_script: Optional[Path] = None
    guest_script: Optional[Path] = None
    dsdt_blob: Optional[Path] = None
