"""PROFINET data models."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ProfinetDevice:
    """Discovered PROFINET device."""

    mac_address: str
    name_of_station: str = ""
    device_type: str = ""  # Device type/family (e.g., "S7-1200")
    ip_address: str = ""
    subnet_mask: str = ""
    gateway: str = ""
    vendor_id: int = 0
    vendor_name: str = ""
    device_id: int = 0
    device_roles: List[str] = field(default_factory=list)  # IO-Device, IO-Controller, etc.
    device_instance: tuple = (0, 0)  # Instance high/low
    alias_name: str = ""
    supported_options: List[tuple] = field(default_factory=list)
    im0_data: Dict[str, Any] = field(default_factory=dict)
    im1_data: Dict[str, Any] = field(default_factory=dict)
    diagnosis: List[Dict[str, Any]] = field(default_factory=list)
    indices: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    topology: Optional[Any] = field(default=None, repr=False)  # PDRealData from library
    module_diff: Optional[Any] = field(default=None, repr=False)  # ModuleDiffBlock
    alarms: List[Dict[str, Any]] = field(default_factory=list)
    slots: List[Any] = field(default_factory=list)  # SlotInfo list from discover_slots
    firmware_version: str = ""
    epm_annotation: str = ""
    first_seen: str = ""
    last_seen: str = ""
    _dcp_desc: Any = field(default=None, repr=False)  # Store DCPDeviceDescription for RPC
    _pn_device: Any = field(default=None, repr=False)  # Store library ProfinetDevice
