#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
S7 Data Models

Data classes for S7 CPU information and firmware version handling.
"""

from dataclasses import dataclass
from typing import Dict, Any, Optional

import logging

logger = logging.getLogger(__name__)


class S7CPUInfo:
    """S7 CPU information structure"""

    def __init__(self, info_dict: Dict[str, Any]):
        self.module_type = info_dict.get("ModuleTypeName", "Unknown")
        self.serial_number = info_dict.get("SerialNumber", "Unknown")
        self.as_name = info_dict.get("ASName", "Unknown")
        self.module_name = info_dict.get("ModuleName", "Unknown")
        self.copyright = info_dict.get("Copyright", "")


@dataclass
class S7FirmwareVersion:
    """S7 firmware version with comparison support for vulnerability checking"""

    major: int
    minor: int
    patch: int
    series: str = ""  # S7-1200, S7-1500, etc.

    @classmethod
    def from_order_code(cls, v1: int, v2: int, v3: int, series: str = "") -> "S7FirmwareVersion":
        """Create from snap7 order_code V1.V2.V3 fields"""
        return cls(major=v1, minor=v2, patch=v3, series=series)

    @classmethod
    def from_string(cls, version_str: str, series: str = "") -> Optional["S7FirmwareVersion"]:
        """Parse 'V4.1.3' or '4.1.3' format"""
        try:
            clean = version_str.strip().lstrip("Vv")
            parts = clean.split(".")
            if len(parts) >= 3:
                return cls(int(parts[0]), int(parts[1]), int(parts[2]), series)
            elif len(parts) == 2:
                return cls(int(parts[0]), int(parts[1]), 0, series)
            return None
        except (ValueError, AttributeError) as e:
            logger.debug(f"Failed to get clean: {e}")
            return None

    def __lt__(self, other: "S7FirmwareVersion") -> bool:
        return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)

    def __le__(self, other: "S7FirmwareVersion") -> bool:
        return (self.major, self.minor, self.patch) <= (other.major, other.minor, other.patch)

    def __gt__(self, other: "S7FirmwareVersion") -> bool:
        return (self.major, self.minor, self.patch) > (other.major, other.minor, other.patch)

    def __ge__(self, other: "S7FirmwareVersion") -> bool:
        return (self.major, self.minor, self.patch) >= (other.major, other.minor, other.patch)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, S7FirmwareVersion):
            return False
        return (self.major, self.minor, self.patch) == (other.major, other.minor, other.patch)

    def __str__(self) -> str:
        return f"V{self.major}.{self.minor}.{self.patch}"

    def __repr__(self) -> str:
        return (
            f"S7FirmwareVersion({self.major}, {self.minor}, {self.patch}, series='{self.series}')"
        )
