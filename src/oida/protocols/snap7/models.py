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
        self.module_name = info_dict.get("ModuleName", "Unknown")


@dataclass
class S7FirmwareVersion:
    """S7 firmware version (major.minor.patch)"""

    major: int
    minor: int
    patch: int

    @classmethod
    def from_order_code(cls, v1: int, v2: int, v3: int) -> "S7FirmwareVersion":
        """Create from snap7 order_code V1.V2.V3 fields"""
        return cls(major=v1, minor=v2, patch=v3)

    @classmethod
    def from_string(cls, version_str: str) -> Optional["S7FirmwareVersion"]:
        """Parse 'V4.1.3' or '4.1.3' format"""
        try:
            clean = version_str.strip().lstrip("Vv")
            parts = clean.split(".")
            if len(parts) >= 3:
                return cls(int(parts[0]), int(parts[1]), int(parts[2]))
            elif len(parts) == 2:
                return cls(int(parts[0]), int(parts[1]), 0)
            return None
        except (ValueError, AttributeError) as e:
            logger.debug(f"Failed to get clean: {e}")
            return None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, S7FirmwareVersion):
            return False
        return (self.major, self.minor, self.patch) == (other.major, other.minor, other.patch)

    def __str__(self) -> str:
        return f"V{self.major}.{self.minor}.{self.patch}"

    def __repr__(self) -> str:
        return f"S7FirmwareVersion({self.major}, {self.minor}, {self.patch})"
