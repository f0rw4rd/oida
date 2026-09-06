#!/usr/bin/env python3
"""
TASE.2 Data Types per IEC 60870-6-802

This module defines the data types used in TASE.2/ICCP protocol as specified
in IEC 60870-6-802 (TASE.2 Object Models).

Reference: IEC 60870-6-503 Section 8 and IEC 60870-6-802
"""

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from typing import Optional, List, Any
import time
import struct


# =============================================================================
# Indication Point Types (Block 1)
# Per IEC 60870-6-802 Section 5.2
# =============================================================================


class IndicationPointType(IntEnum):
    """Data Value types for Indication Points"""

    DATA_REAL = 1  # Single float value
    DATA_REAL_Q = 2  # Float + Quality flags
    DATA_REAL_Q_TIMETAG = 3  # Float + Quality + Timestamp
    DATA_STATE = 4  # 2-bit state value
    DATA_STATE_Q = 5  # State + Quality
    DATA_STATE_Q_TIMETAG = 6  # State + Quality + Timestamp
    DATA_DISCRETE = 7  # Integer value
    DATA_DISCRETE_Q = 8  # Integer + Quality
    DATA_DISCRETE_Q_TIMETAG = 9  # Integer + Quality + Timestamp


class StateValue(IntEnum):
    """Two-bit state values for digital points"""

    INTERMEDIATE = 0  # 00 - Transition state
    OFF = 1  # 01 - Off/Open state
    ON = 2  # 10 - On/Closed state
    BAD_STATE = 3  # 11 - Invalid state


# =============================================================================
# Quality Flags
# Per IEC 60870-6-802 Section 5.2.1
# =============================================================================


class DataFlags(IntFlag):
    """Quality flags for data values (DataFlags in spec)"""

    # Validity (bits 0-1)
    VALIDITY_GOOD = 0x00
    VALIDITY_HELD = 0x01  # Value held from previous scan
    VALIDITY_SUSPECT = 0x02  # Value is suspect
    VALIDITY_NOT_VALID = 0x03  # Value is invalid

    # Current Source (bits 2-3)
    SOURCE_TELEMETERED = 0x00  # Real-time from RTU
    SOURCE_CALCULATED = 0x04  # Calculated value
    SOURCE_ENTERED = 0x08  # Manually entered
    SOURCE_ESTIMATED = 0x0C  # State estimator

    # Normal Value (bit 4)
    NORMAL_VALUE = 0x00
    ABNORMAL_VALUE = 0x10

    # Fault (bit 5) - for state points
    NO_FAULT = 0x00
    FAULT = 0x20


class TimeStampFlags(IntFlag):
    """Timestamp quality flags"""

    LEAP_SECOND_KNOWN = 0x80
    CLOCK_FAILURE = 0x40
    CLOCK_NOT_SYNCHRONIZED = 0x20
    ACCURACY_UNSPECIFIED = 0x1F  # Mask for accuracy bits


# =============================================================================
# Control Point Types (Block 5)
# Per IEC 60870-6-802 Section 5.3
# =============================================================================


class ControlPointType(IntEnum):
    """Control point data types"""

    COMMAND = 1  # Binary command (trip/close)
    SETPOINT_REAL = 2  # Analog setpoint (float)
    SETPOINT_DISCRETE = 3  # Discrete setpoint (integer)


class CommandValue(IntEnum):
    """Command values for binary control"""

    TRIP = 0  # Open/Trip command
    CLOSE = 1  # Close command


class TagValue(IntEnum):
    """Tag values for device control (Block 5)

    Per IEC 60870-6-503 Section 5.2.11.4:
    - NO_TAG: Select and Operate allowed
    - OPEN_AND_CLOSE_INHIBIT: No operations allowed
    - CLOSE_ONLY_INHIBIT: Only Open/Trip allowed, Close blocked
    """

    NO_TAG = 0
    OPEN_AND_CLOSE_INHIBIT = 1
    CLOSE_ONLY_INHIBIT = 2


class DeviceState(IntEnum):
    """Device state for SBO (Select-Before-Operate) devices"""

    IDLE = 0  # Not selected
    ARMED = 1  # Selected, waiting for operate


class DeviceClass(IntEnum):
    """Device class per IEC 60870-6-802"""

    SBO = 0  # Select-Before-Operate
    DIRECT = 1  # Direct control (non-SBO)


# =============================================================================
# Transfer Set Types (Block 2)
# Per IEC 60870-6-503 Section 5.2.9
# =============================================================================


class DSConditions(IntFlag):
    """Data Set Transfer Conditions (DSConditions)

    Bitmap indicating which conditions trigger a transfer report.
    """

    INTERVAL_TIMEOUT = 0x0001  # Periodic interval elapsed
    INTEGRITY_TIMEOUT = 0x0002  # Integrity check interval
    OBJECT_CHANGE = 0x0004  # Any value changed
    OPERATOR_REQUEST = 0x0008  # Manual request from server
    EXTERNAL_EVENT = 0x0010  # External event triggered


class TransferSetStatus(IntEnum):
    """Transfer Set enable status"""

    DISABLED = 0
    ENABLED = 1


# =============================================================================
# Supported Features Bitmap
# Per IEC 60870-6-503 Section 8.2.1
# =============================================================================


class SupportedFeatures(IntFlag):
    """TASE.2 Conformance Building Blocks (Supported_Features)

    12-bit bitmap indicating which blocks are supported.
    """

    BLOCK_1 = 0x001  # Basic services
    BLOCK_2 = 0x002  # Report-by-Exception
    BLOCK_3 = 0x004  # Block 3 (reserved)
    BLOCK_4 = 0x008  # Block 4 (reserved)
    BLOCK_5 = 0x010  # Device control
    BLOCK_6 = 0x020  # Programs (informative)
    BLOCK_7 = 0x040  # Event conditions (informative)
    BLOCK_8 = 0x080  # Block 8 (reserved)
    BLOCK_9 = 0x100  # Accounts (informative)
    BLOCK_10 = 0x200  # Info messages (informative)
    BLOCK_11 = 0x400  # Time series (informative)
    BLOCK_12 = 0x800  # Block 12 (reserved)


# =============================================================================
# Data Structures
# =============================================================================


@dataclass
class TimeStamp:
    """UTC timestamp with quality

    Per IEC 60870-6-802 TimeStampExtended type (8 bytes):
    - 4 bytes: seconds since 1970-01-01
    - 3 bytes: fraction of second (24-bit)
    - 1 byte: quality flags
    """

    seconds: int = 0
    fraction: int = 0  # 24-bit fraction of second
    quality: int = 0  # TimeStampFlags

    @classmethod
    def now(cls) -> "TimeStamp":
        """Create timestamp for current time"""
        t = time.time()
        seconds = int(t)
        fraction = int((t - seconds) * 0x1000000)  # 24-bit fraction
        return cls(seconds=seconds, fraction=fraction, quality=0)

    def to_bytes(self) -> bytes:
        """Encode as 8-byte timestamp"""
        return (
            struct.pack(">I", self.seconds)
            + struct.pack(">I", self.fraction)[1:]
            + struct.pack("B", self.quality)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "TimeStamp":
        """Decode 8-byte timestamp"""
        seconds = struct.unpack(">I", data[0:4])[0]
        fraction = struct.unpack(">I", b"\x00" + data[4:7])[0]
        quality = data[7]
        return cls(seconds=seconds, fraction=fraction, quality=quality)


@dataclass
class Quality:
    """Data quality flags"""

    flags: DataFlags = DataFlags.VALIDITY_GOOD

    @property
    def is_valid(self) -> bool:
        return (self.flags & 0x03) == DataFlags.VALIDITY_GOOD

    @property
    def is_telemetered(self) -> bool:
        return (self.flags & 0x0C) == DataFlags.SOURCE_TELEMETERED


@dataclass
class IndicationPoint:
    """Indication Point data value

    Maps to MMS Named Variable with IndicationPoint type.
    """

    name: str
    point_type: IndicationPointType
    value: Any = 0.0
    quality: Quality = field(default_factory=Quality)
    timestamp: Optional[TimeStamp] = None

    def has_quality(self) -> bool:
        return self.point_type in (
            IndicationPointType.DATA_REAL_Q,
            IndicationPointType.DATA_REAL_Q_TIMETAG,
            IndicationPointType.DATA_STATE_Q,
            IndicationPointType.DATA_STATE_Q_TIMETAG,
            IndicationPointType.DATA_DISCRETE_Q,
            IndicationPointType.DATA_DISCRETE_Q_TIMETAG,
        )

    def has_timestamp(self) -> bool:
        return self.point_type in (
            IndicationPointType.DATA_REAL_Q_TIMETAG,
            IndicationPointType.DATA_STATE_Q_TIMETAG,
            IndicationPointType.DATA_DISCRETE_Q_TIMETAG,
        )


@dataclass
class ControlPoint:
    """Control Point for device operations (Block 5)

    Maps to MMS Named Variable with ControlPoint type.
    """

    name: str
    control_type: ControlPointType
    device_class: DeviceClass = DeviceClass.SBO
    command_value: CommandValue = CommandValue.TRIP
    setpoint_value: float = 0.0
    check_back_id: int = 0
    tag: TagValue = TagValue.NO_TAG
    tag_reason: str = ""
    state: DeviceState = DeviceState.IDLE
    timeout_seconds: int = 30  # SBO timeout
    selected_by: Optional[str] = None  # Client AP-title that selected


@dataclass
class TagValueStruct:
    """Tag_Value structure per IEC 60870-6-802

    Used for Get/Set Tag Value operations.
    """

    tag: TagValue = TagValue.NO_TAG
    reason: str = ""


@dataclass
class DSTransmissionPars:
    """Data Set Transmission Parameters (Block 2)

    Per IEC 60870-6-503 Section 5.2.9.1.2
    """

    start_time: int = 0  # Start time (0 = immediately)
    interval: int = 0  # Report interval in seconds
    tle: int = 0  # Time limit for execution
    buffer_time: int = 0  # Event buffering time
    integrity_check: int = 0  # Integrity check interval
    ds_conditions_requested: DSConditions = DSConditions.INTERVAL_TIMEOUT
    block_data: bool = False  # Use block transfer mode
    critical: bool = False  # Require confirmation
    rbe: bool = False  # Report-by-Exception only


@dataclass
class DataSetTransferSet:
    """Data Set Transfer Set object (Block 2)

    Maps to MMS Named Variable with DSTransferSet type.
    """

    name: str
    data_set_name: str = ""
    transmission_pars: DSTransmissionPars = field(default_factory=DSTransmissionPars)
    status: TransferSetStatus = TransferSetStatus.DISABLED
    last_report_time: Optional[TimeStamp] = None
    conditions_detected: DSConditions = DSConditions(0)


@dataclass
class DataSet:
    """Data Set object (Named Variable List)

    Per IEC 60870-6-503 Section 5.2.6
    """

    name: str
    scope: str = "ICC"  # "VCC" or "ICC"
    members: List[str] = field(default_factory=list)  # List of Data Value names
    deletable: bool = True


@dataclass
class BilateralTable:
    """Bilateral Table per IEC 60870-6-503 Section 5.2.3

    Represents the access control agreement between control centers.
    """

    client_ap_title: str = ""
    version: str = "BLT_001"
    tase2_version: tuple = (2000, 8)  # Major, Minor
    domain_name: str = ""
    data_values: List[str] = field(default_factory=list)
    data_sets: List[str] = field(default_factory=list)
    transfer_sets: List[str] = field(default_factory=list)
    devices: List[str] = field(default_factory=list)


# =============================================================================
# MMS Error Codes
# Per ISO 9506-1
# =============================================================================


class MmsErrorClass(IntEnum):
    """MMS Error Class"""

    VMD_STATE = 0
    APPLICATION_REFERENCE = 1
    DEFINITION = 2
    RESOURCE = 3
    SERVICE = 4
    SERVICE_PREEMPT = 5
    TIME_RESOLUTION = 6
    ACCESS = 7
    INITIATE = 8
    CONCLUDE = 9
    CANCEL = 10
    FILE = 11
    OTHERS = 12


class MmsDataAccessError(IntEnum):
    """MMS Data Access Error codes"""

    OBJECT_INVALIDATED = 0
    HARDWARE_FAULT = 1
    TEMPORARILY_UNAVAILABLE = 2
    OBJECT_ACCESS_DENIED = 3
    OBJECT_UNDEFINED = 4
    INVALID_ADDRESS = 5
    TYPE_UNSUPPORTED = 6
    TYPE_INCONSISTENT = 7
    OBJECT_ATTRIBUTE_INCONSISTENT = 8
    OBJECT_ACCESS_UNSUPPORTED = 9
    OBJECT_NON_EXISTENT = 10


# =============================================================================
# Utility Functions
# =============================================================================


def create_tase2_version() -> bytes:
    """Create TASE.2 Version structure (2000.08)"""
    # Structure: { Integer major, Integer minor }
    return struct.pack(">HH", 2000, 8)


def create_supported_features(blocks: SupportedFeatures) -> bytes:
    """Create Supported_Features bitstring (12 bits)"""
    # Bitstring with 12 bits, MSB first
    value = int(blocks)
    return struct.pack(">H", value << 4)  # Shift to align 12 bits


def parse_supported_features(data: bytes) -> SupportedFeatures:
    """Parse Supported_Features bitstring"""
    value = struct.unpack(">H", data)[0] >> 4
    return SupportedFeatures(value)
