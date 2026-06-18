#!/usr/bin/env python3
"""
CAN protocol constants and data structures.

Defines arbitration ID ranges, standard baudrates, UDS service identifiers,
OBD-II PIDs, XCP/CCP calibration protocol commands, and data classes for
CAN bus security scanning.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CAN bus frame constants
# ---------------------------------------------------------------------------

# Standard CAN frame: 11-bit arbitration ID (0x000 - 0x7FF)
CAN_STD_ID_MIN = 0x000
CAN_STD_ID_MAX = 0x7FF

# Extended CAN frame: 29-bit arbitration ID (0x00000000 - 0x1FFFFFFF)
CAN_EXT_ID_MIN = 0x00000000
CAN_EXT_ID_MAX = 0x1FFFFFFF

# Maximum data length for classic CAN
CAN_MAX_DLC = 8

# CAN FD maximum data lengths
CAN_FD_MAX_DLC = 64

# ---------------------------------------------------------------------------
# Standard CAN baudrates (bits per second)
# ---------------------------------------------------------------------------

CAN_BAUDRATES: Dict[str, int] = {
    "10k": 10000,
    "20k": 20000,
    "50k": 50000,
    "100k": 100000,
    "125k": 125000,
    "250k": 250000,
    "500k": 500000,
    "800k": 800000,
    "1m": 1000000,
}

DEFAULT_BAUDRATE = 500000

# Common automotive baudrates
AUTOMOTIVE_BAUDRATES = [500000, 250000, 125000]

# ---------------------------------------------------------------------------
# Well-known CAN arbitration ID ranges
# ---------------------------------------------------------------------------

# Automotive / OBD-II
OBD2_REQUEST_ID = 0x7DF  # Broadcast OBD-II request
OBD2_RESPONSE_BASE = 0x7E8  # Base response ID (ECU #1)
OBD2_RESPONSE_RANGE = (0x7E8, 0x7EF)  # Response ID range (8 ECUs)

# UDS (ISO 14229) standard request/response pair offsets
UDS_PHYSICAL_REQUEST_BASE = 0x700  # Common physical request base
UDS_PHYSICAL_RESPONSE_OFFSET = 0x08  # Response = request + 0x08

# Common UDS arbitration ID pairs (request -> response)
COMMON_UDS_PAIRS: Dict[int, int] = {
    0x7E0: 0x7E8,  # ECU #1 (engine)
    0x7E1: 0x7E9,  # ECU #2 (transmission)
    0x7E2: 0x7EA,  # ECU #3 (ABS/ESP)
    0x7E3: 0x7EB,  # ECU #4
    0x7E4: 0x7EC,  # ECU #5
    0x7E5: 0x7ED,  # ECU #6
    0x7E6: 0x7EE,  # ECU #7
    0x7E7: 0x7EF,  # ECU #8
    0x7DF: 0x7E8,  # Broadcast (functional addressing)
}

# Industrial CAN ranges (CANopen, DeviceNet)
CANOPEN_NMT_ID = 0x000
CANOPEN_SYNC_ID = 0x080
CANOPEN_EMCY_BASE = 0x080  # Emergency base (0x081-0x0FF)
CANOPEN_TPDO1_BASE = 0x180  # TPDO1 base (0x181-0x1FF)
CANOPEN_RPDO1_BASE = 0x200  # RPDO1 base (0x201-0x27F)
CANOPEN_TPDO2_BASE = 0x280
CANOPEN_RPDO2_BASE = 0x300
CANOPEN_TPDO3_BASE = 0x380
CANOPEN_RPDO3_BASE = 0x400
CANOPEN_TPDO4_BASE = 0x480
CANOPEN_RPDO4_BASE = 0x500
CANOPEN_SDO_TX_BASE = 0x580  # SDO response base (0x581-0x5FF)
CANOPEN_SDO_RX_BASE = 0x600  # SDO request base (0x601-0x67F)
CANOPEN_HEARTBEAT_BASE = 0x700  # Heartbeat/node guarding (0x701-0x77F)

# J1939 PGN ranges (heavy-duty vehicles, extended frame)
J1939_PRIORITY_MASK = 0x1C000000
J1939_PGN_MASK = 0x03FFFF00
J1939_SOURCE_MASK = 0x000000FF

# ---------------------------------------------------------------------------
# UDS Service Identifiers (ISO 14229-1)
# ---------------------------------------------------------------------------

UDS_SERVICES: Dict[int, str] = {
    # Diagnostic and Communication Management
    0x10: "DiagnosticSessionControl",
    0x11: "ECUReset",
    0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation",
    0x27: "SecurityAccess",
    0x28: "CommunicationControl",
    0x29: "Authentication",
    0x2A: "ReadDataByPeriodicIdentifier",
    0x2C: "DynamicallyDefineDataIdentifier",
    0x2E: "WriteDataByIdentifier",
    0x2F: "InputOutputControlByIdentifier",
    0x31: "RoutineControl",
    0x34: "RequestDownload",
    0x35: "RequestUpload",
    0x36: "TransferData",
    0x37: "RequestTransferExit",
    0x38: "RequestFileTransfer",
    0x3D: "WriteMemoryByAddress",
    0x3E: "TesterPresent",
    0x85: "ControlDTCSetting",
    0x86: "ResponseOnEvent",
    # Data Transmission
    0x22: "ReadDataByIdentifier",
    0x23: "ReadMemoryByAddress",
    0x24: "ReadScalingDataByIdentifier",
}

# UDS positive response offset
UDS_POSITIVE_RESPONSE_OFFSET = 0x40

# UDS negative response service ID
UDS_NEGATIVE_RESPONSE = 0x7F

# UDS Negative Response Codes (NRC)
UDS_NRC: Dict[int, str] = {
    0x10: "GeneralReject",
    0x11: "ServiceNotSupported",
    0x12: "SubFunctionNotSupported",
    0x13: "IncorrectMessageLengthOrInvalidFormat",
    0x14: "ResponseTooLong",
    0x21: "BusyRepeatRequest",
    0x22: "ConditionsNotCorrect",
    0x24: "RequestSequenceError",
    0x25: "NoResponseFromSubnetComponent",
    0x26: "FailurePreventsExecutionOfRequestedAction",
    0x31: "RequestOutOfRange",
    0x33: "SecurityAccessDenied",
    0x35: "InvalidKey",
    0x36: "ExceededNumberOfAttempts",
    0x37: "RequiredTimeDelayNotExpired",
    0x70: "UploadDownloadNotAccepted",
    0x71: "TransferDataSuspended",
    0x72: "GeneralProgrammingFailure",
    0x73: "WrongBlockSequenceCounter",
    0x78: "RequestCorrectlyReceivedResponsePending",
    0x7E: "SubFunctionNotSupportedInActiveSession",
    0x7F: "ServiceNotSupportedInActiveSession",
}

# UDS Diagnostic Sessions
UDS_SESSIONS: Dict[int, str] = {
    0x01: "DefaultSession",
    0x02: "ProgrammingSession",
    0x03: "ExtendedDiagnosticSession",
    0x04: "SafetySystemDiagnosticSession",
}

# UDS ECU Reset sub-function types (service 0x11)
UDS_RESET_TYPES: Dict[int, str] = {
    0x01: "HardReset",
    0x02: "KeyOffOnReset",
    0x03: "SoftReset",
}

# UDS RoutineControl sub-function types (service 0x31)
UDS_ROUTINE_CONTROL_TYPES: Dict[int, str] = {
    0x01: "StartRoutine",
    0x02: "StopRoutine",
    0x03: "RequestRoutineResults",
}

# ---------------------------------------------------------------------------
# UDS Standard DID ranges (Data Identifiers for ReadDataByIdentifier 0x22)
# ---------------------------------------------------------------------------

# Standard F-DIDs defined by ISO 14229
UDS_STANDARD_DIDS: Dict[int, str] = {
    0xF180: "BootSoftwareIdentification",
    0xF181: "ApplicationSoftwareIdentification",
    0xF182: "ApplicationDataIdentification",
    0xF183: "BootSoftwareFingerprint",
    0xF184: "ApplicationSoftwareFingerprint",
    0xF185: "ApplicationDataFingerprint",
    0xF186: "ActiveDiagnosticSession",
    0xF187: "VehicleManufacturerSparePartNumber",
    0xF188: "VehicleManufacturerECUSoftwareNumber",
    0xF189: "VehicleManufacturerECUSoftwareVersionNumber",
    0xF18A: "SystemSupplierIdentifier",
    0xF18B: "ECUManufacturingDate",
    0xF18C: "ECUSerialNumber",
    0xF18D: "SupportedFunctionalUnits",
    0xF18E: "VehicleManufacturerKitAssemblyPartNumber",
    0xF190: "VIN",
    0xF191: "VehicleManufacturerECUHardwareNumber",
    0xF192: "SystemSupplierECUHardwareNumber",
    0xF193: "SystemSupplierECUHardwareVersionNumber",
    0xF194: "SystemSupplierECUSoftwareNumber",
    0xF195: "SystemSupplierECUSoftwareVersionNumber",
    0xF196: "ExhaustRegulationOrTypeApprovalNumber",
    0xF197: "SystemNameOrEngineType",
    0xF198: "RepairShopCodeOrTesterSerialNumber",
    0xF199: "ProgrammingDate",
    0xF19A: "CalibrationRepairShopCodeOrCalibrationEquipmentSerialNumber",
    0xF19B: "CalibrationDate",
    0xF19C: "CalibrationEquipmentSoftwareNumber",
    0xF19D: "ECUInstallationDate",
    0xF19E: "ODXFileIdentifier",
    0xF19F: "EDIANIdentifier",
}

# Default DID scan range: standard F-DIDs
UDS_DID_SCAN_DEFAULT_START = 0xF180
UDS_DID_SCAN_DEFAULT_END = 0xF19F

# ---------------------------------------------------------------------------
# OBD-II Service/Mode definitions
# ---------------------------------------------------------------------------

OBD2_SERVICES: Dict[int, str] = {
    0x01: "ShowCurrentData",
    0x02: "ShowFreezeFrameData",
    0x03: "ShowStoredDTCs",
    0x04: "ClearDTCs",
    0x05: "OxygenSensorTestResults",
    0x06: "OnBoardMonitoringTestResults",
    0x07: "ShowPendingDTCs",
    0x08: "ControlOnBoardSystem",
    0x09: "VehicleInformation",
    0x0A: "PermanentDTCs",
}

# Common OBD-II PIDs (Mode 0x01)
OBD2_PIDS: Dict[int, str] = {
    0x00: "PIDs supported [01-20]",
    0x01: "Monitor status since DTCs cleared",
    0x04: "Calculated engine load",
    0x05: "Engine coolant temperature",
    0x0C: "Engine RPM",
    0x0D: "Vehicle speed",
    0x0F: "Intake air temperature",
    0x10: "MAF air flow rate",
    0x11: "Throttle position",
    0x1C: "OBD standards compliance",
    0x1F: "Run time since engine start",
    0x20: "PIDs supported [21-40]",
    0x2F: "Fuel tank level input",
    0x40: "PIDs supported [41-60]",
    0x42: "Control module voltage",
    0x46: "Ambient air temperature",
    0x49: "Accelerator pedal position D",
    0x51: "Fuel type",
    0x60: "PIDs supported [61-80]",
}

# OBD-II PIDs for vehicle info (Mode 0x09)
OBD2_VEHICLE_INFO_PIDS: Dict[int, str] = {
    0x00: "Mode 09 supported PIDs [01-20]",
    0x02: "VIN (Vehicle Identification Number)",
    0x04: "Calibration ID",
    0x06: "Calibration verification numbers",
    0x0A: "ECU name",
    0x0D: "ESN (Engine Serial Number)",
}

# ---------------------------------------------------------------------------
# ISO-TP (ISO 15765-2) frame types
# ---------------------------------------------------------------------------

ISOTP_SINGLE_FRAME = 0x00
ISOTP_FIRST_FRAME = 0x10
ISOTP_CONSECUTIVE_FRAME = 0x20
ISOTP_FLOW_CONTROL = 0x30

ISOTP_FRAME_TYPES: Dict[int, str] = {
    ISOTP_SINGLE_FRAME: "SingleFrame",
    ISOTP_FIRST_FRAME: "FirstFrame",
    ISOTP_CONSECUTIVE_FRAME: "ConsecutiveFrame",
    ISOTP_FLOW_CONTROL: "FlowControl",
}

# Flow control status flags
ISOTP_FC_CONTINUE = 0x00
ISOTP_FC_WAIT = 0x01
ISOTP_FC_OVERFLOW = 0x02

# ---------------------------------------------------------------------------
# XCP (Universal Measurement and Calibration Protocol) - ASAM MCD-1 XCP
# ---------------------------------------------------------------------------
# Reference: ASAM MCD-1 XCP specification, Vector XCP Reference Book
# XCP is used for ECU calibration, measurement, and flash programming
# over CAN, Ethernet, FlexRay, SPI, etc.

# XCP Command Codes (CTO Request PIDs - sent by master)
XCP_CMD: Dict[int, str] = {
    # Standard (mandatory) commands
    0xFF: "CONNECT",
    0xFE: "DISCONNECT",
    0xFD: "GET_STATUS",
    0xFC: "SYNCH",
    # Standard (optional) commands
    0xFB: "GET_COMM_MODE_INFO",
    0xFA: "GET_ID",
    0xF9: "SET_REQUEST",
    0xF8: "GET_SEED",
    0xF7: "UNLOCK",
    0xF6: "SET_MTA",
    0xF5: "UPLOAD",
    0xF4: "SHORT_UPLOAD",
    0xF3: "BUILD_CHECKSUM",
    0xF2: "TRANSPORT_LAYER_CMD",
    0xF1: "USER_CMD",
    # Calibration commands
    0xF0: "DOWNLOAD",
    0xEF: "DOWNLOAD_NEXT",
    0xEE: "DOWNLOAD_MAX",
    0xED: "SHORT_DOWNLOAD",
    0xEC: "MODIFY_BITS",
    # Page switching commands
    0xEB: "SET_CAL_PAGE",
    0xEA: "GET_CAL_PAGE",
    0xE9: "GET_PAG_PROCESSOR_INFO",
    0xE8: "GET_SEGMENT_INFO",
    0xE7: "GET_PAGE_INFO",
    0xE6: "SET_SEGMENT_MODE",
    0xE5: "GET_SEGMENT_MODE",
    0xE4: "COPY_CAL_PAGE",
    # DAQ commands
    0xE3: "CLEAR_DAQ_LIST",
    0xE2: "SET_DAQ_PTR",
    0xE1: "WRITE_DAQ",
    0xE0: "SET_DAQ_LIST_MODE",
    0xDF: "GET_DAQ_LIST_MODE",
    0xDE: "START_STOP_DAQ_LIST",
    0xDD: "START_STOP_SYNCH",
    0xDC: "GET_DAQ_CLOCK",
    0xDB: "READ_DAQ",
    0xDA: "GET_DAQ_PROCESSOR_INFO",
    0xD9: "GET_DAQ_RESOLUTION_INFO",
    0xD8: "GET_DAQ_LIST_INFO",
    0xD7: "GET_DAQ_EVENT_INFO",
    # Dynamic DAQ configuration
    0xD6: "FREE_DAQ",
    0xD5: "ALLOC_DAQ",
    0xD4: "ALLOC_ODT",
    0xD3: "ALLOC_ODT_ENTRY",
    # Flash programming commands
    0xD2: "PROGRAM_START",
    0xD1: "PROGRAM_CLEAR",
    0xD0: "PROGRAM",
    0xCF: "PROGRAM_RESET",
    0xCE: "GET_PGM_PROCESSOR_INFO",
    0xCD: "GET_SECTOR_INFO",
    0xCC: "PROGRAM_PREPARE",
    0xCB: "PROGRAM_FORMAT",
    0xCA: "PROGRAM_NEXT",
    0xC9: "PROGRAM_MAX",
    0xC8: "PROGRAM_VERIFY",
}

# XCP Response Packet Identifiers (CTO Response PIDs)
XCP_RES_PID = 0xFF  # Positive response
XCP_ERR_PID = 0xFE  # Error / negative response
XCP_EV_PID = 0xFD  # Event packet
XCP_SERV_PID = 0xFC  # Service request packet

# XCP specific command byte constants (for building packets)
XCP_CONNECT_CMD = 0xFF
XCP_DISCONNECT_CMD = 0xFE
XCP_GET_STATUS_CMD = 0xFD
XCP_GET_COMM_MODE_INFO_CMD = 0xFB
XCP_GET_ID_CMD = 0xFA
XCP_GET_SEED_CMD = 0xF8
XCP_UPLOAD_CMD = 0xF5
XCP_SHORT_UPLOAD_CMD = 0xF4
XCP_SET_MTA_CMD = 0xF6

# XCP CONNECT mode byte
XCP_CONNECT_MODE_NORMAL = 0x00
XCP_CONNECT_MODE_USER_DEFINED = 0x01

# XCP GET_ID request types
XCP_ID_TYPE_ASCII = 0x00  # ASCII text
XCP_ID_TYPE_ASAM_MC2_FILENAME = 0x01  # ASAM-MC2 filename without path/extension
XCP_ID_TYPE_ASAM_MC2_FILEPATH = 0x02  # ASAM-MC2 filename with path/extension
XCP_ID_TYPE_URL = 0x03  # URL for ASAM-MC2 file
XCP_ID_TYPE_ASAM_MC2_UPLOAD = 0x04  # ASAM-MC2 file to upload

# XCP Error Codes
XCP_ERR: Dict[int, str] = {
    0x00: "ERR_CMD_SYNCH",
    0x10: "ERR_CMD_BUSY",
    0x11: "ERR_DAQ_ACTIVE",
    0x12: "ERR_PGM_ACTIVE",
    0x20: "ERR_CMD_UNKNOWN",
    0x21: "ERR_CMD_SYNTAX",
    0x22: "ERR_OUT_OF_RANGE",
    0x23: "ERR_WRITE_PROTECTED",
    0x24: "ERR_ACCESS_DENIED",
    0x25: "ERR_ACCESS_LOCKED",
    0x26: "ERR_PAGE_NOT_VALID",
    0x27: "ERR_MODE_NOT_VALID",
    0x28: "ERR_SEGMENT_NOT_VALID",
    0x29: "ERR_SEQUENCE",
    0x2A: "ERR_DAQ_CONFIG",
    0x30: "ERR_MEMORY_OVERFLOW",
    0x31: "ERR_GENERIC",
    0x32: "ERR_VERIFY",
    0x33: "ERR_RESOURCE_TEMPORARY_NOT_ACCESSIBLE",
}

# XCP Resource/Protection bitmask (returned in CONNECT response)
XCP_RESOURCE_CAL_PAG = 0x01  # Calibration/Paging
XCP_RESOURCE_DAQ = 0x04  # Data Acquisition
XCP_RESOURCE_STIM = 0x08  # Stimulation
XCP_RESOURCE_PGM = 0x10  # Flash Programming

# XCP broadcast CAN ID (commonly used for discovery)
XCP_BROADCAST_CAN_ID = 0x100  # Common default, varies per implementation

# ---------------------------------------------------------------------------
# CCP (CAN Calibration Protocol) - ASAM MCD-1 CCP v2.1
# ---------------------------------------------------------------------------
# Reference: ASAM MCD-1 CCP Version 2.1 specification
# CCP is the predecessor to XCP, CAN-only. Uses CRO (Command Receive Object)
# from master and DTO (Data Transmission Object) from slave. All CRO/DTO
# frames are always 8 bytes.

# CCP Command Codes (sent in CRO byte 0)
CCP_CMD: Dict[int, str] = {
    0x01: "CONNECT",
    0x02: "SET_MTA",
    0x03: "DNLOAD",
    0x04: "UPLOAD",
    0x05: "TEST",
    0x06: "START_STOP",
    0x07: "DISCONNECT",
    0x08: "START_STOP_ALL",
    0x09: "GET_ACTIVE_CAL_PAGE",
    0x0C: "SET_S_STATUS",
    0x0D: "GET_S_STATUS",
    0x0E: "BUILD_CHKSUM",
    0x0F: "SHORT_UP",
    0x10: "CLEAR_MEMORY",
    0x11: "SELECT_CAL_PAGE",
    0x12: "GET_SEED",
    0x13: "UNLOCK",
    0x14: "GET_DAQ_SIZE",
    0x15: "SET_DAQ_PTR",
    0x16: "WRITE_DAQ",
    0x17: "EXCHANGE_ID",
    0x18: "PROGRAM",
    0x19: "MOVE",
    0x1B: "GET_CCP_VERSION",
    0x20: "DIAG_SERVICE",
    0x21: "ACTION_SERVICE",
    0x22: "PROGRAM_6",
    0x23: "DNLOAD_6",
}

# CCP specific command byte constants
CCP_CONNECT_CMD = 0x01
CCP_DISCONNECT_CMD = 0x07
CCP_GET_CCP_VERSION_CMD = 0x1B
CCP_EXCHANGE_ID_CMD = 0x17
CCP_GET_SEED_CMD = 0x12
CCP_UNLOCK_CMD = 0x13
CCP_UPLOAD_CMD = 0x04
CCP_SHORT_UP_CMD = 0x0F
CCP_SET_MTA_CMD = 0x02
CCP_TEST_CMD = 0x05
CCP_GET_S_STATUS_CMD = 0x0D

# CCP Return Codes (byte 3 of DTO response)
CCP_CRC: Dict[int, str] = {
    0x00: "Acknowledge / No Error",
    0x01: "DAQ processor overload",
    0x10: "Command processor busy",
    0x11: "DAQ processor busy",
    0x12: "Internal timeout",
    0x18: "Key request",
    0x19: "Session status request",
    0x20: "Cold start request",
    0x21: "Cal. data init. request",
    0x22: "DAQ list init. request",
    0x23: "Code update request",
    0x30: "Unknown command",
    0x31: "Command syntax",
    0x32: "Parameter(s) out of range",
    0x33: "Access denied",
    0x34: "Overload",
    0x35: "Access locked",
    0x36: "Resource/function not available",
}

# CCP DTO Packet ID byte values
CCP_DTO_COMMAND_RETURN = 0xFF  # Command return message
CCP_DTO_EVENT = 0xFE  # Event message

# CCP Disconnect modes
CCP_DISCONNECT_TEMPORARY = 0x00
CCP_DISCONNECT_END_SESSION = 0x01

# CCP default CAN IDs (these vary per A2L file, these are common defaults)
CCP_DEFAULT_CRO_ID = 0x701  # Master -> Slave (Command Receive Object)
CCP_DEFAULT_DTO_ID = 0x702  # Slave -> Master (Data Transmission Object)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class CANMessage:
    """Represents a single CAN bus message."""

    arbitration_id: int
    data: bytes
    timestamp: float = 0.0
    is_extended: bool = False
    is_remote: bool = False
    is_error: bool = False
    is_fd: bool = False
    dlc: int = 0
    channel: str = ""

    def __post_init__(self) -> None:
        if self.dlc == 0:
            self.dlc = len(self.data)

    @property
    def id_hex(self) -> str:
        """Return arbitration ID as hex string."""
        if self.is_extended:
            return f"0x{self.arbitration_id:08X}"
        return f"0x{self.arbitration_id:03X}"

    @property
    def data_hex(self) -> str:
        """Return data as hex string."""
        return " ".join(f"{b:02X}" for b in self.data)


@dataclass
class CANDevice:
    """Discovered CAN device / ECU."""

    arbitration_id: int
    response_id: int = 0
    name: str = ""
    uds_services: List[int] = field(default_factory=list)
    obd2_supported: bool = False
    diagnostic_session: int = 0
    security_access: bool = False
    message_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    data_samples: List[bytes] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def id_hex(self) -> str:
        """Return arbitration ID as hex string."""
        return f"0x{self.arbitration_id:03X}"

    @property
    def response_id_hex(self) -> str:
        """Return response ID as hex string."""
        if self.response_id:
            return f"0x{self.response_id:03X}"
        return "N/A"


@dataclass
class CANTrafficStats:
    """Statistics from CAN bus traffic capture."""

    total_messages: int = 0
    unique_ids: int = 0
    duration_seconds: float = 0.0
    messages_per_second: float = 0.0
    id_counts: Dict[int, int] = field(default_factory=dict)
    id_first_seen: Dict[int, float] = field(default_factory=dict)
    id_last_seen: Dict[int, float] = field(default_factory=dict)
    extended_ids: Set[int] = field(default_factory=set)
    error_frames: int = 0
    remote_frames: int = 0
    bus_load_estimate: float = 0.0

    def get_top_ids(self, n: int = 20) -> List[tuple]:
        """Return the top N most frequent arbitration IDs."""
        sorted_ids = sorted(self.id_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_ids[:n]


@dataclass
class UDSScanResult:
    """Result from UDS service discovery scan."""

    request_id: int
    response_id: int
    supported_services: List[int] = field(default_factory=list)
    diagnostic_sessions: List[int] = field(default_factory=list)
    security_access_levels: List[int] = field(default_factory=list)
    dids_readable: List[int] = field(default_factory=list)
    vehicle_info: Dict[str, str] = field(default_factory=dict)
    negative_responses: Dict[int, int] = field(default_factory=dict)  # service -> NRC
    routines_discovered: List[int] = field(default_factory=list)
    seeds_collected: List[bytes] = field(default_factory=list)


@dataclass
class XCPScanResult:
    """Result from XCP protocol discovery on a CAN arbitration ID."""

    request_id: int
    response_id: int
    connected: bool = False
    resource_protection: int = 0  # Bitmask of protected resources
    comm_mode_basic: int = 0
    max_cto: int = 0  # Max CTO size (command)
    max_dto: int = 0  # Max DTO size (data)
    xcp_version: str = ""
    transport_version: str = ""
    identification: str = ""  # GET_ID result
    status: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    memory_data: Dict[int, bytes] = field(default_factory=dict)  # addr -> data


@dataclass
class CCPScanResult:
    """Result from CCP protocol discovery on a CAN ID pair."""

    cro_id: int  # Master -> Slave CAN ID
    dto_id: int  # Slave -> Master CAN ID
    station_address: int = 0
    connected: bool = False
    ccp_version: str = ""
    device_id: bytes = b""
    session_status: int = 0
    error: str = ""


# ---------------------------------------------------------------------------
# Research Note: Modbus over CAN
# ---------------------------------------------------------------------------
#
# Research conducted 2026-02: "Does Modbus over CAN exist as a standard?"
#
# FINDINGS:
# There is NO formal standard for "Modbus over CAN" as a unified protocol.
# Modbus (RTU/TCP) and CAN are fundamentally different architectures:
#   - CAN: broadcast-based, multi-master, message-oriented (arb ID + data)
#   - Modbus: master-slave, request/response, register-oriented
#
# In practice, industry uses GATEWAY/CONVERTER devices to bridge the two:
#   - HMS Anybus Communicator: CAN <-> Modbus-TCP 2-port converter
#   - GCAN-204: Modbus RTU <-> CAN bidirectional converter
#   - Axiomatic AX141830A: CAN <-> Modbus RTU <-> Modbus TCP/IP
#   - ICP DAS: CANbus gateways with RS-485/Modbus support
#   - Moxa MGate 5118: Modbus TCP gateway series
#
# The converters do protocol TRANSLATION, not encapsulation. They map
# CAN data (e.g., CANopen PDOs/SDOs or J1939 PGNs) to Modbus registers
# and vice versa. The mapping is user-configured (which CAN IDs map to
# which Modbus register addresses).
#
# Related concepts that DO exist as standards:
#   - CANopen (CiA 301): Higher-layer protocol on CAN for automation
#   - DeviceNet: CAN-based protocol by ODVA (uses CIP over CAN)
#   - J1939: Heavy vehicle CAN protocol (SAE standard)
#   - Modbus/TCP, Modbus RTU, Modbus ASCII: Modbus variants on serial/IP
#
# There are also some niche products that tunnel Modbus RTU frames over
# CAN as raw bytes, but this is proprietary and vendor-specific, not a
# recognized standard. The typical industrial pattern is:
#   PLC/SCADA <--Modbus TCP--> Gateway <--CAN/CANopen--> CAN devices
#
# RECOMMENDATION: Do NOT implement "Modbus over CAN" as a protocol.
# If needed in the future, implement CANopen (CiA 301) SDO/PDO parsing
# instead, since that is the actual higher-layer protocol used on CAN
# in industrial environments. Gateway detection could be a separate
# feature that identifies converters by their traffic patterns.
#
# Sources:
#   - https://www.hms-networks.com (Anybus CAN-Modbus converters)
#   - https://www.icpdas-usa.com/canbus_gateways.html
#   - https://kvaser.com/about-can/higher-layer-protocols/modbus/
#   - https://wiki.dfrobot.com/Modbus_vs_CAN_bus
#   - https://www.axiomatic.com/product-category/connectivity-solutions/


# ===========================================================================
# CANopen Protocol Constants (CiA 301 / CiA 309)
# ===========================================================================
#
# References:
#   - CiA 301: CANopen Application Layer and Communication Profile v4.x
#   - CiA 309-2: Accessing CANopen via TCP - Modbus/TCP Mapping
#   - CiA 401: Generic I/O device profile
#   - CiA 402: Drives and motion control device profile
#   - https://canopen.readthedocs.io/
#   - https://github.com/CANopenNode/CANopenNode
#   - https://www.can-cia.org/can-knowledge/

# ---------------------------------------------------------------------------
# CANopen COB-ID Function Codes (4 MSBs of 11-bit arb ID)
# ---------------------------------------------------------------------------
# COB-ID = (function_code << 7) | node_id
# Node IDs are 1-127 (7 bits), 0 is reserved for broadcast/NMT

CANOPEN_NODE_ID_MIN = 1
CANOPEN_NODE_ID_MAX = 127

# Function code bases (already defined above but consolidated here for reference):
# CANOPEN_NMT_ID = 0x000       # NMT module control (broadcast)
# CANOPEN_SYNC_ID = 0x080      # SYNC (broadcast)
# CANOPEN_EMCY_BASE = 0x080    # Emergency: 0x081-0x0FF
# CANOPEN_TPDO1_BASE = 0x180   # TPDO1: 0x181-0x1FF
# CANOPEN_RPDO1_BASE = 0x200   # RPDO1: 0x201-0x27F
# CANOPEN_TPDO2_BASE = 0x280   # TPDO2: 0x281-0x2FF
# CANOPEN_RPDO2_BASE = 0x300   # RPDO2: 0x301-0x37F
# CANOPEN_TPDO3_BASE = 0x380   # TPDO3: 0x381-0x3FF
# CANOPEN_RPDO3_BASE = 0x400   # RPDO3: 0x401-0x47F
# CANOPEN_TPDO4_BASE = 0x480   # TPDO4: 0x481-0x4FF
# CANOPEN_RPDO4_BASE = 0x500   # RPDO4: 0x501-0x57F
# CANOPEN_SDO_TX_BASE = 0x580  # SDO server->client (response): 0x581-0x5FF
# CANOPEN_SDO_RX_BASE = 0x600  # SDO client->server (request): 0x601-0x67F
# CANOPEN_HEARTBEAT_BASE = 0x700  # Heartbeat/NMT error control: 0x701-0x77F

CANOPEN_TIMESTAMP_ID = 0x100  # TIME stamp object (optional)
CANOPEN_LSS_TX_ID = 0x7E4  # LSS master->slave
CANOPEN_LSS_RX_ID = 0x7E5  # LSS slave->master

# COB-ID function code table (maps human-readable name -> base offset)
CANOPEN_FUNCTION_CODES: Dict[str, int] = {
    "NMT": 0x000,
    "SYNC": 0x080,
    "TIME": 0x100,
    "EMCY": 0x080,
    "TPDO1": 0x180,
    "RPDO1": 0x200,
    "TPDO2": 0x280,
    "RPDO2": 0x300,
    "TPDO3": 0x380,
    "RPDO3": 0x400,
    "TPDO4": 0x480,
    "RPDO4": 0x500,
    "SDO_TX": 0x580,
    "SDO_RX": 0x600,
    "HEARTBEAT": 0x700,
}

# ---------------------------------------------------------------------------
# CANopen NMT (Network Management) Commands
# ---------------------------------------------------------------------------
# NMT command frame: COB-ID=0x000, DLC=2
#   byte[0] = NMT command specifier
#   byte[1] = node ID (0 = all nodes)

CANOPEN_NMT_CMD_START = 0x01  # Start remote node (-> Operational)
CANOPEN_NMT_CMD_STOP = 0x02  # Stop remote node (-> Stopped)
CANOPEN_NMT_CMD_PREOPERATIONAL = 0x80  # Enter pre-operational
CANOPEN_NMT_CMD_RESET_NODE = 0x81  # Reset node (application reset)
CANOPEN_NMT_CMD_RESET_COMM = 0x82  # Reset communication

CANOPEN_NMT_COMMANDS: Dict[int, str] = {
    CANOPEN_NMT_CMD_START: "Start (Operational)",
    CANOPEN_NMT_CMD_STOP: "Stop",
    CANOPEN_NMT_CMD_PREOPERATIONAL: "Enter Pre-Operational",
    CANOPEN_NMT_CMD_RESET_NODE: "Reset Node",
    CANOPEN_NMT_CMD_RESET_COMM: "Reset Communication",
}

# ---------------------------------------------------------------------------
# CANopen NMT States (reported in heartbeat byte[0] & 0x7F)
# ---------------------------------------------------------------------------

CANOPEN_NMT_STATE_INITIALISING = 0x00
CANOPEN_NMT_STATE_STOPPED = 0x04
CANOPEN_NMT_STATE_OPERATIONAL = 0x05
CANOPEN_NMT_STATE_PREOPERATIONAL = 0x7F

CANOPEN_NMT_STATES: Dict[int, str] = {
    CANOPEN_NMT_STATE_INITIALISING: "Initialising (Boot-up)",
    CANOPEN_NMT_STATE_STOPPED: "Stopped",
    CANOPEN_NMT_STATE_OPERATIONAL: "Operational",
    CANOPEN_NMT_STATE_PREOPERATIONAL: "Pre-Operational",
}

# ---------------------------------------------------------------------------
# CANopen SDO (Service Data Object) Protocol
# ---------------------------------------------------------------------------
# SDO uses CAN IDs: 0x580+node (server->client TX) and 0x600+node (client->server RX)
# Each SDO frame is always 8 bytes.
# byte[0] = command specifier (CSS/SCS bits in upper 3 bits)
# byte[1..2] = index (little-endian) of object dictionary entry
# byte[3] = sub-index
# byte[4..7] = data or reserved

# Client Command Specifiers (CCS) - bits 7..5 of byte[0]
SDO_CCS_SEGMENT_DOWNLOAD = 0  # Segment download
SDO_CCS_INITIATE_DOWNLOAD = 1  # Initiate download (write)
SDO_CCS_INITIATE_UPLOAD = 2  # Initiate upload (read)
SDO_CCS_SEGMENT_UPLOAD = 3  # Segment upload
SDO_CCS_ABORT = 4  # Abort transfer
SDO_CCS_BLOCK_UPLOAD = 5  # Block upload
SDO_CCS_BLOCK_DOWNLOAD = 6  # Block download

# Server Command Specifiers (SCS) - bits 7..5 of byte[0]
SDO_SCS_SEGMENT_UPLOAD = 0  # Segment upload response
SDO_SCS_SEGMENT_DOWNLOAD = 1  # Segment download response
SDO_SCS_INITIATE_UPLOAD = 2  # Initiate upload response
SDO_SCS_INITIATE_DOWNLOAD = 3  # Initiate download response
SDO_SCS_ABORT = 4  # Abort transfer

# Pre-built SDO command bytes for common operations
# Initiate upload (read) request: CCS=2, no other flags
SDO_CMD_UPLOAD_INITIATE = SDO_CCS_INITIATE_UPLOAD << 5  # 0x40

# Initiate download (write) expedited 4 bytes: CCS=1, n=0, e=1, s=1
SDO_CMD_DOWNLOAD_INITIATE_4B = (SDO_CCS_INITIATE_DOWNLOAD << 5) | 0x23  # 0x23
SDO_CMD_DOWNLOAD_INITIATE_3B = (SDO_CCS_INITIATE_DOWNLOAD << 5) | 0x27  # 0x27
SDO_CMD_DOWNLOAD_INITIATE_2B = (SDO_CCS_INITIATE_DOWNLOAD << 5) | 0x2B  # 0x2B
SDO_CMD_DOWNLOAD_INITIATE_1B = (SDO_CCS_INITIATE_DOWNLOAD << 5) | 0x2F  # 0x2F

# Segment upload request: CCS=3, toggle bit in bit 4
SDO_CMD_SEGMENT_UPLOAD_0 = SDO_CCS_SEGMENT_UPLOAD << 5  # 0x60, toggle=0
SDO_CMD_SEGMENT_UPLOAD_1 = (SDO_CCS_SEGMENT_UPLOAD << 5) | 0x10  # 0x70, toggle=1

# Abort command byte
SDO_CMD_ABORT = SDO_CCS_ABORT << 5  # 0x80

# Server response command bytes
SDO_SCS_UPLOAD_INITIATE_BYTE = SDO_SCS_INITIATE_UPLOAD << 5  # 0x40 (expedited bits vary)
SDO_SCS_DOWNLOAD_INITIATE_BYTE = SDO_SCS_INITIATE_DOWNLOAD << 5  # 0x60

# Bit masks for SDO command byte
SDO_CMD_SPECIFIER_MASK = 0xE0  # Upper 3 bits (CCS/SCS)
SDO_EXPEDITED_BIT = 0x02  # Bit 1: expedited transfer
SDO_SIZE_INDICATED_BIT = 0x01  # Bit 0: size is indicated
SDO_N_BITS_MASK = 0x0C  # Bits 3..2: number of unused bytes (n)
SDO_TOGGLE_BIT = 0x10  # Bit 4: toggle bit for segmented transfer

# ---------------------------------------------------------------------------
# SDO Abort Codes (CiA 301 Table 22)
# ---------------------------------------------------------------------------

SDO_ABORT_CODES: Dict[int, str] = {
    0x05030000: "Toggle bit not alternated",
    0x05040000: "SDO protocol timed out",
    0x05040001: "Client/server command specifier not valid or unknown",
    0x05040002: "Invalid block size (block mode only)",
    0x05040003: "Invalid sequence number (block mode only)",
    0x05040004: "CRC error (block mode only)",
    0x05040005: "Out of memory",
    0x06010000: "Unsupported access to an object",
    0x06010001: "Attempt to read a write-only object",
    0x06010002: "Attempt to write a read-only object",
    0x06020000: "Object does not exist in the object dictionary",
    0x06040041: "Object cannot be mapped to the PDO",
    0x06040042: "Number and length of objects to be mapped exceeds PDO length",
    0x06040043: "General parameter incompatibility reason",
    0x06040047: "General internal incompatibility in the device",
    0x06060000: "Access failed due to a hardware error",
    0x06070010: "Data type does not match, length of service parameter does not match",
    0x06070012: "Data type does not match, length of service parameter too high",
    0x06070013: "Data type does not match, length of service parameter too low",
    0x06090011: "Sub-index does not exist",
    0x06090030: "Invalid value for parameter (download only)",
    0x06090031: "Value of parameter written too high (download only)",
    0x06090032: "Value of parameter written too low (download only)",
    0x06090036: "Maximum value is less than minimum value",
    0x060A0023: "Resource not available: SDO connection",
    0x08000000: "General error",
    0x08000020: "Data cannot be transferred or stored to the application",
    0x08000021: "Data cannot be transferred or stored due to local control",
    0x08000022: "Data cannot be transferred or stored due to device state",
    0x08000023: "Object dictionary dynamic generation fails or no OD present",
    0x08000024: "No data available",
}

# ---------------------------------------------------------------------------
# CANopen Object Dictionary Standard Entries (CiA 301)
# ---------------------------------------------------------------------------
# Range 0x1000-0x1FFF: Communication Profile Area

CANOPEN_OD_DEVICE_TYPE = 0x1000  # UNSIGNED32, mandatory
CANOPEN_OD_ERROR_REGISTER = 0x1001  # UNSIGNED8, mandatory
CANOPEN_OD_MANUFACTURER_STATUS = 0x1002  # UNSIGNED32, optional
CANOPEN_OD_PREDEFINED_ERROR = 0x1003  # ARRAY of UNSIGNED32, optional
CANOPEN_OD_SYNC_COB_ID = 0x1005  # UNSIGNED32, optional
CANOPEN_OD_COMM_CYCLE_PERIOD = 0x1006  # UNSIGNED32, optional
CANOPEN_OD_SYNC_WINDOW_LENGTH = 0x1007  # UNSIGNED32, optional
CANOPEN_OD_DEVICE_NAME = 0x1008  # VISIBLE_STRING, optional
CANOPEN_OD_HW_VERSION = 0x1009  # VISIBLE_STRING, optional
CANOPEN_OD_SW_VERSION = 0x100A  # VISIBLE_STRING, optional
CANOPEN_OD_GUARD_TIME = 0x100C  # UNSIGNED16, optional
CANOPEN_OD_LIFE_TIME_FACTOR = 0x100D  # UNSIGNED8, optional
CANOPEN_OD_STORE_PARAMETERS = 0x1010  # UNSIGNED32, optional
CANOPEN_OD_RESTORE_PARAMETERS = 0x1011  # UNSIGNED32, optional
CANOPEN_OD_EMCY_COB_ID = 0x1014  # UNSIGNED32, optional
CANOPEN_OD_HEARTBEAT_CONSUMER = 0x1016  # ARRAY, optional
CANOPEN_OD_HEARTBEAT_PRODUCER = 0x1017  # UNSIGNED16, optional
CANOPEN_OD_IDENTITY = 0x1018  # RECORD, mandatory

# Identity object (0x1018) sub-indices
CANOPEN_OD_IDENTITY_VENDOR_ID = 0x01  # UNSIGNED32
CANOPEN_OD_IDENTITY_PRODUCT_CODE = 0x02  # UNSIGNED32
CANOPEN_OD_IDENTITY_REVISION = 0x03  # UNSIGNED32
CANOPEN_OD_IDENTITY_SERIAL = 0x04  # UNSIGNED32

# SDO server/client parameters
CANOPEN_OD_SDO_SERVER_1 = 0x1200  # SDO server parameter
CANOPEN_OD_SDO_CLIENT_1 = 0x1280  # SDO client parameter

# RPDO/TPDO communication parameters
CANOPEN_OD_RPDO1_COMM = 0x1400
CANOPEN_OD_RPDO1_MAPPING = 0x1600
CANOPEN_OD_TPDO1_COMM = 0x1800
CANOPEN_OD_TPDO1_MAPPING = 0x1A00

# Standard CANopen PDO entries — shared with EtherCAT CoE (ethercat/coe.py)
CANOPEN_PDO_ENTRIES: Dict[int, str] = {
    0x1400: "RPDO1 Communication Parameter",
    0x1401: "RPDO2 Communication Parameter",
    0x1402: "RPDO3 Communication Parameter",
    0x1403: "RPDO4 Communication Parameter",
    0x1600: "RPDO1 Mapping Parameter",
    0x1601: "RPDO2 Mapping Parameter",
    0x1602: "RPDO3 Mapping Parameter",
    0x1603: "RPDO4 Mapping Parameter",
    0x1800: "TPDO1 Communication Parameter",
    0x1801: "TPDO2 Communication Parameter",
    0x1802: "TPDO3 Communication Parameter",
    0x1803: "TPDO4 Communication Parameter",
    0x1A00: "TPDO1 Mapping Parameter",
    0x1A01: "TPDO2 Mapping Parameter",
    0x1A02: "TPDO3 Mapping Parameter",
    0x1A03: "TPDO4 Mapping Parameter",
}

# Standard OD entries for identification with descriptions
CANOPEN_OD_ENTRIES: Dict[int, str] = {
    0x1000: "Device Type",
    0x1001: "Error Register",
    0x1002: "Manufacturer Status Register",
    0x1003: "Pre-Defined Error Field",
    0x1005: "COB-ID SYNC Message",
    0x1006: "Communication Cycle Period",
    0x1007: "Synchronous Window Length",
    0x1008: "Manufacturer Device Name",
    0x1009: "Manufacturer Hardware Version",
    0x100A: "Manufacturer Software Version",
    0x100C: "Guard Time",
    0x100D: "Life Time Factor",
    0x1010: "Store Parameters",
    0x1011: "Restore Default Parameters",
    0x1012: "COB-ID TIME Stamp Object",
    0x1013: "High Resolution Time Stamp",
    0x1014: "COB-ID Emergency Message",
    0x1015: "Inhibit Time Emergency",
    0x1016: "Consumer Heartbeat Time",
    0x1017: "Producer Heartbeat Time",
    0x1018: "Identity Object",
    0x1019: "Synchronous Counter Overflow Value",
    0x1020: "Verify Configuration",
    0x1021: "Store EDS",
    0x1022: "Store Format",
    0x1023: "OS Command",
    0x1024: "OS Command Mode",
    0x1025: "OS Debugger Interface",
    0x1026: "OS Prompt",
    0x1027: "Module List",
    0x1028: "Emergency Consumer Object",
    0x1029: "Error Behavior Object",
    0x1200: "SDO Server Parameter",
    0x1280: "SDO Client Parameter",
    **CANOPEN_PDO_ENTRIES,
}

# Key OD indices for device fingerprinting (read these first)
CANOPEN_FINGERPRINT_INDICES = [
    (0x1000, 0x00, "Device Type"),
    (0x1001, 0x00, "Error Register"),
    (0x1008, 0x00, "Device Name"),
    (0x1009, 0x00, "Hardware Version"),
    (0x100A, 0x00, "Software Version"),
    (0x1018, 0x01, "Vendor ID"),
    (0x1018, 0x02, "Product Code"),
    (0x1018, 0x03, "Revision Number"),
    (0x1018, 0x04, "Serial Number"),
]

# ---------------------------------------------------------------------------
# CANopen Device Profile Identifiers (lower 16 bits of 0x1000)
# ---------------------------------------------------------------------------
# The device type object (0x1000) contains:
#   bits 15..0:  device profile number
#   bits 31..16: additional information

CANOPEN_DEVICE_PROFILES: Dict[int, str] = {
    0: "Generic (no profile)",
    301: "Communication Profile (CiA 301)",
    309: "CANopen-to-Modbus Gateway (CiA 309)",
    401: "Generic I/O Modules (CiA 401)",
    402: "Drives and Motion Control (CiA 402)",
    404: "Measuring Devices and Controllers (CiA 404)",
    405: "IEC 61131-3 Programmable Devices (CiA 405)",
    406: "Rotary/Linear Encoders (CiA 406)",
    408: "Hydraulic Drives and Proportional Valves (CiA 408)",
    410: "Inclinometers (CiA 410)",
    412: "Medical Devices (CiA 412)",
    413: "Truck Gateways (CiA 413)",
    414: "Weaving Machines (CiA 414)",
    415: "Road Construction Machinery (CiA 415)",
    416: "Municipal Vehicles (CiA 416)",
    417: "Lift Control Systems (CiA 417)",
    418: "Battery Modules (CiA 418)",
    419: "Battery Chargers (CiA 419)",
    420: "Extruder Downstream Devices (CiA 420)",
    422: "Municipal Utility Vehicles (CiA 422)",
    443: "SIIS Level-2 Devices (CiA 443)",
    444: "SIIS Level-1 Devices (CiA 444)",
    445: "RFID Reader Devices (CiA 445)",
    446: "Proportional Hydraulic Valves (CiA 446)",
    447: "AC Power Supply Units (CiA 447)",
    450: "Light Modules (CiA 450)",
    452: "Service Tool (CiA 452)",
    454: "Roller Bearing Monitoring (CiA 454)",
}

# ---------------------------------------------------------------------------
# CANopen EMCY (Emergency) Error Codes
# ---------------------------------------------------------------------------
# EMCY message format: COB-ID = 0x080 + node_id, DLC=8
#   byte[0..1] = emergency error code (little-endian)
#   byte[2]    = error register (= OD 0x1001)
#   byte[3..7] = manufacturer-specific error data

# Error register bits (object 0x1001)
CANOPEN_ERR_REG_GENERIC = 0x01  # Bit 0: generic error
CANOPEN_ERR_REG_CURRENT = 0x02  # Bit 1: current
CANOPEN_ERR_REG_VOLTAGE = 0x04  # Bit 2: voltage
CANOPEN_ERR_REG_TEMPERATURE = 0x08  # Bit 3: temperature
CANOPEN_ERR_REG_COMMUNICATION = 0x10  # Bit 4: communication error
CANOPEN_ERR_REG_DEVICE_PROFILE = 0x20  # Bit 5: device profile specific
CANOPEN_ERR_REG_RESERVED = 0x40  # Bit 6: reserved
CANOPEN_ERR_REG_MANUFACTURER = 0x80  # Bit 7: manufacturer specific

CANOPEN_ERR_REGISTER_BITS: Dict[int, str] = {
    0x01: "Generic error",
    0x02: "Current",
    0x04: "Voltage",
    0x08: "Temperature",
    0x10: "Communication error",
    0x20: "Device profile specific",
    0x40: "Reserved",
    0x80: "Manufacturer specific",
}

# Standard EMCY error codes (CiA 301 + CiA 401)
CANOPEN_EMCY_CODES: Dict[int, str] = {
    0x0000: "Error reset / no error",
    0x1000: "Generic error",
    0x2000: "Current - generic",
    0x2100: "Current, device input side",
    0x2200: "Current inside the device",
    0x2300: "Current, device output side",
    0x2310: "Current at outputs too high (overload)",
    0x2320: "Short circuit at outputs",
    0x2330: "Load dump at outputs",
    0x3000: "Voltage - generic",
    0x3100: "Mains voltage",
    0x3110: "Mains voltage too high",
    0x3120: "Mains voltage too low",
    0x3200: "Voltage inside the device",
    0x3210: "DC link voltage too high",
    0x3220: "DC link voltage too low",
    0x3300: "Output voltage",
    0x3310: "Output voltage too high",
    0x3320: "Output voltage too low",
    0x4000: "Temperature - generic",
    0x4100: "Ambient temperature",
    0x4200: "Device temperature",
    0x5000: "Device hardware - generic",
    0x6000: "Device software - generic",
    0x6100: "Internal software",
    0x6200: "User software",
    0x6300: "Data set",
    0x7000: "Additional modules",
    0x8000: "Monitoring - generic",
    0x8100: "Communication",
    0x8110: "CAN overrun (objects lost)",
    0x8120: "CAN in error passive mode",
    0x8130: "Life guard error / heartbeat error",
    0x8140: "Recovered from bus off",
    0x8150: "CAN-ID collision",
    0x8200: "Protocol error",
    0x8210: "PDO not processed due to length error",
    0x8220: "PDO length exceeded",
    0x8230: "DAM MPDO not processed, dest object not available",
    0x8240: "Unexpected SYNC data length",
    0x8250: "RPDO timeout",
    0x9000: "External error",
    0xF000: "Additional functions",
    0xFF00: "Device specific",
}

# ---------------------------------------------------------------------------
# CANopen PDO Communication Parameters
# ---------------------------------------------------------------------------
# TPDO/RPDO communication parameter sub-indices

CANOPEN_PDO_COMM_COB_ID = 0x01  # COB-ID used by PDO
CANOPEN_PDO_COMM_TRANSMISSION = 0x02  # Transmission type
CANOPEN_PDO_COMM_INHIBIT_TIME = 0x03  # Inhibit time
CANOPEN_PDO_COMM_EVENT_TIMER = 0x05  # Event timer

# PDO transmission types
CANOPEN_PDO_TRANS_SYNC_ACYCLIC = 0x00  # Synchronous (acyclic)
CANOPEN_PDO_TRANS_SYNC_CYCLIC_BASE = 0x01  # Synchronous (cyclic, every N-th SYNC)
CANOPEN_PDO_TRANS_RTR_SYNC = 0xFC  # RTR-only (synchronous)
CANOPEN_PDO_TRANS_RTR_ASYNC = 0xFD  # RTR-only (asynchronous)
CANOPEN_PDO_TRANS_ASYNC_MFR = 0xFE  # Asynchronous, manufacturer specific
CANOPEN_PDO_TRANS_ASYNC_PROFILE = 0xFF  # Asynchronous, device profile specific

# ---------------------------------------------------------------------------
# CiA 309 - CANopen-to-Modbus Gateway Constants
# ---------------------------------------------------------------------------
# CiA 309-2 defines the Modbus/TCP mapping for CANopen gateways.
# A device with profile 309 in object 0x1000 is a Modbus gateway.

CIA309_PROFILE_NUMBER = 309

# Gateway-specific OD entries (CiA 309 defines these in manufacturer range)
CIA309_OD_GATEWAY_CONFIG = 0x5000  # Gateway configuration base
CIA309_OD_MODBUS_MAP_BASE = 0x5100  # Modbus register mapping base
CIA309_OD_SLAVE_MAP_BASE = 0x5200  # CAN slave assignment base

# Modbus function codes used through gateways (standard Modbus FC)
CIA309_MODBUS_FC_READ_HOLDING = 0x03
CIA309_MODBUS_FC_READ_INPUT = 0x04
CIA309_MODBUS_FC_WRITE_SINGLE = 0x06
CIA309_MODBUS_FC_WRITE_MULTIPLE = 0x10

# Known gateway vendor IDs (CiA assigned) - commonly seen in the field
CANOPEN_KNOWN_GATEWAY_VENDORS: Dict[int, str] = {
    0x00000002: "Beckhoff Automation",
    0x00000022: "HMS Industrial Networks (Anybus)",
    0x00000050: "IXXAT / HMS",
    0x0000005A: "WAGO",
    0x00000066: "Hilscher",
    0x0000006A: "esd electronics",
    0x00000079: "IFM Electronic",
    0x000000A2: "Phoenix Contact",
    0x000000AB: "PEAK System",
    0x000000C7: "Moxa",
    0x000000F4: "Helmholz",
    0x00000113: "Advantech",
    0x0000021C: "ICP DAS",
}

# ---------------------------------------------------------------------------
# CANopen Scan Result Data Classes
# ---------------------------------------------------------------------------


@dataclass
class CANopenNode:
    """Discovered CANopen node on the bus."""

    node_id: int
    nmt_state: int = 0
    nmt_state_name: str = ""
    device_type: int = 0
    device_profile: int = 0
    device_profile_name: str = ""
    device_name: str = ""
    hw_version: str = ""
    sw_version: str = ""
    vendor_id: int = 0
    vendor_name: str = ""
    product_code: int = 0
    revision: int = 0
    serial_number: int = 0
    error_register: int = 0
    heartbeat_ms: int = 0
    od_entries_found: List[int] = field(default_factory=list)
    pdo_mappings: Dict[str, Any] = field(default_factory=dict)
    is_gateway: bool = False
    gateway_type: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def node_id_hex(self) -> str:
        """Return node ID formatted."""
        return f"0x{self.node_id:02X} ({self.node_id})"

    @property
    def sdo_rx_cob_id(self) -> int:
        """SDO request COB-ID (client->server)."""
        return 0x600 + self.node_id

    @property
    def sdo_tx_cob_id(self) -> int:
        """SDO response COB-ID (server->client)."""
        return 0x580 + self.node_id

    @property
    def heartbeat_cob_id(self) -> int:
        """Heartbeat COB-ID."""
        return 0x700 + self.node_id

    @property
    def emcy_cob_id(self) -> int:
        """Emergency COB-ID."""
        return 0x080 + self.node_id


@dataclass
class CANopenScanResult:
    """Result from a CANopen network scan."""

    nodes: List[CANopenNode] = field(default_factory=list)
    total_nodes_found: int = 0
    scan_duration: float = 0.0
    heartbeat_nodes: List[int] = field(default_factory=list)
    emcy_messages: List[Dict[str, Any]] = field(default_factory=list)
    gateways: List[CANopenNode] = field(default_factory=list)
    modbus_mappings: Dict[int, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class CANopenSDOResponse:
    """Result from a single SDO read operation."""

    node_id: int
    index: int
    subindex: int
    data: bytes = b""
    error: bool = False
    abort_code: int = 0
    abort_message: str = ""

    @property
    def as_uint8(self) -> Optional[int]:
        """Interpret data as UNSIGNED8."""
        if len(self.data) >= 1 and not self.error:
            return self.data[0]
        return None

    @property
    def as_uint16(self) -> Optional[int]:
        """Interpret data as UNSIGNED16 (little-endian)."""
        if len(self.data) >= 2 and not self.error:
            return self.data[0] | (self.data[1] << 8)
        return None

    @property
    def as_uint32(self) -> Optional[int]:
        """Interpret data as UNSIGNED32 (little-endian)."""
        if len(self.data) >= 4 and not self.error:
            return self.data[0] | (self.data[1] << 8) | (self.data[2] << 16) | (self.data[3] << 24)
        return None

    @property
    def as_string(self) -> Optional[str]:
        """Interpret data as VISIBLE_STRING."""
        if self.data and not self.error:
            try:
                return self.data.decode("ascii", errors="ignore").rstrip("\x00")
            except Exception as e:
                logger.debug(f"Return value computation failed: {e}")
                return None
        return None
