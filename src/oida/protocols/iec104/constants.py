"""
IEC 60870-5-104 Protocol Constants and Data Types

Contains:
- FT1.2 frame format constants (IEC 101 serial mode)
- IEC 104 Type ID definitions
- Cause of Transmission (COT) lookup
- CapturedASDU and ListenStats dataclasses
- protocol_options dict for the scanner registry
"""

from typing import Dict, Any, Set, Optional
from dataclasses import dataclass, field
import time

# =============================================================================
# FT1.2 Frame Format Constants (for IEC 101 serial mode)
# =============================================================================

FT12_START_FIXED = 0x10  # Fixed length frame start
FT12_START_VARIABLE = 0x68  # Variable length frame start
FT12_END = 0x16  # Frame end

# Control field function codes (unbalanced mode)
FC_RESET_REMOTE_LINK = 0x00
FC_RESET_USER_PROCESS = 0x01
FC_USER_DATA_CONFIRMED = 0x03
FC_USER_DATA_NO_REPLY = 0x04
FC_REQUEST_ACCESS_DEMAND = 0x08
FC_REQUEST_STATUS_LINK = 0x09
FC_REQUEST_USER_DATA_CLASS1 = 0x0A
FC_REQUEST_USER_DATA_CLASS2 = 0x0B

# Direction and frame bits
DIR_MASTER = 0x40
PRM_PRIMARY = 0x40
FCB = 0x20  # Frame count bit
FCV = 0x10  # Frame count valid

# =============================================================================
# APCI / APDU Frame Structure
# =============================================================================

ASDU_TYPE_ID_OFFSET = 6
ASDU_VSQ_OFFSET = 7
ASDU_COT_OFFSET = 8
ASDU_CA_OFFSET = 9
ASDU_IOA_OFFSET = 11
ASDU_DATA_OFFSET = 14
ASDU_HEADER_SIZE = 12  # APCI(6) + TI(1) + VSQ(1) + COT(2) + CA(2)
IOA_SIZE = 3
IFRAME_MASK = 0x01  # (data[2] & IFRAME_MASK) == 0 → I-frame

# IEC 60870-5-101 (serial) Common Address / IOA octet widths.
# NOTE: these widths are configurable per IEC 60870-5-101 (CA may be 1 or 2
# octets, IOA 1/2/3 octets). This implementation currently assumes the most
# common 1-octet CA / 2-octet IOA profile; stations configured for wider
# fields will have their CA/IOA parsed and built incorrectly.
IEC101_CA_OCTETS = 1
IEC101_IOA_OCTETS = 2

# =============================================================================
# VSQ (Variable Structure Qualifier)
# =============================================================================

VSQ_COUNT_MASK = 0x7F
VSQ_SINGLE_OBJECT = 0x01

# IEC 104 Type ID definitions
IEC104_TYPE_IDS = {
    # Process information in monitoring direction
    1: ("M_SP_NA_1", "Single-point information"),
    2: ("M_SP_TA_1", "Single-point information with time tag"),
    3: ("M_DP_NA_1", "Double-point information"),
    4: ("M_DP_TA_1", "Double-point information with time tag"),
    5: ("M_ST_NA_1", "Step position information"),
    6: ("M_ST_TA_1", "Step position information with time tag"),
    7: ("M_BO_NA_1", "Bitstring of 32 bits"),
    8: ("M_BO_TA_1", "Bitstring of 32 bits with time tag"),
    9: ("M_ME_NA_1", "Measured value, normalized value"),
    10: ("M_ME_TA_1", "Measured value, normalized value with time tag"),
    11: ("M_ME_NB_1", "Measured value, scaled value"),
    12: ("M_ME_TB_1", "Measured value, scaled value with time tag"),
    13: ("M_ME_NC_1", "Measured value, short floating point"),
    14: ("M_ME_TC_1", "Measured value, short floating point with time tag"),
    15: ("M_IT_NA_1", "Integrated totals"),
    16: ("M_IT_TA_1", "Integrated totals with time tag"),
    17: ("M_EP_TA_1", "Event of protection equipment with time tag"),
    18: ("M_EP_TB_1", "Packed start events with time tag"),
    19: ("M_EP_TC_1", "Packed output circuit info with time tag"),
    20: ("M_PS_NA_1", "Packed single-point info with status change"),
    21: ("M_ME_ND_1", "Measured value, normalized without quality"),
    # With CP56Time2a timestamps (IEC 104 specific)
    30: ("M_SP_TB_1", "Single-point information with CP56Time2a"),
    31: ("M_DP_TB_1", "Double-point information with CP56Time2a"),
    32: ("M_ST_TB_1", "Step position information with CP56Time2a"),
    33: ("M_BO_TB_1", "Bitstring of 32 bits with CP56Time2a"),
    34: ("M_ME_TD_1", "Measured value, normalized with CP56Time2a"),
    35: ("M_ME_TE_1", "Measured value, scaled with CP56Time2a"),
    36: ("M_ME_TF_1", "Measured value, short float with CP56Time2a"),
    37: ("M_IT_TB_1", "Integrated totals with CP56Time2a"),
    38: ("M_EP_TD_1", "Event of protection equipment with CP56Time2a"),
    39: ("M_EP_TE_1", "Packed start events with CP56Time2a"),
    40: ("M_EP_TF_1", "Packed output circuit info with CP56Time2a"),
    # Process information in control direction
    45: ("C_SC_NA_1", "Single command"),
    46: ("C_DC_NA_1", "Double command"),
    47: ("C_RC_NA_1", "Regulating step command"),
    48: ("C_SE_NA_1", "Set point command, normalized"),
    49: ("C_SE_NB_1", "Set point command, scaled"),
    50: ("C_SE_NC_1", "Set point command, short float"),
    51: ("C_BO_NA_1", "Bitstring of 32 bits command"),
    # With CP56Time2a
    58: ("C_SC_TA_1", "Single command with CP56Time2a"),
    59: ("C_DC_TA_1", "Double command with CP56Time2a"),
    60: ("C_RC_TA_1", "Regulating step command with CP56Time2a"),
    61: ("C_SE_TA_1", "Set point, normalized with CP56Time2a"),
    62: ("C_SE_TB_1", "Set point, scaled with CP56Time2a"),
    63: ("C_SE_TC_1", "Set point, short float with CP56Time2a"),
    64: ("C_BO_TA_1", "Bitstring of 32 bits with CP56Time2a"),
    # System information in monitoring direction
    70: ("M_EI_NA_1", "End of initialization"),
    # System information in control direction
    100: ("C_IC_NA_1", "Interrogation command"),
    101: ("C_CI_NA_1", "Counter interrogation command"),
    102: ("C_RD_NA_1", "Read command"),
    103: ("C_CS_NA_1", "Clock synchronization command"),
    104: ("C_TS_NA_1", "Test command"),
    105: ("C_RP_NA_1", "Reset process command"),
    106: ("C_CD_NA_1", "Delay acquisition command"),
    107: ("C_TS_TA_1", "Test command with CP56Time2a"),
    # Parameter in control direction
    110: ("P_ME_NA_1", "Parameter of measured normalized"),
    111: ("P_ME_NB_1", "Parameter of measured scaled"),
    112: ("P_ME_NC_1", "Parameter of measured short float"),
    113: ("P_AC_NA_1", "Parameter activation"),
    # File transfer
    120: ("F_FR_NA_1", "File ready"),
    121: ("F_SR_NA_1", "Section ready"),
    122: ("F_SC_NA_1", "Call directory, select file, call file, call section"),
    123: ("F_LS_NA_1", "Last section, last segment"),
    124: ("F_AF_NA_1", "ACK file, ACK section"),
    125: ("F_SG_NA_1", "Segment"),
    126: ("F_DR_TA_1", "Directory"),
    127: ("F_SC_NB_1", "QueryLog - Request archive file"),
}

# Type ID ranges
MONITORING_TYPE_ID_MAX = 44
COUNTER_TYPE_ID_START = 15
COUNTER_TYPE_ID_END = 21
FILE_TRANSFER_TYPE_ID_START = 120
FILE_TRANSFER_TYPE_ID_END = 127

# Cause of Transmission (COT) lookup
IEC104_COT = {
    1: "periodic",
    2: "background",
    3: "spontaneous",
    4: "initialized",
    5: "request",
    6: "activation",
    7: "activation_confirm",
    8: "deactivation",
    9: "deactivation_confirm",
    10: "activation_termination",
    11: "return_remote",
    12: "return_local",
    13: "file_transfer",
    20: "interrogated_station",
    21: "interrogated_group_1",
    22: "interrogated_group_2",
    23: "interrogated_group_3",
    24: "interrogated_group_4",
    25: "interrogated_group_5",
    26: "interrogated_group_6",
    27: "interrogated_group_7",
    28: "interrogated_group_8",
    29: "interrogated_group_9",
    30: "interrogated_group_10",
    31: "interrogated_group_11",
    32: "interrogated_group_12",
    33: "interrogated_group_13",
    34: "interrogated_group_14",
    35: "interrogated_group_15",
    36: "interrogated_group_16",
    37: "counter_interrogation",
    44: "unknown_type",
    45: "unknown_cause",
    46: "unknown_asdu",
    47: "unknown_ioa",
}

# COT masks and named values
COT_VALUE_MASK = 0x3F
COT_NEGATIVE_BIT = 0x40
COT_SPONTANEOUS = 3
COT_ACTIVATION = 6
COT_ACTIVATION_CONFIRM = 7

# =============================================================================
# Quality Descriptor Bits (QDS)
# =============================================================================

QDS_IV = 0x80  # Invalid
QDS_NT = 0x40  # Not topical
QDS_SB = 0x20  # Substituted
QDS_BL = 0x10  # Blocked
QDS_OV = 0x01  # Overflow

# =============================================================================
# Value Parsing Masks
# =============================================================================

SIQ_SPI_MASK = 0x01
DIQ_DPI_MASK = 0x03
VTI_VALUE_MASK = 0x7F
VTI_TRANSIENT = 0x80
NORMALIZED_SCALE = 32768.0

# =============================================================================
# CP56Time2a
# =============================================================================

CP56TIME2A_SIZE = 7
CP56TIME2A_MINUTE_MASK = 0x3F
CP56TIME2A_HOUR_MASK = 0x1F
CP56TIME2A_DAY_MASK = 0x1F
CP56TIME2A_MONTH_MASK = 0x0F
CP56TIME2A_YEAR_MASK = 0x7F
CP56TIME2A_BASE_YEAR = 2000

# =============================================================================
# Address Space Limits
# =============================================================================

ASDU_ADDRESS_MAX = 65535
IOA_MAX = 16777215


@dataclass
class CapturedASDU:
    """Represents a captured IEC 104 ASDU"""

    timestamp: str
    type_id: int
    type_name: str
    type_description: str
    cause_of_transmission: int
    cot_name: str
    common_address: int
    ioa: int
    value: Any
    quality: str
    raw_bytes: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = {
            "timestamp": self.timestamp,
            "type_id": self.type_id,
            "type_name": self.type_name,
            "type_description": self.type_description,
            "cot": self.cause_of_transmission,
            "cot_name": self.cot_name,
            "common_address": self.common_address,
            "ioa": self.ioa,
            "value": self.value,
            "quality": self.quality,
        }
        if self.raw_bytes:
            result["raw"] = self.raw_bytes.hex()
        return result


@dataclass
class ListenStats:
    """Statistics for listen mode"""

    start_time: float = field(default_factory=time.time)
    asdu_count: int = 0
    type_ids_seen: Set[int] = field(default_factory=set)
    common_addresses_seen: Set[int] = field(default_factory=set)
    ioas_seen: Set[int] = field(default_factory=set)
    bytes_received: int = 0

    @property
    def duration(self) -> float:
        return time.time() - self.start_time

    @property
    def rate(self) -> float:
        d = self.duration
        return self.asdu_count / d if d > 0 else 0.0


# Information element sizes (excluding IOA) for each type ID
# Used to parse non-sequence ASDUs with multiple objects
INFO_ELEMENT_SIZES = {
    1: 1,
    2: 4,
    3: 1,
    4: 4,
    5: 2,
    6: 5,
    7: 5,
    8: 8,  # Single/double/step/bitstring
    9: 3,
    10: 6,
    11: 3,
    12: 6,
    13: 5,
    14: 8,  # Measured values
    15: 5,
    16: 8,
    20: 5,
    21: 2,  # Integrated totals, packed
    30: 8,
    31: 8,
    32: 9,
    33: 12,
    34: 10,
    35: 10,
    36: 12,
    37: 12,  # With CP56Time2a
}


protocol_options = {
    "tls": {
        "type": "bool",
        "description": "Enable TLS encryption (IEC 62351-3)",
        "required": False,
        "default": False,
    },
    "tls-cert": {
        "type": "string",
        "description": "Client certificate file for mutual TLS",
        "required": False,
        "default": None,
    },
    "tls-key": {
        "type": "string",
        "description": "Client private key file for mutual TLS",
        "required": False,
        "default": None,
    },
    "asdu-address": {
        "type": "int",
        "description": "ASDU address (common address of ASDU)",
        "required": False,
        "default": -1,
    },
    "ioa-range": {
        "type": "string",
        "description": "Range of information object addresses to scan",
        "required": False,
        "default": "1-1000",
    },
    "common-address": {
        "type": "int",
        "description": "Common address for commands",
        "required": False,
        "default": 1,
    },
    "max-commands": {
        "type": "int",
        "description": "Maximum number of commands to test",
        "required": False,
        "default": 10,
    },
    "interrogate": {
        "type": "bool",
        "description": "Run general interrogation (GI) to discover data points",
        "required": False,
        "default": False,
    },
    "interrogate-groups": {
        "type": "bool",
        "description": "Run group interrogation (groups 1-16) to map point-to-group layout",
        "required": False,
        "default": False,
    },
    "station-scan": {
        "type": "string",
        "description": "Scan for active Common Addresses (optional range, default 1-254)",
        "required": False,
        "default": None,
    },
    "test-commands": {
        "type": "bool",
        "description": "Test command execution (write operations)",
        "required": False,
        "default": False,
    },
    "probe-files": {
        "type": "bool",
        "description": "Probe for file transfer capability (Type IDs 120-127)",
        "required": False,
        "default": False,
    },
    "wait-time": {
        "type": "int",
        "description": "Time to wait for interrogation responses (seconds)",
        "required": False,
        "default": 3,
    },
    "t1": {
        "type": "int",
        "description": "APCI message ack timeout in seconds",
        "required": False,
        "default": None,
    },
    "t3": {
        "type": "int",
        "description": "APCI keepalive/test interval in seconds",
        "required": False,
        "default": None,
    },
    "originator": {
        "type": "int",
        "description": "Originator address (0-255) to identify this client in device logs",
        "required": False,
        "default": None,
    },
    "list-files": {
        "type": "bool",
        "description": "List files using c104 browse_directory (Type 122/126)",
        "required": False,
        "default": False,
    },
    "download-file": {
        "type": "int",
        "description": "Download file by IOA using c104 (Type 120-125)",
        "required": False,
        "default": None,
    },
    "file-output": {
        "type": "string",
        "description": "Output path for downloaded file",
        "required": False,
        "default": None,
    },
    "upload-file": {
        "type": "string",
        "description": "Local file path to upload to device (DANGEROUS)",
        "required": False,
        "default": None,
    },
    "upload-ioa": {
        "type": "int",
        "description": "Target IOA for file upload",
        "required": False,
        "default": None,
    },
    "upload-nof": {
        "type": "int",
        "description": "File type for upload: 1=transparent, 2=disturbance",
        "required": False,
        "default": 1,
    },
    "query-log": {
        "type": "int",
        "description": "Query archive log by IOA (Type 127)",
        "required": False,
        "default": None,
    },
    "log-start": {
        "type": "string",
        "description": "Log query start time",
        "required": False,
        "default": None,
    },
    "log-end": {
        "type": "string",
        "description": "Log query end time",
        "required": False,
        "default": None,
    },
    "log-type": {
        "type": "int",
        "description": "Log type: 1=transparent, 2=disturbance, 3=events, 4=analogue",
        "required": False,
        "default": 2,
    },
}
