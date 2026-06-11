#!/usr/bin/env python3
"""
Mock CAN Bus Server for testing OIDA CAN scanner.

Simulates a realistic CAN bus with multiple ECUs using python-can's
udp_multicast interface, which works across containers via UDP multicast
without requiring kernel CAN modules or host networking.

Simulated devices:
  - 2 UDS ECUs (0x7E0/0x7E8 and 0x7E1/0x7E9) with full diagnostic support
  - 1 OBD-II ECU responding on 0x7DF -> 0x7E8
  - 4 CANopen nodes (1-4) with heartbeats, SDO, EMCY, PDO (TPDO/RPDO 1-4)
  - 1 XCP slave on 0x550/0x551
  - 2 CCP stations (0,1) on CRO 0x701 / DTO 0x702
  - Background automotive traffic (engine RPM, speed, temp, etc.)

Usage:
  python can_server.py [--channel 239.0.0.1] [--port 43113]

Dependency: python-can >= 4.0.0
"""

import logging
import os
import random
import struct
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

import can

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("can-mock")

# =============================================================================
# Configuration
# =============================================================================

MULTICAST_CHANNEL = os.environ.get("CAN_CHANNEL", "239.0.0.1")
MULTICAST_PORT = int(os.environ.get("CAN_PORT", "43113"))

MOCK_VIN = "1OIDA2MOCK3TEST45"  # 17-char VIN


def _env_flag(name: str, default: bool = True) -> bool:
    """Parse a boolean environment flag (1/true/yes/on enable)."""
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


# =============================================================================
# UDS Constants
# =============================================================================

UDS_POSITIVE_OFFSET = 0x40
UDS_NEGATIVE_RESPONSE = 0x7F

# NRC codes
NRC_SERVICE_NOT_SUPPORTED = 0x11
NRC_SUBFUNCTION_NOT_SUPPORTED = 0x12
NRC_CONDITIONS_NOT_CORRECT = 0x22
NRC_REQUEST_OUT_OF_RANGE = 0x31
NRC_SECURITY_ACCESS_DENIED = 0x33
NRC_INVALID_KEY = 0x35

# =============================================================================
# UDS ECU Definitions
# =============================================================================

# Two UDS ECUs
UDS_ECUS: Dict[int, int] = {
    0x7E0: 0x7E8,  # ECU #1 (engine)
    0x7E1: 0x7E9,  # ECU #2 (transmission)
}

# OBD-II broadcast -> ECU #1
OBD2_REQUEST_ID = 0x7DF
OBD2_RESPONSE_ID = 0x7E8

# Services supported by each ECU
UDS_SUPPORTED_SERVICES = {
    0x7E0: [
        0x10,
        0x11,
        0x14,
        0x19,
        0x22,
        0x23,
        0x27,
        0x28,
        0x2E,
        0x2F,
        0x31,
        0x34,
        0x36,
        0x37,
        0x3E,
        0x85,
    ],
    0x7E1: [0x10, 0x22, 0x27, 0x31, 0x3E],
}

# DID data per ECU
UDS_DID_DATA: Dict[int, Dict[int, bytes]] = {
    0x7E0: {
        0xF180: b"OIDA-BOOT-1.0.0\x00",
        0xF181: b"OIDA-APP-2.3.1\x00\x00",
        0xF182: b"OIDA-CAL-1.0.0\x00\x00",
        0xF183: b"OIDA-CALFP-A001",
        0xF184: b"OIDA-APP-FP-1234",
        0xF186: b"\x01",
        0xF187: b"OIDA-ECU1-PN001",
        0xF188: b"OIDA-MCU-2.0.0\x00\x00",
        0xF189: b"2025-01-15",
        0xF18A: b"OIDA-SYSID-001\x00\x00",
        0xF18B: b"2025-06-20",
        0xF18C: b"SN-ECU1-00001",
        0xF18E: b"OIDA-1234-5678-ABCD",
        0xF190: MOCK_VIN.encode("ascii"),
        0xF191: b"HW-ECU1-R3\x00\x00\x00\x00\x00",
        0xF193: b"v3.1",
        0xF194: b"OIDA-SW-001\x00\x00\x00\x00\x00",
        0xF195: b"OIDA-SW-FP-V3.1\x00",
        0xF196: b"OIDA-CAL-FP-V1\x00\x00",
        0xF197: b"4-Cyl Turbo\x00\x00\x00\x00\x00",
        0xF198: b"Tester SN 12345\x00",
        0xF199: b"2025-11-01",
        0xF19E: b"OIDA-ASAM-ODX-V1",
    },
    0x7E1: {
        0xF180: b"OIDA-BOOT-1.0.0\x00",
        0xF181: b"OIDA-TCU-1.5.2\x00\x00",
        0xF182: b"OIDA-TCU-CAL-1.0",
        0xF186: b"\x01",
        0xF187: b"OIDA-TCU1-PN002",
        0xF188: b"OIDA-TCU-SW-1.5\x00",
        0xF189: b"2025-02-20",
        0xF18A: b"OIDA-SYSID-002\x00\x00",
        0xF18C: b"SN-TCU1-00002",
        0xF190: MOCK_VIN.encode("ascii"),
        0xF191: b"HW-TCU1-R2\x00\x00\x00\x00\x00",
        0xF195: b"OIDA-TCU-FP-V1.5",
        0xF197: b"6-Speed Auto\x00\x00\x00\x00",
        0xF199: b"2025-03-10",
    },
}

# Supported sessions per ECU
UDS_SESSIONS = {
    0x7E0: [0x01, 0x02, 0x03],  # Default, Programming, Extended
    0x7E1: [0x01, 0x03],  # Default, Extended
}

# Available routine IDs per ECU
UDS_ROUTINES = {
    0x7E0: [
        0x0001,
        0x0002,
        0x0003,
        0x0004,
        0x0005,
        0x0006,
        0x0007,
        0x0008,
        0x0009,
        0x000A,
        0x00FF,
        0x0201,
        0x0203,
        0xFF00,
        0xFF01,
    ],
    0x7E1: [0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0201],
}

# Seed counter for SecurityAccess (generates varying seeds)
_seed_counter = 0

# =============================================================================
# OBD-II Data
# =============================================================================

# Supported PIDs bitmap for Mode 01 PID 00
# Bits set for: PID 01,04,05,0C,0D,0F,10,11,1C,1F,20
OBD2_SUPPORTED_PIDS_01_20 = 0b10111110000111110001100000010000

# OBD-II PID responses (Mode 01)
OBD2_PID_DATA: Dict[int, bytes] = {
    0x04: bytes([0x33]),  # Engine load ~20%
    0x05: bytes([0xA0 - 40]),  # Coolant temp (~80 C, value = C + 40)
    0x0C: bytes([0x0C, 0x80]),  # RPM = 800 (value * 4)
    0x0D: bytes([0x00]),  # Vehicle speed 0 km/h
    0x0F: bytes([0x55 - 40]),  # Intake air temp ~45 C
    0x11: bytes([0x19]),  # Throttle ~10%
    0x1C: bytes([0x06]),  # OBD standard: EOBD
}

# =============================================================================
# CANopen Definitions
# =============================================================================

CANOPEN_HEARTBEAT_BASE = 0x700
CANOPEN_SDO_RX_BASE = 0x600
CANOPEN_SDO_TX_BASE = 0x580
CANOPEN_EMCY_BASE = 0x080
CANOPEN_TPDO1_BASE = 0x180
CANOPEN_TPDO2_BASE = 0x280
CANOPEN_TPDO3_BASE = 0x380
CANOPEN_TPDO4_BASE = 0x480

CANOPEN_NMT_STATE_OPERATIONAL = 0x05

# SDO command bytes
SDO_SCS_INITIATE_UPLOAD = 2  # bits 7..5 of response byte[0]
SDO_SCS_SEGMENT_UPLOAD = 0
SDO_SCS_ABORT = 4

SDO_CMD_UPLOAD_INITIATE = 0x40  # CCS=2 (initiate upload request)
SDO_ABORT_OBJECT_NOT_EXIST = 0x06020000
SDO_ABORT_SUBINDEX_NOT_EXIST = 0x06090011

# CANopen nodes 1-4
CANOPEN_NODES = {
    1: {
        "device_type": 0x00000191,  # Profile 401 (Generic I/O)
        "error_register": 0x00,
        "device_name": "OIDA-IO-Module",
        "hw_version": "v2.0",
        "sw_version": "v1.3.7",
        "vendor_id": 0x0000005A,  # WAGO
        "product_code": 0x00000750,
        "revision": 0x00020003,  # v2.3
        "serial_number": 0x00001001,
    },
    2: {
        "device_type": 0x00000192,  # Profile 402 (Drives)
        "error_register": 0x00,
        "device_name": "OIDA-Drive-1",
        "hw_version": "v3.1",
        "sw_version": "v2.1.0",
        "vendor_id": 0x00000002,  # Beckhoff
        "product_code": 0x00000192,
        "revision": 0x00030001,  # v3.1
        "serial_number": 0x00002002,
    },
    3: {
        "device_type": 0x00000196,  # Profile 406 (Encoders)
        "error_register": 0x00,
        "device_name": "OIDA-Encoder",
        "hw_version": "v1.0",
        "sw_version": "v1.0.5",
        "vendor_id": 0x00000079,  # IFM
        "product_code": 0x00000406,
        "revision": 0x00010005,  # v1.5
        "serial_number": 0x00003003,
    },
    4: {
        "device_type": 0x00000135,  # Profile 309 (Modbus gateway)
        "error_register": 0x00,
        "device_name": "OIDA-Modbus-GW",
        "hw_version": "v1.2",
        "sw_version": "v3.0.1",
        "vendor_id": 0x00000022,  # HMS (Anybus)
        "product_code": 0x00000309,
        "revision": 0x00030001,  # v3.1
        "serial_number": 0x00004004,
    },
}

# PDO configuration per node
# Structure: {node_id: {"tpdo": {pdo_num: {comm_params}, ...}, "rpdo": {...}}}
# comm_params: {"cob_id": int, "trans_type": int}
# Each PDO also has mapping params: {"num_mappings": int, "mappings": [uint32, ...]}


def _build_pdo_config() -> Dict[int, dict]:
    """Build PDO configuration for all 4 nodes."""
    config: Dict[int, dict] = {}
    for node_id in range(1, 5):
        node_cfg: dict = {"tpdo": {}, "rpdo": {}}

        # TPDO COB-ID bases: TPDO1=0x180, TPDO2=0x280, TPDO3=0x380, TPDO4=0x480
        tpdo_bases = [0x180, 0x280, 0x380, 0x480]
        # RPDO COB-ID bases: RPDO1=0x200, RPDO2=0x300, RPDO3=0x400, RPDO4=0x500
        rpdo_bases = [0x200, 0x300, 0x400, 0x500]

        # TPDO1-4
        for pdo_num in range(4):
            cob_id = tpdo_bases[pdo_num] + node_id
            # Realistic mapping entries: index<<16 | subindex<<8 | bits
            if pdo_num == 0:
                mappings = [0x60000108, 0x60000208]  # 0x6000:01 8bit, 0x6000:02 8bit
            elif pdo_num == 1:
                mappings = [0x60000110, 0x60000210]  # 0x6000:01 16bit, 0x6000:02 16bit
            elif pdo_num == 2:
                mappings = [0x60010120]  # 0x6001:01 32bit
            else:
                mappings = [0x60020108, 0x60020208, 0x60020308, 0x60020408]

            node_cfg["tpdo"][pdo_num + 1] = {
                "cob_id": cob_id,
                "trans_type": 0xFF,
                "num_mappings": len(mappings),
                "mappings": mappings,
            }

        # RPDO1-4
        for pdo_num in range(4):
            cob_id = rpdo_bases[pdo_num] + node_id
            if pdo_num == 0:
                mappings = [0x62000108, 0x62000208]
            elif pdo_num == 1:
                mappings = [0x62000110, 0x62000210]
            elif pdo_num == 2:
                mappings = [0x62010120]
            else:
                mappings = [0x62020108, 0x62020208, 0x62020308, 0x62020408]

            node_cfg["rpdo"][pdo_num + 1] = {
                "cob_id": cob_id,
                "trans_type": 0xFF,
                "num_mappings": len(mappings),
                "mappings": mappings,
            }

        config[node_id] = node_cfg
    return config


CANOPEN_PDO_CONFIG = _build_pdo_config()

# CiA 309 gateway OD entries for node 4
CIA309_OD_DATA: Dict[int, bytes] = {
    0x5100: struct.pack("<I", 0x00010003),  # Gateway config: FC03, 1 mapping
    0x5101: struct.pack("<I", 0x00000000),  # Mapping entry 0
    0x5102: struct.pack("<I", 0x00640001),  # Mapping: reg 100, 1 register
    0x5103: struct.pack("<I", 0x00020004),  # FC04 input registers, 2 mappings
    0x5104: struct.pack("<I", 0x00C80002),  # Mapping: reg 200, 2 registers
    0x5105: struct.pack("<I", 0x01000004),  # Mapping: reg 256, 4 registers
    0x5106: struct.pack("<I", 0x00010006),  # FC06 write single, 1 mapping
    0x5107: struct.pack("<I", 0x01F40001),  # Mapping: reg 500, 1 register
    0x5108: struct.pack("<I", 0x00030010),  # FC16 write multiple, 3 mappings
    0x5109: struct.pack("<I", 0x03E80004),  # Mapping: reg 1000, 4 registers
    0x510A: struct.pack("<I", 0x04000002),  # Mapping: reg 1024, 2 registers
    0x510B: struct.pack("<I", 0x05000008),  # Mapping: reg 1280, 8 registers
    0x510C: struct.pack("<I", 0x00000000),  # Reserved
    0x510D: struct.pack("<I", 0x00000000),  # Reserved
    0x510E: struct.pack("<I", 0x00000000),  # Reserved
    0x510F: struct.pack("<I", 0x00000000),  # Reserved
    0x6000: struct.pack("<H", 0x0000),  # Digital inputs
    0x6001: struct.pack("<H", 0x00FF),  # Digital outputs
    0x6002: struct.pack("<H", 0x1234),  # Analog input 1
    0x6003: struct.pack("<H", 0x5678),  # Analog input 2
    0x6004: struct.pack("<H", 0x0000),  # Analog output 1
    0x6005: struct.pack("<H", 0x0000),  # Analog output 2
    0x6006: struct.pack("<I", 0x00000000),  # Counter input 1
    0x6007: struct.pack("<I", 0x00000000),  # Counter input 2
    0x6008: struct.pack("<H", 0xABCD),  # Process data word 1
    0x6009: struct.pack("<H", 0xEF01),  # Process data word 2
    0x600A: struct.pack("<I", 0xDEADBEEF),  # Process data long 1
    0x600B: struct.pack("<I", 0xCAFEBABE),  # Process data long 2
    0x600C: struct.pack("<H", 0x0042),  # Status register 1
    0x600D: struct.pack("<H", 0x0000),  # Status register 2
    0x600E: struct.pack("<H", 0x0001),  # Config register 1
    0x600F: struct.pack("<H", 0x0000),  # Config register 2
}

# =============================================================================
# XCP Constants
# =============================================================================

XCP_REQ_ID = 0x550
XCP_RESP_ID = 0x551
XCP_RES_PID = 0xFF
XCP_ERR_PID = 0xFE

XCP_CONNECT_CMD = 0xFF
XCP_DISCONNECT_CMD = 0xFE
XCP_GET_STATUS_CMD = 0xFD
XCP_GET_COMM_MODE_INFO_CMD = 0xFB
XCP_GET_ID_CMD = 0xFA
XCP_SHORT_UPLOAD_CMD = 0xF4

# XCP slave state
XCP_CONNECTED = False
XCP_RESOURCE_PROTECTION = 0x15  # CAL/PAG + DAQ + PGM
XCP_MAX_CTO = 8
XCP_MAX_DTO = 8
XCP_VERSION_MAJOR = 1
XCP_VERSION_MINOR = 0

# =============================================================================
# CCP Constants (CAN Calibration Protocol v2.1)
# =============================================================================

CCP_CRO_ID = 0x701  # Master -> Slave (Command Receive Object)
CCP_DTO_ID = 0x702  # Slave -> Master (Data Transmission Object)
CCP_DTO_COMMAND_RETURN = 0xFF

CCP_CONNECT_CMD = 0x01
CCP_DISCONNECT_CMD = 0x07
CCP_GET_S_STATUS_CMD = 0x0D
CCP_EXCHANGE_ID_CMD = 0x17
CCP_GET_CCP_VERSION_CMD = 0x1B

CCP_VERSION_MAJOR = 2
CCP_VERSION_MINOR = 1

# Simulated CCP stations
CCP_STATIONS: Dict[int, dict] = {
    0: {
        "id": "OIDA-CCP-ECU0",
        "data_type": 0x01,  # Qualitative data
        "availability": 0x03,  # CAL + DAQ available
        "protection": 0x00,  # No protection
    },
    1: {
        "id": "OIDA-CCP-ECU1",
        "data_type": 0x02,
        "availability": 0x01,  # CAL available
        "protection": 0x01,  # Seed/key required
    },
}

# Simulated memory (address -> bytes)
XCP_MEMORY: Dict[int, bytes] = {
    0x00000000: bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]),
    0x00001000: bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
    0x08000000: bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
}

# =============================================================================
# Background Traffic Configuration
# =============================================================================


def _traffic_rate_scale() -> float:
    """Return a multiplier applied to periodic-sender INTERVALS (test knob).

    Default is 1.0 (unchanged -- full ~3700 fps flood for manual use). Tests
    set an opt-in env knob to throttle the high-frequency background flood so
    the scanner's matching responses are not buried under a datagram storm
    (which both slows probes to their full timeouts and pushes single-frame
    answers out of the receive window):

      * ``CAN_QUIET=1``     -> scale 25.0 (e.g. a 10ms sender becomes 250ms)
      * ``CAN_TRAFFIC_RATE=N`` -> scale = 1/N relative to baseline rate, where
        ``N`` is a frames-rate FRACTION (0 < N <= 1). ``CAN_TRAFFIC_RATE=0.04``
        is equivalent to ``CAN_QUIET=1``.

    Crucially this only stretches the *noise* senders' periods. The CANopen
    heartbeats, J1939 broadcasts / Address Claimed, TPDOs and every protocol
    responder stay fully active, so the J1939 / sniff / classification tests
    still observe real traffic -- the bus is throttled, not silenced.
    """
    if _env_flag("CAN_QUIET", default=False):
        return 25.0
    rate = os.environ.get("CAN_TRAFFIC_RATE")
    if rate is not None:
        try:
            frac = float(rate)
        except ValueError:
            return 1.0
        if 0.0 < frac < 1.0:
            return 1.0 / frac
    return 1.0


TRAFFIC_RATE_SCALE = _traffic_rate_scale()

# Standard automotive CAN IDs and their periodic data
BACKGROUND_TRAFFIC: List[Tuple[int, float, int]] = [
    # (arb_id, interval_seconds, data_length)
    (0x100, 0.010, 8),  # Engine RPM + torque (10ms cycle)
    (0x120, 0.020, 8),  # Wheel speeds (20ms)
    (0x130, 0.020, 6),  # Brake pressure
    (0x140, 0.050, 4),  # Steering angle
    (0x200, 0.100, 8),  # Body controller (lights, wipers)
    (0x300, 0.100, 8),  # Climate control
    (0x400, 0.500, 8),  # Battery / power management
    (0x3E0, 1.000, 4),  # Slow diagnostics (1s cycle)
]

# Extended frame for J1939-like traffic
EXTENDED_TRAFFIC: List[Tuple[int, float, int]] = [
    (0x18FEF100, 2.000, 8),  # J1939 PGN 65265 (Cruise Control / Vehicle Speed)
    (0x18FEDF00, 5.000, 8),  # J1939 PGN 65247 (Electronic Engine Controller 3)
]

# =============================================================================
# J1939 (SAE J1939) Definitions
# =============================================================================
#
# J1939 rides on 29-bit extended CAN identifiers. The arbitration ID is
# composed (consistent with the scanner's constants.py masks) as:
#
#   arb_id = (priority << 26) | (PGN << 8) | source_address
#
# where PGN occupies bits 8..25 (J1939_PGN_MASK = 0x03FFFF00) and the
# source address occupies bits 0..7 (J1939_SOURCE_MASK = 0x000000FF).
# For PDU1 (destination-specific) PGNs the low byte of the PGN carries the
# destination address; for PDU2 (broadcast) PGNs the whole PGN is fixed.

J1939_PRIORITY_MASK = 0x1C000000
J1939_PGN_MASK = 0x03FFFF00
J1939_SOURCE_MASK = 0x000000FF

J1939_GLOBAL_ADDRESS = 0xFF  # Broadcast destination address

# Source addresses for the simulated ECUs (distinct from UDS/OBD/CANopen IDs,
# which live on 11-bit standard frames, so there is no real collision; these
# are the 8-bit J1939 node addresses).
J1939_SA_ENGINE = 0x00  # Engine controller #1
J1939_SA_TRANSMISSION = 0x03  # Transmission #1

# Supported broadcast PGNs: (PGN, interval_seconds, source_address)
# EEC1  = 61444 (0xF004) Electronic Engine Controller 1 (engine speed)
# ET1   = 65262 (0xFEEE) Engine Temperature 1 (coolant temp)
# CCVS1 = 65265 (0xFEF1) Cruise Control / Vehicle Speed 1
J1939_PGN_EEC1 = 0xF004
J1939_PGN_ET1 = 0xFEEE
J1939_PGN_CCVS1 = 0xFEF1
J1939_PGN_VEHICLE_ID = 0xFEEC  # 65260 (VI) - VIN, multi-packet via TP
J1939_PGN_REQUEST = 0xEA00  # 59904 Request PGN (PDU1)
J1939_PGN_ADDRESS_CLAIMED = 0xEE00  # 60928 Address Claimed (PDU1)
J1939_PGN_TP_CM = 0xEC00  # 60416 Transport Protocol - Connection Mgmt
J1939_PGN_TP_DT = 0xEB00  # 60160 Transport Protocol - Data Transfer

J1939_TP_CM_BAM = 0x20  # TP.CM control byte for BAM (broadcast)

# Periodic broadcast schedule: (PGN, interval, source_address)
J1939_BROADCAST_PGNS: List[Tuple[int, float, int]] = [
    (J1939_PGN_EEC1, 0.100, J1939_SA_ENGINE),  # 100ms
    (J1939_PGN_ET1, 1.000, J1939_SA_ENGINE),  # 1s
    (J1939_PGN_CCVS1, 0.100, J1939_SA_TRANSMISSION),  # 100ms
]

# NAME fields (64-bit) for Address Claimed, per ECU source address.
# Encoded little-endian as 8 bytes. Built from a simplified NAME (the exact
# bit layout is not what the scanner inspects; the scanner only needs to see
# the Address Claimed PGN with a source address).
J1939_NAMES: Dict[int, int] = {
    J1939_SA_ENGINE: 0x80_00_00_00_00_00_00_00,  # arbitrary-address-capable engine
    J1939_SA_TRANSMISSION: 0x00_00_00_00_00_00_03_00,
}

MOCK_VIN_J1939 = MOCK_VIN + "*"  # J1939 VIN field is "*"-delimited ASCII


# =============================================================================
# CAN Bus Singleton
# =============================================================================


class CANBus:
    """Shared CAN bus connection for all mock components."""

    def __init__(self, channel: str, port: int):
        self.channel = channel
        self.port = port
        self.bus: Optional[can.Bus] = None
        self._lock = threading.Lock()

    def connect(self) -> can.Bus:
        """Create and return the CAN bus instance."""
        self.bus = can.Bus(
            interface="udp_multicast",
            channel=self.channel,
            port=self.port,
        )
        log.info(f"CAN bus connected: udp_multicast://{self.channel}:{self.port}")
        return self.bus

    def send(self, arb_id: int, data: bytes, is_extended: bool = False) -> None:
        """Thread-safe send."""
        if self.bus is None:
            return
        msg = can.Message(
            arbitration_id=arb_id,
            data=data,
            is_extended_id=is_extended,
        )
        with self._lock:
            try:
                self.bus.send(msg)
            except Exception as e:
                log.debug(f"Send failed 0x{arb_id:03X}: {e}")

    def recv(self, timeout: float = 0.1) -> Optional[can.Message]:
        """Receive a message (non-thread-safe, use in dedicated thread)."""
        if self.bus is None:
            return None
        return self.bus.recv(timeout=timeout)

    def shutdown(self) -> None:
        """Shut down the bus."""
        if self.bus:
            self.bus.shutdown()
            self.bus = None


# =============================================================================
# UDS Responder
# =============================================================================


class UDSResponder:
    """Handles UDS (ISO 14229) and OBD-II requests."""

    def __init__(self, bus: CANBus, fc_event: Optional[threading.Event] = None):
        self.bus = bus
        # Shared with the dispatcher: set when the tester's Flow Control (0x30)
        # arrives. The off-thread multi-frame senders wait on it before
        # streaming Consecutive Frames (real ISO-TP behaviour).
        self._fc_event = fc_event

    def _stream_consecutive_frames(self, resp_id: int, payload: bytes, offset: int) -> None:
        """Wait for the tester's Flow Control, then stream Consecutive Frames.

        Runs in a short-lived daemon thread so the dispatcher's single reader
        loop stays free to receive (and signal) the incoming FC frame.
        """
        if self._fc_event is not None:
            # Wait up to 0.5s for the tester's Flow Control before proceeding.
            self._fc_event.wait(timeout=0.5)

        seq = 1
        while offset < len(payload):
            cf_pci = 0x20 | (seq & 0x0F)
            chunk = payload[offset : offset + 7]
            cf_data = bytes([cf_pci]) + chunk + bytes(max(0, 7 - len(chunk)))
            self.bus.send(resp_id, cf_data[:8])
            offset += 7
            seq = (seq + 1) & 0x0F
            time.sleep(0.001)

    def handle(self, msg: can.Message) -> None:
        """Process an incoming CAN message for UDS/OBD-II."""
        arb_id = msg.arbitration_id
        data = bytes(msg.data)

        # OBD-II broadcast
        if arb_id == OBD2_REQUEST_ID:
            self._handle_obd2(data)
            return

        # UDS request
        if arb_id in UDS_ECUS:
            resp_id = UDS_ECUS[arb_id]
            self._handle_uds(arb_id, resp_id, data)

    def _handle_uds(self, req_id: int, resp_id: int, data: bytes) -> None:
        """Process a UDS request."""
        if len(data) < 2:
            return

        pci_len = data[0] & 0x0F
        service_id = data[1]

        supported = UDS_SUPPORTED_SERVICES.get(req_id, [])

        if service_id == 0x3E:
            # TesterPresent
            sub = data[2] if len(data) > 2 else 0x00
            if sub & 0x80:
                # Suppress positive response
                return
            self._send_positive(resp_id, 0x3E, bytes([sub]))

        elif service_id == 0x10:
            # DiagnosticSessionControl
            self._handle_session_control(req_id, resp_id, data)

        elif service_id == 0x11:
            # ECUReset
            if service_id not in supported:
                self._send_negative(resp_id, service_id, NRC_SERVICE_NOT_SUPPORTED)
                return
            reset_type = data[2] if len(data) > 2 else 0x01
            self._send_positive(resp_id, 0x11, bytes([reset_type]))

        elif service_id == 0x22:
            # ReadDataByIdentifier
            self._handle_read_did(req_id, resp_id, data)

        elif service_id == 0x27:
            # SecurityAccess
            self._handle_security_access(req_id, resp_id, data)

        elif service_id == 0x23:
            # ReadMemoryByAddress - return dummy bytes
            if service_id not in supported:
                self._send_negative(resp_id, service_id, NRC_SERVICE_NOT_SUPPORTED)
                return
            self._send_positive(resp_id, 0x23, bytes([0xDE, 0xAD, 0xBE, 0xEF]))

        elif service_id == 0x28:
            # CommunicationControl - return positive ack
            if service_id not in supported:
                self._send_negative(resp_id, service_id, NRC_SERVICE_NOT_SUPPORTED)
                return
            sub = data[2] if len(data) > 2 else 0x00
            self._send_positive(resp_id, 0x28, bytes([sub]))

        elif service_id == 0x2F:
            # InputOutputControlByIdentifier - return positive ack
            if service_id not in supported:
                self._send_negative(resp_id, service_id, NRC_SERVICE_NOT_SUPPORTED)
                return
            did_bytes = data[2:4] if len(data) >= 4 else b"\x00\x00"
            self._send_positive(resp_id, 0x2F, did_bytes)

        elif service_id == 0x31:
            # RoutineControl
            self._handle_routine_control(req_id, resp_id, data)

        elif service_id == 0x34:
            # RequestDownload - return positive ack with format
            if service_id not in supported:
                self._send_negative(resp_id, service_id, NRC_SERVICE_NOT_SUPPORTED)
                return
            # Response: lengthFormatIdentifier=0x20 (2 bytes memorySize), maxBlockLength
            self._send_positive(resp_id, 0x34, bytes([0x20, 0x00, 0xFF]))

        elif service_id == 0x36:
            # TransferData - return positive ack
            if service_id not in supported:
                self._send_negative(resp_id, service_id, NRC_SERVICE_NOT_SUPPORTED)
                return
            block_seq = data[2] if len(data) > 2 else 0x01
            self._send_positive(resp_id, 0x36, bytes([block_seq]))

        elif service_id == 0x37:
            # RequestTransferExit - return positive ack
            if service_id not in supported:
                self._send_negative(resp_id, service_id, NRC_SERVICE_NOT_SUPPORTED)
                return
            self._send_positive(resp_id, 0x37, b"")

        elif service_id == 0x85:
            # ControlDTCSetting - return positive ack
            if service_id not in supported:
                self._send_negative(resp_id, service_id, NRC_SERVICE_NOT_SUPPORTED)
                return
            sub = data[2] if len(data) > 2 else 0x01
            self._send_positive(resp_id, 0x85, bytes([sub]))

        elif service_id in supported:
            # Supported but we just return a generic positive response
            self._send_positive(resp_id, service_id, b"")

        else:
            self._send_negative(resp_id, service_id, NRC_SERVICE_NOT_SUPPORTED)

    def _handle_session_control(self, req_id: int, resp_id: int, data: bytes) -> None:
        """Handle DiagnosticSessionControl (0x10)."""
        if len(data) < 3:
            self._send_negative(resp_id, 0x10, NRC_SUBFUNCTION_NOT_SUPPORTED)
            return

        session = data[2]
        sessions = UDS_SESSIONS.get(req_id, [0x01])

        if session in sessions:
            # P2 server time = 50ms, P2* = 5000ms
            self._send_positive(resp_id, 0x10, bytes([session, 0x00, 0x32, 0x01, 0xF4]))
        else:
            self._send_negative(resp_id, 0x10, NRC_SUBFUNCTION_NOT_SUPPORTED)

    def _handle_read_did(self, req_id: int, resp_id: int, data: bytes) -> None:
        """Handle ReadDataByIdentifier (0x22)."""
        if len(data) < 4:
            self._send_negative(resp_id, 0x22, NRC_REQUEST_OUT_OF_RANGE)
            return

        did = (data[2] << 8) | data[3]
        did_data = UDS_DID_DATA.get(req_id, {}).get(did)

        if did_data is None:
            self._send_negative(resp_id, 0x22, NRC_REQUEST_OUT_OF_RANGE)
            return

        # Build response: [PCI, 0x62, DID_hi, DID_lo, data...]
        resp_payload = bytes([0x22 + UDS_POSITIVE_OFFSET, (did >> 8) & 0xFF, did & 0xFF]) + did_data

        # If it fits in a single frame (7 bytes of payload max)
        if len(resp_payload) <= 7:
            pci = len(resp_payload)
            frame = bytes([pci]) + resp_payload + bytes(7 - len(resp_payload))
            self.bus.send(resp_id, frame[:8])
        else:
            # ISO-TP multi-frame response: send the First Frame, then stream
            # the Consecutive Frames off-thread only AFTER the tester's Flow
            # Control (real ECU behaviour). The dispatcher's single reader sets
            # _fc_event when it sees the 0x30 frame.
            total_len = len(resp_payload)
            # First Frame: [0x1L_hi, 0xLL_lo, data...]
            ff_pci_hi = 0x10 | ((total_len >> 8) & 0x0F)
            ff_pci_lo = total_len & 0xFF
            ff_data = bytes([ff_pci_hi, ff_pci_lo]) + resp_payload[:6]
            if self._fc_event is not None:
                self._fc_event.clear()
            self.bus.send(resp_id, ff_data[:8])

            threading.Thread(
                target=self._stream_consecutive_frames,
                args=(resp_id, resp_payload, 6),
                daemon=True,
            ).start()

    def _handle_security_access(self, req_id: int, resp_id: int, data: bytes) -> None:
        """Handle SecurityAccess (0x27)."""
        if len(data) < 3:
            self._send_negative(resp_id, 0x27, NRC_SUBFUNCTION_NOT_SUPPORTED)
            return

        sub_func = data[2]

        if sub_func % 2 == 1:
            # Odd sub-function = requestSeed
            global _seed_counter
            _seed_counter += 1
            # Generate a pseudo-random seed (varies each time)
            seed = struct.pack(">I", (_seed_counter * 0x1234ABCD + 0x5678) & 0xFFFFFFFF)
            # Response: [PCI, 0x67, sub, seed(4 bytes)]
            resp = bytes([0x06, 0x27 + UDS_POSITIVE_OFFSET, sub_func]) + seed
            self.bus.send(resp_id, resp + bytes(max(0, 8 - len(resp))))
        elif sub_func % 2 == 0:
            # Even sub-function = sendKey
            # Always reject (this is a mock)
            self._send_negative(resp_id, 0x27, NRC_INVALID_KEY)
        else:
            self._send_negative(resp_id, 0x27, NRC_SUBFUNCTION_NOT_SUPPORTED)

    def _handle_routine_control(self, req_id: int, resp_id: int, data: bytes) -> None:
        """Handle RoutineControl (0x31)."""
        if len(data) < 5:
            self._send_negative(resp_id, 0x31, NRC_REQUEST_OUT_OF_RANGE)
            return

        sub_func = data[2]
        routine_id = (data[3] << 8) | data[4]

        routines = UDS_ROUTINES.get(req_id, [])

        if routine_id in routines:
            # Positive response
            resp = bytes(
                [
                    0x04,
                    0x31 + UDS_POSITIVE_OFFSET,
                    sub_func,
                    (routine_id >> 8) & 0xFF,
                    routine_id & 0xFF,
                    0x00,
                    0x00,
                    0x00,
                ]
            )
            self.bus.send(resp_id, resp)
        else:
            self._send_negative(resp_id, 0x31, NRC_REQUEST_OUT_OF_RANGE)

    def _handle_obd2(self, data: bytes) -> None:
        """Process OBD-II request on 0x7DF."""
        if len(data) < 3:
            return

        pci_len = data[0] & 0x0F
        mode = data[1]
        pid = data[2]

        if mode == 0x01:
            # Mode 01: Current Data
            if pid == 0x00:
                # Supported PIDs [01-20]
                bitmap = OBD2_SUPPORTED_PIDS_01_20
                resp = bytes(
                    [
                        0x06,
                        0x41,
                        0x00,
                        (bitmap >> 24) & 0xFF,
                        (bitmap >> 16) & 0xFF,
                        (bitmap >> 8) & 0xFF,
                        bitmap & 0xFF,
                        0x00,
                    ]
                )
                self.bus.send(OBD2_RESPONSE_ID, resp)
            elif pid in OBD2_PID_DATA:
                pid_data = OBD2_PID_DATA[pid]
                resp_len = 2 + len(pid_data)
                resp = bytes([resp_len, 0x41, pid]) + pid_data
                resp += bytes(max(0, 8 - len(resp)))
                self.bus.send(OBD2_RESPONSE_ID, resp[:8])

        elif mode == 0x03:
            # Mode 03: Show stored Diagnostic Trouble Codes.
            # Response: [count_byte, 0x43, num_dtcs, DTC1_hi, DTC1_lo, DTC2_hi, DTC2_lo, ...]
            # Each DTC is 2 bytes. We report two DTCs: P0301 and C0035.
            #   P0301 -> first nibble 00b (P) | 0x0301 = 0x0301
            #   C0035 -> first nibble 01b (C) shifted into bit 14-15 -> 0x4035
            dtcs = [0x0301, 0x4035]
            payload = bytes([0x43, len(dtcs)])
            for dtc in dtcs:
                payload += bytes([(dtc >> 8) & 0xFF, dtc & 0xFF])
            resp = bytes([len(payload)]) + payload
            resp += bytes(max(0, 8 - len(resp)))
            self.bus.send(OBD2_RESPONSE_ID, resp[:8])

        elif mode == 0x09:
            # Mode 09: Vehicle Information
            if pid == 0x00:
                # Mode 09 supported PIDs [01-20]: advertise PID 02 (VIN)
                bitmap = 0b01000000000000000000000000000000  # bit for PID 0x02
                resp = bytes(
                    [
                        0x06,
                        0x49,
                        0x00,
                        (bitmap >> 24) & 0xFF,
                        (bitmap >> 16) & 0xFF,
                        (bitmap >> 8) & 0xFF,
                        bitmap & 0xFF,
                        0x00,
                    ]
                )
                self.bus.send(OBD2_RESPONSE_ID, resp)
            elif pid == 0x02:
                # VIN via ISO-TP multi-frame
                vin_bytes = MOCK_VIN.encode("ascii")
                # First byte is number of data items (1 for VIN)
                payload = bytes([0x01]) + vin_bytes
                total_len = len(payload) + 2  # +2 for service + PID bytes
                full_resp = bytes([0x49, pid]) + payload

                # First Frame, then off-thread Consecutive Frames after the
                # tester's Flow Control (see _stream_consecutive_frames).
                ff_hi = 0x10 | ((total_len >> 8) & 0x0F)
                ff_lo = total_len & 0xFF
                ff = bytes([ff_hi, ff_lo]) + full_resp[:6]
                if self._fc_event is not None:
                    self._fc_event.clear()
                self.bus.send(OBD2_RESPONSE_ID, ff[:8])

                threading.Thread(
                    target=self._stream_consecutive_frames,
                    args=(OBD2_RESPONSE_ID, full_resp, 6),
                    daemon=True,
                ).start()

    def _send_positive(self, resp_id: int, service_id: int, extra: bytes) -> None:
        """Send a UDS positive response."""
        resp_byte = service_id + UDS_POSITIVE_OFFSET
        payload = bytes([resp_byte]) + extra
        pci = len(payload)
        frame = bytes([pci]) + payload + bytes(max(0, 7 - len(payload)))
        self.bus.send(resp_id, frame[:8])

    def _send_negative(self, resp_id: int, service_id: int, nrc: int) -> None:
        """Send a UDS negative response."""
        frame = bytes([0x03, UDS_NEGATIVE_RESPONSE, service_id, nrc, 0x00, 0x00, 0x00, 0x00])
        self.bus.send(resp_id, frame)


# =============================================================================
# CANopen Responder
# =============================================================================


class CANopenResponder:
    """Handles CANopen SDO requests and generates heartbeats/EMCY/PDO."""

    def __init__(self, bus: CANBus):
        self.bus = bus

    def handle_sdo(self, msg: can.Message) -> None:
        """Process SDO request on 0x600+node_id -> 0x580+node_id."""
        arb_id = msg.arbitration_id
        data = bytes(msg.data)

        if len(data) < 4:
            return

        # Extract node_id
        node_id = arb_id - CANOPEN_SDO_RX_BASE
        if node_id < 1 or node_id > 127:
            return
        if node_id not in CANOPEN_NODES:
            return

        resp_id = CANOPEN_SDO_TX_BASE + node_id
        cmd = data[0]
        index = data[1] | (data[2] << 8)
        subindex = data[3]
        ccs = (cmd >> 5) & 0x07

        if ccs == 2:
            # Initiate upload (read) request
            self._handle_sdo_read(node_id, resp_id, index, subindex)
        elif ccs == 3:
            # Segment upload request - we handle this for segmented transfers
            self._handle_sdo_segment_upload(node_id, resp_id, cmd)
        else:
            # Unsupported - abort
            self._send_sdo_abort(resp_id, index, subindex, 0x05040001)

    def _handle_sdo_read(self, node_id: int, resp_id: int, index: int, subindex: int) -> None:
        """Handle SDO read (upload initiate)."""
        node_data = CANOPEN_NODES[node_id]
        value = self._get_od_value(node_id, node_data, index, subindex)

        if value is None:
            # Check CiA 309 gateway data for node 4
            if node_id == 4 and index in CIA309_OD_DATA and subindex == 0:
                value = CIA309_OD_DATA[index]
            else:
                self._send_sdo_abort(resp_id, index, subindex, SDO_ABORT_OBJECT_NOT_EXIST)
                return

        if len(value) <= 4:
            # Expedited transfer
            n = 4 - len(value)  # unused bytes
            cmd = (SDO_SCS_INITIATE_UPLOAD << 5) | (n << 2) | 0x02 | 0x01
            padded = value + bytes(4 - len(value))
            frame = bytes([cmd, index & 0xFF, (index >> 8) & 0xFF, subindex]) + padded
            self.bus.send(resp_id, frame[:8])
        else:
            # Segmented transfer - store pending data
            if not hasattr(self, "_pending_segments"):
                self._pending_segments: Dict[int, Tuple[bytes, int]] = {}
            self._pending_segments[node_id] = (value, 0)  # (data, toggle)

            # Initiate upload response with size indicated
            total_len = len(value)
            cmd = (SDO_SCS_INITIATE_UPLOAD << 5) | 0x01  # size indicated, not expedited
            size_bytes = struct.pack("<I", total_len)
            frame = bytes([cmd, index & 0xFF, (index >> 8) & 0xFF, subindex]) + size_bytes
            self.bus.send(resp_id, frame[:8])

    def _handle_sdo_segment_upload(self, node_id: int, resp_id: int, cmd: int) -> None:
        """Handle SDO segment upload request."""
        if not hasattr(self, "_pending_segments"):
            self._pending_segments = {}

        if node_id not in self._pending_segments:
            self._send_sdo_abort(resp_id, 0, 0, 0x05040001)
            return

        data_buf, expected_toggle = self._pending_segments[node_id]
        req_toggle = (cmd >> 4) & 0x01

        # Send next segment
        offset = 0
        # Calculate how many bytes we've already sent
        # We need to track the offset properly
        if not hasattr(self, "_segment_offsets"):
            self._segment_offsets: Dict[int, int] = {}
        offset = self._segment_offsets.get(node_id, 0)

        remaining = data_buf[offset:]
        if len(remaining) <= 7:
            # Last segment
            seg_data = remaining + bytes(7 - len(remaining))
            n = 7 - len(remaining)
            resp_cmd = (SDO_SCS_SEGMENT_UPLOAD << 5) | (req_toggle << 4) | (n << 1) | 0x01
            frame = bytes([resp_cmd]) + seg_data
            self.bus.send(resp_id, frame[:8])
            # Clean up
            del self._pending_segments[node_id]
            if node_id in self._segment_offsets:
                del self._segment_offsets[node_id]
        else:
            seg_data = remaining[:7]
            resp_cmd = (SDO_SCS_SEGMENT_UPLOAD << 5) | (req_toggle << 4)
            frame = bytes([resp_cmd]) + seg_data
            self.bus.send(resp_id, frame[:8])
            self._segment_offsets[node_id] = offset + 7

    def _get_od_value(
        self, node_id: int, node_data: dict, index: int, subindex: int
    ) -> Optional[bytes]:
        """Look up Object Dictionary value for a node."""
        # --- Mandatory objects ---
        if index == 0x1000 and subindex == 0:
            return struct.pack("<I", node_data["device_type"])
        elif index == 0x1001 and subindex == 0:
            return bytes([node_data["error_register"]])

        # --- Standard communication profile objects ---
        elif index == 0x1003:
            # Pre-defined error field
            if subindex == 0:
                return bytes([1])  # 1 error logged
            elif subindex == 1:
                return struct.pack("<I", 0x00001000)  # Last error: generic

        elif index == 0x1005 and subindex == 0:
            # SYNC COB-ID
            return struct.pack("<I", 0x00000080)

        elif index == 0x1006 and subindex == 0:
            # Communication cycle period (10ms = 10000 us)
            return struct.pack("<I", 10000)

        elif index == 0x1007 and subindex == 0:
            # Synchronous window length (5ms = 5000 us)
            return struct.pack("<I", 5000)

        elif index == 0x1008 and subindex == 0:
            return node_data["device_name"].encode("ascii")
        elif index == 0x1009 and subindex == 0:
            return node_data["hw_version"].encode("ascii")
        elif index == 0x100A and subindex == 0:
            return node_data["sw_version"].encode("ascii")

        elif index == 0x1010:
            # Store parameters
            if subindex == 0:
                return bytes([1])  # 1 sub-index
            elif subindex == 1:
                return struct.pack("<I", 0x00000001)  # Save all supported

        elif index == 0x1011:
            # Restore default parameters
            if subindex == 0:
                return bytes([1])
            elif subindex == 1:
                return struct.pack("<I", 0x00000001)  # Restore all supported

        elif index == 0x1014 and subindex == 0:
            # Emergency COB-ID
            return struct.pack("<I", 0x80 + node_id)

        elif index == 0x1015 and subindex == 0:
            # Inhibit time EMCY (100 * 100us = 10ms)
            return struct.pack("<H", 100)

        elif index == 0x1016:
            # Consumer heartbeat time
            if subindex == 0:
                return bytes([1])  # 1 consumer entry
            elif subindex == 1:
                # Format: node_id_of_producer<<16 | timeout_ms
                # Monitor node 1 with 2000ms timeout (or next node)
                monitored = 1 if node_id != 1 else 2
                return struct.pack("<I", (monitored << 16) | 2000)

        elif index == 0x1017 and subindex == 0:
            # Producer heartbeat time (1000ms)
            return struct.pack("<H", 1000)

        elif index == 0x1018:
            # Identity object
            if subindex == 0:
                return bytes([4])  # Number of sub-indices
            elif subindex == 1:
                return struct.pack("<I", node_data["vendor_id"])
            elif subindex == 2:
                return struct.pack("<I", node_data["product_code"])
            elif subindex == 3:
                return struct.pack("<I", node_data["revision"])
            elif subindex == 4:
                return struct.pack("<I", node_data["serial_number"])

        elif index == 0x1029:
            # Error behavior object
            if subindex == 0:
                return bytes([1])  # 1 sub-index
            elif subindex == 1:
                return bytes([0x00])  # Switch to pre-operational on error

        elif index == 0x1200:
            # SDO server parameter
            if subindex == 0:
                return bytes([2])  # 2 sub-indices
            elif subindex == 1:
                return struct.pack("<I", CANOPEN_SDO_RX_BASE + node_id)
            elif subindex == 2:
                return struct.pack("<I", CANOPEN_SDO_TX_BASE + node_id)

        # --- TPDO communication parameters (0x1800-0x1803) ---
        if 0x1800 <= index <= 0x1803:
            pdo_num = index - 0x1800 + 1  # 1-4
            node_pdo = CANOPEN_PDO_CONFIG.get(node_id, {}).get("tpdo", {}).get(pdo_num)
            if node_pdo:
                if subindex == 0:
                    return bytes([5])  # Number of sub-indices (max entries)
                elif subindex == 1:
                    return struct.pack("<I", node_pdo["cob_id"])
                elif subindex == 2:
                    return bytes([node_pdo["trans_type"]])
            return None

        # --- TPDO mapping parameters (0x1A00-0x1A03) ---
        if 0x1A00 <= index <= 0x1A03:
            pdo_num = index - 0x1A00 + 1
            node_pdo = CANOPEN_PDO_CONFIG.get(node_id, {}).get("tpdo", {}).get(pdo_num)
            if node_pdo:
                if subindex == 0:
                    return bytes([node_pdo["num_mappings"]])
                mappings = node_pdo.get("mappings", [])
                if 1 <= subindex <= len(mappings):
                    return struct.pack("<I", mappings[subindex - 1])
            return None

        # --- RPDO communication parameters (0x1400-0x1403) ---
        if 0x1400 <= index <= 0x1403:
            pdo_num = index - 0x1400 + 1
            node_pdo = CANOPEN_PDO_CONFIG.get(node_id, {}).get("rpdo", {}).get(pdo_num)
            if node_pdo:
                if subindex == 0:
                    return bytes([5])
                elif subindex == 1:
                    return struct.pack("<I", node_pdo["cob_id"])
                elif subindex == 2:
                    return bytes([node_pdo["trans_type"]])
            return None

        # --- RPDO mapping parameters (0x1600-0x1603) ---
        if 0x1600 <= index <= 0x1603:
            pdo_num = index - 0x1600 + 1
            node_pdo = CANOPEN_PDO_CONFIG.get(node_id, {}).get("rpdo", {}).get(pdo_num)
            if node_pdo:
                if subindex == 0:
                    return bytes([node_pdo["num_mappings"]])
                mappings = node_pdo.get("mappings", [])
                if 1 <= subindex <= len(mappings):
                    return struct.pack("<I", mappings[subindex - 1])
            return None

        return None

    def _send_sdo_abort(self, resp_id: int, index: int, subindex: int, abort_code: int) -> None:
        """Send SDO abort transfer."""
        cmd = SDO_SCS_ABORT << 5  # 0x80
        abort_bytes = struct.pack("<I", abort_code)
        frame = bytes([cmd, index & 0xFF, (index >> 8) & 0xFF, subindex]) + abort_bytes
        self.bus.send(resp_id, frame[:8])


# =============================================================================
# XCP Responder
# =============================================================================


class XCPResponder:
    """Handles XCP protocol requests on 0x550 -> 0x551."""

    def __init__(self, bus: CANBus):
        self.bus = bus
        self.connected = False

    def handle(self, msg: can.Message) -> None:
        """Process XCP request."""
        if msg.arbitration_id != XCP_REQ_ID:
            return

        data = bytes(msg.data)
        if len(data) < 1:
            return

        cmd = data[0]

        if cmd == XCP_CONNECT_CMD:
            self._handle_connect(data)
        elif cmd == XCP_DISCONNECT_CMD:
            self._handle_disconnect()
        elif cmd == XCP_GET_STATUS_CMD:
            self._handle_get_status()
        elif cmd == XCP_GET_COMM_MODE_INFO_CMD:
            self._handle_get_comm_mode_info()
        elif cmd == XCP_GET_ID_CMD:
            self._handle_get_id(data)
        elif cmd == XCP_SHORT_UPLOAD_CMD:
            self._handle_short_upload(data)
        else:
            # Unknown command
            self._send_error(0x20)  # ERR_CMD_UNKNOWN

    def _handle_connect(self, data: bytes) -> None:
        """Handle XCP CONNECT."""
        self.connected = True
        resp = bytes(
            [
                XCP_RES_PID,
                XCP_RESOURCE_PROTECTION,  # Resource protection
                0x00,  # Comm mode basic
                XCP_MAX_CTO,  # Max CTO
                XCP_MAX_DTO & 0xFF,
                (XCP_MAX_DTO >> 8) & 0xFF,  # Max DTO (LE)
                XCP_VERSION_MAJOR,
                XCP_VERSION_MINOR,  # XCP version
            ]
        )
        self.bus.send(XCP_RESP_ID, resp)

    def _handle_disconnect(self) -> None:
        """Handle XCP DISCONNECT."""
        self.connected = False
        self.bus.send(XCP_RESP_ID, bytes([XCP_RES_PID, 0, 0, 0, 0, 0, 0, 0]))

    def _handle_get_status(self) -> None:
        """Handle XCP GET_STATUS."""
        if not self.connected:
            self._send_error(0x29)  # ERR_SEQUENCE
            return
        # Response: [RES, session_status, resource_protection, reserved, session_config_id(2)]
        resp = bytes(
            [
                XCP_RES_PID,
                0x00,  # Session status (no active session flags)
                XCP_RESOURCE_PROTECTION,
                0x00,  # Reserved
                0x00,
                0x00,  # Session config ID
                0x00,
                0x00,
            ]
        )
        self.bus.send(XCP_RESP_ID, resp)

    def _handle_get_comm_mode_info(self) -> None:
        """Handle XCP GET_COMM_MODE_INFO."""
        if not self.connected:
            self._send_error(0x29)
            return
        # Response: [RES, reserved, comm_mode_optional, reserved, max_bs, min_st, queue_size,
        #            xcp_driver_version_major, xcp_driver_version_minor]
        resp = bytes(
            [
                XCP_RES_PID,
                0x00,  # Reserved
                0x01,  # Comm mode optional (master block mode supported)
                0x00,  # Reserved
                0x00,  # Max BS
                0x00,  # Min ST
                0x01,
                XCP_VERSION_MAJOR,
                XCP_VERSION_MINOR,  # truncated to 8 bytes below
            ]
        )
        # CAN frame is max 8 bytes
        self.bus.send(XCP_RESP_ID, resp[:8])

    def _handle_get_id(self, data: bytes) -> None:
        """Handle XCP GET_ID."""
        if not self.connected:
            self._send_error(0x29)
            return
        id_type = data[1] if len(data) > 1 else 0
        # For ASCII type: report length (actual data would need UPLOAD)
        id_string = b"OIDA-XCP-MOCK"
        id_len = len(id_string)
        resp = bytes(
            [
                XCP_RES_PID,
                0x00,  # Mode (0 = data in response or need UPLOAD)
                0x00,
                0x00,  # Reserved
            ]
        ) + struct.pack("<I", id_len)
        self.bus.send(XCP_RESP_ID, resp[:8])

    def _handle_short_upload(self, data: bytes) -> None:
        """Handle XCP SHORT_UPLOAD."""
        if not self.connected:
            self._send_error(0x29)
            return
        if len(data) < 8:
            self._send_error(0x21)  # ERR_CMD_SYNTAX
            return

        num_elements = data[1]
        address = struct.unpack("<I", data[4:8])[0]

        # Look for matching memory region
        mem_data = None
        for base_addr, mem_bytes in XCP_MEMORY.items():
            if base_addr <= address < base_addr + len(mem_bytes):
                offset = address - base_addr
                mem_data = mem_bytes[offset : offset + num_elements]
                break

        if mem_data is None:
            self._send_error(0x22)  # ERR_OUT_OF_RANGE
            return

        # Pad to requested length
        mem_data = mem_data + bytes(max(0, num_elements - len(mem_data)))

        # Response: [RES, data...]
        resp = bytes([XCP_RES_PID]) + mem_data[:7]
        resp += bytes(max(0, 8 - len(resp)))
        self.bus.send(XCP_RESP_ID, resp[:8])

    def _send_error(self, error_code: int) -> None:
        """Send XCP error response."""
        resp = bytes([XCP_ERR_PID, error_code, 0, 0, 0, 0, 0, 0])
        self.bus.send(XCP_RESP_ID, resp)


# =============================================================================
# CCP Responder (CAN Calibration Protocol v2.1)
# =============================================================================


class CCPResponder:
    """Handles CCP protocol requests on CRO 0x701 -> DTO 0x702.

    Simulates 2 CCP stations (address 0 and 1), each with its own
    device identification. Supports CONNECT, GET_CCP_VERSION,
    EXCHANGE_ID, GET_S_STATUS, and DISCONNECT commands.
    """

    def __init__(self, bus: CANBus):
        self.bus = bus
        self.connected_station: Optional[int] = None  # Currently connected station

    def handle(self, msg: can.Message) -> None:
        """Process a CCP CRO message."""
        if msg.arbitration_id != CCP_CRO_ID:
            return

        data = bytes(msg.data)
        if len(data) < 2:
            return

        cmd = data[0]
        ctr = data[1]

        if cmd == CCP_CONNECT_CMD:
            self._handle_connect(ctr, data)
        elif cmd == CCP_GET_CCP_VERSION_CMD:
            self._handle_get_version(ctr, data)
        elif cmd == CCP_EXCHANGE_ID_CMD:
            self._handle_exchange_id(ctr, data)
        elif cmd == CCP_GET_S_STATUS_CMD:
            self._handle_get_s_status(ctr, data)
        elif cmd == CCP_DISCONNECT_CMD:
            self._handle_disconnect(ctr, data)
        else:
            # Unknown command
            self._send_dto(0x30, ctr)  # CRC_CMD_UNKNOWN

    def _handle_connect(self, ctr: int, data: bytes) -> None:
        """Handle CCP CONNECT command.

        CRO: [0x01, ctr, station_lo, station_hi, 0,0,0,0]
        DTO: [0xFF, err_code, ctr, 0,0,0,0,0]
        """
        if len(data) < 4:
            self._send_dto(0x31, ctr)  # CRC_CMD_SYNTAX
            return

        station_addr = data[2] | (data[3] << 8)

        if station_addr in CCP_STATIONS:
            self.connected_station = station_addr
            self._send_dto(0x00, ctr)  # Acknowledge
            log.debug(f"CCP CONNECT station {station_addr}")
        else:
            self._send_dto(0x32, ctr)  # CRC_PARAMETER_OUT_OF_RANGE

    def _handle_get_version(self, ctr: int, data: bytes) -> None:
        """Handle CCP GET_CCP_VERSION command.

        CRO: [0x1B, ctr, main_ver_req, release_ver_req, 0,0,0,0]
        DTO: [0xFF, err_code, ctr, main_ver, release_ver, 0,0,0]
        """
        if self.connected_station is None:
            self._send_dto(0x33, ctr)  # Access denied (not connected)
            return

        # Return our CCP version regardless of requested version
        resp = bytes(
            [
                CCP_DTO_COMMAND_RETURN,
                0x00,  # No error
                ctr,
                CCP_VERSION_MAJOR,
                CCP_VERSION_MINOR,
                0x00,
                0x00,
                0x00,
            ]
        )
        self.bus.send(CCP_DTO_ID, resp)

    def _handle_exchange_id(self, ctr: int, data: bytes) -> None:
        """Handle CCP EXCHANGE_ID command.

        CRO: [0x17, ctr, 0,0,0,0,0,0]
        DTO: [0xFF, err_code, ctr, id_length, data_type, availability, protection, 0]
        """
        if self.connected_station is None:
            self._send_dto(0x33, ctr)
            return

        station = CCP_STATIONS[self.connected_station]
        id_str = station["id"]

        resp = bytes(
            [
                CCP_DTO_COMMAND_RETURN,
                0x00,  # No error
                ctr,
                len(id_str),
                station["data_type"],
                station["availability"],
                station["protection"],
                0x00,
            ]
        )
        self.bus.send(CCP_DTO_ID, resp)

    def _handle_get_s_status(self, ctr: int, data: bytes) -> None:
        """Handle CCP GET_S_STATUS command.

        CRO: [0x0D, ctr, 0,0,0,0,0,0]
        DTO: [0xFF, err_code, ctr, session_status, additional_info, 0,0,0]
        """
        if self.connected_station is None:
            self._send_dto(0x33, ctr)
            return

        # session_status bits: bit0=CAL, bit1=DAQ, bit2=RESUME, bit6=STORE, bit7=RUN
        session_status = 0x01 if self.connected_station == 0 else 0x00

        resp = bytes(
            [
                CCP_DTO_COMMAND_RETURN,
                0x00,  # No error
                ctr,
                session_status,
                0x00,  # Additional info
                0x00,
                0x00,
                0x00,
            ]
        )
        self.bus.send(CCP_DTO_ID, resp)

    def _handle_disconnect(self, ctr: int, data: bytes) -> None:
        """Handle CCP DISCONNECT command.

        CRO: [0x07, ctr, type, 0x00, station_lo, station_hi, 0, 0]
        DTO: [0xFF, err_code, ctr, 0,0,0,0,0]
        """
        if len(data) >= 6:
            station_addr = data[4] | (data[5] << 8)
            if self.connected_station == station_addr:
                self.connected_station = None
        else:
            self.connected_station = None

        self._send_dto(0x00, ctr)  # Acknowledge
        log.debug("CCP DISCONNECT")

    def _send_dto(self, err_code: int, ctr: int) -> None:
        """Send a basic CCP DTO (command return) response."""
        resp = bytes(
            [
                CCP_DTO_COMMAND_RETURN,
                err_code,
                ctr,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            ]
        )
        self.bus.send(CCP_DTO_ID, resp)


# =============================================================================
# J1939 Responder (SAE J1939 over 29-bit extended CAN IDs)
# =============================================================================


class J1939Responder:
    """Handles SAE J1939 traffic over extended (29-bit) CAN identifiers.

    Simulates two ECUs (engine SA 0x00, transmission SA 0x03):
      - Address Claimed (PGN 60928 / 0xEE00) advertising each NAME
      - Request PGN (PGN 59904 / 0xEA00) handling: answers requests for
        supported PGNs (EEC1, ET1, CCVS1, Address Claimed, and the VIN)
      - Periodic broadcast PGNs (EEC1, ET1, CCVS1) driven by the
        TrafficGenerator, plus on-demand broadcasts on request
      - Multi-packet VIN (PGN 65260 / 0xFEEC) delivered via BAM transport
        protocol (TP.CM 0xEC00 announce + TP.DT 0xEB00 data frames)

    All frames use proper extended IDs so the scanner's traffic classifier
    tags them as J1939 / extended.
    """

    def __init__(self, bus: CANBus):
        self.bus = bus

    @staticmethod
    def make_id(pgn: int, source: int, priority: int = 6) -> int:
        """Compose a 29-bit J1939 arbitration ID from PGN + source address."""
        return ((priority & 0x7) << 26) | ((pgn & 0x3FFFF) << 8) | (source & 0xFF)

    @staticmethod
    def decode_id(arb_id: int) -> Tuple[int, int, int]:
        """Decode a 29-bit J1939 arbitration ID into (priority, pgn, source)."""
        priority = (arb_id & J1939_PRIORITY_MASK) >> 26
        pgn = (arb_id & J1939_PGN_MASK) >> 8
        source = arb_id & J1939_SOURCE_MASK
        return priority, pgn, source

    def _send(self, pgn: int, source: int, data: bytes, priority: int = 6) -> None:
        """Send a single-frame J1939 PGN."""
        arb_id = self.make_id(pgn, source, priority)
        frame = data[:8] + bytes(max(0, 8 - len(data)))
        self.bus.send(arb_id, frame[:8], is_extended=True)

    # ------------------------------------------------------------------
    # PGN payload builders
    # ------------------------------------------------------------------

    def build_eec1(self) -> bytes:
        """EEC1 (0xF004): byte 4-5 = engine speed (rpm), 0.125 rpm/bit LE."""
        rpm = 800
        raw = int(rpm / 0.125) & 0xFFFF
        return bytes([0xF0, 0x7D, 0x00, 0x00, raw & 0xFF, (raw >> 8) & 0xFF, 0x00, 0xFF])

    def build_et1(self) -> bytes:
        """ET1 (0xFEEE): byte 0 = coolant temp, 1 deg C/bit, -40 offset."""
        coolant_c = 87
        return bytes([(coolant_c + 40) & 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])

    def build_ccvs1(self) -> bytes:
        """CCVS1 (0xFEF1): byte 1-2 = wheel-based vehicle speed, 1/256 km/h/bit LE."""
        speed_kmh = 64
        raw = int(speed_kmh * 256) & 0xFFFF
        return bytes([0xFF, raw & 0xFF, (raw >> 8) & 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])

    def build_payload(self, pgn: int) -> Optional[bytes]:
        """Return the 8-byte payload for a single-frame broadcast PGN."""
        if pgn == J1939_PGN_EEC1:
            return self.build_eec1()
        if pgn == J1939_PGN_ET1:
            return self.build_et1()
        if pgn == J1939_PGN_CCVS1:
            return self.build_ccvs1()
        return None

    # ------------------------------------------------------------------
    # Broadcast helpers (called by TrafficGenerator)
    # ------------------------------------------------------------------

    def send_broadcast(self, pgn: int, source: int) -> None:
        """Send one periodic broadcast PGN frame."""
        payload = self.build_payload(pgn)
        if payload is not None:
            self._send(pgn, source, payload)

    def send_address_claimed(self, source: int) -> None:
        """Send Address Claimed (PGN 60928) for the given source address."""
        name = J1939_NAMES.get(source, 0)
        name_bytes = struct.pack("<Q", name & 0xFFFFFFFFFFFFFFFF)
        # PGN 0xEE00 with destination = global (0xFF) -> low byte of PGN.
        pgn = J1939_PGN_ADDRESS_CLAIMED | J1939_GLOBAL_ADDRESS
        self._send(pgn, source, name_bytes)

    def send_vin_bam(self, source: int) -> None:
        """Send the VIN (PGN 65260) as a BAM multi-packet transport.

        Sends a TP.CM (BAM) announce frame followed by TP.DT data frames.
        """
        vin = MOCK_VIN_J1939.encode("ascii")
        total_size = len(vin)
        num_packets = (total_size + 6) // 7
        target_pgn = J1939_PGN_VEHICLE_ID

        # TP.CM BAM: [0x20, size_lo, size_hi, num_packets, 0xFF, pgn_lo, pgn_mid, pgn_hi]
        cm = bytes(
            [
                J1939_TP_CM_BAM,
                total_size & 0xFF,
                (total_size >> 8) & 0xFF,
                num_packets,
                0xFF,
                target_pgn & 0xFF,
                (target_pgn >> 8) & 0xFF,
                (target_pgn >> 16) & 0xFF,
            ]
        )
        # TP.CM is broadcast to the global address (PDU1 0xEC00 | 0xFF).
        self._send(J1939_PGN_TP_CM | J1939_GLOBAL_ADDRESS, source, cm, priority=7)
        time.sleep(0.002)

        # TP.DT frames: [seq_no, 7 data bytes], 0xFF padding for the last frame.
        for seq in range(num_packets):
            chunk = vin[seq * 7 : seq * 7 + 7]
            chunk = chunk + bytes([0xFF] * (7 - len(chunk)))
            dt = bytes([seq + 1]) + chunk
            self._send(J1939_PGN_TP_DT | J1939_GLOBAL_ADDRESS, source, dt, priority=7)
            time.sleep(0.001)

    # ------------------------------------------------------------------
    # Request handling
    # ------------------------------------------------------------------

    def handle(self, msg: can.Message) -> None:
        """Process an incoming extended-frame J1939 request."""
        if not msg.is_extended_id:
            return

        _, pgn, source = self.decode_id(msg.arbitration_id)

        # Request PGN (0xEA00, PDU1). Data bytes 0..2 = the requested PGN (LE).
        if (pgn & 0xFF00) == J1939_PGN_REQUEST:
            data = bytes(msg.data)
            if len(data) < 3:
                return
            requested_pgn = data[0] | (data[1] << 8) | (data[2] << 16)
            self._handle_request(requested_pgn)

    def _handle_request(self, requested_pgn: int) -> None:
        """Respond to a Request PGN with the requested data."""
        if requested_pgn in (J1939_PGN_EEC1, J1939_PGN_CCVS1):
            self.send_broadcast(requested_pgn, J1939_SA_ENGINE)
        elif requested_pgn == J1939_PGN_ET1:
            self.send_broadcast(requested_pgn, J1939_SA_ENGINE)
        elif requested_pgn == J1939_PGN_VEHICLE_ID:
            self.send_vin_bam(J1939_SA_ENGINE)
        elif (requested_pgn & 0xFF00) == J1939_PGN_ADDRESS_CLAIMED:
            # Requesting Address Claimed -> both ECUs claim their address.
            self.send_address_claimed(J1939_SA_ENGINE)
            self.send_address_claimed(J1939_SA_TRANSMISSION)


# =============================================================================
# Background Traffic Generator
# =============================================================================


class TrafficGenerator:
    """Generates realistic background CAN traffic."""

    def __init__(self, bus: CANBus, j1939: Optional["J1939Responder"] = None):
        self.bus = bus
        self.running = False
        self._threads: List[threading.Thread] = []
        self.j1939 = j1939

    def start(self) -> None:
        """Start all traffic generation threads."""
        self.running = True

        # Standard automotive traffic
        for arb_id, interval, data_len in BACKGROUND_TRAFFIC:
            t = threading.Thread(
                target=self._periodic_sender,
                args=(arb_id, interval, data_len, False),
                daemon=True,
                name=f"traffic-0x{arb_id:03X}",
            )
            t.start()
            self._threads.append(t)

        # Extended frame traffic (J1939-like)
        for arb_id, interval, data_len in EXTENDED_TRAFFIC:
            t = threading.Thread(
                target=self._periodic_sender,
                args=(arb_id, interval, data_len, True),
                daemon=True,
                name=f"traffic-0x{arb_id:08X}",
            )
            t.start()
            self._threads.append(t)

        # CANopen heartbeats (4 nodes, 1s interval)
        for node_id in CANOPEN_NODES:
            t = threading.Thread(
                target=self._heartbeat_sender,
                args=(node_id,),
                daemon=True,
                name=f"heartbeat-node{node_id}",
            )
            t.start()
            self._threads.append(t)

        # CANopen TPDO traffic
        t = threading.Thread(target=self._pdo_sender, daemon=True, name="pdo-sender")
        t.start()
        self._threads.append(t)

        # CANopen EMCY (occasional)
        t = threading.Thread(target=self._emcy_sender, daemon=True, name="emcy-sender")
        t.start()
        self._threads.append(t)

        # J1939 background traffic (broadcast PGNs + periodic Address Claimed)
        if self.j1939 is not None:
            for pgn, interval, source in J1939_BROADCAST_PGNS:
                t = threading.Thread(
                    target=self._j1939_broadcast_sender,
                    args=(pgn, interval, source),
                    daemon=True,
                    name=f"j1939-{pgn:04X}",
                )
                t.start()
                self._threads.append(t)

            t = threading.Thread(
                target=self._j1939_address_claim_sender,
                daemon=True,
                name="j1939-addr-claim",
            )
            t.start()
            self._threads.append(t)

        log.info("Traffic generator started (%d threads)", len(self._threads))

    def stop(self) -> None:
        """Stop traffic generation."""
        self.running = False
        for t in self._threads:
            t.join(timeout=2.0)
        self._threads.clear()

    def _periodic_sender(self, arb_id: int, interval: float, data_len: int, extended: bool) -> None:
        """Send periodic CAN frames with slightly varying data."""
        # Throttle the high-frequency noise senders when the test knob is set
        # (default scale 1.0 leaves manual behaviour unchanged).
        interval = interval * TRAFFIC_RATE_SCALE
        base_data = [random.randint(0, 255) for _ in range(data_len)]
        counter = 0

        while self.running:
            # Vary data slightly to simulate real bus activity
            data = list(base_data)
            if data_len >= 2:
                # Simulate an incrementing counter in bytes 0-1
                data[0] = (counter >> 8) & 0xFF
                data[1] = counter & 0xFF
            if data_len >= 4:
                # Simulate a slowly changing sensor value in bytes 2-3
                noise = random.randint(-5, 5)
                val = (0x8000 + counter * 3 + noise) & 0xFFFF
                data[2] = (val >> 8) & 0xFF
                data[3] = val & 0xFF

            self.bus.send(arb_id, bytes(data), is_extended=extended)
            counter = (counter + 1) & 0xFFFF
            time.sleep(interval)

    def _heartbeat_sender(self, node_id: int) -> None:
        """Send CANopen heartbeat for a node every 1 second."""
        hb_id = CANOPEN_HEARTBEAT_BASE + node_id

        while self.running:
            # Heartbeat: 1 byte, NMT state (Operational = 0x05)
            self.bus.send(hb_id, bytes([CANOPEN_NMT_STATE_OPERATIONAL]))
            time.sleep(1.0)

    def _pdo_sender(self) -> None:
        """Send CANopen TPDO frames periodically."""
        # TPDOs are pure background noise for our scans; throttle them with the
        # same test knob so the CANopen SDO reads are not buried under PDO spam.
        pdo_interval = 0.1 * TRAFFIC_RATE_SCALE
        counter = 0

        while self.running:
            for node_id in CANOPEN_NODES:
                # TPDO1 (0x180 + node_id) - 100ms
                tpdo1_data = bytes(
                    [
                        (counter + node_id) & 0xFF,
                        random.randint(0, 255),
                        random.randint(0, 100),
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                    ]
                )
                self.bus.send(CANOPEN_TPDO1_BASE + node_id, tpdo1_data)

            time.sleep(pdo_interval)

            # TPDO2 (0x280 + node_id) - 500ms
            if counter % 5 == 0:
                for node_id in CANOPEN_NODES:
                    tpdo2_data = bytes(
                        [
                            random.randint(0, 255),
                            random.randint(0, 255),
                            (counter >> 8) & 0xFF,
                            counter & 0xFF,
                            0x00,
                            0x00,
                            0x00,
                            0x00,
                        ]
                    )
                    self.bus.send(CANOPEN_TPDO2_BASE + node_id, tpdo2_data)

            # TPDO3 + TPDO4 - slower (1s)
            if counter % 10 == 0:
                for node_id in [1, 2]:  # Only nodes 1-2 have TPDO3/4
                    self.bus.send(
                        CANOPEN_TPDO3_BASE + node_id,
                        bytes([random.randint(0, 255) for _ in range(4)]) + bytes(4),
                    )
                    self.bus.send(
                        CANOPEN_TPDO4_BASE + node_id,
                        bytes([random.randint(0, 255) for _ in range(8)]),
                    )

            counter = (counter + 1) & 0xFFFF

    def _emcy_sender(self) -> None:
        """Send occasional CANopen EMCY (emergency) frames."""
        while self.running:
            # Random EMCY from node 1 or 2 every 10-30 seconds
            time.sleep(random.uniform(10, 30))
            if not self.running:
                break

            node_id = random.choice([1, 2])
            emcy_id = CANOPEN_EMCY_BASE + node_id

            # Pick a random error code
            error_codes = [0x0000, 0x1000, 0x2310, 0x3120, 0x4200, 0x8130]
            error_code = random.choice(error_codes)
            error_register = 0x01 if error_code != 0x0000 else 0x00

            emcy_data = struct.pack("<H", error_code) + bytes([error_register]) + bytes(5)
            self.bus.send(emcy_id, emcy_data)

            if error_code != 0x0000:
                log.debug(
                    f"EMCY node {node_id}: error 0x{error_code:04X} reg=0x{error_register:02X}"
                )

    def _j1939_broadcast_sender(self, pgn: int, interval: float, source: int) -> None:
        """Periodically broadcast a single J1939 PGN."""
        while self.running:
            if self.j1939 is not None:
                self.j1939.send_broadcast(pgn, source)
            time.sleep(interval)

    def _j1939_address_claim_sender(self) -> None:
        """Periodically emit Address Claimed frames for both J1939 ECUs."""
        while self.running:
            if self.j1939 is not None:
                self.j1939.send_address_claimed(J1939_SA_ENGINE)
                self.j1939.send_address_claimed(J1939_SA_TRANSMISSION)
            time.sleep(5.0)


# =============================================================================
# Message Dispatcher
# =============================================================================


class MessageDispatcher:
    """Receives CAN messages and routes them to the appropriate handler."""

    def __init__(self, bus: CANBus, j1939: Optional[J1939Responder] = None):
        self.bus = bus
        # Shared ISO-TP Flow Control event: the single blocking reader (run())
        # sets this when it sees a tester Flow Control frame (0x30) so that the
        # off-thread multi-frame senders may release their Consecutive Frames.
        self._fc_event = threading.Event()
        self.uds = UDSResponder(bus, fc_event=self._fc_event)
        self.canopen = CANopenResponder(bus)
        self.xcp = XCPResponder(bus)
        self.ccp = CCPResponder(bus)
        self.j1939 = j1939

    def run(self) -> None:
        """Main receive loop."""
        log.info("Message dispatcher started")

        while True:
            try:
                msg = self.bus.recv(timeout=0.5)
                if msg is None:
                    continue

                arb_id = msg.arbitration_id

                # J1939 (extended 29-bit frames) - handle requests / TP
                if msg.is_extended_id:
                    if self.j1939 is not None:
                        self.j1939.handle(msg)
                    continue

                # ISO-TP Flow Control (0x30) from the tester on a UDS/OBD-II
                # request ID: signal the off-thread CF senders. This MUST be
                # handled by the single reader -- a handler calling bus.recv()
                # itself would starve this loop and never see the FC.
                data = bytes(msg.data)
                if (
                    (arb_id in UDS_ECUS or arb_id == OBD2_REQUEST_ID)
                    and len(data) >= 1
                    and (data[0] & 0xF0) == 0x30
                ):
                    self._fc_event.set()
                    continue

                # UDS / OBD-II
                if arb_id in UDS_ECUS or arb_id == OBD2_REQUEST_ID:
                    self.uds.handle(msg)
                    continue

                # CANopen SDO requests (0x601-0x67F)
                if CANOPEN_SDO_RX_BASE < arb_id <= CANOPEN_SDO_RX_BASE + 127:
                    self.canopen.handle_sdo(msg)
                    continue

                # XCP requests
                if arb_id == XCP_REQ_ID:
                    self.xcp.handle(msg)
                    continue

                # CCP requests (CRO on 0x701)
                if arb_id == CCP_CRO_ID:
                    self.ccp.handle(msg)
                    continue

                # Ignore other traffic (our own background, etc.)

            except Exception:
                # Silently ignore malformed packets (e.g. healthcheck probes)
                pass


# =============================================================================
# Main
# =============================================================================


def main() -> None:
    """Start the CAN mock server."""
    channel = sys.argv[1] if len(sys.argv) > 1 else MULTICAST_CHANNEL
    port = int(sys.argv[2]) if len(sys.argv) > 2 else MULTICAST_PORT

    # J1939 simulation is on by default; disable with CAN_J1939=0.
    j1939_enabled = _env_flag("CAN_J1939", default=True)

    log.info("=" * 60)
    log.info("OIDA CAN Bus Mock Server")
    log.info("=" * 60)
    log.info(f"  Channel:  {channel}")
    log.info(f"  Port:     {port}")
    log.info(f"  UDS ECUs: {', '.join(f'0x{k:03X}->0x{v:03X}' for k, v in UDS_ECUS.items())}")
    log.info(f"  OBD-II:   0x{OBD2_REQUEST_ID:03X} -> 0x{OBD2_RESPONSE_ID:03X}")
    log.info(f"  CANopen:  nodes {list(CANOPEN_NODES.keys())}")
    log.info(f"  XCP:      0x{XCP_REQ_ID:03X} -> 0x{XCP_RESP_ID:03X}")
    log.info(
        f"  CCP:      0x{CCP_CRO_ID:03X} -> 0x{CCP_DTO_ID:03X} (stations: {list(CCP_STATIONS.keys())})"
    )
    if j1939_enabled:
        log.info(
            f"  J1939:    SA 0x{J1939_SA_ENGINE:02X} (engine), "
            f"0x{J1939_SA_TRANSMISSION:02X} (transmission); "
            "PGNs EEC1/ET1/CCVS1 + VIN via BAM"
        )
    log.info(f"  VIN:      {MOCK_VIN}")
    if TRAFFIC_RATE_SCALE != 1.0:
        log.info(
            f"  Traffic:  THROTTLED (interval x{TRAFFIC_RATE_SCALE:g}; "
            "CAN_QUIET/CAN_TRAFFIC_RATE set) -- heartbeats + J1939 + responders stay active"
        )
    log.info("=" * 60)

    bus = CANBus(channel, port)
    bus.connect()

    # J1939 responder (optional, enabled by default)
    j1939 = J1939Responder(bus) if j1939_enabled else None

    # Start background traffic
    traffic = TrafficGenerator(bus, j1939=j1939)
    traffic.start()

    # Start message dispatcher in main thread
    dispatcher = MessageDispatcher(bus, j1939=j1939)
    try:
        dispatcher.run()
    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        traffic.stop()
        bus.shutdown()
        log.info("CAN mock server stopped")


if __name__ == "__main__":
    main()
