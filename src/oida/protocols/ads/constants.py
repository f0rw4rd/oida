"""
Beckhoff ADS Protocol Constants

Single source of truth for ADS/AMS constants used by the scanner,
passive listener, and other modules.  Follows the established pattern
from ``protocols/modbus/constants.py`` and ``protocols/ethernetip/constants.py``.
"""

from typing import Dict, FrozenSet

# ---------------------------------------------------------------------------
# ADS Command IDs
# ---------------------------------------------------------------------------

ADS_COMMANDS: Dict[int, str] = {
    0x0001: "ReadDeviceInfo",
    0x0002: "Read",
    0x0003: "Write",
    0x0004: "ReadState",
    0x0005: "WriteControl",
    0x0006: "AddDeviceNotification",
    0x0007: "DeleteDeviceNotification",
    0x0008: "DeviceNotification",
    0x0009: "ReadWrite",
}

WRITE_COMMAND_IDS: FrozenSet[int] = frozenset({0x0003, 0x0005, 0x0009})
READ_COMMAND_IDS: FrozenSet[int] = frozenset({0x0001, 0x0002, 0x0004})

# ---------------------------------------------------------------------------
# ADS Index Groups  (name -> int, for building requests)
# ---------------------------------------------------------------------------

ADS_IDX_GRP: Dict[str, int] = {
    # File system operations (via SystemService port 10000)
    "FILE_OPEN": 0x78,  # 120 - Open file (flags: R/W/APPEND/BINARY/TEXT)
    "FILE_CLOSE": 0x79,  # 121 - Close file handle
    "FILE_READ": 0x7A,  # 122 - Read from file
    "FILE_WRITE": 0x7B,  # 123 - Write to file
    "FILE_DELETE": 0x83,  # 131 - Delete file
    "FILE_BROWSE": 0x85,  # 133 - Browse directory
    # Windows registry operations (official Beckhoff)
    "REG_HKLM": 0xC8,  # 200 - HKEY_LOCAL_MACHINE
    "REG_HKCU": 0xC9,  # 201 - HKEY_CURRENT_USER
    "REG_HKCR": 0xCA,  # 202 - HKEY_CLASSES_ROOT
    "REG_DEL_HKLM": 0xCE,  # 206 - Delete from HKLM
    "REG_DEL_HKCU": 0xCF,  # 207 - Delete from HKCU
    "REG_DEL_HKCR": 0xD0,  # 208 - Delete from HKCR
    # License/registration
    "LICENSE_INFO": 0xDC,  # 220 - License information
    # Command execution (official Beckhoff)
    "EXECUTE": 0x1F4,  # 500 - Start process
    "SET_NUMPROC": 0x4B0,  # 1200 - Set number of processors
    # System XML
    "TC_XML": 0x2BC,  # 700 - TwinCAT XML description
    # Route management
    "ROUTE_ADD": 0x321,  # 801 - Add route
    "ROUTE_DEL": 0x322,  # 802 - Remove route
    "ROUTE_LIST": 0x323,  # 803 - List routes
    # PLC memory regions
    "MEM_INPUT": 0x4000,
    "MEM_OUTPUT": 0x4010,
    "MEM_MARKER": 0x4020,
    "MEM_MARKER_BIT": 0x4021,
    "MEM_SIZE_M": 0x4025,  # Get %M area size
    "MEM_RETAIN": 0x4030,
    "MEM_SIZE_RB": 0x4035,  # Get retain data size
    "MEM_DATA": 0x4040,
    "MEM_SIZE_DB": 0x4045,  # Get data area size
    # Symbol table operations
    "SYM_TABLE": 0xF000,
    "SYM_NAME": 0xF001,
    "SYM_VALUE": 0xF002,
    "SYM_HNDL_BY_NAME": 0xF003,
    "SYM_VAL_BY_NAME": 0xF004,
    "SYM_VAL_BY_HNDL": 0xF005,
    "SYM_RELEASE": 0xF006,
    "SYM_INFO_BY_NAME": 0xF007,
    "SYM_VERSION": 0xF008,
    "SYM_INFO_EX": 0xF009,
    "SYM_DOWNLOAD": 0xF00A,
    "SYM_UPLOAD": 0xF00B,
    "SYM_UPLOAD_INFO": 0xF00C,
    "SYM_DOWNLOAD2": 0xF00D,  # Extended download
    "SYM_DTYPE_UPLOAD": 0xF00E,  # Data type upload
    "SYM_UPLOAD_INFO2": 0xF00F,  # Upload info v2 (24 bytes)
    "SYM_NOTIFY": 0xF010,  # Named handle notification
    "SYM_DTYPE_INFO_EX": 0xF011,  # Extended data type info
    "SYM_ADDR_BY_HNDL": 0xF012,  # Symbol address by handle
    # I/O image access
    "IO_INPUT_BYTE": 0xF020,
    "IO_INPUT_BIT": 0xF021,
    "IO_SIZE_I": 0xF025,  # Physical input size
    "IO_OUTPUT_BYTE": 0xF030,
    "IO_OUTPUT_BIT": 0xF031,
    "IO_SIZE_Q": 0xF035,  # Physical output size
    "IO_CLEAR_INPUT": 0xF040,
    "IO_CLEAR_OUTPUT": 0xF050,
    "IO_RW_COMBINED": 0xF060,  # Read input + write output atomically
    # Batch/Sum operations
    "BATCH_READ": 0xF080,
    "BATCH_WRITE": 0xF081,
    "BATCH_RW": 0xF082,
    "BATCH_READ_EX": 0xF083,
    "BATCH_READ_EX2": 0xF084,
    "BATCH_ADD_NOTIFY": 0xF085,
    "BATCH_DEL_NOTIFY": 0xF086,
    # I/O image creation
    "IOIMAGE_CREATE": 0xF068,  # Create I/O image
    # Device information
    "DEV_DATA": 0xF100,
    # Task data (reserved range 0xF200-0xF2FF)
    "TASK_DATA": 0xF200,
    # License service (port 30)
    "LIC_DEV_INFO": 0x01010004,  # Device info (SystemID, PlatformID, VolumeNo)
    "LIC_ONLINE": 0x01010006,  # License count and online info
    "LIC_NAME": 0x0101000C,  # License name by GUID
    "LIC_ORDER": 0x0101000D,  # License order number by GUID
    # Router/hardware access (port 1)
    "HW_ACCESS": 0x05,  # Hardware access base
    # I/O device state (port 300)
    "IO_DEV_STATE": 0x5000,  # I/O device state base
    # EtherCAT master (port 0xFFFF)
    "ECAT_FLB_CMD": 0x2C,  # EtherCAT FLB commands
    "ECAT_DC_STAT": 0x2F,  # EtherCAT DC statistics
    "ECAT_SLAVE_COUNT": 0x0006,  # Slave count (2 bytes at offset 0)
    "ECAT_FIRST_PORT": 0x0007,  # First slave port number (2 bytes at offset 0)
    "ECAT_AL_STATE": 0x0009,  # AL state: offset=0 -> master, offset=port -> slave (2 bytes)
    "ECAT_SLAVE_IDENT": 0x0011,  # Slave identity (16 bytes at offset=slave_port)
    # CoE SDO access (slave ports 1001+)
    "COE_SDO": 0xF302,  # CANopen-over-EtherCAT SDO
    # EEPROM access (port 0xFFFF, offset = (slave_port << 16) | word_addr)
    "ECAT_EEPROM_READ": 0x000E,  # EtherCAT EEPROM read (2 bytes per word)
    # ESC register access (slave ports, offset = register address)
    "ECAT_ESC_REG": 0xF300,
    # FoE handle-based access (slave ports, from pcap analysis)
    "ECAT_FOE_OPEN_R": 0xF401,  # FoE open for read
    "ECAT_FOE_OPEN_W": 0xF402,  # FoE open for write
    "ECAT_FOE_CLOSE": 0xF403,  # FoE close
    "ECAT_FOE_READ_DATA": 0xF404,  # FoE read data
    "ECAT_FOE_WRITE_DATA": 0xF405,  # FoE write data
    "ECAT_FOE_PROGRESSINFO": 0xF406,  # FoE transfer progress query
    # SoE IDN access (slave ports, Beckhoff ig=0xF420/0xF421)
    "ECAT_SOE_READ": 0xF420,  # SoE IDN read
    "ECAT_SOE_WRITE": 0xF421,  # SoE IDN write
    # VoE (Vendor-specific over EtherCAT)
    "ECAT_VOE": 0xF430,
    # CoE info service (slave ports)
    "COE_ENTRY_DESC": 0xF3FE,  # CoE entry description
}

# Device data sub-offsets (index *offsets* used with DEV_DATA's index
# *group* 0xF100 -- these are NOT index groups themselves and must stay out
# of ADS_IDX_GRP / its reverse map, or they collide with real low-valued
# index groups such as HW_ACCESS=0x05).
ADS_DEV_DATA_OFFSETS: Dict[str, int] = {
    "DEV_DATA_ADSSTATE": 0x0000,  # ADS state (2 bytes)
    "DEV_DATA_DEVSTATE": 0x0002,  # Device state (2 bytes)
    "DEV_DATA_CONFIGID": 0x0004,  # Config ID (1 byte)
    "DEV_DATA_ADSVERSIONCHECK": 0x0005,  # ADS version check (1 byte)
}

# Reverse lookup: int -> name (for decoding captured packets).  Built only
# from true index groups -- see ADS_DEV_DATA_OFFSETS above for why the
# DEV_DATA sub-offsets are excluded.
ADS_IDX_GRP_NAMES: Dict[int, str] = {v: k for k, v in ADS_IDX_GRP.items()}

# ---------------------------------------------------------------------------
# ADS Error Codes  (merged superset from scanner + passive listener)
# ---------------------------------------------------------------------------

ADS_ERROR_CODES: Dict[int, str] = {
    # Success
    0x0000: "OK",
    # Global/AMS errors (0x01-0x1C) - from packet-ams.h
    0x01: "Internal error",
    0x02: "No real-time",
    0x03: "Allocation locked",
    0x04: "Mailbox full",
    0x05: "Wrong HMSG",
    0x06: "Target port not found",
    0x07: "Target machine not found",
    0x08: "Unknown command ID",
    0x09: "Bad task ID",
    0x0A: "No IO",
    0x0B: "Unknown AMS command",
    0x0C: "Win32 error",
    0x0D: "Port not connected",
    0x0E: "Invalid AMS length",
    0x0F: "Invalid AMS Net ID",
    0x10: "Low installation level",
    0x11: "No debugging available",
    0x12: "Port disabled",
    0x13: "Port already connected",
    0x14: "AMS Sync Win32 error",
    0x15: "AMS Sync timeout",
    0x16: "AMS Sync AMS error",
    0x17: "No index map for AMS Sync",
    0x18: "Invalid AMS port",
    0x19: "No memory",
    0x1A: "TCP send error",
    0x1B: "Host unreachable",
    0x1C: "Invalid AMS fragment",
    # Router errors (0x0500-0x050D) - from packet-ams.h
    0x0500: "Router: no locked memory",
    0x0501: "Router: resize memory",
    0x0502: "Router: mailbox full",
    0x0503: "Router: debug box full",
    0x0504: "Router: unknown port type",
    0x0505: "Router: not initialized",
    0x0506: "Router: port already in use",
    0x0507: "Router: port not registered",
    0x0508: "Router: no more queues",
    0x0509: "Router: invalid port",
    0x050A: "Router: not activated",
    0x050B: "Router: fragment box full",
    0x050C: "Router: fragment timeout",
    0x050D: "Router: to be removed",
    # ADS device errors (0x0700-0x072F) - from AdsDef.h
    0x0700: "Device error",
    0x0701: "Service not supported",
    0x0702: "Invalid index group",
    0x0703: "Invalid index offset",
    0x0704: "Read/write not permitted",
    0x0705: "Parameter size invalid",
    0x0706: "Invalid data",
    0x0707: "Device not ready",
    0x0708: "Device busy",
    0x0709: "Invalid context",
    0x070A: "Out of memory",
    0x070B: "Invalid parameter",
    0x070C: "Not found",
    0x070D: "Syntax error",
    0x070E: "Incompatible",
    0x070F: "Object exists",
    0x0710: "Symbol not found",
    0x0711: "Symbol version invalid",
    0x0712: "Invalid device state",
    0x0713: "Transmode not supported",
    0x0714: "Notification handle invalid",
    0x0715: "Client unknown",
    0x0716: "No more handles",
    0x0717: "Invalid watch size",
    0x0718: "Not initialized",
    0x0719: "Timeout",
    0x071A: "No interface",
    0x071B: "Invalid interface",
    0x071C: "Invalid class ID",
    0x071D: "Invalid object ID",
    0x071E: "Request pending",
    0x071F: "Request aborted",
    0x0720: "Warning",
    0x0721: "Invalid array index",
    0x0722: "Symbol not active",
    0x0723: "Access denied",
    0x0724: "License not found",
    0x0725: "License expired",
    0x0726: "License exceeded",
    0x0727: "License invalid",
    0x0728: "License system ID",
    0x0729: "License no time limit",
    0x072A: "License future issue",
    0x072B: "License time too long",
    0x072C: "Exception",
    0x072D: "License duplicated",
    0x072E: "Signature invalid",
    0x072F: "Certificate invalid",
    # ADS client errors (0x0740-0x0755) - from packet-ams.h
    0x0740: "Client error",
    0x0741: "Client: invalid parameter",
    0x0742: "Client: list empty",
    0x0743: "Client: variable used",
    0x0744: "Client: duplicate invoke ID",
    0x0745: "Client: sync timeout",
    0x0746: "Client: Win32 error",
    0x0747: "Client: timeout invalid",
    0x0748: "Client: port not open",
    0x0749: "Client: no AMS address",
    0x0750: "Client: sync internal",
    0x0751: "Client: add hash failed",
    0x0752: "Client: remove hash failed",
    0x0753: "Client: no more symbols",
    0x0754: "Client: sync result invalid",
    0x0755: "Client: sync port locked",
}

# ---------------------------------------------------------------------------
# ADS State Map
# ---------------------------------------------------------------------------

ADS_STATE_MAP: Dict[int, str] = {
    0: "INVALID",
    1: "IDLE",
    2: "RESET",
    3: "INIT",
    4: "START",
    5: "RUN",
    6: "STOP",
    7: "SAVECFG",
    8: "LOADCFG",
    9: "POWERFAILURE",
    10: "POWERGOOD",
    11: "ERROR",
    12: "SHUTDOWN",
    13: "SUSPEND",
    14: "RESUME",
    15: "CONFIG",
    16: "RECONFIG",
    17: "STOPPING",
    18: "INCOMPATIBLE",
    19: "EXCEPTION",
}

# ---------------------------------------------------------------------------
# AMS Service Ports  (name -> port)
# ---------------------------------------------------------------------------

AMS_SERVICE_PORTS: Dict[str, int] = {
    # Core system services
    "ROUTER": 1,
    "DEBUGGER": 2,
    "TCOM_SERVER": 10,
    "TCOM_TASK": 11,
    "TCOM_PASSIVE": 12,
    "TC_DEBUGGER": 20,
    "TC_DEBUG_TASK": 21,
    "LICENSE_SVC": 30,
    "LOGGER": 100,
    "EVENT_LOG": 110,
    "DEVICE_APP": 120,
    "EVTLOG_UM": 130,
    "EVTLOG_RT": 131,
    "EVTLOG_PUB": 132,
    "REALTIME": 200,
    "TRACE": 290,
    "IO_DRIVER": 300,
    "R0_SPS": 400,  # Ring 0 PLC (from packet-ams.h)
    # Motion control subsystem
    "NC_AXIS": 500,
    "NC_SAF": 501,
    "NC_SVB": 511,
    "NC_INSTANCE": 520,
    "ISG_KERNEL": 550,
    "CNC_KERNEL": 600,
    "LINE_CTRL": 700,
    # PLC runtime environments
    "PLC_BASE": 800,
    "PLC_RT1": 801,  # TwinCAT 2 Runtime 1
    "PLC_RT2": 811,  # TwinCAT 2 Runtime 2
    "PLC_RT3": 821,  # TwinCAT 2 Runtime 3
    "PLC_RT4": 831,  # TwinCAT 2 Runtime 4
    "RTS_BASE": 850,
    "PLC3_RT1": 851,  # TwinCAT 3 Runtime 1
    "PLC3_RT2": 852,  # TwinCAT 3 Runtime 2
    "PLC3_RT3": 853,  # TwinCAT 3 Runtime 3
    "PLC3_RT4": 854,  # TwinCAT 3 Runtime 4
    "PLC3_RT5": 855,  # TwinCAT 3 Runtime 5
    # EtherCAT subsystem
    "ECAT_SLV1": 1001,
    "ECAT_SLV2": 1002,
    "ECAT_TASK": 1003,
    "ECAT_SLV4": 1004,
    "ECAT_SLV5": 1005,
    "ECAT_SLV6": 1006,
    "ECAT_MASTER": 65535,
    # Application ports
    "CAM_CTRL": 900,
    "CAM_TOOL": 950,
    "USER_BASE": 2000,
    # System services (R3 layer)
    "SYS_SERVICE": 10000,
    "SYS_CTRL": 10001,
    "SYS_SAMPLER": 10100,
    "TCP_RAW": 10200,
    "TCP_SERVER": 10201,
    "SYS_MANAGER": 10300,
    "SMS_SERVER": 10400,
    "MODBUS_GW": 10500,
    "AMS_LOGGER": 10502,
    "XML_SERVER": 10600,
    "AUTO_CONFIG": 10700,
    "PLC_CONTROL": 10800,
    "FTP_CLIENT": 10900,
    "NC_CTRL": 11000,
    "NC_INTERP": 11500,
    "GST_INTERP": 11600,
    "STRECKE": 12000,
    "CAM_SERVER": 13000,
    "SCOPE_SVC": 14000,
    "CONDITION_MON": 14100,
    "SINE_CH1": 15000,
    "CONTROLNET": 16000,
    "OPC_SERVER": 17000,
    "OPC_CLIENT": 17500,
    "MAIL_SERVER": 18000,
    "EL60XX_DRV": 19000,
    "MGMT_SVC": 19100,
    "CPLINK3": 19300,
    "VN_SERVICE": 19500,
    "MULTIUSER": 19600,
}

# Reverse lookup: port -> name (for decoding captured packets)
AMS_PORT_NAMES: Dict[int, str] = {v: k for k, v in AMS_SERVICE_PORTS.items()}

# ---------------------------------------------------------------------------
# ADS Port Map  (common PLC runtime ports, subset)
# ---------------------------------------------------------------------------

ADS_PORT_MAP: Dict[str, int] = {
    "TC3PLC1": 851,
    "TC3PLC2": 852,
    "TC3PLC3": 853,
    "TC3PLC4": 854,
    "SPS1": 801,
    "SPS2": 811,
    "SPS3": 821,
    "SPS4": 831,
    "NC": 500,
    "CNC": 100,
    "NCSAF": 501,
    "CUSTOMER1": 900,
    "CUSTOMER2": 901,
    "ECAT_TASK": 1003,
    "ECAT_MASTER": 65535,
}

# ---------------------------------------------------------------------------
# ADS Transport Layer
# ---------------------------------------------------------------------------

ADS_TRANSPORT: Dict[str, int] = {
    "TCP": 48898,  # Standard ADS over TCP
    "TLS": 8016,  # ADS over TLS 1.2 (Secure ADS)
    "UDP": 48899,  # ADS discovery broadcast
}

# ---------------------------------------------------------------------------
# ADS UDP Discovery Protocol
# ---------------------------------------------------------------------------

ADS_UDP_MAGIC: int = 0x71146603  # Beckhoff UDP protocol signature (LE: 03 66 14 71)
ADS_UDP_SVC_IDENTIFY: int = 1  # Query remote system info

ADS_UDP_TAG: Dict[str, int] = {
    "STATUS": 1,
    "PASSWORD": 2,
    "TC_VERSION": 3,
    "OS_VERSION": 4,
    "HOSTNAME": 5,
    "NETID": 7,
    "OPTIONS": 9,
    "ROUTE_NAME": 12,
    "USERNAME": 13,
    "FINGERPRINT": 18,
}

# ---------------------------------------------------------------------------
# File Access Flags (for FILE_OPEN index group)
# ---------------------------------------------------------------------------

ADS_FILE_FLAG: Dict[str, int] = {
    "READ": 0x01,
    "WRITE": 0x02,
    "APPEND": 0x04,
    "BINARY": 0x10,
    "TEXT": 0x20,
    "ENSURE_DIR": 0x40,
    "ENABLE_DIR": 0x80,
    "OVERWRITE": 0x100,
}

# ---------------------------------------------------------------------------
# I/O Image Constants
# ---------------------------------------------------------------------------

# Aliases for the I/O image byte index groups (same values as the
# ADS_IDX_GRP IO_INPUT_BYTE / IO_OUTPUT_BYTE entries above).
INDEXGROUP_IOIMAGE_RWIB: int = ADS_IDX_GRP["IO_INPUT_BYTE"]  # Input image read/write byte
INDEXGROUP_IOIMAGE_RWOB: int = ADS_IDX_GRP["IO_OUTPUT_BYTE"]  # Output image read/write byte

# ---------------------------------------------------------------------------
# Timeout Constants (all milliseconds unless noted)
# ---------------------------------------------------------------------------

ADS_TIMEOUT_MS: int = 500  # ADS operation timeout (probes, CoE, device info)
ADS_TLS_TIMEOUT: int = 5  # TLS socket connect (seconds)
ADS_UDP_TIMEOUT: float = 0.5  # UDP discovery response (seconds)
ADS_FUZZ_DELAY: float = 0.05  # Inter-mutation delay, CoE fuzz (seconds)
ADS_FUZZ_SYMBOL_DELAY: float = 0.1  # Inter-write delay, symbol fuzz (seconds)
