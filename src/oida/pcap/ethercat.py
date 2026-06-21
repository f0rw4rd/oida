"""
EtherCAT Passive Listener (PyShark-based).

Passively monitors EtherCAT (EtherType 0x88A4) traffic to identify:
- EtherCAT master and slave devices on the network
- Datagram commands (APRD, APWR, FPRD, FPWR, BRD, BWR, LRD, LWR, etc.)
- Slave addresses and memory offsets being accessed
- Working Counter (WKC) values for slave health monitoring
- Read vs write vs read-write operation classification
- Memory regions of interest (AL Status, EEPROM, SyncManager, DC, etc.)
- Mailbox protocols: CoE (SDO transfers), FoE (firmware uploads), SoE (servo)

EtherCAT is a Layer 2 protocol (EtherType 0x88A4) with no IP stack.
Frames travel in a daisy-chain through all slaves and return to the master.
Each frame can contain multiple datagrams, each targeting different slaves
or memory regions. The Working Counter (WKC) is incremented by each slave
that successfully processes a datagram -- a WKC of 0 means no slave
responded, which may indicate a cable break or slave failure.

Protocol format:
- Ethernet header: dst MAC (typically broadcast or slave MAC), src MAC,
  EtherType 0x88A4
- EtherCAT frame header: Length (11 bits), Reserved (1 bit), Type (4 bits)
- Datagram(s), each containing:
  - Command (1 byte): operation type (NOP, APRD, APWR, etc.)
  - Index (1 byte): frame index
  - Slave Address (2 bytes) / Logical Address (4 bytes): target address
  - Offset Address (2 bytes): memory offset within slave (physical commands)
  - Length (11 bits): data length, plus flags (circulating, more datagrams)
  - Data (variable): payload
  - Working Counter (2 bytes): incremented by addressed slaves

Command types:
- Auto-increment (AP*): address by position in daisy-chain
- Configured/Fixed (FP*): address by configured station address
- Broadcast (B*): all slaves
- Logical (L*): logical address mapping
- Suffix: RD=read, WR=write, RW=read-write, MW=multi-write

tshark fields used:
- ecat.cmd: Command type (FT_UINT8, BASE_HEX)
- ecat.adp: Slave address / physical address (FT_UINT16, BASE_HEX)
- ecat.ado: Offset address within slave (FT_UINT16, BASE_HEX)
- ecat.lad: Logical address (FT_UINT32, BASE_HEX) -- for L* commands
- ecat.cnt: Working Counter (FT_UINT16, BASE_DEC)
- ecat.idx: Frame index (FT_UINT8, BASE_HEX)
- ecat.subframe.length: Datagram data length (FT_UINT16, BASE_DEC)
- ecat.sub1.cmd .. ecat.sub10.cmd: Sub-datagram commands

Mailbox protocol fields (exposed on ecat layer as ecat_mailbox_*):
- ecat_mailbox.type: Mailbox type (1=ERR, 2=AoE, 3=CoE, 4=FoE, 5=SoE)
- ecat_mailbox.coe.type: CoE type (2=SDO Request, 3=SDO Response)
- ecat_mailbox.coe.sdoreq: SDO request command (1=Download, 3=Upload)
- ecat_mailbox.coe.sdores: SDO response command (3=Upload Initiated)
- ecat_mailbox.coe.sdoidx: Object Dictionary index (FT_UINT16, BASE_HEX)
- ecat_mailbox.coe.sdosub: SubIndex (FT_UINT8, BASE_HEX)
- ecat_mailbox.coe.sdodata: Expedited data (FT_UINT32, BASE_HEX)
- ecat_mailbox.coe.dsoldata: Variable-length data (FT_BYTES)
- ecat_mailbox.coe.sdolength: Data length (FT_UINT32, BASE_HEX)
- ecat_mailbox.coe.abortcode: Abort code (FT_UINT32, BASE_HEX)
- ecat_mailbox.foe_opmode: FoE operation mode (FT_UINT8, BASE_HEX)
- ecat_mailbox.foe_filename: Firmware/file name (FT_STRING)
- ecat_mailbox.foe_filelength: File size (FT_UINT32, BASE_DEC)
- ecat_mailbox.foe_packetno: Packet number (FT_UINT16, BASE_DEC)
- ecat_mailbox.foe_errcode: Error code (FT_UINT32, BASE_DEC)
- ecat_mailbox.foe_errtext: Error text (FT_STRING)
- ecat_mailbox.soe_opcode: SoE operation code (FT_UINT16, BASE_DEC)
- ecat_mailbox.soe_header_driveno: Drive number (FT_UINT16, BASE_DEC)
- ecat_mailbox.soe_idn: IDN identifier (FT_UINT16, BASE_HEX)
- ecat_mailbox.soe_header_error: Error flag (FT_BOOLEAN)

References:
- ETG.1000: EtherCAT Specification
- EtherType 0x88A4 (IEEE registered)
- Wireshark dissector: packet-ecat.c, packet-ecatmb.c
"""

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import lookup_mac_vendor

import logging

logger = logging.getLogger(__name__)


# EtherCAT datagram command codes (ETG.1000.4)
ECAT_COMMANDS: Dict[int, str] = {
    0x00: "NOP",  # No Operation
    0x01: "APRD",  # Auto Increment Physical Read
    0x02: "APWR",  # Auto Increment Physical Write
    0x03: "APRW",  # Auto Increment Physical Read Write
    0x04: "FPRD",  # Configured Address Physical Read
    0x05: "FPWR",  # Configured Address Physical Write
    0x06: "FPRW",  # Configured Address Physical Read Write
    0x07: "BRD",  # Broadcast Read
    0x08: "BWR",  # Broadcast Write
    0x09: "BRW",  # Broadcast Read Write
    0x0A: "LRD",  # Logical Memory Read
    0x0B: "LWR",  # Logical Memory Write
    0x0C: "LRW",  # Logical Memory Read Write
    0x0D: "ARMW",  # Auto Increment Physical Read Multiple Write
    0x0E: "FRMW",  # Configured Address Physical Read Multiple Write
}

# Command classification: command_code -> "read" | "write" | "read-write" | "nop"
COMMAND_RW: Dict[int, str] = {
    0x00: "nop",
    0x01: "read",
    0x04: "read",
    0x07: "read",
    0x0A: "read",
    0x02: "write",
    0x05: "write",
    0x08: "write",
    0x0B: "write",
    0x03: "rw",
    0x06: "rw",
    0x09: "rw",
    0x0C: "rw",
    0x0D: "rw",
    0x0E: "rw",
}

# Write commands that might modify slave state (for alerting)
WRITE_COMMANDS = {0x02, 0x03, 0x05, 0x06, 0x08, 0x09, 0x0B, 0x0C, 0x0D, 0x0E}

# Notable ESC register offsets for enriched display
ESC_REGISTER_NAMES: Dict[int, str] = {
    0x0000: "Type",
    0x0001: "Revision",
    0x0002: "Build",
    0x0010: "Station Address",
    0x0012: "Station Alias",
    0x0100: "DL Control",
    0x0110: "DL Status",
    0x0120: "AL Control",
    0x0130: "AL Status",
    0x0134: "AL Status Code",
    0x0140: "PDI Control",
    0x0200: "ECAT Event Mask",
    0x0220: "ECAT Event Request",
    0x0300: "Error Counter Port 0",
    0x0302: "Error Counter Port 1",
    0x0304: "Error Counter Port 2",
    0x0306: "Error Counter Port 3",
    0x0420: "Watchdog Divider",
    0x0440: "Watchdog SM",
    0x0442: "Watchdog PDO",
    0x0500: "SII EEPROM",
    0x0502: "SII EEPROM Ctrl",
    0x0504: "SII EEPROM Addr",
    0x0508: "SII EEPROM Data",
    0x0600: "FMMU0",
    0x0610: "FMMU1",
    0x0620: "FMMU2",
    0x0630: "FMMU3",
    0x0800: "SM0",
    0x0808: "SM1",
    0x0810: "SM2",
    0x0818: "SM3",
    0x0900: "DC RecvTime Port 0",
    0x0904: "DC RecvTime Port 1",
    0x0908: "DC RecvTime Port 2",
    0x090C: "DC RecvTime Port 3",
    0x0910: "DC SysTime",
    0x0918: "DC RecvTime64",
    0x0920: "DC SysTimeOffs",
    0x0928: "DC SysTimeDelay",
    0x0930: "DC SpeedStart",
    0x0980: "DC CycUnitCtrl",
    0x0981: "DC Activation",
    0x0990: "DC StartTime0",
    0x09A0: "DC CycTime0",
}

# Maximum number of sub-datagrams tshark dissects
_MAX_SUB_DATAGRAMS = 10

# AL Status state values (ecat.reg.alstatus.status, ETG.1000.6 Table 9)
AL_STATUS_NAMES: Dict[int, str] = {
    0x01: "Init",
    0x02: "Pre-Operational",
    0x03: "Bootstrap",
    0x04: "Safe-Operational",
    0x08: "Operational",
}

# Common AL Status Codes (ecat.reg.alstatuscode, ETG.1000.6 Table 11)
AL_STATUS_CODE_NAMES: Dict[int, str] = {
    0x0000: "No error",
    0x0001: "Unspecified error",
    0x0011: "Invalid requested state change",
    0x0012: "Unknown requested state",
    0x0013: "Bootstrap not supported",
    0x0014: "No valid firmware",
    0x0015: "Invalid mailbox configuration (Bootstrap)",
    0x0016: "Invalid mailbox configuration (Pre-Op)",
    0x0017: "Invalid sync manager configuration",
    0x0018: "No valid inputs available",
    0x0019: "No valid outputs",
    0x001A: "Synchronization error",
    0x001B: "Sync manager watchdog",
    0x001C: "Invalid sync manager types",
    0x001D: "Invalid output configuration",
    0x001E: "Invalid input configuration",
    0x001F: "Invalid watchdog configuration",
    0x0020: "Slave needs cold start",
    0x0021: "Slave needs INIT",
    0x0022: "Slave needs Pre-Op",
    0x0023: "Slave needs Safe-Op",
    0x002D: "Invalid output FMMU configuration",
    0x002E: "Invalid input FMMU configuration",
    0x0030: "Invalid DC SYNC configuration",
    0x0031: "Invalid DC latch configuration",
    0x0032: "PLL error",
    0x0033: "DC sync I/O error",
    0x0034: "DC sync timeout error",
    0x0035: "DC invalid sync cycle time",
    0x0036: "DC sync0 cycle time",
    0x0042: "MBX_AOE",
    0x0043: "MBX_EOE",
    0x0044: "MBX_COE",
    0x0045: "MBX_FOE",
    0x0046: "MBX_SOE",
    0x004F: "MBX_VOE",
}

# --------------------------------------------------------------------------
# Mailbox protocol constants (ETG.1000.6)
# --------------------------------------------------------------------------

# Mailbox types (ecat_mailbox.type)
MAILBOX_TYPE_ERR = 0
MAILBOX_TYPE_AOE = 1  # ADS over EtherCAT
MAILBOX_TYPE_EOE = 2  # Ethernet over EtherCAT
MAILBOX_TYPE_COE = 3  # CAN over EtherCAT
MAILBOX_TYPE_FOE = 4  # File over EtherCAT
MAILBOX_TYPE_SOE = 5  # Servo over EtherCAT

MAILBOX_TYPE_NAMES: Dict[int, str] = {
    MAILBOX_TYPE_ERR: "ERR",
    MAILBOX_TYPE_AOE: "AoE",
    MAILBOX_TYPE_EOE: "EoE",
    MAILBOX_TYPE_COE: "CoE",
    MAILBOX_TYPE_FOE: "FoE",
    MAILBOX_TYPE_SOE: "SoE",
}

# CoE types (ecat_mailbox.coe.type)
COE_TYPE_EMERGENCY = 1
COE_TYPE_SDO_REQ = 2
COE_TYPE_SDO_RES = 3
COE_TYPE_TXPDO = 4
COE_TYPE_RXPDO = 5
COE_TYPE_TXPDO_REMOTE = 6
COE_TYPE_RXPDO_REMOTE = 7
COE_TYPE_SDO_INFO = 8

COE_TYPE_NAMES: Dict[int, str] = {
    COE_TYPE_EMERGENCY: "Emergency",
    COE_TYPE_SDO_REQ: "SDO Request",
    COE_TYPE_SDO_RES: "SDO Response",
    COE_TYPE_TXPDO: "TxPDO",
    COE_TYPE_RXPDO: "RxPDO",
    COE_TYPE_TXPDO_REMOTE: "TxPDO Remote",
    COE_TYPE_RXPDO_REMOTE: "RxPDO Remote",
    COE_TYPE_SDO_INFO: "SDO Info",
}

# SDO request command specifiers (ecat_mailbox.coe.sdoreq)
SDO_REQ_DOWNLOAD = 1  # Initiate Download (write to device)
SDO_REQ_DOWNLOAD_SEG = 2  # Download Segment
SDO_REQ_UPLOAD = 3  # Initiate Upload (read from device)
SDO_REQ_UPLOAD_SEG = 4  # Upload Segment
SDO_REQ_ABORT = 5  # Abort Transfer

SDO_REQ_NAMES: Dict[int, str] = {
    SDO_REQ_DOWNLOAD: "SDO Download",
    SDO_REQ_DOWNLOAD_SEG: "SDO Download Segment",
    SDO_REQ_UPLOAD: "SDO Upload",
    SDO_REQ_UPLOAD_SEG: "SDO Upload Segment",
    SDO_REQ_ABORT: "SDO Abort",
}

# SDO response command specifiers (ecat_mailbox.coe.sdores)
SDO_RES_DOWNLOAD = 1  # Download Initiated
SDO_RES_DOWNLOAD_SEG = 2  # Download Segment
SDO_RES_UPLOAD = 3  # Upload Initiated
SDO_RES_UPLOAD_SEG = 4  # Upload Segment

SDO_RES_NAMES: Dict[int, str] = {
    SDO_RES_DOWNLOAD: "SDO Download Response",
    SDO_RES_DOWNLOAD_SEG: "SDO Download Seg Response",
    SDO_RES_UPLOAD: "SDO Upload Response",
    SDO_RES_UPLOAD_SEG: "SDO Upload Seg Response",
}

# FoE operation modes (ecat_mailbox.foe_opmode)
FOE_OP_READ = 1  # Read request (download from device)
FOE_OP_WRITE = 2  # Write request (upload to device / firmware)
FOE_OP_DATA = 3  # Data packet
FOE_OP_ACK = 4  # Acknowledgment
FOE_OP_ERROR = 5  # Error
FOE_OP_BUSY = 6  # Busy

FOE_OP_NAMES: Dict[int, str] = {
    FOE_OP_READ: "FoE Read",
    FOE_OP_WRITE: "FoE Write",
    FOE_OP_DATA: "FoE Data",
    FOE_OP_ACK: "FoE Ack",
    FOE_OP_ERROR: "FoE Error",
    FOE_OP_BUSY: "FoE Busy",
}

# SoE operation codes (ecat_mailbox.soe_opcode)
SOE_OP_READ_REQ = 1  # Read request
SOE_OP_READ_RES = 2  # Read response
SOE_OP_WRITE_REQ = 3  # Write request
SOE_OP_WRITE_RES = 4  # Write response
SOE_OP_NOTIFICATION = 5  # Notification (async)

SOE_OP_NAMES: Dict[int, str] = {
    SOE_OP_READ_REQ: "SoE Read",
    SOE_OP_READ_RES: "SoE Read Response",
    SOE_OP_WRITE_REQ: "SoE Write",
    SOE_OP_WRITE_RES: "SoE Write Response",
    SOE_OP_NOTIFICATION: "SoE Notification",
}

# Critical OD index ranges -- SDO writes to these are security-relevant
# 0x1000-0x1FFF: Communication parameters (SM/PDO mapping)
# 0x6000-0x6FFF: Input area (device-specific)
# 0x7000-0x7FFF: Output area (device-specific)
# 0xF000-0xFFFF: Device-specific diagnostic / configuration
CRITICAL_OD_RANGES: List[Tuple[int, int, str]] = [
    (0x1600, 0x17FF, "RxPDO Mapping"),
    (0x1A00, 0x1BFF, "TxPDO Mapping"),
    (0x1C00, 0x1C33, "SM PDO Assignment"),
    (0xF000, 0xFFFF, "Device Configuration"),
]


@dataclass
class EtherCATMaster:
    """Track an EtherCAT master (identified by source MAC)."""

    mac: str
    vendor: str = ""
    slave_addrs_seen: Set[int] = field(default_factory=set)
    logical_addrs_seen: Set[int] = field(default_factory=set)
    commands_used: Counter = field(default_factory=Counter)
    total_frames: int = 0
    total_datagrams: int = 0
    write_datagrams: int = 0
    read_datagrams: int = 0
    wkc_zero_count: int = 0
    offsets_seen: Set[int] = field(default_factory=set)
    first_seen: str = ""
    last_seen: str = ""
    # Mailbox statistics
    coe_sdo_downloads: int = 0
    coe_sdo_uploads: int = 0
    coe_sdo_aborts: int = 0
    coe_od_indices_seen: Set[str] = field(default_factory=set)
    foe_transfers: int = 0
    foe_filenames: Set[str] = field(default_factory=set)
    soe_operations: int = 0
    soe_drives_seen: Set[int] = field(default_factory=set)
    # Register-level fields (from dissected ESC register content)
    esc_type: Optional[int] = None
    esc_revision: Optional[int] = None
    esc_build: Optional[int] = None
    al_status_states_seen: Set[int] = field(default_factory=set)
    al_status_codes_seen: Set[int] = field(default_factory=set)
    syncman_enabled: bool = False
    dc_cyclic_enabled: bool = False
    dl_port_states: Dict[str, Any] = field(default_factory=dict)


class EtherCATPassiveListener(PySharkListenerBase):
    """Passive EtherCAT traffic listener (PyShark-based).

    Monitors EtherCAT traffic without sending packets to:
    - Identify master devices by source MAC address
    - Track slave addresses and memory offsets being accessed
    - Classify operations as read, write, or read-write
    - Monitor Working Counter (WKC) for slave health
    - Detect write operations to critical ESC registers
    - Map logical and physical address usage
    - Extract CoE/SDO transfers (Object Dictionary access)
    - Detect FoE file/firmware transfers (high security risk)
    - Track SoE servo drive access

    EtherCAT is Layer 2 only (EtherType 0x88A4) -- there are no IP addresses.
    Devices are keyed by MAC address. The master is the frame source; slaves
    process datagrams in transit but do not originate frames.

    Usage:
        listener = EtherCATPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Access master statistics
        for master in listener.masters.values():
            print(f"Master {master.mac}: {master.total_frames} frames")
            print(f"  Slaves seen: {sorted(master.slave_addrs_seen)}")
            print(f"  WKC=0 count: {master.wkc_zero_count}")

    Data stored in device.ethercat_passive_data:
        {
            "role": "master",
            "slave_addresses": [0, 1, 2],
            "commands_used": {"LRW": 500, "FPRD": 120},
            "total_frames": 1000,
            "total_datagrams": 3200,
            "write_datagrams": 800,
            "wkc_zero_count": 5,
            "protocol": "EtherCAT/L2",
        }
    """

    PROTOCOL_NAME = "ethercat"
    DISPLAY_FILTER = "ecat"
    REQUIRED_LAYERS = ("ecat",)
    PROTOCOL_COLUMNS = (
        "command",
        "slave_addr",
        "offset",
        "length",
        "wkc",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize EtherCAT passive listener."""
        super().__init__(interface, timeout, nxc_logger)
        self.masters: Dict[str, EtherCATMaster] = {}

    def process_packet(self, packet) -> None:
        """Process an EtherCAT packet using PyShark dissection.

        A single EtherCAT Ethernet frame can contain multiple datagrams.
        PyShark exposes the first datagram via ecat.cmd/adp/ado/cnt and
        additional datagrams via ecat.sub1.cmd, ecat.sub2.cmd, etc.
        We process all available datagrams.

        Mailbox protocol fields (CoE, FoE, SoE) are embedded in the ecat
        layer as ecat_mailbox_* attributes by PyShark. After datagram
        processing we check for mailbox content.
        """
        if not hasattr(packet, "ecat"):
            return

        ecat_layer = packet.ecat

        # EtherCAT is Layer 2 -- extract MAC addresses (no IP)
        src_mac, dst_mac = self.get_mac_info(packet)
        if not src_mac:
            return

        # Update or create master tracker
        master = self._ensure_master(src_mac)
        master.total_frames += 1

        now = datetime.now().isoformat()
        flow_id = self.get_flow_id(packet)

        # Process primary datagram (ecat.cmd, ecat.adp, ecat.ado, ecat.cnt)
        self._process_datagram(
            ecat_layer,
            master,
            src_mac,
            dst_mac,
            now,
            flow_id,
            cmd_field="cmd",
            adp_field="adp",
            ado_field="ado",
            cnt_field="cnt",
            lad_field="lad",
            len_field="subframe_length",
        )

        # Process sub-datagrams (ecat.sub1.cmd .. ecat.sub10.cmd)
        for i in range(1, _MAX_SUB_DATAGRAMS + 1):
            cmd_field = f"sub{i}_cmd"
            # Check if this sub-datagram exists
            if self.get_field(ecat_layer, cmd_field) is None:
                break
            self._process_datagram(
                ecat_layer,
                master,
                src_mac,
                dst_mac,
                now,
                flow_id,
                cmd_field=cmd_field,
                adp_field=f"sub{i}_adp",
                ado_field=f"sub{i}_ado",
                cnt_field=f"sub{i}_cnt",
                lad_field=f"sub{i}_lad",
                len_field=None,
            )

        # Process mailbox protocols (CoE/FoE/SoE) if present
        self._process_mailbox(ecat_layer, master, src_mac, dst_mac, now, flow_id)

        # Extract register-level fields (AL status, DL status, SyncManager, DC, etc.)
        self._process_register_fields(ecat_layer, master, src_mac, dst_mac, now, flow_id)

        # Update device entries
        self._update_device(src_mac, master)

    # Datagram field names referenced via variable indirection below;
    # listed here for audit tool visibility.
    _DATAGRAM_FIELDS = ("cmd", "adp", "ado", "cnt", "lad", "subframe_length")

    def _process_datagram(
        self,
        ecat_layer,
        master: EtherCATMaster,
        src_mac: str,
        dst_mac: str,
        now: str,
        flow_id: str,
        *,
        cmd_field: str,
        adp_field: str,
        ado_field: str,
        cnt_field: str,
        lad_field: str,
        len_field: Optional[str],
    ) -> None:
        """Process a single EtherCAT datagram from the packet."""
        cmd_raw = self.get_field(ecat_layer, cmd_field)
        if cmd_raw is None:
            return

        cmd_int = self._parse_hex_int(cmd_raw, -1)
        if cmd_int < 0:
            return

        cmd_name = ECAT_COMMANDS.get(cmd_int, f"0x{cmd_int:02x}")
        rw = COMMAND_RW.get(cmd_int, "")

        # Parse slave address (physical) or logical address
        slave_addr = self._parse_hex_int(self.get_field(ecat_layer, adp_field), None)
        offset = self._parse_hex_int(self.get_field(ecat_layer, ado_field), None)
        logical_addr = self._parse_hex_int(self.get_field(ecat_layer, lad_field), None)
        wkc = self._parse_int(self.get_field(ecat_layer, cnt_field), None)
        data_len = (
            self._parse_int(self.get_field(ecat_layer, len_field), None) if len_field else None
        )

        # Update master statistics
        master.total_datagrams += 1
        master.commands_used[cmd_name] += 1

        if rw == "write" or rw == "rw":
            master.write_datagrams += 1
        if rw == "read" or rw == "rw":
            master.read_datagrams += 1

        if wkc is not None and wkc == 0 and cmd_int != 0x00:
            master.wkc_zero_count += 1

        # Track slave addresses (physical addressing commands: AP*, FP*, B*)
        if slave_addr is not None and cmd_int in range(0x01, 0x0A):
            master.slave_addrs_seen.add(slave_addr)

        # Track logical addresses (L* commands)
        if logical_addr is not None and cmd_int in (0x0A, 0x0B, 0x0C):
            master.logical_addrs_seen.add(logical_addr)

        # Track offsets (for physical commands)
        if offset is not None and cmd_int in range(0x01, 0x0A):
            master.offsets_seen.add(offset)

        # Build address display string
        if cmd_int in (0x0A, 0x0B, 0x0C) and logical_addr is not None:
            addr_str = f"0x{logical_addr:08x}"
            offset_str = ""
        else:
            addr_str = f"0x{slave_addr:04x}" if slave_addr is not None else ""
            offset_str = self._format_offset(offset) if offset is not None else ""

        # Build interaction details
        details: Dict[str, Any] = {
            "command": cmd_name,
            "command_code": cmd_int,
            "rw": rw,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
        }
        if slave_addr is not None:
            details["slave_addr"] = slave_addr
        if offset is not None:
            details["offset"] = offset
        if logical_addr is not None:
            details["logical_addr"] = logical_addr
        if wkc is not None:
            details["wkc"] = wkc
        if data_len is not None:
            details["length"] = data_len

        summary = self._build_summary(cmd_name, rw, addr_str, offset_str, wkc)

        self._record_interaction(
            now,
            src_mac,
            "",  # no dst_ip for L2
            "request",  # master always initiates
            cmd_name,
            details,
            summary,
            flow_id=flow_id,
        )

    # ------------------------------------------------------------------
    # Mailbox protocol processing
    # ------------------------------------------------------------------

    def _process_mailbox(
        self,
        ecat_layer,
        master: EtherCATMaster,
        src_mac: str,
        dst_mac: str,
        now: str,
        flow_id: str,
    ) -> None:
        """Process EtherCAT mailbox protocols embedded in the ecat layer.

        PyShark exposes mailbox fields on the ecat layer with the naming
        convention ecat_mailbox_* (dots replaced by underscores). We check
        for ecat_mailbox_type to detect mailbox content, then dispatch to
        protocol-specific handlers.
        """
        mb_type_raw = self.get_field(ecat_layer, "ecat_mailbox_type")
        if mb_type_raw is None:
            return

        mb_type = self._parse_int(mb_type_raw, -1)
        if mb_type < 0:
            return

        if mb_type == MAILBOX_TYPE_COE:
            self._process_coe(ecat_layer, master, src_mac, dst_mac, now, flow_id)
        elif mb_type == MAILBOX_TYPE_FOE:
            self._process_foe(ecat_layer, master, src_mac, dst_mac, now, flow_id)
        elif mb_type == MAILBOX_TYPE_SOE:
            self._process_soe(ecat_layer, master, src_mac, dst_mac, now, flow_id)

    def _process_coe(
        self,
        ecat_layer,
        master: EtherCATMaster,
        src_mac: str,
        dst_mac: str,
        now: str,
        flow_id: str,
    ) -> None:
        """Process CoE (CAN over EtherCAT) mailbox content.

        Handles SDO Request/Response as well as SDO Info operations.
        """
        coe_type = self._parse_int(self.get_field(ecat_layer, "ecat_mailbox_coe_type"), -1)
        if coe_type < 0:
            return

        if coe_type == COE_TYPE_SDO_REQ:
            self._process_coe_sdo_request(ecat_layer, master, src_mac, dst_mac, now, flow_id)
        elif coe_type == COE_TYPE_SDO_RES:
            self._process_coe_sdo_response(ecat_layer, master, src_mac, dst_mac, now, flow_id)

    def _process_coe_sdo_request(
        self,
        ecat_layer,
        master: EtherCATMaster,
        src_mac: str,
        dst_mac: str,
        now: str,
        flow_id: str,
    ) -> None:
        """Process an SDO Request (CoE type 2)."""
        sdo_req = self._parse_int(self.get_field(ecat_layer, "ecat_mailbox_coe_sdoreq"), -1)
        if sdo_req < 0:
            return

        # Extract common SDO fields
        idx_raw = self.get_field(ecat_layer, "ecat_mailbox_coe_sdoidx")
        sub_raw = self.get_field(ecat_layer, "ecat_mailbox_coe_sdosub")
        data_raw = self.get_field(ecat_layer, "ecat_mailbox_coe_sdodata")
        dsoldata_raw = self.get_field(ecat_layer, "ecat_mailbox_coe_dsoldata")
        length_raw = self.get_field(ecat_layer, "ecat_mailbox_coe_sdolength")
        abort_raw = self.get_field(ecat_layer, "ecat_mailbox_coe_abortcode")

        idx = self._parse_hex_int(idx_raw, None)
        sub = self._parse_hex_int(sub_raw, None)

        operation = SDO_REQ_NAMES.get(sdo_req, f"SDO Req {sdo_req}")
        direction = "request"

        # Update master statistics
        if sdo_req in (SDO_REQ_DOWNLOAD, SDO_REQ_DOWNLOAD_SEG):
            master.coe_sdo_downloads += 1
        elif sdo_req in (SDO_REQ_UPLOAD, SDO_REQ_UPLOAD_SEG):
            master.coe_sdo_uploads += 1
        elif sdo_req == SDO_REQ_ABORT:
            master.coe_sdo_aborts += 1

        # Track OD index:subindex
        if idx is not None:
            idx_str = f"0x{idx:04x}" if idx is not None else ""
            sub_str = f"0x{sub:02x}" if sub is not None else ""
            od_key = f"{idx_str}:{sub_str}" if sub is not None else idx_str
            master.coe_od_indices_seen.add(od_key)

        # Build details
        details: Dict[str, Any] = {
            "command": operation,
            "mailbox_type": "CoE",
            "coe_type": "SDO Request",
            "sdo_command": sdo_req,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
        }
        if idx is not None:
            details["od_index"] = f"0x{idx:04x}"
        if sub is not None:
            details["od_subindex"] = f"0x{sub:02x}"
        if data_raw is not None:
            details["sdo_data"] = str(data_raw)
        if dsoldata_raw is not None:
            details["sdo_long_data"] = str(dsoldata_raw)
        if length_raw is not None:
            details["sdo_length"] = str(length_raw)
        if abort_raw is not None:
            details["abort_code"] = str(abort_raw)

        # Build summary
        parts = [operation]
        if idx is not None:
            od_display = f"0x{idx:04x}:{sub:02x}" if sub is not None else f"0x{idx:04x}"
            parts.append(f"OD={od_display}")
        if data_raw is not None:
            parts.append(f"data={data_raw}")
        summary = " ".join(parts)

        self._record_interaction(
            now, src_mac, "", direction, operation, details, summary, flow_id=flow_id
        )

    def _process_coe_sdo_response(
        self,
        ecat_layer,
        master: EtherCATMaster,
        src_mac: str,
        dst_mac: str,
        now: str,
        flow_id: str,
    ) -> None:
        """Process an SDO Response (CoE type 3)."""
        sdo_res = self._parse_int(self.get_field(ecat_layer, "ecat_mailbox_coe_sdores"), -1)
        if sdo_res < 0:
            return

        # Extract common SDO fields
        idx_raw = self.get_field(ecat_layer, "ecat_mailbox_coe_sdoidx")
        sub_raw = self.get_field(ecat_layer, "ecat_mailbox_coe_sdosub")
        data_raw = self.get_field(ecat_layer, "ecat_mailbox_coe_sdodata")
        dsoldata_raw = self.get_field(ecat_layer, "ecat_mailbox_coe_dsoldata")
        length_raw = self.get_field(ecat_layer, "ecat_mailbox_coe_sdolength")
        abort_raw = self.get_field(ecat_layer, "ecat_mailbox_coe_abortcode")

        idx = self._parse_hex_int(idx_raw, None)
        sub = self._parse_hex_int(sub_raw, None)

        operation = SDO_RES_NAMES.get(sdo_res, f"SDO Res {sdo_res}")
        direction = "response"

        # Build details
        details: Dict[str, Any] = {
            "command": operation,
            "mailbox_type": "CoE",
            "coe_type": "SDO Response",
            "sdo_command": sdo_res,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
        }
        if idx is not None:
            details["od_index"] = f"0x{idx:04x}"
        if sub is not None:
            details["od_subindex"] = f"0x{sub:02x}"
        if data_raw is not None:
            details["sdo_data"] = str(data_raw)
        if dsoldata_raw is not None:
            details["sdo_long_data"] = str(dsoldata_raw)
        if length_raw is not None:
            details["sdo_length"] = str(length_raw)
        if abort_raw is not None:
            details["abort_code"] = str(abort_raw)

        # Build summary
        parts = [operation]
        if idx is not None:
            od_display = f"0x{idx:04x}:{sub:02x}" if sub is not None else f"0x{idx:04x}"
            parts.append(f"OD={od_display}")
        if data_raw is not None:
            parts.append(f"data={data_raw}")
        summary = " ".join(parts)

        self._record_interaction(
            now, src_mac, "", direction, operation, details, summary, flow_id=flow_id
        )

    def _process_foe(
        self,
        ecat_layer,
        master: EtherCATMaster,
        src_mac: str,
        dst_mac: str,
        now: str,
        flow_id: str,
    ) -> None:
        """Process FoE (File over EtherCAT) mailbox content.

        FoE is used for firmware updates and file transfers to slaves.
        Any FoE activity is flagged as a high-security event.
        """
        opmode_raw = self.get_field(ecat_layer, "ecat_mailbox_foe_opmode")
        opmode = self._parse_hex_int(opmode_raw, -1)
        if opmode < 0:
            return

        filename = self.get_field(ecat_layer, "ecat_mailbox_foe_filename")
        filelength_raw = self.get_field(ecat_layer, "ecat_mailbox_foe_filelength")
        packetno_raw = self.get_field(ecat_layer, "ecat_mailbox_foe_packetno")
        errcode_raw = self.get_field(ecat_layer, "ecat_mailbox_foe_errcode")
        errtext = self.get_field(ecat_layer, "ecat_mailbox_foe_errtext")

        filelength = self._parse_int(filelength_raw, None)
        packetno = self._parse_int(packetno_raw, None)
        errcode = self._parse_int(errcode_raw, None)

        operation = FOE_OP_NAMES.get(opmode, f"FoE Op {opmode}")

        # Update master statistics
        master.foe_transfers += 1
        if filename is not None:
            master.foe_filenames.add(str(filename))

        # Build details
        details: Dict[str, Any] = {
            "command": operation,
            "mailbox_type": "FoE",
            "foe_opmode": opmode,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
        }
        if filename is not None:
            details["filename"] = str(filename)
        if filelength is not None:
            details["file_length"] = filelength
        if packetno is not None:
            details["packet_no"] = packetno
        if errcode is not None:
            details["error_code"] = errcode
        if errtext is not None:
            details["error_text"] = str(errtext)

        # Build summary
        parts = [operation]
        if filename is not None:
            parts.append(f"file={filename}")
        if filelength is not None:
            parts.append(f"len={filelength}")
        if packetno is not None:
            parts.append(f"pkt={packetno}")
        if errcode is not None:
            parts.append(f"err={errcode}")
        summary = " ".join(parts)

        self._record_interaction(
            now, src_mac, "", "request", operation, details, summary, flow_id=flow_id
        )

    def _process_soe(
        self,
        ecat_layer,
        master: EtherCATMaster,
        src_mac: str,
        dst_mac: str,
        now: str,
        flow_id: str,
    ) -> None:
        """Process SoE (Servo over EtherCAT) mailbox content."""
        opcode_raw = self.get_field(ecat_layer, "ecat_mailbox_soe_opcode")
        opcode = self._parse_int(opcode_raw, -1)
        if opcode < 0:
            return

        drive_raw = self.get_field(ecat_layer, "ecat_mailbox_soe_header_driveno")
        idn_raw = self.get_field(ecat_layer, "ecat_mailbox_soe_idn")
        error_raw = self.get_field(ecat_layer, "ecat_mailbox_soe_header_error")

        drive = self._parse_int(drive_raw, None)
        idn = self._parse_hex_int(idn_raw, None)
        has_error = str(error_raw).lower() in ("true", "1") if error_raw is not None else False

        operation = SOE_OP_NAMES.get(opcode, f"SoE Op {opcode}")
        direction = "request" if opcode in (SOE_OP_READ_REQ, SOE_OP_WRITE_REQ) else "response"

        # Update master statistics
        master.soe_operations += 1
        if drive is not None:
            master.soe_drives_seen.add(drive)

        # Build details
        details: Dict[str, Any] = {
            "command": operation,
            "mailbox_type": "SoE",
            "soe_opcode": opcode,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
        }
        if drive is not None:
            details["drive_no"] = drive
        if idn is not None:
            details["idn"] = f"0x{idn:04x}"
        if has_error:
            details["error"] = True

        # Build summary
        parts = [operation]
        if drive is not None:
            parts.append(f"drive={drive}")
        if idn is not None:
            parts.append(f"IDN=0x{idn:04x}")
        if has_error:
            parts.append("ERROR")
        summary = " ".join(parts)

        self._record_interaction(
            now, src_mac, "", direction, operation, details, summary, flow_id=flow_id
        )

    # ------------------------------------------------------------------
    # Register-level field extraction
    # ------------------------------------------------------------------

    def _process_register_fields(
        self,
        ecat_layer,
        master: EtherCATMaster,
        src_mac: str,
        dst_mac: str,
        now: str,
        flow_id: str,
    ) -> None:
        """Extract register-level fields from dissected EtherCAT packets.

        When tshark dissects reads/writes to specific ESC registers, it
        exposes the decoded register content as additional fields on the
        ecat layer. These provide rich device identity and status info:

        - Device identity: reg_type, reg_revision, reg_build
        - AL Status: reg_alstatus_status (state machine), reg_alstatuscode
        - SyncManager: syncman_ctrlstatus, syncman_enable
        - Distributed Clocks: reg_dc_activation_enablecyclic
        - DL Status: reg_dlstatus1, reg_dlstatus2, port link states
        """
        # --- Device identity registers ---
        reg_type = self.get_field(ecat_layer, "reg_type")
        reg_revision = self.get_field(ecat_layer, "reg_revision")
        reg_build = self.get_field(ecat_layer, "reg_build")

        if reg_type is not None and master.esc_type is None:
            master.esc_type = self._parse_first_int(reg_type, None)
        if reg_revision is not None and master.esc_revision is None:
            master.esc_revision = self._parse_first_int(reg_revision, None)
        if reg_build is not None and master.esc_build is None:
            master.esc_build = self._parse_first_int(reg_build, None)

        # --- AL Status (state machine) ---
        al_status_raw = self.get_field(ecat_layer, "reg_alstatus")
        al_status_status = self.get_field(ecat_layer, "reg_alstatus_status")
        al_status_code = self.get_field(ecat_layer, "reg_alstatuscode")

        if al_status_status is not None:
            # EK mode may return comma-separated list for broadcast reads;
            # parse all unique values to capture per-slave states.
            al_vals = self._parse_int_list(al_status_status)
            for val in al_vals:
                master.al_status_states_seen.add(val)
            # Record a single interaction with the first (or representative) value
            first_val = al_vals[0] if al_vals else None
            if first_val is not None:
                state_name = AL_STATUS_NAMES.get(first_val, f"0x{first_val:02x}")
                details: Dict[str, Any] = {
                    "command": "AL Status",
                    "al_status_state": first_val,
                    "al_status_name": state_name,
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                }
                if al_status_raw is not None:
                    details["al_status_raw"] = str(al_status_raw)
                if len(al_vals) > 1:
                    details["al_status_all"] = ",".join(str(v) for v in sorted(set(al_vals)))
                self._record_interaction(
                    now,
                    src_mac,
                    "",
                    "response",
                    "AL Status",
                    details,
                    f"AL Status: {state_name}",
                    flow_id=flow_id,
                )

        if al_status_code is not None:
            code_val = self._parse_first_int(al_status_code, None)
            if code_val is not None and code_val != 0:
                master.al_status_codes_seen.add(code_val)
                code_name = AL_STATUS_CODE_NAMES.get(code_val, f"0x{code_val:04x}")
                self._record_interaction(
                    now,
                    src_mac,
                    "",
                    "response",
                    "AL Status Code",
                    {
                        "command": "AL Status Code",
                        "al_status_code": code_val,
                        "al_status_code_name": code_name,
                        "src_mac": src_mac,
                        "dst_mac": dst_mac,
                    },
                    f"AL Status Code: {code_name} ({code_val})",
                    flow_id=flow_id,
                )

        # --- SyncManager configuration ---
        syncman_ctrlstatus = self.get_field(ecat_layer, "syncman_ctrlstatus")
        syncman_enable = self.get_field(ecat_layer, "syncman_enable")

        if syncman_enable is not None:
            # EK mode returns list of bools for each SM channel
            enable_str = str(syncman_enable)
            if "True" in enable_str or "true" in enable_str or "1" in enable_str:
                master.syncman_enabled = True

        if syncman_ctrlstatus is not None:
            details_sm: Dict[str, Any] = {
                "command": "SyncManager Config",
                "syncman_ctrlstatus": str(syncman_ctrlstatus),
                "src_mac": src_mac,
                "dst_mac": dst_mac,
            }
            if syncman_enable is not None:
                details_sm["syncman_enable"] = str(syncman_enable)
            self._record_interaction(
                now,
                src_mac,
                "",
                "response",
                "SyncManager Config",
                details_sm,
                f"SyncManager ctrlstatus={syncman_ctrlstatus}",
                flow_id=flow_id,
            )

        # --- Distributed Clocks ---
        dc_cyclic = self.get_field(ecat_layer, "reg_dc_activation_enablecyclic")
        if dc_cyclic is not None:
            enabled = str(dc_cyclic).lower() in ("true", "1")
            if enabled:
                master.dc_cyclic_enabled = True
            self._record_interaction(
                now,
                src_mac,
                "",
                "response",
                "DC Activation",
                {
                    "command": "DC Activation",
                    "dc_cyclic_enabled": enabled,
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                },
                f"DC Cyclic: {'enabled' if enabled else 'disabled'}",
                flow_id=flow_id,
            )

        # --- DL Status (Data Link layer) ---
        dl_status1 = self.get_field(ecat_layer, "reg_dlstatus1")
        dl_status2 = self.get_field(ecat_layer, "reg_dlstatus2")

        if dl_status1 is not None or dl_status2 is not None:
            dl_details: Dict[str, Any] = {
                "command": "DL Status",
                "src_mac": src_mac,
                "dst_mac": dst_mac,
            }
            if dl_status1 is not None:
                dl_details["dl_status1"] = str(dl_status1)
            if dl_status2 is not None:
                dl_details["dl_status2"] = str(dl_status2)

            # Extract per-port link states (DL Status byte 2 sub-fields)
            port_states = {}
            p0 = self.get_field(ecat_layer, "reg_dlstatus2_port0")
            p1 = self.get_field(ecat_layer, "reg_dlstatus2_port1")
            p2 = self.get_field(ecat_layer, "reg_dlstatus2_port2")
            p3 = self.get_field(ecat_layer, "reg_dlstatus2_port3")
            if p0 is not None:
                port_states["port0"] = str(p0)
            if p1 is not None:
                port_states["port1"] = str(p1)
            if p2 is not None:
                port_states["port2"] = str(p2)
            if p3 is not None:
                port_states["port3"] = str(p3)
            if port_states:
                # Store as string in interaction details (avoid raw dict in table cells)
                dl_details["port_link_states"] = ", ".join(
                    f"{k}={v}" for k, v in sorted(port_states.items())
                )
                master.dl_port_states = port_states

            summary_parts = ["DL Status"]
            if dl_status1 is not None:
                summary_parts.append(f"byte1={dl_status1}")
            if port_states:
                summary_parts.append(dl_details["port_link_states"])
            self._record_interaction(
                now,
                src_mac,
                "",
                "response",
                "DL Status",
                dl_details,
                " ".join(summary_parts),
                flow_id=flow_id,
            )

    # ------------------------------------------------------------------
    # Master tracking
    # ------------------------------------------------------------------

    def _ensure_master(self, mac: str) -> EtherCATMaster:
        """Get or create a master tracker for the given MAC."""
        if mac not in self.masters:
            vendor = lookup_mac_vendor(mac)
            now = datetime.now().isoformat()
            self.masters[mac] = EtherCATMaster(
                mac=mac,
                vendor=vendor if vendor != "Unknown" else "",
                first_seen=now,
                last_seen=now,
            )
        master = self.masters[mac]
        master.last_seen = datetime.now().isoformat()
        return master

    # ------------------------------------------------------------------
    # Device creation
    # ------------------------------------------------------------------

    def _update_device(self, src_mac: str, master: EtherCATMaster) -> None:
        """Update discovered device entry for the EtherCAT master."""
        key = f"ethercat-master:{src_mac}"
        vendor = master.vendor or lookup_mac_vendor(src_mac)
        if vendor == "Unknown":
            vendor = ""

        device, _is_new = self._ensure_device(
            key,
            "",  # no IP for L2 protocol
            mac=src_mac,
            manufacturer=vendor,
            device_type="EtherCAT Master",
        )
        device.ethercat_passive_data = self._build_device_data(master)

    def _build_device_data(self, master: EtherCATMaster) -> Dict[str, Any]:
        """Build ethercat_passive_data dict for a master."""
        data: Dict[str, Any] = {
            "role": "master",
            "mac": master.mac,
            "vendor": master.vendor,
            "slave_addresses": sorted(master.slave_addrs_seen),
            "logical_addresses_seen": len(master.logical_addrs_seen),
            "commands_used": dict(master.commands_used.most_common()),
            "total_frames": master.total_frames,
            "total_datagrams": master.total_datagrams,
            "read_datagrams": master.read_datagrams,
            "write_datagrams": master.write_datagrams,
            "wkc_zero_count": master.wkc_zero_count,
            "notable_offsets": self._classify_offsets(master.offsets_seen),
            "protocol": "EtherCAT/L2",
            "first_seen": master.first_seen,
            "last_seen": master.last_seen,
        }
        # Include ESC identity when available
        if master.esc_type is not None:
            data["esc_type"] = master.esc_type
        if master.esc_revision is not None:
            data["esc_revision"] = master.esc_revision
        if master.esc_build is not None:
            data["esc_build"] = master.esc_build

        # Include AL status states
        if master.al_status_states_seen:
            data["al_status_states"] = {
                v: AL_STATUS_NAMES.get(v, f"0x{v:02x}")
                for v in sorted(master.al_status_states_seen)
            }
        if master.al_status_codes_seen:
            data["al_status_codes"] = {
                v: AL_STATUS_CODE_NAMES.get(v, f"0x{v:04x}")
                for v in sorted(master.al_status_codes_seen)
            }

        # SyncManager and DC status
        if master.syncman_enabled:
            data["syncman_enabled"] = True
        if master.dc_cyclic_enabled:
            data["dc_cyclic_enabled"] = True
        if master.dl_port_states:
            data["dl_port_states"] = master.dl_port_states

        # Include mailbox statistics when present
        if master.coe_sdo_downloads or master.coe_sdo_uploads or master.coe_sdo_aborts:
            data["coe_sdo"] = {
                "downloads": master.coe_sdo_downloads,
                "uploads": master.coe_sdo_uploads,
                "aborts": master.coe_sdo_aborts,
                "od_indices": sorted(master.coe_od_indices_seen),
            }
        if master.foe_transfers:
            data["foe"] = {
                "transfers": master.foe_transfers,
                "filenames": sorted(master.foe_filenames),
            }
        if master.soe_operations:
            data["soe"] = {
                "operations": master.soe_operations,
                "drives": sorted(master.soe_drives_seen),
            }
        return data

    # ------------------------------------------------------------------
    # Interaction formatting
    # ------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format protocol-specific columns for an interaction."""
        d = ix.details

        # Check if this is a mailbox interaction
        mb_type = d.get("mailbox_type")
        if mb_type:
            return self._format_mailbox_columns(d)

        # Standard datagram formatting
        cmd_name = d.get("command", "")
        rw = d.get("rw", "")
        slave_addr = d.get("slave_addr")
        offset = d.get("offset")
        logical_addr = d.get("logical_addr")
        wkc = d.get("wkc")
        data_len = d.get("length")

        # Command column: "FPRD (read)" or "LRW (rw)"
        cmd_str = f"{cmd_name} ({rw})" if rw and rw != "nop" else cmd_name

        # Address column: physical or logical
        if logical_addr is not None and slave_addr is None:
            addr_str = f"L:0x{logical_addr:08x}"
        elif slave_addr is not None:
            addr_str = f"0x{slave_addr:04x}"
        else:
            addr_str = ""

        offset_str = self._format_offset(offset) if offset is not None else ""
        len_str = str(data_len) if data_len is not None else ""
        wkc_str = str(wkc) if wkc is not None else ""

        return [
            cmd_str,
            addr_str,
            offset_str,
            len_str,
            wkc_str,
        ]

    def _format_mailbox_columns(self, d: Dict[str, Any]) -> List[Any]:
        """Format mailbox interaction as protocol-specific columns.

        Maps mailbox-specific data into the PROTOCOL_COLUMNS structure:
        - Command: mailbox operation name
        - Slave Addr: OD index:sub (CoE), filename (FoE), drive (SoE)
        - Offset: data value or IDN
        - Length: data length or file length
        - WKC: abort/error codes
        """
        mb_type = d.get("mailbox_type", "")
        command = d.get("command", "")

        if mb_type == "CoE":
            od_idx = d.get("od_index", "")
            od_sub = d.get("od_subindex", "")
            addr_str = f"{od_idx}:{od_sub}" if od_sub else od_idx
            offset_str = d.get("sdo_data", "")
            len_str = d.get("sdo_length", "")
            wkc_str = d.get("abort_code", "")
        elif mb_type == "FoE":
            addr_str = d.get("filename", "")
            offset_str = ""
            file_len = d.get("file_length")
            len_str = str(file_len) if file_len is not None else ""
            pkt = d.get("packet_no")
            err = d.get("error_code")
            wkc_str = str(err) if err is not None else (f"pkt={pkt}" if pkt is not None else "")
        elif mb_type == "SoE":
            drive = d.get("drive_no")
            addr_str = f"drive={drive}" if drive is not None else ""
            idn = d.get("idn", "")
            offset_str = f"IDN={idn}" if idn else ""
            len_str = ""
            wkc_str = "ERROR" if d.get("error") else ""
        else:
            addr_str = ""
            offset_str = ""
            len_str = ""
            wkc_str = ""

        return [
            command,
            addr_str,
            offset_str,
            len_str,
            wkc_str,
        ]

    # ------------------------------------------------------------------
    # Harvest: security alerts for mailbox protocols
    # ------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data with mailbox security alerts.

        Extends the base harvest() with additional alerts for:
        - FoE file transfers (HIGH severity -- firmware update risk)
        - SDO writes to critical OD ranges (configuration tampering)
        """
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}

        alerts = result.setdefault("alerts", [])

        # FoE firmware transfer alerts (HIGH severity)
        for master in self.masters.values():
            if master.foe_transfers > 0:
                filenames = ", ".join(sorted(master.foe_filenames)) or "(no filename)"
                alerts.append(
                    {
                        "level": "fail",
                        "category": "firmware_alert",
                        "message": (
                            f"ETHERCAT FoE FIRMWARE TRANSFER: {master.mac} "
                            f"({master.foe_transfers} packets, files: {filenames}) "
                            f"-- potential firmware update in progress"
                        ),
                    }
                )

        # SDO writes to critical OD ranges
        for master in self.masters.values():
            if master.coe_sdo_downloads > 0:
                critical_writes = self._find_critical_od_writes(master)
                if critical_writes:
                    for od_key, category in critical_writes:
                        alerts.append(
                            {
                                "level": "fail",
                                "category": "config_alert",
                                "message": (
                                    f"ETHERCAT SDO WRITE to {od_key} ({category}) from {master.mac}"
                                ),
                            }
                        )

        return result

    @staticmethod
    def _find_critical_od_writes(
        master: EtherCATMaster,
    ) -> List[Tuple[str, str]]:
        """Find SDO download targets in critical OD ranges."""
        critical: List[Tuple[str, str]] = []
        for od_key in master.coe_od_indices_seen:
            # Parse "0x1c12:0x00" -> index int
            try:
                idx_str = od_key.split(":")[0]
                idx_val = int(idx_str, 16)
            except (ValueError, IndexError) as e:
                logger.debug(f"Failed to get idx_str: {e}")
                continue
            for range_lo, range_hi, category in CRITICAL_OD_RANGES:
                if range_lo <= idx_val <= range_hi:
                    critical.append((od_key, category))
                    break
        return critical

    # ------------------------------------------------------------------
    # Write/control operation summaries (for harvest() alerts)
    # ------------------------------------------------------------------

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get masters with write operations (for alerting)."""
        results = []
        for master in self.masters.values():
            if master.write_datagrams > 0:
                results.append(
                    {
                        "client": master.mac,
                        "server": f"{len(master.slave_addrs_seen)} slaves",
                        "write_count": master.write_datagrams,
                    }
                )
        return results

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed EtherCAT masters."""
        return [
            {
                "master_mac": master.mac,
                "vendor": master.vendor,
                "slaves_seen": len(master.slave_addrs_seen),
                "frames": master.total_frames,
                "datagrams": master.total_datagrams,
                "reads": master.read_datagrams,
                "writes": master.write_datagrams,
                "wkc_zero": master.wkc_zero_count,
            }
            for master in self.masters.values()
        ]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_hex_int(value, default=None):
        """Parse a value that may be hex string or int."""
        if value is None:
            return default
        try:
            s = str(value).strip()
            if s.startswith("0x") or s.startswith("0X"):
                return int(s, 16)
            return int(s, 0)
        except (ValueError, TypeError) as e:
            logger.debug(f"EtherCAT: hex/decimal int parse failed for field value: {e}")
            return default

    @staticmethod
    def _parse_first_int(value, default=None):
        """Parse the first integer from a value that may be comma-separated.

        EK mode returns lists for broadcast register reads (e.g. "1,1,3,1,1").
        This takes the first element.
        """
        if value is None:
            return default
        try:
            s = str(value).strip()
            # Handle comma-separated lists from EK mode broadcast reads
            if "," in s:
                s = s.split(",")[0].strip()
            return int(s)
        except (ValueError, TypeError) as e:
            logger.debug(f"EtherCAT: first-int parse from comma-split field failed: {e}")
            return default

    @staticmethod
    def _parse_int_list(value) -> List[int]:
        """Parse a comma-separated string into a list of integers.

        EK mode broadcast reads return per-slave values as "1,2,1,4".
        Returns all successfully parsed integers.
        """
        if value is None:
            return []
        results = []
        for part in str(value).split(","):
            part = part.strip()
            if part:
                try:
                    results.append(int(part))
                except (ValueError, TypeError) as e:
                    logger.debug(f"results.append(int(part)): {e}")
        return results

    @staticmethod
    def _format_offset(offset: int) -> str:
        """Format an offset with register name annotation if known."""
        name = ESC_REGISTER_NAMES.get(offset)
        if name:
            return f"0x{offset:04x} ({name})"
        return f"0x{offset:04x}"

    @staticmethod
    def _classify_offsets(offsets: Set[int]) -> List[str]:
        """Classify observed offsets into human-readable register categories."""
        categories: List[str] = []
        for offset in sorted(offsets):
            name = ESC_REGISTER_NAMES.get(offset)
            if name:
                categories.append(f"0x{offset:04x} ({name})")
        return categories

    @staticmethod
    def _build_summary(
        cmd_name: str,
        rw: str,
        addr_str: str,
        offset_str: str,
        wkc: Optional[int],
    ) -> str:
        """Build human-readable summary for a datagram."""
        parts = [cmd_name]
        if addr_str:
            parts.append(f"addr={addr_str}")
        if offset_str:
            parts.append(f"off={offset_str}")
        if wkc is not None:
            parts.append(f"WKC={wkc}")
        return " ".join(parts)
