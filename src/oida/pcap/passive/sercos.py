"""
SERCOS III Passive Listener (PyShark-based).

Passively monitors SERCOS III (EtherType 0x88CD) traffic to identify:
- Master and slave devices on the network
- Telegram types: MDT (Master Data Telegram) and AT (Acknowledge Telegram)
- Communication phases (CP0-CP4) and phase transitions
- Service channel (SVC) transfers with IDN (Identification Number) access
- Hot-plug channel activity
- Device control and status words
- Slave addresses from topology discovery

SERCOS III is a real-time Ethernet fieldbus for motion control and CNC,
standardised as IEC 61784-2 CPF 16 and IEC 61158. It uses a ring or
line topology with two channels for redundancy.

Communication phases:
- CP0: Topology scan (no data exchange)
- CP1: Communication parameter configuration
- CP2: Process data configuration
- CP3: Data exchange with reduced timing
- CP4: Full real-time operation

Telegram structure:
- Ethernet header: EtherType 0x88CD
- SERCOS III header: Channel (1 bit), Type (1 bit), CycleCntValid (1 bit),
  TelNo (4 bits)
- MST (Master Synchronization Telegram) or MDT/AT payload
- MDT: Master Data Telegram (master -> slaves)
- AT: Acknowledge Telegram (slaves -> master)
- Each MDT/AT contains: Device Control/Status + Service Channel + Hot-Plug + RT data

Key tshark fields:
- siii.channel: Channel (0=primary, 1=secondary) (FT_UINT8)
- siii.type: Telegram type (0=MDT, 1=AT) (FT_UINT8)
- siii.telno: Telegram number (FT_UINT8)
- siii.cyclecntvalid: Cycle count valid flag (FT_BOOLEAN)
- siii.mst.phase: Communication phase (FT_UINT8)
- siii.mst.cyclecnt: Cycle count (FT_UINT8)
- siii.mdt.svch.ctrl: SVC control word (FT_UINT16)
- siii.mdt.svch.idn: IDN number (FT_UINT32)
- siii.mdt.svch.rw: Read/Write flag (FT_BOOLEAN)
- siii.mdt.svch.mhs: Master handshake (FT_UINT16)
- siii.at.svch.ahs: Slave handshake/acknowledge (FT_UINT16)
- siii.mdt.svch.dbe: Data block element (FT_UINT16)
- siii.mdt.svch.eot: End of element transmission (FT_BOOLEAN)
- siii.mdt.devcontrol: Device control word (FT_UINT16)
- siii.at.devstatus: Device status word (FT_UINT16)
- siii.at.sercosaddress: Slave SERCOS address (FT_UINT16)
- siii.mdt.devcontrol.topcontrol: Topology control (FT_UINT16)
- siii.at.devstatus.commwarning: Communication warning (FT_UINT16)
- siii.at.devstatus.slavevalid: Slave data valid (FT_UINT16)
- siii.at.cp0.num_devices: Number of devices in CP0 (FT_UINT16)
- siii.at.cp0.sercos_address: SERCOS address discovered in CP0 (FT_UINT16)
- siii.mdt.hp.sercosaddress: Hot-plug SERCOS address (FT_UINT16)
- siii.mdt.hp.ctrl: Hot-plug control (FT_UINT16)

References:
- IEC 61158 Type 19 / IEC 61784-2 CPF 16 (SERCOS III)
- Sercos International: SERCOS III specification
- Wireshark dissector: packet-sercosiii.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import lookup_mac_vendor

# Communication phases
SERCOS_PHASES = {
    0x00: "CP0",  # Topology scan
    0x01: "CP1",  # Communication parameters
    0x02: "CP2",  # Process data configuration
    0x03: "CP3",  # Reduced timing
    0x04: "CP4",  # Full real-time
    0x80: "CP0 (switching)",
    0x81: "CP1 (switching)",
    0x82: "CP2 (switching)",
    0x83: "CP3 (switching)",
}

# Telegram types
TELEGRAM_TYPES = {
    0: "MDT",  # Master Data Telegram
    1: "AT",  # Acknowledge Telegram
}

# Service channel data block elements (siii.mdt.svch.dbe)
SVC_DBE = {
    0: "IDN",  # Identification number
    1: "Name",  # Name of parameter
    2: "Attribute",  # Attribute of parameter
    3: "Unit",  # Unit of parameter
    4: "Minimum",  # Minimum value
    5: "Maximum",  # Maximum value
    6: "OperatingData",  # Current operating data
    7: "Default",  # Default value
}

# Well-known SERCOS IDNs (S-parameter, P-parameter)
WELL_KNOWN_IDNS = {
    # S-parameters (standardized)
    0x00010001: "S-0-0001 (Phase command value)",
    0x00020001: "S-0-0002 (Phase command change bit)",
    0x00110001: "S-0-0017 (Vendor ID)",
    0x00120001: "S-0-0018 (Vendor Name)",
    0x00130001: "S-0-0019 (Device Name)",
    0x00240001: "S-0-0036 (Velocity feedback value)",
    0x00250001: "S-0-0037 (Velocity command value)",
    0x00300001: "S-0-0048 (Position feedback value 1)",
    0x00310001: "S-0-0049 (Position command value)",
    0x007A0001: "S-0-0122 (SERCOS address)",
    0x008A0001: "S-0-0138 (Device Control word)",
    0x008B0001: "S-0-0139 (Device Status word)",
    0x00C80001: "S-0-0200 (Operating mode)",
    # P-parameters (manufacturer-specific) are vendor-defined
}


def _format_idn(idn: int) -> str:
    """Format a SERCOS IDN to human-readable form.

    IDN structure (32-bit):
    - Bit 15: S(0) or P(1) parameter
    - Bits 14-12: Set number
    - Bits 11-0: Parameter number
    """
    if idn in WELL_KNOWN_IDNS:
        return WELL_KNOWN_IDNS[idn]
    # Decode the IDN structure
    param_type = "P" if (idn >> 15) & 1 else "S"
    set_num = (idn >> 12) & 0x7
    param_num = idn & 0xFFF
    return f"{param_type}-{set_num}-{param_num:04d}"


@dataclass
class SERCOSSlave:
    """Track a SERCOS III slave device."""

    address: int
    mac: str = ""
    comm_warning: bool = False
    slave_valid: bool = False
    svc_read_count: int = 0
    svc_write_count: int = 0
    idns_accessed: Set[str] = field(default_factory=set)
    first_seen: str = ""
    last_seen: str = ""


class SERCOSPassiveListener(PySharkListenerBase):
    """Passive SERCOS III traffic listener (PyShark-based).

    Monitors SERCOS III (EtherType 0x88CD) real-time Ethernet traffic to:
    - Identify master and slave devices
    - Track communication phase transitions (CP0-CP4)
    - Monitor service channel (SVC) IDN access patterns
    - Detect hot-plug activity
    - Flag phase transitions and SVC write operations

    tshark layer: siii
    EtherType: 0x88CD (Layer 2, no IP)

    Usage:
        listener = SERCOSPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        print(f"Phase: {listener.current_phase}")
        for slave in listener.slaves.values():
            print(f"Slave {slave.address}: IDNs accessed: {slave.idns_accessed}")
    """

    PROTOCOL_NAME = "sercos"
    DISPLAY_FILTER = "siii"
    REQUIRED_LAYERS = ("siii",)
    PROTOCOL_COLUMNS = ("telegram", "phase", "slave", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.slaves: Dict[int, SERCOSSlave] = {}
        self.current_phase: str = ""
        self.phase_history: List[str] = []
        self.master_mac: str = ""
        self._num_devices_cp0: int = 0

    def process_packet(self, packet) -> None:
        """Process a SERCOS III packet."""
        if not hasattr(packet, "siii"):
            return

        siii = packet.siii
        src_mac, dst_mac = self.get_mac_info(packet)
        flow_id = self.get_flow_id(packet)
        now = datetime.now().isoformat()

        # Parse telegram type (MDT=0, AT=1)
        tel_type_raw = self.get_field(siii, "type")
        tel_type = self._parse_int(tel_type_raw, None)
        tel_name = TELEGRAM_TYPES.get(tel_type, "Unknown") if tel_type is not None else "Unknown"

        # Parse telegram number
        tel_no_raw = self.get_field(siii, "telno")
        tel_no = self._parse_int(tel_no_raw, 0)

        # Parse channel (primary=0, secondary=1)
        channel_raw = self.get_field(siii, "channel")
        channel = self._parse_int(channel_raw, 0)

        # Parse phase from MST
        phase_raw = self.get_field(siii, "mst_phase")
        if phase_raw is not None:
            phase_code = self._parse_int(phase_raw, None)
            if phase_code is not None:
                new_phase = SERCOS_PHASES.get(phase_code, f"Phase(0x{phase_code:02x})")
                if new_phase != self.current_phase and self.current_phase:
                    self.phase_history.append(f"{self.current_phase}->{new_phase}")
                self.current_phase = new_phase

        direction = "request" if tel_type == 0 else "response"
        detail = ""
        rw = ""

        # Track master MAC from MDT source
        if tel_type == 0 and src_mac:
            self.master_mac = src_mac

        # Process CP0 topology discovery
        num_devices_raw = self.get_field(siii, "at_cp0_num_devices")
        if num_devices_raw is not None:
            self._num_devices_cp0 = self._parse_int(num_devices_raw, 0)
            detail = f"CP0 topology: {self._num_devices_cp0} devices"

        # Process slave addresses from CP0 AT
        sercos_addr_raw = self.get_field(siii, "at_cp0_sercos_address")
        if sercos_addr_raw is not None:
            addr = self._parse_int(sercos_addr_raw, None)
            if addr is not None and addr > 0:
                self._ensure_slave(addr, now)
                detail = f"CP0 slave addr={addr}"

        # Process slave SERCOS address from AT
        svc_target_addr: int | None = None
        at_addr_raw = self.get_field(siii, "at_sercosaddress")
        if at_addr_raw is not None:
            addr = self._parse_int(at_addr_raw, None)
            if addr is not None and addr > 0:
                svc_target_addr = addr
                slave = self._ensure_slave(addr, now)
                if src_mac:
                    slave.mac = src_mac

                # Check device status flags
                comm_warn_raw = self.get_field(siii, "at_devstatus_commwarning")
                if comm_warn_raw is not None:
                    slave.comm_warning = self._parse_bool(comm_warn_raw)

                valid_raw = self.get_field(siii, "at_devstatus_slavevalid")
                if valid_raw is not None:
                    slave.slave_valid = self._parse_bool(valid_raw)

        # Process service channel in MDT
        svc_ctrl_raw = self.get_field(siii, "mdt_svch_ctrl")
        if svc_ctrl_raw is not None:
            svc_detail, svc_rw = self._process_svc(siii, now, svc_target_addr)
            if svc_detail:
                detail = svc_detail
                rw = svc_rw

        # Process hot-plug
        hp_addr_raw = self.get_field(siii, "mdt_hp_sercosaddress")
        if hp_addr_raw is not None:
            hp_addr = self._parse_int(hp_addr_raw, None)
            if hp_addr is not None and hp_addr > 0:
                self._ensure_slave(hp_addr, now)
                detail = f"HotPlug slave={hp_addr}"

        # Build details
        details: Dict[str, Any] = {
            "telegram": tel_name,
            "telegram_no": tel_no,
            "channel": channel,
            "phase": self.current_phase,
            "detail": detail,
            "rw": rw,
        }

        # Derive slave ID for summary if available
        if at_addr_raw is not None:
            addr = self._parse_int(at_addr_raw, None)
            if addr is not None and addr > 0:
                details["slave"] = addr

        summary = f"{tel_name}/{tel_no} ch={channel}"
        if self.current_phase:
            summary += f" {self.current_phase}"
        if detail:
            summary += f" {detail}"

        self._record_interaction(
            now,
            src_mac or "master",
            dst_mac or "network",
            direction,
            tel_name,
            details,
            summary,
            flow_id=flow_id,
        )

        # Update discovered devices
        for slave in self.slaves.values():
            self._update_device(slave)

    def _process_svc(self, siii, now: str, target_addr: int | None = None) -> Tuple[str, str]:
        """Process service channel fields. Returns (detail_str, rw).

        SVC stats are attributed to the slave addressed by this telegram
        (``target_addr``, derived from the AT sercosaddress) rather than the
        arbitrary first slave in dict order.
        """
        # Read/Write flag
        rw_raw = self.get_field(siii, "mdt_svch_rw")
        is_write = self._parse_bool(rw_raw)
        rw = "write" if is_write else "read"

        # IDN
        idn_raw = self.get_field(siii, "mdt_svch_idn")
        idn_val = self._parse_int(idn_raw, None)
        idn_str = _format_idn(idn_val) if idn_val is not None else ""

        # Data block element
        dbe_raw = self.get_field(siii, "mdt_svch_dbe")
        dbe_val = self._parse_int(dbe_raw, None)
        dbe_name = SVC_DBE.get(dbe_val, f"dbe={dbe_val}") if dbe_val is not None else ""

        # End of transmission
        eot_raw = self.get_field(siii, "mdt_svch_eot")
        eot = self._parse_bool(eot_raw)

        # Attribute SVC stats to the addressed slave, not an arbitrary one.
        target_slave: SERCOSSlave | None = None
        if target_addr is not None and target_addr in self.slaves:
            target_slave = self.slaves[target_addr]
        if target_slave is not None:
            if is_write:
                target_slave.svc_write_count += 1
            else:
                target_slave.svc_read_count += 1
            if idn_str:
                target_slave.idns_accessed.add(idn_str)

        parts = [f"SVC {'Write' if is_write else 'Read'}"]
        if idn_str:
            parts.append(idn_str)
        if dbe_name:
            parts.append(dbe_name)
        if eot:
            parts.append("(EOT)")

        return " ".join(parts), rw

    def _ensure_slave(self, address: int, now: str) -> SERCOSSlave:
        """Ensure a slave entry exists and return it."""
        if address not in self.slaves:
            self.slaves[address] = SERCOSSlave(
                address=address,
                first_seen=now,
                last_seen=now,
            )
        slave = self.slaves[address]
        slave.last_seen = now
        return slave

    def _update_device(self, slave: SERCOSSlave) -> None:
        """Update discovered device entry for a slave."""
        vendor = lookup_mac_vendor(slave.mac) if slave.mac else ""
        key = f"sercos:{slave.address}"

        device, is_new = self._ensure_device(
            key,
            "",  # L2 protocol, no IP
            mac=slave.mac,
            name=f"SERCOS Slave {slave.address}",
            device_type="SERCOS III Slave",
            manufacturer=vendor if vendor else "",
        )
        device.sercos_passive_data = {
            "address": slave.address,
            "protocol": "SERCOS III",
            "phase": self.current_phase,
            "comm_warning": slave.comm_warning,
            "slave_valid": slave.slave_valid,
            "svc_read_count": slave.svc_read_count,
            "svc_write_count": slave.svc_write_count,
            "idns_accessed": sorted(slave.idns_accessed),
            "first_seen": slave.first_seen,
            "last_seen": slave.last_seen,
        }
        if is_new:
            self.logger.debug(
                f"SERCOS: Slave {slave.address}"
                + (f" MAC={slave.mac}" if slave.mac else "")
                + f" phase={self.current_phase}"
            )

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format interaction as table row matching PROTOCOL_COLUMNS."""
        d = ix.details
        return [
            d.get("telegram", ""),
            d.get("phase", ""),
            d.get("slave", ""),
            d.get("detail", ""),
        ]

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get slaves with SVC write operations."""
        return [
            {
                "client": "master",
                "server": f"slave:{slave.address}",
                "write_count": slave.svc_write_count,
            }
            for slave in self.slaves.values()
            if slave.svc_write_count > 0
        ]

    def get_control_operations(self) -> List[Dict[str, Any]]:
        """Get phase transitions (security-relevant control operations)."""
        if not self.phase_history:
            return []
        return [
            {
                "controlling": f"master:{self.master_mac}" if self.master_mac else "master",
                "controlled": "SERCOS network",
                "control_count": len(self.phase_history),
            }
        ]

    def get_slaves_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed SERCOS slaves."""
        return [
            {
                "address": slave.address,
                "mac": slave.mac,
                "comm_warning": slave.comm_warning,
                "slave_valid": slave.slave_valid,
                "svc_reads": slave.svc_read_count,
                "svc_writes": slave.svc_write_count,
                "idns": sorted(slave.idns_accessed),
            }
            for slave in sorted(self.slaves.values(), key=lambda s: s.address)
        ]
