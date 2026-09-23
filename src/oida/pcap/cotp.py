"""
COTP/TPKT Passive Listener (PyShark-based).

Passively monitors ISO Transport (COTP over TPKT) traffic to identify:
- COTP connections by source/destination reference pairs
- TSAP (Transport Service Access Point) pairs identifying upper-layer protocols
- Connection lifecycle (CR -> CC -> DT -> DR/DC)
- Data volume and connection duration per reference pair
- Error and reject frames indicating protocol issues
- Security anomalies (connection floods, probing, unusual TSAPs)

COTP (Connection-Oriented Transport Protocol, ISO 8073) runs over
TPKT (RFC 1006) on TCP port 102. This is the transport layer for:
- Siemens S7comm/S7comm-plus (PLC communication)
- MMS/IEC 61850 (power utility automation)
- Other ISO-based protocols

Protocol format:
- TCP port 102
- TPKT header (4 bytes): version (1), reserved (1), length (2)
- COTP PDU:
  - Length indicator (1 byte)
  - PDU type (4 bits of byte): identifies the TPDU type
  - PDU-specific fields depending on type

COTP PDU types:
- 0xE0: CR (Connection Request) - initiates connection, carries TSAPs
- 0xD0: CC (Connection Confirm) - accepts connection
- 0x80: DR (Disconnect Request) - teardown
- 0xC0: DC (Disconnect Confirm) - acknowledges teardown
- 0xF0: DT (Data Transfer) - carries payload data
- 0x10: ED (Expedited Data) - urgent/priority data
- 0x60: AK (Acknowledge) - data acknowledgment
- 0x20: EA (Expedited Acknowledge) - expedited data ack
- 0x70: ER (Error) - protocol error
- 0x50: RJ (Reject) - TPDU rejected

Security notes:
- COTP has NO encryption or authentication
- Connection floods (many CR without CC) indicate scanning or DoS
- DR without prior CC suggests connection probing
- ER/RJ frames indicate protocol-level errors or fuzzing
- Unusual TSAPs may indicate non-standard or malicious applications
- Large TPKT lengths could indicate exploitation attempts (buffer overflow)
- TSAPs reveal the upper-layer service (S7 vs MMS vs other)

tshark fields used:
- tpkt.version: TPKT version (FT_UINT8, typically 3)
- tpkt.length: TPKT packet length including header (FT_UINT16)
- cotp.type: PDU type code (FT_UINT8, upper 4 bits)
- cotp.destref: Destination reference (FT_UINT16)
- cotp.srcref: Source reference (FT_UINT16)
- cotp.class: COTP class (FT_UINT8, 0-4)
- cotp.tpdu_size: TPDU size parameter (FT_UINT8, power-of-2 encoded)
- cotp.parameter_code: Parameter code in variable part (FT_UINT8)
- cotp.tsap: Calling/Called TSAP (FT_BYTES)
- cotp.tsap_calling: Calling TSAP string (FT_STRING)
- cotp.tsap_called: Called TSAP string (FT_STRING)
- cotp.eot: End of TSDU flag (FT_BOOLEAN)
- cotp.nr: TPDU number (FT_UINT32)
- cotp.cause: Disconnect/reject cause code (FT_UINT8)

References:
- ISO 8073: Connection-Oriented Transport Protocol
- RFC 1006: ISO Transport over TCP (TPKT)
- Wireshark dissectors: packet-cotp.c, packet-tpkt.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# COTP PDU type codes (upper 4 bits of the type byte)
# Keyed on the UPPER NIBBLE, matching Wireshark's cotp.type value_string
# (verified `tshark -G values`: 0xe=CR, 0xd=CC ...). The dissector exposes only
# the nibble, so the old full-byte keys (0xE0 ...) matched nothing.
COTP_PDU_TYPES = {
    0xE: "CR",  # Connection Request
    0xD: "CC",  # Connection Confirm
    0x8: "DR",  # Disconnect Request
    0xC: "DC",  # Disconnect Confirm
    0xF: "DT",  # Data Transfer
    0x1: "ED",  # Expedited Data
    0x6: "AK",  # Acknowledge
    0x2: "EA",  # Expedited Acknowledge
    0x7: "ER",  # Error
    0x5: "RJ",  # Reject
}

# Well-known TSAP patterns and their likely upper-layer protocols
KNOWN_TSAPS = {
    "0100": "S7comm (Rack 0, Slot 1)",
    "0102": "S7comm (Rack 0, Slot 2)",
    "0103": "S7comm (Rack 0, Slot 3)",
    "0200": "S7comm (Rack 1, Slot 0)",
    "0201": "S7comm (Rack 1, Slot 1)",
    "4d4d53": "MMS (IEC 61850)",
    "00": "Default TSAP",
}

# Thresholds for security alerts
CR_FLOOD_THRESHOLD = 20  # CR frames from single source without CC


@dataclass
class COTPConnection:
    """Track a COTP connection by reference pair.

    Only the fields consumed by the DR-probe alert in harvest() are kept;
    per-connection volume/state tracking is surfaced via COTPEndpoint instead.
    """

    src_ip: str
    dst_ip: str
    src_ref: int
    dst_ref: int
    # cr_seen is state-completeness tracking only: the harvest() DR-probe
    # alert keys on "no CC" (see _handle_dr comment), never on cr_seen.
    cr_seen: bool = False
    cc_seen: bool = False
    dr_seen: bool = False


@dataclass
class COTPEndpoint:
    """Track a COTP endpoint (IP address)."""

    ip: str
    cr_sent: int = 0
    cr_received: int = 0
    cc_sent: int = 0
    cc_received: int = 0
    dr_sent: int = 0
    er_count: int = 0
    rj_count: int = 0
    dt_count: int = 0
    total_frames: int = 0
    tsaps_seen: Set[str] = field(default_factory=set)
    peer_ips: Set[str] = field(default_factory=set)
    mac: str = ""  # last-seen ethernet MAC for vendor lookup
    first_seen: str = ""
    last_seen: str = ""


class COTPPassiveListener(PySharkListenerBase):
    """Passive COTP/TPKT (ISO Transport) traffic listener (PyShark-based).

    Monitors COTP traffic on TCP port 102 without sending packets to:
    - Track COTP connections by source/destination reference
    - Identify TSAP pairs to determine upper-layer protocols (S7 vs MMS)
    - Monitor connection lifecycle (CR -> CC -> DT -> DR)
    - Detect connection floods, probing, and error conditions
    - Alert on unusual TSAPs, excessive errors, and large TPKT lengths

    COTP runs over TCP, so packets have full IP/TCP headers.
    Devices are keyed by IP address.

    Usage:
        listener = COTPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for ep in listener.endpoints.values():
            print(f"{ep.ip}: CR_sent={ep.cr_sent} DT={ep.dt_count}")

    Data stored in device.cotp_passive_data:
        {
            "role": "cotp_endpoint",
            "cr_sent": 5,
            "cc_sent": 3,
            "dt_count": 1000,
            "tsaps": ["0102", "4d4d53"],
            "peers": ["10.0.0.1"],
            "protocol": "COTP/TCP",
        }
    """

    PROTOCOL_NAME = "cotp"
    DISPLAY_FILTER = "cotp"
    REQUIRED_LAYERS = ("cotp",)
    PROTOCOL_COLUMNS = (
        "pdu_type",
        "src_ref",
        "dst_ref",
        "tsap",
        "detail",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize COTP passive listener."""
        super().__init__(interface, timeout, nxc_logger)
        # Track connections by "src_ip:src_ref -> dst_ip:dst_ref"
        self.connections: Dict[str, COTPConnection] = {}
        # Track endpoints by IP
        self.endpoints: Dict[str, COTPEndpoint] = {}
        # Track large TPKT lengths for anomaly detection
        self._large_tpkt: List[Dict[str, Any]] = []

    def process_packet(self, packet) -> None:
        """Process a COTP/TPKT packet."""
        if not hasattr(packet, "cotp"):
            return

        cotp_layer = packet.cotp
        src_ip, dst_ip = self.get_ip_info(packet)
        src_port, dst_port = self.get_port_info(packet)

        if not src_ip or not dst_ip:
            return

        now = datetime.now().isoformat()

        # Extract TPKT fields if available
        tpkt_version = 0
        tpkt_length = 0
        if hasattr(packet, "tpkt"):
            tpkt_version = self._parse_int(self.get_field(packet.tpkt, "version"), 0)
            tpkt_length = self._parse_int(self.get_field(packet.tpkt, "length"), 0)

        # Extract COTP fields
        pdu_type_raw = self._parse_int(self.get_field(cotp_layer, "type"), 0)
        dst_ref = self._parse_int(self.get_field(cotp_layer, "destref"), 0)
        src_ref = self._parse_int(self.get_field(cotp_layer, "srcref"), 0)
        cotp_class = self._parse_int(self.get_field(cotp_layer, "class"), -1)
        tpdu_size = self._parse_int(self.get_field(cotp_layer, "tpdu_size"), 0)
        eot = self._parse_bool(self.get_field(cotp_layer, "eot"))
        cause = self._parse_int(self.get_field(cotp_layer, "cause"), -1)

        # Extract TSAPs
        calling_tsap = str(self.get_field(cotp_layer, "src-tsap") or "")
        called_tsap = str(self.get_field(cotp_layer, "dst-tsap") or "")
        # Fallback: raw tsap field
        if not calling_tsap and not called_tsap:
            raw_tsap = str(self.get_field(cotp_layer, "dst-tsap-bytes") or "")
            if raw_tsap:
                called_tsap = raw_tsap

        # Resolve PDU type name
        pdu_name = COTP_PDU_TYPES.get(pdu_type_raw, f"0x{pdu_type_raw:02X}")

        # Track large TPKT lengths (potential exploitation)
        if tpkt_length > 4096:
            self._large_tpkt.append(
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "tpkt_length": tpkt_length,
                    "pdu_type": pdu_name,
                    "timestamp": now,
                }
            )

        # Update endpoint tracking
        src_mac, dst_mac = self.get_mac_info(packet)
        src_ep = self._ensure_endpoint(src_ip, now)
        dst_ep = self._ensure_endpoint(dst_ip, now)
        src_ep.total_frames += 1
        src_ep.peer_ips.add(dst_ip)
        dst_ep.peer_ips.add(src_ip)
        if src_mac:
            src_ep.mac = src_mac
        if dst_mac:
            dst_ep.mac = dst_mac

        # Update connection tracking based on PDU type
        direction = "request"
        if pdu_type_raw == 0xE:  # CR
            self._handle_cr(src_ip, dst_ip, src_ref, dst_ref)
            src_ep.cr_sent += 1
            dst_ep.cr_received += 1
            direction = "request"
        elif pdu_type_raw == 0xD:  # CC
            self._handle_cc(src_ip, dst_ip, src_ref, dst_ref)
            src_ep.cc_sent += 1
            dst_ep.cc_received += 1
            direction = "response"
        elif pdu_type_raw == 0x8:  # DR
            self._handle_dr(src_ip, dst_ip, src_ref, dst_ref)
            src_ep.dr_sent += 1
            direction = "request"
        elif pdu_type_raw == 0xC:  # DC
            direction = "response"
        elif pdu_type_raw == 0xF:  # DT
            src_ep.dt_count += 1
            direction = "request"
        elif pdu_type_raw == 0x7:  # ER
            src_ep.er_count += 1
            direction = "response"
        elif pdu_type_raw == 0x5:  # RJ
            src_ep.rj_count += 1
            direction = "response"

        # Track TSAPs on endpoints
        if calling_tsap:
            src_ep.tsaps_seen.add(calling_tsap)
        if called_tsap:
            dst_ep.tsaps_seen.add(called_tsap)

        # Record interaction
        flow_id = self.get_flow_id(packet)
        stream_id = self.get_stream_id(packet)
        details: Dict[str, Any] = {
            "pdu_type": pdu_type_raw,
            "pdu_name": pdu_name,
            "src_ref": src_ref,
            "dst_ref": dst_ref,
            "tpkt_version": tpkt_version,
            "tpkt_length": tpkt_length,
        }
        if calling_tsap:
            details["calling_tsap"] = calling_tsap
        if called_tsap:
            details["called_tsap"] = called_tsap
        if cotp_class >= 0:
            details["cotp_class"] = cotp_class
        if tpdu_size > 0:
            details["tpdu_size"] = tpdu_size
        if cause >= 0:
            details["cause"] = cause
        if eot:
            details["eot"] = True

        summary = self._build_summary(
            pdu_name,
            src_ref,
            dst_ref,
            calling_tsap,
            called_tsap,
            tpkt_length,
        )
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            pdu_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Update device entries
        self._update_device(src_ip, src_ep)
        self._update_device(dst_ip, dst_ep)

    # ------------------------------------------------------------------
    # Connection lifecycle handlers
    # ------------------------------------------------------------------

    def _handle_cr(
        self,
        src_ip: str,
        dst_ip: str,
        src_ref: int,
        dst_ref: int,
    ) -> None:
        """Handle Connection Request (CR)."""
        conn_key = f"{src_ip}:{src_ref}->{dst_ip}"
        if conn_key not in self.connections:
            self.connections[conn_key] = COTPConnection(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_ref=src_ref,
                dst_ref=dst_ref,
            )
        self.connections[conn_key].cr_seen = True

    def _handle_cc(self, src_ip: str, dst_ip: str, src_ref: int, dst_ref: int) -> None:
        """Handle Connection Confirm (CC)."""
        # CC comes from the server back to the client
        # Look for matching CR: client_ip:client_ref -> server_ip
        conn_key = f"{dst_ip}:{dst_ref}->{src_ip}"
        if conn_key in self.connections:
            self.connections[conn_key].cc_seen = True

    def _handle_dr(self, src_ip: str, dst_ip: str, src_ref: int, dst_ref: int) -> None:
        """Handle Disconnect Request (DR)."""
        conn = self._find_connection(src_ip, dst_ip, src_ref, dst_ref)
        if conn is None:
            # A DR with no matching CR/CC is exactly the connection-probing case
            # the DR alert targets. Track it (cr_seen/cc_seen stay False) so the
            # probe is not silently dropped -- previously _handle_dr only marked
            # pre-existing connections, so a standalone DR created nothing.
            conn_key = f"{src_ip}:{src_ref}->{dst_ip}"
            conn = self.connections.setdefault(
                conn_key,
                COTPConnection(src_ip=src_ip, dst_ip=dst_ip, src_ref=src_ref, dst_ref=dst_ref),
            )
        conn.dr_seen = True

    def _find_connection(
        self, src_ip: str, dst_ip: str, src_ref: int, dst_ref: int
    ) -> Optional[COTPConnection]:
        """Find an existing connection by reference pair (either direction)."""
        # Try forward direction
        key1 = f"{src_ip}:{src_ref}->{dst_ip}"
        if key1 in self.connections:
            return self.connections[key1]
        # Try reverse direction
        key2 = f"{dst_ip}:{dst_ref}->{src_ip}"
        if key2 in self.connections:
            return self.connections[key2]
        return None

    # ------------------------------------------------------------------
    # Endpoint management
    # ------------------------------------------------------------------

    def _ensure_endpoint(self, ip: str, now: str) -> COTPEndpoint:
        """Get or create a COTP endpoint entry."""
        if ip not in self.endpoints:
            self.endpoints[ip] = COTPEndpoint(
                ip=ip,
                first_seen=now,
                last_seen=now,
            )
        ep = self.endpoints[ip]
        ep.last_seen = now
        return ep

    # ------------------------------------------------------------------
    # Interaction formatting
    # ------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details

        pdu_name = d.get("pdu_name", "")
        src_ref = d.get("src_ref", "")
        if src_ref:
            src_ref = f"0x{src_ref:04X}" if isinstance(src_ref, int) else str(src_ref)
        dst_ref = d.get("dst_ref", "")
        if dst_ref:
            dst_ref = f"0x{dst_ref:04X}" if isinstance(dst_ref, int) else str(dst_ref)

        # Show TSAP info when available
        tsap_str = ""
        calling = d.get("calling_tsap", "")
        called = d.get("called_tsap", "")
        if calling and called:
            tsap_str = f"{calling}->{called}"
        elif calling:
            tsap_str = f"from={calling}"
        elif called:
            tsap_str = f"to={called}"

        # Build detail based on PDU type
        detail_parts = []
        tpkt_len = d.get("tpkt_length", 0)
        if tpkt_len:
            detail_parts.append(f"len={tpkt_len}")
        cause = d.get("cause", -1)
        if cause >= 0:
            detail_parts.append(f"cause={cause}")
        cotp_class = d.get("cotp_class", -1)
        if cotp_class >= 0:
            detail_parts.append(f"class={cotp_class}")
        detail = " ".join(detail_parts)

        return [pdu_name, src_ref, dst_ref, tsap_str, detail]

    # ------------------------------------------------------------------
    # Security alerts
    # ------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return harvest data with COTP-specific security alerts."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}
        if "alerts" not in result:
            result["alerts"] = []

        for ep in self.endpoints.values():
            # Alert: connection flood (many CR without corresponding CC)
            if ep.cr_sent >= CR_FLOOD_THRESHOLD and ep.cc_received == 0:
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "cotp_connection_flood",
                        "message": (
                            f"COTP CONNECTION FLOOD: {ep.ip} "
                            f"sent {ep.cr_sent} CR without receiving CC "
                            f"-- possible scanning or DoS attack"
                        ),
                    }
                )

            # Alert: error/reject frames
            if ep.er_count > 0 or ep.rj_count > 0:
                result["alerts"].append(
                    {
                        "level": "highlight",
                        "category": "cotp_errors",
                        "message": (
                            f"COTP ERRORS: {ep.ip} "
                            f"ER={ep.er_count} RJ={ep.rj_count} "
                            f"-- protocol errors or fuzzing detected"
                        ),
                    }
                )

        # Alert: DR without a completed connection (connection probing). The
        # signal is "no CC" (session never established); a standalone DR (also
        # no CR) is now tracked by _handle_dr. The old extra `not cr_seen` clause
        # was unsatisfiable for any tracked connection and made this dead.
        for conn in self.connections.values():
            if conn.dr_seen and not conn.cc_seen:
                result["alerts"].append(
                    {
                        "level": "highlight",
                        "category": "cotp_probe",
                        "message": (
                            f"COTP PROBE: DR from {conn.src_ip} to {conn.dst_ip} "
                            f"ref=0x{conn.src_ref:04X}->0x{conn.dst_ref:04X} "
                            f"without prior connection -- possible probing"
                        ),
                    }
                )

        # Alert: large TPKT lengths (potential exploitation)
        for entry in self._large_tpkt:
            result["alerts"].append(
                {
                    "level": "highlight",
                    "category": "cotp_large_tpkt",
                    "message": (
                        f"COTP LARGE TPKT: {entry['src_ip']} -> {entry['dst_ip']} "
                        f"length={entry['tpkt_length']} PDU={entry['pdu_type']} "
                        f"-- unusually large packet"
                    ),
                }
            )

        if not result.get("tables") and not result.get("alerts"):
            return {}
        return result

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _update_device(self, ip: str, ep: COTPEndpoint) -> None:
        """Update or create a device entry for a COTP endpoint."""
        if not ip or not is_valid_discovered_ip(ip):
            return

        device_key = f"cotp:{ip}"
        mac = ep.mac
        vendor = lookup_mac_vendor(mac) if mac else ""
        if vendor == "Unknown":
            vendor = ""

        # Determine role based on connection patterns
        if ep.cr_received > ep.cr_sent:
            device_type = "COTP Server (ISO Transport)"
        elif ep.cr_sent > ep.cr_received:
            device_type = "COTP Client (ISO Transport)"
        else:
            device_type = "COTP Endpoint (ISO Transport)"

        device, is_new = self._ensure_device(
            device_key,
            ip,
            mac=mac,
            device_type=device_type,
            manufacturer=vendor,
        )

        device.cotp_passive_data = self._build_device_data(ip)

        if is_new:
            tsaps = sorted(ep.tsaps_seen)
            tsap_str = f" TSAPs={tsaps}" if tsaps else ""
            self.logger.debug(
                f"COTP: {ip} CR_sent={ep.cr_sent} CC_sent={ep.cc_sent} DT={ep.dt_count}{tsap_str}"
            )

    def _build_device_data(self, ip: str) -> Dict[str, Any]:
        """Build cotp_passive_data dict for an endpoint IP."""
        ep = self.endpoints.get(ip)
        if not ep:
            return {}

        # Identify likely upper-layer protocol from TSAPs
        services: List[str] = []
        for tsap in ep.tsaps_seen:
            tsap_lower = tsap.lower().replace(":", "")
            label = KNOWN_TSAPS.get(tsap_lower, "")
            if label and label not in services:
                services.append(label)

        return {
            "role": "cotp_endpoint",
            "cr_sent": ep.cr_sent,
            "cr_received": ep.cr_received,
            "cc_sent": ep.cc_sent,
            "cc_received": ep.cc_received,
            "dr_sent": ep.dr_sent,
            "dt_count": ep.dt_count,
            "er_count": ep.er_count,
            "rj_count": ep.rj_count,
            "total_frames": ep.total_frames,
            "tsaps": sorted(ep.tsaps_seen),
            "services": services,
            "peers": sorted(ep.peer_ips),
            "protocol": "COTP/TCP",
            "first_seen": ep.first_seen,
            "last_seen": ep.last_seen,
        }

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(
        pdu_name: str,
        src_ref: int,
        dst_ref: int,
        calling_tsap: str,
        called_tsap: str,
        tpkt_length: int,
    ) -> str:
        """Build a one-line human-readable interaction summary."""
        parts: List[str] = [pdu_name]

        if src_ref or dst_ref:
            parts.append(f"Ref=0x{src_ref:04X}->0x{dst_ref:04X}")

        if calling_tsap and called_tsap:
            parts.append(f"TSAP={calling_tsap}->{called_tsap}")
        elif calling_tsap:
            parts.append(f"TSAP={calling_tsap}")
        elif called_tsap:
            parts.append(f"TSAP={called_tsap}")

        if tpkt_length:
            parts.append(f"Len={tpkt_length}")

        return " ".join(parts)
