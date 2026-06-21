"""
Modbus TCP Passive Listener (PyShark-based).

Passively monitors Modbus TCP traffic to identify:
- Modbus servers (slaves) and clients (masters)
- Unit IDs in use
- Function codes being used
- Register/coil address ranges
- Write operations (potentially dangerous)

Based on Modbus Application Protocol Specification V1.1b3.

Protocol format:
- MBAP Header (7 bytes): Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1)
- PDU: Function Code (1) + Data (variable)

Uses PyShark/tshark for Modbus TCP dissection:
- mbtcp layer: MBAP header fields (trans_id, prot_id, len, unit_id)
- modbus layer: PDU fields (func_code, reference_num, word_cnt, bit_cnt)

Reference: https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf
"""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

import logging

logger = logging.getLogger(__name__)


# Modbus function codes
MODBUS_FC = {
    # Read functions
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    # Write functions (potentially dangerous)
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
    # Diagnostic functions
    0x07: "Read Exception Status",
    0x08: "Diagnostics",
    0x0B: "Get Comm Event Counter",
    0x0C: "Get Comm Event Log",
    0x11: "Report Slave ID",
    # Advanced functions
    0x14: "Read File Record",
    0x15: "Write File Record",
    0x16: "Mask Write Register",
    0x17: "Read/Write Multiple Registers",
    0x18: "Read FIFO Queue",
    0x2B: "Encapsulated Interface Transport",
}

# Write function codes (potentially dangerous operations)
WRITE_FUNCTION_CODES = {0x05, 0x06, 0x0F, 0x10, 0x15, 0x16, 0x17}

# Read function codes
READ_FUNCTION_CODES = {0x01, 0x02, 0x03, 0x04, 0x07, 0x0B, 0x0C, 0x11, 0x14, 0x17, 0x18}


@dataclass
class ModbusSession:
    """Track Modbus session statistics."""

    client_ip: str
    server_ip: str
    unit_ids: Set[int] = field(default_factory=set)
    function_codes: Set[int] = field(default_factory=set)
    read_addresses: List[Tuple[int, int]] = field(default_factory=list)  # (start, count)
    write_addresses: List[Tuple[int, int]] = field(default_factory=list)
    write_count: int = 0
    read_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    trans_id_min: Optional[int] = None
    trans_id_max: Optional[int] = None


class ModbusPassiveListener(PySharkListenerBase):
    """Passive Modbus TCP traffic listener (PyShark-based).

    Monitors Modbus TCP traffic without sending packets to:
    - Identify Modbus servers and clients
    - Track unit IDs in use
    - Monitor function codes (detect writes)
    - Map register/coil address ranges
    - Detect potentially dangerous operations

    Uses PyShark/tshark for Modbus protocol dissection:
    - mbtcp layer: MBAP header (transaction_id, protocol_id, unit_id)
    - modbus layer: PDU (func_code, reference_num, word_cnt, bit_cnt)

    Usage:
        # Live capture
        listener = ModbusPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
        devices = listener.scan()

        # Access session statistics
        for session in listener.sessions.values():
            print(f"{session.client_ip} -> {session.server_ip}")
            print(f"  Unit IDs: {session.unit_ids}")
            print(f"  Writes: {session.write_count}")

    Data stored in device.modbus_passive_data:
        {
            "role": "server" | "client",
            "unit_ids": [1, 2, 3],
            "function_codes_seen": [1, 2, 3, 4],
            "register_ranges": [(0, 100), (1000, 1100)],
            "write_operations": 5,
            "read_operations": 10,
            "protocol": "Modbus/TCP",
        }
    """

    PROTOCOL_NAME = "modbus"
    DISPLAY_FILTER = "mbtcp"  # Modbus/TCP protocol
    REQUIRED_LAYERS = ("mbtcp",)
    OVERRIDE_PREFS = {"mbtcp.tcp.port": "502"}
    PROTOCOL_COLUMNS = ("tx_id", "unit", "fc", "function", "address", "count", "data")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize Modbus passive listener."""
        super().__init__(interface, timeout, nxc_logger)
        # Track sessions by (client_ip, server_ip) tuple
        self.sessions: Dict[Tuple[str, str], ModbusSession] = {}
        # FIFO queues of request address info per connection for correlating
        # with responses (pop when a response without address info arrives).
        self._req_addr_q: Dict[Tuple[str, str], Deque[Tuple[int, int]]] = {}

    def process_packet(self, packet) -> None:
        """Process Modbus TCP packet using PyShark dissection.

        Handles multi-PDU TCP segments where tshark dissects multiple Modbus
        messages in one frame.  In EK mode these produce ``_fields_dict`` as a
        list of dicts instead of a single dict -- PyShark's EkLayer cannot
        resolve field names in that case, so we iterate the raw dicts and
        create synthetic EkLayer objects for each PDU.
        """
        # Check for Modbus TCP layer
        if not hasattr(packet, "mbtcp"):
            return

        # Get IP and port info (shared across all PDUs in the segment)
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        flow_id = self.get_flow_id(packet)
        stream_id = self.get_stream_id(packet)

        # Detect multi-PDU EK mode: _fields_dict is a list of dicts
        mbtcp_dicts = self._get_ek_layer_dicts(packet.mbtcp)
        modbus_dicts = (
            self._get_ek_layer_dicts(packet.modbus) if hasattr(packet, "modbus") else None
        )

        if mbtcp_dicts is not None:
            # Multi-PDU TCP segment -- iterate each PDU
            from pyshark.packet.layers.ek_layer import EkLayer as _EkLayer

            n_mbtcp = len(mbtcp_dicts)
            n_modbus = len(modbus_dicts) if modbus_dicts else 0

            for i in range(n_mbtcp):
                mbtcp_syn = _EkLayer(packet.mbtcp._layer_name, mbtcp_dicts[i])
                if modbus_dicts and i < n_modbus:
                    modbus_syn = _EkLayer(packet.modbus._layer_name, modbus_dicts[i])
                else:
                    modbus_syn = None
                self._process_single_pdu(
                    mbtcp_syn,
                    modbus_syn,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    src_mac,
                    dst_mac,
                    flow_id,
                    stream_id,
                    packet,
                )
        else:
            # Normal single-PDU path
            modbus_layer = packet.modbus if hasattr(packet, "modbus") else None
            self._process_single_pdu(
                packet.mbtcp,
                modbus_layer,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                src_mac,
                dst_mac,
                flow_id,
                stream_id,
                packet,
            )

    # ------------------------------------------------------------------
    # EK multi-PDU helper
    # ------------------------------------------------------------------

    @staticmethod
    def _get_ek_layer_dicts(layer) -> Optional[List[dict]]:
        """Return the raw list of dicts when an EK layer wraps multiple PDUs.

        In PyShark's EK mode, multi-PDU TCP segments store ``_fields_dict``
        as a *list* of dicts instead of a single dict.  PyShark's ``EkLayer``
        cannot resolve field names in that case.  This helper detects the
        array case and returns the list, or ``None`` for normal single-PDU
        layers.
        """
        try:
            fd = object.__getattribute__(layer, "_fields_dict")
            if isinstance(fd, list):
                return fd
        except AttributeError as e:
            logger.debug(f"Modbus EK layer _fields_dict access failed: {e}")
        return None

    # ------------------------------------------------------------------
    # Per-PDU processing
    # ------------------------------------------------------------------

    def _process_single_pdu(
        self,
        mbtcp_layer,
        modbus_layer,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
        stream_id: str,
        packet,
    ) -> None:
        """Process a single Modbus PDU (one MBAP + one modbus payload).

        Called once for normal packets and N times for multi-PDU segments.
        """
        # Extract MBAP header fields from mbtcp layer
        unit_id_str = self.get_field(mbtcp_layer, "unit_id")
        prot_id_str = self.get_field(mbtcp_layer, "prot_id")
        trans_id_str = self.get_field(mbtcp_layer, "trans_id")
        pdu_len_str = self.get_field(mbtcp_layer, "len")

        # Verify Modbus protocol ID (should be 0). Pyshark's EK output can
        # misread this byte when tshark emits a "Cannot classify packet type"
        # warning (the recovery path shifts offsets), so non-zero prot_id is
        # only a soft signal — log and proceed. The presence of a mbtcp layer
        # plus a valid func_code in the modbus payload is the real evidence.
        if prot_id_str is not None:
            try:
                prot_id = int(prot_id_str)
                if prot_id != 0:
                    self.logger.debug(
                        f"non-zero mbtcp.prot_id={prot_id} from {src_ip} -> {dst_ip}; "
                        "EK parser quirk on 'Cannot classify' frames — proceeding"
                    )
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get prot_id: {e}")

        # Parse unit ID
        unit_id = 0
        if unit_id_str:
            try:
                unit_id = int(unit_id_str)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get unit_id: {e}")

        # Parse MBAP Transaction ID (pairs requests with responses)
        trans_id: Optional[int] = None
        if trans_id_str:
            try:
                trans_id = int(trans_id_str)
            except (ValueError, TypeError):
                self.logger.debug(
                    f"Failed to parse trans_id={trans_id_str!r} from {src_ip} -> {dst_ip}"
                )

        # Parse MBAP PDU Length
        pdu_len: Optional[int] = None
        if pdu_len_str:
            try:
                pdu_len = int(pdu_len_str)
            except (ValueError, TypeError):
                self.logger.debug(
                    f"Failed to parse pdu_len={pdu_len_str!r} from {src_ip} -> {dst_ip}"
                )

        # Get function code from modbus layer
        fc_found = False
        function_code = 0
        if modbus_layer is not None:
            fc_str = self.get_field(modbus_layer, "func_code")
            if fc_str:
                try:
                    # func_code can be hex or decimal
                    if isinstance(fc_str, str) and fc_str.startswith("0x"):
                        function_code = int(fc_str, 16)
                    else:
                        function_code = int(fc_str)
                    fc_found = True
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"if isinstance(fc_str, str) and fc_str...: {e}")

        if not fc_found:
            # No function code at all -- MBAP-only frame (e.g. keepalive or
            # fragment).  Still record an interaction so nothing is dropped.
            self._record_mbap_only(
                mbtcp_layer,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                src_mac,
                dst_mac,
                flow_id,
                stream_id,
                unit_id,
                trans_id,
                pdu_len,
            )
            return

        # Determine direction. Modbus-TCP defaults to port 502 but the spec
        # allows any TCP port — gateways and security devices commonly relay
        # over non-standard ports. Use the canonical port if either side has
        # it; otherwise fall back to "lower port wins" (server side has the
        # smaller fixed port; client side has an ephemeral high port).
        if dst_port == 502 or (dst_port != 502 and src_port != 502 and dst_port < src_port):
            # Request: src is client, dst is server
            client_ip = src_ip
            server_ip = dst_ip
            client_mac = src_mac
            server_mac = dst_mac
            is_request = True
        else:
            # Response: src is server, dst is client
            client_ip = dst_ip
            server_ip = src_ip
            client_mac = dst_mac
            server_mac = src_mac
            is_request = False

        # Extract address information from modbus layer
        address_info = None
        if modbus_layer is not None:
            address_info = self._extract_address_info(modbus_layer, function_code)

        # Correlate: queue request addresses, dequeue for responses
        conn_key = (client_ip, server_ip)
        if is_request and address_info:
            self._req_addr_q.setdefault(conn_key, deque()).append(address_info)
        elif not is_request and not address_info:
            q = self._req_addr_q.get(conn_key)
            if q:
                address_info = q.popleft()

        # Check for exception response
        is_exception = False
        exception_code = 0
        if not is_request and modbus_layer is not None:
            exc_str = self.get_field(modbus_layer, "exception_code")
            if exc_str:
                try:
                    exception_code = int(exc_str)
                    is_exception = True
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to get exception_code: {e}")

        # Extract register/coil values when meaningful:
        #   - Responses to read FCs (1-4): carry read-back values
        #   - Requests with write FCs (5,6,15,16): carry values being written
        values: List[str] = []
        has_decode_error = False
        if modbus_layer is not None:
            want_values = (not is_request and function_code in READ_FUNCTION_CODES) or (
                is_request and function_code in WRITE_FUNCTION_CODES
            )
            if want_values:
                values = self._extract_values(modbus_layer, function_code)
            # Detect tshark decode failure
            cc = self.get_field(mbtcp_layer, "cannot_classify")
            if cc is not None:
                has_decode_error = True

        # Record interaction
        now = datetime.now().isoformat()
        fc_name = MODBUS_FC.get(function_code, f"FC{function_code}")
        direction = "request" if is_request else "response"
        details: Dict[str, Any] = {
            "unit_id": unit_id,
            "function_code": function_code,
            "function_name": fc_name,
            "trans_id": trans_id,
            "pdu_len": pdu_len,
        }

        if address_info:
            details["address"] = address_info[0]
            details["quantity"] = address_info[1]

        if is_exception:
            details["exception_code"] = exception_code

        if values:
            details["values"] = values
            # Hex representation for easy reverse engineering
            hex_vals = []
            for v in values:
                try:
                    hex_vals.append(f"{int(v):04x}")
                except (ValueError, TypeError):
                    hex_vals.append(v)
            details["values_hex"] = hex_vals
        elif has_decode_error:
            details["values"] = ["[decode error]"]

        summary = self._build_interaction_summary(
            unit_id,
            fc_name,
            function_code,
            address_info,
            is_exception,
            exception_code,
            is_request,
        )
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            fc_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Update session
        session_key = (client_ip, server_ip)
        self._update_session(
            session_key, unit_id, function_code, address_info, is_request, trans_id
        )

        # Update devices
        self._update_devices(client_ip, client_mac, server_ip, server_mac, session_key)

    def _record_mbap_only(
        self,
        mbtcp_layer,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
        stream_id: str,
        unit_id: int,
        trans_id: Optional[int],
        pdu_len: Optional[int],
    ) -> None:
        """Record an interaction for an MBAP-only frame (no modbus func_code).

        These are typically keepalives, fragments, or malformed frames.
        We still record them so no packet matching the display filter is
        silently dropped.
        """
        now = datetime.now().isoformat()
        # Direction: same lower-port-wins fallback as the main path.
        is_request_dir = dst_port == 502 or (
            dst_port != 502 and src_port != 502 and dst_port < src_port
        )
        direction = "request" if is_request_dir else "response"
        details: Dict[str, Any] = {
            "unit_id": unit_id,
            "function_code": "?",
            "function_name": "MBAP Only",
            "trans_id": trans_id,
            "pdu_len": pdu_len,
        }
        self.logger.debug(
            f"MBAP-only frame (no func_code) from {src_ip}:{src_port} -> "
            f"{dst_ip}:{dst_port} unit={unit_id} trans_id={trans_id}"
        )
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            "MBAP Only",
            details,
            f"UnitID {unit_id}: MBAP-only frame (no function code)",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Still update session and devices for visibility
        if is_request_dir:
            client_ip, server_ip = src_ip, dst_ip
            client_mac, server_mac = src_mac, dst_mac
        else:
            client_ip, server_ip = dst_ip, src_ip
            client_mac, server_mac = dst_mac, src_mac

        session_key = (client_ip, server_ip)
        if session_key not in self.sessions:
            self.sessions[session_key] = ModbusSession(
                client_ip=client_ip,
                server_ip=server_ip,
                first_seen=now,
                last_seen=now,
            )
        else:
            self.sessions[session_key].last_seen = now
        self.sessions[session_key].unit_ids.add(unit_id)

        self._update_devices(client_ip, client_mac, server_ip, server_mac, session_key)

    def _extract_address_info(self, modbus_layer, function_code: int) -> Optional[Tuple[int, int]]:
        """Extract starting address and quantity from PyShark modbus layer.

        Args:
            modbus_layer: PyShark modbus layer
            function_code: Modbus function code

        Returns:
            Tuple of (starting_address, quantity) or None
        """
        # Get reference number (starting address)
        ref_num_str = self.get_field(modbus_layer, "reference_num")
        if not ref_num_str:
            # Try read/write specific fields
            ref_num_str = self.get_field(modbus_layer, "read_reference_num")
            if not ref_num_str:
                ref_num_str = self.get_field(modbus_layer, "write_reference_num")

        if not ref_num_str:
            return None

        try:
            starting_addr = int(ref_num_str)
        except (ValueError, TypeError) as e:
            self.logger.debug(f"Failed to get starting_addr: {e}")
            return None

        # Get quantity based on function code type
        quantity = 1  # Default for single coil/register writes

        if function_code in (0x01, 0x02):
            # Coil/discrete input reads - use bit_cnt
            bit_cnt_str = self.get_field(modbus_layer, "bit_cnt")
            if bit_cnt_str:
                try:
                    quantity = int(bit_cnt_str)
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to get quantity: {e}")
        elif function_code in (0x03, 0x04, 0x10, 0x17):
            # Register reads/writes - use word_cnt
            word_cnt_str = self.get_field(modbus_layer, "word_cnt")
            if not word_cnt_str:
                word_cnt_str = self.get_field(modbus_layer, "read_word_cnt")
            if not word_cnt_str:
                word_cnt_str = self.get_field(modbus_layer, "write_word_cnt")
            if word_cnt_str:
                try:
                    quantity = int(word_cnt_str)
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to get quantity: {e}")
        elif function_code == 0x0F:
            # Write multiple coils - use bit_cnt
            bit_cnt_str = self.get_field(modbus_layer, "bit_cnt")
            if bit_cnt_str:
                try:
                    quantity = int(bit_cnt_str)
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to get quantity: {e}")

        return (starting_addr, quantity)

    def _extract_values(self, modbus_layer, function_code: int) -> List[str]:
        """Extract register/coil values from a PyShark modbus layer.

        Tries ``modbus.regval_uint16`` (register values) and
        ``modbus.bitval`` (coil/discrete values).

        In EK mode, multi-value fields are returned as comma-separated
        strings by ``get_field()`` (e.g. ``"9,24"``).  In XML mode they
        are field objects with ``.all_fields``.  Both paths are handled.

        Returns:
            List of value strings, or ``[]`` if none found.
        """
        vals: List[str] = []

        # Register values (FC 3, 4, 16, etc.)
        raw = self.get_field(modbus_layer, "regval_uint16")
        if raw is not None:
            vals = self._parse_field_values(modbus_layer, "regval_uint16", raw)

        # Coil / discrete bit values (FC 1, 2, 5, 15)
        if not vals:
            raw = self.get_field(modbus_layer, "bitval")
            if raw is not None:
                vals = self._parse_field_values(modbus_layer, "bitval", raw)

        # Single-register write (FC 6) — value is in regval_uint16 already handled,
        # but also check modbus.regval16 as a fallback
        if not vals:
            raw = self.get_field(modbus_layer, "regval16")
            if raw is not None:
                vals = self._parse_field_values(modbus_layer, "regval16", raw)

        # Write Single Coil (FC 5) / Write Multiple Coils (FC 15) — tshark
        # stores the raw coil bytes in modbus.data (hex string like "00:00"
        # or "ff:00") rather than regval/bitval.  Decode to ON/OFF.
        if not vals and function_code in (0x05, 0x0F):
            raw = self.get_field(modbus_layer, "data")
            if raw is not None:
                vals = self._parse_coil_data(raw, function_code)

        return vals

    @staticmethod
    def _parse_coil_data(raw: str, function_code: int) -> List[str]:
        """Decode modbus.data hex bytes into coil ON/OFF values.

        FC5 Write Single Coil: 2 bytes — ``FF00`` = ON, ``0000`` = OFF.
        FC15 Write Multiple Coils: N bytes — each bit is one coil.
        """
        hex_str = str(raw).replace(":", "").replace(" ", "")
        if not hex_str:
            return []
        try:
            data_bytes = bytes.fromhex(hex_str)
        except ValueError as e:
            logger.debug(f"Failed to get data_bytes: {e}")
            return []
        if function_code == 0x05:
            return ["ON" if data_bytes[0] == 0xFF else "OFF"]
        # FC15: each bit is a coil, LSB first per byte
        vals: List[str] = []
        for byte in data_bytes:
            for bit in range(8):
                vals.append("1" if byte & (1 << bit) else "0")
        return vals

    @staticmethod
    def _parse_field_values(layer, field_name: str, raw: str) -> List[str]:
        """Parse register/coil values from a pyshark field.

        Handles both XML mode (``.all_fields``) and EK mode (comma-separated
        string from ``get_field()``).
        """
        vals: List[str] = []
        # XML mode: field objects with .all_fields / .showname_value
        try:
            for fld in getattr(layer, field_name).all_fields:
                vals.append(str(int(fld.showname_value)))
            if vals:
                return vals
        except Exception as e:
            logger.debug(f"for fld in getattr(layer, field_name)...: {e}")
        # EK mode: get_field() normalises lists to "v1,v2,..." strings
        # and bools to "True"/"False" (coil/discrete bit values).
        raw_str = str(raw)
        for part in raw_str.split(","):
            part = part.strip()
            if not part:
                continue
            low = part.lower()
            if low in ("true", "false"):
                vals.append("1" if low == "true" else "0")
            else:
                try:
                    vals.append(str(int(part)))
                except (ValueError, TypeError):
                    vals.append(part)
        return vals

    def _update_session(
        self,
        session_key: Tuple[str, str],
        unit_id: int,
        function_code: int,
        address_info: Optional[Tuple[int, int]],
        is_request: bool,
        trans_id: Optional[int] = None,
    ) -> None:
        """Update session statistics."""
        now = datetime.now().isoformat()

        if session_key not in self.sessions:
            self.sessions[session_key] = ModbusSession(
                client_ip=session_key[0],
                server_ip=session_key[1],
                first_seen=now,
                last_seen=now,
            )

        session = self.sessions[session_key]
        session.last_seen = now
        session.unit_ids.add(unit_id)
        session.function_codes.add(function_code)

        # Track transaction ID range
        if trans_id is not None:
            if session.trans_id_min is None or trans_id < session.trans_id_min:
                session.trans_id_min = trans_id
            if session.trans_id_max is None or trans_id > session.trans_id_max:
                session.trans_id_max = trans_id

        # Only track address details for requests
        if not is_request:
            return

        # Track read/write operations
        if function_code in WRITE_FUNCTION_CODES:
            session.write_count += 1
            if address_info:
                session.write_addresses.append(address_info)
        elif function_code in READ_FUNCTION_CODES:
            session.read_count += 1
            if address_info:
                session.read_addresses.append(address_info)

    def _update_devices(
        self,
        client_ip: str,
        client_mac: str,
        server_ip: str,
        server_mac: str,
        session_key: Tuple[str, str],
    ) -> None:
        """Update device entries for client and server."""
        session = self.sessions[session_key]

        # Server device
        if is_valid_discovered_ip(server_ip):
            server_key = f"modbus-server:{server_ip}"
            server_vendor = lookup_mac_vendor(server_mac) if server_mac else ""

            device, is_new = self._ensure_device(
                server_key,
                server_ip,
                mac=server_mac,
                device_type="Modbus Server (PLC/RTU)",
                manufacturer=server_vendor,
            )
            device.modbus_passive_data = self._build_device_data("server", session)
            if is_new:
                self.logger.debug(f"Modbus: Server {server_ip} units={list(session.unit_ids)}")
        # Client device
        if is_valid_discovered_ip(client_ip):
            client_key = f"modbus-client:{client_ip}"
            client_vendor = lookup_mac_vendor(client_mac) if client_mac else ""

            device, is_new = self._ensure_device(
                client_key,
                client_ip,
                mac=client_mac,
                device_type="Modbus Client (HMI/SCADA)",
                manufacturer=client_vendor,
            )
            device.modbus_passive_data = self._build_device_data("client", session)

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        addr = d.get("address", "")
        qty = d.get("quantity", "")
        if addr != "" and qty:
            addr_str = f"{addr}-{addr + qty - 1}" if qty > 1 else str(addr)
        elif addr != "":
            addr_str = str(addr)
        elif ix.direction == "response":
            # Response with no correlated request — mark as unknown
            addr_str = "?"
            qty = "?"
        else:
            addr_str = ""

        exc = d.get("exception_code")
        if exc:
            data = f"Exception {exc}"
        else:
            vals = d.get("values", [])
            data = " | ".join(vals) if isinstance(vals, list) else ""

        trans_id = d.get("trans_id")
        trans_id_str = str(trans_id) if trans_id is not None else ""

        return [
            trans_id_str,
            d.get("unit_id", ""),
            d.get("function_code", ""),
            d.get("function_name", ""),
            addr_str,
            qty if qty else "",
            data,
        ]

    def harvest(self) -> Dict[str, Any]:
        """Filter out WRITE alerts (writes are visible in the operations table)."""
        result = super().harvest()
        if result and result.get("alerts"):
            result["alerts"] = [a for a in result["alerts"] if a.get("category") != "write_alert"]
        return result

    def _build_device_data(self, role: str, session: ModbusSession) -> Dict[str, Any]:
        """Build modbus_passive_data dict from session."""
        # Merge overlapping address ranges
        read_ranges = self._merge_ranges(session.read_addresses)
        write_ranges = self._merge_ranges(session.write_addresses)

        data: Dict[str, Any] = {
            "role": role,
            "unit_ids": sorted(list(session.unit_ids)),
            "function_codes_seen": sorted(list(session.function_codes)),
            "function_names": [
                MODBUS_FC.get(fc, f"FC{fc}") for fc in sorted(session.function_codes)
            ],
            "read_ranges": read_ranges,
            "write_ranges": write_ranges,
            "write_operations": session.write_count,
            "read_operations": session.read_count,
            "protocol": "Modbus/TCP",
            "first_seen": session.first_seen,
            "last_seen": session.last_seen,
        }
        if session.trans_id_min is not None:
            data["trans_id_range"] = [session.trans_id_min, session.trans_id_max]
        return data

    def _merge_ranges(self, addresses: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        """Merge overlapping address ranges."""
        if not addresses:
            return []

        # Convert (start, count) to (start, end)
        ranges = [(start, start + count - 1) for start, count in addresses]

        # Sort by start address
        ranges.sort(key=lambda x: x[0])

        merged = [ranges[0]]
        for start, end in ranges[1:]:
            last_start, last_end = merged[-1]
            if start <= last_end + 1:
                # Overlapping or adjacent, merge
                merged[-1] = (last_start, max(last_end, end))
            else:
                merged.append((start, end))

        return merged

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed Modbus sessions."""
        summaries = []
        for session in self.sessions.values():
            s: Dict[str, Any] = {
                "client": session.client_ip,
                "server": session.server_ip,
                "unit_ids": sorted(list(session.unit_ids)),
                "function_codes": sorted(list(session.function_codes)),
                "write_count": session.write_count,
                "read_count": session.read_count,
                "first_seen": session.first_seen,
                "last_seen": session.last_seen,
            }
            if session.trans_id_min is not None:
                s["trans_id_range"] = [session.trans_id_min, session.trans_id_max]
            summaries.append(s)
        return summaries

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with write operations (potentially dangerous)."""
        return [
            {
                "client": session.client_ip,
                "server": session.server_ip,
                "write_count": session.write_count,
                "write_function_codes": [
                    fc for fc in session.function_codes if fc in WRITE_FUNCTION_CODES
                ],
                "write_ranges": self._merge_ranges(session.write_addresses),
            }
            for session in self.sessions.values()
            if session.write_count > 0
        ]

    @staticmethod
    def _build_interaction_summary(
        unit_id: int,
        fc_name: str,
        function_code: int,
        address_info: Optional[Tuple[int, int]],
        is_exception: bool,
        exception_code: int,
        is_request: bool,
    ) -> str:
        """Build a one-line human-readable interaction summary."""
        if is_exception:
            return f"UnitID {unit_id}: Exception {exception_code} for {fc_name}"

        if not is_request:
            return f"UnitID {unit_id}: {fc_name} response"

        if address_info:
            addr, qty = address_info
            if function_code in WRITE_FUNCTION_CODES:
                if qty == 1:
                    return f"UnitID {unit_id}: {fc_name} @{addr}"
                return f"UnitID {unit_id}: {fc_name} @{addr}-{addr + qty - 1} ({qty})"
            else:
                return f"UnitID {unit_id}: {fc_name} @{addr}-{addr + qty - 1} ({qty})"

        return f"UnitID {unit_id}: {fc_name}"
