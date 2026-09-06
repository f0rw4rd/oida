"""
X11 Passive Listener for display protocol and credential extraction.

Passively captures X11 (X Window System) traffic to extract:
- MIT-MAGIC-COOKIE-1 authentication data from initial connections
- Unauthenticated connection attempts (security risk)
- Display information (protocol version, screen dimensions)
- Window operations (CreateWindow, MapWindow, etc.)
- Connection establishment and tear-down

X11 uses TCP port 6000+display_number (e.g., :0 = 6000, :1 = 6001).
The protocol starts with a connection request containing optional
authentication data.

Security value:
- MIT-MAGIC-COOKIE-1 extraction enables display hijacking
- Unauthenticated X11 access enables keylogging and screenshotting
- Remote X11 forwarding detection

PyShark X11 field reference (EK mode short names):
- x11.byte-order: Byte order indicator ('B' or 'l')
- x11.protocol-major-version: Protocol major version (always 11)
- x11.protocol-minor-version: Protocol minor version
- x11.authorization-protocol-name: Auth protocol (e.g., "MIT-MAGIC-COOKIE-1")
- x11.authorization-protocol-name-length: Auth name length
- x11.authorization-protocol-data: Auth data (cookie bytes)
- x11.authorization-protocol-data-length: Auth data length
- x11.success: Connection reply success code (1=success, 0=fail)
- x11.replylength: Reply data length
- x11.opcode: Request opcode (for subsequent requests)
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

# X11 port range
X11_BASE_PORT = 6000
X11_PORTS = set(range(6000, 6064))  # :0 through :63

# X11 request opcodes
X11_OPCODES = {
    1: "CreateWindow",
    2: "ChangeWindowAttributes",
    3: "GetWindowAttributes",
    4: "DestroyWindow",
    5: "DestroySubwindows",
    6: "ChangeSaveSet",
    7: "ReparentWindow",
    8: "MapWindow",
    9: "MapSubwindows",
    10: "UnmapWindow",
    12: "ConfigureWindow",
    14: "GetGeometry",
    15: "QueryTree",
    16: "InternAtom",
    17: "GetAtomName",
    18: "ChangeProperty",
    19: "DeleteProperty",
    20: "GetProperty",
    23: "GetSelectionOwner",
    38: "QueryPointer",
    40: "TranslateCoords",
    42: "SetInputFocus",
    43: "GetInputFocus",
    47: "QueryFont",
    48: "QueryTextExtents",
    49: "ListFonts",
    55: "CreateGC",
    56: "ChangeGC",
    60: "FreeGC",
    62: "CopyArea",
    72: "PutImage",
    73: "GetImage",
    84: "AllocColor",
    91: "QueryColors",
    98: "QueryExtension",
    99: "ListExtensions",
    101: "GetKeyboardMapping",
    104: "Bell",
    116: "SetPointerMapping",
    119: "GetModifierMapping",
}

# X11 event codes (server -> client)
X11_EVENT_CODES = {
    2: "KeyPress",
    3: "KeyRelease",
    4: "ButtonPress",
    5: "ButtonRelease",
    6: "MotionNotify",
    7: "EnterNotify",
    8: "LeaveNotify",
    9: "FocusIn",
    10: "FocusOut",
    11: "KeymapNotify",
    12: "Expose",
    13: "GraphicsExposure",
    14: "NoExposure",
    15: "VisibilityNotify",
    16: "CreateNotify",
    17: "DestroyNotify",
    18: "UnmapNotify",
    19: "MapNotify",
    20: "MapRequest",
    21: "ReparentNotify",
    22: "ConfigureNotify",
    23: "ConfigureRequest",
    24: "GravityNotify",
    25: "ResizeRequest",
    26: "CirculateNotify",
    27: "CirculateRequest",
    28: "PropertyNotify",
    29: "SelectionClear",
    30: "SelectionRequest",
    31: "SelectionNotify",
    32: "ColormapNotify",
    33: "ClientMessage",
    34: "MappingNotify",
    35: "GenericEvent",
}


class X11PassiveListener(PySharkListenerBase):
    """Passive X11 traffic listener for display and credential extraction.

    Captures X11 traffic to extract:
    - MIT-MAGIC-COOKIE-1 authentication cookies (credential extraction)
    - Unauthenticated connection attempts (no auth data)
    - Protocol version and display information
    - Window operations (CreateWindow, MapWindow, etc.)
    - Connection success/failure tracking

    Security implications:
    - Extracted cookies can be used for X11 display hijacking
    - Unauthenticated X11 access enables keylogging
    - Remote X11 forwarding may expose internal displays

    Usage:
        listener = X11PassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for cred in listener.credentials:
            print(f"X11 cookie: {cred['auth_data']}")
    """

    PROTOCOL_NAME = "x11"
    DISPLAY_FILTER = "x11"
    REQUIRED_LAYERS = ("x11",)
    SERVER_PORTS = tuple(sorted(X11_PORTS))
    PROTOCOL_COLUMNS = ("operation", "auth_method", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)

        self._known_servers: Set[str] = set()
        self.credentials: List[Dict[str, Any]] = []
        self._seen_creds: Set[Tuple[str, str, str]] = set()
        self._alerts: List[Dict[str, str]] = []

    def process_packet(self, packet) -> None:
        """Process X11 packet.

        Handles four packet categories:
        1. Connection request (has byte-order, no success)
        2. Connection reply (has success field)
        3. Core request (has opcode field via getattr)
        4. Fallback: reply, event, extension, or multi-PDU frame

        In EK mode, pyshark may deliver a *list* of dicts in _fields_dict
        when a single TCP segment carries multiple X11 PDUs.  Standard
        getattr() returns None for those frames because field_names is
        empty.  The fallback path inspects _fields_dict directly to
        ensure every frame produces exactly one interaction.
        """
        if not hasattr(packet, "x11"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        flow_id = self.get_flow_id(packet)
        stream_id = self.get_stream_id(packet)

        x11 = packet.x11
        now = self._get_timestamp()

        # Check for initial connection request
        byte_order = self.get_field(x11, "byte-order", None)
        success = self.get_field(x11, "success", None)

        if byte_order is not None and success is None:
            # Client connection request
            self._process_connection_request(
                now,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                src_mac,
                dst_mac,
                x11,
                flow_id,
                stream_id,
            )
        elif success is not None:
            # Server connection reply
            self._process_connection_reply(
                now,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                src_mac,
                dst_mac,
                x11,
                flow_id,
                stream_id,
            )
        else:
            # Regular X11 request/reply (opcodes)
            opcode = self.get_field(x11, "opcode", None)
            if opcode is not None:
                self._process_request(
                    now,
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    src_mac,
                    dst_mac,
                    x11,
                    flow_id,
                    stream_id,
                )
            else:
                # Fallback: handle replies, events, extensions, and
                # multi-PDU frames where getattr() can't resolve fields.
                self._process_fallback(
                    now,
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    src_mac,
                    dst_mac,
                    x11,
                    flow_id,
                    stream_id,
                )

    def _process_connection_request(
        self,
        now: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        x11: Any,
        flow_id: str,
        stream_id: str,
    ) -> None:
        """Process X11 initial connection request."""
        client_ip, client_port = src_ip, src_port
        server_ip, server_port = dst_ip, dst_port
        client_mac, server_mac = src_mac, dst_mac

        major_version = self.get_field(x11, "protocol-major-version", "")
        minor_version = self.get_field(x11, "protocol-minor-version", "")
        auth_name = str(self.get_field(x11, "authorization-protocol-name", "") or "")
        auth_data_raw = self.get_field(x11, "authorization-protocol-data", "")
        auth_name_len = self.get_field(x11, "authorization-protocol-name-length", "")
        auth_data_len = self.get_field(x11, "authorization-protocol-data-length", "")

        # Determine display number from port
        display_num = (dst_port - X11_BASE_PORT) if dst_port >= X11_BASE_PORT else 0

        # Extract auth data
        auth_data_hex = ""
        if auth_data_raw:
            raw_str = str(auth_data_raw)
            # Try to extract hex representation
            if ":" in raw_str:
                auth_data_hex = raw_str.replace(":", "")
            else:
                # Raw bytes -- encode to hex
                try:
                    auth_data_hex = raw_str.encode("latin-1").hex()
                except (UnicodeEncodeError, AttributeError):
                    auth_data_hex = raw_str

        # Detect unauthenticated access
        is_noauth = not auth_name or str(auth_name_len) in ("0", "")
        if is_noauth:
            self._alerts.append(
                {
                    "level": "fail",
                    "category": "write_alert",
                    "message": (
                        f"X11 NO AUTH: {client_ip} connecting to {server_ip}:{server_port} "
                        f"(display :{display_num}) without authentication"
                    ),
                }
            )

        # Record credential if auth data present
        if auth_name and auth_data_hex:
            self._record_credential(
                client_ip,
                server_ip,
                server_port,
                auth_name,
                auth_data_hex,
                display_num,
            )

        # Build details
        details: Dict[str, Any] = {
            "major_version": str(major_version) if major_version else "",
            "minor_version": str(minor_version) if minor_version else "",
            "auth_method": auth_name or "(none)",
            "auth_data_length": str(auth_data_len) if auth_data_len else "0",
            "display": f":{display_num}",
        }
        if is_noauth:
            details["no_auth"] = True
        if auth_data_hex:
            details["auth_data"] = auth_data_hex

        auth_summary = auth_name if auth_name else "NO AUTH"
        summary = f"X11 Connect {client_ip}->:{display_num}@{server_ip} auth={auth_summary}"

        self._record_interaction(
            now,
            client_ip,
            server_ip,
            "request",
            "Connect",
            details,
            summary,
            flow_id=flow_id,
            src_port=client_port,
            dst_port=server_port,
            stream_id=stream_id,
        )

        self._ensure_server_device(server_ip, server_port, server_mac, display_num)
        self._ensure_client_device(client_ip, server_ip, client_mac)

    def _process_connection_reply(
        self,
        now: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        x11: Any,
        flow_id: str,
        stream_id: str,
    ) -> None:
        """Process X11 connection reply from server."""
        server_ip, server_port = src_ip, src_port
        client_ip, client_port = dst_ip, dst_port
        self._known_servers.add(server_ip)

        success = self.get_field(x11, "success", "")
        major_version = self.get_field(x11, "protocol-major-version", "")
        minor_version = self.get_field(x11, "protocol-minor-version", "")
        reply_length = self.get_field(x11, "replylength", "")

        success_str = "Success" if str(success) == "1" else "Failed"

        details: Dict[str, Any] = {
            "success": str(success),
            "major_version": str(major_version) if major_version else "",
            "minor_version": str(minor_version) if minor_version else "",
            "reply_length": str(reply_length) if reply_length else "",
        }

        display_num = (src_port - X11_BASE_PORT) if src_port >= X11_BASE_PORT else 0

        summary = f"X11 {success_str} v{major_version}.{minor_version}"

        self._record_interaction(
            now,
            server_ip,
            client_ip,
            "response",
            f"Reply ({success_str})",
            details,
            summary,
            flow_id=flow_id,
            src_port=server_port,
            dst_port=client_port,
            stream_id=stream_id,
        )

        self._ensure_server_device(server_ip, server_port, src_mac, display_num)
        self._ensure_client_device(client_ip, server_ip, dst_mac)

    def _process_request(
        self,
        now: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        x11: Any,
        flow_id: str,
        stream_id: str,
    ) -> None:
        """Process X11 request with opcode."""
        opcode_raw = self.get_field(x11, "opcode", "")
        try:
            opcode_num = int(str(opcode_raw))
        except (ValueError, TypeError):
            opcode_num = 0

        opcode_name = X11_OPCODES.get(opcode_num, f"Request({opcode_num})")

        # A core X11 request carries an opcode and always flows client -> server,
        # a clean port-independent signal we feed as the cascade's native tier.
        # resolve_direction() also folds in learned _known_servers via the
        # known-server-port tier when native is absent, but here native settles
        # it directly.
        d = self.resolve_direction(
            None,
            native=True,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flow_id=flow_id,
        )
        direction = d.direction

        details: Dict[str, Any] = {
            "opcode": opcode_num,
            "opcode_name": opcode_name,
        }

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            opcode_name,
            details,
            f"X11 {opcode_name}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

    # -----------------------------------------------------------------
    # Fallback: replies, events, extensions, and multi-PDU frames
    # -----------------------------------------------------------------

    @staticmethod
    def _get_ek_field(fields_dict: dict, short_name: str, default: str = "") -> str:
        """Extract a field from an EK-mode _fields_dict sub-dict.

        Keys are prefixed ``x11_x11_``.  Returns *default* when the key
        is absent or the value is ``None``.

        tshark's ``-T ek`` JSON normalizes both dots and hyphens in field
        names to underscores, so a hyphenated short name like
        ``reply-sequencenumber`` is exposed as the key
        ``x11_x11_reply_sequencenumber``.  We therefore try the literal
        short name first and then fall back to the hyphen->underscore
        normalized form so both spellings resolve.
        """
        val = fields_dict.get(f"x11_x11_{short_name}")
        if val is None and "-" in short_name:
            val = fields_dict.get(f"x11_x11_{short_name.replace('-', '_')}")
        if val is None:
            return default
        if isinstance(val, list):
            # Multi-valued field -- take first non-None element
            for v in val:
                if v is not None:
                    return str(v)
            return default
        return str(val)

    def _classify_ek_subdict(self, sd: dict) -> tuple:
        """Classify an EK sub-dict into (msg_type, operation, details).

        Returns a tuple of ``(msg_type, operation, details_dict)`` where
        *msg_type* is one of ``"request"``, ``"reply"``, ``"event"``.
        """
        opcode_raw = self._get_ek_field(sd, "opcode")
        if opcode_raw:
            try:
                opcode_num = int(opcode_raw)
            except (ValueError, TypeError):
                opcode_num = 0
            opcode_name = X11_OPCODES.get(opcode_num, f"Request({opcode_num})")
            return (
                "request",
                opcode_name,
                {"opcode": opcode_num, "opcode_name": opcode_name},
            )

        # Extension request -- has major-opcode but no 'opcode'
        major_opc = self._get_ek_field(sd, "major-opcode")
        if major_opc and self._get_ek_field(sd, "reply") == "":
            # major-opcode without reply marker -> extension request
            minor_opc = self._get_ek_field(sd, "minor-opcode", "0")
            return (
                "request",
                f"ExtRequest({major_opc}.{minor_opc})",
                {"major_opcode": major_opc, "minor_opcode": minor_opc},
            )

        # Reply packet -- has 'reply' or 'reply-sequencenumber'
        reply_marker = self._get_ek_field(sd, "reply")
        reply_seq = self._get_ek_field(sd, "reply-sequencenumber")
        if reply_marker or reply_seq:
            ext_label = ""
            if major_opc:
                ext_label = f" ext={major_opc}"
            # Try to extract extension-specific info from field names
            ext_info = self._extract_extension_info(sd)
            details: Dict[str, Any] = {
                "reply_sequence": reply_seq or "?",
                "reply_length": self._get_ek_field(sd, "replylength", "?"),
            }
            if major_opc:
                details["major_opcode"] = major_opc
            if ext_info:
                details["extension_info"] = ext_info
            return (
                "reply",
                f"Reply(seq={reply_seq}){ext_label}",
                details,
            )

        # Event packet -- has 'eventcode'
        eventcode_raw = self._get_ek_field(sd, "eventcode")
        if eventcode_raw:
            try:
                ec = int(eventcode_raw)
            except (ValueError, TypeError):
                ec = 0
            event_name = X11_EVENT_CODES.get(ec, f"Event({ec})")
            return (
                "event",
                event_name,
                {"eventcode": ec, "event_name": event_name},
            )

        # Unknown -- still produce an interaction
        return ("request", "X11 Message", {})

    @staticmethod
    def _extract_extension_info(sd: dict) -> str:
        """Try to extract human-readable info from extension-specific fields.

        Extension replies have keys like
        ``x11_x11_glx_QueryVersion_reply_major_version``.  This method
        scans for such keys and returns a compact summary string.
        """
        parts = []
        for key in sd:
            if not key.startswith("x11_x11_"):
                continue
            suffix = key[8:]  # strip 'x11_x11_'
            # Skip generic fields
            if suffix in (
                "reply",
                "reply-sequencenumber",
                "replylength",
                "unused",
                "undecoded",
                "major-opcode",
                "first-event",
                "first-error",
                "present",
            ):
                continue
            # Extension-specific field -- include abbreviated
            val = sd[key]
            if val is None or (isinstance(val, list) and all(v is None for v in val)):
                continue
            if isinstance(val, list):
                # Take first non-None
                for v in val:
                    if v is not None:
                        val = v
                        break
                else:
                    continue
            # Abbreviate long keys
            short_key = suffix.rsplit("_", 1)[-1] if "_" in suffix else suffix
            parts.append(f"{short_key}={val}")
            if len(parts) >= 3:
                break
        return ", ".join(parts)

    def _process_fallback(
        self,
        now: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        src_mac: str,
        dst_mac: str,
        x11: Any,
        flow_id: str,
        stream_id: str,
    ) -> None:
        """Handle X11 packets that don't match connection request/reply/opcode.

        Covers three scenarios:
        1. Dict-typed _fields_dict: replies (reply-sequencenumber),
           events (eventcode), extension requests (major-opcode).
        2. List-typed _fields_dict: multiple X11 PDUs in one TCP segment.
           pyshark's getattr() returns None because field_names is empty.
           We iterate sub-dicts to find the best classification.
        3. Catch-all: record as generic "X11 Message" so no packet is
           silently dropped.
        """
        fd = getattr(x11, "_fields_dict", None)

        if isinstance(fd, list):
            # Multi-PDU frame: _fields_dict is a list of dicts.
            # Classify the first sub-dict to label the frame.
            msg_type = "request"
            operation = "X11 Message"
            details: Dict[str, Any] = {"pdu_count": len(fd)}

            for item in fd:
                if not isinstance(item, dict):
                    continue
                msg_type, operation, sub_details = self._classify_ek_subdict(item)
                details.update(sub_details)
                break  # Use first PDU for classification

        elif isinstance(fd, dict):
            # Single-PDU frame with fields not reachable via getattr.
            msg_type, operation, details = self._classify_ek_subdict(fd)

        else:
            # No _fields_dict at all -- try field_names as last resort
            msg_type = "request"
            operation = "X11 Message"
            details = {}

            reply = self.get_field(x11, "reply", None)
            reply_seq = self.get_field(x11, "reply-sequencenumber", None)
            eventcode = self.get_field(x11, "eventcode", None)
            major_opc = self.get_field(x11, "major-opcode", None)

            if reply is not None or reply_seq is not None:
                msg_type = "reply"
                seq_str = str(reply_seq) if reply_seq is not None else "?"
                operation = f"Reply(seq={seq_str})"
                details = {"reply_sequence": seq_str}
                if major_opc is not None:
                    operation += f" ext={major_opc}"
                    details["major_opcode"] = str(major_opc)
            elif eventcode is not None:
                msg_type = "event"
                try:
                    ec = int(str(eventcode))
                except (ValueError, TypeError):
                    ec = 0
                event_name = X11_EVENT_CODES.get(ec, f"Event({ec})")
                operation = event_name
                details = {"eventcode": ec, "event_name": event_name}
            elif major_opc is not None:
                minor_opc = self.get_field(x11, "minor-opcode", "0")
                operation = f"ExtRequest({major_opc}.{minor_opc})"
                details = {"major_opcode": str(major_opc), "minor_opcode": str(minor_opc)}

        # Determine direction via the shared cascade.  Replies and events are
        # server-originated (a clean native=False signal).  For requests /
        # unknown frames we fold in the listener's own learned _known_servers
        # set as a native hint (a frame to a known display = request, from a
        # known display = response); otherwise native=None lets
        # resolve_direction() use the known-server-port tier (the X11 6000-6063
        # range plus user --decode-as / OVERRIDE_PREFS) and the lower-port
        # heuristic.  Default to request when nothing distinguishes the sides
        # (preserves the old fallback behaviour).
        if msg_type in ("reply", "event"):
            native = False
        elif dst_ip in self._known_servers:
            native = True
        elif src_ip in self._known_servers:
            native = False
        else:
            native = None
        d = self.resolve_direction(
            None,
            native=native,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flow_id=flow_id,
        )
        direction = d.direction

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            f"X11 {operation}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

    def _record_credential(
        self,
        client_ip: str,
        server_ip: str,
        server_port: int,
        auth_method: str,
        auth_data: str,
        display_num: int,
    ) -> None:
        """Record extracted X11 authentication credential."""
        cred_key = (client_ip, server_ip, auth_data)
        if cred_key in self._seen_creds:
            return
        self._seen_creds.add(cred_key)

        cred = {
            "protocol": "X11",
            "credential_type": auth_method,
            "auth_method": auth_method,
            "auth_data": auth_data,
            "value": auth_data,
            "username": f"display:{display_num}",
            "server_ip": server_ip,
            "server_port": server_port,
            "client_ip": client_ip,
            "display": display_num,
            "timestamp": datetime.now().isoformat(),
        }
        self.credentials.append(cred)
        self.logger.info(
            f"X11 {auth_method}: {client_ip} -> {server_ip}:{server_port} "
            f"(display :{display_num}) data={auth_data}"
        )

    # -------------------------------------------------------------------------
    # Interaction table formatting
    # -------------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format X11 interaction as protocol-specific table columns."""
        d = ix.details
        op = ix.operation
        auth_method = d.get("auth_method", "")
        detail = ""

        if op == "Connect":
            display = d.get("display", "")
            detail = f"display={display}"
            if d.get("no_auth"):
                detail += " [NO AUTH]"
            elif d.get("auth_data"):
                detail += f" cookie={d['auth_data']}"
        elif op.startswith("Reply ("):
            # Connection reply (Success/Failed)
            version = f"v{d.get('major_version', '')}.{d.get('minor_version', '')}"
            detail = version
        elif op.startswith("Reply("):
            # Generic reply (from fallback path)
            ext_info = d.get("extension_info", "")
            detail = ext_info if ext_info else f"len={d.get('reply_length', '?')}"
        elif d.get("event_name"):
            # Event packet
            detail = d.get("event_name", "")
        elif d.get("pdu_count"):
            # Multi-PDU frame
            detail = d.get("opcode_name", d.get("extension_info", ""))
            if not detail:
                detail = f"{d['pdu_count']} PDUs"
        else:
            detail = d.get("opcode_name", op)

        return [op, auth_method, detail]

    # -------------------------------------------------------------------------
    # Device tracking
    # -------------------------------------------------------------------------

    def _ensure_server_device(
        self,
        ip: str,
        port: int,
        mac: str = "",
        display_num: int = 0,
    ) -> None:
        """Create or update X11 server (display) device."""
        if not is_valid_discovered_ip(ip):
            return
        key = f"x11-server:{ip}"
        vendor = lookup_mac_vendor(mac) if mac else ""
        device, is_new = self._ensure_device(
            key,
            ip,
            mac=mac,
            name=f"X11 Display ({ip}:{display_num})",
            device_type="X11 Display Server",
            manufacturer=vendor if vendor != "Unknown" else "",
        )
        device.x11_passive_data = {
            "role": "server",
            "port": port,
            "display": display_num,
            "protocol": "X11/TCP",
        }

    def _ensure_client_device(self, ip: str, server_ip: str, mac: str = "") -> None:
        """Create or update X11 client device."""
        if not is_valid_discovered_ip(ip):
            return
        key = f"x11-client:{ip}"
        vendor = lookup_mac_vendor(mac) if mac else ""
        device, is_new = self._ensure_device(
            key,
            ip,
            mac=mac,
            name=f"X11 Client ({ip})",
            device_type="X11 Client",
            manufacturer=vendor if vendor != "Unknown" else "",
        )
        if is_new:
            device.x11_passive_data = {
                "role": "client",
                "servers_accessed": [server_ip],
                "protocol": "X11/TCP",
            }
        else:
            if hasattr(device, "x11_passive_data") and device.x11_passive_data:
                servers = device.x11_passive_data.get("servers_accessed", [])
                if server_ip not in servers:
                    servers.append(server_ip)

    # -------------------------------------------------------------------------
    # Harvest / credential summaries
    # -------------------------------------------------------------------------

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials."""
        return list(self.credentials)

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data."""
        result = super().harvest()
        if self._alerts:
            if not result:
                result = {"tables": [], "alerts": []}
            alerts = result.get("alerts", [])
            for alert in self._alerts:
                if alert not in alerts:
                    alerts.append(alert)
            result["alerts"] = alerts
        return result
