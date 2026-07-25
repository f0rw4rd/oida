"""
VNC Passive Listener for authentication extraction (PyShark-based).

Passively captures VNC/RFB authentication to extract:
- Server challenge (16 bytes)
- Client encrypted response (16 bytes)
- Output in John the Ripper `vnc` format for offline cracking

RFB Protocol flow:
1. Server sends protocol version
2. Client responds with protocol version
3. Server sends security types
4. Client selects security type
5. VNC Auth (type 2): Server sends 16-byte challenge
6. Client sends 16-byte DES-encrypted response

Cracking: John the Ripper `vnc` format (1.9.0-Jumbo-1+), line
``$vnc$*<challenge>*<response>`` (the same line vncpcap2john produces).
NOTE: hashcat has NO VNC mode; mode 5600 is NetNTLMv2, unrelated to VNC.

Reference: RFB Protocol Specification
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip

# VNC security types
VNC_SECURITY_VNC_AUTH = 2

# Well-known VNC port range
_VNC_PORTS = frozenset(range(5900, 5910))

# RFB client message types (RFC 6143 Section 7.5)
_CLIENT_MSG_TYPES: Dict[str, str] = {
    "0": "SetPixelFormat",
    "2": "SetEncodings",
    "3": "FramebufferUpdateRequest",
    "4": "KeyEvent",
    "5": "PointerEvent",
    "6": "ClientCutText",
}

# RFB server message types (RFC 6143 Section 7.6)
_SERVER_MSG_TYPES: Dict[str, str] = {
    "0": "FramebufferUpdate",
    "1": "SetColourMapEntries",
    "2": "Bell",
    "3": "ServerCutText",
}


@dataclass
class VNCCredential:
    """Extracted VNC challenge-response."""

    challenge: str  # 16 bytes hex
    response: str  # 16 bytes hex
    server_ip: str
    client_ip: str
    server_port: int
    rfb_version: str = ""
    timestamp: str = ""

    @property
    def username(self) -> str:
        """VNC uses password-only auth; return server:port as identifier."""
        return f"{self.server_ip}:{self.server_port}"

    @property
    def password(self) -> str:
        """No plaintext password -- hash is challenge:response."""
        return ""

    @property
    def hash_value(self) -> str:
        """Challenge:response pair."""
        return f"{self.challenge}:{self.response}"

    @property
    def hashcat_format(self) -> str:
        """John the Ripper `vnc` format line: ``$vnc$*<challenge>*<response>``.

        (Property name kept for the generic credential-export hook; this is a
        John format, not a hashcat mode — hashcat has no VNC mode.)
        """
        # Both halves are required to crack; the listener already skips
        # challenge-less responses, but guard here too so an incomplete pair is
        # never emitted as a deliverable hash.
        if not (self.challenge and self.response):
            return ""
        return f"$vnc$*{self.challenge}*{self.response}"

    @property
    def credential_type(self) -> str:
        return "hash"

    @property
    def auth_method(self) -> str:
        return "VNC-DES"


@dataclass
class VNCSession:
    """Track VNC session state."""

    client_ip: str
    server_ip: str
    server_port: int
    rfb_version: str = ""
    client_rfb_version: str = ""
    security_type: int = 0
    num_security_types: int = 0
    desktop_name: str = ""
    challenge: str = ""
    state: str = "init"  # init, got_challenge, complete


class VNCPassiveListener(PySharkListenerBase):
    """Passive VNC/RFB traffic listener for auth extraction (PyShark-based).

    Captures VNC authentication to extract:
    - 16-byte server challenge
    - 16-byte client response (DES encrypted)
    - Hashcat-compatible format for offline cracking

    VNC password is max 8 chars, DES encrypted with challenge.

    Uses PyShark/tshark for protocol dissection, extracting:
    - vnc.auth_challenge: Server's 16-byte random challenge
    - vnc.auth_response: Client's DES-encrypted response
    - vnc.server_proto_ver, vnc.client_proto_ver: RFB versions
    - vnc.security_type, vnc.client_security_type: Security negotiation
    - vnc.client_message_type, vnc.server_message_type: RFB message types

    Usage:
        listener = VNCPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for line in listener.get_hashcat_hashes():
            print(line)  # $vnc$*challenge*response format
    """

    PROTOCOL_NAME = "vnc"
    DISPLAY_FILTER = "vnc"
    REQUIRED_LAYERS = ("vnc",)
    PROTOCOL_COLUMNS = ("phase", "detail", "info")
    SERVER_PORTS = tuple(sorted(_VNC_PORTS))

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.credentials: List[VNCCredential] = []
        self._sessions: Dict[Tuple[str, str, int], VNCSession] = {}
        # Track known server endpoints from handshake for direction inference
        self._known_servers: Set[Tuple[str, int]] = set()

    def _resolve_direction(
        self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, flow_id: str = ""
    ) -> Tuple[str, str, int]:
        """Determine (server_ip, client_ip, server_port) from packet endpoints.

        Delegates to the shared resolve_direction() cascade (VNC has no native
        request/response field, so native=None) seeded with SERVER_PORTS
        (5900-5909) plus any user --decode-as / OVERRIDE_PREFS ports, instead
        of hardcoding the well-known range. Session-learned servers (from a
        prior handshake on this flow) are checked first since they're a
        stronger signal than the generic port/heuristic tiers.
        """
        if (dst_ip, dst_port) in self._known_servers:
            return dst_ip, src_ip, dst_port
        if (src_ip, src_port) in self._known_servers:
            return src_ip, dst_ip, src_port
        d = self.resolve_direction(
            None,
            native=None,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flow_id=flow_id,
        )
        return d.server_ip, d.client_ip, d.server_port

    def process_packet(self, packet) -> None:
        """Process VNC/RFB packet using PyShark dissection."""
        # Check for VNC layer
        if not hasattr(packet, "vnc"):
            return

        vnc = packet.vnc
        src_ip, dst_ip = self.get_ip_info(packet)
        src_port, dst_port = self.get_port_info(packet)

        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        now = datetime.now().isoformat()
        stream_id = self.get_stream_id(packet)

        # Determine direction
        server_ip, client_ip, server_port = self._resolve_direction(
            src_ip, dst_ip, src_port, dst_port, flow_id
        )

        session_key = (client_ip, server_ip, server_port)

        # Track how many interactions we had before processing this packet
        ix_before = len(self.interactions)

        # -----------------------------------------------------------------
        # Handshake fields
        # -----------------------------------------------------------------

        # Process server version
        server_proto = self.get_field(vnc, "server_proto_ver")
        if server_proto:
            self._known_servers.add((server_ip, server_port))
            self._process_server_version(session_key, server_proto, server_port)
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "Server Version",
                {"server_proto_ver": server_proto},
                f"Server version: {server_proto.strip()}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        # Process client version (T1 field: vnc.client_proto_ver)
        client_proto = self.get_field(vnc, "client_proto_ver")
        if client_proto:
            self._process_client_version(session_key, client_proto)
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                "Client Version",
                {"client_proto_ver": client_proto},
                f"Client version: {client_proto.strip()}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        # Process number of security types (T1 field: vnc.num_security_types)
        num_sec_types = self.get_field(vnc, "num_security_types")
        if num_sec_types:
            self._process_num_security_types(session_key, num_sec_types)

        # Process security type selection
        security_type = self.get_field(vnc, "security_type")
        client_security = self.get_field(vnc, "client_security_type")

        if security_type:
            self._process_security_type(session_key, security_type)
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "Security Type Offered",
                {"security_type": security_type, "num_security_types": num_sec_types or "?"},
                f"Server offers security type {security_type}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
        if client_security:
            self._process_client_security(session_key, client_security)
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                "Security Type Selected",
                {"client_security_type": client_security},
                f"Client selects security type {client_security}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        # Extract desktop name (T1 field: vnc.desktop_name)
        desktop_name = self.get_field(vnc, "desktop_name")
        if desktop_name:
            self._process_desktop_name(session_key, desktop_name)
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "Desktop Name",
                {"desktop_name": desktop_name},
                f"Desktop: {desktop_name}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        # Extract authentication challenge (from server)
        auth_challenge = self.get_field(vnc, "auth_challenge")
        if auth_challenge:
            self._process_challenge(session_key, auth_challenge)
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "Auth Challenge",
                {"auth_challenge": auth_challenge},
                "Server sends auth challenge",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        # Extract authentication response (from client)
        auth_response = self.get_field(vnc, "auth_response")
        if auth_response:
            self._process_response(session_key, auth_response)
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                "Auth Response",
                {"auth_response": auth_response},
                "Client sends auth response",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        # Track auth result
        auth_result = self.get_field(vnc, "auth_result")
        if auth_result is not None:
            # RFB SecurityResult: tshark FT_BOOLEAN where TRUE means Failed,
            # FALSE (0) means OK/success. Invert accordingly.
            result_str = "failed" if str(auth_result) in ("1", "True", "true") else "success"
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "Auth Result",
                {"auth_result": result_str},
                f"Auth result: {result_str}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
            session = self._sessions.get(session_key)
            if session:
                self.logger.debug(f"VNC: Auth result for {session.server_ip}: {result_str}")

        # -----------------------------------------------------------------
        # Fallback: if no handshake interaction was recorded for this packet,
        # check for post-handshake RFB message types so every VNC packet
        # produces at least one interaction.
        # -----------------------------------------------------------------
        if len(self.interactions) == ix_before:
            self._process_rfb_message(
                vnc,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                server_ip,
                client_ip,
                now,
                flow_id,
                stream_id,
            )

    def _process_rfb_message(
        self,
        vnc: Any,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        server_ip: str,
        client_ip: str,
        now: str,
        flow_id: str,
        stream_id: str,
    ) -> None:
        """Record an interaction for post-handshake RFB messages.

        Handles client messages (SetPixelFormat, SetEncodings, KeyEvent, etc.)
        and server messages (FramebufferUpdate, Bell, etc.) as well as
        special handshake packets like ClientInit (share_desktop_flag).
        """
        # Check for client message type
        client_msg = self.get_field(vnc, "client_message_type")
        if client_msg is not None:
            msg_name = _CLIENT_MSG_TYPES.get(str(client_msg), f"ClientMsg({client_msg})")
            details: Dict[str, Any] = {"client_message_type": client_msg, "message": msg_name}
            # Enrich details for specific message types
            if str(client_msg) == "4":  # KeyEvent
                key = self.get_field(vnc, "key")
                key_down = self.get_field(vnc, "key_down")
                if key:
                    details["key"] = key
                if key_down is not None:
                    details["key_down"] = key_down
            elif str(client_msg) == "5":  # PointerEvent
                button_mask = self.get_field(vnc, "button_mask")
                if button_mask is not None:
                    details["button_mask"] = button_mask
            elif str(client_msg) == "0":  # SetPixelFormat
                bpp = self.get_field(vnc, "client_bits_per_pixel")
                depth = self.get_field(vnc, "client_depth")
                if bpp:
                    details["bits_per_pixel"] = bpp
                if depth:
                    details["depth"] = depth
            elif str(client_msg) == "2":  # SetEncodings
                num_enc = self.get_field(vnc, "client_set_encodings_num")
                if num_enc:
                    details["num_encodings"] = num_enc
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                msg_name,
                details,
                f"Client: {msg_name}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
            return

        # Check for server message type
        server_msg = self.get_field(vnc, "server_message_type")
        if server_msg is not None:
            msg_name = _SERVER_MSG_TYPES.get(str(server_msg), f"ServerMsg({server_msg})")
            details = {"server_message_type": server_msg, "message": msg_name}
            # Enrich details for FramebufferUpdate
            if str(server_msg) == "0":
                num_rects = self.get_field(vnc, "fb_update_num_rects")
                if num_rects:
                    details["num_rects"] = num_rects
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                msg_name,
                details,
                f"Server: {msg_name}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
            return

        # Check for ClientInit (share_desktop_flag without a message type)
        share_flag = self.get_field(vnc, "share_desktop_flag")
        if share_flag is not None:
            details = {"share_desktop_flag": share_flag}
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                "ClientInit",
                details,
                f"ClientInit (share={share_flag})",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
            return

        # Last resort: generic VNC Data for any unrecognized VNC packet
        self.logger.debug(
            f"VNC: Unrecognized VNC packet from {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        )
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "VNC Data",
            {},
            "Unrecognized VNC message",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

    def _process_server_version(
        self, session_key: Tuple[str, str, int], version: str, server_port: int
    ) -> None:
        """Process RFB server version."""
        try:
            client_ip, server_ip, _ = session_key

            if session_key not in self._sessions:
                self._sessions[session_key] = VNCSession(
                    client_ip=client_ip,
                    server_ip=server_ip,
                    server_port=server_port,
                    rfb_version=version,
                    state="init",
                )
            else:
                self._sessions[session_key].rfb_version = version

            self.logger.debug(f"VNC: Server {server_ip}:{server_port} version {version}")
        except Exception as e:
            self.logger.debug(f"VNC version parse error: {e}")

    def _process_client_version(self, session_key: Tuple[str, str, int], version: str) -> None:
        """Process RFB client version (vnc.client_proto_ver)."""
        try:
            client_ip, server_ip, server_port = session_key

            if session_key not in self._sessions:
                self._sessions[session_key] = VNCSession(
                    client_ip=client_ip,
                    server_ip=server_ip,
                    server_port=server_port,
                    client_rfb_version=version,
                    state="init",
                )
            else:
                self._sessions[session_key].client_rfb_version = version

            self.logger.debug(f"VNC: Client {client_ip} version {version}")
        except Exception as e:
            self.logger.debug(f"VNC client version parse error: {e}")

    def _process_num_security_types(
        self, session_key: Tuple[str, str, int], num_types: str
    ) -> None:
        """Process number of security types offered (vnc.num_security_types)."""
        session = self._sessions.get(session_key)
        if not session:
            client_ip, server_ip, server_port = session_key
            session = VNCSession(
                client_ip=client_ip,
                server_ip=server_ip,
                server_port=server_port,
                state="init",
            )
            self._sessions[session_key] = session

        try:
            session.num_security_types = int(num_types)
            self.logger.debug(
                f"VNC: {session.server_ip} offers {session.num_security_types} security types"
            )
        except (ValueError, TypeError):
            session.num_security_types = 0
            self.logger.debug(f"VNC: Could not parse num_security_types: {num_types}")

    def _process_desktop_name(self, session_key: Tuple[str, str, int], desktop_name: str) -> None:
        """Process desktop name from server (vnc.desktop_name)."""
        session = self._sessions.get(session_key)
        if not session:
            client_ip, server_ip, server_port = session_key
            session = VNCSession(
                client_ip=client_ip,
                server_ip=server_ip,
                server_port=server_port,
                state="init",
            )
            self._sessions[session_key] = session

        session.desktop_name = desktop_name
        self.logger.debug(f"VNC: Desktop name for {session.server_ip}: {desktop_name}")

    def _process_security_type(self, session_key: Tuple[str, str, int], security_type: str) -> None:
        """Process security type offered by server."""
        session = self._sessions.get(session_key)
        if not session:
            # Create session if needed
            client_ip, server_ip, server_port = session_key
            session = VNCSession(
                client_ip=client_ip,
                server_ip=server_ip,
                server_port=server_port,
                state="init",
            )
            self._sessions[session_key] = session

        try:
            sec_type = int(security_type)
            if sec_type == VNC_SECURITY_VNC_AUTH:
                session.security_type = sec_type
                self.logger.debug(f"VNC: {session.server_ip} offers VNC Auth")
        except (ValueError, TypeError) as e:
            self.logger.debug(f"Failed to get sec_type: {e}")

    def _process_client_security(
        self, session_key: Tuple[str, str, int], security_type: str
    ) -> None:
        """Process security type selected by client."""
        session = self._sessions.get(session_key)
        if not session:
            return

        try:
            sec_type = int(security_type)
            session.security_type = sec_type
            if sec_type == VNC_SECURITY_VNC_AUTH:
                session.state = "got_security"
                self.logger.debug(f"VNC: Client selected VNC Auth for {session.server_ip}")
        except (ValueError, TypeError) as e:
            self.logger.debug(f"Failed to get sec_type: {e}")

    def _process_challenge(self, session_key: Tuple[str, str, int], challenge: str) -> None:
        """Process VNC Auth challenge (16 bytes hex from tshark)."""
        session = self._sessions.get(session_key)
        if not session:
            # Create session for this challenge
            client_ip, server_ip, server_port = session_key
            session = VNCSession(
                client_ip=client_ip,
                server_ip=server_ip,
                server_port=server_port,
                security_type=VNC_SECURITY_VNC_AUTH,
                state="init",
            )
            self._sessions[session_key] = session

        # tshark provides challenge as hex string with colons (e.g., "ab:cd:ef:...")
        # or as raw hex bytes - normalize to plain hex
        challenge_hex = challenge.replace(":", "").replace(" ", "").lower()

        # Validate 16 bytes = 32 hex chars
        if len(challenge_hex) != 32:
            self.logger.debug(f"VNC: Invalid challenge length: {len(challenge_hex)} (expected 32)")
            return

        session.challenge = challenge_hex
        session.state = "got_challenge"
        self.logger.debug(f"VNC: Challenge from {session.server_ip}: {challenge_hex}")

    def _process_response(self, session_key: Tuple[str, str, int], response: str) -> None:
        """Process VNC Auth response (16 bytes hex from tshark)."""
        session = self._sessions.get(session_key)
        if not session or not session.challenge:
            self.logger.debug("VNC: Response without challenge, skipping")
            return

        # Normalize hex format
        response_hex = response.replace(":", "").replace(" ", "").lower()

        # Validate 16 bytes = 32 hex chars
        if len(response_hex) != 32:
            self.logger.debug(f"VNC: Invalid response length: {len(response_hex)} (expected 32)")
            return

        cred = VNCCredential(
            challenge=session.challenge,
            response=response_hex,
            server_ip=session.server_ip,
            client_ip=session.client_ip,
            server_port=session.server_port,
            rfb_version=session.rfb_version,
            timestamp=datetime.now().isoformat(),
        )

        if not self._is_duplicate(cred):
            self.credentials.append(cred)
            self.logger.info(
                f"VNC: Auth captured from {session.client_ip} -> "
                f"{session.server_ip}:{session.server_port}"
            )
            self._update_devices(cred)

        session.state = "complete"

    def _is_duplicate(self, cred: VNCCredential) -> bool:
        """Check for duplicate credential."""
        for c in self.credentials:
            if (
                c.challenge == cred.challenge
                and c.response == cred.response
                and c.server_ip == cred.server_ip
            ):
                return True
        return False

    def _update_devices(self, cred: VNCCredential) -> None:
        """Update device entries for both server and client."""
        # Look up session for extra metadata
        session_key = (cred.client_ip, cred.server_ip, cred.server_port)
        session = self._sessions.get(session_key)

        # Server device
        if is_valid_discovered_ip(cred.server_ip):
            key = f"vnc-server:{cred.server_ip}"
            desktop_name = session.desktop_name if session else ""
            num_sec_types = session.num_security_types if session else 0
            device, is_new = self._ensure_device(
                key,
                cred.server_ip,
                name=f"VNC Server :{cred.server_port - 5900}",
                device_type="VNC Server",
            )
            if is_new:
                device.vnc_passive_data = {
                    "role": "server",
                    "port": cred.server_port,
                    "rfb_version": cred.rfb_version,
                    "desktop_name": desktop_name,
                    "num_security_types": num_sec_types,
                    "auth_attempts": 1,
                    "protocol": "RFB/TCP",
                }
            else:
                if device.vnc_passive_data:
                    device.vnc_passive_data["auth_attempts"] = (
                        device.vnc_passive_data.get("auth_attempts", 0) + 1
                    )
                    # Update desktop_name if newly discovered
                    if desktop_name and not device.vnc_passive_data.get("desktop_name"):
                        device.vnc_passive_data["desktop_name"] = desktop_name
                    if num_sec_types and not device.vnc_passive_data.get("num_security_types"):
                        device.vnc_passive_data["num_security_types"] = num_sec_types

        # Client device
        if is_valid_discovered_ip(cred.client_ip):
            client_rfb = session.client_rfb_version if session else ""
            client_key = f"vnc-client:{cred.client_ip}"
            device, is_new = self._ensure_device(
                client_key,
                cred.client_ip,
                name=f"VNC Client ({cred.client_ip})",
                device_type="VNC Client",
            )
            if is_new:
                device.vnc_passive_data = {
                    "role": "client",
                    "client_rfb_version": client_rfb,
                    "targets": [f"{cred.server_ip}:{cred.server_port}"],
                    "protocol": "RFB/TCP",
                }

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format VNC interaction as protocol-specific table columns.

        Returns a list of three strings: [Phase, Detail, Info].
        """
        d = ix.details
        phase = str(ix.operation or "")
        # Build detail from the most descriptive value in the details dict
        detail_parts: List[str] = []
        for key in (
            "server_proto_ver",
            "client_proto_ver",
            "security_type",
            "client_security_type",
            "num_security_types",
            "desktop_name",
            "auth_challenge",
            "auth_response",
            "auth_result",
            "client_message_type",
            "server_message_type",
            "message",
            "key",
            "key_down",
            "num_rects",
            "bits_per_pixel",
            "depth",
            "num_encodings",
            "share_desktop_flag",
        ):
            val = d.get(key)
            if val is not None:
                detail_parts.append(f"{key}={val}")
        detail = ", ".join(detail_parts) if detail_parts else ""
        info = str(ix.summary or "")
        return [phase, detail, info]

    def get_hashcat_hashes(self) -> List[str]:
        """Get cracking lines in John the Ripper `vnc` format.

        Format: ``$vnc$*CHALLENGE*RESPONSE`` (hashcat has no VNC mode).
        Delegates to the per-credential property so incomplete pairs (missing
        challenge or response) are skipped rather than emitted as ``$vnc$**``.
        """
        return [c.hashcat_format for c in self.credentials if c.hashcat_format]

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of extracted credentials using canonical key names."""
        return [
            {
                "protocol": "VNC",
                "credential_type": "hash",
                "auth_method": "VNC-DES",
                "username": f"{c.server_ip}:{c.server_port}",
                "server_ip": c.server_ip,
                "client_ip": c.client_ip,
                "challenge": c.challenge,
                "response": c.response,
                "rfb_version": c.rfb_version,
            }
            for c in self.credentials
        ]

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all VNC sessions with negotiation details."""
        return [
            {
                "client_ip": s.client_ip,
                "server_ip": s.server_ip,
                "server_port": s.server_port,
                "server_rfb_version": s.rfb_version or "?",
                "client_rfb_version": s.client_rfb_version or "?",
                "security_type": s.security_type,
                "num_security_types": s.num_security_types,
                "desktop_name": s.desktop_name or "",
                "state": s.state,
            }
            for s in self._sessions.values()
        ]

    def get_hashes_summary(self) -> List[Dict[str, Any]]:
        """Get hashes in the format expected by base class harvest().

        Returns list of dicts with keys expected by base class harvest():
        protocol, hash_type, username, domain, server_ip, client_ip,
        hashcat_format.
        """
        hashcat_lines = self.get_hashcat_hashes()
        result = []
        for i, c in enumerate(self.credentials):
            result.append(
                {
                    "protocol": "VNC",
                    "hash_type": "VNC-DES",
                    "username": f"{c.server_ip}:{c.server_port}",
                    "domain": "",
                    "server_ip": c.server_ip,
                    "client_ip": c.client_ip,
                    "hashcat_format": hashcat_lines[i] if i < len(hashcat_lines) else "",
                }
            )
        return result
