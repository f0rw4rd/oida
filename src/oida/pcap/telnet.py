"""
Telnet Passive Listener for credential extraction.

Passively captures Telnet traffic to extract:
- Login credentials (username/password in plaintext)
- Telnet authentication negotiation (RFC 2941) -- auth type, command, data
- Telnet option negotiation (NAWS, terminal type, environment)
- Server identification

Based on BruteShark's TelnetPasswordParser approach.

Telnet authentication flow (simplified):
    Server: login:
    Client: username
    Server: Password:
    Client: password
    Server: (success message or shell prompt)

Handles both Line-Mode (RFC 1116) and Character-Mode (default).
Filters NVT ASCII characters per RFC 854.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip

# ---------------------------------------------------------------------------
# Telnet protocol constants
# ---------------------------------------------------------------------------

# Authentication commands (RFC 2941)
AUTH_CMD_NAMES: Dict[int, str] = {0: "IS", 1: "SEND", 2: "REPLY", 3: "NAME"}

# Authentication types (RFC 2941 / IANA Telnet Auth Types)
AUTH_TYPE_NAMES: Dict[int, str] = {
    0: "NULL",
    1: "Kerberos_V4",
    2: "Kerberos_V5",
    3: "SPX",
    6: "RSA",
    10: "LOKI",
    11: "SSA",
    12: "KEA_SJ",
    13: "KEA_SJ_INTEG",
    14: "DSS",
    15: "NTLM",
}

# Auth encryption modifier (RFC 2946)
AUTH_ENC_NAMES: Dict[int, str] = {
    0: "ENCRYPT_OFF",
    1: "ENCRYPT_USING_TELOPT",
    2: "ENCRYPT_AFTER_EXCHANGE",
    3: "ENCRYPT_RESERVED",
    4: "ENCRYPT_START_TLS",
}

# Telnet option codes (subcmd values)
TELNET_OPT_NAMES: Dict[int, str] = {
    0: "Binary Transmission",
    1: "Echo",
    3: "Suppress Go-Ahead",
    5: "Status",
    24: "Terminal Type",
    31: "NAWS",
    32: "Terminal Speed",
    33: "Remote Flow Control",
    34: "Linemode",
    35: "X Display Location",
    36: "Environment Option",
    37: "Authentication",
    38: "Encryption",
    39: "New Environment Option",
}


class TelnetState(Enum):
    """Telnet session authentication state."""

    NONE = "none"
    WAIT_FOR_USERNAME = "wait_for_username"
    WAIT_FOR_PASSWORD = "wait_for_password"
    COMPLETE = "complete"


@dataclass
class TelnetCredential:
    """Extracted Telnet credential."""

    username: str
    password: str
    server_ip: str
    server_port: int = 0
    client_ip: str = ""
    timestamp: str = ""
    credential_type: str = "plaintext"

    @property
    def auth_method(self) -> str:
        """Scanner credential loop compatibility."""
        return "Telnet"


@dataclass
class TelnetSession:
    """Track Telnet session state for credential extraction."""

    client_ip: str
    server_ip: str
    server_port: int = 0
    state: TelnetState = TelnetState.NONE
    username: str = ""
    password: str = ""
    username_buffer: str = ""  # For character mode
    password_buffer: str = ""  # For character mode
    data_buffer: str = ""  # Accumulated session data (mixed client+server)
    client_buffer: str = ""  # Client-only data (no server echoes)
    # Auth negotiation tracking (RFC 2941)
    auth_types_seen: Set[str] = field(default_factory=set)
    auth_encryption: str = ""
    # Terminal info from option negotiation
    terminal_type: str = ""
    terminal_width: int = 0
    terminal_height: int = 0
    # Negotiated options (option code -> WILL/DO/WONT/DONT)
    options_negotiated: Set[str] = field(default_factory=set)


# NVT ASCII character range (RFC 854)
NVT_ASCII_MIN = 0x20  # Space
NVT_ASCII_MAX = 0x7E  # Tilde


class TelnetPassiveListener(PySharkListenerBase):
    """Passive Telnet traffic listener for credential extraction.

    Captures Telnet traffic to extract:
    - Login credentials (plaintext username/password)
    - Server identification

    Handles both Line-Mode and Character-Mode Telnet authentication.
    Uses state machine to track authentication flow across packets.

    Usage:
        # Live capture
        listener = TelnetPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Access extracted credentials
        for cred in listener.credentials:
            print(f"{cred.username}:{cred.password} @ {cred.server_ip}")

    Data structure stored in device.telnet_passive_data:
        {
            "role": "server" | "client",
            "credentials": [
                {"username": "admin", "password": "secret"}
            ],
            "protocol": "Telnet/TCP",
        }
    """

    PROTOCOL_NAME = "telnet"
    DISPLAY_FILTER = "telnet"
    REQUIRED_LAYERS = ("telnet",)
    SERVER_PORTS = (23,)

    PROTOCOL_COLUMNS = ("type", "detail", "info")

    # Patterns to detect login prompts
    LOGIN_PROMPT_REGEX = re.compile(r"login:\s*$", re.IGNORECASE)
    PASSWORD_PROMPT_REGEX = re.compile(r"password:\s*$", re.IGNORECASE)

    # Combined pattern for session-level matching (from BruteShark).
    # The username group is lazy and the password group stops at end-of-line so
    # a buffer holding several attempts (a failed login followed by a retry)
    # yields one match per attempt instead of one greedy span that pairs the
    # first username with the last password.
    TELNET_LOGIN_REGEX = re.compile(r"login:(.*?)password:([^\r\n]*)", re.IGNORECASE | re.DOTALL)

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize Telnet passive listener.

        Args:
            interface: Network interface to capture on
            timeout: Capture timeout in seconds
            nxc_logger: Optional NXC-style logger
        """
        super().__init__(interface, timeout, nxc_logger)

        # Track Telnet sessions by (client_ip, server_ip) tuple
        self._sessions: Dict[Tuple[str, str], TelnetSession] = {}

        # Extracted credentials
        self.credentials: List[TelnetCredential] = []

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format a Telnet interaction as a table row.

        Returns a list whose length matches ``PROTOCOL_COLUMNS``:
        [Type, Detail, Info].
        """
        d = ix.details
        op = ix.operation  # e.g. "Telnet Data", "Telnet Auth IS", "Telnet Negotiation"

        # Determine type from operation string
        if op.startswith("Telnet Auth"):
            op_type = "Auth"
            auth_cmd = d.get("auth_cmd", "")
            auth_type = d.get("auth_type", "")
            detail = f"{auth_cmd} {auth_type}".strip()
            # Extra info: encryption, auth data preview
            info_parts: List[str] = []
            enc = d.get("auth_mod_enc", "")
            if enc:
                info_parts.append(f"enc={enc}")
            auth_data = d.get("auth_data", "")
            if auth_data:
                info_parts.append(f"data={auth_data}")
            info = " ".join(info_parts)
        elif op == "Telnet Negotiation":
            op_type = "Negotiation"
            cmd = d.get("cmd", "")
            subcmd = d.get("subcmd", "")
            detail = f"cmd={cmd} opt={subcmd}" if subcmd else f"cmd={cmd}"
            # Extra info: NAWS dimensions, terminal type, string suboptions
            info_parts = []
            nw = d.get("naws_width", "")
            nh = d.get("naws_height", "")
            if nw or nh:
                info_parts.append(f"NAWS {nw}x{nh}")
            sopt = d.get("string_subopt", "")
            if sopt:
                info_parts.append(str(sopt))
            info = " ".join(info_parts)
        else:
            # "Telnet Data" or any other — type is redundant with operation
            op_type = ""
            text = d.get("text", "")
            detail = text if text else ""
            info = ""

        return [op_type, detail, info]

    def process_packet(self, packet) -> None:
        """Process Telnet packet and extract credentials + negotiation fields."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)

        src_port, dst_port = self.get_port_info(packet)

        # Get telnet layer from packet
        if not hasattr(packet, "telnet"):
            return

        telnet_layer = packet.telnet

        # Determine direction via the shared cascade.  Telnet has no
        # request/response indicator in the wire format, so native=None: the
        # known-server-port tier (canonical 23 plus any user --decode-as /
        # OVERRIDE_PREFS override) classifies, falling back to the lower-port /
        # first-seen heuristic.  Unlike the old `dst_port == 23` checks this
        # never drops traffic on a non-standard port.
        d = self.resolve_direction(
            packet,
            native=None,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flow_id=flow_id,
        )
        is_request = d.is_request
        direction = d.direction
        client_ip, server_ip = d.client_ip, d.server_ip
        server_port = d.server_port

        session = self._get_session(client_ip, server_ip)
        if server_port and not session.server_port:
            session.server_port = server_port

        now = datetime.now().isoformat()
        interaction_details: Dict[str, Any] = {}

        # --- T1: Authentication negotiation (RFC 2941) ---
        auth_cmd_raw = self.get_field(telnet_layer, "auth_cmd", "")
        auth_type_raw = self.get_field(telnet_layer, "auth_type", "")
        auth_data = self.get_field(telnet_layer, "auth_data", "")
        auth_mod_enc_raw = self.get_field(telnet_layer, "auth_mod_enc", "")
        # T2 auth modifier booleans
        auth_mod_who = self.get_field(telnet_layer, "auth_mod_who", "")
        auth_mod_how = self.get_field(telnet_layer, "auth_mod_how", "")
        auth_mod_cred_fwd = self.get_field(telnet_layer, "auth_mod_cred_fwd", "")

        has_auth = bool(auth_cmd_raw or auth_type_raw)
        if has_auth:
            self._process_auth_negotiation(
                session,
                client_ip,
                server_ip,
                auth_cmd_raw,
                auth_type_raw,
                auth_data,
                auth_mod_enc_raw,
                direction,
                flow_id,
                now,
                auth_mod_who=auth_mod_who,
                auth_mod_how=auth_mod_how,
                auth_mod_cred_fwd=auth_mod_cred_fwd,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )

        # --- T2: Option negotiation fields ---
        cmd_raw = self.get_field(telnet_layer, "cmd", "")
        subcmd_raw = self.get_field(telnet_layer, "subcmd", "")
        naws_width = self.get_field(telnet_layer, "naws_subopt_width", "")
        naws_height = self.get_field(telnet_layer, "naws_subopt_height", "")
        string_subopt = self.get_field(telnet_layer, "string_subopt_value", "")

        # Track terminal dimensions (NAWS)
        if naws_width:
            try:
                w = int(str(naws_width))
                session.terminal_width = w
                interaction_details["naws_width"] = w
            except (ValueError, TypeError):
                interaction_details["naws_width"] = str(naws_width)
        if naws_height:
            try:
                h = int(str(naws_height))
                session.terminal_height = h
                interaction_details["naws_height"] = h
            except (ValueError, TypeError):
                interaction_details["naws_height"] = str(naws_height)

        # Track terminal type and environment strings
        # get_field() converts EK lists to comma-separated strings
        if string_subopt:
            val = str(string_subopt)
            # String suboptions are typically terminal type or env values.
            # When multiple values come in one packet (e.g. "Sandbox:0.0,xterm"),
            # the last non-empty value is usually the terminal emulator name.
            if val and not session.terminal_type:
                parts = [p.strip() for p in val.split(",") if p.strip()]
                session.terminal_type = parts[-1] if parts else val
            interaction_details["string_subopt"] = val

        # Track negotiated option names
        # get_field() converts EK lists to comma-separated strings like "3,24,31"
        if subcmd_raw:
            subcmd_str = str(subcmd_raw)
            for part in subcmd_str.split(","):
                part = part.strip()
                if not part:
                    continue
                try:
                    opt_code = int(part)
                    opt_name = TELNET_OPT_NAMES.get(opt_code, f"Option-{opt_code}")
                    session.options_negotiated.add(opt_name)
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to get opt_code: {e}")

        if cmd_raw:
            interaction_details["cmd"] = str(cmd_raw)
        if subcmd_raw:
            interaction_details["subcmd"] = str(subcmd_raw)

        # Enrich server device with negotiation data (NAWS, terminal type, options)
        if naws_width or naws_height or string_subopt or subcmd_raw:
            self._update_server_device(server_ip, session)

        # --- Text data processing (credential extraction) ---
        telnet_data = self.get_field(telnet_layer, "data", "")

        if telnet_data:
            # Add decoded text to interaction details
            text = self._filter_nvt_ascii(str(telnet_data)).strip()
            if text:
                interaction_details["text"] = text
            # Record data interaction
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                direction,
                "Telnet Data",
                interaction_details,
                f"Telnet data {src_ip} -> {dst_ip}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )

            if is_request:
                self._process_client_packet(client_ip, server_ip, telnet_data)
            else:
                self._process_server_packet(client_ip, server_ip, telnet_data)
        elif interaction_details:
            # Record negotiation-only interaction (no text data)
            op = "Telnet Auth" if has_auth else "Telnet Negotiation"
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                direction,
                op,
                interaction_details,
                f"{op} {src_ip} -> {dst_ip}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )
        elif not has_auth:
            # Fallback: packet matched telnet display filter but had no
            # parseable fields (e.g. malformed/truncated telnet segment).
            # Record it so every filtered packet produces an interaction.
            self.logger.debug(f"Telnet packet with no parseable fields from {src_ip} -> {dst_ip}")
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                direction,
                "Telnet Empty",
                {"malformed": True},
                f"Telnet empty/malformed {src_ip} -> {dst_ip}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )

    def _process_auth_negotiation(
        self,
        session: "TelnetSession",
        client_ip: str,
        server_ip: str,
        auth_cmd_raw: Any,
        auth_type_raw: Any,
        auth_data: Any,
        auth_mod_enc_raw: Any,
        direction: str,
        flow_id: str,
        timestamp: str,
        auth_mod_who: Any = "",
        auth_mod_how: Any = "",
        auth_mod_cred_fwd: Any = "",
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Process Telnet authentication negotiation (RFC 2941).

        Extracts auth command, type, encryption modifier, auth modifiers,
        and auth data.  Records the auth event as an interaction with rich
        details.
        """
        details: Dict[str, Any] = {}

        # Auth command: IS(0), SEND(1), REPLY(2), NAME(3)
        auth_cmd_name = "?"
        if auth_cmd_raw not in ("", None):
            try:
                auth_cmd_int = int(str(auth_cmd_raw))
                auth_cmd_name = AUTH_CMD_NAMES.get(auth_cmd_int, str(auth_cmd_int))
            except (ValueError, TypeError):
                auth_cmd_name = str(auth_cmd_raw)
                self.logger.debug(
                    f"Non-numeric auth_cmd value {auth_cmd_raw!r} from {client_ip} -> {server_ip}"
                )
        details["auth_cmd"] = auth_cmd_name

        # Auth type: NULL(0), Kerberos_V5(2), NTLM(15), etc.
        auth_type_name = "?"
        if auth_type_raw not in ("", None):
            try:
                auth_type_int = int(str(auth_type_raw))
                auth_type_name = AUTH_TYPE_NAMES.get(auth_type_int, str(auth_type_int))
                session.auth_types_seen.add(auth_type_name)
            except (ValueError, TypeError):
                auth_type_name = str(auth_type_raw)
                self.logger.debug(
                    f"Non-numeric auth_type value {auth_type_raw!r} from {client_ip} -> {server_ip}"
                )
        details["auth_type"] = auth_type_name

        # Encryption modifier
        enc_name = ""
        if auth_mod_enc_raw not in ("", None):
            try:
                enc_int = int(str(auth_mod_enc_raw))
                enc_name = AUTH_ENC_NAMES.get(enc_int, str(enc_int))
                session.auth_encryption = enc_name
            except (ValueError, TypeError):
                enc_name = str(auth_mod_enc_raw)
        if enc_name:
            details["auth_mod_enc"] = enc_name

        # Auth modifier booleans (RFC 2941 section 2)
        if auth_mod_who not in ("", None):
            details["auth_mod_who"] = str(auth_mod_who)
        if auth_mod_how not in ("", None):
            details["auth_mod_how"] = str(auth_mod_how)
        if auth_mod_cred_fwd not in ("", None):
            details["auth_mod_cred_fwd"] = str(auth_mod_cred_fwd)

        # Auth data (may contain NTLM blobs, Kerberos tickets, etc.)
        if auth_data:
            data_str = str(auth_data)
            details["auth_data"] = data_str
            data_preview = data_str
        else:
            data_preview = ""

        summary = f"Telnet Auth {auth_cmd_name} type={auth_type_name}"
        if enc_name:
            summary += f" enc={enc_name}"
        if data_preview:
            summary += f" data={data_preview}"

        self._record_interaction(
            timestamp,
            client_ip if direction == "request" else server_ip,
            server_ip if direction == "request" else client_ip,
            direction,
            f"Telnet Auth {auth_cmd_name}",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Update server device with auth capability info
        self._update_server_device(server_ip, session)

        self.logger.debug(
            f"Telnet auth: {auth_cmd_name} type={auth_type_name} enc={enc_name} "
            f"{client_ip} -> {server_ip}"
        )

    def _get_session(self, client_ip: str, server_ip: str) -> TelnetSession:
        """Get or create Telnet session tracker."""
        key = (client_ip, server_ip)
        if key not in self._sessions:
            self._sessions[key] = TelnetSession(
                client_ip=client_ip,
                server_ip=server_ip,
            )
        return self._sessions[key]

    def _filter_nvt_ascii(self, data: str) -> str:
        """Filter to NVT ASCII data characters only (RFC 854).

        Telnet uses NVT (Network Virtual Terminal) ASCII.
        Valid data characters are 0x20 (space) through 0x7E (tilde).
        Also allow CR/LF for line endings.

        Args:
            data: Text data from Telnet packet

        Returns:
            Filtered ASCII string containing only valid NVT data characters
        """
        result = []
        for char in data:
            byte = ord(char)
            if NVT_ASCII_MIN <= byte <= NVT_ASCII_MAX:
                result.append(char)
            elif byte in (0x0D, 0x0A):  # CR, LF
                # Skip newlines in buffers (they indicate end of input)
                pass
        return "".join(result)

    def _process_server_packet(self, client_ip: str, server_ip: str, data: str) -> None:
        """Process Telnet server output (prompts)."""
        session = self._get_session(client_ip, server_ip)
        session.data_buffer += data

        # A password was pending when this segment arrived - finalize and record
        # it before evaluating what the segment means for the next state. This
        # must run before the login/password prompt branches below: servers
        # commonly coalesce a failure banner ("Login incorrect") and the next
        # login prompt into a single TCP segment, and if the prompt branch reset
        # the buffers first, the just-typed password would be silently dropped.
        if session.state == TelnetState.WAIT_FOR_PASSWORD and len(data) > 0:
            # Server sent something after password - likely logged in or failed
            # At this point we have username and password
            if session.username_buffer:
                session.username = session.username_buffer.strip()
            if session.password_buffer:
                session.password = session.password_buffer.strip()

            if session.username and session.password:
                self._record_credential(session)

        # Check for login prompt
        if self.LOGIN_PROMPT_REGEX.search(data):
            session.state = TelnetState.WAIT_FOR_USERNAME
            session.username_buffer = ""
            self.logger.debug(f"Telnet: Server {server_ip} sent login prompt")
            self._update_server_device(server_ip)

        # Check for password prompt
        elif self.PASSWORD_PROMPT_REGEX.search(data):
            if session.state == TelnetState.WAIT_FOR_USERNAME:
                # Username collection complete
                session.username = session.username_buffer.strip()
            session.state = TelnetState.WAIT_FOR_PASSWORD
            session.password_buffer = ""
            self.logger.debug(f"Telnet: Server {server_ip} sent password prompt")

        # Successful login (or any other server output after the password) -
        # mark the session complete now that the credential above is recorded.
        elif session.state == TelnetState.WAIT_FOR_PASSWORD:
            session.state = TelnetState.COMPLETE

    def _process_client_packet(self, client_ip: str, server_ip: str, data: str) -> None:
        """Process Telnet client input (username/password)."""
        session = self._get_session(client_ip, server_ip)
        session.data_buffer += data
        session.client_buffer += data  # Track client-only data for dedup

        # Filter to NVT ASCII data characters
        nvt_data = self._filter_nvt_ascii(data)

        if session.state == TelnetState.WAIT_FOR_USERNAME:
            # Accumulate username characters (handles Character-Mode)
            session.username_buffer += nvt_data
            self.logger.debug(f"Telnet: Client {client_ip} username data: {nvt_data!r}")
            self._update_client_device(client_ip, server_ip)

        elif session.state == TelnetState.WAIT_FOR_PASSWORD:
            # Accumulate password characters (handles Character-Mode)
            session.password_buffer += nvt_data
            self.logger.debug(f"Telnet: Client {client_ip} password data captured")

        # Only try session-level regex when state machine is NOT already tracking.
        # In character-mode, the state machine (username_buffer/password_buffer) handles
        # credential extraction correctly. The session regex is a fallback for line-mode
        # where prompts and input may arrive in few large packets.
        if session.state == TelnetState.NONE:
            self._try_session_match(session)

    def _try_session_match(self, session: TelnetSession) -> None:
        """Try to extract credentials using session-level regex.

        This handles Line-Mode where username and password are sent in single packets.
        Uses client_buffer (client-only data) to avoid server echo duplication.
        Falls back to data_buffer if client_buffer has no match.
        """
        # Prefer client-only buffer to avoid echo duplication
        session_text = session.client_buffer or session.data_buffer

        matches = list(self.TELNET_LOGIN_REGEX.finditer(session_text))
        if not matches and session.client_buffer:
            # Fallback to mixed buffer if client-only didn't match
            matches = list(self.TELNET_LOGIN_REGEX.finditer(session.data_buffer))

        for match in matches:
            # Extract username (text between "login:" and "password:")
            username_part = match.group(1)
            password_part = match.group(2)

            # Clean up - get just the input, not echoed prompts
            # Filter to NVT ASCII
            username = self._filter_nvt_ascii(username_part).strip()
            password = self._filter_nvt_ascii(password_part).strip()

            # Remove any trailing/embedded prompts. A lazy username group keeps
            # each match to a single attempt, but strip a stray "login" echo too.
            if "password" in username.lower():
                username = username.split("password")[0].strip()
            if "login" in username.lower():
                username = username.rsplit("login", 1)[-1].strip()

            if username and password:
                # Check if we already recorded this
                if not any(
                    c.username == username
                    and c.password == password
                    and c.server_ip == session.server_ip
                    for c in self.credentials
                ):
                    session.username = username
                    session.password = password
                    self._record_credential(session)
                    session.state = TelnetState.COMPLETE

    def _record_credential(self, session: TelnetSession) -> None:
        """Record extracted Telnet credential."""
        # Check for duplicates
        for cred in self.credentials:
            if (
                cred.server_ip == session.server_ip
                and cred.client_ip == session.client_ip
                and cred.username == session.username
                and cred.password == session.password
            ):
                return

        cred = TelnetCredential(
            username=session.username,
            password=session.password,
            server_ip=session.server_ip,
            server_port=session.server_port,
            client_ip=session.client_ip,
            timestamp=datetime.now().isoformat(),
        )
        self.credentials.append(cred)

        self.logger.info(
            f"Telnet Credential: {session.username}:{session.password} "
            f"@ {session.server_ip}:{session.server_port}"
        )

        # Update device entries
        self._update_device_credentials(session)

    def _update_server_device(
        self, server_ip: str, session: Optional["TelnetSession"] = None
    ) -> None:
        """Update or create Telnet server device entry."""
        if not is_valid_discovered_ip(server_ip):
            return

        device_key = f"telnet-server:{server_ip}"

        device, is_new = self._ensure_device(
            device_key,
            server_ip,
            name=f"Telnet Server ({server_ip})",
            device_type="Telnet Server",
        )
        if is_new:
            device.telnet_passive_data = {
                "role": "server",
                "credentials": [],
                "protocol": "Telnet/TCP",
            }

        # Enrich with auth and terminal negotiation data from session
        if session and device.telnet_passive_data:
            pdata = device.telnet_passive_data
            if session.auth_types_seen:
                existing = set(pdata.get("auth_types", []))
                existing.update(session.auth_types_seen)
                pdata["auth_types"] = sorted(existing)
            if session.auth_encryption:
                pdata["auth_encryption"] = session.auth_encryption
            if session.terminal_type:
                pdata["terminal_type"] = session.terminal_type
            if session.terminal_width and session.terminal_height:
                pdata["terminal_size"] = f"{session.terminal_width}x{session.terminal_height}"
            if session.options_negotiated:
                existing_opts = set(pdata.get("options_negotiated", []))
                existing_opts.update(session.options_negotiated)
                pdata["options_negotiated"] = sorted(existing_opts)

    def _update_client_device(self, client_ip: str, server_ip: str) -> None:
        """Update or create Telnet client device entry."""
        if not is_valid_discovered_ip(client_ip):
            return

        device_key = f"telnet-client:{client_ip}"

        device, is_new = self._ensure_device(
            device_key,
            client_ip,
            name=f"Telnet Client ({client_ip})",
            device_type="Telnet Client",
        )
        if is_new:
            device.telnet_passive_data = {
                "role": "client",
                "credentials": [],
                "servers_accessed": [server_ip],
                "protocol": "Telnet/TCP",
            }
        else:
            if device.telnet_passive_data:
                servers = device.telnet_passive_data.get("servers_accessed", [])
                if server_ip not in servers:
                    servers.append(server_ip)
                    device.telnet_passive_data["servers_accessed"] = servers

    def _update_device_credentials(self, session: TelnetSession) -> None:
        """Update device entries with credential information."""
        server_key = f"telnet-server:{session.server_ip}"
        client_key = f"telnet-client:{session.client_ip}"

        cred_entry = {
            "username": session.username,
            "password": session.password,
            "timestamp": datetime.now().isoformat(),
        }

        with self._lock:
            # Update server
            if server_key in self.discovered_devices:
                device = self.discovered_devices[server_key]
                if device.telnet_passive_data:
                    creds = device.telnet_passive_data.get("credentials", [])
                    if not any(
                        c.get("username") == session.username
                        and c.get("password") == session.password
                        for c in creds
                    ):
                        cred_entry["client_ip"] = session.client_ip
                        creds.append(cred_entry)
                        device.telnet_passive_data["credentials"] = creds

            # Update client
            if client_key in self.discovered_devices:
                device = self.discovered_devices[client_key]
                if device.telnet_passive_data:
                    creds = device.telnet_passive_data.get("credentials", [])
                    client_cred = {
                        "username": session.username,
                        "password": session.password,
                        "server_ip": session.server_ip,
                        "timestamp": datetime.now().isoformat(),
                    }
                    if not any(
                        c.get("username") == session.username
                        and c.get("server_ip") == session.server_ip
                        for c in creds
                    ):
                        creds.append(client_cred)
                        device.telnet_passive_data["credentials"] = creds

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials.

        Returns:
            List of credential dictionaries with:
                - protocol: "Telnet"
                - username: str
                - password: str
                - server_ip: str
                - client_ip: str
                - timestamp: str
        """
        return [
            {
                "protocol": "Telnet",
                "credential_type": "plaintext",
                "auth_method": "Telnet",
                "username": cred.username,
                "password": cred.password,
                "server_ip": cred.server_ip,
                "client_ip": cred.client_ip,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]
