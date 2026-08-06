"""
POP3 Passive Listener for credential extraction.

Passively captures POP3 traffic to extract:
- POP3 server banners (+OK response)
- Login credentials (USER/PASS commands)
- AUTH PLAIN credentials (base64 decoded)
- STLS (STARTTLS) detection
- CAPA (capabilities) parsing

Based on CredSLayer's POP parser approach.

POP3 authentication flows:
    +OK Server ready
    USER username
    +OK
    PASS password
    +OK / -ERR

    +OK Server ready
    AUTH PLAIN
    + (continuation)
    <base64: \x00username\x00password>
    +OK / -ERR

PyShark POP3 field reference (packet.pop.*):
- pop.response.indicator: "+OK" or "-ERR"
- pop.response.description: Banner text
- pop.request.command: Command (CAPA, USER, PASS, AUTH, STLS, STAT, LIST, RETR, DELE, QUIT)
- pop.request.parameter: Command parameter
- pop.response.data: Response data (capabilities)
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
)


@dataclass
class POP3Credential:
    """Extracted POP3 credential."""

    username: str
    password: str
    auth_method: str  # "USER/PASS" or "AUTH PLAIN"
    server_ip: str = ""
    server_port: int = 0
    client_ip: str = ""
    server_banner: str = ""
    timestamp: str = ""
    success: Optional[bool] = None  # True if +OK, False if -ERR, None if unknown
    credential_type: str = "plaintext"


@dataclass
class POP3Session:
    """Track POP3 session state for credential extraction."""

    client_ip: str
    server_ip: str
    server_port: int = 0
    server_banner: str = ""
    username: str = ""
    password: str = ""
    auth_method: str = ""  # "USER/PASS" or "AUTH PLAIN"
    state: str = "init"  # init, got_banner, got_user, got_pass, auth_plain_pending, complete


class POP3PassiveListener(PySharkListenerBase):
    """Passive POP3 traffic listener for credential extraction.

    Captures POP3 traffic to extract:
    - Server banners (+OK response)
    - Usernames (USER command)
    - Passwords (PASS command, plaintext)
    - AUTH PLAIN credentials (base64 decoded)
    - Login success/failure (+OK/-ERR responses)
    - STLS (STARTTLS) usage detection
    - CAPA capabilities

    Usage:
        # Live capture
        listener = POP3PassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Access extracted credentials
        for cred in listener.credentials:
            print(f"{cred.username}:{cred.password} @ {cred.server_ip}")

    Data structure stored in device.pop3_passive_data:
        {
            "role": "server" | "client",
            "server_banner": "+OK POP server ready",
            "credentials": [
                {"username": "admin", "password": "secret", "auth_method": "USER/PASS", "success": True}
            ],
            "protocol": "POP3/TCP",
        }
    """

    PROTOCOL_NAME = "pop3"
    DISPLAY_FILTER = "pop"
    REQUIRED_LAYERS = ("pop",)
    PROTOCOL_COLUMNS = (
        "command",
        "parameter",
        "server_banner",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize POP3 passive listener.

        Args:
            interface: Network interface to capture on
            timeout: Capture timeout in seconds
            nxc_logger: Optional NXC-style logger
        """
        super().__init__(interface, timeout, nxc_logger)

        # Track POP3 sessions by (client_ip, client_port, server_ip) tuple
        # This handles multiple concurrent connections from same client
        self._sessions: Dict[Tuple[str, int, str], POP3Session] = {}

        # Extracted credentials
        self.credentials: List[POP3Credential] = []

        # Track server banners by IP (first banner wins)
        self.server_banners: Dict[str, str] = {}
        # Track STLS (STARTTLS) usage
        self.stls_servers: Set[str] = set()
        # Track CAPA capabilities per server
        self.server_capabilities: Dict[str, List[str]] = {}

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format POP3 interaction as a table row."""
        d = ix.details
        command = d.get("command", "")
        response_indicator = d.get("response_indicator", "")
        if command:
            cmd_str = command
        elif response_indicator:
            cmd_str = response_indicator
        else:
            cmd_str = "?"

        param = d.get("parameter", "") or d.get("response_description", "") or "-"
        # Mask PASS password in table display
        if command == "PASS" and param != "-":
            param = "****"
        # Mask AUTH PLAIN base64 credential blobs
        if d.get("is_auth_data"):
            cmd_str = "****"
        banner = d.get("banner", "") or "-"

        return [
            cmd_str,
            param,
            banner,
        ]

    def process_packet(self, packet) -> None:
        """Process POP3 packet and extract credentials."""
        # Get IP info
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)

        # Get port info
        src_port, dst_port = self.get_port_info(packet)
        # Only drop when *both* ports are absent (matches the IMAP listener).
        # The previous `or` dropped any packet where a single side was 0 --
        # e.g. an ICMP-quoted POP segment that only preserved one port --
        # which discarded recoverable packets invisibly.
        if src_port == 0 and dst_port == 0:
            self.logger.debug(f"Dropping POP3 packet with no port info (src={src_ip} dst={dst_ip})")
            return

        # Check if we have a POP layer
        if not hasattr(packet, "pop"):
            return

        pop_layer = packet.pop

        # Try to get request command and parameter
        request_command = self.get_field(pop_layer, "request_command", "")
        request_parameter = self.get_field(pop_layer, "request_parameter", "")

        # Try to get response indicator and description
        response_indicator = self.get_field(pop_layer, "response_indicator", "")
        response_description = self.get_field(pop_layer, "response_description", "")

        # Try to get response data (capabilities)
        response_data = self.get_field(pop_layer, "response_data", "")

        # Determine direction based on port.
        # POP3 standard port 110, POP3S port 995, but the protocol may run on any
        # port (stunnel wrappers, lab setups, containers mapping 1100/8110, etc.).
        # Prefer the canonical port if it appears on either side; otherwise fall
        # back to "lower port wins" (the listening server has the smaller
        # fixed-vs-ephemeral port), matching the iec104/modbus/mms/smtp listeners.
        # This avoids silently dropping POP3 sessions on non-standard ports.
        now = datetime.now().isoformat()
        cmd = str(request_command).upper() if request_command else ""

        _STD_PORTS = (110, 995)
        if dst_port in _STD_PORTS:
            is_request = True
        elif src_port in _STD_PORTS:
            is_request = False
        else:
            # Non-standard port: server is the lower (listening) port.
            is_request = dst_port < src_port
            self.logger.debug(
                f"POP3 on non-standard port: {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                f"(treating as {'request' if is_request else 'response'})"
            )

        if is_request:
            # Client -> Server (commands)
            client_ip = src_ip
            client_port = src_port
            server_ip = dst_ip
            banner = self.server_banners.get(server_ip, "")

            detail: Dict[str, Any] = {
                "command": cmd,
                "parameter": str(request_parameter) if request_parameter else "",
                "banner": banner,
            }

            # Detect AUTH PLAIN base64 continuation data
            # Known POP3 commands won't be mistaken for base64
            _KNOWN_CMDS = {
                "USER",
                "PASS",
                "AUTH",
                "APOP",
                "QUIT",
                "STAT",
                "LIST",
                "RETR",
                "DELE",
                "NOOP",
                "RSET",
                "TOP",
                "UIDL",
                "CAPA",
                "STLS",
                "",
            }
            if cmd and cmd not in _KNOWN_CMDS:
                detail["is_auth_data"] = True

            # STLS detection
            if cmd == "STLS":
                self.stls_servers.add(server_ip)
                detail["stls"] = True
                self.logger.debug(f"POP3 STLS: {client_ip} -> {server_ip}")

            op = f"POP3 {cmd}" if cmd else "POP3"
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                op,
                detail,
                f"{op} {src_ip} -> {dst_ip}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )

            self._process_client_packet(
                client_ip,
                client_port,
                server_ip,
                dst_port,
                request_command,
                request_parameter,
            )
        else:
            # Server -> Client (responses)
            client_ip = dst_ip
            client_port = dst_port
            server_ip = src_ip
            banner = self.server_banners.get(server_ip, "")

            detail = {
                "response_indicator": str(response_indicator) if response_indicator else "",
                "response_description": str(response_description) if response_description else "",
                "banner": banner,
            }

            # Parse CAPA response data
            if response_data:
                self._parse_capa_response(server_ip, str(response_data))

            op = f"POP3 {response_indicator}" if response_indicator else "POP3"
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                op,
                detail,
                f"{op} {src_ip} -> {dst_ip}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )

            self._process_server_packet(
                client_ip,
                client_port,
                server_ip,
                src_port,
                response_indicator,
                response_description,
            )

    def _parse_capa_response(self, server_ip: str, data: str) -> None:
        """Parse CAPA response data into capabilities list."""
        if not data:
            return
        caps = self.server_capabilities.setdefault(server_ip, [])
        # CAPA data may contain multiple capabilities separated by newlines or commas
        for line in data.replace(",", "\n").split("\n"):
            cap = line.strip()
            if cap and cap != "." and cap not in caps:
                caps.append(cap)

    def _get_session(self, client_ip: str, client_port: int, server_ip: str) -> POP3Session:
        """Get or create POP3 session tracker."""
        key = (client_ip, client_port, server_ip)
        if key not in self._sessions:
            self._sessions[key] = POP3Session(
                client_ip=client_ip,
                server_ip=server_ip,
            )
        return self._sessions[key]

    def _process_server_packet(
        self,
        client_ip: str,
        client_port: int,
        server_ip: str,
        port: int,
        response_indicator: str,
        response_description: str,
    ) -> None:
        """Process POP3 server response."""
        session = self._get_session(client_ip, client_port, server_ip)
        if port and not session.server_port:
            session.server_port = port

        # Check for banner (+OK at start of session)
        if session.state == "init" and response_indicator == "+OK":
            if response_description:
                session.server_banner = response_description.strip()
                session.state = "got_banner"
                self._update_server_device(server_ip, session.server_banner, port)
                self.logger.debug(f"POP3: Server {server_ip} banner: {session.server_banner}")
                # First banner wins
                if server_ip not in self.server_banners:
                    self.server_banners[server_ip] = session.server_banner

        # Check for continuation prompt (+ ) for AUTH PLAIN
        if session.state == "auth_plain_pending" and response_indicator == "+":
            # Server is ready for the base64 credentials
            self.logger.debug(f"POP3: Server {server_ip} ready for AUTH PLAIN credentials")
            return

        # Check for +OK response (success)
        if response_indicator == "+OK":
            if session.username and session.password:
                self._record_credential(session, success=True)
                session.state = "complete"
            elif session.state == "got_user":
                # USER command accepted, waiting for PASS
                session.state = "got_user_ok"

        # Check for -ERR response (failure)
        if response_indicator == "-ERR":
            if session.username:
                # Record failed attempt if we have at least a username
                self._record_credential(session, success=False)
                # Reset for next attempt
                session.password = ""
                session.auth_method = ""
                session.state = "got_banner" if session.server_banner else "init"

    def _process_client_packet(
        self,
        client_ip: str,
        client_port: int,
        server_ip: str,
        port: int,
        command: str,
        parameter: str,
    ) -> None:
        """Process POP3 client command."""
        session = self._get_session(client_ip, client_port, server_ip)
        if port and not session.server_port:
            session.server_port = port

        # Normalize command to uppercase for comparison
        command_upper = command.upper() if command else ""

        # Check for USER command
        if command_upper == "USER" and parameter:
            session.username = parameter.strip()
            session.auth_method = "USER/PASS"
            session.state = "got_user"
            self.logger.debug(f"POP3: Client {client_ip} USER: {session.username}")
            self._update_client_device(client_ip, server_ip, port)
            return

        # Check for PASS command
        if command_upper == "PASS" and parameter:
            session.password = parameter.strip()
            # Remove trailing \r if present
            if session.password.endswith("\r"):
                session.password = session.password[:-1]
            session.state = "got_pass"
            self.logger.debug(f"POP3: Client {client_ip} PASS captured")

            # If we have both username and password, record immediately
            # Success status will be updated by server response
            if session.username:
                self._record_credential(session, success=None)
            return

        # Check for STLS command
        if command_upper == "STLS":
            self.stls_servers.add(server_ip)
            self.logger.debug(f"POP3 STLS: {client_ip} -> {server_ip}")

        # Check for AUTH PLAIN command
        if command_upper == "AUTH" and parameter and parameter.upper().startswith("PLAIN"):
            session.auth_method = "AUTH PLAIN"
            session.state = "auth_plain_pending"
            self.logger.debug(f"POP3: Client {client_ip} AUTH PLAIN initiated")
            self._update_client_device(client_ip, server_ip, port)

            # Check if credentials are inline (AUTH PLAIN <base64>)
            parts = parameter.split(None, 1)
            if len(parts) > 1:
                credentials = self._decode_auth_plain(parts[1])
                if credentials[0]:
                    session.username, session.password = credentials
                    session.state = "got_pass"
                    self.logger.debug(f"POP3: AUTH PLAIN decoded - user: {session.username}")
                    self._record_credential(session, success=None)
            return

        # Check for base64 credentials after AUTH PLAIN
        if session.state == "auth_plain_pending" and command:
            # The line after AUTH PLAIN should be base64 encoded
            # Format: \x00username\x00password
            credentials = self._decode_auth_plain(command)
            if credentials[0]:
                session.username, session.password = credentials
                session.state = "got_pass"
                self.logger.debug(f"POP3: AUTH PLAIN decoded - user: {session.username}")
                self._record_credential(session, success=None)

    def _record_credential(self, session: POP3Session, success: Optional[bool]) -> None:
        """Record extracted POP3 credential."""
        # Don't record incomplete credentials
        if not session.username:
            return

        # Check if we already have this credential
        for cred in self.credentials:
            if (
                cred.server_ip == session.server_ip
                and cred.client_ip == session.client_ip
                and cred.username == session.username
                and cred.password == session.password
            ):
                # Update success status if we now know it
                if success is not None and cred.success is None:
                    cred.success = success
                return

        cred = POP3Credential(
            username=session.username,
            password=session.password,
            auth_method=session.auth_method or "USER/PASS",
            server_ip=session.server_ip,
            server_port=session.server_port,
            client_ip=session.client_ip,
            server_banner=session.server_banner,
            timestamp=datetime.now().isoformat(),
            success=success,
        )
        self.credentials.append(cred)

        self.logger.info(
            f"POP3 Credential: {session.username}:{session.password} "
            f"@ {session.server_ip}:{session.server_port} (method={session.auth_method}, success={success})"
        )

        # Update device with credential info
        self._update_device_credentials(session)

    def _update_server_device(self, server_ip: str, banner: str, port: int) -> None:
        """Update or create POP3 server device entry."""
        if not is_valid_discovered_ip(server_ip):
            return

        device_key = f"pop3-server:{server_ip}"
        protocol = "POP3/TCP" if port == 110 else "POP3S/TCP"

        device, is_new = self._ensure_device(
            device_key,
            server_ip,
            name=f"POP3 Server ({server_ip})",
            device_type="POP3 Server",
        )
        if is_new:
            device.pop3_passive_data = {
                "role": "server",
                "server_banner": banner,
                "credentials": [],
                "protocol": protocol,
                "port": port,
            }
        else:
            if device.pop3_passive_data and banner:
                device.pop3_passive_data["server_banner"] = banner

    def _update_client_device(self, client_ip: str, server_ip: str, port: int) -> None:
        """Update or create POP3 client device entry."""
        if not is_valid_discovered_ip(client_ip):
            return

        device_key = f"pop3-client:{client_ip}"
        protocol = "POP3/TCP" if port == 110 else "POP3S/TCP"

        device, is_new = self._ensure_device(
            device_key,
            client_ip,
            name=f"POP3 Client ({client_ip})",
            device_type="POP3 Client",
        )
        if is_new:
            device.pop3_passive_data = {
                "role": "client",
                "server_banner": "",
                "credentials": [],
                "servers_accessed": [server_ip],
                "protocol": protocol,
            }
        else:
            if device.pop3_passive_data:
                servers = device.pop3_passive_data.get("servers_accessed", [])
                if server_ip not in servers:
                    servers.append(server_ip)
                    device.pop3_passive_data["servers_accessed"] = servers

    def _update_device_credentials(self, session: POP3Session) -> None:
        """Update device entries with credential information."""
        # Update server device
        server_key = f"pop3-server:{session.server_ip}"
        client_key = f"pop3-client:{session.client_ip}"

        cred_entry = {
            "username": session.username,
            "password": session.password,
            "auth_method": session.auth_method,
            "client_ip": session.client_ip,
            "timestamp": datetime.now().isoformat(),
        }

        with self._lock:
            # Update server
            if server_key in self.discovered_devices:
                device = self.discovered_devices[server_key]
                if device.pop3_passive_data:
                    creds = device.pop3_passive_data.get("credentials", [])
                    # Avoid duplicates
                    if not any(
                        c.get("username") == session.username
                        and c.get("password") == session.password
                        for c in creds
                    ):
                        creds.append(cred_entry)
                        device.pop3_passive_data["credentials"] = creds

            # Update client
            if client_key in self.discovered_devices:
                device = self.discovered_devices[client_key]
                if device.pop3_passive_data:
                    creds = device.pop3_passive_data.get("credentials", [])
                    client_cred = {
                        "username": session.username,
                        "password": session.password,
                        "auth_method": session.auth_method,
                        "server_ip": session.server_ip,
                        "timestamp": datetime.now().isoformat(),
                    }
                    if not any(
                        c.get("username") == session.username
                        and c.get("server_ip") == session.server_ip
                        for c in creds
                    ):
                        creds.append(client_cred)
                        device.pop3_passive_data["credentials"] = creds

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials.

        Returns:
            List of credential dictionaries with:
                - protocol: "POP3"
                - username: str
                - password: str
                - auth_method: str
                - server_ip: str
                - client_ip: str
                - success: bool or None
                - timestamp: str
        """
        return [
            {
                "protocol": "POP3",
                "credential_type": "plaintext",
                "username": cred.username,
                "password": cred.password,
                "auth_method": cred.auth_method,
                "server_ip": cred.server_ip,
                "client_ip": cred.client_ip,
                "server_banner": cred.server_banner,
                "success": cred.success,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]
