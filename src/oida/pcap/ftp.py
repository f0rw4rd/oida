"""
FTP Passive Listener for credential extraction.

Passively captures FTP traffic to extract:
- FTP server banners
- Login credentials (username/password in plaintext)
- FTP client identification

Based on BruteShark's FtpPasswordParser approach.

FTP authentication flow:
    220 Banner
    USER username
    331 Password required
    PASS password
    230 Login successful / 530 Login failed
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
)


@dataclass
class FTPCredential:
    """Extracted FTP credential."""

    username: str
    password: str
    server_ip: str
    server_port: int = 0
    client_ip: str = ""
    server_banner: str = ""
    timestamp: str = ""
    success: Optional[bool] = None  # True if 230, False if 530, None if unknown
    credential_type: str = "plaintext"

    @property
    def auth_method(self) -> str:
        """Scanner credential loop compatibility."""
        return "FTP"


@dataclass
class FTPSession:
    """Track FTP session state for credential extraction."""

    client_ip: str
    server_ip: str
    server_port: int = 0
    server_banner: str = ""
    username: str = ""
    password: str = ""
    state: str = "init"  # init, got_banner, got_user, got_pass, complete


class FTPPassiveListener(PySharkListenerBase):
    """Passive FTP traffic listener for credential extraction.

    Captures FTP traffic to extract:
    - Server banners (220 response)
    - Usernames (USER command)
    - Passwords (PASS command, plaintext)
    - Login success/failure (230/530 responses)

    Usage:
        # Live capture
        listener = FTPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
        devices = listener.scan()

        # Access extracted credentials
        for cred in listener.credentials:
            print(f"{cred.username}:{cred.password} @ {cred.server_ip}")

    Data structure stored in device.ftp_passive_data:
        {
            "role": "server" | "client",
            "server_banner": "220 FTP Server Ready",
            "credentials": [
                {"username": "admin", "password": "secret", "success": True}
            ],
            "protocol": "FTP/TCP",
        }
    """

    PROTOCOL_NAME = "ftp"
    DISPLAY_FILTER = "ftp"
    REQUIRED_LAYERS = ("ftp",)
    PROTOCOL_COLUMNS = ("command", "argument", "code", "detail")
    # FTP response codes
    FTP_BANNER = 220
    FTP_PASSWORD_REQUIRED = 331
    FTP_LOGIN_SUCCESS = 230
    FTP_LOGIN_FAILED = 530

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize FTP passive listener.

        Args:
            interface: Network interface to capture on
            timeout: Capture timeout in seconds
            nxc_logger: Optional NXC-style logger
        """
        super().__init__(interface, timeout, nxc_logger)

        # Track FTP sessions by (client_ip, server_ip) tuple
        self._sessions: Dict[Tuple[str, str], FTPSession] = {}

        # Extracted credentials
        self.credentials: List[FTPCredential] = []

        # File operations tracking
        self.file_operations: List[Dict[str, str]] = []

    def process_packet(self, packet) -> None:
        """Process FTP packet and extract credentials.

        Args:
            packet: PyShark packet object with FTP layer
        """
        # Check for FTP layer
        if not hasattr(packet, "ftp"):
            return

        # Get IP information
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)

        # Get port information
        src_port, dst_port = self.get_port_info(packet)

        ftp_layer = packet.ftp

        now = datetime.now().isoformat()

        # Check for FTP request (client -> server)
        request_command = self.get_field(ftp_layer, "request_command")
        if request_command:
            # Client command
            client_ip = src_ip
            server_ip = dst_ip
            server_port = dst_port
            request_arg = self.get_field(ftp_layer, "request_arg", "")
            cmd_upper = request_command.upper() if request_command else ""
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                f"FTP {cmd_upper}",
                {"command": cmd_upper, "argument": request_arg or ""},
                (
                    f"FTP {cmd_upper} {request_arg}".strip()
                    if cmd_upper != "PASS"
                    else "FTP PASS ****"
                ),
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )
            self._process_client_command(
                client_ip, server_ip, request_command, request_arg, server_port
            )
            return

        # Check for FTP response (server -> client)
        response_code = self.get_field(ftp_layer, "response_code")
        if response_code:
            # Server response
            client_ip = dst_ip
            server_ip = src_ip
            server_port = src_port
            response_arg = self.get_field(ftp_layer, "response_arg", "")
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                f"FTP {response_code}",
                {
                    "response_code": response_code,
                    "response_arg": response_arg or "",
                },
                f"FTP {response_code} {response_arg or ''}".strip(),
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )
            self._process_server_response(
                client_ip, server_ip, response_code, response_arg, server_port
            )
            return

        # FTP layer present but neither a request command nor a response code was
        # found (e.g. a tshark continuation/reassembly segment of a multi-line
        # response). Log and skip rather than silently dropping the frame.
        self.logger.debug(
            f"FTP: frame {src_ip}->{dst_ip} has ftp layer but no recognized "
            "request_command or response_code; no interaction recorded"
        )

    def _get_session(self, client_ip: str, server_ip: str) -> FTPSession:
        """Get or create FTP session tracker."""
        key = (client_ip, server_ip)
        if key not in self._sessions:
            self._sessions[key] = FTPSession(
                client_ip=client_ip,
                server_ip=server_ip,
            )
        return self._sessions[key]

    def _process_server_response(
        self,
        client_ip: str,
        server_ip: str,
        response_code: str,
        response_arg: str,
        server_port: int = 0,
    ) -> None:
        """Process FTP server response."""
        session = self._get_session(client_ip, server_ip)
        if server_port and not session.server_port:
            session.server_port = server_port

        try:
            code = int(response_code)
        except (ValueError, TypeError) as e:
            self.logger.debug(f"FTP: response code int parse failed: {e}")
            return

        # Check for banner (220)
        if code == self.FTP_BANNER:
            session.server_banner = response_arg.strip() if response_arg else ""
            session.state = "got_banner"
            self._update_server_device(server_ip, session.server_banner)
            self.logger.debug(f"FTP: Server {server_ip} banner: {session.server_banner}")

        # Check for 331 (password required) - confirms USER was accepted
        elif code == self.FTP_PASSWORD_REQUIRED:
            if session.state == "got_user":
                session.state = "got_user_ok"

        # Check for login success (230)
        elif code == self.FTP_LOGIN_SUCCESS:
            if session.username and session.password:
                self._record_credential(session, success=True)
                session.state = "complete"

        # Check for login failure (530)
        elif code == self.FTP_LOGIN_FAILED:
            if session.username:
                self._record_credential(session, success=False)
                # Reset for next attempt
                session.password = ""
                session.state = "got_banner" if session.server_banner else "init"

    def _process_client_command(
        self,
        client_ip: str,
        server_ip: str,
        command: str,
        argument: str,
        server_port: int = 0,
    ) -> None:
        """Process FTP client command."""
        session = self._get_session(client_ip, server_ip)
        if server_port and not session.server_port:
            session.server_port = server_port

        command_upper = command.upper() if command else ""

        # Check for USER command
        if command_upper == "USER":
            session.username = argument.strip() if argument else ""
            session.state = "got_user"
            self.logger.debug(f"FTP: Client {client_ip} USER: {session.username}")
            self._update_client_device(client_ip, server_ip)

        # Check for file operation commands
        elif command_upper in (
            "RETR",
            "STOR",
            "DELE",
            "LIST",
            "NLST",
            "MKD",
            "RMD",
            "RNFR",
            "RNTO",
            "CWD",
        ):
            filename = argument.strip() if argument else ""
            op_names = {
                "RETR": "Download",
                "STOR": "Upload",
                "DELE": "Delete",
                "LIST": "List",
                "NLST": "List",
                "MKD": "MkDir",
                "RMD": "RmDir",
                "RNFR": "Rename From",
                "RNTO": "Rename To",
                "CWD": "ChDir",
            }
            self.file_operations.append(
                {
                    "operation": op_names.get(command_upper, command_upper),
                    "filename": filename,
                    "source_ip": client_ip,
                    "dest_ip": server_ip,
                }
            )

        # Check for PASS command
        elif command_upper == "PASS":
            session.password = argument.strip() if argument else ""
            # Remove trailing \r if present
            if session.password.endswith("\r"):
                session.password = session.password[:-1]
            session.state = "got_pass"
            self.logger.debug(f"FTP: Client {client_ip} PASS captured")

            # If we have both username and password, we can record
            # (success will be determined by server response)
            if session.username:
                # Record immediately - success status will be updated later
                self._record_credential(session, success=None)

    def _record_credential(self, session: FTPSession, success: Optional[bool]) -> None:
        """Record extracted FTP credential."""
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

        cred = FTPCredential(
            username=session.username,
            password=session.password,
            server_ip=session.server_ip,
            server_port=session.server_port,
            client_ip=session.client_ip,
            server_banner=session.server_banner,
            timestamp=datetime.now().isoformat(),
            success=success,
        )
        self.credentials.append(cred)

        self.logger.info(
            f"FTP Credential: {session.username}:{session.password} "
            f"@ {session.server_ip}:{session.server_port} (success={success})"
        )

        # Update device with credential info
        self._update_device_credentials(session)

    def _update_server_device(self, server_ip: str, banner: str) -> None:
        """Update or create FTP server device entry."""
        if not is_valid_discovered_ip(server_ip):
            return

        device_key = f"ftp-server:{server_ip}"

        device, is_new = self._ensure_device(
            device_key,
            server_ip,
            name=f"FTP Server ({server_ip})",
            device_type="FTP Server",
        )
        if is_new:
            device.ftp_passive_data = {
                "role": "server",
                "server_banner": banner,
                "credentials": [],
                "protocol": "FTP/TCP",
            }
        else:
            if device.ftp_passive_data and banner:
                device.ftp_passive_data["server_banner"] = banner

    def _update_client_device(self, client_ip: str, server_ip: str) -> None:
        """Update or create FTP client device entry."""
        if not is_valid_discovered_ip(client_ip):
            return

        device_key = f"ftp-client:{client_ip}"

        device, is_new = self._ensure_device(
            device_key,
            client_ip,
            name=f"FTP Client ({client_ip})",
            device_type="FTP Client",
        )
        if is_new:
            device.ftp_passive_data = {
                "role": "client",
                "server_banner": "",
                "credentials": [],
                "servers_accessed": [server_ip],
                "protocol": "FTP/TCP",
            }
        else:
            if device.ftp_passive_data:
                servers = device.ftp_passive_data.get("servers_accessed", [])
                if server_ip not in servers:
                    servers.append(server_ip)
                    device.ftp_passive_data["servers_accessed"] = servers

    def _update_device_credentials(self, session: FTPSession) -> None:
        """Update device entries with credential information."""
        # Update server device
        server_key = f"ftp-server:{session.server_ip}"
        client_key = f"ftp-client:{session.client_ip}"

        cred_entry = {
            "username": session.username,
            "password": session.password,
            "client_ip": session.client_ip,
            "timestamp": datetime.now().isoformat(),
        }

        with self._lock:
            # Update server
            if server_key in self.discovered_devices:
                device = self.discovered_devices[server_key]
                if device.ftp_passive_data:
                    creds = device.ftp_passive_data.get("credentials", [])
                    # Avoid duplicates
                    if not any(
                        c.get("username") == session.username
                        and c.get("password") == session.password
                        for c in creds
                    ):
                        creds.append(cred_entry)
                        device.ftp_passive_data["credentials"] = creds

            # Update client
            if client_key in self.discovered_devices:
                device = self.discovered_devices[client_key]
                if device.ftp_passive_data:
                    creds = device.ftp_passive_data.get("credentials", [])
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
                        device.ftp_passive_data["credentials"] = creds

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format interaction as [Command, Argument, Code, Detail]."""
        d = ix.details
        if ix.direction == "request":
            cmd = d.get("command", "")
            arg = d.get("argument", "")
            # Mask passwords
            if cmd == "PASS":
                arg = "****"
            return [cmd, arg, "", ""]
        else:
            code = d.get("response_code", "")
            resp_arg = d.get("response_arg", "")
            return ["", "", code, resp_arg]

    def harvest(self) -> Dict[str, Any]:
        """Override harvest to use unified operations table only.

        Credentials are still reported via get_credentials_summary() but
        rendered inside the operations table flow rather than a separate
        credentials table.
        """
        tables: List[Dict[str, Any]] = []
        alerts: List[Dict[str, str]] = []

        # Credential alerts
        if self.credentials:
            for cred in self.credentials:
                status = (
                    "success"
                    if cred.success
                    else ("failed" if cred.success is False else "unknown")
                )
                alerts.append(
                    {
                        "level": "fail" if cred.success else "warning",
                        "category": "credential",
                        "message": (
                            f"FTP credential: {cred.username}@{cred.server_ip}"
                            f":{cred.server_port} ({status})"
                        ),
                    }
                )

        if not tables and not alerts:
            return {}

        return {"tables": tables, "alerts": alerts}

    def get_file_operations(self) -> List[Dict[str, str]]:
        """Get file operations extracted from FTP commands."""
        return self.file_operations

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials.

        Returns:
            List of credential dictionaries with:
                - protocol: "FTP"
                - username: str
                - password: str
                - server_ip: str
                - client_ip: str
                - success: bool or None
                - timestamp: str
        """
        return [
            {
                "protocol": "FTP",
                "credential_type": "plaintext",
                "auth_method": "FTP",
                "username": cred.username,
                "password": cred.password,
                "server_ip": cred.server_ip,
                "client_ip": cred.client_ip,
                "server_banner": cred.server_banner,
                "success": cred.success,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]
