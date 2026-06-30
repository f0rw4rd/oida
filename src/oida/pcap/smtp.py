"""
SMTP Passive Listener for credential and server extraction.

Passively captures SMTP traffic to extract:
- AUTH LOGIN credentials (Base64)
- AUTH PLAIN credentials (Base64)
- CRAM-MD5 authentication hashes
- Server banners and software versions
- EHLO client hostnames (fingerprinting)
- MAIL FROM / RCPT TO email addresses
- STARTTLS usage detection
- EHLO capabilities (auth methods, extensions)

Based on BruteShark's SmtpPasswordParser approach.

PyShark SMTP field reference (packet.smtp.*):
- smtp.req.command: SMTP command (EHLO, MAIL, RCPT, AUTH, DATA, STARTTLS, QUIT)
- smtp.req.parameter: Command parameter
- smtp.response.code: Response code (220, 250, 334, 235, 354, etc.)
- smtp.rsp.parameter: Response parameter (banner, capabilities, etc.)
- smtp.auth.username: Base64-encoded username (AUTH LOGIN)
- smtp.auth.password: Base64-encoded password (AUTH LOGIN)
- smtp.command_line: Full command line
- smtp.data.fragment.count: DATA fragment count
- smtp.data.reassembled.length: Reassembled DATA length
"""

import base64
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
)


@dataclass
class SMTPCredential:
    """Extracted SMTP credential."""

    auth_method: str  # "AUTH LOGIN", "AUTH PLAIN", "CRAM-MD5"
    credential_type: str  # "plaintext" or "hash"
    username: str
    password: str = ""  # For plaintext
    hash_value: str = ""  # For CRAM-MD5 (wire base64 response)
    challenge: str = ""  # For CRAM-MD5 (wire base64 challenge)
    server_ip: str = ""
    server_port: int = 0
    client_ip: str = ""
    timestamp: str = ""

    @property
    def hashcat_format(self) -> str:
        """Hashcat-compatible hash string (mode 10200, CRAM-MD5).

        ``$cram_md5$<base64-challenge>$<base64-response>`` -- both base64 on the
        wire, passed through verbatim (verified against hashcat example_hashes).
        """
        if self.auth_method == "CRAM-MD5" and self.challenge and self.hash_value:
            return f"$cram_md5${self.challenge}${self.hash_value}"
        return ""


@dataclass
class SMTPSession:
    """Track SMTP session state."""

    client_ip: str
    server_ip: str
    server_port: int = 0
    data_buffer: str = ""


class SMTPPassiveListener(PySharkListenerBase):
    """Passive SMTP traffic listener for credential and server extraction.

    Captures SMTP traffic to extract:
    - AUTH LOGIN/PLAIN credentials, CRAM-MD5 hashes
    - Server banners and software versions
    - EHLO client hostnames (fingerprinting)
    - MAIL FROM / RCPT TO email addresses
    - STARTTLS usage detection
    - EHLO capabilities (auth methods, extensions)

    Usage:
        listener = SMTPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for cred in listener.credentials:
            print(f"{cred.auth_method}: {cred.username}")
    """

    PROTOCOL_NAME = "smtp"
    DISPLAY_FILTER = "smtp"
    REQUIRED_LAYERS = ("smtp",)
    PROTOCOL_COLUMNS = (
        "command",
        "parameter",
        "server_banner",
    )
    SMTP_PORTS = (25, 587, 465)

    # Well-known Base64 prompts
    USERNAME_PROMPT_B64 = "VXNlcm5hbWU6"  # "Username:" in Base64
    PASSWORD_PROMPT_B64 = "UGFzc3dvcmQ6"  # "Password:" in Base64

    # Regex patterns (from BruteShark)
    # AUTH LOGIN: Base64 username and password with server prompts
    SMTP_AUTH_LOGIN_REGEX = re.compile(
        rf"AUTH\s+LOGIN\r\n"
        rf"334\s+{USERNAME_PROMPT_B64}\r\n"
        rf"(?P<Username>[A-Za-z0-9+/=]+)\r\n"
        rf"334\s+{PASSWORD_PROMPT_B64}\r\n"
        rf"(?P<Password>[A-Za-z0-9+/=]+)\r\n"
        rf"235",
        re.IGNORECASE | re.DOTALL,
    )

    # AUTH PLAIN: Single Base64 string
    SMTP_AUTH_PLAIN_REGEX = re.compile(
        r"AUTH\s+PLAIN\s+(?P<Credentials>[A-Za-z0-9+/=]+)\r\n.*?235",
        re.IGNORECASE | re.DOTALL,
    )

    # AUTH PLAIN with continuation (server sends + to request credentials)
    SMTP_AUTH_PLAIN_CONT_REGEX = re.compile(
        r"AUTH\s+PLAIN\r\n\+\s*\r\n(?P<Credentials>[A-Za-z0-9+/=]+)\r\n.*?235",
        re.IGNORECASE | re.DOTALL,
    )

    # AUTH CRAM-MD5: Challenge-response
    SMTP_CRAM_MD5_REGEX = re.compile(
        r"AUTH\s+CRAM-MD5\r\n"
        r"334\s+(?P<Challenge>[A-Za-z0-9+/=]+)\r\n"
        r"(?P<Hash>[A-Za-z0-9+/=]+)\r\n"
        r"235",
        re.IGNORECASE | re.DOTALL,
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self._sessions: Dict[Tuple[str, str], SMTPSession] = {}
        self.credentials: List[SMTPCredential] = []
        # Track server banners by IP
        self.server_banners: Dict[str, str] = {}
        # Track email addresses seen
        self.email_addresses: Dict[str, Set[str]] = {}  # ip -> {email, ...}
        # Track STARTTLS usage
        self.starttls_servers: Set[str] = set()
        # Track EHLO capabilities per server
        self.server_capabilities: Dict[str, List[str]] = {}

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format SMTP interaction as a table row."""
        d = ix.details
        command = d.get("command", "")
        response_code = d.get("response_code", "")
        if command:
            cmd_str = command
        elif response_code:
            cmd_str = response_code
        else:
            cmd_str = "?"

        param = d.get("parameter", "") or d.get("rsp_detail", "") or "-"
        banner = d.get("banner", "") or "-"

        return [
            cmd_str,
            param,
            banner,
        ]

    def process_packet(self, packet) -> None:
        """Process SMTP packet -- extract credentials, banners, emails, STARTTLS.

        Handles four packet categories that match the ``smtp`` display filter:
        1. Normal SMTP commands/responses (smtp.req.command / smtp.response.code)
        2. AUTH LOGIN base64 data lines (smtp.auth.username / smtp.auth.password
           present, but no smtp.req.command)
        3. Email body content lines between DATA and ``.`` (smtp layer present
           but no parseable fields)
        4. ICMP-encapsulated SMTP packets (no smtp layer in pyshark EK mode,
           but tshark still counts them under the ``smtp`` display filter)
        """
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        now = datetime.now().isoformat()
        stream_id = self.get_stream_id(packet)

        # --- Category 4: No smtp layer (ICMP-encapsulated SMTP) ---
        # Must run BEFORE the port-zero check because ICMP packets (type 3
        # "Destination Unreachable") lack a TCP layer, so get_port_info()
        # returns (0, 0).  tshark still counts them under the "smtp" filter
        # because the ICMP payload contains the original SMTP TCP segment.
        if not hasattr(packet, "smtp"):
            # Determine best-effort direction from ports (may both be 0)
            direction = "request"
            if src_port in self.SMTP_PORTS:
                direction = "response"
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                direction,
                "SMTP (encapsulated)",
                {"encapsulated": True},
                f"SMTP data in encapsulated packet {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
            return

        # For normal SMTP processing we need port info to determine direction
        if src_port == 0 and dst_port == 0:
            return

        # Determine direction based on SMTP ports. SMTP defaults to 25/587/465
        # but may run on any TCP port; the captured peer could be on a remapped
        # submission/proxy port. Use a canonical port if it appears on either
        # side; otherwise fall back to "lower port wins" (the listening server
        # side has the smaller fixed port vs. the ephemeral client port). This
        # mirrors the iec104/mms heuristic and avoids dropping non-standard-port
        # sessions that still match the smtp display filter.
        if dst_port in self.SMTP_PORTS:
            client_ip, server_ip = src_ip, dst_ip
            server_port = dst_port
        elif src_port in self.SMTP_PORTS:
            client_ip, server_ip = dst_ip, src_ip
            server_port = src_port
        elif dst_port <= src_port:
            client_ip, server_ip = src_ip, dst_ip
            server_port = dst_port
        else:
            client_ip, server_ip = dst_ip, src_ip
            server_port = src_port

        smtp_layer = packet.smtp
        session = self._get_session(client_ip, server_ip)
        if server_port and not session.server_port:
            session.server_port = server_port

        command = str(self.get_field(smtp_layer, "req_command", "") or "")
        parameter = str(self.get_field(smtp_layer, "req_parameter", "") or "")
        response_code = str(self.get_field(smtp_layer, "response_code", "") or "")
        rsp_param = str(self.get_field(smtp_layer, "rsp_parameter", "") or "")

        # T1: Full command line (e.g. "EHLO host\r\n", "AUTH LOGIN\r\n")
        command_line = str(self.get_field(smtp_layer, "command_line", "") or "").rstrip("\r\n")

        # T1: Combined AUTH PLAIN credential blob decoded by tshark
        auth_username_password = str(self.get_field(smtp_layer, "auth_username_password", "") or "")

        # T2: Full response text (code + message, e.g. "250 OK\r\n")
        response_text = str(self.get_field(smtp_layer, "response", "") or "").rstrip("\r\n")

        # T2: DATA fragment statistics
        data_fragment_count = str(self.get_field(smtp_layer, "data_fragment_count", "") or "")
        data_reassembled_length = str(
            self.get_field(smtp_layer, "data_reassembled_length", "") or ""
        )

        banner = self.server_banners.get(server_ip, "")

        # Track whether we record at least one interaction for this packet.
        # If none of the specific handlers below fire, we record a catch-all
        # interaction at the end so no packet is silently dropped.
        interaction_recorded = False

        # --- Process server responses ---
        if response_code:
            # 220 banner -- extract server software/version (only first 220)
            if response_code == "220" and rsp_param and server_ip not in self.server_banners:
                banner = _parse_banner(rsp_param)
                self.server_banners[server_ip] = banner
                self.logger.debug(f"SMTP banner: {server_ip} -> {banner}")

            # 250 after EHLO -- parse capabilities
            if response_code == "250" and rsp_param:
                self._parse_ehlo_capability(server_ip, rsp_param)

            rsp_detail: Dict[str, Any] = {
                "response_code": response_code,
                "rsp_detail": rsp_param if rsp_param else "",
                "banner": banner,
            }
            # T2: full response text preserves the complete server reply
            if response_text:
                rsp_detail["response_text"] = response_text
            # T2: DATA reassembly statistics
            if data_fragment_count:
                rsp_detail["data_fragment_count"] = data_fragment_count
            if data_reassembled_length:
                rsp_detail["data_reassembled_length"] = data_reassembled_length

            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                f"SMTP {response_code}",
                rsp_detail,
                f"SMTP {response_code} {rsp_param}".strip(),
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
            interaction_recorded = True

        # --- Process client commands ---
        if command:
            cmd_upper = command.upper()
            detail: Dict[str, Any] = {
                "command": cmd_upper,
                "parameter": parameter,
                "banner": banner,
            }
            # T1: raw command line preserves the original text for forensics
            if command_line:
                detail["command_line"] = command_line

            # EHLO/HELO -- extract client hostname
            if cmd_upper in ("EHLO", "HELO") and parameter:
                detail["client_hostname"] = parameter

            # MAIL FROM -- extract sender
            if cmd_upper == "MAIL" and parameter:
                email = _extract_email(parameter)
                if email:
                    detail["mail_from"] = email
                    self.email_addresses.setdefault(client_ip, set()).add(email)

            # RCPT TO -- extract recipient
            if cmd_upper == "RCPT" and parameter:
                email = _extract_email(parameter)
                if email:
                    detail["rcpt_to"] = email

            # STARTTLS detection (PyShark splits as command=STAR parameter=TLS)
            if cmd_upper == "STARTTLS" or (cmd_upper == "STAR" and parameter.upper() == "TLS"):
                self.starttls_servers.add(server_ip)
                detail["starttls"] = True
                detail["command"] = "STARTTLS"
                detail["parameter"] = ""
                self.logger.debug(f"SMTP STARTTLS: {client_ip} -> {server_ip}")

            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                f"SMTP {cmd_upper}",
                detail,
                f"SMTP {cmd_upper} {parameter}".strip(),
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
            interaction_recorded = True

        # --- Credential extraction ---
        # PyShark AUTH LOGIN fields
        auth_username = self.get_field(smtp_layer, "auth_username", "")
        auth_password = self.get_field(smtp_layer, "auth_password", "")

        if auth_username:
            try:
                username = base64.b64decode(auth_username).decode("utf-8", errors="ignore")
            except Exception:
                username = str(auth_username)
            session.data_buffer = f"username:{username}"

            # Category 2: AUTH LOGIN base64 username line (no command field)
            if not interaction_recorded:
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "request",
                    "SMTP AUTH data",
                    {"command": "AUTH", "parameter": "(username b64)", "banner": banner},
                    f"AUTH LOGIN username: {auth_username}",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
                interaction_recorded = True

        if auth_password:
            try:
                password = base64.b64decode(auth_password).decode("utf-8", errors="ignore")
            except Exception:
                password = str(auth_password)

            if session.data_buffer.startswith("username:"):
                username = session.data_buffer[9:]
                if username and self._is_new_credential(session, "AUTH LOGIN", username, password):
                    cred = SMTPCredential(
                        auth_method="AUTH LOGIN",
                        credential_type="plaintext",
                        username=username,
                        password=password,
                        server_ip=session.server_ip,
                        server_port=session.server_port,
                        client_ip=session.client_ip,
                        timestamp=datetime.now().isoformat(),
                    )
                    self._record_credential(session, cred)
                    session.data_buffer = ""

            # Category 2: AUTH LOGIN base64 password line (no command field)
            if not interaction_recorded:
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "request",
                    "SMTP AUTH data",
                    {"command": "AUTH", "parameter": "(password b64)", "banner": banner},
                    f"AUTH LOGIN password: {auth_password}",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
                interaction_recorded = True

        # T1: AUTH PLAIN via tshark-decoded auth.username_password field
        # tshark pre-parses AUTH PLAIN into a combined Base64 blob; use it
        # directly when available as it's more reliable than parameter parsing.
        if auth_username_password:
            username, password = self._decode_auth_plain(auth_username_password)
            if username and self._is_new_credential(session, "AUTH PLAIN", username, password):
                cred = SMTPCredential(
                    auth_method="AUTH PLAIN",
                    credential_type="plaintext",
                    username=username,
                    password=password,
                    server_ip=session.server_ip,
                    server_port=session.server_port,
                    client_ip=session.client_ip,
                    timestamp=datetime.now().isoformat(),
                )
                self._record_credential(session, cred)

        # AUTH PLAIN in command parameter (fallback when tshark field absent)
        if not auth_username_password and command and command.upper() == "AUTH" and parameter:
            param_upper = parameter.upper()
            if param_upper.startswith("PLAIN "):
                creds_b64 = parameter[6:].strip()
                username, password = self._decode_auth_plain(creds_b64)
                if username and self._is_new_credential(session, "AUTH PLAIN", username, password):
                    cred = SMTPCredential(
                        auth_method="AUTH PLAIN",
                        credential_type="plaintext",
                        username=username,
                        password=password,
                        server_ip=session.server_ip,
                        server_port=session.server_port,
                        client_ip=session.client_ip,
                        timestamp=datetime.now().isoformat(),
                    )
                    self._record_credential(session, cred)

        # T2: DATA reassembly summary packets (no command/response_code)
        if not command and not response_code and (data_fragment_count or data_reassembled_length):
            if not interaction_recorded:
                data_detail: Dict[str, Any] = {"banner": banner}
                if data_fragment_count:
                    data_detail["data_fragment_count"] = data_fragment_count
                if data_reassembled_length:
                    data_detail["data_reassembled_length"] = data_reassembled_length
                size_str = f"{data_reassembled_length} bytes" if data_reassembled_length else ""
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "SMTP DATA",
                    data_detail,
                    f"DATA reassembled: {data_fragment_count} fragments, {size_str}".strip(),
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
                interaction_recorded = True

        # CRAM-MD5 accumulation
        if response_code or command:
            payload_parts = []
            if command:
                payload_parts.append(
                    f"{command} {parameter}\r\n" if parameter else f"{command}\r\n"
                )
            if response_code:
                payload_parts.append(
                    f"{response_code} {rsp_param}\r\n" if rsp_param else f"{response_code}\r\n"
                )
            payload = "".join(payload_parts)
            if "CRAM-MD5" in session.data_buffer or "CRAM-MD5" in payload:
                session.data_buffer += payload
                self._try_cram_md5(session, session.data_buffer)

        # --- Catch-all: record interaction for any packet not yet accounted ---
        # This covers Category 3 (email body lines between DATA and ".") and
        # Category 2 edge cases (bare auth continuation lines like CRAM-MD5
        # responses that have an smtp layer but zero parseable fields).
        if not interaction_recorded:
            # Determine direction from the resolved server endpoint: traffic
            # FROM the server is a response, traffic TO the server is a request.
            # (Uses the same canonical-or-lower-port direction decision above so
            # non-standard-port sessions are labelled consistently.)
            direction = "request" if dst_ip == server_ip else "response"
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                direction,
                "SMTP DATA line",
                {"banner": banner},
                f"SMTP data content {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

    def _parse_ehlo_capability(self, server_ip: str, param: str) -> None:
        """Parse EHLO capability from 250 response line."""
        cap = param.strip()
        if not cap:
            return
        caps = self.server_capabilities.setdefault(server_ip, [])
        if cap not in caps:
            caps.append(cap)

    def _get_session(self, client_ip: str, server_ip: str) -> SMTPSession:
        """Get or create SMTP session tracker."""
        key = (client_ip, server_ip)
        if key not in self._sessions:
            self._sessions[key] = SMTPSession(
                client_ip=client_ip,
                server_ip=server_ip,
            )
        return self._sessions[key]

    def _try_cram_md5(self, session: SMTPSession, session_text: str) -> None:
        """Extract CRAM-MD5 challenge/response."""
        match = self.SMTP_CRAM_MD5_REGEX.search(session_text)
        if match:
            challenge_b64 = match.group("Challenge")
            hash_b64 = match.group("Hash")

            # Decode response to get username (format: username hash)
            username = self._extract_cram_md5_username(hash_b64)

            if username and self._is_new_hash(session, "CRAM-MD5", username, hash_b64):
                cred = SMTPCredential(
                    auth_method="CRAM-MD5",
                    credential_type="hash",
                    username=username,
                    hash_value=hash_b64,
                    challenge=challenge_b64,
                    server_ip=session.server_ip,
                    server_port=session.server_port,
                    client_ip=session.client_ip,
                    timestamp=datetime.now().isoformat(),
                )
                self._record_credential(session, cred)

    def _is_new_credential(
        self, session: SMTPSession, method: str, username: str, password: str
    ) -> bool:
        """Check if this is a new credential."""
        for cred in self.credentials:
            if (
                cred.server_ip == session.server_ip
                and cred.auth_method == method
                and cred.username == username
                and cred.password == password
            ):
                return False
        return True

    def _is_new_hash(
        self, session: SMTPSession, method: str, username: str, hash_value: str
    ) -> bool:
        """Check if this is a new hash."""
        for cred in self.credentials:
            if (
                cred.server_ip == session.server_ip
                and cred.auth_method == method
                and cred.username == username
                and cred.hash_value == hash_value
            ):
                return False
        return True

    def _record_credential(self, session: SMTPSession, cred: SMTPCredential) -> None:
        """Record extracted credential."""
        self.credentials.append(cred)

        if cred.credential_type == "plaintext":
            self.logger.info(
                f"SMTP {cred.auth_method}: {cred.username}:{cred.password} "
                f"@ {cred.server_ip}:{cred.server_port}"
            )
        else:
            self.logger.info(
                f"SMTP {cred.auth_method} hash: {cred.username} "
                f"@ {cred.server_ip}:{cred.server_port}"
            )

        # Update device entries
        self._update_devices(session, cred)

    def _update_devices(self, session: SMTPSession, cred: SMTPCredential) -> None:
        """Update device entries with credential information."""
        if not is_valid_discovered_ip(session.server_ip):
            return

        server_key = f"smtp-server:{session.server_ip}"
        client_key = f"smtp-client:{session.client_ip}"

        cred_entry = {
            "auth_method": cred.auth_method,
            "credential_type": cred.credential_type,
            "username": cred.username,
            "timestamp": cred.timestamp,
        }
        if cred.credential_type == "plaintext":
            cred_entry["password"] = cred.password
        else:
            cred_entry["hash"] = cred.hash_value
            cred_entry["challenge"] = cred.challenge

        # Server device
        banner = self.server_banners.get(session.server_ip, "")
        caps = self.server_capabilities.get(session.server_ip, [])
        uses_starttls = session.server_ip in self.starttls_servers

        device, is_new = self._ensure_device(
            server_key,
            session.server_ip,
            name=f"SMTP Server ({session.server_ip})",
            device_type="SMTP Server",
        )
        if is_new:
            device.smtp_passive_data = {
                "role": "server",
                "banner": banner,
                "capabilities": caps,
                "starttls": uses_starttls,
                "credentials": [cred_entry],
                "auth_methods": [cred.auth_method],
                "protocol": "SMTP/TCP",
            }
        else:
            if device.smtp_passive_data:
                device.smtp_passive_data.setdefault("credentials", []).append(cred_entry)
                if cred.auth_method not in device.smtp_passive_data.get("auth_methods", []):
                    device.smtp_passive_data.setdefault("auth_methods", []).append(cred.auth_method)
                if banner:
                    device.smtp_passive_data["banner"] = banner
        # Client device
        if is_valid_discovered_ip(session.client_ip):
            device, is_new = self._ensure_device(
                client_key,
                session.client_ip,
                name=f"SMTP Client ({session.client_ip})",
                device_type="SMTP Client",
            )
            if is_new:
                device.smtp_passive_data = {
                    "role": "client",
                    "credentials": [cred_entry],
                    "servers_accessed": [session.server_ip],
                    "emails": list(self.email_addresses.get(session.client_ip, set())),
                    "protocol": "SMTP/TCP",
                }

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials."""
        result = []
        for cred in self.credentials:
            entry = {
                "protocol": "SMTP",
                "auth_method": cred.auth_method,
                "credential_type": cred.credential_type,
                "username": cred.username,
                "server_ip": cred.server_ip,
                "client_ip": cred.client_ip,
                "timestamp": cred.timestamp,
            }
            if cred.credential_type == "plaintext":
                entry["password"] = cred.password
            else:
                entry["hash"] = cred.hash_value
                entry["challenge"] = cred.challenge
            result.append(entry)
        return result

    def get_hashcat_hashes(self) -> List[str]:
        """CRAM-MD5 credentials in hashcat mode-10200 format.

        Delegates to the per-credential property; plaintext credentials yield ""
        and are skipped.
        """
        return [c.hashcat_format for c in self.credentials if c.hashcat_format]


def _parse_banner(rsp_param: str) -> str:
    """Extract server software/version from 220 banner.

    Examples:
        "xc90.websitewelcome.com ESMTP Exim 4.69 #1 Mon, ..."
            -> "Exim 4.69"
        "napier Microsoft ESMTP MAIL Service, Version: 6.0.3790.3959 ready at ..."
            -> "Microsoft ESMTP 6.0.3790.3959"
        "mx.google.com ESMTP hf10si4097299icc.190 - gsmtp"
            -> "Google ESMTP"
    """
    if not rsp_param:
        return ""
    text = rsp_param.strip()
    # Remove leading hostname if present (before ESMTP/SMTP)
    for marker in ("ESMTP", "SMTP"):
        idx = text.find(marker)
        if idx > 0:
            text = text[idx:]
            break

    # Try to extract software + version
    # "ESMTP Exim 4.69" or "ESMTP Postfix"
    m = re.search(r"(?:E?SMTP)\s+(\S+(?:\s+[\d.]+)?)", text)
    if m:
        return m.group(0).strip()

    # "Microsoft ESMTP MAIL Service, Version: 6.0.3790.3959"
    m = re.search(r"Microsoft\s+ESMTP.*?Version:\s*([\d.]+)", rsp_param)
    if m:
        return f"Microsoft ESMTP {m.group(1)}"

    return text


def _extract_email(parameter: str) -> str:
    """Extract email address from MAIL FROM or RCPT TO parameter.

    Examples:
        "FROM:<user@example.com>"  -> "user@example.com"
        "TO:<admin@corp.net>"      -> "admin@corp.net"
        "FROM: user@host SIZE=1234" -> "user@host"
    """
    if not parameter:
        return ""
    # Try angle bracket format
    m = re.search(r"<([^>]+)>", parameter)
    if m:
        return m.group(1)
    # Try bare email
    m = re.search(r"(?:FROM|TO):?\s*(\S+@\S+)", parameter, re.IGNORECASE)
    if m:
        return m.group(1)
    return ""
