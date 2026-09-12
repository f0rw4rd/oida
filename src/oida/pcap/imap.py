"""
IMAP Passive Listener for credential extraction.

Passively captures IMAP traffic to extract:
- Plaintext LOGIN credentials
- AUTHENTICATE PLAIN credentials (Base64)
- CRAM-MD5 authentication hashes
- Server banners (* OK greeting)
- CAPABILITY parsing
- STARTTLS detection
- Mailbox access tracking (SELECT/EXAMINE)

Based on BruteShark's ImapPasswordParser approach.

RFCs:
- RFC 4959: IMAP Extension for Simple Authentication and Security Layer (SASL) - PLAIN
- RFC 1731: IMAP4 Authentication Mechanisms - Kerberos V4, GSSAPI, SKEY
- RFC 2195: IMAP/POP AUTHorize Extension - CRAM-MD5
- RFC 2831: Digest-MD5 SASL Mechanism

IMAP Authentication Methods:
1. LOGIN command: Plaintext username/password
   > a001 LOGIN username password
   < a001 OK LOGIN completed

2. AUTHENTICATE PLAIN: Base64-encoded credentials (RFC 2595)
   > a001 AUTHENTICATE PLAIN
   < +
   > AGF1dGhlbnRpY2F0aW9uLWlkAHBhc3N3b3Jk  (base64 of \0authid\0password)
   < a001 OK PLAIN authentication successful

3. AUTHENTICATE CRAM-MD5: Challenge-response (RFC 2195)
   > a001 AUTHENTICATE CRAM-MD5
   < + PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2UucmVzdG9uLm1jaS5uZXQ+
   > dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw
   < a001 OK CRAM-MD5 authentication successful

PyShark IMAP field reference (packet.imap.*):
- imap.line: Full line ("* OK Microsoft Exchange IMAP4rev1 server ...")
- imap.request.command / imap.command: Command name (CAPABILITY, LOGIN, SELECT, etc.)
- imap.request.username: Username from LOGIN (PyShark directly decodes)
- imap.request.password: Password from LOGIN (PyShark directly decodes)
- imap.request.folder: Folder name for SELECT/EXAMINE
- imap.request_tag: Command tag
- imap.response.status: OK/NO/BAD/BYE
- imap.response.command: Command being responded to
- imap.isrequest: True/False
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
)


@dataclass
class IMAPCredential:
    """Extracted IMAP credential."""

    auth_method: str  # "LOGIN", "PLAIN", "CRAM-MD5"
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

        ``$cram_md5$<base64-challenge>$<base64-response>``. On the wire both the
        server challenge and the client response are already base64, and hashcat
        wants them base64, so they pass through verbatim. Verified against the
        hashcat example_hashes mode-10200 vector.
        """
        if self.auth_method == "CRAM-MD5" and self.challenge and self.hash_value:
            return f"$cram_md5${self.challenge}${self.hash_value}"
        return ""


@dataclass
class IMAPSession:
    """Track IMAP session state."""

    client_ip: str
    server_ip: str
    server_port: int = 0
    data_buffer: str = ""
    # Per-method "credential already extracted" flags. Once a method has
    # yielded a credential for this session, its DOTALL regex is no longer
    # re-run over the (re-accumulating) buffer -- this both stops the O(n^2)
    # re-scan and avoids repeatedly re-matching the same already-recorded
    # credential. Keys: "LOGIN", "PLAIN", "CRAM-MD5".
    extracted: Set[str] = field(default_factory=set)


class IMAPPassiveListener(PySharkListenerBase):
    """Passive IMAP traffic listener for credential extraction.

    Captures IMAP traffic to extract:
    - LOGIN command credentials (plaintext)
    - AUTHENTICATE PLAIN credentials (Base64)
    - CRAM-MD5 challenge/response hashes
    - Server banners (* OK greeting)
    - CAPABILITY extensions
    - STARTTLS detection
    - Mailbox access (SELECT/EXAMINE)

    Usage:
        # Live capture
        listener = IMAPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Access extracted credentials
        for cred in listener.credentials:
            print(f"{cred.auth_method}: {cred.username}")

    Data structure stored in device.imap_passive_data:
        {
            "role": "server" | "client",
            "credentials": [...],
            "auth_methods": ["LOGIN", "PLAIN", "CRAM-MD5"],
            "protocol": "IMAP/TCP",
        }
    """

    PROTOCOL_NAME = "imap"
    DISPLAY_FILTER = "imap"
    REQUIRED_LAYERS = ("imap",)
    PROTOCOL_COLUMNS = (
        "tag",
        "command",
        "parameter",
        "server_banner",
    )
    IMAP_PORTS = (143, 993)

    # Bound the per-session regex-extraction buffer. IMAP auth exchanges that
    # the DOTALL fallback cares about (LOGIN / AUTHENTICATE PLAIN / CRAM-MD5)
    # complete within a handful of small lines, so the most recent few KB are
    # always enough. Capping the buffer turns the per-packet re-scan from
    # O(n^2) / unbounded-memory (peer-controlled wire traffic) into bounded
    # work, closing the passive-capture DoS vector.
    MAX_BUFFER = 8192

    # IMAP command tag pattern (e.g., "a001 ", "A1 ")
    IMAP_TAG = r"[A-Za-z0-9]{1,6}\s+"

    # Regex patterns (from BruteShark)
    # Plaintext LOGIN: a001 LOGIN username password
    IMAP_PLAINTEXT_LOGIN_REGEX = re.compile(
        rf"({IMAP_TAG})?LOGIN\s+(?P<Username>\S+)\s+(?P<Password>\S+)\r?\n.*?({IMAP_TAG})?OK",
        re.IGNORECASE | re.DOTALL,
    )

    # AUTHENTICATE PLAIN: credentials as Base64
    # Format: AUTHENTICATE PLAIN\r\n+ \r\nbase64creds\r\nOK
    # Or: AUTHENTICATE PLAIN base64creds\r\nOK (inline)
    IMAP_AUTH_PLAIN_REGEX = re.compile(
        rf"({IMAP_TAG})?AUTHENTICATE\s+PLAIN(?:(?:\r?\n\+\s*\r?\n)|\s+)(?P<CredentialsBase64>[A-Za-z0-9+/=]+)\r?\n.*?({IMAP_TAG})?OK",
        re.IGNORECASE | re.DOTALL,
    )

    # AUTHENTICATE CRAM-MD5: challenge-response
    IMAP_CRAM_MD5_REGEX = re.compile(
        rf"({IMAP_TAG})?AUTHENTICATE\s+CRAM-MD5\r?\n\+\s+(?P<Challenge>[A-Za-z0-9+/=]+)\r?\n(?P<Response>[A-Za-z0-9+/=]+)\r?\n.*?({IMAP_TAG})?OK",
        re.IGNORECASE | re.DOTALL,
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize IMAP passive listener."""
        super().__init__(interface, timeout, nxc_logger)

        # Track IMAP sessions by (client_ip, server_ip) tuple
        self._sessions: Dict[Tuple[str, str], IMAPSession] = {}

        # Extracted credentials
        self.credentials: List[IMAPCredential] = []

        # Track server banners by IP (first banner wins)
        self.server_banners: Dict[str, str] = {}
        # Track STARTTLS usage
        self.starttls_servers: Set[str] = set()
        # Track CAPABILITY per server
        self.server_capabilities: Dict[str, List[str]] = {}
        # Track mailbox access per client IP -> set of folder names
        self.mailbox_access: Dict[str, Set[str]] = {}

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format IMAP interaction as a table row."""
        d = ix.details
        tag = d.get("tag", "") or "-"
        command = d.get("command", "")
        response_status = d.get("response_status", "")
        if command:
            cmd_str = command
        elif response_status:
            cmd_str = response_status
        else:
            cmd_str = "?"

        param = d.get("parameter", "") or d.get("response_detail", "") or "-"
        # Mask LOGIN password in table display
        if command == "LOGIN" and d.get("has_password"):
            # Show username but mask password
            username = d.get("login_username", "")
            param = f"{username} ****" if username else "****"
        banner = d.get("banner", "") or "-"

        return [
            tag,
            cmd_str,
            param,
            banner,
        ]

    def process_packet(self, packet) -> None:
        """Process IMAP packet and extract credentials."""
        # Get IP info using helper
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)

        # Get port info
        src_port, dst_port = self.get_port_info(packet)
        if src_port == 0 and dst_port == 0:
            self.logger.debug(f"Dropping IMAP packet with no port info (src={src_ip} dst={dst_ip})")
            return

        # Check if we have IMAP layer
        if not hasattr(packet, "imap"):
            return

        imap_layer = packet.imap

        # Extract structured fields from PyShark
        request_command = self.get_field_any(imap_layer, "request_command", "command", default="")
        request_tag = self.get_field(imap_layer, "request_tag", "")
        response_status = self.get_field(imap_layer, "response_status", "")
        response_command = self.get_field(imap_layer, "response_command", "")
        line_data = self.get_field(imap_layer, "line", "")
        request_folder = self.get_field(imap_layer, "request_folder", "")

        # PyShark direct credential fields
        pyshark_username = self.get_field(imap_layer, "request_username", "")
        pyshark_password = self.get_field(imap_layer, "request_password", "")

        # Determine direction based on port (143 = IMAP, 993 = IMAPS). IMAP may
        # run on any TCP port (e.g. a proxy/remapped port); use a canonical port
        # if it appears on either side, otherwise fall back to "lower port wins"
        # (the listening server side has the smaller fixed port vs. the ephemeral
        # client port). This mirrors the iec104/mms heuristic and avoids dropping
        # non-standard-port sessions that still match the imap display filter.
        if dst_port in self.IMAP_PORTS:
            # Client -> Server
            is_request = True
        elif src_port in self.IMAP_PORTS:
            # Server -> Client
            is_request = False
        else:
            # Non-standard port: lower port is the server (listening) side.
            is_request = dst_port <= src_port

        if is_request:
            client_ip = src_ip
            server_ip = dst_ip
            server_port = dst_port
        else:
            client_ip = dst_ip
            server_ip = src_ip
            server_port = src_port

        now = datetime.now().isoformat()
        banner = self.server_banners.get(server_ip, "")
        cmd_upper = str(request_command).upper() if request_command else ""

        # --- Process server responses (line_data, response_status) ---
        if not is_request:
            # Server -> Client: check for banner, capabilities
            if line_data:
                line_str = str(line_data)
                # Banner: "* OK ..." at start of session
                if line_str.startswith("* OK") and server_ip not in self.server_banners:
                    banner_text = line_str[4:].strip()
                    if banner_text:
                        self.server_banners[server_ip] = banner_text
                        banner = banner_text
                        self.logger.debug(f"IMAP banner: {server_ip} -> {banner_text}")

                # CAPABILITY: "* CAPABILITY IMAP4rev1 AUTH=PLAIN ..."
                if line_str.upper().startswith("* CAPABILITY"):
                    self._parse_capability(server_ip, line_str)

            detail: Dict[str, Any] = {
                "response_status": str(response_status) if response_status else "",
                "response_detail": str(response_command) if response_command else "",
                "tag": str(request_tag) if request_tag else "*",
                "banner": banner,
            }
            op = f"IMAP {response_status}" if response_status else "IMAP"
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                op,
                detail,
                f"IMAP {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )

        # --- Process client commands ---
        if is_request:
            # Try to determine the command -- either from PyShark's parsed
            # request_command/command fields, or by inspecting the raw request
            # data for unrecognised commands (DONE, SASL continuation, etc.).
            if not cmd_upper:
                raw_request = self.get_field(imap_layer, "request", "")
                if raw_request:
                    raw_str = str(raw_request).strip()
                    # DONE (IDLE termination) -- tshark puts it only in
                    # imap.request / imap.line, not request_command.
                    if raw_str.upper() == "DONE":
                        cmd_upper = "DONE"
                    else:
                        # SASL continuation data (Base64 blob after
                        # AUTHENTICATE PLAIN / CRAM-MD5 challenge).
                        cmd_upper = "CONTINUATION"

            if cmd_upper:
                detail = {
                    "command": cmd_upper,
                    "parameter": str(request_folder) if request_folder else "",
                    "tag": str(request_tag) if request_tag else "",
                    "banner": banner,
                }

                # STARTTLS detection
                if cmd_upper == "STARTTLS":
                    self.starttls_servers.add(server_ip)
                    detail["starttls"] = True
                    self.logger.debug(f"IMAP STARTTLS: {client_ip} -> {server_ip}")

                # LOGIN command - use PyShark direct fields for table display
                if cmd_upper == "LOGIN":
                    detail["has_password"] = True
                    if pyshark_username:
                        detail["login_username"] = str(pyshark_username).strip("\"'")
                        detail["parameter"] = str(pyshark_username).strip("\"'")

                    # Direct credential extraction from PyShark fields
                    if pyshark_username and pyshark_password:
                        username = str(pyshark_username).strip("\"'")
                        password = str(pyshark_password).strip("\"'")
                        session = self._get_session(client_ip, server_ip)
                        if server_port and not session.server_port:
                            session.server_port = server_port
                        if username and self._is_new_credential(
                            session, "LOGIN", username, password
                        ):
                            session.extracted.add("LOGIN")
                            cred = IMAPCredential(
                                auth_method="LOGIN",
                                credential_type="plaintext",
                                username=username,
                                password=password,
                                server_ip=server_ip,
                                server_port=server_port,
                                client_ip=client_ip,
                                timestamp=now,
                            )
                            self._record_credential(session, cred)

                # SELECT / EXAMINE - track mailbox access
                if cmd_upper in ("SELECT", "EXAMINE") and request_folder:
                    folder = str(request_folder).strip("\"'")
                    self.mailbox_access.setdefault(client_ip, set()).add(folder)
                    detail["parameter"] = folder
                    self.logger.debug(f"IMAP {cmd_upper}: {client_ip} -> {folder}")

                # AUTHENTICATE - track SASL mechanism (PLAIN / LOGIN /
                # CRAM-MD5 / XOAUTH2, ...). There is no
                # "imap.request.parameter" / "imap.request_parameter" field in
                # any Wireshark version -- derive the mechanism from the raw
                # request text instead. ``imap.request`` is documented as the
                # "remainder of request line" (tag already stripped by the
                # dissector), e.g. "AUTHENTICATE PLAIN", but be defensive in
                # case a caller feeds the full line (tag included) or trailing
                # CRLF.
                if cmd_upper == "AUTHENTICATE":
                    raw_request = self.get_field(imap_layer, "request", "")
                    if raw_request:
                        tokens = str(raw_request).strip().split()
                        upper_tokens = [t.upper() for t in tokens]
                        mechanism = ""
                        if "AUTHENTICATE" in upper_tokens:
                            idx = upper_tokens.index("AUTHENTICATE")
                            if idx + 1 < len(tokens):
                                mechanism = tokens[idx + 1].upper()
                        elif tokens:
                            # Verb already stripped (e.g. only the remainder
                            # after "AUTHENTICATE" was supplied) -- the first
                            # token is the mechanism itself.
                            mechanism = tokens[0].upper()
                        if mechanism:
                            detail["parameter"] = mechanism

                # CONTINUATION - SASL data after AUTHENTICATE
                if cmd_upper == "CONTINUATION":
                    raw_request = self.get_field(imap_layer, "request", "")
                    detail["parameter"] = str(raw_request)[:40] if raw_request else ""
                    detail["tag"] = ""  # continuation has no tag

                op = f"IMAP {cmd_upper}"
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "request",
                    op,
                    detail,
                    f"IMAP {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=self.get_stream_id(packet),
                )

        # --- Accumulate session data for regex-based credential extraction ---
        # This is the fallback for AUTHENTICATE PLAIN, CRAM-MD5, and LOGIN
        # when PyShark direct fields aren't available.
        request_data = self.get_field(imap_layer, "request", "")
        response_data = self.get_field(imap_layer, "response", "")

        packet_data = ""
        if request_data:
            packet_data += str(request_data) + "\r\n"
        if response_data:
            packet_data += str(response_data) + "\r\n"
        if line_data:
            packet_data += str(line_data) + "\r\n"

        # Also check for other common IMAP field names in pyshark
        for field_name in [
            "request_tag",
            "request_command",
            "response_tag",
            "response_status",
        ]:
            field_val = self.get_field(imap_layer, field_name, "")
            if field_val:
                packet_data += str(field_val) + " "

        if not packet_data.strip():
            return

        # Accumulate session data for regex-based extraction
        session = self._get_session(client_ip, server_ip)
        if server_port and not session.server_port:
            session.server_port = server_port
        session.data_buffer += packet_data
        # Cap the buffer to a bounded sliding window: keep only the most recent
        # MAX_BUFFER bytes so a long-lived / high-volume session cannot grow it
        # without limit nor force ever-larger DOTALL scans.
        if len(session.data_buffer) > self.MAX_BUFFER:
            session.data_buffer = session.data_buffer[-self.MAX_BUFFER :]

        # Try to extract credentials from accumulated session data
        self._try_extract_credentials(session)

    def _parse_capability(self, server_ip: str, line: str) -> None:
        """Parse CAPABILITY response line into capabilities list.

        Example: "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN AUTH=LOGIN IDLE"
        """
        # Strip "* CAPABILITY " prefix
        cap_str = (
            line[len("* CAPABILITY") :].strip() if line.upper().startswith("* CAPABILITY") else line
        )
        caps = self.server_capabilities.setdefault(server_ip, [])
        for cap in cap_str.split():
            cap = cap.strip()
            if cap and cap not in caps:
                caps.append(cap)

    def _get_session(self, client_ip: str, server_ip: str) -> IMAPSession:
        """Get or create IMAP session tracker."""
        key = (client_ip, server_ip)
        if key not in self._sessions:
            self._sessions[key] = IMAPSession(
                client_ip=client_ip,
                server_ip=server_ip,
            )
        return self._sessions[key]

    def _try_extract_credentials(self, session: IMAPSession) -> None:
        """Try to extract credentials from session data."""
        session_text = session.data_buffer

        # Try each authentication method
        self._try_plaintext_login(session, session_text)
        self._try_auth_plain(session, session_text)
        self._try_cram_md5(session, session_text)

    def _try_plaintext_login(self, session: IMAPSession, session_text: str) -> None:
        """Extract plaintext LOGIN credentials."""
        # Already recorded a LOGIN credential for this session: stop re-running
        # the DOTALL search over the re-accumulating buffer every packet.
        if "LOGIN" in session.extracted:
            return
        match = self.IMAP_PLAINTEXT_LOGIN_REGEX.search(session_text)
        if match:
            username = match.group("Username").strip("\"'")
            password = match.group("Password").strip("\"'")

            if self._is_new_credential(session, "LOGIN", username, password):
                session.extracted.add("LOGIN")
                cred = IMAPCredential(
                    auth_method="LOGIN",
                    credential_type="plaintext",
                    username=username,
                    password=password,
                    server_ip=session.server_ip,
                    server_port=session.server_port,
                    client_ip=session.client_ip,
                    timestamp=datetime.now().isoformat(),
                )
                self._record_credential(session, cred)

    def _try_auth_plain(self, session: IMAPSession, session_text: str) -> None:
        """Extract AUTHENTICATE PLAIN credentials (Base64)."""
        if "PLAIN" in session.extracted:
            return
        match = self.IMAP_AUTH_PLAIN_REGEX.search(session_text)
        if match:
            creds_b64 = match.group("CredentialsBase64")
            username, password = self._decode_auth_plain(creds_b64)

            if username and self._is_new_credential(session, "PLAIN", username, password):
                session.extracted.add("PLAIN")
                cred = IMAPCredential(
                    auth_method="PLAIN",
                    credential_type="plaintext",
                    username=username,
                    password=password,
                    server_ip=session.server_ip,
                    server_port=session.server_port,
                    client_ip=session.client_ip,
                    timestamp=datetime.now().isoformat(),
                )
                self._record_credential(session, cred)

    def _try_cram_md5(self, session: IMAPSession, session_text: str) -> None:
        """Extract CRAM-MD5 challenge/response."""
        if "CRAM-MD5" in session.extracted:
            return
        match = self.IMAP_CRAM_MD5_REGEX.search(session_text)
        if match:
            challenge = match.group("Challenge")
            response = match.group("Response")

            # Decode response to get username (format: username hash)
            username = self._extract_cram_md5_username(response)

            if username and self._is_new_hash(session, "CRAM-MD5", username, response):
                session.extracted.add("CRAM-MD5")
                cred = IMAPCredential(
                    auth_method="CRAM-MD5",
                    credential_type="hash",
                    username=username,
                    hash_value=response,
                    challenge=challenge,
                    server_ip=session.server_ip,
                    server_port=session.server_port,
                    client_ip=session.client_ip,
                    timestamp=datetime.now().isoformat(),
                )
                self._record_credential(session, cred)

    def _is_new_credential(
        self, session: IMAPSession, method: str, username: str, password: str
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
        self, session: IMAPSession, method: str, username: str, hash_value: str
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

    def _record_credential(self, session: IMAPSession, cred: IMAPCredential) -> None:
        """Record extracted credential."""
        self.credentials.append(cred)

        if cred.credential_type == "plaintext":
            self.logger.info(
                f"IMAP {cred.auth_method}: {cred.username}:{cred.password} "
                f"@ {cred.server_ip}:{cred.server_port}"
            )
        else:
            self.logger.info(
                f"IMAP {cred.auth_method} hash: {cred.username} "
                f"@ {cred.server_ip}:{cred.server_port}"
            )

        # Update device entries
        self._update_devices(session, cred)

    def _update_devices(self, session: IMAPSession, cred: IMAPCredential) -> None:
        """Update device entries with credential information."""
        if not is_valid_discovered_ip(session.server_ip):
            return

        server_key = f"imap-server:{session.server_ip}"
        client_key = f"imap-client:{session.client_ip}"

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
            name=f"IMAP Server ({session.server_ip})",
            device_type="IMAP Server",
        )
        if is_new:
            device.imap_passive_data = {
                "role": "server",
                "banner": banner,
                "capabilities": caps,
                "starttls": uses_starttls,
                "credentials": [cred_entry],
                "auth_methods": [cred.auth_method],
                "protocol": "IMAP/TCP",
            }
        else:
            if device.imap_passive_data:
                device.imap_passive_data.setdefault("credentials", []).append(cred_entry)
                if cred.auth_method not in device.imap_passive_data.get("auth_methods", []):
                    device.imap_passive_data.setdefault("auth_methods", []).append(cred.auth_method)
                if banner:
                    device.imap_passive_data["banner"] = banner
        # Client device
        if is_valid_discovered_ip(session.client_ip):
            device, is_new = self._ensure_device(
                client_key,
                session.client_ip,
                name=f"IMAP Client ({session.client_ip})",
                device_type="IMAP Client",
            )
            if is_new:
                device.imap_passive_data = {
                    "role": "client",
                    "credentials": [cred_entry],
                    "servers_accessed": [session.server_ip],
                    "mailboxes": list(self.mailbox_access.get(session.client_ip, set())),
                    "protocol": "IMAP/TCP",
                }

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials."""
        result = []
        for cred in self.credentials:
            entry = {
                "protocol": "IMAP",
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

        Delegates to the per-credential property; non-CRAM-MD5 (plaintext)
        credentials yield "" and are skipped.
        """
        return [c.hashcat_format for c in self.credentials if c.hashcat_format]
