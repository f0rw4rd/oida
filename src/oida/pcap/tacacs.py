"""
TACACS+ Passive Listener for credential extraction.

Passively captures TACACS+ traffic to extract:
- Usernames from authentication requests
- Passwords from authentication requests (when unencrypted)
- Session IDs, version info, authentication types
- Service types, privilege levels, remote addresses

TACACS+ (RFC 8907) normally encrypts the body using a shared secret,
but misconfigured deployments may use unencrypted mode.

tshark fields:
- tacplus.user: Username
- tacplus.auth_password: Authentication password
- tacplus.session_id: Session identifier
- tacplus.majvers / tacplus.minvers: Protocol version
- tacplus.authentication_type: Auth type (ASCII, PAP, CHAP, etc.)
- tacplus.service: Service type (Login, Enable, PPP, etc.)
- tacplus.authen_action: Authentication action (Login, ChangePass, etc.)
- tacplus.remote_address: Client-reported remote address
- tacplus.privilege_level: Requested privilege level (0-15)
- tacplus.type: Message type (Authentication, Authorization, Accounting)
- tacplus.seqno: Sequence number within session
- tacplus.flags.unencrypted: Whether payload is unencrypted
- tacplus.port: Client port/terminal identifier
- tacplus.user_len / tacplus.password_length / tacplus.address_len: Field lengths
- tacacs.username: Legacy TACACS username
- tacacs.password: Legacy TACACS password

References:
- RFC 8907: TACACS+ Protocol
- Wireshark dissector: packet-tacacs.c
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase

# ---------------------------------------------------------------------------
# Lookup tables (RFC 8907)
# ---------------------------------------------------------------------------

_TACPLUS_MSG_TYPES: Dict[int, str] = {
    1: "Authentication",
    2: "Authorization",
    3: "Accounting",
}

_TACPLUS_AUTHEN_TYPES: Dict[int, str] = {
    1: "ASCII",
    2: "PAP",
    3: "CHAP",
    4: "ARAP",
    5: "MSCHAP",
    6: "MSCHAPv2",
}

_TACPLUS_SERVICES: Dict[int, str] = {
    0: "None",
    1: "Login",
    2: "Enable",
    3: "PPP",
    4: "ARAP",
    5: "PT",
    6: "RCMD",
    7: "X25",
    8: "NASI",
    9: "FW-PROXY",
}

_TACPLUS_ACTIONS: Dict[int, str] = {
    1: "Login",
    2: "ChangePass",
    3: "SendPass",
    4: "SendAuth",
}


@dataclass
class TACACSCredential:
    """Extracted TACACS+ credential."""

    username: str
    password: str = ""
    credential_type: str = "plaintext"
    server_ip: str = ""
    server_port: int = 0
    client_ip: str = ""
    timestamp: str = ""
    authen_type: str = ""
    privilege_level: str = ""
    session_id: str = ""
    # hashcat-16100 material (encrypted-body case): all hex
    tacacs_session_hex: str = ""  # 4-byte session id
    tacacs_cipher_hex: str = ""  # encrypted body bytes
    tacacs_verseq_hex: str = ""  # version byte ‖ seq byte (e.g. "c002")

    @property
    def auth_method(self) -> str:
        """Scanner credential loop compatibility."""
        if self.authen_type:
            return f"TACACS+/{self.authen_type}"
        return "TACACS+"

    @property
    def hash_value(self) -> str:
        """Canonical credential field: the hashcat-16100 line for hash creds."""
        return self.hashcat_format if self.credential_type == "hash" else ""

    @property
    def hashcat_format(self) -> str:
        """Hashcat-compatible hash string (mode 16100, TACACS+).

        ``$tacacs-plus$0$<session_id>$<ciphertext>$<version||seq>`` -- cracking
        recovers the TACACS+ shared secret from an encrypted AUTHEN body.
        Verified against the hashcat example_hashes mode-16100 vector. Returns ""
        unless the session id + ciphertext + version/seq are all present.
        """
        if self.tacacs_session_hex and self.tacacs_cipher_hex and self.tacacs_verseq_hex:
            return (
                f"$tacacs-plus$0${self.tacacs_session_hex}$"
                f"{self.tacacs_cipher_hex}${self.tacacs_verseq_hex}"
            )
        return ""


class TACACSPassiveListener(PySharkListenerBase):
    """Passive TACACS+ traffic listener for credential extraction.

    Captures TACACS+ authentication traffic to extract usernames and passwords.
    Only effective when TACACS+ traffic is unencrypted (misconfiguration).
    """

    PROTOCOL_NAME = "tacacs"
    DISPLAY_FILTER = "tacacs or tacplus"
    REQUIRED_LAYERS = ("tacacs", "tacplus")
    PROTOCOL_COLUMNS = (
        "session",
        "seq",
        "type",
        "action",
        "auth_type",
        "service",
        "user",
        "priv_lvl",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.credentials: List[TACACSCredential] = []

    def process_packet(self, packet) -> None:
        """Process TACACS+ packet and extract credentials and session data."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)

        username = ""
        password = ""

        # --- T1 and T2 field extraction ---
        session_id = ""
        majvers = ""
        minvers = ""
        remote_address = ""
        authen_type_raw = ""
        authen_type_name = ""
        service_raw = ""
        service_name = ""
        action_raw = ""
        action_name = ""
        user_len = ""
        address_len = ""
        password_length = ""
        # T2 fields
        msg_type_raw = ""
        msg_type_name = ""
        seqno = ""
        flags_unencrypted = ""
        privilege_level = ""
        port_name = ""

        # Try TACACS+ (tacplus) layer
        if hasattr(packet, "tacplus"):
            tacplus = packet.tacplus
            username = str(self.get_field(tacplus, "user", "") or "").strip()
            password = str(self.get_field(tacplus, "auth_password", "") or "").strip()

            # T1: session_id
            session_id = str(self.get_field(tacplus, "session_id", "") or "").strip()
            if not session_id:
                session_id = "?"
                self.logger.debug(f"Missing session_id in TACACS+ packet from {src_ip} -> {dst_ip}")

            # T1: version (majvers / minvers)
            majvers = str(self.get_field(tacplus, "majvers", "") or "").strip()
            minvers = str(self.get_field(tacplus, "minvers", "") or "").strip()
            if not majvers:
                majvers = "?"
                self.logger.debug(f"Missing majvers in TACACS+ packet from {src_ip} -> {dst_ip}")
            if not minvers:
                minvers = "?"
                self.logger.debug(f"Missing minvers in TACACS+ packet from {src_ip} -> {dst_ip}")

            # T1: remote_address (client-reported address)
            remote_address = str(self.get_field(tacplus, "remote_address", "") or "").strip()
            if not remote_address:
                remote_address = "?"
                self.logger.debug(
                    f"Missing remote_address in TACACS+ packet from {src_ip} -> {dst_ip}"
                )

            # T1: authentication_type
            authen_type_raw = str(self.get_field(tacplus, "authentication_type", "") or "").strip()
            if authen_type_raw:
                try:
                    authen_type_name = _TACPLUS_AUTHEN_TYPES.get(
                        int(authen_type_raw, 0), authen_type_raw
                    )
                except (ValueError, TypeError):
                    authen_type_name = authen_type_raw
            else:
                authen_type_raw = "?"
                authen_type_name = "?"
                self.logger.debug(
                    f"Missing authentication_type in TACACS+ packet from {src_ip} -> {dst_ip}"
                )

            # T1: service
            service_raw = str(self.get_field(tacplus, "service", "") or "").strip()
            if service_raw:
                try:
                    service_name = _TACPLUS_SERVICES.get(int(service_raw, 0), service_raw)
                except (ValueError, TypeError):
                    service_name = service_raw
            else:
                service_raw = "?"
                service_name = "?"
                self.logger.debug(f"Missing service in TACACS+ packet from {src_ip} -> {dst_ip}")

            # T1: authen_action
            action_raw = str(self.get_field(tacplus, "authen_action", "") or "").strip()
            if action_raw:
                try:
                    action_name = _TACPLUS_ACTIONS.get(int(action_raw, 0), action_raw)
                except (ValueError, TypeError):
                    action_name = action_raw
            else:
                action_raw = "?"
                action_name = "?"
                self.logger.debug(
                    f"Missing authen_action in TACACS+ packet from {src_ip} -> {dst_ip}"
                )

            # T1: length fields (user_len, address_len, password_length)
            user_len = str(self.get_field(tacplus, "user_len", "") or "").strip()
            if not user_len:
                user_len = "?"
                self.logger.debug(f"Missing user_len in TACACS+ packet from {src_ip} -> {dst_ip}")

            address_len = str(self.get_field(tacplus, "address_len", "") or "").strip()
            if not address_len:
                address_len = "?"
                self.logger.debug(
                    f"Missing address_len in TACACS+ packet from {src_ip} -> {dst_ip}"
                )

            password_length = str(self.get_field(tacplus, "password_length", "") or "").strip()
            if not password_length:
                password_length = "?"
                self.logger.debug(
                    f"Missing password_length in TACACS+ packet from {src_ip} -> {dst_ip}"
                )

            # T2: type (message type)
            msg_type_raw = str(self.get_field(tacplus, "type", "") or "").strip()
            if msg_type_raw:
                try:
                    msg_type_name = _TACPLUS_MSG_TYPES.get(int(msg_type_raw, 0), msg_type_raw)
                except (ValueError, TypeError):
                    msg_type_name = msg_type_raw
            else:
                msg_type_raw = "?"
                msg_type_name = "?"
                self.logger.debug(f"Missing type in TACACS+ packet from {src_ip} -> {dst_ip}")

            # T2: seqno
            seqno = str(self.get_field(tacplus, "seqno", "") or "").strip()
            if not seqno:
                seqno = "?"
                self.logger.debug(f"Missing seqno in TACACS+ packet from {src_ip} -> {dst_ip}")

            # T2: flags.unencrypted (security-critical)
            flags_unencrypted = str(self.get_field(tacplus, "flags_unencrypted", "") or "").strip()
            if not flags_unencrypted:
                flags_unencrypted = "?"
                self.logger.debug(
                    f"Missing flags_unencrypted in TACACS+ packet from {src_ip} -> {dst_ip}"
                )

            # T2: privilege_level
            privilege_level = str(self.get_field(tacplus, "privilege_level", "") or "").strip()
            if not privilege_level:
                privilege_level = "?"
                self.logger.debug(
                    f"Missing privilege_level in TACACS+ packet from {src_ip} -> {dst_ip}"
                )

            # T2: port (terminal/line identifier)
            port_name = str(self.get_field(tacplus, "port", "") or "").strip()
            if not port_name:
                port_name = "?"
                self.logger.debug(f"Missing port in TACACS+ packet from {src_ip} -> {dst_ip}")

        # Try legacy TACACS layer
        if hasattr(packet, "tacacs"):
            tacacs = packet.tacacs
            if not username:
                username = str(self.get_field(tacacs, "username", "") or "").strip()
            if not password:
                password = str(self.get_field(tacacs, "password", "") or "").strip()

        # Encrypted AUTHEN body -> hashcat 16100 (recovers the shared secret).
        # This is the NORMAL (correctly-configured) case, where there is no
        # cleartext user/password to extract -- so do it before the early return.
        self._extract_encrypted_hash(packet, src_ip, dst_ip, src_port, dst_port)

        if not username and not password:
            return

        # Determine direction from request field or seqno
        # TACACS+ uses odd seqno for requests, even for responses
        direction = "request"
        if seqno and seqno != "?":
            try:
                if int(seqno, 0) % 2 == 0:
                    direction = "response"
            except (ValueError, TypeError) as e:
                self.logger.debug(f"TACACS+: failed to parse seqno={seqno!r} for direction: {e}")

        # Build descriptive operation name
        parts = ["TACACS+"]
        if msg_type_name and msg_type_name != "?":
            parts.append(msg_type_name)
        if action_name and action_name != "?":
            parts.append(action_name)
        operation = " ".join(parts)

        # Record interaction with full detail
        now = datetime.now().isoformat()
        details: Dict[str, Any] = {
            "username": username,
            "session_id": session_id,
            "majvers": majvers,
            "minvers": minvers,
            "remote_address": remote_address,
            "authentication_type": authen_type_raw,
            "authentication_type_name": authen_type_name,
            "service": service_raw,
            "service_name": service_name,
            "authen_action": action_raw,
            "authen_action_name": action_name,
            "user_len": user_len,
            "address_len": address_len,
            "password_length": password_length,
            "msg_type": msg_type_raw,
            "msg_type_name": msg_type_name,
            "seqno": seqno,
            "flags_unencrypted": flags_unencrypted,
            "privilege_level": privilege_level,
            "port": port_name,
        }

        summary = (
            f"TACACS+ {msg_type_name} user={username} "
            f"auth={authen_type_name} svc={service_name} "
            f"priv={privilege_level} {src_ip} -> {dst_ip}"
            if username
            else f"TACACS+ {msg_type_name} {src_ip} -> {dst_ip}"
        )

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Alert on unencrypted TACACS+ traffic (security finding)
        if flags_unencrypted and flags_unencrypted.lower() in ("true", "1"):
            self.logger.warning(
                f"TACACS+ UNENCRYPTED traffic detected: {src_ip} -> {dst_ip} "
                f"session={session_id} user={username}"
            )

        if not self._is_duplicate(username, password, src_ip, dst_ip):
            cred = TACACSCredential(
                username=username,
                password=password,
                credential_type="plaintext" if password else "username_only",
                server_ip=dst_ip,
                server_port=dst_port,
                client_ip=src_ip,
                timestamp=now,
                authen_type=authen_type_name if authen_type_name != "?" else "",
                privilege_level=privilege_level if privilege_level != "?" else "",
                session_id=session_id if session_id != "?" else "",
            )
            self.credentials.append(cred)
            self._update_devices(
                src_ip,
                dst_ip,
                session_id=session_id,
                majvers=majvers,
                minvers=minvers,
                authen_type_name=authen_type_name,
                service_name=service_name,
                privilege_level=privilege_level,
                remote_address=remote_address,
            )

            if password:
                self.logger.info(f"TACACS+: {username}:{password} @ {dst_ip}:{dst_port}")
            else:
                self.logger.info(f"TACACS+: username={username} @ {dst_ip}:{dst_port}")

    def _is_duplicate(self, username: str, password: str, client_ip: str, server_ip: str) -> bool:
        """Check if credential is already recorded."""
        for cred in self.credentials:
            if (
                cred.username == username
                and cred.password == password
                and cred.client_ip == client_ip
                and cred.server_ip == server_ip
            ):
                return True
        return False

    def _update_devices(
        self,
        client_ip: str,
        server_ip: str,
        *,
        session_id: str = "",
        majvers: str = "",
        minvers: str = "",
        authen_type_name: str = "",
        service_name: str = "",
        privilege_level: str = "",
        remote_address: str = "",
    ) -> None:
        """Update device entries with protocol-specific data."""
        version = ""
        if majvers and majvers != "?" and minvers and minvers != "?":
            # Majvers is the full version byte; extract actual major from high nibble
            try:
                maj_int = int(majvers, 0)
                # TACACS+ packs major in high nibble (0xC = 12 for TACACS+)
                actual_major = maj_int >> 4
                actual_minor = int(minvers, 0)
                version = f"{actual_major}.{actual_minor}"
            except (ValueError, TypeError):
                version = f"{majvers}.{minvers}"

        server_data: Dict[str, Any] = {
            "role": "server",
            "protocol": "TACACS+/TCP",
        }
        if version:
            server_data["version"] = version
        if session_id and session_id != "?":
            server_data.setdefault("session_ids", [])
            if session_id not in server_data.get("session_ids", []):
                server_data.setdefault("session_ids", []).append(session_id)

        self._ensure_device(
            f"tacacs-server:{server_ip}",
            server_ip,
            name=f"TACACS+ Server ({server_ip})",
            device_type="AAA Server",
            data_attr="tacacs_passive_data",
            protocol_data=server_data,
        )

        client_data: Dict[str, Any] = {
            "role": "client",
            "protocol": "TACACS+/TCP",
        }
        if authen_type_name and authen_type_name != "?":
            client_data["authen_type"] = authen_type_name
        if service_name and service_name != "?":
            client_data["service"] = service_name
        if privilege_level and privilege_level != "?":
            client_data["privilege_level"] = privilege_level
        if remote_address and remote_address != "?":
            client_data["remote_address"] = remote_address
        if version:
            client_data["version"] = version

        self._ensure_device(
            f"tacacs-client:{client_ip}",
            client_ip,
            name=f"TACACS+ Client ({client_ip})",
            device_type="Network Device",
            data_attr="tacacs_passive_data",
            protocol_data=client_data,
        )

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format interaction for the operations table."""
        d = ix.details
        return [
            d.get("session_id", "?"),
            d.get("seqno", "?"),
            d.get("msg_type_name", "?"),
            d.get("authen_action_name", "?"),
            d.get("authentication_type_name", "?"),
            d.get("service_name", "?"),
            d.get("username", ""),
            d.get("privilege_level", "?"),
        ]

    @staticmethod
    def _tcp_payload_bytes(packet) -> bytes:
        """Raw TCP payload (the full TACACS+ packet) for hash extraction."""
        tcp = getattr(packet, "tcp", None)
        if tcp is None:
            return b""
        p = getattr(tcp, "payload", None)
        if isinstance(p, (bytes, bytearray)):
            return bytes(p)
        if not p:
            return b""
        try:
            return bytes.fromhex(str(p).replace(":", "").replace(" ", ""))
        except ValueError:
            return b""

    def _extract_encrypted_hash(
        self, packet, src_ip: str, dst_ip: str, src_port: int, dst_port: int
    ) -> None:
        """Build a hashcat-16100 hash from an encrypted TACACS+ AUTHEN packet.

        TACACS+ header (12 bytes): version(1) type(1) seq_no(1) flags(1)
        session_id(4) length(4), followed by the encrypted body. The body is
        recoverable only by cracking the shared secret -- mode 16100 does that
        from session_id, version, seq_no and the encrypted bytes.
        """
        body = self._tcp_payload_bytes(packet)
        if len(body) < 18:  # 12-byte header + >=6 bytes cipher
            return
        version, ptype, seq, flags = body[0], body[1], body[2], body[3]
        if flags & 0x01:  # TAC_PLUS_UNENCRYPTED_FLAG -> cleartext, handled elsewhere
            return
        if ptype != 0x01:  # only AUTHEN (the 16100 known-plaintext case)
            return
        length = int.from_bytes(body[8:12], "big")
        cipher = body[12 : 12 + length]
        if len(cipher) < 6:
            return
        session_hex = body[4:8].hex()
        verseq_hex = f"{version:02x}{seq:02x}"
        key = ("tacacs16100", session_hex, verseq_hex)
        if key in getattr(self, "_seen_hashes", set()):
            return
        self._seen_hashes = getattr(self, "_seen_hashes", set())
        self._seen_hashes.add(key)
        # BMC/server is the AUTHEN reply sender; record ip/port best-effort.
        cred = TACACSCredential(
            username="",
            credential_type="hash",
            server_ip=dst_ip,
            server_port=dst_port or 49,
            client_ip=src_ip,
            timestamp=datetime.now().isoformat(),
            session_id=session_hex,
            tacacs_session_hex=session_hex,
            tacacs_cipher_hex=cipher.hex(),
            tacacs_verseq_hex=verseq_hex,
        )
        self.credentials.append(cred)
        self.logger.info(
            f"TACACS+ encrypted AUTHEN hash (mode 16100) session={session_hex} "
            f"{src_ip} -> {dst_ip}"
        )

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials."""
        return [
            {
                "protocol": "TACACS+",
                "credential_type": cred.credential_type,
                "auth_method": cred.auth_method,
                "username": cred.username,
                "password": cred.password,
                "server_ip": cred.server_ip,
                "client_ip": cred.client_ip,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]

    def get_hashcat_hashes(self) -> List[str]:
        """TACACS+ encrypted-AUTHEN hashes in hashcat mode-16100 format.

        Delegates to the per-credential property; plaintext (misconfigured)
        credentials yield "" and are skipped.
        """
        return [c.hashcat_format for c in self.credentials if c.hashcat_format]
