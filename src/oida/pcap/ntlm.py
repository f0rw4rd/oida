"""
NTLM Passive Listener for hash extraction (PyShark-based).

Passively captures NTLMSSP authentication traffic to extract:
- NTLMv1 hashes (challenge + response)
- NTLMv2 hashes (challenge + response)
- User/domain/workstation information

Based on BruteShark's NtlmsspHashParser approach.

NTLM Authentication Flow:
1. Client sends Type 1 (Negotiate) message
2. Server sends Type 2 (Challenge) message with 8-byte challenge
3. Client sends Type 3 (Authenticate) message with hashed response

Output formats are compatible with hashcat.

Reference: http://davenport.sourceforge.net/ntlm.html
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
)

# NTLM message types
NTLMSSP_TYPE1 = 1  # Negotiate (0x00000001)
NTLMSSP_TYPE2 = 2  # Challenge (0x00000002)
NTLMSSP_TYPE3 = 3  # Authenticate (0x00000003)


@dataclass
class NTLMHash:
    """Extracted NTLM hash."""

    hash_type: str  # "NTLMv1" or "NTLMv2"
    username: str
    domain: str
    workstation: str
    challenge: str  # Hex-encoded server challenge
    lm_hash: str  # Hex-encoded LM response
    nt_hash: str  # Hex-encoded NT response
    server_ip: str = ""
    server_port: int = 0
    client_ip: str = ""
    timestamp: str = ""

    @property
    def credential_type(self) -> str:
        return "hash"

    @property
    def auth_method(self) -> str:
        return self.hash_type

    @property
    def hash_value(self) -> str:
        return self.nt_hash

    @property
    def hashcat_format(self) -> str:
        """Hashcat-compatible hash string (mode 5500/5600).

        Returns "" when the hash has no crackable hashcat representation. A
        NetNTLM hash needs the server challenge (NTLM Type 2): without it the
        bare NT response cannot be cracked, so we return "" rather than a value
        that looks like a deliverable hash.
        """
        if not self.challenge:
            return ""
        if self.hash_type == "NTLMv1":
            return f"{self.username}::{self.domain}:{self.lm_hash}:{self.nt_hash}:{self.challenge}"
        elif self.hash_type == "NTLMv2" and len(self.nt_hash) >= 32:
            nt_proof = self.nt_hash[:32]
            blob = self.nt_hash[32:]
            return f"{self.username}::{self.domain}:{self.challenge}:{nt_proof}:{blob}"
        return ""


@dataclass
class NTLMSession:
    """Track NTLM session state for hash extraction."""

    client_ip: str
    server_ip: str
    challenge: str = ""  # From Type 2
    state: str = "init"  # init, got_challenge, complete


class NTLMPassiveListener(PySharkListenerBase):
    """Passive NTLM traffic listener for hash extraction.

    Captures NTLMSSP authentication to extract:
    - Server challenges (Type 2)
    - Client responses with hashes (Type 3)
    - NTLMv1 and NTLMv2 hashes for offline cracking

    Works with any protocol using NTLMSSP:
    - SMB (ports 445, 139)
    - HTTP (NTLM auth)
    - LDAP, MSSQL, etc.

    Usage:
        # Live capture (captures all TCP with NTLMSSP)
        listener = NTLMPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
        devices = listener.scan()

        # Access extracted hashes
        for h in listener.hashes:
            print(f"{h.hash_type}: {h.domain}\\{h.username}")

        # Get hashcat-compatible format
        for line in listener.get_hashcat_hashes():
            print(line)

    Data structure stored in device.ntlm_passive_data:
        {
            "role": "server" | "client",
            "domain": "CONTOSO",
            "hashes": [...],
            "protocol": "NTLMSSP/TCP",
        }
    """

    PROTOCOL_NAME = "ntlm"

    # Display filter for PyShark - matches NTLMSSP in any protocol layer
    DISPLAY_FILTER = "ntlmssp"
    REQUIRED_LAYERS = ("ntlmssp", "http", "smb", "smb2")

    PROTOCOL_COLUMNS: Tuple[str, ...] = ("message", "user", "domain", "detail")

    # BPF filter for live capture optimization
    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize NTLM passive listener."""
        super().__init__(interface, timeout, nxc_logger)

        # Track NTLM sessions by (client_ip, server_ip, stream_id) for challenge
        # correlation. Including the stream id keeps concurrent handshakes on the
        # same client/server pair from overwriting each other's challenge.
        self._sessions: Dict[Tuple[str, str, str], NTLMSession] = {}

        # Extracted hashes
        self.hashes: List[NTLMHash] = []

    @property
    def credentials(self) -> List[NTLMHash]:
        """Expose hashes as credentials for scanner.py credential surfacing."""
        return self.hashes

    # EK mode field name prefix (ntlmssp_ntlmssp_) -> clean name mapping.
    # Maps from the EK-format key (after stripping the ntlmssp_ntlmssp_ prefix)
    # to the dotted name that the rest of this class expects (auth.username etc.).
    _EK_FIELD_MAP = {
        "messagetype": "messagetype",
        "ntlmserverchallenge": "ntlmserverchallenge",
        "auth_username": "auth.username",
        "auth_domain": "auth.domain",
        "auth_hostname": "auth.hostname",
        "auth_ntresponse": "auth.ntresponse",
        "auth_lmresponse": "auth.lmresponse",
        "auth_sesskey": "auth.sesskey",
        "ntlmclientchallenge": "ntlmclientchallenge",
        "ntlmv2_response": "ntlmv2_response",
        "ntlmv2_response_ntproofstr": "ntlmv2_response.ntproofstr",
        "identifier": "identifier",
        "challenge_target_name": "challenge.target_name",
        "challenge_target_info_nb_domain_name": "challenge.target_info.nb_domain_name",
        "challenge_target_info_nb_computer_name": "challenge.target_info.nb_computer_name",
        "challenge_target_info_dns_domain_name": "challenge.target_info.dns_domain_name",
        "challenge_target_info_dns_computer_name": "challenge.target_info.dns_computer_name",
    }

    def _get_ntlmssp_fields(self, packet) -> Dict[str, str]:
        """Extract all ntlmssp.* fields from any layer in the packet.

        NTLMSSP fields may be embedded in SMB, SMB2, HTTP, or other layers.
        In XML mode, fields are in layer._all_fields with "ntlmssp." prefix.
        In EK mode, fields are nested inside _fields_dict under gss-api/spnego
        or directly as "ntlmssp" key, with "ntlmssp_ntlmssp_" prefix.

        Args:
            packet: PyShark packet

        Returns:
            Dict of field names (without ntlmssp. prefix) to values
        """
        result: Dict[str, str] = {}

        for layer in packet.layers:
            try:
                # XML mode: _all_fields with ntlmssp.* keys
                if hasattr(layer, "_all_fields"):
                    for key, value in layer._all_fields.items():
                        if key.startswith("ntlmssp."):
                            field_name = key[8:]  # Remove 'ntlmssp.'
                            result[field_name] = value

                # EK mode: ntlmssp dict nested inside _fields_dict
                if not result and hasattr(layer, "_fields_dict"):
                    ntlm_dict = self._find_ntlmssp_dict(layer._fields_dict)
                    if ntlm_dict:
                        result = self._extract_ek_fields(ntlm_dict)
            except Exception as e:
                self.logger.debug(f"if hasattr(layer, _all_fields):: {e}")

            if result:
                break

        return result

    def _find_ntlmssp_dict(self, d: dict, depth: int = 0) -> Optional[dict]:
        """Recursively find the ntlmssp nested dict in EK mode _fields_dict.

        In EK mode, NTLMSSP fields are nested at various depths:
        - HTTP: _fields_dict["ntlmssp"] = {ntlmssp_ntlmssp_*: ...}
        - SMB2: _fields_dict["gss-api"]["spnego"]["ntlmssp"] = {...}

        For SMB2 Type 3, the spnego dict itself has some ntlmssp_ntlmssp_*
        keys (verf, mechListMIC) but the actual auth fields are one level
        deeper in a nested "ntlmssp" sub-dict.  We always prefer the deepest
        "ntlmssp"-keyed dict that has the messagetype field.
        """
        if depth > 6:
            return None
        if not isinstance(d, dict):
            return None

        # Check for "ntlmssp" key containing a dict -- prefer deepest match
        ntlm = d.get("ntlmssp")
        if isinstance(ntlm, dict):
            # Recurse into the ntlmssp dict itself (it may contain a deeper ntlmssp)
            deeper = self._find_ntlmssp_dict(ntlm, depth + 1)
            if deeper is not None:
                return deeper
            # Otherwise, if this ntlmssp dict has messagetype, use it
            if "ntlmssp_ntlmssp_messagetype" in ntlm:
                return ntlm

        # Recurse into all nested dicts (gss-api, spnego, etc.)
        for key, val in d.items():
            if key == "ntlmssp":
                continue  # Already handled above
            if isinstance(val, dict):
                found = self._find_ntlmssp_dict(val, depth + 1)
                if found is not None:
                    return found

        # Fallback: if this dict itself has messagetype, use it
        if "ntlmssp_ntlmssp_messagetype" in d:
            return d

        return None

    def _extract_ek_fields(self, ntlm_dict: dict) -> Dict[str, str]:
        """Convert EK mode ntlmssp_ntlmssp_* keys to clean field names."""
        result: Dict[str, str] = {}
        prefix = "ntlmssp_ntlmssp_"
        for key, value in ntlm_dict.items():
            if not key.startswith(prefix):
                continue
            short_key = key[len(prefix) :]
            # Map to the dotted field name used by the rest of this class
            mapped = self._EK_FIELD_MAP.get(short_key, short_key)
            result[mapped] = value
        return result

    def process_packet(self, packet) -> None:
        """Process packet and extract NTLM hashes using PyShark."""
        # Get all NTLMSSP fields from any layer
        fields = self._get_ntlmssp_fields(packet)
        if not fields:
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)

        # Get message type.
        # XML mode: hex string "0x00000001", "0x00000002", "0x00000003"
        # EK mode:  decimal string "1", "2", "3"
        msg_type_raw = fields.get("messagetype")
        if msg_type_raw is None:
            return

        try:
            if isinstance(msg_type_raw, str):
                if msg_type_raw.startswith("0x"):
                    msg_type = int(msg_type_raw, 16)
                else:
                    msg_type = int(msg_type_raw)
            else:
                msg_type = int(msg_type_raw)
        except (ValueError, TypeError) as e:
            self.logger.debug(f"if isinstance(msg_type_raw, str):: {e}")
            return

        stream_id = self.get_stream_id(packet)

        # Record interaction
        now = datetime.now().isoformat()
        type_names = {1: "Negotiate", 2: "Challenge", 3: "Authenticate"}
        type_name = type_names.get(msg_type, f"Type{msg_type}")
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request" if msg_type in (1, 3) else "response",
            f"NTLMSSP {type_name}",
            {"msg_type": msg_type},
            f"NTLMSSP {type_name}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        if msg_type == NTLMSSP_TYPE2:
            # Server challenge - store for later correlation
            self._process_type2(src_ip, dst_ip, fields, stream_id)
        elif msg_type == NTLMSSP_TYPE3:
            # Client response - extract hash
            self._process_type3(src_ip, dst_ip, fields, dst_port, stream_id)

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format a single NTLM interaction as a table row.

        Columns: Message, User, Domain, Detail
        """
        d = ix.details

        # Message type name from the operation string ("NTLMSSP Negotiate" etc.)
        message = (
            ix.operation.replace("NTLMSSP ", "")
            if ix.operation.startswith("NTLMSSP ")
            else ix.operation
        )

        username = str(d.get("username", ""))
        domain = str(d.get("domain", ""))

        # Build detail string from available fields
        detail_parts: List[str] = []
        workstation = d.get("workstation")
        if workstation:
            detail_parts.append(f"ws={workstation}")
        flags = d.get("flags")
        if flags:
            detail_parts.append(f"flags={flags}")
        hash_type = d.get("hash_type")
        if hash_type:
            detail_parts.append(hash_type)
        challenge = d.get("challenge")
        if challenge:
            detail_parts.append(f"challenge={challenge}")
        detail = " ".join(str(p) for p in detail_parts)

        return [str(message), username, domain, detail]

    @staticmethod
    def _session_key(client_ip: str, server_ip: str, stream_id: str) -> Tuple[str, str, str]:
        """Build the session-correlation key.

        Keying on the tcp/udp stream id in addition to the IP pair keeps
        concurrent NTLM handshakes between the same client and server (multiple
        SMB2 trees, parallel HTTP, back-to-back logons) from clobbering each
        other's stored server challenge. When the stream id is unavailable
        (non-TCP/UDP or odd captures) it falls back to "" so the key degrades to
        the old IP-pair behaviour rather than dropping the session.
        """
        return (client_ip, server_ip, stream_id or "")

    def _process_type2(
        self, src_ip: str, dst_ip: str, fields: Dict[str, str], stream_id: str = ""
    ) -> None:
        """Process NTLM Type 2 (Challenge) message.

        Extract and store the 8-byte challenge for later correlation.
        """
        # Server sends Type 2, so src_ip is server, dst_ip is client
        server_ip = src_ip
        client_ip = dst_ip

        # Extract challenge from field: ntlmssp.ntlmserverchallenge
        challenge_raw = fields.get("ntlmserverchallenge")
        if not challenge_raw:
            return

        # PyShark returns bytes as colon-separated hex like "88:bc:9b:58:34:be:37:0d"
        challenge_hex = self._normalize_hex(challenge_raw)
        if not challenge_hex:
            return

        # Store in session (keyed per stream so concurrent handshakes don't collide)
        session_key = self._session_key(client_ip, server_ip, stream_id)
        self._sessions[session_key] = NTLMSession(
            client_ip=client_ip,
            server_ip=server_ip,
            challenge=challenge_hex,
            state="got_challenge",
        )

        self.logger.debug(f"NTLM Type 2: Challenge from {server_ip}: {challenge_hex}")

    def _process_type3(
        self,
        src_ip: str,
        dst_ip: str,
        fields: Dict[str, str],
        server_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Process NTLM Type 3 (Authenticate) message.

        Extract LM/NT hashes, domain, username, and workstation.
        """
        # Client sends Type 3, so src_ip is client, dst_ip is server
        client_ip = src_ip
        server_ip = dst_ip

        # Get challenge from the session for THIS stream. Keying on the stream id
        # ensures the Type 3 is paired with the challenge from its own handshake
        # rather than the most recent Type 2 on the client/server pair.
        session_key = self._session_key(client_ip, server_ip, stream_id)
        session = self._sessions.get(session_key)

        challenge = ""
        if session and session.challenge:
            challenge = session.challenge
        else:
            self.logger.warning(
                f"NTLM Type 3 from {client_ip} -> {server_ip}: "
                "missing server challenge (Type 2 not in capture) — hash is UNCRACKABLE"
            )

        try:
            # Extract fields from ntlmssp
            # Fields: auth.username, auth.domain, auth.hostname
            username = fields.get("auth.username", "") or ""
            domain = fields.get("auth.domain", "") or ""
            workstation = fields.get("auth.hostname", "") or ""

            # Extract hash responses
            # Fields: auth.ntresponse, auth.lmresponse
            nt_response_raw = fields.get("auth.ntresponse", "")
            lm_response_raw = fields.get("auth.lmresponse", "")

            nt_hash = self._normalize_hex(nt_response_raw)
            lm_hash = self._normalize_hex(lm_response_raw)

            if not username:
                return

            # Skip anonymous/null authentication
            if username.upper() in ("NULL", ""):
                return

            # Determine NTLM version based on NT hash length
            # NTLMv1: NT hash = 24 bytes (48 hex chars)
            # NTLMv2: NT hash > 24 bytes
            hash_type = "NTLM"
            if nt_hash:
                nt_len = len(nt_hash) // 2  # Convert hex chars to bytes
                if nt_len == 24:
                    hash_type = "NTLMv1"
                elif nt_len > 24:
                    hash_type = "NTLMv2"

            # Check for duplicate
            if self._is_duplicate_hash(username, domain, challenge, nt_hash):
                return

            ntlm_hash = NTLMHash(
                hash_type=hash_type,
                username=username,
                domain=domain,
                workstation=workstation,
                challenge=challenge,
                lm_hash=lm_hash,
                nt_hash=nt_hash,
                server_ip=server_ip,
                server_port=server_port,
                client_ip=client_ip,
                timestamp=datetime.now().isoformat(),
            )
            self._record_hash(ntlm_hash)

            # Mark session complete
            if session:
                session.state = "complete"

        except Exception as e:
            self.logger.debug(f"NTLM Type 3 parse error: {e}")

    def _normalize_hex(self, value) -> str:
        """Normalize hex value from PyShark to plain hex string.

        PyShark may return:
        - Plain hex string: "88bc9b5834be370d"
        - Colon-separated: "88:bc:9b:58:34:be:37:0d"
        - None or empty

        Returns:
            Lowercase hex string without separators
        """
        if not value:
            return ""

        # Convert to string if needed
        val_str = str(value)

        # Remove colons and spaces
        val_str = val_str.replace(":", "").replace(" ", "").lower()

        # Validate hex
        try:
            int(val_str, 16)
            return val_str
        except ValueError as e:
            self.logger.debug(f"NTLM: hex validation of normalized hash value failed: {e}")
            return ""

    def _is_duplicate_hash(self, username: str, domain: str, challenge: str, nt_hash: str) -> bool:
        """Check if hash is already recorded."""
        for h in self.hashes:
            if (
                h.username == username
                and h.domain == domain
                and h.challenge == challenge
                and h.nt_hash == nt_hash
            ):
                return True
        return False

    def _record_hash(self, ntlm_hash: NTLMHash) -> None:
        """Record extracted NTLM hash."""
        self.hashes.append(ntlm_hash)

        self.logger.info(
            f"NTLM {ntlm_hash.hash_type}: {ntlm_hash.domain}\\{ntlm_hash.username} "
            f"from {ntlm_hash.client_ip} -> {ntlm_hash.server_ip}:{ntlm_hash.server_port}"
        )

        # Update device entries
        self._update_devices(ntlm_hash)

    def _update_devices(self, ntlm_hash: NTLMHash) -> None:
        """Update device entries with hash information."""
        server_ip = ntlm_hash.server_ip
        client_ip = ntlm_hash.client_ip

        if not is_valid_discovered_ip(server_ip):
            return

        server_key = f"ntlm-server:{server_ip}"
        client_key = f"ntlm-client:{client_ip}"

        hash_entry = {
            "hash_type": ntlm_hash.hash_type,
            "username": ntlm_hash.username,
            "domain": ntlm_hash.domain,
            "workstation": ntlm_hash.workstation,
            "timestamp": ntlm_hash.timestamp,
        }

        # Server device
        device, is_new = self._ensure_device(
            server_key,
            server_ip,
            name=f"NTLM Server ({ntlm_hash.domain})",
            device_type="Windows Server",
        )
        if is_new:
            device.ntlm_passive_data = {
                "role": "server",
                "domain": ntlm_hash.domain,
                "hashes": [hash_entry],
                "protocol": "NTLMSSP/TCP",
            }
        else:
            if device.ntlm_passive_data:
                device.ntlm_passive_data.setdefault("hashes", []).append(hash_entry)
        # Client device
        if is_valid_discovered_ip(client_ip):
            device, is_new = self._ensure_device(
                client_key,
                client_ip,
                name=ntlm_hash.workstation or f"NTLM Client ({client_ip})",
                device_type="Windows Client",
            )
            if is_new:
                device.ntlm_passive_data = {
                    "role": "client",
                    "domain": ntlm_hash.domain,
                    "username": ntlm_hash.username,
                    "workstation": ntlm_hash.workstation,
                    "protocol": "NTLMSSP/TCP",
                }
            else:
                if ntlm_hash.workstation and device.name.startswith("NTLM Client"):
                    device.name = ntlm_hash.workstation

    def get_hashes_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted hashes.

        Returns list of dicts with keys expected by base class harvest():
        protocol, hash_type, username, domain, server_ip, client_ip,
        hashcat_format.
        """
        result = []
        hashcat_lines = self.get_hashcat_hashes()
        hashcat_idx = 0
        for h in self.hashes:
            incomplete = not h.challenge
            if not incomplete:
                hashcat_str = hashcat_lines[hashcat_idx] if hashcat_idx < len(hashcat_lines) else ""
                hashcat_idx += 1
            else:
                hashcat_str = "[!] INCOMPLETE — missing server challenge (Type 2 not captured)"
            entry: Dict[str, Any] = {
                "protocol": "NTLMSSP",
                "hash_type": h.hash_type + (" [!]" if incomplete else ""),
                "username": h.username,
                "domain": h.domain,
                "workstation": h.workstation,
                "challenge": h.challenge or "(missing)",
                "lm_hash": h.lm_hash,
                "nt_hash": h.nt_hash,
                "server_ip": h.server_ip,
                "client_ip": h.client_ip,
                "timestamp": h.timestamp,
                "credential_type": "hash",
                "hash_value": h.nt_hash or "",
                "hashcat_format": hashcat_str,
            }
            result.append(entry)
        return result

    def get_hashcat_hashes(self) -> List[str]:
        """Get hashes in hashcat-compatible format.

        Only returns hashes with a valid server challenge.
        Hashes missing the challenge (Type 2 not captured) are skipped.

        NTLMv1 (hashcat mode 5500):
            username::domain:lm_response:nt_response:challenge

        NTLMv2 (hashcat mode 5600):
            username::domain:challenge:nt_response[:lm_response]
        """
        result = []
        for h in self.hashes:
            if not h.challenge:
                continue  # Skip — server challenge missing, hash is uncrackable
            if h.hash_type == "NTLMv1":
                # Format: user::domain:lm:nt:challenge
                result.append(f"{h.username}::{h.domain}:{h.lm_hash}:{h.nt_hash}:{h.challenge}")
            elif h.hash_type == "NTLMv2":
                # Format: user::domain:challenge:nt (nt contains blob)
                # NTLMv2 hash = first 32 hex chars, blob = rest
                if len(h.nt_hash) >= 32:
                    nt_proof = h.nt_hash[:32]
                    blob = h.nt_hash[32:]
                    result.append(f"{h.username}::{h.domain}:{h.challenge}:{nt_proof}:{blob}")
        return result

    def get_john_hashes(self) -> List[str]:
        """Get hashes in John the Ripper format.

        NTLMv1:
            user:$NETLM$challenge$lm_response
            user:$NETNTLM$challenge$nt_response

        NTLMv2:
            user:$NETNTLMv2$domain$challenge$nt_response
        """
        result = []
        for h in self.hashes:
            if h.hash_type == "NTLMv1":
                if h.lm_hash:
                    result.append(f"{h.username}:$NETLM${h.challenge}${h.lm_hash}")
                result.append(f"{h.username}:$NETNTLM${h.challenge}${h.nt_hash}")
            elif h.hash_type == "NTLMv2":
                result.append(f"{h.username}:$NETNTLMv2${h.domain}${h.challenge}${h.nt_hash}")
        return result
