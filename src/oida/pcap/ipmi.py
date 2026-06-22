"""
IPMI Passive Listener for BMC discovery and credential extraction.

Passively captures IPMI/RMCP traffic to extract:
- IPMI session authentication types
- RMCP+ payload types (Open Session, RAKP messages)
- RAKP usernames and HMAC hashes (crackable)
- BMC session details and privilege levels

Security value:
- BMC discovery on the network
- RAKP hash extraction for offline cracking
- Cipher-zero detection (unauthenticated access)
- Authentication type enumeration

tshark fields used:
- ipmi_session.authtype: Authentication type (0=none, 1=MD2, 2=MD5, 4=password, 5=OEM, 6=RMCP+)
- ipmi_session.id: Session ID
- ipmi_session.payloadtype: RMCP+ payload type
- rmcp.class: RMCP message class (0x07 = IPMI)
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# IPMI Authentication types
AUTH_TYPES = {
    "0x00": "None",
    "0x01": "MD2",
    "0x02": "MD5",
    "0x04": "Straight Password",
    "0x05": "OEM Proprietary",
    "0x06": "RMCP+",
    "0": "None",
    "1": "MD2",
    "2": "MD5",
    "4": "Straight Password",
    "5": "OEM Proprietary",
    "6": "RMCP+",
}

# RMCP+ Payload types
PAYLOAD_TYPES = {
    "0x00": "IPMI Message",
    "0x01": "SOL (Serial over LAN)",
    "0x02": "OEM Explicit",
    "0x10": "Open Session Request",
    "0x11": "Open Session Response",
    "0x12": "RAKP Message 1",
    "0x13": "RAKP Message 2",
    "0x14": "RAKP Message 3",
    "0x15": "RAKP Message 4",
    "16": "Open Session Request",
    "17": "Open Session Response",
    "18": "RAKP Message 1",
    "19": "RAKP Message 2",
    "20": "RAKP Message 3",
    "21": "RAKP Message 4",
}


@dataclass
class IPMICredential:
    """Extracted IPMI credential or hash."""

    username: str
    credential_type: str  # "rakp_hash", "auth_none", "cipher_zero"
    source_ip: str
    dest_ip: str
    dest_port: int = 623
    auth_type: str = ""
    timestamp: str = ""
    rakp_hash: str = ""  # RAKP-2 key-exchange auth code (crackable HMAC), hex

    @property
    def server_ip(self) -> str:
        """BMC is typically the destination."""
        return self.dest_ip

    @property
    def client_ip(self) -> str:
        """Client is the source."""
        return self.source_ip

    @property
    def auth_method(self) -> str:
        """Scanner credential loop compatibility (scanner.py getattr chain).

        The scanner reads ``cred.auth_method`` directly off the credential
        object; expose the descriptive auth type string here so the method
        column is populated without a fallback chain.
        """
        return self.auth_type or self.credential_type

    @property
    def server_port(self) -> int:
        """Scanner credential loop compatibility (server port for display)."""
        return self.dest_port

    @property
    def hash_value(self) -> str:
        """Canonical credential field: the RAKP-2 HMAC for hash-type creds.

        The scanner credential loop reads ``cred.hash_value`` directly; expose
        the crackable RAKP HMAC here so RAKP creds surface in the hash column
        without a fallback chain.
        """
        return self.rakp_hash


class IPMIPassiveListener(PySharkListenerBase):
    """Passive IPMI traffic listener for BMC discovery and credential extraction.

    Captures IPMI/RMCP traffic to identify:
    - BMC (Baseboard Management Controller) endpoints
    - Authentication types in use
    - RAKP handshakes with extractable hashes
    - Cipher-zero (unauthenticated) sessions

    Usage:
        listener = IPMIPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for cred in listener.credentials:
            print(f"IPMI {cred.credential_type}: {cred.username} @ {cred.dest_ip}")
    """

    PROTOCOL_NAME = "ipmi"
    DISPLAY_FILTER = "ipmi_session || rmcp"
    REQUIRED_LAYERS = ("ipmi_session", "rmcp")
    SERVER_PORTS = (623,)
    PROTOCOL_COLUMNS = ("auth_type", "payload_type", "session_id", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.credentials: List[IPMICredential] = []
        self._seen_creds: set = set()
        # Track BMC details
        self.bmc_info: Dict[str, Dict[str, Any]] = {}
        # RAKP-1 (client -> BMC) carries the username; RAKP-2 (BMC -> client)
        # carries the crackable HMAC. They are separate packets, so stash the
        # RAKP-1 username keyed by the BMC IP and pair it when RAKP-2 arrives.
        self._rakp_users: Dict[str, str] = {}

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format IPMI interaction as protocol-specific table columns."""
        d = ix.details
        return [
            d.get("auth_type_name", d.get("auth_type", "?")),
            d.get("payload_type_name", ""),
            d.get("session_id", "?"),
            d.get("detail", ""),
        ]

    def process_packet(self, packet) -> None:
        """Process IPMI/RMCP packet and extract session information."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        # Extract IPMI session fields
        auth_type = ""
        auth_type_name = ""
        session_id = ""
        payload_type = ""
        payload_type_name = ""
        detail = ""

        if hasattr(packet, "ipmi_session"):
            ipmi = packet.ipmi_session
            auth_type = str(self.get_field(ipmi, "authtype", "") or "")
            auth_type_name = AUTH_TYPES.get(auth_type, auth_type)
            session_id = str(self.get_field(ipmi, "id", "") or "")
            payload_type = str(self.get_field(ipmi, "payloadtype", "") or "")
            payload_type_name = PAYLOAD_TYPES.get(payload_type, payload_type)

        # Determine direction via the shared cascade.  RMCP+ payload types carry
        # a clean request/response signal: Open Session / RAKP odd-numbered
        # messages (1,3) are client -> BMC requests, the even responses
        # (Open Session Response, RAKP 2,4) are BMC -> client.  We feed that as
        # the authoritative native tier.  When the payload type is unknown
        # (plain IPMI message / SOL), native=None falls through to the
        # known-server-port tier (canonical 623 plus any user --decode-as /
        # OVERRIDE_PREFS override) and then the lower-port heuristic.
        native: Optional[bool] = None
        if payload_type_name:
            if (
                "Response" in payload_type_name
                or "RAKP Message 2" in payload_type_name
                or "RAKP Message 4" in payload_type_name
            ):
                native = False
            elif (
                "Request" in payload_type_name
                or "RAKP Message 1" in payload_type_name
                or "RAKP Message 3" in payload_type_name
            ):
                native = True
        d = self.resolve_direction(
            packet,
            native=native,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flow_id=flow_id,
        )
        is_to_bmc = d.is_request
        direction = "request" if is_to_bmc else "response"

        # Build operation
        if payload_type_name:
            operation = f"IPMI {payload_type_name}"
        elif auth_type_name:
            operation = f"IPMI Session (auth={auth_type_name})"
        else:
            operation = "IPMI/RMCP"

        # Detect cipher-zero (auth type None with active session). The session
        # id must be compared numerically: in EK mode get_field() returns it as
        # a decimal string ("0"), while XML mode yields "0x00000000". Both
        # render a not-yet-established session (Open Session / RAKP setup) that
        # must NOT be flagged. _parse_int normalizes both forms.
        if auth_type in ("0x00", "0") and self._parse_int(session_id, 0) != 0:
            detail = "[!] Cipher-zero (no auth)"
            self.logger.warning(
                f"IPMI cipher-zero detected: {src_ip} -> {dst_ip} session={session_id}"
            )
            self._record_credential(
                username="",
                credential_type="cipher_zero",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dest_port=dst_port,
                auth_type="None (cipher-zero)",
            )

        # Track RAKP messages (authentication handshake)
        if "RAKP" in payload_type_name:
            detail = payload_type_name
            if "Message 1" in payload_type_name:
                detail = "RAKP-1 (username + random)"
                # RAKP-1 (client -> BMC) carries the username being authenticated.
                # The BMC is the destination; stash the username under it so the
                # RAKP-2 response from that BMC can be paired with it.
                username = self._parse_rakp1_username(packet)
                if username:
                    self._rakp_users[dst_ip] = username
            elif "Message 2" in payload_type_name:
                detail = "RAKP-2 (HMAC hash)"
                # RAKP-2 (BMC -> client) carries the crackable key-exchange auth
                # code (HMAC). The BMC is the source; recover the username seen in
                # the matching RAKP-1 (may be absent if RAKP-1 was not captured).
                rakp_hash = self._parse_rakp2_hash(packet)
                if rakp_hash:
                    username = self._rakp_users.get(src_ip, "")
                    self.logger.info(
                        f"IPMI RAKP-2 hash from BMC {src_ip} -> {dst_ip} "
                        f"user={username or '(unknown)'}"
                    )
                    self._record_credential(
                        username=username,
                        credential_type="rakp_hash",
                        src_ip=dst_ip,
                        dst_ip=src_ip,
                        dest_port=src_port if src_port else 623,
                        auth_type="RMCP+ RAKP",
                        rakp_hash=rakp_hash,
                    )
                else:
                    self.logger.info(
                        f"IPMI RAKP-2 from BMC {src_ip} -> {dst_ip} (no parseable HMAC in payload)"
                    )
            elif "Message 3" in payload_type_name:
                detail = "RAKP-3 (client proof)"
            elif "Message 4" in payload_type_name:
                detail = "RAKP-4 (server proof)"

        if "Open Session" in payload_type_name:
            detail = payload_type_name

        # Build details
        details: Dict[str, Any] = {
            "auth_type": auth_type,
            "auth_type_name": auth_type_name,
            "session_id": session_id,
            "payload_type": payload_type,
            "payload_type_name": payload_type_name,
            "detail": detail,
        }

        now = datetime.now().isoformat()
        summary = f"IPMI {auth_type_name or '?'} {src_ip} -> {dst_ip}"
        if payload_type_name:
            summary += f" ({payload_type_name})"

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

        # Track BMC device
        bmc_ip = dst_ip if is_to_bmc else src_ip
        client_ip = src_ip if is_to_bmc else dst_ip
        bmc_mac = dst_mac if is_to_bmc else src_mac
        client_mac = src_mac if is_to_bmc else dst_mac

        if is_valid_discovered_ip(bmc_ip):
            vendor = lookup_mac_vendor(bmc_mac) if bmc_mac else ""
            self._ensure_device(
                f"ipmi-bmc:{bmc_ip}",
                bmc_ip,
                mac=bmc_mac or "",
                device_type="IPMI BMC",
                manufacturer=vendor if vendor != "Unknown" else "",
                data_attr="ipmi_passive_data",
                protocol_data={
                    "role": "bmc",
                    "auth_types": [auth_type_name] if auth_type_name else [],
                    "protocol": "IPMI/UDP",
                },
            )
            # Update BMC info
            if bmc_ip not in self.bmc_info:
                self.bmc_info[bmc_ip] = {
                    "auth_types": set(),
                    "sessions_seen": 0,
                    "first_seen": now,
                }
            self.bmc_info[bmc_ip]["auth_types"].add(auth_type_name or "unknown")
            self.bmc_info[bmc_ip]["sessions_seen"] += 1
            self.bmc_info[bmc_ip]["last_seen"] = now

        if is_valid_discovered_ip(client_ip):
            client_vendor = lookup_mac_vendor(client_mac) if client_mac else ""
            self._ensure_device(
                f"ipmi-client:{client_ip}",
                client_ip,
                mac=client_mac or "",
                device_type="IPMI Client",
                manufacturer=client_vendor if client_vendor != "Unknown" else "",
                data_attr="ipmi_passive_data",
                protocol_data={
                    "role": "client",
                    "protocol": "IPMI/UDP",
                },
            )

    @staticmethod
    def _rakp_payload_bytes(packet) -> bytes:
        """Return the raw RMCP+ payload (RAKP body) bytes for a packet.

        tshark's IPMI dissector does not decode the RAKP message body, so the
        username (RAKP-1) and HMAC (RAKP-2) are only available as the raw
        ``data`` layer that follows the session wrapper.
        """
        raw = None
        if hasattr(packet, "data"):
            raw = getattr(packet.data, "data", None)
        if not raw:
            return b""
        try:
            return bytes.fromhex(str(raw).replace(":", "").replace(" ", ""))
        except ValueError:
            return b""

    def _parse_rakp1_username(self, packet) -> str:
        """Extract the username from a RAKP Message 1 body.

        RAKP-1 layout (IPMI 2.0, after the session wrapper):
            [0]    message tag
            [1:4]  reserved
            [4:8]  managed system session ID
            [8:24] remote console random number (16 bytes)
            [24]   requested maximum privilege level
            [25:27] reserved
            [27]   username length (N)
            [28:28+N] username
        """
        body = self._rakp_payload_bytes(packet)
        if len(body) < 28:
            return ""
        ulen = body[27]
        if ulen == 0 or len(body) < 28 + ulen:
            return ""
        try:
            return body[28 : 28 + ulen].decode("latin1").strip("\x00")
        except Exception:
            return ""

    def _parse_rakp2_hash(self, packet) -> str:
        """Extract the key-exchange auth code (crackable HMAC) from RAKP-2.

        RAKP-2 layout (IPMI 2.0, after the session wrapper):
            [0]     message tag
            [1:4]   reserved
            [4:8]   remote console session ID
            [8:24]  managed system (BMC) random number (16 bytes)
            [24:40] managed system (BMC) GUID (16 bytes)
            [40:]   key exchange authentication code (HMAC, 0/12/16/20/32 bytes)
        """
        body = self._rakp_payload_bytes(packet)
        if len(body) <= 40:
            return ""
        return body[40:].hex()

    def _record_credential(
        self,
        username: str,
        credential_type: str,
        src_ip: str,
        dst_ip: str,
        dest_port: int = 623,
        auth_type: str = "",
        rakp_hash: str = "",
    ) -> None:
        """Record an extracted IPMI credential."""
        cred_key = (username, credential_type, src_ip, dst_ip)
        if cred_key in self._seen_creds:
            return
        self._seen_creds.add(cred_key)

        cred = IPMICredential(
            username=username,
            credential_type=credential_type,
            source_ip=src_ip,
            dest_ip=dst_ip,
            dest_port=dest_port,
            auth_type=auth_type,
            timestamp=datetime.now().isoformat(),
            rakp_hash=rakp_hash,
        )
        self.credentials.append(cred)

        self.logger.info(
            f"IPMI credential: {credential_type} "
            f"user={username or '(none)'} ({src_ip} -> {dst_ip}:{dest_port})"
        )

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials."""
        return [
            {
                "protocol": "IPMI",
                "credential_type": cred.credential_type,
                "username": cred.username,
                "auth_type": cred.auth_type,
                "server_ip": cred.dest_ip,
                "client_ip": cred.source_ip,
                "server_port": cred.dest_port,
                "rakp_hash": cred.rakp_hash,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]
