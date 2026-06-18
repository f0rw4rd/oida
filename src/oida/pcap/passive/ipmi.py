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
from ...protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

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

# IPMI privilege levels
PRIVILEGE_LEVELS = {
    "0": "Reserved",
    "1": "Callback",
    "2": "User",
    "3": "Operator",
    "4": "Administrator",
    "5": "OEM Proprietary",
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

    @property
    def server_ip(self) -> str:
        """BMC is typically the destination."""
        return self.dest_ip

    @property
    def client_ip(self) -> str:
        """Client is the source."""
        return self.source_ip


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

        # Determine direction: port 623 is the BMC
        is_to_bmc = dst_port == 623
        direction = "request" if is_to_bmc else "response"

        # Build operation
        if payload_type_name:
            operation = f"IPMI {payload_type_name}"
        elif auth_type_name:
            operation = f"IPMI Session (auth={auth_type_name})"
        else:
            operation = "IPMI/RMCP"

        # Detect cipher-zero (auth type None with active session)
        if auth_type in ("0x00", "0") and session_id and session_id != "0x00000000":
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
            elif "Message 2" in payload_type_name:
                detail = "RAKP-2 (HMAC hash)"
                # RAKP Message 2 contains the crackable hash
                self.logger.info(f"IPMI RAKP-2 hash from BMC {src_ip} -> {dst_ip}")
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

    def _record_credential(
        self,
        username: str,
        credential_type: str,
        src_ip: str,
        dst_ip: str,
        dest_port: int = 623,
        auth_type: str = "",
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
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]
