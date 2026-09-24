"""
PAP (Password Authentication Protocol) Passive Listener for credential extraction.

Passively captures PPP/PAP traffic to extract:
- Peer ID (username) from Authenticate-Request
- Password from Authenticate-Request
- Identifier for request/reply matching
- Authentication results (Ack/Nak) from responses

PAP transmits credentials in cleartext over PPP links.

tshark fields:
- pap.code: Packet type (1=Auth-Request, 2=Auth-Ack, 3=Auth-Nak)
- pap.identifier: Transaction ID for matching requests and replies
- pap.peer_id: Username / Peer ID
- pap.peer_id.length: Length of the Peer ID field
- pap.password: Password
- pap.password.length: Length of the Password field
- pap.length: Total PAP packet length
- pap.message: Response message (in Ack/Nak packets)

References:
- RFC 1334: PPP Authentication Protocols (PAP)
- Wireshark dissector: packet-pap.c
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase

# PAP code values (RFC 1334 Section 2.2)
PAP_CODE_AUTH_REQUEST = "1"
PAP_CODE_AUTH_ACK = "2"
PAP_CODE_AUTH_NAK = "3"

PAP_CODE_NAMES = {
    PAP_CODE_AUTH_REQUEST: "Authenticate-Request",
    PAP_CODE_AUTH_ACK: "Authenticate-Ack",
    PAP_CODE_AUTH_NAK: "Authenticate-Nak",
}


@dataclass
class PAPCredential:
    """Extracted PAP credential."""

    username: str
    password: str = ""
    credential_type: str = "plaintext"
    server_ip: str = ""
    client_ip: str = ""
    timestamp: str = ""
    identifier: str = ""
    password_length: str = ""

    @property
    def auth_method(self) -> str:
        """Scanner credential loop compatibility."""
        return "PAP"


class PAPPassiveListener(PySharkListenerBase):
    """Passive PAP traffic listener for credential extraction.

    Captures PPP/PAP authentication traffic to extract usernames
    and passwords. PAP is inherently insecure as it transmits
    credentials in plaintext.
    """

    PROTOCOL_NAME = "pap"
    DISPLAY_FILTER = "pap"
    REQUIRED_LAYERS = ("pap",)
    PROTOCOL_COLUMNS = ("code", "id", "user", "password_len", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.credentials: List[PAPCredential] = []

    def process_packet(self, packet) -> None:
        """Process PAP packet and extract credentials."""
        if not hasattr(packet, "pap"):
            return

        pap = packet.pap
        src_ip, dst_ip = self.get_ip_info(packet)
        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        # PAP is layer 2 so IPs may not be available
        if not src_ip:
            src_ip = "unknown"
        if not dst_ip:
            dst_ip = "unknown"

        # --- Extract all available fields ---
        code = str(self.get_field(pap, "code", "") or "").strip()
        if not code:
            code = "?"
            self.logger.debug(f"Missing pap.code field in packet from {src_ip} -> {dst_ip}")

        identifier = str(self.get_field(pap, "identifier", "") or "").strip()
        if not identifier:
            identifier = "?"
            self.logger.debug(f"Missing pap.identifier field in packet from {src_ip} -> {dst_ip}")

        pap_length = str(self.get_field(pap, "length", "") or "").strip()

        username = str(self.get_field(pap, "peer_id", "") or "").strip()
        password = str(self.get_field(pap, "password", "") or "").strip()
        peer_id_length = str(self.get_field(pap, "peer_id_length", "") or "").strip()
        password_length = str(self.get_field(pap, "password_length", "") or "").strip()
        message = str(self.get_field(pap, "message", "") or "").strip()

        code_name = PAP_CODE_NAMES.get(code, f"Unknown({code})")

        # Determine direction from code
        if code == PAP_CODE_AUTH_REQUEST:
            direction = "request"
        else:
            direction = "response"

        # Build interaction details with all extracted fields
        details: Dict[str, Any] = {
            "code": code,
            "code_name": code_name,
            "identifier": identifier,
        }
        if username:
            details["username"] = username
        if password_length:
            details["password_length"] = password_length
        if peer_id_length:
            details["peer_id_length"] = peer_id_length
        if pap_length:
            details["pap_length"] = pap_length
        if message:
            details["message"] = message

        # Build summary
        if code == PAP_CODE_AUTH_REQUEST:
            summary = f"PAP Auth-Request id={identifier}"
            if username:
                summary += f" user={username}"
            operation = "PAP Auth-Request"
        elif code == PAP_CODE_AUTH_ACK:
            summary = f"PAP Auth-Ack id={identifier}"
            if message:
                summary += f" msg={message}"
            operation = "PAP Auth-Ack"
        elif code == PAP_CODE_AUTH_NAK:
            summary = f"PAP Auth-Nak id={identifier}"
            if message:
                summary += f" msg={message}"
            operation = "PAP Auth-Nak"
        else:
            summary = f"PAP Unknown code={code} id={identifier}"
            operation = f"PAP Code {code}"

        # Record interaction for every packet type
        now = datetime.now().isoformat()
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
        )

        # Only extract credentials from Auth-Request packets
        if code != PAP_CODE_AUTH_REQUEST:
            # For Ack/Nak packets, still update devices but skip credential extraction
            if code in (PAP_CODE_AUTH_ACK, PAP_CODE_AUTH_NAK):
                self._update_devices(dst_ip, src_ip)
            return

        if not username and not password:
            return

        if not self._is_duplicate(username, password, src_ip, dst_ip):
            cred = PAPCredential(
                username=username,
                password=password,
                credential_type="plaintext" if password else "username_only",
                server_ip=dst_ip,
                client_ip=src_ip,
                timestamp=now,
                identifier=identifier,
                password_length=password_length,
            )
            self.credentials.append(cred)
            self._update_devices(src_ip, dst_ip)

            if password:
                self.logger.info(f"PAP: {username}:{password}")
            else:
                self.logger.info(f"PAP: username={username}")

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

    def _update_devices(self, client_ip: str, server_ip: str) -> None:
        """Update device entries for both endpoints."""
        if server_ip and server_ip != "unknown":
            self._ensure_device(
                f"pap-server:{server_ip}",
                server_ip,
                name=f"PAP Authenticator ({server_ip})",
                device_type="PPP Authenticator",
                data_attr="pap_passive_data",
                protocol_data={"role": "authenticator", "protocol": "PAP/PPP"},
            )
        if client_ip and client_ip != "unknown":
            self._ensure_device(
                f"pap-client:{client_ip}",
                client_ip,
                name=f"PAP Peer ({client_ip})",
                device_type="PPP Peer",
                data_attr="pap_passive_data",
                protocol_data={"role": "peer", "protocol": "PAP/PPP"},
            )

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format interaction for the operations table."""
        d = ix.details
        code_name = d.get("code_name", "?")
        identifier = d.get("identifier", "?")
        username = d.get("username", "")
        password_length = d.get("password_length", "")

        # Build detail column
        detail_parts = []
        if d.get("message"):
            detail_parts.append(f"msg={d['message']}")
        if d.get("peer_id_length"):
            detail_parts.append(f"pid_len={d['peer_id_length']}")
        if d.get("pap_length"):
            detail_parts.append(f"pkt_len={d['pap_length']}")
        detail = ", ".join(detail_parts) if detail_parts else ""

        return [
            code_name,
            identifier,
            username,
            password_length,
            detail,
        ]

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials."""
        return [
            {
                "protocol": "PAP",
                "credential_type": cred.credential_type,
                "auth_method": "PAP",
                "username": cred.username,
                "password": cred.password,
                "server_ip": cred.server_ip,
                "client_ip": cred.client_ip,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]
