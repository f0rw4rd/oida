"""
RDP Passive Listener for credential extraction.

Passively captures RDP traffic to extract:
- Usernames from RDP connection requests
- Passwords from RDSTLS authentication (when visible)

RDP normally uses TLS/NLA encryption, but RDSTLS and some legacy
configurations may expose credentials in cleartext.

tshark fields:
- rdp.userName: Username in RDP connection request
- rdp.password: Password field (rarely visible)
- rdp.rdstls.username: RDSTLS username
- rdp.rdstls.password: RDSTLS password

References:
- MS-RDPBCGR: Remote Desktop Protocol
- Wireshark dissector: packet-rdp.c
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip


@dataclass
class RDPCredential:
    """Extracted RDP credential."""

    username: str
    password: str = ""
    credential_type: str = "plaintext"
    source: str = ""  # "rdp" or "rdstls"
    server_ip: str = ""
    server_port: int = 0
    client_ip: str = ""
    timestamp: str = ""

    @property
    def auth_method(self) -> str:
        """Scanner credential loop compatibility."""
        return f"RDP-{self.source.upper()}" if self.source else "RDP"


class RDPPassiveListener(PySharkListenerBase):
    """Passive RDP traffic listener for credential extraction.

    Captures RDP traffic to extract usernames and passwords
    from connection requests and RDSTLS authentication.
    """

    PROTOCOL_NAME = "rdp"
    DISPLAY_FILTER = "rdp"
    REQUIRED_LAYERS = ("rdp",)
    PROTOCOL_COLUMNS = ("source", "username", "password")
    SERVER_PORTS = frozenset({3389})

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.credentials: List[RDPCredential] = []

    def process_packet(self, packet) -> None:
        """Process RDP packet and extract credentials."""
        if not hasattr(packet, "rdp"):
            return

        rdp = packet.rdp
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)

        # Try standard RDP fields
        username = str(self.get_field(rdp, "userName", "") or "").strip()
        password = str(self.get_field(rdp, "password", "") or "").strip()
        source = "rdp"

        # Try RDSTLS fields
        rdstls_user = str(self.get_field(rdp, "rdstls_username", "") or "").strip()
        rdstls_pass = str(self.get_field(rdp, "rdstls_password", "") or "").strip()

        if rdstls_user:
            username = rdstls_user
            source = "rdstls"
        if rdstls_pass:
            password = rdstls_pass
            source = "rdstls"

        if not username and not password:
            # No credential fields, but still record the RDP interaction.
            # Common case: connection request with only an rt_cookie field.
            cookie = str(self.get_field(rdp, "rt_cookie", "") or "").strip()
            cookie_user = ""
            if cookie:
                # Extract username from "Cookie: mstshash=<user>"
                if "mstshash=" in cookie:
                    cookie_user = cookie.split("mstshash=", 1)[1].strip()
                detail = cookie
            else:
                detail = "RDP handshake"

            now = datetime.now().isoformat()
            # No native request/response field here, so fall through to the
            # known-server-port (3389) / lower-port heuristic instead of
            # hardcoding "request" -- a server-originated PDU (negotiation
            # response, licensing) would otherwise be mislabelled client->server.
            d = self.resolve_direction(
                packet,
                native=None,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                flow_id=flow_id,
            )
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                d.direction,
                "RDP Connection",
                {
                    "username": cookie_user,
                    "password": "",
                    "source": "cookie" if cookie else "handshake",
                    "cookie": cookie,
                },
                f"RDP Connection {detail} {src_ip} -> {dst_ip}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )
            return

        # Record interaction
        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            f"RDP {source}",
            {"username": username, "password": password, "source": source},
            f"RDP {source} user={username} {src_ip} -> {dst_ip}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        if not self._is_duplicate(username, password, src_ip, dst_ip):
            cred = RDPCredential(
                username=username,
                password=password,
                credential_type="plaintext" if password else "username_only",
                source=source,
                server_ip=dst_ip,
                server_port=dst_port,
                client_ip=src_ip,
                timestamp=datetime.now().isoformat(),
            )
            self.credentials.append(cred)
            self._update_devices(src_ip, dst_ip)

            if password:
                self.logger.info(f"RDP: {username}:{password} @ {dst_ip}:{dst_port} ({source})")
            else:
                self.logger.info(f"RDP: username={username} @ {dst_ip}:{dst_port} ({source})")

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format RDP protocol-specific columns."""
        d = ix.details
        return [
            d.get("source", "rdp"),
            d.get("username", ""),
            d.get("password", ""),
        ]

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
        """Update device entries.

        Validates both endpoints with ``is_valid_discovered_ip()`` so broadcast,
        multicast, and link-local addresses never produce phantom device records.
        """
        if is_valid_discovered_ip(server_ip):
            self._ensure_device(
                f"rdp-server:{server_ip}",
                server_ip,
                name=f"RDP Server ({server_ip})",
                device_type="Windows Server",
                data_attr="rdp_passive_data",
                protocol_data={"role": "server", "protocol": "RDP/TCP"},
            )
        else:
            self.logger.debug(f"RDP: skipping invalid server IP {server_ip!r} for device tracking")
        if is_valid_discovered_ip(client_ip):
            self._ensure_device(
                f"rdp-client:{client_ip}",
                client_ip,
                name=f"RDP Client ({client_ip})",
                device_type="RDP Client",
                data_attr="rdp_passive_data",
                protocol_data={"role": "client", "protocol": "RDP/TCP"},
            )
        else:
            self.logger.debug(f"RDP: skipping invalid client IP {client_ip!r} for device tracking")

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials using canonical key names."""
        return [
            {
                "protocol": "RDP",
                "credential_type": cred.credential_type,
                "auth_method": f"RDP-{cred.source.upper()}" if cred.source else "RDP",
                "username": cred.username,
                "password": cred.password,
                "source": cred.source,
                "server_ip": cred.server_ip,
                "client_ip": cred.client_ip,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]
