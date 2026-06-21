"""
RIP (Routing Information Protocol) passive listener.

RIP uses:
- UDP port 520
- Multicast 224.0.0.9 (RIPv2)
- Broadcast 255.255.255.255 (RIPv1)

Useful for discovering:
- RIP routers and their routes
- Network topology information
- Route metrics and next hops
- Authentication configuration

Uses PyShark (tshark wrapper) for RIP packet dissection.

PyShark RIP field reference (packet.rip.*):
- command: RIP command (1=Request, 2=Response)
- version: RIP version
- auth_type: Authentication type (if auth entry present)
- ip: Route IP address
- netmask: Route netmask
- next_hop: Next hop address
- metric: Route metric
- route_tag: Route tag (RIPv2)
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip

import logging

logger = logging.getLogger(__name__)


@dataclass
class RIPCredential:
    """Extracted RIP authentication credential."""

    auth_type: int  # 2 = Simple Password, 3 = MD5
    auth_type_name: str
    credential_type: str  # "plaintext" or "hash"
    password: str = ""  # For simple password auth
    auth_data: str = ""  # For MD5/SHA auth data
    router_ip: str = ""
    timestamp: str = ""

    @property
    def username(self) -> str:
        """Canonical credential field: password or auth data as username."""
        return self.password or self.auth_data

    @property
    def server_ip(self) -> str:
        """Canonical credential field: router is the server."""
        return self.router_ip

    @property
    def client_ip(self) -> str:
        """Canonical credential field: same as router for multicast protocols."""
        return self.router_ip

    @property
    def auth_method(self) -> str:
        """Canonical credential field."""
        return self.auth_type_name

    @property
    def hash_value(self) -> str:
        """Canonical credential field: MD5 auth data."""
        return self.auth_data if self.credential_type == "hash" else ""


# RIP constants
RIP_PORT = 520
RIP_MULTICAST = "224.0.0.9"

# RIP commands
RIP_COMMANDS = {
    1: "Request",
    2: "Response",
}

# RIP versions
RIP_VERSIONS = {
    1: "RIPv1",
    2: "RIPv2",
}

# RIP authentication types
RIP_AUTH_TYPES = {
    0: "None",
    2: "Simple Password",
    3: "MD5",
}


class RIPPassiveListener(PySharkListenerBase):
    """Passive RIP traffic listener using PyShark.

    Captures RIP packets to identify:
    - RIP routers
    - Advertised routes and metrics
    - Network topology information
    """

    PROTOCOL_NAME = "rip"
    DISPLAY_FILTER = "rip"
    REQUIRED_LAYERS = ("rip",)
    PROTOCOL_COLUMNS = ("version", "command", "auth", "routes", "networks")

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.routes: Dict[str, List[Dict]] = {}  # src_ip -> routes
        self.credentials: List[RIPCredential] = []

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format RIP protocol-specific columns."""
        d = ix.details
        route_count = d.get("route_count", 0)
        networks = d.get("networks", [])
        net_str = ", ".join(networks)
        # Auth type "None" means no authentication (type 0) — show as empty
        auth = d.get("auth_type_name", "")
        if auth == "None":
            auth = ""
        return [
            d.get("version_name", ""),
            d.get("command_name", ix.operation),
            auth,
            str(route_count),
            net_str,
        ]

    def process_packet(self, packet) -> None:
        """Process RIP packet using PyShark's RIP dissector."""
        if not hasattr(packet, "rip"):
            return

        rip = packet.rip

        # Get IP info
        src_ip, dst_ip = self.get_ip_info(packet)
        src_port, dst_port = self.get_port_info(packet)
        flow_id = self.get_flow_id(packet)
        if not src_ip:
            return

        # Skip invalid IPs
        if not is_valid_discovered_ip(src_ip):
            return

        # Get MAC info
        src_mac, _ = self.get_mac_info(packet)

        # Extract RIP header fields
        command = self._parse_int(self.get_field(rip, "command", "0"), 0)
        version = self._parse_int(self.get_field(rip, "version", "0"), 0)

        command_name = RIP_COMMANDS.get(command, f"Unknown({command})")
        version_name = RIP_VERSIONS.get(version, f"v{version}")

        # Extract authentication info
        auth_type = 0
        auth_type_name = "None"
        auth_type_field = self.get_field(rip, "auth_type", None)
        if auth_type_field is not None:
            auth_type = self._parse_int(auth_type_field, 0)
            auth_type_name = RIP_AUTH_TYPES.get(auth_type, f"Unknown({auth_type})")

        # Extract authentication password/data
        if auth_type == 2:
            # Simple password authentication
            auth_passwd = str(self.get_field(rip, "auth_passwd", "") or "").strip()
            if auth_passwd and not self._is_duplicate_credential(
                auth_type, auth_passwd, "", src_ip
            ):
                cred = RIPCredential(
                    auth_type=auth_type,
                    auth_type_name=auth_type_name,
                    credential_type="plaintext",
                    password=auth_passwd,
                    router_ip=src_ip,
                    timestamp=datetime.now().isoformat(),
                )
                self.credentials.append(cred)
                self.logger.info(f"RIP: Simple Password={auth_passwd} from {src_ip}")

        elif auth_type == 3:
            # MD5 authentication data
            auth_data = str(self.get_field(rip, "authentication_data", "") or "").strip()
            if auth_data and not self._is_duplicate_credential(auth_type, "", auth_data, src_ip):
                cred = RIPCredential(
                    auth_type=auth_type,
                    auth_type_name=auth_type_name,
                    credential_type="hash",
                    auth_data=auth_data,
                    router_ip=src_ip,
                    timestamp=datetime.now().isoformat(),
                )
                self.credentials.append(cred)
                self.logger.info(f"RIP: MD5 auth data from {src_ip}")

        # Extract route entries
        # PyShark provides route fields; for multiple routes, fields may be repeated
        routes = []

        # Get route IP addresses
        route_ip = self.get_field(rip, "ip", None)
        route_mask = self.get_field(rip, "netmask", None)
        route_next_hop = self.get_field(rip, "next_hop", None)
        route_metric = self.get_field(rip, "metric", None)
        route_tag = self.get_field(rip, "route_tag", None)

        if route_ip is not None:
            # Handle single or comma-separated values
            ips = str(route_ip).split(",")
            masks = str(route_mask).split(",") if route_mask else ["classful"] * len(ips)
            next_hops = str(route_next_hop).split(",") if route_next_hop else [src_ip] * len(ips)
            metrics = str(route_metric).split(",") if route_metric else ["0"] * len(ips)
            tags = str(route_tag).split(",") if route_tag else ["0"] * len(ips)

            for i, ip in enumerate(ips):
                ip = ip.strip()
                if not ip:
                    continue

                mask = masks[i].strip() if i < len(masks) else "classful"
                if version == 1:
                    mask = "classful"

                nh = next_hops[i].strip() if i < len(next_hops) else src_ip
                if nh == "0.0.0.0":
                    nh = src_ip

                metric = self._parse_int(metrics[i].strip() if i < len(metrics) else "0", 0)

                route = {
                    "network": ip,
                    "mask": mask,
                    "next_hop": nh,
                    "metric": metric,
                }
                if version == 2:
                    tag = self._parse_int(tags[i].strip() if i < len(tags) else "0", 0)
                    route["route_tag"] = tag

                routes.append(route)

        # Record interaction
        now = datetime.now().isoformat()
        networks = [r.get("network", "") for r in routes]
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            f"RIP {command_name}",
            {
                "command": command,
                "command_name": command_name,
                "version": version,
                "version_name": version_name,
                "route_count": len(routes),
                "auth_type_name": auth_type_name,
                "networks": networks,
            },
            f"RIP {version_name} {command_name} {len(routes)} routes",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
        )

        self._update_device(
            src_ip=src_ip,
            src_mac=src_mac if src_mac else "",
            dst_ip=dst_ip,
            version=version,
            version_name=version_name,
            command=command,
            command_name=command_name,
            auth_type=auth_type,
            auth_type_name=auth_type_name,
            routes=routes,
        )

    def _update_device(
        self,
        src_ip: str,
        src_mac: str,
        dst_ip: str,
        version: int,
        version_name: str,
        command: int,
        command_name: str,
        auth_type: int,
        auth_type_name: str,
        routes: List[Dict],
    ) -> None:
        """Update or create device entry."""
        device, is_new = self._register_device(
            src_ip,
            src_mac,
            name=f"RIP Router ({version_name})",
            device_type="Router (RIP)",
        )
        if not device:
            return
        if is_new:
            device.rip_data = {
                "version": version,
                "version_name": version_name,
                "command": command,
                "command_name": command_name,
                "auth_type": auth_type,
                "auth_type_name": auth_type_name,
                "routes": routes,
                "route_count": len(routes),
                "multicast_dst": dst_ip,
                "protocol": "RIP",
            }

            self.routes[src_ip] = routes

            self.logger.debug(
                f"RIP: {src_ip} {version_name} {len(routes)} routes auth={auth_type_name}"
            )
        else:
            # Merge new routes
            existing_routes = self.routes.get(src_ip, [])
            existing_networks = {r["network"] for r in existing_routes}
            for route in routes:
                if route["network"] not in existing_networks:
                    existing_routes.append(route)
                    existing_networks.add(route["network"])
            self.routes[src_ip] = existing_routes
            device.rip_data["routes"] = existing_routes
            device.rip_data["route_count"] = len(existing_routes)

    def _is_duplicate_credential(
        self,
        auth_type: int,
        password: str,
        auth_data: str,
        router_ip: str,
    ) -> bool:
        """Check if credential is already recorded."""
        for cred in self.credentials:
            if (
                cred.auth_type == auth_type
                and cred.password == password
                and cred.auth_data == auth_data
                and cred.router_ip == router_ip
            ):
                return True
        return False

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted RIP credentials."""
        result = []
        for cred in self.credentials:
            entry: Dict[str, Any] = {
                "protocol": "RIP",
                "credential_type": cred.credential_type,
                "username": cred.password or cred.auth_data,
                "server_ip": cred.router_ip,
                "client_ip": cred.router_ip,
                "auth_method": cred.auth_type_name,
                "timestamp": cred.timestamp,
            }
            result.append(entry)
        return result


