"""
VRRP (Virtual Router Redundancy Protocol) passive listener.

VRRP uses:
- IP protocol 112
- Multicast 224.0.0.18 (VRRPv2/v3 IPv4)
- Multicast ff02::12 (VRRPv3 IPv6)

Useful for discovering:
- Virtual router configurations
- Active/backup router roles
- Virtual IP addresses
- Priority configurations
- MD5 authentication hashes (auth_type 254)

Uses PyShark (tshark wrapper) for VRRP packet dissection.

PyShark EK-mode VRRP field reference (packet.vrrp.*):
- version: VRRP version (2 or 3)
- virt_rtr_id: Virtual Router ID
- prio: Priority (0-255, 255 = owner/master)
- addr_count: Number of virtual IP addresses
- auth_type: Authentication type (v2: 0=None, 1=Simple Text, 254=MD5)
- adver_int: Advertisement interval (seconds)
- ip_addr: Virtual IPv4 address(es) (may be repeated)
- ipv6_addr: Virtual IPv6 address(es) (may be repeated)
- checksum: Packet checksum value
- checksum_status: Checksum validation (1=good, 2=bad)
- md5_auth_data: MD5 authentication digest (when auth_type=254)
- auth_string: Simple text auth string (when auth_type=1)
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip

import logging

logger = logging.getLogger(__name__)


@dataclass
class VRRPCredential:
    """Extracted VRRP authentication credential."""

    auth_type: int  # 1 = Simple Text, 254 = MD5
    auth_type_name: str
    auth_string: str
    credential_type: str = "plaintext"  # "plaintext" for simple text, "hash" for MD5
    router_ip: str = ""
    vrid: int = 0
    timestamp: str = ""
    md5_hash: str = ""  # MD5 digest hex when auth_type=254

    @property
    def username(self) -> str:
        """Canonical credential field: auth string as username."""
        return self.auth_string

    @property
    def password(self) -> str:
        """Canonical credential field."""
        return self.auth_string

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
        """Canonical credential field: MD5 digest for hash-type credentials."""
        return self.md5_hash


# VRRP constants
VRRP_MULTICAST_V4 = "224.0.0.18"
VRRP_MULTICAST_V6 = "ff02::12"
VRRP_PROTOCOL = 112

# VRRP states
VRRP_STATES = {
    0: "Initialize",
    1: "Backup",
    2: "Master",
}

# VRRP auth types (v2 only; 254 is Cisco MD5 extension)
VRRP_AUTH_TYPES = {
    0: "None",
    1: "Simple Text",
    2: "IP Auth Header",
    254: "MD5",
}

# Checksum validation status values (tshark)
CHECKSUM_STATUS_GOOD = 1
CHECKSUM_STATUS_BAD = 2


class VRRPPassiveListener(PySharkListenerBase):
    """Passive VRRP traffic listener using PyShark.

    Captures VRRP advertisements to identify:
    - Virtual routers (master and backup)
    - Virtual IP addresses
    - Router priorities and preemption settings

    Supports:
    - Live capture via PyShark LiveCapture
    - Direct packet feeding for testing
    """

    PROTOCOL_NAME = "vrrp"
    DISPLAY_FILTER = "vrrp"
    REQUIRED_LAYERS = ("vrrp",)
    PROTOCOL_COLUMNS = (
        "version",
        "vrid",
        "priority",
        "role",
        "addr_count",
        "virtual_ips",
        "auth",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.virtual_routers: Dict[str, Dict] = {}  # VRID -> info
        self.credentials: List[VRRPCredential] = []

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format VRRP protocol-specific columns."""
        d = ix.details
        vips = d.get("virtual_ips", [])
        vip_str = ", ".join(vips)
        if not vip_str:
            vip_str = "?"
            self.logger.debug(f"Missing virtual IPs in VRRP interaction from {ix.src_ip}")
        vrid = d.get("vrid", "")
        if vrid == "" or vrid is None:
            vrid = "?"
            self.logger.debug(f"Missing VRID in VRRP interaction from {ix.src_ip}")
        # All received VRRP Advertisements are from Master (RFC 5798 §6.4.3).
        role = "Master"
        addr_count = d.get("addr_count", "?")
        auth_type = d.get("auth_type_name", "?")
        return [
            d.get("version", "?"),
            vrid,
            d.get("priority", "?"),
            role,
            addr_count,
            vip_str,
            auth_type,
        ]

    def process_packet(self, packet) -> None:
        """Process VRRP packet using PyShark's VRRP dissector."""
        if not hasattr(packet, "vrrp"):
            return

        vrrp = packet.vrrp

        # Get IP and MAC info
        src_ip, dst_ip = self.get_ip_info(packet)
        flow_id = self.get_flow_id(packet)
        if not src_ip:
            return

        # Skip invalid IPs
        if not is_valid_discovered_ip(src_ip):
            return

        src_mac, _ = self.get_mac_info(packet)

        # Extract VRRP fields using correct EK-mode field names
        # "version" is the EK name for vrrp.version (vrrp_ver is XML-only)
        version = _safe_int(self.get_field(vrrp, "version", "2"), 2)
        # "virt_rtr_id" is the EK name for vrrp.virt_rtr_id (vrid is XML-only)
        vrid = _safe_int(self.get_field(vrrp, "virt_rtr_id", "0"), 0)
        if vrid == 0:
            vrid = _safe_int(self.get_field(vrrp, "vrid", "0"), 0)
        if vrid == 0:
            self.logger.debug(f"Missing VRID in VRRP packet from {src_ip} -> {dst_ip}")
        priority = _safe_int(self.get_field(vrrp, "prio", "100"), 100)
        adver_int = _safe_int(self.get_field(vrrp, "adver_int", "1"), 1)

        # T1 field: addr_count -- number of virtual IPs advertised
        addr_count = _safe_int(self.get_field(vrrp, "addr_count", "0"), 0)

        # T1 field: checksum and checksum validation status
        checksum_raw = self.get_field(vrrp, "checksum", None)
        checksum = str(checksum_raw) if checksum_raw is not None else "?"
        checksum_status_raw = self.get_field(vrrp, "checksum_status", None)
        checksum_status = (
            _safe_int(checksum_status_raw, 0) if checksum_status_raw is not None else 0
        )

        # Extract virtual IPs -- use "ip_addr" (EK name for vrrp.ip_addr)
        virtual_ips: List[str] = []
        ip_field = self.get_field(vrrp, "ip_addr", None)
        if ip_field is not None:
            for ip in str(ip_field).split(","):
                ip = ip.strip()
                if ip:
                    virtual_ips.append(ip)

        # Also check for IPv6 virtual addresses (EK name: ipv6_addr)
        ip6_field = self.get_field(vrrp, "ipv6_addr", None)
        if ip6_field is not None:
            for ip in str(ip6_field).split(","):
                ip = ip.strip()
                if ip:
                    virtual_ips.append(ip)

        if not virtual_ips:
            self.logger.debug(f"No virtual IPs extracted from VRRP packet {src_ip} -> {dst_ip}")

        # Per RFC 5798 §6.4.3 (and RFC 3768 §6.4.3 for v2), only a router
        # in Master state transmits VRRP Advertisements; Backup routers
        # MUST NOT send them. So observing ANY Advertisement = sender is
        # Master, regardless of priority. The old `priority == 255` check
        # confused "IP address owner" (255) with "Master role" and
        # misclassified the typical Cisco/Keepalived default (priority=100
        # master) as Backup. Priority 255 still means address-owner —
        # expose separately as `is_address_owner` for downstream use.
        is_master = True
        is_address_owner = priority == 255

        # T1 field: md5_auth_data -- MD5 authentication digest
        md5_auth_data = self.get_field(vrrp, "md5_auth_data", None)
        if md5_auth_data is not None:
            md5_auth_data = str(md5_auth_data).strip()
        else:
            md5_auth_data = ""

        # Determine authentication type and name
        auth_type_raw = self.get_field(vrrp, "auth_type", None)
        auth_type_val = _safe_int(auth_type_raw, 0) if auth_type_raw is not None else 0
        auth_type_name = VRRP_AUTH_TYPES.get(auth_type_val, f"Unknown({auth_type_val})")

        # Extract authentication credentials (VRRPv2 only)
        if version == 2 and auth_type_raw is not None:
            if auth_type_val == 1:
                # Simple Text authentication
                auth_string = str(self.get_field(vrrp, "auth_string", "") or "").strip()
                # Clean null bytes
                auth_string = auth_string.replace("\x00", "").strip()
                if auth_string and not self._is_duplicate_credential(auth_string, src_ip, vrid):
                    cred = VRRPCredential(
                        auth_type=auth_type_val,
                        auth_type_name=auth_type_name,
                        auth_string=auth_string,
                        credential_type="plaintext",
                        router_ip=src_ip,
                        vrid=vrid,
                        timestamp=datetime.now().isoformat(),
                    )
                    self.credentials.append(cred)
                    self.logger.info(f"VRRP: auth_string={auth_string} from {src_ip} VRID={vrid}")
            elif auth_type_val == 254 and md5_auth_data:
                # MD5 authentication -- extract hash as credential
                if not self._is_duplicate_credential(md5_auth_data, src_ip, vrid):
                    cred = VRRPCredential(
                        auth_type=auth_type_val,
                        auth_type_name=auth_type_name,
                        auth_string=f"VRID{vrid}@{src_ip}",
                        credential_type="hash",
                        router_ip=src_ip,
                        vrid=vrid,
                        timestamp=datetime.now().isoformat(),
                        md5_hash=md5_auth_data,
                    )
                    self.credentials.append(cred)
                    self.logger.info(
                        f"VRRP: MD5 hash from {src_ip} VRID={vrid} digest={md5_auth_data}"
                    )

        # Alert on bad checksum (potential tampering or corruption)
        if checksum_status == CHECKSUM_STATUS_BAD:
            self.logger.warning(f"VRRP: Bad checksum from {src_ip} VRID={vrid} checksum={checksum}")

        # Record interaction with all extracted fields
        now = datetime.now().isoformat()
        role = "Master" if is_master else "Backup"
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "VRRP Advertisement",
            {
                "vrid": vrid,
                "priority": priority,
                "version": version,
                "addr_count": addr_count,
                "virtual_ips": virtual_ips,
                "checksum": checksum,
                "checksum_status": checksum_status,
                "auth_type": auth_type_val,
                "auth_type_name": auth_type_name,
                "md5_auth_data": md5_auth_data if md5_auth_data else "",
            },
            f"VRRP v{version} VRID={vrid} {role} pri={priority}",
            flow_id=flow_id,
        )

        device, is_new = self._register_device(
            src_ip,
            src_mac or "",
            name=f"VRRP Router (VRID {vrid})",
            device_type="Router (VRRP Master)" if is_master else "Router (VRRP Backup)",
        )
        if not device:
            return
        if is_new:
            device.vrrp_data = {
                "version": version,
                "vrid": vrid,
                "priority": priority,
                "state": 2 if is_master else 1,
                "state_name": "Master" if is_master else "Backup",
                "is_master": is_master,
                "is_address_owner": is_address_owner,
                "virtual_ips": virtual_ips,
                "addr_count": addr_count,
                "adver_int": adver_int,
                "auth_type": auth_type_val,
                "auth_type_name": auth_type_name,
                "protocol": "VRRP",
                "multicast_dst": dst_ip,
            }

            # Track virtual router
            vrid_key = str(vrid)
            if vrid_key not in self.virtual_routers:
                self.virtual_routers[vrid_key] = {
                    "vrid": vrid,
                    "virtual_ips": virtual_ips,
                    "routers": [],
                }
            self.virtual_routers[vrid_key]["routers"].append(
                {
                    "ip": src_ip,
                    "priority": priority,
                    "is_master": is_master,
                }
            )

            role = "Master" if is_master else "Backup"
            self.logger.debug(f"VRRP: {src_ip} VRID={vrid} {role} pri={priority}")

    def _is_duplicate_credential(self, value: str, router_ip: str, vrid: int) -> bool:
        """Check if credential is already recorded.

        *value* is compared against both auth_string and md5_hash fields
        so that dedup works for both plaintext and MD5 credentials.
        """
        for cred in self.credentials:
            if cred.router_ip == router_ip and cred.vrid == vrid:
                if cred.auth_string == value or cred.md5_hash == value:
                    return True
        return False

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted VRRP credentials."""
        results = []
        for cred in self.credentials:
            entry: Dict[str, Any] = {
                "protocol": "VRRP",
                "credential_type": cred.credential_type,
                "username": cred.auth_string,
                "server_ip": cred.router_ip,
                "client_ip": cred.router_ip,
                "auth_method": cred.auth_type_name,
                "vrid": cred.vrid,
                "timestamp": cred.timestamp,
            }
            if cred.md5_hash:
                entry["hash_value"] = cred.md5_hash
            results.append(entry)
        return results


def _safe_int(value, default: int = 0) -> int:
    """Safely convert a PyShark field value to int."""
    try:
        return int(value)
    except (ValueError, TypeError) as e:
        logger.debug(f"Return value computation failed: {e}")
        return default
