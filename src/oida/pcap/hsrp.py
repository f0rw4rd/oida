"""
HSRP (Hot Standby Router Protocol) passive listener.

HSRP is Cisco's proprietary protocol for router redundancy.

HSRPv1:
- Multicast: 224.0.0.2 (all routers)
- UDP port: 1985
- 20-byte fixed format packet

HSRPv2:
- Multicast: 224.0.0.102 (HSRPv2)
- UDP port: 1985
- TLV-based format with extended features

Uses PyShark (tshark wrapper) for HSRP packet dissection.

PyShark HSRP field reference (packet.hsrp.*):
- version: HSRP version (0 = v1, 2 = v2)
- opcode: Operation code (0=Hello, 1=Coup, 2=Resign)
- state: HSRP state
- hellotime: Hello interval
- holdtime: Hold time
- priority: Router priority
- group: Group number
- auth_data: Authentication data (v1)
- virtual_ip: Virtual IP address
- identifier: Router identifier MAC (v2)
- md5_key_id: MD5 key ID (v2 with MD5 auth)
- md5_auth_data: MD5 authentication digest (v2)

References:
- Wireshark dissector: packet-hsrp.c
- Cisco HSRP v2 documentation
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip
from ..shared.hsrp_constants import (
    HSRP_OPCODES,
    HSRP_PORT,
    HSRP_V1_STATES,
    HSRP_V2_STATES,
)

import logging

logger = logging.getLogger(__name__)


class HSRPPassiveListener(PySharkListenerBase):
    """Unified HSRP v1 and v2 passive listener using PyShark.

    Listens for HSRP Hello packets on UDP 1985 to discover:
    - Cisco routers using HSRP for gateway redundancy
    - Virtual IP addresses (VIPs)
    - Active/Standby states and priorities
    - Authentication data (plaintext or MD5)
    - Router MAC addresses (identifier field in v2)

    Usage:
        # Live capture
        listener = HSRPPassiveListener(interface="eth0", timeout=30)
        devices = listener.scan()
        devices = listener.scan()

        # Testing - feed packets directly
        listener = HSRPPassiveListener(interface="eth0")
        listener.feed_packet(mock_hsrp_packet)
    """

    PROTOCOL_NAME = "hsrp"
    DISPLAY_FILTER = "hsrp"
    REQUIRED_LAYERS = ("hsrp",)
    PROTOCOL_COLUMNS = (
        "version",
        "group",
        "state",
        "priority",
        "virtual_ip",
        "auth",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger=None,
    ):
        super().__init__(interface, timeout, nxc_logger)

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format HSRP protocol-specific columns."""
        d = ix.details
        auth = d.get("auth_data", "")
        if not auth:
            auth = d.get("auth_type", "None")
        vip = d.get("virtual_ip", "")
        if not vip:
            vip = "?"
            self.logger.debug(f"Missing virtual_ip in HSRP interaction from {ix.src_ip}")
        state = d.get("state", "")
        if not state:
            state = "?"
            self.logger.debug(f"Missing state in HSRP interaction from {ix.src_ip}")
        return [
            d.get("version", "?"),
            d.get("group", "?"),
            state,
            d.get("priority", "?"),
            vip,
            auth,
        ]

    def should_process_packet(self, packet) -> bool:
        """Check if packet has HSRP layer."""
        return hasattr(packet, "hsrp")

    def process_packet(self, packet) -> None:
        """Process captured HSRP packet using PyShark's HSRP dissector."""
        if not hasattr(packet, "hsrp"):
            return

        hsrp = packet.hsrp

        # Get IP and MAC info
        src_ip, dst_ip = self.get_ip_info(packet)
        flow_id = self.get_flow_id(packet)
        if not src_ip:
            return

        # Skip local/invalid IPs
        if not is_valid_discovered_ip(src_ip):
            return

        src_mac, _ = self.get_mac_info(packet)

        # Determine HSRP version.
        # In EK mode, v1 fields use "version" (resolves to hsrp_hsrp_version)
        # while v2 fields use "hsrp2_version" (resolves to hsrp_hsrp2_version).
        # Try v1 name first; if missing, check v2 name.
        version_field = self.get_field(hsrp, "version", None)
        if version_field is None:
            version_field = self.get_field(hsrp, "hsrp2_version", "0")
        version_raw = self._parse_int(version_field, 0)

        # Wireshark: version=0 for HSRPv1, version=2 for HSRPv2
        if version_raw == 2:
            hsrp_info = self._parse_hsrp_v2(hsrp)
        else:
            hsrp_info = self._parse_hsrp_v1(hsrp)

        if not hsrp_info:
            return

        # Record interaction
        ver = hsrp_info.get("version", 1)
        opcode_name = hsrp_info.get("opcode_name", "")
        state_name = hsrp_info.get("state_name", "")
        vip = hsrp_info.get("virtual_ip", "")
        grp = hsrp_info.get("group", 0)
        pri = hsrp_info.get("priority", 0)
        auth_data = hsrp_info.get("auth_data", "")
        auth_type = hsrp_info.get("auth_type", "")
        now = datetime.now().isoformat()
        interaction_details = {
            "version": ver,
            "group": grp,
            "priority": pri,
            "state": state_name,
            "virtual_ip": vip,
            "auth_data": auth_data,
            "auth_type": auth_type,
            "hold_time": hsrp_info.get("hold_time"),
            "ip_version": hsrp_info.get("ip_version"),
        }
        # Include MD5-specific fields when present
        if hsrp_info.get("md5_auth_tlv") is not None:
            interaction_details["md5_auth_tlv"] = hsrp_info["md5_auth_tlv"]
        if hsrp_info.get("md5_key_id") is not None:
            interaction_details["md5_key_id"] = hsrp_info["md5_key_id"]
        if hsrp_info.get("md5_algorithm") is not None:
            interaction_details["md5_algorithm"] = hsrp_info["md5_algorithm"]
        if hsrp_info.get("md5_auth_data"):
            interaction_details["md5_auth_data"] = hsrp_info["md5_auth_data"]

        self._record_interaction(
            now,
            src_ip,
            dst_ip or "",
            "request",
            f"HSRPv{ver} {opcode_name}",
            interaction_details,
            f"HSRPv{ver} {opcode_name} group={grp} state={state_name} vip={vip} pri={pri}",
            flow_id=flow_id,
        )

        # Use identifier MAC from v2 or Ethernet src MAC
        device_mac = hsrp_info.get("identifier", "") or src_mac

        device, is_new = self._register_device(
            src_ip,
            device_mac,
            device_type="Router",
        )
        if not device:
            return
        if is_new:
            device.hsrp_data = {
                "version": hsrp_info.get("version"),
                "opcode": hsrp_info.get("opcode"),
                "opcode_name": hsrp_info.get("opcode_name"),
                "state": hsrp_info.get("state"),
                "state_name": hsrp_info.get("state_name"),
                "group": hsrp_info.get("group"),
                "priority": hsrp_info.get("priority"),
                "virtual_ip": hsrp_info.get("virtual_ip"),
                "hello_time": hsrp_info.get("hello_time"),
                "hold_time": hsrp_info.get("hold_time"),
                "identifier": hsrp_info.get("identifier"),
                "auth_type": hsrp_info.get("auth_type"),
                "auth_data": hsrp_info.get("auth_data"),
                "md5_key_id": hsrp_info.get("md5_key_id"),
                "md5_algorithm": hsrp_info.get("md5_algorithm"),
                "md5_auth_data": hsrp_info.get("md5_auth_data"),
                "md5_auth_tlv": hsrp_info.get("md5_auth_tlv"),
                "ip_version": hsrp_info.get("ip_version"),
                "multicast_group": dst_ip,
                "active_groups": hsrp_info.get("active_groups"),
                "passive_groups": hsrp_info.get("passive_groups"),
                "protocol": f"HSRPv{hsrp_info.get('version', 1)}/UDP",
                "port": HSRP_PORT,
            }

            ver = hsrp_info.get("version", 1)
            state = hsrp_info.get("state_name", "unknown")
            vip = hsrp_info.get("virtual_ip", "")
            pri = hsrp_info.get("priority", 0)
            grp = hsrp_info.get("group", 0)
            auth = hsrp_info.get("auth_data", "")
            self.logger.debug(
                f"HSRPv{ver}: {src_ip} group={grp} state={state} "
                f"vip={vip} priority={pri} auth={auth}"
            )
        else:
            # Update existing device
            # Update hsrp_data with latest info
            if device.hsrp_data:
                device.hsrp_data["state"] = hsrp_info.get("state")
                device.hsrp_data["state_name"] = hsrp_info.get("state_name")
                device.hsrp_data["priority"] = hsrp_info.get("priority")

    def get_credentials_summary(self):
        """Get HSRP authentication credentials from discovered devices."""
        creds = []
        for device in self.discovered_devices.values():
            hsrp_data = getattr(device, "hsrp_data", None)
            if not hsrp_data:
                continue
            auth_data_val = hsrp_data.get("auth_data", "")
            if not auth_data_val:
                continue
            ip = device.ip_addresses[0] if device.ip_addresses else ""
            creds.append(
                {
                    "protocol": f"HSRPv{hsrp_data.get('version', 1)}",
                    "credential_type": hsrp_data.get("auth_type", "plaintext"),
                    "username": auth_data_val,
                    "server_ip": ip,
                    "client_ip": ip,
                    "auth_method": f"HSRPv{hsrp_data.get('version', 1)}",
                    "group": hsrp_data.get("group", 0),
                }
            )
        return creds

    def _parse_hsrp_v1(self, hsrp) -> Optional[Dict[str, Any]]:
        """Parse HSRPv1 packet fields from PyShark HSRP layer.

        In EK mode, v1 fields resolve via the ``hsrp_hsrp_*`` prefix
        (e.g. ``getattr(layer, "opcode")`` -> ``hsrp_hsrp_opcode``).
        The virtual IP field is ``virt_ip`` in tshark (not ``virtual_ip``).
        """
        try:
            opcode = self._parse_int(self.get_field(hsrp, "opcode", "0"), 0)
            state = self._parse_int(self.get_field(hsrp, "state", "0"), 0)
            hello_time = self._parse_int(self.get_field(hsrp, "hellotime", "3"), 3)
            hold_time = self._parse_int(self.get_field(hsrp, "holdtime", "10"), 10)
            priority = self._parse_int(self.get_field(hsrp, "priority", "100"), 100)
            group = self._parse_int(self.get_field(hsrp, "group", "0"), 0)

            # Virtual IP -- tshark field is hsrp.virt_ip (not virtual_ip)
            virtual_ip = str(
                self.get_field(hsrp, "virt_ip", None) or self.get_field(hsrp, "virtual_ip", "")
            )

            # Authentication data (plaintext for v1)
            auth_data = str(self.get_field(hsrp, "auth_data", ""))
            # Clean up null bytes from auth string
            auth_data = auth_data.replace("\x00", "").strip()

            # Get state name
            state_name = HSRP_V1_STATES.get(state, f"Unknown({state})")

            # Get opcode name
            opcode_name = HSRP_OPCODES.get(opcode, f"Unknown({opcode})")

            return {
                "version": 1,
                "opcode": opcode,
                "opcode_name": opcode_name,
                "state": state,
                "state_name": state_name,
                "hello_time": hello_time,
                "hold_time": hold_time,
                "priority": priority,
                "group": group,
                "auth_type": "plaintext",
                "auth_data": auth_data,
                "virtual_ip": virtual_ip,
                "ip_version": 4,
            }

        except Exception as e:
            self.logger.debug(f"HSRPv1 PyShark parse failed: {e}")
            return None

    def _parse_hsrp_v2(self, hsrp) -> Optional[Dict[str, Any]]:
        """Parse HSRPv2 packet fields from PyShark HSRP layer.

        HSRPv2 uses TLV format. In EK mode, v2 fields are prefixed with
        ``hsrp2_`` (e.g. ``hsrp2_opcode``) which resolves to the EK key
        ``hsrp_hsrp2_opcode``.  We try the ``hsrp2_`` name first and fall
        back to the unprefixed v1 name for XML-mode compatibility.
        """
        try:
            opcode = self._parse_int(
                self.get_field(hsrp, "hsrp2_opcode", None) or self.get_field(hsrp, "opcode", "0"),
                0,
            )
            state = self._parse_int(
                self.get_field(hsrp, "hsrp2_state", None) or self.get_field(hsrp, "state", "0"),
                0,
            )
            group = self._parse_int(
                self.get_field(hsrp, "hsrp2_group", None) or self.get_field(hsrp, "group", "0"),
                0,
            )
            priority = self._parse_int(
                self.get_field(hsrp, "hsrp2_priority", None)
                or self.get_field(hsrp, "priority", "100"),
                100,
            )
            hello_time = self._parse_int(
                self.get_field(hsrp, "hsrp2_hellotime", None)
                or self.get_field(hsrp, "hellotime", "3000"),
                3000,
            )
            hold_time = self._parse_int(
                self.get_field(hsrp, "hsrp2_holdtime", None)
                or self.get_field(hsrp, "holdtime", "10000"),
                10000,
            )
            virtual_ip = str(
                self.get_field(hsrp, "hsrp2_virt_ip", None)
                or self.get_field(hsrp, "virtual_ip", "")
            )

            # Identifier (MAC address) from v2
            identifier = str(
                self.get_field(hsrp, "hsrp2_identifier", None)
                or self.get_field(hsrp, "identifier", "")
            )

            # IP version (hsrp2.ipversion in EK mode)
            ip_version = self._parse_int(
                self.get_field(hsrp, "hsrp2_ipversion", None)
                or self.get_field(hsrp, "addr_type", "4"),
                4,
            )

            # Get state name using v2 states
            state_name = HSRP_V2_STATES.get(state, f"Unknown({state})")

            # Get opcode name
            opcode_name = HSRP_OPCODES.get(opcode, f"Unknown({opcode})")

            result: Dict[str, Any] = {
                "version": 2,
                "opcode": opcode,
                "opcode_name": opcode_name,
                "state": state,
                "state_name": state_name,
                "group": group,
                "priority": priority,
                "hello_time": hello_time,
                "hold_time": hold_time,
                "virtual_ip": virtual_ip,
                "identifier": identifier,
                "ip_version": ip_version,
            }

            # Authentication -- check for text auth or MD5 auth.
            # Text auth (TLV type 3)
            auth_data = str(
                self.get_field(hsrp, "hsrp2_auth_data", None)
                or self.get_field(hsrp, "auth_data", "")
            )
            if auth_data:
                auth_data = auth_data.replace("\x00", "").strip()
                if auth_data:
                    result["auth_type"] = "plaintext"
                    result["auth_data"] = auth_data

            # MD5 authentication TLV (type 4)
            md5_auth_tlv = self.get_field(hsrp, "hsrp2_md5_auth_tlv", None)
            if md5_auth_tlv is not None:
                result["md5_auth_tlv"] = self._parse_int(md5_auth_tlv, 0)

            md5_key_id = self.get_field(hsrp, "hsrp2_md5_key_id", None) or self.get_field(
                hsrp, "md5_key_id", None
            )
            if md5_key_id is not None:
                result["auth_type"] = "md5"
                result["md5_key_id"] = self._parse_int(md5_key_id, 0)
                result["md5_algorithm"] = self._parse_int(
                    self.get_field(hsrp, "hsrp2_md5_algorithm", None)
                    or self.get_field(hsrp, "md5_algorithm", "0"),
                    0,
                )

                # MD5 authentication digest (hsrp2.md5_auth_data)
                md5_digest = self.get_field(hsrp, "hsrp2_md5_auth_data", None) or self.get_field(
                    hsrp, "md5_auth_data", None
                )
                if md5_digest:
                    result["md5_auth_data"] = str(md5_digest)
                else:
                    result["md5_auth_data"] = "?"
                    self.logger.debug("Missing md5_auth_data in HSRPv2 MD5 auth TLV")

                result["auth_data"] = f"MD5 Key-ID:{result['md5_key_id']}"

            # Interface state TLV fields
            active_groups = self.get_field(hsrp, "hsrp2_active_groups", None) or self.get_field(
                hsrp, "active_groups", None
            )
            if active_groups is not None:
                result["active_groups"] = self._parse_int(active_groups, 0)
                result["passive_groups"] = self._parse_int(
                    self.get_field(hsrp, "hsrp2_passive_groups", None)
                    or self.get_field(hsrp, "passive_groups", "0"),
                    0,
                )

            return result

        except Exception as e:
            self.logger.debug(f"HSRPv2 PyShark parse failed: {e}")
            return None


# Alias for v2 variant (same implementation handles both versions)
HSRPv2PassiveListener = HSRPPassiveListener


