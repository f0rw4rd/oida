"""
DTP (Dynamic Trunking Protocol) passive listener.

DTP is Cisco's proprietary Layer 2 protocol for negotiating trunk links
between switches. It is a significant security concern because an attacker
can send DTP frames to negotiate a trunk and gain access to all VLANs
(VLAN hopping attack).

DTP uses:
- Multicast MAC: 01:00:0c:cc:cc:cc (shared with CDP)
- SNAP encapsulation (LLC/SNAP with OUI 0x00000c, PID 0x2004)
- No IP layer (Layer 2 only)

Useful for discovering:
- Switches with DTP enabled (misconfiguration)
- Trunk negotiation status (admin vs operating)
- VTP domain names
- Sender switch MACs
- Trunk type (ISL vs 802.1Q)
- Potential VLAN hopping attack surface

Uses PyShark (tshark wrapper) for DTP packet dissection.

PyShark DTP field reference (packet.dtp.*):
- dtp.version: Protocol version (typically 1)
- dtp.domain: VTP management domain name
- dtp.senderid: Sender ID (MAC address of sending switch)
- dtp.tas: Trunk Administrative Status (admin-configured mode)
- dtp.tat: Trunk Administrative Type (admin-configured encapsulation)
- dtp.tos: Trunk Operating Status (current operating mode)
- dtp.tot: Trunk Operating Type (current encapsulation in use)
- dtp.tlv_type: TLV type codes (multi-value for each TLV)
- dtp.tlv_len: TLV lengths (multi-value for each TLV)
"""

from datetime import datetime
from typing import Any, Dict, List

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import lookup_mac_vendor, normalize_mac

import logging

logger = logging.getLogger(__name__)


# DTP constants
DTP_MULTICAST_MAC = "01:00:0c:cc:cc:cc"

# DTP trunk status values (admin and operating)
DTP_STATUS = {
    0x01: "On",
    0x02: "Off",
    0x03: "Desirable",
    0x04: "Auto",
    0x81: "On (Operating)",
    0x82: "Off (Operating)",
    0x83: "Desirable (Operating)",
    0x84: "Auto (Operating)",
}

# DTP trunk type / encapsulation values
DTP_TYPES = {
    0x01: "Native",
    0x02: "ISL",
    0x03: "Negotiate",
    0x04: "Dot1Q-Native",
    0x05: "802.1Q",
    0xA5: "802.1Q/802.1Q",
}


class DTPPassiveListener(PySharkListenerBase):
    """Passive DTP traffic listener using PyShark.

    Listens for DTP frames to discover:
    - Switches with DTP enabled (security risk)
    - Trunk negotiation attempts
    - VTP domain names
    - Sender switch identification
    - VLAN hopping attack surface

    Usage:
        # Live capture
        listener = DTPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = DTPPassiveListener(interface="eth0")
        listener.feed_packet(mock_dtp_packet)
    """

    PROTOCOL_NAME = "dtp"
    DISPLAY_FILTER = "dtp"
    REQUIRED_LAYERS = ("dtp",)
    PROTOCOL_COLUMNS = (
        "admin_status",
        "oper_status",
        "domain",
        "sender",
        "type",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger=None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.switches: Dict[str, Dict] = {}  # src_mac -> switch info

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format DTP protocol-specific columns."""
        d = ix.details
        admin_status = d.get("admin_status_name", "")
        if not admin_status:
            admin_status = "?"
            self.logger.debug(f"Missing admin_status in DTP interaction from {ix.src_ip}")
        oper_status = d.get("oper_status_name", "") or "-"
        domain = d.get("domain", "") or "-"
        sender = d.get("sender_id", "") or "-"
        oper_type = d.get("oper_type_name", "") or "-"
        return [
            admin_status,
            oper_status,
            domain,
            sender,
            oper_type,
        ]

    def process_packet(self, packet) -> None:
        """Process captured DTP packet using PyShark's DTP dissector."""
        if not hasattr(packet, "dtp"):
            return

        dtp = packet.dtp

        # DTP is Layer 2 - get MAC info
        src_mac, dst_mac = self.get_mac_info(packet)
        if not src_mac:
            return

        src_mac = normalize_mac(src_mac)

        # Extract DTP fields using correct tshark field names
        version = str(self.get_field(dtp, "version", "") or "")
        domain = str(self.get_field(dtp, "domain", "") or "")

        # Sender ID (MAC of sending switch)
        sender_raw = str(self.get_field(dtp, "senderid", "") or "")
        sender_id = normalize_mac(sender_raw) if sender_raw else ""

        # Trunk Administrative Status (admin-configured mode)
        tas_raw = self.get_field(dtp, "tas", None)
        tas_val = _safe_int(tas_raw, -1)
        admin_status_name = DTP_STATUS.get(tas_val, str(tas_raw) if tas_raw else "?")

        # Trunk Administrative Type (admin-configured encapsulation)
        tat_raw = self.get_field(dtp, "tat", None)
        tat_val = _safe_int(tat_raw, -1)
        admin_type_name = DTP_TYPES.get(tat_val, str(tat_raw) if tat_raw else "?")

        # Trunk Operating Status (current operating mode)
        tos_raw = self.get_field(dtp, "tos", None)
        tos_val = _safe_int(tos_raw, -1)
        oper_status_name = DTP_STATUS.get(tos_val, str(tos_raw) if tos_raw else "?")

        # Trunk Operating Type (current encapsulation)
        tot_raw = self.get_field(dtp, "tot", None)
        tot_val = _safe_int(tot_raw, -1)
        oper_type_name = DTP_TYPES.get(tot_val, str(tot_raw) if tot_raw else "?")

        # TLV fields (optional, multi-value)
        tlv_types = str(self.get_field(dtp, "tlv_type", "") or "")
        tlv_lens = str(self.get_field(dtp, "tlv_len", "") or "")

        # Determine trunk state from operating status
        is_trunking = tos_val in (0x01, 0x81)  # On / On (Operating)
        is_negotiating = tas_val in (0x03, 0x04, 0x83, 0x84)  # Desirable / Auto

        # Build flow ID from MAC addresses
        flow_id = f"{src_mac} -> {dst_mac}" if dst_mac else src_mac

        # Build details dict
        details: Dict[str, Any] = {
            "src_mac": src_mac,
            "version": version,
            "domain": domain,
            "sender_id": sender_id,
            "admin_status_raw": str(tas_val) if tas_val >= 0 else "?",
            "admin_status_name": admin_status_name,
            "admin_type_raw": str(tat_val) if tat_val >= 0 else "?",
            "admin_type_name": admin_type_name,
            "oper_status_raw": str(tos_val) if tos_val >= 0 else "?",
            "oper_status_name": oper_status_name,
            "oper_type_raw": str(tot_val) if tot_val >= 0 else "?",
            "oper_type_name": oper_type_name,
            "is_trunking": is_trunking,
            "is_negotiating": is_negotiating,
        }
        if tlv_types:
            details["tlv_types"] = tlv_types
        if tlv_lens:
            details["tlv_lens"] = tlv_lens

        # Record interaction
        now = datetime.now().isoformat()
        operation = f"DTP {admin_status_name}"
        if is_trunking:
            operation = f"DTP Trunk Active ({oper_type_name})"
        elif is_negotiating:
            operation = f"DTP Negotiating ({admin_status_name})"

        self._record_interaction(
            now,
            src_mac,
            dst_mac or "",
            "request",
            operation,
            details,
            (
                f"DTP {src_mac} admin={admin_status_name} oper={oper_status_name} "
                f"domain={domain} sender={sender_id}"
            ),
            flow_id=flow_id,
        )

        # Track switch
        self.switches[src_mac] = {
            "mac": src_mac,
            "domain": domain,
            "sender_id": sender_id,
            "admin_status": admin_status_name,
            "oper_status": oper_status_name,
            "admin_type": admin_type_name,
            "oper_type": oper_type_name,
            "is_trunking": is_trunking,
            "is_negotiating": is_negotiating,
        }

        # Create/update device
        device_key = f"dtp:{src_mac}"
        mac_vendor = lookup_mac_vendor(src_mac) if src_mac else ""

        device_type = "Network Switch (DTP)"
        if is_trunking:
            device_type = "Network Switch (DTP Trunk)"
        elif is_negotiating:
            device_type = "Network Switch (DTP Negotiating)"

        device, is_new = self._ensure_device(
            device_key,
            "",  # No IP in DTP
            mac=src_mac,
            name=f"Switch ({src_mac})",
            device_type=device_type,
            manufacturer=mac_vendor if mac_vendor and mac_vendor != "Unknown" else "Cisco",
        )
        if is_new:
            device.dtp_data = {
                "version": version,
                "domain": domain,
                "sender_id": sender_id,
                "admin_status": admin_status_name,
                "oper_status": oper_status_name,
                "admin_type": admin_type_name,
                "oper_type": oper_type_name,
                "is_trunking": is_trunking,
                "is_negotiating": is_negotiating,
                "protocol": "DTP/L2",
            }
            self.logger.debug(
                f"DTP: {src_mac} admin={admin_status_name} oper={oper_status_name} "
                f"type={oper_type_name} domain={domain} sender={sender_id}"
            )

    def harvest(self) -> Dict[str, Any]:
        """Return DTP switch summary and security alerts."""
        if not self.switches:
            return {}

        headers = [
            "Switch MAC",
            "Vendor",
            "Domain",
            "Admin Status",
            "Oper Status",
            "Type",
            "Sender",
        ]
        rows = []
        alerts = []

        for mac, info in sorted(self.switches.items()):
            vendor = lookup_mac_vendor(mac)
            rows.append(
                [
                    mac,
                    vendor if vendor != "Unknown" else "-",
                    info.get("domain", "-"),
                    info.get("admin_status", "?"),
                    info.get("oper_status", "?"),
                    info.get("oper_type", "-"),
                    info.get("sender_id", "-"),
                ]
            )

            # Security alerts for DTP-enabled ports
            if info.get("is_negotiating"):
                alerts.append(
                    {
                        "level": "fail",
                        "category": "security",
                        "message": (
                            f"DTP NEGOTIATING: {mac} is in {info.get('admin_status', '?')} mode "
                            f"(domain={info.get('domain', '?')}). "
                            "Vulnerable to VLAN hopping via DTP spoofing."
                        ),
                    }
                )
            elif info.get("is_trunking"):
                alerts.append(
                    {
                        "level": "warning",
                        "category": "security",
                        "message": (
                            f"DTP TRUNK: {mac} has active trunk "
                            f"(domain={info.get('domain', '?')}, type={info.get('oper_type', '?')}). "
                            "Verify trunk is intentional and DTP is disabled on access ports."
                        ),
                    }
                )

        tables = [{"headers": headers, "rows": rows, "title": f"DTP Switches ({len(rows)})"}]
        return {"tables": tables, "alerts": alerts}


def _safe_int(value, default: int = 0) -> int:
    """Safely convert a PyShark field value to int."""
    try:
        s = str(value).strip()
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError) as e:
        logger.debug(f"DTP: hex/decimal int parse failed for field value: {e}")
        return default
