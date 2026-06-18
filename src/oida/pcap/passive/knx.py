"""
KNX/IP Passive Listener (PyShark-based).

Passively monitors KNX/IP building automation traffic to identify:
- KNX/IP gateways and their device information (name, serial, medium)
- Tunneling clients and their communication patterns
- Group address communication (GroupValueRead, GroupValueWrite, GroupValueResponse)
- Individual address communication (memory read/write, device descriptor, etc.)
- APCI operations and data point values
- Connection management (Connect, Disconnect, Tunneling, Routing)
- Security posture (KNX Secure usage or lack thereof)

KNX/IP protocol:
- Port 3671 (UDP and TCP)
- KNXnet/IP header: Header Length + Protocol Version + Service Type + Total Length
- cEMI (Common External Message Interface) carries the actual KNX telegram
- Individual addresses: area.line.device (e.g., 1.2.3) from 16-bit raw address
- Group addresses: main/middle/sub (e.g., 1/2/100) from 16-bit raw address
- APCI: Application Protocol Control Information in cEMI data layer

tshark layers:
- knxnetip (kip): KNXnet/IP frame header and service-specific fields
- cemi: Common External Message Interface telegram fields

References:
- KNX Standard ISO 22510
- KNXnet/IP specification (AN159)
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

import logging

logger = logging.getLogger(__name__)


# KNXnet/IP service types
KNXIP_SERVICES = {
    0x0201: "SEARCH_REQUEST",
    0x0202: "SEARCH_RESPONSE",
    0x0203: "DESCRIPTION_REQUEST",
    0x0204: "DESCRIPTION_RESPONSE",
    0x0205: "CONNECT_REQUEST",
    0x0206: "CONNECT_RESPONSE",
    0x0207: "CONNSTATE_REQUEST",
    0x0208: "CONNSTATE_RESPONSE",
    0x0209: "DISCONNECT_REQUEST",
    0x020A: "DISCONNECT_RESPONSE",
    0x020B: "SEARCH_REQUEST_EXT",
    0x020C: "SEARCH_RESPONSE_EXT",
    0x0310: "CONFIG_REQUEST",
    0x0311: "CONFIG_ACK",
    0x0420: "TUNNELING_REQUEST",
    0x0421: "TUNNELING_ACK",
    0x0422: "TUNNELING_FEATURE_GET",
    0x0423: "TUNNELING_FEATURE_RESP",
    0x0424: "TUNNELING_FEATURE_SET",
    0x0425: "TUNNELING_FEATURE_INFO",
    0x0530: "ROUTING_INDICATION",
    0x0531: "ROUTING_LOSS",
    0x0532: "ROUTING_BUSY",
    0x0533: "ROUTING_SYSBROADCAST",
    0x0950: "SECURE_WRAPPER",
    0x0951: "SESSION_REQUEST",
    0x0952: "SESSION_RESPONSE",
    0x0953: "SESSION_AUTHENTICATE",
    0x0954: "SESSION_STATUS",
    0x0955: "TIMER_NOTIFY",
}

# Request service types (for direction classification)
REQUEST_SERVICES = {
    0x0201,
    0x0203,
    0x0205,
    0x0207,
    0x0209,
    0x020B,
    0x0310,
    0x0420,
    0x0422,
    0x0424,
    0x0530,  # Routing indication is a broadcast, treat as request
    0x0950,
    0x0951,
    0x0953,
    0x0955,
}

# KNX Secure service types
SECURE_SERVICES = {0x0950, 0x0951, 0x0952, 0x0953, 0x0954, 0x0955}

# cEMI APCI service codes (from cemi.ac field)
APCI_SERVICES = {
    0x0: "GroupValueRead",
    0x1: "GroupValueResponse",
    0x2: "GroupValueWrite",
    0x3: "IndividualAddressWrite",
    0x4: "IndividualAddressRead",
    0x5: "IndividualAddressResponse",
    0x6: "ADCRead",
    0x7: "ADCResponse",
    0x8: "MemoryRead",
    0x9: "MemoryResponse",
    0xA: "MemoryWrite",
    0xB: "UserMessage",
    0xC: "DeviceDescriptorRead",
    0xD: "DeviceDescriptorResponse",
    0xE: "Restart",
    0xF: "Escape",
}

# APCI codes classified as write operations
APCI_WRITE_CODES = {0x2, 0x3, 0xA}  # GroupValueWrite, IndAddrWrite, MemWrite

# APCI codes classified as read operations
APCI_READ_CODES = {0x0, 0x4, 0x6, 0x8, 0xC}

# APCI codes classified as response operations (no count increment)
APCI_RESPONSE_CODES = {0x1, 0x5, 0x7, 0x9, 0xD}

# cEMI message codes (from cemi.mc field)
CEMI_MESSAGE_CODES = {
    0x11: "L_Data.req",
    0x29: "L_Data.ind",
    0x2E: "L_Data.con",
    0x2B: "L_Busmon.ind",
    0x10: "L_Raw.req",
    0x2D: "L_Raw.ind",
    0x2F: "L_Raw.con",
    0xFC: "M_PropRead.req",
    0xFB: "M_PropRead.con",
    0xF6: "M_PropWrite.req",
    0xF5: "M_PropWrite.con",
    0xF7: "M_PropInfo.ind",
    0xF1: "M_Reset.req",
    0xF0: "M_Reset.ind",
}

# cEMI address type (from cemi.at field)
ADDR_TYPE_INDIVIDUAL = 0
ADDR_TYPE_GROUP = 1

# KNX medium types
KNX_MEDIUMS = {
    0x01: "TP0",
    0x02: "TP1",
    0x04: "PL110",
    0x08: "PL132",
    0x10: "RF",
    0x20: "IP",
}


def _format_individual_address(raw: int) -> str:
    """Format a 16-bit raw individual address as area.line.device."""
    area = (raw >> 12) & 0x0F
    line = (raw >> 8) & 0x0F
    device = raw & 0xFF
    return f"{area}.{line}.{device}"


def _format_group_address(raw: int) -> str:
    """Format a 16-bit raw group address as main/middle/sub (3-level)."""
    main = (raw >> 11) & 0x1F
    middle = (raw >> 8) & 0x07
    sub = raw & 0xFF
    return f"{main}/{middle}/{sub}"


def _parse_hex_int(value: str) -> Optional[int]:
    """Parse a hex or decimal string to int, returning None on failure."""
    if value is None:
        return None
    try:
        s = str(value).strip()
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError) as e:
        logger.debug(f"KNX: hex/decimal int parse failed for field value: {e}")
        return None


@dataclass
class KNXSession:
    """Track a KNX/IP communication session between two endpoints."""

    client_ip: str  # Tunneling client / routing peer
    gateway_ip: str  # KNX/IP gateway / routing peer
    services_seen: Set[int] = field(default_factory=set)
    service_families: Set[int] = field(default_factory=set)
    individual_addresses: Set[str] = field(default_factory=set)
    group_addresses: Set[str] = field(default_factory=set)
    apci_codes: Set[int] = field(default_factory=set)
    write_count: int = 0
    read_count: int = 0
    secure_seen: bool = False
    channel_id: Optional[int] = None
    protocol_version: Optional[str] = None
    first_seen: str = ""
    last_seen: str = ""


class KNXPassiveListener(PySharkListenerBase):
    """Passive KNX/IP traffic listener (PyShark-based).

    Monitors KNX/IP building automation traffic without sending packets to:
    - Identify KNX/IP gateways and tunneling clients
    - Track group address communication (the primary BAS data exchange)
    - Monitor APCI operations (read/write/response)
    - Extract data point values from group telegrams
    - Detect connection management (connect, disconnect, tunneling)
    - Flag security posture (KNX Secure vs plaintext)
    - Map individual addresses (area.line.device) to IPs

    tshark layers:
    - knxnetip (kip): KNXnet/IP service header
    - cemi: Common External Message Interface with KNX telegram

    Usage:
        listener = KNXPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for session in listener.sessions.values():
            print(f"{session.client_ip} -> {session.gateway_ip}")
            print(f"  Group addresses: {session.group_addresses}")
            print(f"  Writes: {session.write_count}")
    """

    PROTOCOL_NAME = "knx"
    DISPLAY_FILTER = "kip"
    REQUIRED_LAYERS = ("kip",)
    PROTOCOL_COLUMNS = ("rw", "service", "source", "destination", "apci", "value")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.sessions: Dict[Tuple[str, str], KNXSession] = {}
        # Track gateway device info from SEARCH/DESCRIPTION responses
        self._gateway_info: Dict[str, Dict[str, Any]] = {}

    def _get_kip_field(self, layer, field_name: str, default=None):
        """Get field from kip layer, trying knxip_ EK prefix first.

        In EK mode, kip layer fields are prefixed with knxip_ (e.g.,
        knxip.service -> attribute knxip_service). In XML mode, the short
        name works directly.
        """
        val = self.get_field(layer, f"knxip_{field_name}", None)
        if val is not None:
            return val
        return self.get_field(layer, field_name, default)

    def _get_cemi_field(self, layer, field_name: str, default=None):
        """Get field from cEMI layer, trying cemi_ EK prefix first.

        In EK mode, cemi layer fields are prefixed with cemi_ (e.g.,
        cemi.sa -> attribute cemi_sa). In XML mode, the short name works.
        """
        val = self.get_field(layer, f"cemi_{field_name}", None)
        if val is not None:
            return val
        return self.get_field(layer, field_name, default)

    def process_packet(self, packet) -> None:
        """Process a KNX/IP packet."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        src_mac, dst_mac = self.get_mac_info(packet)

        flow_id = self.get_flow_id(packet)

        if not hasattr(packet, "kip"):
            return

        kip_layer = packet.kip

        # Handle multi-PDU TCP segments (EK array: _fields_dict is a list)
        ek_dicts = self._get_ek_layer_dicts(kip_layer)
        if ek_dicts:
            self._process_ek_array(
                packet,
                ek_dicts,
                kip_layer,
                src_ip,
                dst_ip,
                src_mac,
                dst_mac,
                flow_id,
            )
            return

        self._process_single_kip(
            packet,
            kip_layer,
            src_ip,
            dst_ip,
            src_mac,
            dst_mac,
            flow_id,
        )

    def _process_single_kip(
        self,
        packet,
        kip_layer,
        src_ip: str,
        dst_ip: str,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
    ) -> None:
        """Process a single KNXnet/IP PDU (real or synthetic EkLayer)."""
        src_port, dst_port = self.get_port_info(packet)

        # Parse KNXnet/IP protocol version (knxip.version)
        version_raw = self._get_kip_field(kip_layer, "version")
        version_int = _parse_hex_int(version_raw)
        version_str = ""
        if version_int is not None:
            # Version 0x10 = 1.0, 0x20 = 2.0, etc.
            major = (version_int >> 4) & 0x0F
            minor = version_int & 0x0F
            version_str = f"{major}.{minor}"
        else:
            version_str = "?"
            self.logger.debug(f"Missing knxip.version in packet from {src_ip} -> {dst_ip}")

        # Parse KNXnet/IP service type (knxip.service)
        service_raw = self._get_kip_field(kip_layer, "service")
        if service_raw is None:
            # Fallback: knxip.service.type (knxip.service_type in EK)
            service_raw = self._get_kip_field(kip_layer, "service_type")
        service_type = _parse_hex_int(service_raw)
        if service_type is None:
            # Still record an interaction for unrecognized PDUs so coverage
            # tests don't see a silent drop.
            now = datetime.now().isoformat()
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                "KNX/IP (unknown service)",
                {"service_name": "unknown", "rw": ""},
                "KNX/IP unknown service type",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
            )
            return

        service_name = KNXIP_SERVICES.get(service_type, f"Unknown(0x{service_type:04x})")
        is_request = service_type in REQUEST_SERVICES
        direction = "request" if is_request else "response"

        # Parse service family (knxip.service.family)
        service_family_raw = self._get_kip_field(kip_layer, "service_family")
        service_family = _parse_hex_int(service_family_raw)

        # Determine client vs gateway based on service direction
        # Requests go from client to gateway; responses go from gateway to client
        if is_request:
            client_ip, gateway_ip = src_ip, dst_ip
            client_mac, gateway_mac = src_mac, dst_mac
        else:
            client_ip, gateway_ip = dst_ip, src_ip
            client_mac, gateway_mac = dst_mac, src_mac

        # Ensure session
        session = self._ensure_session(client_ip, gateway_ip)
        session.services_seen.add(service_type)

        # Track protocol version
        if version_str and version_str != "?":
            session.protocol_version = version_str

        # Track service family
        if service_family is not None:
            session.service_families.add(service_family)

        # Track KNX Secure usage
        if service_type in SECURE_SERVICES:
            session.secure_seen = True

        # Extract channel ID from connection management
        channel_raw = self._get_kip_field(kip_layer, "channel")
        if channel_raw is not None:
            channel_id = _parse_hex_int(channel_raw)
            if channel_id is not None:
                session.channel_id = channel_id

        # Extract gateway device information from discovery responses
        if service_type in (0x0202, 0x0204, 0x020C):
            self._extract_gateway_info(kip_layer, gateway_ip)

        # Process cEMI layer if present (tunneling/routing data)
        knx_src = ""
        knx_dst = ""
        apci_name = ""
        value_str = ""
        rw = ""

        if hasattr(packet, "cemi"):
            cemi_result = self._process_cemi(packet.cemi, session)
            if cemi_result:
                knx_src, knx_dst, apci_name, value_str, rw = cemi_result

        # If no APCI but we have a service-level operation, classify R/W
        if not rw:
            if service_type in (0x0201, 0x0203, 0x020B):
                rw = "read"  # Discovery/search
            elif service_type in (0x0310,):
                rw = "write"  # Configuration

        # Record interaction
        now = datetime.now().isoformat()
        details: Dict[str, Any] = {
            "service_type": service_type,
            "service_name": service_name,
            "version": version_str,
            "service_family": service_family,
            "knx_src": knx_src,
            "knx_dst": knx_dst,
            "apci": apci_name,
            "value": value_str,
            "rw": rw,
        }
        if session.channel_id is not None:
            details["channel"] = session.channel_id

        summary = self._build_summary(service_name, knx_src, knx_dst, apci_name, value_str)
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            service_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
        )

        # Update discovered devices
        self._update_devices(client_ip, client_mac, gateway_ip, gateway_mac, session)

    def _process_ek_array(
        self,
        packet,
        ek_dicts: List[dict],
        kip_layer,
        src_ip: str,
        dst_ip: str,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
    ) -> None:
        """Process multi-PDU TCP segments where _fields_dict is a list of dicts."""
        from pyshark.packet.layers.ek_layer import EkLayer as _EkLayer

        for fd in ek_dicts:
            synthetic = _EkLayer(kip_layer._layer_name, fd)
            self._process_single_kip(
                packet,
                synthetic,
                src_ip,
                dst_ip,
                src_mac,
                dst_mac,
                flow_id,
            )

    @staticmethod
    def _get_ek_layer_dicts(layer) -> Optional[List[dict]]:
        """Return the raw list of dicts when an EK layer wraps multiple PDUs.

        In PyShark's EK mode, multi-PDU TCP segments store ``_fields_dict``
        as a *list* of dicts instead of a single dict.  This helper detects
        the case and returns the list, or ``None`` for normal single-PDU layers.
        """
        try:
            fd = object.__getattribute__(layer, "_fields_dict")
            if isinstance(fd, list):
                return fd
        except AttributeError as e:
            logger.debug(f"KNX EK layer _fields_dict access failed: {e}")
        return None

    def _process_cemi(
        self, cemi_layer, session: KNXSession
    ) -> Optional[Tuple[str, str, str, str, str]]:
        """Process cEMI layer to extract KNX telegram details.

        Returns:
            Tuple of (knx_src, knx_dst, apci_name, value_str, rw) or None.
        """
        # Parse source and destination addresses
        src_raw = self._get_cemi_field(cemi_layer, "sa")
        dst_raw = self._get_cemi_field(cemi_layer, "da")
        addr_type_raw = self._get_cemi_field(cemi_layer, "at")

        knx_src = ""
        knx_dst = ""

        if src_raw is not None:
            src_int = _parse_hex_int(src_raw)
            if src_int is not None:
                knx_src = _format_individual_address(src_int)
                session.individual_addresses.add(knx_src)

        if dst_raw is not None:
            dst_int = _parse_hex_int(dst_raw)
            if dst_int is not None:
                # Determine address type: 0=individual, 1=group
                addr_type = _parse_hex_int(addr_type_raw)
                if addr_type == ADDR_TYPE_GROUP:
                    knx_dst = _format_group_address(dst_int)
                    session.group_addresses.add(knx_dst)
                else:
                    knx_dst = _format_individual_address(dst_int)
                    session.individual_addresses.add(knx_dst)

        # Parse APCI service code
        apci_raw = self._get_cemi_field(cemi_layer, "ac")
        apci_code = _parse_hex_int(apci_raw)
        apci_name = ""
        rw = ""

        if apci_code is not None:
            session.apci_codes.add(apci_code)
            apci_name = APCI_SERVICES.get(apci_code, f"APCI(0x{apci_code:x})")

            if apci_code in APCI_WRITE_CODES:
                rw = "write"
                session.write_count += 1
            elif apci_code in APCI_READ_CODES:
                rw = "read"
                session.read_count += 1
            elif apci_code in APCI_RESPONSE_CODES:
                rw = "response"

        # Extract data value from cEMI
        value_str = self._extract_cemi_value(cemi_layer, apci_code)

        return knx_src, knx_dst, apci_name, value_str, rw

    def _extract_cemi_value(self, cemi_layer, apci_code: Optional[int]) -> str:
        """Extract data value from the cEMI layer.

        For short data (6-bit APCI data field), the value is embedded in
        cemi.ad. For longer data, cemi.data contains the raw bytes.
        """
        # Short data (embedded in APCI for small values like 1-bit switches)
        ad_raw = self._get_cemi_field(cemi_layer, "ad")
        if ad_raw is not None:
            ad_int = _parse_hex_int(ad_raw)
            if ad_int is not None:
                # For GroupValueWrite/Response with small data, decode as value
                if apci_code in (0x1, 0x2):  # GroupValueResponse, GroupValueWrite
                    # Mask the lower 6 bits (APCI data field)
                    data_val = ad_int & 0x3F
                    return str(data_val)

        # Longer data payload
        data_raw = self._get_cemi_field(cemi_layer, "data")
        if data_raw is not None:
            data_str = str(data_raw).replace(":", "")
            if data_str and len(data_str) <= 16:
                return f"0x{data_str}"
            elif data_str:
                return f"0x{data_str}"

        return ""

    def _extract_gateway_info(self, kip_layer, gateway_ip: str) -> None:
        """Extract device information from SEARCH/DESCRIPTION responses."""
        info: Dict[str, Any] = self._gateway_info.get(gateway_ip, {})

        # Friendly name (knxip.device.name → knxip_device_name in EK)
        name = self._get_kip_field(kip_layer, "device_name")
        if name:
            info["name"] = str(name)

        # KNX individual address of the gateway
        knx_addr_raw = self._get_kip_field(kip_layer, "knxaddr")
        if knx_addr_raw is not None:
            knx_addr_int = _parse_hex_int(knx_addr_raw)
            if knx_addr_int is not None:
                info["knx_address"] = _format_individual_address(knx_addr_int)

        # Serial number
        serial = self._get_kip_field(kip_layer, "sernr")
        if serial:
            info["serial"] = str(serial)

        # MAC address
        mac = self._get_kip_field(kip_layer, "macaddr")
        if mac:
            info["mac"] = str(mac)

        # KNX medium
        medium_raw = self._get_kip_field(kip_layer, "medium")
        if medium_raw is not None:
            medium_int = _parse_hex_int(medium_raw)
            if medium_int is not None:
                info["medium"] = KNX_MEDIUMS.get(medium_int, f"0x{medium_int:02x}")

        # Manufacturer code
        mfr_raw = self._get_kip_field(kip_layer, "manufacturer")
        if mfr_raw is not None:
            info["manufacturer_code"] = str(mfr_raw)

        # Programming mode
        progmode = self._get_kip_field(kip_layer, "progmode")
        if progmode is not None:
            info["programming_mode"] = str(progmode) in ("1", "True")

        # Multicast address
        mcaddr = self._get_kip_field(kip_layer, "mcaddr")
        if mcaddr:
            info["multicast_address"] = str(mcaddr)

        if info:
            self._gateway_info[gateway_ip] = info

    def _ensure_session(self, client_ip: str, gateway_ip: str) -> KNXSession:
        """Ensure a session exists and return it."""
        key = (client_ip, gateway_ip)
        now = datetime.now().isoformat()

        if key not in self.sessions:
            self.sessions[key] = KNXSession(
                client_ip=client_ip,
                gateway_ip=gateway_ip,
                first_seen=now,
                last_seen=now,
            )

        session = self.sessions[key]
        session.last_seen = now
        return session

    def _update_devices(
        self,
        client_ip: str,
        client_mac: str,
        gateway_ip: str,
        gateway_mac: str,
        session: KNXSession,
    ) -> None:
        """Update discovered device entries."""
        # Gateway device
        if is_valid_discovered_ip(gateway_ip):
            gw_info = self._gateway_info.get(gateway_ip, {})
            gw_vendor = lookup_mac_vendor(gateway_mac) if gateway_mac else ""
            gw_name = gw_info.get("name", "")

            key = f"knx-gateway:{gateway_ip}"
            device, is_new = self._ensure_device(
                key,
                gateway_ip,
                mac=gateway_mac,
                name=gw_name,
                device_type="KNX/IP Gateway",
                manufacturer=gw_vendor if gw_vendor else "",
            )
            device.knx_passive_data = self._build_device_data("gateway", session, gw_info)
            if is_new:
                self.logger.debug(
                    f"KNX: Gateway {gateway_ip}"
                    + (f" ({gw_name})" if gw_name else "")
                    + f" groups={len(session.group_addresses)}"
                )

        # Client device
        if is_valid_discovered_ip(client_ip):
            client_vendor = lookup_mac_vendor(client_mac) if client_mac else ""

            key = f"knx-client:{client_ip}"
            device, is_new = self._ensure_device(
                key,
                client_ip,
                mac=client_mac,
                device_type="KNX/IP Client",
                manufacturer=client_vendor if client_vendor else "",
            )
            device.knx_passive_data = self._build_device_data("client", session)
            if is_new:
                self.logger.debug(f"KNX: Client {client_ip}")

    def _build_device_data(
        self,
        role: str,
        session: KNXSession,
        gateway_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build knx_passive_data dict from session."""
        data: Dict[str, Any] = {
            "role": role,
            "services_seen": [
                KNXIP_SERVICES.get(s, f"0x{s:04x}") for s in sorted(session.services_seen)
            ],
            "service_families": sorted(session.service_families),
            "individual_addresses": sorted(session.individual_addresses),
            "group_addresses": sorted(session.group_addresses),
            "apci_operations": [
                APCI_SERVICES.get(a, f"0x{a:x}") for a in sorted(session.apci_codes)
            ],
            "write_operations": session.write_count,
            "read_operations": session.read_count,
            "secure_seen": session.secure_seen,
            "protocol": "KNX/IP",
            "first_seen": session.first_seen,
            "last_seen": session.last_seen,
        }
        if session.protocol_version:
            data["protocol_version"] = session.protocol_version
        if session.channel_id is not None:
            data["channel_id"] = session.channel_id
        if gateway_info:
            data["gateway_info"] = gateway_info
        return data

    @staticmethod
    def _build_summary(
        service_name: str,
        knx_src: str,
        knx_dst: str,
        apci_name: str,
        value_str: str,
    ) -> str:
        """Build a one-line human-readable interaction summary."""
        parts = [service_name]
        if knx_src and knx_dst:
            parts.append(f"{knx_src}->{knx_dst}")
        elif knx_src:
            parts.append(f"from {knx_src}")
        if apci_name:
            parts.append(apci_name)
        if value_str:
            parts.append(f"val={value_str}")
        return " ".join(parts)

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format interaction as table row matching PROTOCOL_COLUMNS."""
        d = ix.details
        return [
            d.get("rw", ""),
            d.get("service_name", ""),
            d.get("knx_src", ""),
            d.get("knx_dst", ""),
            d.get("apci", ""),
            d.get("value", ""),
        ]

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed KNX/IP sessions."""
        results = []
        for session in self.sessions.values():
            results.append(
                {
                    "client": session.client_ip,
                    "gateway": session.gateway_ip,
                    "group_addresses": sorted(session.group_addresses),
                    "individual_addresses": sorted(session.individual_addresses),
                    "write_count": session.write_count,
                    "read_count": session.read_count,
                    "secure": session.secure_seen,
                }
            )
        return results

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with write operations."""
        return [
            {
                "client": session.client_ip,
                "server": session.gateway_ip,
                "write_count": session.write_count,
                "write_apci": [
                    APCI_SERVICES.get(a, f"0x{a:x}")
                    for a in session.apci_codes
                    if a in APCI_WRITE_CODES
                ],
                "group_addresses_written": sorted(session.group_addresses),
            }
            for session in self.sessions.values()
            if session.write_count > 0
        ]
