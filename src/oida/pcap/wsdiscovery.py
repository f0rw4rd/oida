"""
WS-Discovery Passive Listener for network device discovery.

Passively captures WS-Discovery traffic to extract:
- Device types (ONVIF cameras, printers, scanners)
- Endpoint references (unique device identifiers)
- Scopes (device metadata URIs)
- Transport addresses (XAddrs)
- Metadata versions

WS-Discovery uses:
- Multicast: 239.255.255.250
- UDP port: 3702
- SOAP over UDP

Message types:
- Probe: Client searching for devices by type/scope
- ProbeMatch: Device responding to probe
- Hello: Device announcing itself
- Bye: Device leaving the network
- Resolve: Client resolving endpoint reference
- ResolveMatch: Device responding to resolve

Security value for ICS:
- Network device discovery (ONVIF cameras, printers)
- IoT device enumeration
- PROFINET device detection via WS-Discovery
- Uncontrolled device announcements

tshark dissection notes:
    tshark may dissect WS-Discovery as either:
    - ``wsdiscovery`` layer (with heuristic detection)
    - ``xml`` layer on UDP port 3702 (fallback)
    This listener supports both dissection modes by checking the
    ``wsdiscovery`` layer first, then falling back to ``xml`` layer
    parsing when packets arrive on port 3702.

PyShark field reference:
    When dissected as wsdiscovery:
    - wsd.types, wsd.endpoint_reference, wsd.scopes, wsd.xaddrs
    When dissected as XML:
    - xml.tag contains SOAP envelope tags with wsd: prefixed elements
    - xml.value / xml.cdata contain text content
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

# WS-Discovery constants
WSD_PORT = 3702

# WS-Discovery action types (extracted from SOAP action header)
WSD_ACTIONS = {
    "Probe": "Probe",
    "ProbeMatches": "ProbeMatch",
    "Hello": "Hello",
    "Bye": "Bye",
    "Resolve": "Resolve",
    "ResolveMatches": "ResolveMatch",
}

# Common WS-Discovery device type prefixes
DEVICE_TYPE_PREFIXES = {
    "dn:NetworkVideoTransmitter": "ONVIF Camera",
    "dp:PrintDeviceType": "Printer",
    "ds:ScanDeviceType": "Scanner",
    "wsdp:Device": "WSD Device",
    "pub:Computer": "Computer",
    "tns:NetworkVideoTransmitter": "ONVIF Camera",
}


class WSDiscoveryPassiveListener(PySharkListenerBase):
    """Passive WS-Discovery traffic listener for device enumeration.

    Captures WS-Discovery multicast traffic to discover:
    - ONVIF cameras and video transmitters
    - Printers and scanners
    - Generic WSD devices
    - Device endpoint references and transport addresses
    - Device type classification

    Handles two tshark dissection modes:
    - Native ``wsdiscovery`` layer (when heuristic matches)
    - ``xml`` layer on UDP port 3702 (fallback)

    Usage:
        listener = WSDiscoveryPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for key, device in listener.discovered_devices.items():
            print(f"{device.ip_addresses} - {device.device_type}")
    """

    PROTOCOL_NAME = "wsdiscovery"
    # WS-Discovery is dissected as XML on UDP port 3702 by tshark
    DISPLAY_FILTER = "xml && udp.port == 3702"
    REQUIRED_LAYERS = ()  # Handled by should_process_packet
    PROTOCOL_COLUMNS = (
        "action",
        "types",
        "endpoint",
        "xaddrs",
        "scopes",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)

    def should_process_packet(self, packet) -> bool:
        """Check if packet is WS-Discovery traffic.

        Accepts packets with native ``wsdiscovery`` layer, or XML
        packets on UDP port 3702 that contain WS-Discovery SOAP content.
        """
        if hasattr(packet, "wsdiscovery"):
            return True
        # Fallback: XML on UDP port 3702
        if hasattr(packet, "xml") and hasattr(packet, "udp"):
            try:
                src_port = int(packet.udp.srcport)
                dst_port = int(packet.udp.dstport)
                if src_port == WSD_PORT or dst_port == WSD_PORT:
                    return True
            except (ValueError, AttributeError) as e:
                self.logger.debug(f"Failed to get src_port: {e}")
        return False

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format WS-Discovery interaction as protocol-specific table columns."""
        d = ix.details
        action = d.get("action", "?")
        types = d.get("types", "") or "-"
        endpoint = d.get("endpoint_reference", "") or "-"
        xaddrs = d.get("xaddrs", "") or "-"
        scopes = d.get("scopes", "") or "-"
        return [
            action,
            types,
            endpoint,
            xaddrs,
            scopes,
        ]

    def process_packet(self, packet) -> None:
        """Process WS-Discovery packet and extract device information."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        # Extract WS-Discovery fields from either native or XML layer
        wsd_info = self._extract_wsd_fields(packet)
        if not wsd_info:
            return

        action = wsd_info.get("action", "Unknown")
        is_response = action in ("ProbeMatch", "ResolveMatch", "Hello")
        direction = "response" if is_response else "request"

        # Build interaction details
        details: Dict[str, Any] = {
            "action": action,
            "types": wsd_info.get("types", ""),
            "endpoint_reference": wsd_info.get("endpoint_reference", ""),
            "scopes": wsd_info.get("scopes", ""),
            "xaddrs": wsd_info.get("xaddrs", ""),
            "metadata_version": wsd_info.get("metadata_version", ""),
        }

        now = datetime.now().isoformat()
        types_str = wsd_info.get("types", "")
        summary = f"WSD {action} {src_ip}"
        if types_str:
            summary += f" types={types_str}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            f"WSD {action}",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Track devices from announcements and responses
        if not is_valid_discovered_ip(src_ip):
            return

        device_type = self._classify_device_type(types_str)
        endpoint_ref = wsd_info.get("endpoint_reference", "")

        device_key = f"wsd:{endpoint_ref}" if endpoint_ref else f"wsd:{src_ip}"
        vendor = lookup_mac_vendor(src_mac) if src_mac else ""

        device, is_new = self._ensure_device(
            device_key,
            src_ip,
            mac=src_mac or "",
            name=endpoint_ref or "",
            device_type=device_type,
            manufacturer=vendor if vendor != "Unknown" else "",
        )
        if is_new:
            device.wsdiscovery_data = {
                "action": action,
                "types": types_str,
                "endpoint_reference": endpoint_ref,
                "scopes": wsd_info.get("scopes", ""),
                "xaddrs": wsd_info.get("xaddrs", ""),
                "metadata_version": wsd_info.get("metadata_version", ""),
                "protocol": "WS-Discovery/UDP",
            }
            self.logger.debug(
                f"WS-Discovery: {src_ip} {action} type={device_type} endpoint={endpoint_ref}"
            )
        else:
            # Update existing device with new info
            data = getattr(device, "wsdiscovery_data", None)
            if data:
                if types_str and not data.get("types"):
                    data["types"] = types_str
                xaddrs = wsd_info.get("xaddrs", "")
                if xaddrs and not data.get("xaddrs"):
                    data["xaddrs"] = xaddrs

    def _extract_wsd_fields(self, packet) -> Optional[Dict[str, str]]:
        """Extract WS-Discovery fields from packet.

        Attempts native wsdiscovery layer first, then falls back to
        parsing XML tags on port 3702.
        """
        # Try native wsdiscovery layer
        layer = getattr(packet, "wsdiscovery", None)
        if layer is not None:
            return self._extract_from_native_layer(layer, packet)

        # Fallback: parse XML layer on port 3702
        xml_layer = getattr(packet, "xml", None)
        if xml_layer is not None:
            return self._extract_from_xml_layer(xml_layer)

        return None

    def _extract_from_native_layer(self, layer, packet) -> Optional[Dict[str, str]]:
        """Extract fields from native wsdiscovery tshark layer."""
        result: Dict[str, str] = {}

        # Determine action type
        all_fields = self.get_all_fields(layer)
        action = "Unknown"
        for key, val in all_fields.items():
            val_str = str(val).lower()
            for action_key, action_name in WSD_ACTIONS.items():
                if action_key.lower() in key.lower() or action_key.lower() in val_str:
                    action = action_name
                    break
            if action != "Unknown":
                break
        result["action"] = action

        result["types"] = str(self.get_field(layer, "types", "") or "")
        endpoint_ref = str(self.get_field(layer, "endpoint_reference", "") or "")
        if not endpoint_ref:
            endpoint_ref = str(self.get_field(layer, "address", "") or "")
        result["endpoint_reference"] = endpoint_ref
        result["scopes"] = str(self.get_field(layer, "scopes", "") or "")
        result["xaddrs"] = str(self.get_field(layer, "xaddrs", "") or "")
        result["metadata_version"] = str(self.get_field(layer, "metadata_version", "") or "")

        return result

    def _extract_from_xml_layer(self, xml_layer) -> Optional[Dict[str, str]]:
        """Extract WS-Discovery fields from XML tags on port 3702.

        When tshark dissects WS-Discovery as plain XML, the SOAP envelope
        tags are available via xml.tag.  We parse these to identify the
        WSD action and extract device metadata.
        """
        result: Dict[str, str] = {}

        # Get all XML fields to look for wsd: prefixed tags
        all_fields = self.get_all_fields(xml_layer)

        # Also try xml.tag field which contains comma-separated tag list
        tags_str = str(self.get_field(xml_layer, "tag", "") or "")
        # xml.value or xml.cdata may contain text content
        value_str = str(self.get_field(xml_layer, "value", "") or "")
        cdata = str(self.get_field(xml_layer, "cdata", "") or "")

        # Combine all text content for searching
        all_text = ""
        for _key, val in all_fields.items():
            all_text += " " + str(val)
        all_text += " " + tags_str + " " + value_str + " " + cdata

        # Determine action from SOAP Action header or element names
        action = "Unknown"
        for action_key, action_name in WSD_ACTIONS.items():
            # Check for action in wsa:Action text or element name
            if f"discovery/{action_key}" in all_text or f"wsd:{action_key}" in all_text:
                action = action_name
                break
        result["action"] = action

        # Extract device types from wsd:Types element content
        types = self._extract_xml_element_text(all_text, "wsd:Types")
        result["types"] = types

        # Extract endpoint reference from wsa:Address inside EndpointReference
        endpoint_ref = self._extract_xml_element_text(all_text, "wsa:Address")
        # Filter out well-known non-device addresses
        if endpoint_ref and "schemas-xmlsoap-org" in endpoint_ref:
            endpoint_ref = ""
        if endpoint_ref and "role/anonymous" in endpoint_ref:
            endpoint_ref = ""
        result["endpoint_reference"] = endpoint_ref

        # Extract scopes
        scopes = self._extract_xml_element_text(all_text, "wsd:Scopes")
        result["scopes"] = scopes

        # Extract XAddrs
        xaddrs = self._extract_xml_element_text(all_text, "wsd:XAddrs")
        result["xaddrs"] = xaddrs

        # Extract MetadataVersion
        metadata_version = self._extract_xml_element_text(all_text, "wsd:MetadataVersion")
        result["metadata_version"] = metadata_version

        # Verify we got something useful
        if action == "Unknown" and not any(
            result.get(k) for k in ("types", "endpoint_reference", "xaddrs")
        ):
            return None

        return result

    @staticmethod
    def _extract_xml_element_text(all_text: str, element_name: str) -> str:
        """Extract text content from an XML element in concatenated field text.

        This is a heuristic parser for pyshark's XML layer representation.
        The xml.tag field contains tag names, and content appears in the
        concatenated all_fields or value/cdata fields following the tag.
        """
        # Look for content that follows the element tag in the text
        # PyShark may expose it differently depending on the mode
        import re

        # Try to find content between element tags in the raw text
        # Pattern: <element>content</element> or element,content,/element
        short_name = element_name.split(":")[-1] if ":" in element_name else element_name

        # Check if the element name appears at all
        if element_name not in all_text and short_name not in all_text:
            return ""

        # Try regex for content after element reference
        # In pyshark XML mode, tags and content are sometimes separated by commas
        for pattern in [
            rf"<{re.escape(element_name)}>([^<]+)</{re.escape(element_name)}>",
            rf"<{re.escape(element_name)}[^>]*>([^<]+)",
        ]:
            match = re.search(pattern, all_text)
            if match:
                return match.group(1).strip()

        return ""

    def _classify_device_type(self, types_str: str) -> str:
        """Classify device type from WS-Discovery types string."""
        if not types_str:
            return "WSD Device"

        for prefix, device_type in DEVICE_TYPE_PREFIXES.items():
            if prefix.lower() in types_str.lower():
                return device_type

        if "video" in types_str.lower() or "camera" in types_str.lower():
            return "ONVIF Camera"
        if "print" in types_str.lower():
            return "Printer"
        if "scan" in types_str.lower():
            return "Scanner"

        return "WSD Device"
