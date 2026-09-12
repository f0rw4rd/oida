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

# WSD_ACTIONS sorted longest-key-first for substring matching below.
# "ProbeMatches"/"ResolveMatches" must be checked before their shorter
# prefixes "Probe"/"Resolve" -- dict insertion order (shorter keys first)
# made a ProbeMatches/ResolveMatches response match the shorter *request*
# key first (e.g. "discovery/Probe" is a substring of
# "discovery/ProbeMatches") and get mislabeled as the client-side action.
WSD_ACTIONS_BY_LEN = sorted(WSD_ACTIONS.items(), key=lambda kv: len(kv[0]), reverse=True)

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
    # Include the native wsdiscovery-layer path: an "xml && ..."-only filter
    # excludes packets tshark dissects as the native wsdiscovery layer (which
    # lack an xml layer) during LIVE capture, so should_process_packet's native
    # branch was unreachable live. Let should_process_packet do the final gating.
    DISPLAY_FILTER = "wsdiscovery || (xml && udp.port == 3702)"
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

        # Fallback: parse XML on port 3702. Parse the raw SOAP payload
        # (udp.payload) directly -- tshark's flattened xml.tag/xml.cdata field
        # lists are NOT index-aligned (container elements emit a tag but no
        # cdata, so a positional zip shifts every leaf's text onto the wrong
        # element), and the default PDML live capture collapses those repeated
        # fields to a single value, extracting nothing at all. The raw UDP
        # payload carries the whole envelope in every dissection mode.
        parsed = self._extract_from_soap_payload(packet)
        if parsed is not None:
            return parsed

        xml_layer = getattr(packet, "xml", None)
        if xml_layer is not None:
            return self._extract_from_xml_layer(xml_layer)

        return None

    @staticmethod
    def _hex_field_to_bytes(value: Any) -> bytes:
        """Decode a tshark hex field (``3c:3f:78`` / ``3c3f78`` / spaced) to bytes."""
        if value is None:
            return b""
        s = str(value)
        hex_str = "".join(ch for ch in s if ch in "0123456789abcdefABCDEF")
        if len(hex_str) % 2:
            hex_str = hex_str[:-1]
        try:
            return bytes.fromhex(hex_str)
        except ValueError:
            return b""

    def _extract_from_soap_payload(self, packet) -> Optional[Dict[str, str]]:
        """Parse the raw SOAP/UDP payload as XML and extract WSD fields.

        Robust across tshark dissection modes because it reads the full envelope
        from udp.payload rather than the mis-aligned/collapsed xml.tag+xml.cdata
        field pair (see _extract_wsd_fields). Returns None when no payload or no
        useful field could be recovered, so callers can fall back.
        """
        import xml.etree.ElementTree as ET

        udp_layer = getattr(packet, "udp", None)
        if udp_layer is None:
            return None
        raw = self._hex_field_to_bytes(self.get_field_any(udp_layer, "payload", default=""))
        if not raw:
            return None
        text = raw.decode("utf-8", "replace")
        start = text.find("<")
        if start < 0:
            return None
        try:
            root = ET.fromstring(text[start:])
        except ET.ParseError:
            return None

        def _local(tag: str) -> str:
            return tag.rsplit("}", 1)[-1] if "}" in tag else tag

        fields: Dict[str, str] = {}
        endpoint_ref = ""
        action_text = ""
        action_elems: List[str] = []
        for el in root.iter():
            name = _local(el.tag)
            val = (el.text or "").strip()
            if name in WSD_ACTIONS:
                action_elems.append(name)
            if name == "Action":
                action_text = val
            elif name == "Address" and not endpoint_ref and val:
                endpoint_ref = val
            elif name in ("Types", "Scopes", "XAddrs", "MetadataVersion") and val:
                fields.setdefault(name, val)

        # Action: longest key first so "ProbeMatches" wins over "Probe".
        haystack = action_text + " " + " ".join(action_elems)
        action = "Unknown"
        for action_key, action_name in WSD_ACTIONS_BY_LEN:
            if action_key in haystack:
                action = action_name
                break

        if endpoint_ref and (
            "schemas-xmlsoap-org" in endpoint_ref or "role/anonymous" in endpoint_ref
        ):
            endpoint_ref = ""

        result = {
            "action": action,
            "types": fields.get("Types", ""),
            "endpoint_reference": endpoint_ref,
            "scopes": fields.get("Scopes", ""),
            "xaddrs": fields.get("XAddrs", ""),
            "metadata_version": fields.get("MetadataVersion", ""),
        }
        if action == "Unknown" and not any(
            result[k] for k in ("types", "endpoint_reference", "xaddrs")
        ):
            return None
        return result

    def _extract_from_native_layer(self, layer, packet) -> Optional[Dict[str, str]]:
        """Extract fields from native wsdiscovery tshark layer."""
        result: Dict[str, str] = {}

        # Determine action type
        all_fields = self.get_all_fields(layer)
        action = "Unknown"
        for key, val in all_fields.items():
            val_str = str(val).lower()
            for action_key, action_name in WSD_ACTIONS_BY_LEN:
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

    def _xml_tag_text_map(self, xml_layer) -> Dict[str, str]:
        """Map each XML element tag to its character-data text.

        tshark's XML dissector exposes element tags (xml.tag) and their text
        (xml.chardata) as parallel, index-aligned occurrences. pyshark's flat
        field VALUES do NOT contain the surrounding <tag>...</tag> markup, so we
        must zip the discrete tag/text field lists rather than regex a
        reconstructed string (which almost never has the < > delimiters).
        """

        def _as_list(field: str) -> list:
            raw = self._resolve_value(getattr(xml_layer, field, None), None)
            if raw is None:
                return []
            return list(raw) if isinstance(raw, (list, tuple)) else [raw]

        tags = _as_list("tag")
        texts = _as_list("chardata") or _as_list("value") or _as_list("cdata")

        mapping: Dict[str, str] = {}
        for tag, text in zip(tags, texts):
            t = str(self._resolve_value(tag, "")).strip()
            if t and not mapping.get(t):
                mapping[t] = str(self._resolve_value(text, "")).strip()
        return mapping

    def _extract_from_xml_layer(self, xml_layer) -> Optional[Dict[str, str]]:
        """Extract WS-Discovery fields from XML tags on port 3702.

        When tshark dissects WS-Discovery as plain XML, the SOAP envelope tags
        are available via xml.tag with text in xml.chardata. We map tag->text
        from those discrete fields (see _xml_tag_text_map) to identify the WSD
        action and extract device metadata.
        """
        result: Dict[str, str] = {}

        tag_text = self._xml_tag_text_map(xml_layer)

        # For action detection: the verb lives in a wsa:Action element text
        # (a discovery/<verb> URI) or a tag name; search both plus the raw
        # field dump as a safety net.
        all_text = " ".join(tag_text.keys()) + " " + " ".join(tag_text.values())
        for val in self.get_all_fields(xml_layer).values():
            all_text += " " + str(val)

        # Determine action from SOAP Action header or element names
        action = "Unknown"
        for action_key, action_name in WSD_ACTIONS_BY_LEN:
            if f"discovery/{action_key}" in all_text or f"wsd:{action_key}" in all_text:
                action = action_name
                break
        result["action"] = action

        def _elem(name: str) -> str:
            # Discrete field first (prefixed then short tag), then a last-resort
            # markup regex for the rare pyshark build that exposes it.
            short = name.split(":")[-1] if ":" in name else name
            for key in (name, short):
                if tag_text.get(key):
                    return tag_text[key]
            return self._extract_xml_element_text(all_text, name)

        result["types"] = _elem("wsd:Types")

        endpoint_ref = _elem("wsa:Address")
        # Filter out well-known non-device addresses
        if endpoint_ref and (
            "schemas-xmlsoap-org" in endpoint_ref or "role/anonymous" in endpoint_ref
        ):
            endpoint_ref = ""
        result["endpoint_reference"] = endpoint_ref

        result["scopes"] = _elem("wsd:Scopes")
        result["xaddrs"] = _elem("wsd:XAddrs")
        result["metadata_version"] = _elem("wsd:MetadataVersion")

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
