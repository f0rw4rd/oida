"""
SSDP (Simple Service Discovery Protocol) passive listener.

SSDP is part of UPnP and used for discovering network services.

SSDP uses:
- Multicast: 239.255.255.250
- UDP port: 1900
- HTTP-like message format

Message types:
- NOTIFY: Device/service announcements (ssdp:alive, ssdp:byebye)
- M-SEARCH: Service discovery queries
- HTTP/1.1 200 OK: M-SEARCH responses

Useful for discovering:
- UPnP devices (routers, media players, IoT)
- Service types and locations
- Server software and versions
- Device descriptions via LOCATION URLs
- Unique Service Names (USN)

Uses PyShark (tshark wrapper) for SSDP packet dissection.

PyShark SSDP field reference:
SSDP may appear as an "ssdp" layer or within "http" layer on port 1900.
Common fields:
- http.request.method: NOTIFY or M-SEARCH
- http.response.code: 200 (for M-SEARCH responses)
- http.server: Server header
- http.location: Location URL
- ssdp.usn: Unique Service Name
- ssdp.st: Search Target
- ssdp.nt: Notification Type
- ssdp.nts: Notification Sub-Type (ssdp:alive, ssdp:byebye)
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip

# SSDP constants
SSDP_MULTICAST_ADDR = "239.255.255.250"
SSDP_PORT = 1900


class SSDPPassiveListener(PySharkListenerBase):
    """Passive SSDP traffic listener using PyShark.

    Listens for SSDP multicast traffic to discover:
    - UPnP devices and services
    - Server software versions
    - Service locations (URLs)
    - Unique Service Names

    Usage:
        # Live capture
        listener = SSDPPassiveListener(interface="eth0", timeout=30)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = SSDPPassiveListener(interface="eth0")
        listener.feed_packet(mock_ssdp_packet)
    """

    PROTOCOL_NAME = "ssdp"
    DISPLAY_FILTER = "ssdp"
    REQUIRED_LAYERS = ("ssdp",)
    PROTOCOL_COLUMNS = (
        "type",
        "server",
        "st_nt",
        "location",
        "usn",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger=None,
    ):
        super().__init__(interface, timeout, nxc_logger)

    def should_process_packet(self, packet) -> bool:
        """Check if packet is SSDP traffic.

        SSDP can appear as 'ssdp' layer or as 'http' on port 1900.
        """
        if hasattr(packet, "ssdp"):
            return True
        # Fall back to checking for HTTP on port 1900
        if hasattr(packet, "http"):
            src_port, dst_port = self.get_port_info(packet)
            if src_port == SSDP_PORT or dst_port == SSDP_PORT:
                return True
        return False

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format SSDP protocol-specific columns."""
        d = ix.details
        msg_type = d.get("msg_type", "")
        if not msg_type:
            msg_type = "?"
            self.logger.debug(f"Missing msg_type in SSDP interaction from {ix.src_ip}")
        server = d.get("server", "") or "-"
        st_nt = d.get("nt", "") or d.get("st", "") or "-"
        location = d.get("location", "") or "-"
        usn = d.get("usn", "") or "-"
        return [
            msg_type,
            server,
            st_nt,
            location,
            usn,
        ]

    def process_packet(self, packet) -> None:
        """Process captured SSDP packet using PyShark."""
        # Get IP info
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        stream_id = self.get_stream_id(packet)
        src_mac, _ = self.get_mac_info(packet)

        # Extract SSDP fields from either ssdp or http layer
        ssdp_info = self._extract_ssdp_fields(packet)
        if not ssdp_info:
            return

        msg_type = ssdp_info.get("msg_type", "UNKNOWN")

        # Record interaction
        now = datetime.now().isoformat()
        direction = "response" if msg_type == "RESPONSE" else "request"
        nt_or_st = ssdp_info.get("nt", "") or ssdp_info.get("st", "")
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            f"SSDP {msg_type}",
            ssdp_info,
            f"SSDP {msg_type} {src_ip} {nt_or_st}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Skip multicast/broadcast for device tracking
        if not is_valid_discovered_ip(src_ip):
            return

        # Create/update device
        device_key = src_mac if src_mac else f"ssdp:{src_ip}"

        server = ssdp_info.get("server", "")
        location = ssdp_info.get("location", "")
        usn = ssdp_info.get("usn", "")

        device, is_new = self._ensure_device(
            device_key,
            src_ip,
            mac=src_mac if src_mac else "",
            name="",
            device_type="UPnP Device",
        )
        if is_new:
            device.ssdp_data = {
                "msg_type": msg_type,
                "server": server,
                "location": location,
                "usn": usn,
                "nt": ssdp_info.get("nt", ""),
                "st": ssdp_info.get("st", ""),
                "nts": ssdp_info.get("nts", ""),
                "cache_control": ssdp_info.get("cache_control", ""),
                "protocol": "SSDP/UDP",
            }
            self.logger.debug(f"SSDP: {src_ip} {msg_type} server={server} nt={nt_or_st}")

    # ------------------------------------------------------------------
    # EK-mode direct field access
    # ------------------------------------------------------------------

    @staticmethod
    def _ek_get(layer, key: str, default: str = "") -> str:
        """Read a field directly from the EkLayer ``_fields_dict``.

        In EK mode the SSDP layer carries HTTP fields with the
        ``http_http_`` prefix.  Standard ``get_field`` / ``getattr`` fail
        because pyshark has no type mapping for the ``ssdp`` protocol,
        so ``all_field_names`` is empty and ``_get_field_value`` raises
        ``FieldNotFound``.  Accessing ``_fields_dict`` directly bypasses
        both problems.
        """
        fd = getattr(layer, "_fields_dict", None)
        if fd is None:
            return default
        val = fd.get(key)
        if val is None:
            return default
        if isinstance(val, list):
            return ",".join(str(v) for v in val)
        return str(val)

    @staticmethod
    def _ek_get_list(layer, key: str) -> List[str]:
        """Read a list-valued field from ``_fields_dict``.

        Returns an empty list when the key is missing or the value is
        not a list.
        """
        fd = getattr(layer, "_fields_dict", None)
        if fd is None:
            return []
        val = fd.get(key)
        if isinstance(val, list):
            return [str(v) for v in val]
        if val is not None:
            return [str(val)]
        return []

    def _extract_ssdp_fields(self, packet) -> Optional[Dict[str, str]]:
        """Extract SSDP fields from packet layers.

        PyShark stores SSDP fields with ``http.`` prefix in the ssdp layer.
        In XML mode, attributes are accessed as ``http_*`` (dots become
        underscores).  In EK mode, the ssdp layer's ``_fields_dict``
        contains keys with ``http_http_`` prefix (the layer has no type
        mapping so ``get_field`` / ``get_all_fields`` return nothing).
        NT, USN, NTS may appear inside ``http.unknown_header`` or
        ``http_http_unknown_header`` as raw text lines, or in
        ``http_http_request_line`` for M-SEARCH packets.
        """
        # The SSDP layer stores fields with http.* prefix
        layer = getattr(packet, "ssdp", None) or getattr(packet, "http", None)
        if layer is None:
            return None

        # ----------------------------------------------------------
        # Detect EK mode: _fields_dict present + all_field_names empty
        # ----------------------------------------------------------
        ek_mode = hasattr(layer, "_fields_dict") and not getattr(layer, "all_field_names", None)

        if ek_mode:
            return self._extract_ssdp_fields_ek(layer)

        # ----------------------------------------------------------
        # XML mode (original path)
        # ----------------------------------------------------------
        return self._extract_ssdp_fields_xml(layer)

    def _extract_ssdp_fields_ek(self, layer) -> Optional[Dict[str, str]]:
        """Extract SSDP fields from an EK-mode layer via ``_fields_dict``.

        Keys use the ``http_http_`` prefix.  Lists (request_line,
        unknown_header) contain raw header strings like
        ``"ST:urn:...\r\n"``.
        """
        result: Dict[str, str] = {}

        method = self._ek_get(layer, "http_http_request_method")
        response_code = self._ek_get(layer, "http_http_response_code")

        if method == "NOTIFY":
            result["msg_type"] = "NOTIFY"
        elif method == "M-SEARCH":
            result["msg_type"] = "M-SEARCH"
        elif response_code == "200":
            result["msg_type"] = "RESPONSE"
        else:
            result["msg_type"] = method or "UNKNOWN"

        # Direct scalar fields
        result["server"] = self._ek_get(layer, "http_http_server")
        result["location"] = self._ek_get(layer, "http_http_location")
        result["cache_control"] = self._ek_get(layer, "http_http_cache_control")

        # Parse NT/USN/NTS/ST from unknown_header list (NOTIFY packets)
        for line in self._ek_get_list(layer, "http_http_unknown_header"):
            self._parse_ssdp_header_line(line, result)

        # Parse ST/MAN/MX from request_line list (M-SEARCH packets)
        for line in self._ek_get_list(layer, "http_http_request_line"):
            self._parse_ssdp_header_line(line, result)

        # M-SEARCH queries are valid even without extra fields
        if result["msg_type"] == "M-SEARCH":
            return result

        if not any(result.get(k) for k in ("usn", "st", "nt", "server", "location")):
            self.logger.debug(
                f"SSDP EK: no useful fields extracted from packet (msg_type={result['msg_type']})"
            )
            return None

        return result

    def _extract_ssdp_fields_xml(self, layer) -> Optional[Dict[str, str]]:
        """Extract SSDP fields from an XML-mode layer via get_field / get_all_fields."""
        result: Dict[str, str] = {}

        # Method / response code (http_request_method / http_response_code)
        method = str(self.get_field(layer, "http_request_method", "") or "")
        response_code = str(self.get_field(layer, "http_response_code", "") or "")

        if method == "NOTIFY":
            result["msg_type"] = "NOTIFY"
        elif method == "M-SEARCH":
            result["msg_type"] = "M-SEARCH"
        elif response_code == "200":
            result["msg_type"] = "RESPONSE"
        else:
            result["msg_type"] = method or "UNKNOWN"

        # Direct http_* fields
        result["server"] = str(self.get_field(layer, "http_server", "") or "")
        result["location"] = str(self.get_field(layer, "http_location", "") or "")
        result["cache_control"] = str(self.get_field(layer, "http_cache_control", "") or "")

        # NT, USN, NTS, ST may be in unknown_header or dedicated fields
        # Parse from _all_fields for reliable access
        all_fields = self.get_all_fields(layer)
        for raw_key, raw_val in all_fields.items():
            val = str(raw_val).strip()
            if raw_key == "http.unknown_header":
                # Format: "NT: upnp:rootdevice\r\n"
                self._parse_ssdp_header_line(val, result)

        # Also try direct ssdp.* fields (some tshark versions expose them)
        for key in ("usn", "st", "nt", "nts"):
            if not result.get(key):
                v = str(self.get_field(layer, key, "") or "")
                if v:
                    result[key] = v

        # M-SEARCH with ST from request.line
        if result["msg_type"] == "M-SEARCH" and not result.get("st"):
            request_line = str(self.get_field(layer, "http_request_line", "") or "")
            if request_line:
                for line in request_line.replace("\\r\\n", "\n").split("\n"):
                    self._parse_ssdp_header_line(line.strip(), result)

        # Skip if nothing useful extracted (pure M-SEARCH queries with no headers)
        if result["msg_type"] == "M-SEARCH":
            # M-SEARCH queries are valid even without extra fields
            return result

        if not any(result.get(k) for k in ("usn", "st", "nt", "server", "location")):
            return None

        return result

    def _parse_ssdp_header_line(self, line: str, result: Dict[str, str]) -> None:
        """Parse a raw SSDP header line like 'NT: upnp:rootdevice\\r\\n'."""
        line = line.replace("\\r\\n", "").replace("\r\n", "").strip()
        if ":" not in line:
            return
        key, _, value = line.partition(":")
        key = key.strip().upper()
        value = value.strip()
        mapping = {"NT": "nt", "NTS": "nts", "USN": "usn", "ST": "st"}
        if key in mapping and not result.get(mapping[key]):
            result[mapping[key]] = value
