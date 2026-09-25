"""
SSDP and WS-Discovery scanners.

Contains:
- SSDPScanner: UPnP/SSDP device discovery (socket-based)
- SSDPPassiveListener: Passive SSDP traffic listener (scapy-based)
- WSDiscoveryScanner: WS-Discovery for ONVIF cameras, printers, Windows devices
"""

import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional
from urllib.parse import urlparse

try:
    from defusedxml import ElementTree  # Protect against XML bomb / XXE
except ImportError as _ssdp_xml_err:  # pragma: no cover - release-checked dep
    raise ImportError(
        "SSDP/UPnP parsing requires defusedxml to protect against XXE and XML-bomb "
        "attacks on untrusted UPnP device descriptions. Install with: "
        "pip install oida-ics[discovery]"
    ) from _ssdp_xml_err

from oida.protocols.discovery.base import PassiveListenerBase
from oida.protocols.discovery.core import (
    DiscoveredDevice,
    SSDP_MULTICAST_ADDR,
    SSDP_PORT,
    SSDP_MX,
    classify_device_type,
    create_udp_socket,
    validate_interface,
    validate_timeout,
)
from oida.utils.rate_limiter import sendto
from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)


class SSDPScanner:
    """SSDP/UPnP device discovery"""

    def __init__(self, interface: str, timeout: int = 30, active: bool = False, nxc_logger=None):
        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.active = active  # If True, send M-SEARCH; if False, just listen
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()
        self.nxc_logger = nxc_logger

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Perform SSDP discovery"""
        sock = None
        try:
            sock = create_udp_socket(self.interface, timeout=2.0, multicast_ttl=2)

            # M-SEARCH request (only in active mode)
            if self.active:
                msearch = (
                    "M-SEARCH * HTTP/1.1\r\n"
                    f"HOST: {SSDP_MULTICAST_ADDR}:{SSDP_PORT}\r\n"
                    'MAN: "ssdp:discover"\r\n'
                    f"MX: {SSDP_MX}\r\n"
                    "ST: ssdp:all\r\n"
                    "\r\n"
                )
                sendto(sock, msearch.encode(), (SSDP_MULTICAST_ADDR, SSDP_PORT))

            # Collect responses
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    self._handle_response(data.decode("utf-8", errors="ignore"), addr[0])
                except TimeoutError:
                    pass  # No resend - OT safety (single M-SEARCH is sufficient)
                except OSError as e:
                    logger.debug(f"SSDP receive error: {e}")

        except OSError as e:
            logger.error(f"SSDP socket error: {e}")
        except Exception as e:
            logger.error(f"SSDP discovery error: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

        return self.discovered_devices

    def _handle_response(self, response: str, ip: str) -> None:
        """Handle SSDP response"""
        try:
            headers = {}
            lines = response.split("\r\n")

            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().upper()] = value.strip()

            location = headers.get("LOCATION", "")
            server = headers.get("SERVER", "")
            usn = headers.get("USN", "")
            st = headers.get("ST", "")

            ssdp_data = {
                "location": location,
                "server": server,
                "usn": usn,
                "search_target": st,
                "headers": headers,
            }

            # Try to fetch device description if location is available
            if location and location.startswith("http"):
                device_info = self._fetch_device_description(location)
                if device_info:
                    ssdp_data.update(device_info)

            # Log with NXC logger if available
            def log_success(msg):
                if self.nxc_logger:
                    self.nxc_logger.success(msg)
                else:
                    logger.info(msg)

            friendly_name = ssdp_data.get("friendly_name", "")
            model = ssdp_data.get("model_name", "")
            manufacturer = ssdp_data.get("manufacturer", "")

            if friendly_name or model:
                log_success(f"SSDP: {ip} - {friendly_name or model}")
            else:
                log_success(f"SSDP: {ip} - {st or server or 'UPnP device'}")

            if manufacturer:
                log_success(f"  Manufacturer: {manufacturer}")
            if model and friendly_name:
                log_success(f"  Model: {model}")
            if server:
                log_success(f"  Server: {server}")

            with self._lock:
                if ip not in self.discovered_devices:
                    device = DiscoveredDevice(
                        ip_addresses=[ip],
                        name=ssdp_data.get("friendly_name", ""),
                        manufacturer=ssdp_data.get("manufacturer", ""),
                        model=ssdp_data.get("model_name", ""),
                        description=ssdp_data.get("model_description", ""),
                        device_type=ssdp_data.get("device_type", ""),
                        discovered_by=["ssdp"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                        ssdp_data=ssdp_data,
                    )
                    self.discovered_devices[ip] = device
                else:
                    device = self.discovered_devices[ip]
                    device.ssdp_data = ssdp_data
                    device.last_seen = datetime.now().isoformat()
                    if "ssdp" not in device.discovered_by:
                        device.discovered_by.append("ssdp")

        except Exception as e:
            logger.debug(f"Error processing SSDP response from {ip}: {e}")

    def _fetch_device_description(self, location: str) -> Optional[Dict[str, Any]]:
        """Fetch UPnP device description XML.

        SSRF note: ``location`` comes from SSDP LOCATION headers which by
        design point to *local-network* devices (SSDP is LAN-only multicast).
        Blocking private/link-local IPs here would break the core discovery
        functionality. Instead we restrict the scheme to HTTP(S) and cap the
        response size so a rogue device cannot cause resource exhaustion.
        """
        try:
            import urllib.request

            parsed = urlparse(location)
            if parsed.scheme not in ("http", "https"):
                logger.debug(f"Skipping non-HTTP URL: {location}")
                return None

            if not parsed.hostname:
                logger.debug(f"Skipping URL without hostname: {location}")
                return None

            with urllib.request.urlopen(location, timeout=3) as response:  # nosec B310
                # Cap response to 1 MB to prevent resource exhaustion from rogue devices
                xml_data = response.read(1_048_576)
                return self._parse_device_xml(xml_data)
        except Exception as e:
            logger.debug(f"Could not fetch device description from {location}: {e}")
            return None

    def _parse_device_xml(self, xml_data: bytes) -> Dict[str, Any]:
        """Parse UPnP device description XML"""
        try:
            root = ElementTree.fromstring(xml_data)
            device_info = {}

            for prefix in ["{urn:schemas-upnp-org:device-1-0}", ""]:
                device = root.find(f".//{prefix}device")
                if device is not None:
                    fields = [
                        ("friendlyName", "friendly_name"),
                        ("manufacturer", "manufacturer"),
                        ("modelName", "model_name"),
                        ("modelDescription", "model_description"),
                        ("modelNumber", "model_number"),
                        ("serialNumber", "serial_number"),
                        ("deviceType", "device_type_raw"),
                        ("UDN", "udn"),
                    ]

                    for xml_field, dict_key in fields:
                        elem = device.find(f"{prefix}{xml_field}")
                        if elem is not None and elem.text:
                            device_info[dict_key] = elem.text

                    # Classify device type from raw URN
                    if "device_type_raw" in device_info:
                        device_type, description = classify_device_type(
                            [device_info["device_type_raw"]], "ssdp"
                        )
                        device_info["device_type"] = device_type
                        device_info["device_type_description"] = description
                    break

            return device_info

        except Exception as e:
            logger.debug(f"Error parsing device XML: {e}")
            return {}


class WSDiscoveryScanner:
    """WS-Discovery (Web Services Dynamic Discovery) scanner

    Discovers devices using SOAP-based WS-Discovery protocol.
    Used by printers, cameras (ONVIF), Windows devices, etc.
    Multicast address: 239.255.255.250:3702
    """

    WSD_MULTICAST_ADDR = "239.255.255.250"
    WSD_PORT = 3702

    # WS-Discovery SOAP envelope for Probe message
    WSD_PROBE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <soap:Header>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    <wsa:MessageID>urn:uuid:{message_id}</wsa:MessageID>
  </soap:Header>
  <soap:Body>
    <wsd:Probe/>
  </soap:Body>
</soap:Envelope>"""

    def __init__(self, interface: str, timeout: int = 10):
        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send WS-Discovery Probe and collect responses"""
        import uuid

        sock = None
        try:
            sock = create_udp_socket(self.interface, timeout=2.0, multicast_ttl=4)

            # Generate unique message ID
            message_id = str(uuid.uuid4())
            probe_message = self.WSD_PROBE_TEMPLATE.format(message_id=message_id)

            # Send probe
            sendto(
                sock,
                probe_message.encode("utf-8"),
                (self.WSD_MULTICAST_ADDR, self.WSD_PORT),
            )

            # Collect responses
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(65535)
                    self._handle_response(data.decode("utf-8", errors="ignore"), addr[0])
                except TimeoutError:
                    pass  # No resend - OT safety (single probe is sufficient)
                except OSError as e:
                    logger.debug(f"WS-Discovery recv error: {e}")

            logger.info(f"WS-Discovery found {len(self.discovered_devices)} devices")

        except OSError as e:
            logger.error(f"WS-Discovery socket error: {e}")
        except Exception as e:
            logger.error(f"WS-Discovery error: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

        return self.discovered_devices

    def _handle_response(self, response: str, ip: str) -> None:
        """Parse WS-Discovery ProbeMatch response"""
        try:
            # Parse XML response
            root = ElementTree.fromstring(response)

            # Extract device info from SOAP body
            wsd_data = {
                "types": [],
                "scopes": [],
                "xaddrs": [],
                "metadata_version": "",
            }

            # Define namespaces
            ns = {
                "soap": "http://www.w3.org/2003/05/soap-envelope",
                "wsa": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
                "wsd": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
            }

            # Find ProbeMatch elements
            for match in root.findall(".//wsd:ProbeMatch", ns):
                # Get Types (device types)
                types_elem = match.find("wsd:Types", ns)
                if types_elem is not None and types_elem.text:
                    wsd_data["types"] = types_elem.text.split()

                # Get Scopes
                scopes_elem = match.find("wsd:Scopes", ns)
                if scopes_elem is not None and scopes_elem.text:
                    wsd_data["scopes"] = scopes_elem.text.split()

                # Get XAddrs (transport addresses)
                xaddrs_elem = match.find("wsd:XAddrs", ns)
                if xaddrs_elem is not None and xaddrs_elem.text:
                    wsd_data["xaddrs"] = xaddrs_elem.text.split()

                # Get MetadataVersion
                version_elem = match.find("wsd:MetadataVersion", ns)
                if version_elem is not None and version_elem.text:
                    wsd_data["metadata_version"] = version_elem.text

            # Classify device type using the type classification system
            device_type, device_description = classify_device_type(wsd_data["types"], "wsd")

            # Check scopes for ONVIF-specific info (overrides generic type)
            name = ""
            for scope in wsd_data["scopes"]:
                if "onvif" in scope.lower() and device_type == "Unknown":
                    device_type = "Camera"
                    device_description = "ONVIF Device"
                if "/name/" in scope.lower():
                    name = scope.split("/name/")[-1]

            # Store classification info in wsd_data
            wsd_data["device_type_classified"] = device_type
            wsd_data["device_type_description"] = device_description

            with self._lock:
                if ip not in self.discovered_devices:
                    device = DiscoveredDevice(
                        ip_addresses=[ip],
                        name=name,
                        device_type=device_type,
                        discovered_by=["ws-discovery"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                        wsdiscovery_data=wsd_data,
                    )
                    self.discovered_devices[ip] = device
                else:
                    device = self.discovered_devices[ip]
                    device.wsdiscovery_data = wsd_data
                    if device_type and not device.device_type:
                        device.device_type = device_type
                    device.last_seen = datetime.now().isoformat()
                    if "ws-discovery" not in device.discovered_by:
                        device.discovered_by.append("ws-discovery")

        except ElementTree.ParseError:
            logger.debug(f"Could not parse WS-Discovery response from {ip}")
        except Exception as e:
            logger.debug(f"Error processing WS-Discovery response from {ip}: {e}")


class SSDPPassiveListener(PassiveListenerBase):
    """Passive SSDP traffic listener using scapy.

    Captures SSDP multicast traffic (NOTIFY announcements and M-SEARCH responses)
    without sending any packets.

    SSDP uses:
    - Multicast 239.255.255.250:1900
    - UDP protocol

    Supports:
    - Live capture via AsyncSniffer
    - Direct packet feeding for testing
    """

    PROTOCOL_NAME = "ssdp-passive"
    BPF_FILTER = f"udp port {SSDP_PORT}"

    def should_process_packet(self, packet) -> bool:
        """Check if packet is an SSDP packet."""
        from scapy.all import UDP, IP

        if UDP not in packet or IP not in packet:
            return False
        return packet[UDP].sport == SSDP_PORT or packet[UDP].dport == SSDP_PORT

    def process_packet(self, packet) -> None:
        """Process captured SSDP packet."""
        try:
            from scapy.all import IP, Raw, Ether

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Extract MAC from Ethernet layer if available
            src_mac = ""
            if Ether in packet:
                src_mac = packet[Ether].src

            if Raw not in packet:
                return

            payload = bytes(packet[Raw].load).decode("utf-8", errors="ignore")

            # Parse SSDP message
            ssdp_info = self._parse_ssdp(payload)
            if not ssdp_info:
                return

            msg_type = ssdp_info.get("type", "unknown")

            with self._lock:
                # Use MAC as key if available, otherwise fall back to IP
                device_key = src_mac if src_mac else f"ssdp:{src_ip}"

                is_new = device_key not in self.discovered_devices
                if is_new:
                    device = DiscoveredDevice(
                        mac_address=src_mac,
                        ip_addresses=[src_ip],
                        name=ssdp_info.get("friendly_name", ""),
                        manufacturer="",
                        model="",
                        device_type=ssdp_info.get("device_type", ""),
                        discovered_by=["ssdp-passive"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                    )
                    self.discovered_devices[device_key] = device
                else:
                    device = self.discovered_devices[device_key]
                    device.last_seen = datetime.now().isoformat()

                # Refresh on every packet, not just the first: a later NOTIFY can
                # carry a changed LOCATION/USN, and an ssdp:byebye must be
                # reflected rather than leaving a stale "alive" record forever.
                # Prefer newly-seen non-empty values but keep prior ones when
                # this packet omits a field.
                existing = getattr(device, "ssdp_data", None) or {}

                def _prefer(key: str, new_val):
                    return new_val if new_val else existing.get(key)

                device.ssdp_data = {
                    "msg_type": msg_type,
                    "location": _prefer("location", ssdp_info.get("location")),
                    "server": _prefer("server", ssdp_info.get("server")),
                    "usn": _prefer("usn", ssdp_info.get("usn")),
                    "nt": _prefer("nt", ssdp_info.get("nt")),
                    "nts": _prefer("nts", ssdp_info.get("nts")),
                    "st": _prefer("st", ssdp_info.get("st")),
                    "cache_control": _prefer("cache_control", ssdp_info.get("cache-control")),
                    "multicast_dst": _prefer("multicast_dst", dst_ip),
                    "protocol": "SSDP/UDP",
                }

                if is_new:
                    nt = ssdp_info.get("nt", ssdp_info.get("st", "?"))
                    logger.debug(f"SSDP: {src_ip} {msg_type} {nt}")

        except Exception as e:
            logger.debug(f"SSDP parse error: {e}")

    def _parse_ssdp(self, payload: str) -> Optional[Dict]:
        """Parse SSDP message (NOTIFY or M-SEARCH response)."""
        try:
            lines = payload.split("\r\n")
            result = {}

            # Determine message type from first line
            first_line = lines[0].upper()
            if first_line.startswith("NOTIFY"):
                result["type"] = "NOTIFY"
            elif first_line.startswith("HTTP/1.1 200"):
                result["type"] = "RESPONSE"
            elif first_line.startswith("M-SEARCH"):
                result["type"] = "M-SEARCH"
            else:
                return None

            # Parse headers
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    result[key.strip().lower()] = value.strip()

            return result

        except Exception as e:
            logger.debug(f"SSDP parse failed: {e}")
            return None
