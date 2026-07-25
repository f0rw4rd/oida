"""
IP camera / surveillance active discovery scanners.

Multicast probes for vendor camera-discovery protocols that ride their own
groups/ports (distinct from generic WS-Discovery / SSDP). These devices are
ubiquitous on OT / physical-security VLANs and are a major attack surface.

Contains:
- HikvisionSADPScanner: Hikvision SADP "Search Active Devices Protocol"
  (UDP 37020, multicast 239.255.255.250)
- DahuaDHDiscoverScanner: Dahua DHIP "DHDiscover.search"
  (UDP 37810, multicast 239.255.255.251)

References:
- Hikvision SADP probe + multicast group/port confirmed across three
  independent implementations:
  - https://sergei.nz/reverse-engineering-hikvision-sadp-tool/
  - https://github.com/4n4nk3/HikPwn/blob/master/hikpwn.py
  - https://github.com/julienblitte/UniversalScanner/blob/master/UniversalScanner/Hikvision.cs
- Dahua DHIP framing + DHDiscover.search probe:
  - https://github.com/mcw0/DahuaConsole/blob/master/net.py
  - response deviceInfo fields (client.notifyDevInfo):
    https://github.com/bozzzzo/dahua-tools/blob/master/Dahua-JSON-Debug-Console-v2.py
"""

import json
import struct
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

try:
    # Hikvision SADP ProbeMatch XML comes straight off the wire from untrusted
    # devices — parse it with defusedxml to block XXE / XML-bomb attacks (same
    # policy as ssdp.py). defusedxml.ElementTree re-exports ParseError.
    from defusedxml import ElementTree
except ImportError as _cam_xml_err:  # pragma: no cover — release-checked dep
    raise ImportError(
        "Camera SADP parsing requires defusedxml to protect against XXE / XML-bomb "
        "attacks on untrusted device responses. Install with: pip install oida[discovery]"
    ) from _cam_xml_err

from .core import (
    DiscoveredDevice,
    create_udp_socket,
    validate_interface,
    validate_timeout,
)
from ...utils.rate_limiter import sendto
from ...utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)


class HikvisionSADPScanner:
    """Hikvision SADP camera/NVR discovery (UDP 37020, mcast 239.255.255.250).

    SADP is Hikvision's WS-Discovery-style device-search protocol. A single
    multicast ``<Probe>`` with ``<Types>inquiry</Types>`` makes every Hikvision
    device on the L2 segment unicast back a ``<ProbeMatch>`` document carrying
    model, serial, firmware, IP and MAC.

    Protocol:
    - Probe (multicast 239.255.255.250:37020):
        <?xml version="1.0" encoding="utf-8"?>
        <Probe><Uuid>{uuid}</Uuid><Types>inquiry</Types></Probe>
    - Response: raw ``<ProbeMatch>`` XML (no framing/header) with child tags
        DeviceDescription, DeviceSN, IPv4Address, MAC, SoftwareVersion,
        DSPVersion, IPv4SubnetMask, IPv4Gateway, DHCP, HttpPort, CommandPort,
        BootTime, Activated, PasswordResetAbility, ...

    OT-safety: the discovery exchange is read-only. NOTE: SADP is a documented
    UDP reflection/amplification vector (~8:1) — we send a single multicast
    probe (no resend) and never spoof the source.
    """

    MULTICAST_ADDR = "239.255.255.250"
    PORT = 37020

    # Fields we lift verbatim out of the ProbeMatch into sadp_data. Order is
    # cosmetic; presence is tolerated, absence is ignored.
    _RESPONSE_FIELDS = (
        "DeviceDescription",
        "DeviceSN",
        "IPv4Address",
        "IPv4SubnetMask",
        "IPv4Gateway",
        "IPv6Address",
        "MAC",
        "DHCP",
        "SoftwareVersion",
        "DSPVersion",
        "BootTime",
        "HttpPort",
        "CommandPort",
        "Activated",
        "PasswordResetAbility",
        "DeviceType",
        "Salt",
    )

    def __init__(self, interface: str, timeout: int = 10):
        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def _build_probe(self) -> bytes:
        """Build the SADP inquiry probe with a fresh session UUID."""
        session = str(uuid.uuid4()).upper()
        return (
            '<?xml version="1.0" encoding="utf-8"?>'
            f"<Probe><Uuid>{session}</Uuid><Types>inquiry</Types></Probe>"
        ).encode("utf-8")

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send the SADP multicast probe and collect ProbeMatch responses."""
        sock = None
        try:
            # Bind to 37020 (SADP devices reply to the source port); multicast
            # TTL keeps the probe on the local segment.
            sock = create_udp_socket(
                self.interface,
                timeout=2.0,
                multicast_ttl=2,
                bind_port=self.PORT,
                reuse_addr=True,
            )

            sendto(sock, self._build_probe(), (self.MULTICAST_ADDR, self.PORT))
            logger.debug(f"SADP: sent inquiry to {self.MULTICAST_ADDR}:{self.PORT}")

            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(65535)
                    device = self._parse_response(data, addr[0])
                    if device:
                        with self._lock:
                            # Prefer the device's self-reported IP as the key,
                            # falling back to the packet source.
                            key = device.ip_addresses[0] if device.ip_addresses else addr[0]
                            self.discovered_devices[key] = device
                            logger.debug(f"SADP: found {key}")
                except TimeoutError:
                    pass  # single probe, no resend (OT safety)
                except OSError as e:
                    logger.debug(f"SADP recv error: {e}")

            logger.info(f"SADP found {len(self.discovered_devices)} devices")

        except OSError as e:
            logger.warning(f"SADP socket error: {e}")
        except Exception as e:
            logger.warning(f"SADP discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

        return self.discovered_devices

    def _parse_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse a SADP ProbeMatch response into a DiscoveredDevice.

        The body is raw XML rooted at ``<ProbeMatch>`` (Hikvision uses no XML
        namespace). Returns None for anything that is not a parseable
        ProbeMatch, so stray multicast traffic on 37020 is ignored.
        """
        try:
            text = data.decode("utf-8", errors="replace").strip()
        except Exception as e:
            logger.debug(f"SADP decode failed: {e}")
            return None

        if not text or "ProbeMatch" not in text:
            return None

        try:
            root = ElementTree.fromstring(text)
        except ElementTree.ParseError as e:
            logger.debug(f"SADP XML parse failed: {e}")
            return None

        # Accept either <ProbeMatch> as root or wrapped in a <ProbeMatch> child.
        match = root if root.tag.endswith("ProbeMatch") else root.find(".//ProbeMatch")
        if match is None:
            return None

        sadp_data: Dict[str, Any] = {}
        for tag in self._RESPONSE_FIELDS:
            elem = match.find(tag)
            if elem is not None and elem.text is not None:
                value = elem.text.strip()
                if value:
                    sadp_data[tag] = value

        # A ProbeMatch with no recognizable fields is not a useful device.
        if not sadp_data:
            return None

        reported_ip = sadp_data.get("IPv4Address", "").strip()
        ip_addresses = [reported_ip] if reported_ip else ([ip] if ip else [])

        model = sadp_data.get("DeviceDescription", "").strip()
        version = sadp_data.get("SoftwareVersion", "").strip()
        description = f"Hikvision {model} {version}".strip()

        return DiscoveredDevice(
            mac_address=sadp_data.get("MAC", "").strip(),
            ip_addresses=ip_addresses,
            name=model or f"Hikvision Device ({ip})",
            manufacturer="Hikvision",
            model=model,
            device_type="Camera",
            description=description,
            discovered_by=["sadp"],
            discovery_reasons=["sadp:ProbeMatch"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            sadp_data=sadp_data,
        )


class DahuaDHDiscoverScanner:
    """Dahua DHDiscover camera/NVR discovery (UDP 37810, mcast 239.255.255.251).

    Dahua devices answer a multicast ``DHDiscover.search`` request with a
    ``client.notifyDevInfo`` reply carrying model, serial, firmware, IP and
    MAC. Both the request and reply are DHIP-framed: a 32-byte binary header
    (magic ``20 00 00 00 'DHIP'`` + session/id/length fields) followed by a
    JSON body.

    Protocol (per mcw0/DahuaConsole net.py):
    - Probe payload: {"method":"DHDiscover.search","params":{"mac":"","uni":1}}
    - DHIP header: p64_be(0x2000000044484950) + 8 zero bytes
        + p32_le(len) + 4 zero + p32_le(len) + 4 zero
    - Response: 32-byte DHIP header + JSON
        {"mac": "...", "method": "client.notifyDevInfo",
         "params": {"deviceInfo": {"DeviceType","SerialNo","Version",
                    "IPv4Address": {"IPAddress","DefaultGateway","SubnetMask",
                                    "DhcpEnable"}, ...}}}

    OT-safety: read-only. NOTE: UDP 37810 is a documented reflection/
    amplification vector — single multicast probe, no resend, no source spoof.
    """

    MULTICAST_ADDR = "239.255.255.251"
    PORT = 37810

    # DHIP magic: 0x2000000044484950 big-endian == b"\x20\x00\x00\x00DHIP"
    _DHIP_MAGIC = struct.pack(">Q", 0x2000000044484950)
    _PROBE_JSON = b'{"method":"DHDiscover.search","params":{"mac":"","uni":1}}'

    def __init__(self, interface: str, timeout: int = 10):
        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def _build_probe(self) -> bytes:
        """Build the DHIP-framed DHDiscover.search probe."""
        body = self._PROBE_JSON
        n = len(body)
        header = (
            self._DHIP_MAGIC
            + b"\x00" * 8
            + struct.pack("<I", n)
            + b"\x00" * 4
            + struct.pack("<I", n)
            + b"\x00" * 4
        )
        return header + body

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send the DHDiscover multicast probe and collect replies."""
        sock = None
        try:
            sock = create_udp_socket(
                self.interface,
                timeout=2.0,
                multicast_ttl=2,
                bind_port=self.PORT,
                reuse_addr=True,
            )

            sendto(sock, self._build_probe(), (self.MULTICAST_ADDR, self.PORT))
            logger.debug(f"Dahua: sent DHDiscover to {self.MULTICAST_ADDR}:{self.PORT}")

            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(65535)
                    device = self._parse_response(data, addr[0])
                    if device:
                        with self._lock:
                            key = device.ip_addresses[0] if device.ip_addresses else addr[0]
                            self.discovered_devices[key] = device
                            logger.debug(f"Dahua: found {key}")
                except TimeoutError:
                    pass  # single probe, no resend (OT safety)
                except OSError as e:
                    logger.debug(f"Dahua recv error: {e}")

            logger.info(f"Dahua found {len(self.discovered_devices)} devices")

        except OSError as e:
            logger.warning(f"Dahua socket error: {e}")
        except Exception as e:
            logger.warning(f"Dahua discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

        return self.discovered_devices

    def _parse_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse a DHIP DHDiscover reply into a DiscoveredDevice.

        Tolerates both DHIP-framed replies (strip the 32-byte header) and
        bare JSON by locating the first ``{`` and decoding to the trailing
        NUL/whitespace. Returns None for anything that is not a DHDiscover
        device-info reply.
        """
        if not data:
            return None

        # Locate the JSON body whether or not a DHIP header is present.
        brace = data.find(b"{")
        if brace == -1:
            return None
        try:
            payload = data[brace:].rstrip(b"\x00").strip()
            obj = json.loads(payload.decode("latin-1"))
        except (ValueError, UnicodeDecodeError) as e:
            logger.debug(f"Dahua JSON parse failed: {e}")
            return None

        if not isinstance(obj, dict):
            return None

        params = obj.get("params")
        device_info = params.get("deviceInfo") if isinstance(params, dict) else None
        if not isinstance(device_info, dict):
            return None

        # Flatten the nested IPv4Address block for convenience while keeping
        # the full deviceInfo verbatim.
        ipv4 = device_info.get("IPv4Address")
        ipv4 = ipv4 if isinstance(ipv4, dict) else {}
        reported_ip = str(ipv4.get("IPAddress", "")).strip()

        mac = str(obj.get("mac", "") or device_info.get("mac", "")).strip()
        model = str(device_info.get("DeviceType", "")).strip()
        serial = str(device_info.get("SerialNo", "")).strip()
        version = str(device_info.get("Version", "")).strip()

        dahua_data: Dict[str, Any] = {
            "DeviceType": model,
            "SerialNo": serial,
            "Version": version,
            "mac": mac,
            "IPAddress": reported_ip,
            "DefaultGateway": str(ipv4.get("DefaultGateway", "")).strip(),
            "SubnetMask": str(ipv4.get("SubnetMask", "")).strip(),
            "DhcpEnable": ipv4.get("DhcpEnable"),
            "Vendor": str(device_info.get("Vendor", "")).strip(),
            "deviceInfo": device_info,
        }
        # Drop empty scalar fields for a tidy payload (keep deviceInfo).
        dahua_data = {
            k: v for k, v in dahua_data.items() if v not in ("", None) or k == "deviceInfo"
        }

        ip_addresses = [reported_ip] if reported_ip else ([ip] if ip else [])
        description = f"Dahua {model} {version}".strip()

        return DiscoveredDevice(
            mac_address=mac,
            ip_addresses=ip_addresses,
            name=model or f"Dahua Device ({ip})",
            manufacturer="Dahua",
            model=model,
            device_type="Camera",
            description=description,
            discovered_by=["dahua"],
            discovery_reasons=["dahua:DHDiscover"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            dahua_data=dahua_data,
        )
