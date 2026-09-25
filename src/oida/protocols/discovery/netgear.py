"""
Network-equipment active discovery scanners.

Broadcast probes for vendor network gear (APs, routers, switches) that ride
their own discovery ports - common on smaller OT/IT networks.

Contains:
- UbiquitiScanner: Ubiquiti device discovery (UDP 10001, broadcast)
- MNDPScanner: MikroTik Neighbor Discovery Protocol (UDP 5678, broadcast)

References:
- Ubiquiti probe + TLV codes (nmap ubiquiti-discovery.nse):
  https://nmap.org/nsedoc/scripts/ubiquiti-discovery.html
  https://github.com/nmap/nmap/blob/master/scripts/ubiquiti-discovery.nse
- MNDP packet/TLV layout (Wireshark dissector + MikroTik docs):
  https://gitlab.com/wireshark/wireshark/-/raw/master/epan/dissectors/packet-mndp.c
  https://help.mikrotik.com/docs/spaces/ROS/pages/24805517/Neighbor+discovery
"""

import struct
import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional

from oida.protocols.discovery.core import (
    DiscoveredDevice,
    create_udp_socket,
    get_all_broadcast_addresses,
    validate_interface,
    validate_subnet,
    validate_timeout,
)
from oida.utils.rate_limiter import sendto
from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)


class UbiquitiScanner:
    """Ubiquiti device discovery (UDP 10001, broadcast).

    Sends the v1 and v2 discovery probes; Ubiquiti devices reply with a
    TLV-encoded record carrying MAC, IP, hostname, model, firmware and ESSID.

    Protocol (per nmap ubiquiti-discovery.nse):
    - Probe v1: 01 00 00 00   ; v2: 02 08 00 00
        (version, command, 2-byte length = 0)
    - Response: byte0 version, byte1 command, bytes2-3 length (BE), then TLV
        records: type(1) + length(2 BE) + value. Key TLV types:
        0x01 MAC(6), 0x02 MAC(6)+IP(4), 0x03 firmware, 0x0a uptime(4 BE),
        0x0b hostname, 0x0c model(short), 0x0d ESSID, 0x14 model(v1),
        0x15 model(v2), 0x16 version.

    OT-safety: caution - active probe and a known reflection vector; we send a
    single probe per broadcast address and never spoof the source.
    """

    PORT = 10001
    PROBE_V1 = b"\x01\x00\x00\x00"
    PROBE_V2 = b"\x02\x08\x00\x00"

    # TLV type -> (key, kind). kind: "str", "mac", "ip", "mac_ip", "u32".
    _TLV = {
        0x01: ("mac", "mac"),
        0x02: ("mac_ip", "mac_ip"),
        0x03: ("firmware", "str"),
        0x0A: ("uptime", "u32"),
        0x0B: ("hostname", "str"),
        0x0C: ("model_short", "str"),
        0x0D: ("essid", "str"),
        0x14: ("model", "str"),
        0x15: ("model", "str"),
        0x16: ("version", "str"),
    }

    def __init__(self, interface: str, subnet: Optional[str] = None, timeout: int = 10):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        sock = None
        try:
            sock = create_udp_socket(self.interface, timeout=0.5, broadcast=True)
            for addr in get_all_broadcast_addresses(self.interface, self.subnet):
                sendto(sock, self.PROBE_V1, (addr, self.PORT))
                sendto(sock, self.PROBE_V2, (addr, self.PORT))
                logger.debug(f"Ubiquiti: sent probes to {addr}:{self.PORT}")

            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    device = self._parse_response(data, addr[0])
                    if device:
                        with self._lock:
                            key = device.ip_addresses[0] if device.ip_addresses else addr[0]
                            self.discovered_devices[key] = device
                            logger.debug(f"Ubiquiti: found {key}")
                except TimeoutError:
                    continue
                except OSError as e:
                    logger.debug(f"Ubiquiti socket error: {e}")

            logger.info(f"Ubiquiti found {len(self.discovered_devices)} devices")
        except OSError as e:
            logger.warning(f"Ubiquiti discovery socket error: {e}")
        except Exception as e:
            logger.warning(f"Ubiquiti discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")
        return self.discovered_devices

    @staticmethod
    def _mac(b: bytes) -> str:
        return ":".join(f"{x:02x}" for x in b[:6])

    def _parse_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse a Ubiquiti discovery reply (TLV-encoded)."""
        # version (0x01/0x02) + command + 2-byte BE payload length.
        if len(data) < 4 or data[0] not in (0x01, 0x02):
            return None
        payload_len = struct.unpack_from(">H", data, 2)[0]
        body = data[4 : 4 + payload_len]
        if not body:
            return None

        fields: Dict[str, Any] = {}
        mac = ""
        reported_ip = ""
        pos = 0
        while pos + 3 <= len(body):
            ttype = body[pos]
            tlen = struct.unpack_from(">H", body, pos + 1)[0]
            value = body[pos + 3 : pos + 3 + tlen]
            if len(value) < tlen:
                break  # truncated TLV
            pos += 3 + tlen

            entry = self._TLV.get(ttype)
            if not entry:
                continue
            key, kind = entry
            if kind == "str":
                fields[key] = value.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
            elif kind == "mac" and len(value) >= 6:
                mac = self._mac(value)
                fields["mac"] = mac
            elif kind == "mac_ip" and len(value) >= 10:
                mac = self._mac(value[:6])
                reported_ip = ".".join(str(x) for x in value[6:10])
                fields["mac"] = mac
                fields["ip"] = reported_ip
            elif kind == "u32" and len(value) >= 4:
                fields[key] = struct.unpack(">I", value[:4])[0]

        if not fields:
            return None

        model = fields.get("model") or fields.get("model_short", "")
        ip_addresses = [reported_ip] if reported_ip else ([ip] if ip else [])
        return DiscoveredDevice(
            mac_address=mac,
            ip_addresses=ip_addresses,
            name=fields.get("hostname") or model or f"Ubiquiti Device ({ip})",
            manufacturer="Ubiquiti",
            model=model,
            device_type="Network Equipment",
            description=f"Ubiquiti {model}".strip(),
            discovered_by=["ubiquiti"],
            discovery_reasons=["ubiquiti:discovery"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            ubiquiti_data=fields,
        )


class MNDPScanner:
    """MikroTik Neighbor Discovery Protocol (UDP 5678, broadcast).

    MikroTik devices periodically broadcast MNDP announcements; sending an
    empty datagram to the broadcast address solicits immediate replies. Each
    announcement is TLV-encoded with identity, version, board and addresses.

    Protocol (per Wireshark packet-mndp.c):
    - Header: 2 bytes + 16-bit BE sequence number.
    - TLV: type(2 BE) + length(2 BE) + value. Key types:
        1 MAC(6), 5 Identity(str), 7 Version(str), 8 Platform(str),
        10 Uptime, 11 Software-ID(str), 12 Board(str), 15 IPv6(16),
        16 Interface(str), 17 IPv4(4).

    OT-safety: safe - listening is passive; the solicitation is a single empty
    broadcast datagram.
    """

    PORT = 5678
    SOLICIT = b"\x00\x00\x00\x00"  # empty MNDP header to trigger replies

    # TLV type -> (key, kind). kind: "str", "mac", "ipv4", "ipv6", "u32".
    _TLV = {
        1: ("mac", "mac"),
        5: ("identity", "str"),
        7: ("version", "str"),
        8: ("platform", "str"),
        10: ("uptime", "u32"),
        11: ("software_id", "str"),
        12: ("board", "str"),
        15: ("ipv6", "ipv6"),
        16: ("interface", "str"),
        17: ("ipv4", "ipv4"),
    }

    def __init__(self, interface: str, subnet: Optional[str] = None, timeout: int = 10):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        sock = None
        try:
            sock = create_udp_socket(self.interface, timeout=0.5, broadcast=True)
            for addr in get_all_broadcast_addresses(self.interface, self.subnet):
                sendto(sock, self.SOLICIT, (addr, self.PORT))
                logger.debug(f"MNDP: solicited {addr}:{self.PORT}")

            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    device = self._parse_response(data, addr[0])
                    if device:
                        with self._lock:
                            key = device.ip_addresses[0] if device.ip_addresses else addr[0]
                            self.discovered_devices[key] = device
                            logger.debug(f"MNDP: found {key}")
                except TimeoutError:
                    continue
                except OSError as e:
                    logger.debug(f"MNDP socket error: {e}")

            logger.info(f"MNDP found {len(self.discovered_devices)} devices")
        except OSError as e:
            logger.warning(f"MNDP discovery socket error: {e}")
        except Exception as e:
            logger.warning(f"MNDP discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")
        return self.discovered_devices

    def _parse_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse an MNDP announcement (TLV-encoded after a 4-byte header)."""
        # 2-byte header + 2-byte sequence, then TLVs.
        if len(data) < 4:
            return None
        body = data[4:]

        fields: Dict[str, Any] = {}
        mac = ""
        reported_ip = ""
        pos = 0
        while pos + 4 <= len(body):
            ttype, tlen = struct.unpack_from(">HH", body, pos)
            value = body[pos + 4 : pos + 4 + tlen]
            if len(value) < tlen:
                break  # truncated TLV
            pos += 4 + tlen

            entry = self._TLV.get(ttype)
            if not entry:
                continue
            key, kind = entry
            if kind == "str":
                fields[key] = value.decode("utf-8", "replace").strip()
            elif kind == "mac" and len(value) >= 6:
                mac = ":".join(f"{x:02x}" for x in value[:6])
                fields["mac"] = mac
            elif kind == "ipv4" and len(value) >= 4:
                reported_ip = ".".join(str(x) for x in value[:4])
                fields["ipv4"] = reported_ip
            elif kind == "ipv6" and len(value) >= 16:
                fields["ipv6"] = value[:16].hex()
            elif kind == "u32" and len(value) >= 4:
                fields[key] = struct.unpack(">I", value[:4])[0]

        # An MNDP packet should carry at least an identity or MAC.
        if not fields or ("identity" not in fields and "mac" not in fields):
            return None

        ip_addresses = [reported_ip] if reported_ip else ([ip] if ip else [])
        identity = fields.get("identity", "")
        board = fields.get("board", "")
        return DiscoveredDevice(
            mac_address=mac,
            ip_addresses=ip_addresses,
            name=identity or f"MikroTik Device ({ip})",
            manufacturer="MikroTik",
            model=board,
            device_type="Network Equipment",
            description=f"MikroTik {board} {fields.get('version', '')}".strip(),
            discovered_by=["mndp"],
            discovery_reasons=["mndp:announce"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            mndp_data=fields,
        )
