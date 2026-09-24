"""
AV / lighting-control active discovery scanners.

Broadcast probes for audio-visual control systems and entertainment-lighting
controllers, which frequently ride shared networks alongside OT/IT gear.

Contains:
- CrestronCIPScanner: Crestron CIP AutoDiscovery (UDP 41794, broadcast)
- ArtNetScanner: Art-Net ArtPoll lighting-node discovery (UDP 6454, broadcast)

References:
- Crestron probe/response offsets + regexes (working tool):
  https://github.com/StephenGenusa/Crestron-List-Devices-On-Network/blob/master/List_Crestron_Devices.py
  https://github.com/Phenomite/AMP-Research/blob/master/Port%2041794%20-%20Crestron%20CIP/README.md
- Art-Net ArtPoll/ArtPollReply field layout:
  https://github.com/jsimonetti/go-artnet/blob/master/packet/artpollreply.go
  https://github.com/jsimonetti/go-artnet/blob/master/packet/artpoll.go
"""

import re
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


class CrestronCIPScanner:
    """Crestron CIP AutoDiscovery (UDP 41794, broadcast).

    Mirrors the Crestron Toolbox "Device Discovery" broadcast: a single packet
    whose control byte is ``0x14`` makes Crestron control processors reply with
    a fixed-size record (control byte ``0x15``) carrying hostname and firmware
    (the firmware string embeds the model).

    Protocol (per StephenGenusa working tool + AMP-Research):
    - Probe (broadcast 255.255.255.255:41794), 266 bytes:
        14 00 00 00 01 04 00 03 00 00  "feed" (66 65 65 64)  + 252 x 00
    - Response: control byte 0x15, ~394 bytes. Hostname is parsed from
        data[9:40] via /\\x00([a-zA-Z0-9-]{2,30})\\x00/ and the firmware/version
        from data[265:350] via /\\x00([\\w].{10,80})\\x00/.

    OT-safety: read-only, unauthenticated by design.
    """

    PORT = 41794
    PROBE = (
        b"\x14\x00\x00\x00\x01\x04\x00\x03\x00\x00" + b"feed" + b"\x00" * 252
    )  # 266 bytes, verbatim from StephenGenusa List_Crestron_Devices.py
    RESPONSE_CONTROL_BYTE = 0x15

    _HOSTNAME_RE = re.compile(rb"\x00([a-zA-Z0-9-]{2,30})\x00")
    _FIRMWARE_RE = re.compile(rb"\x00([\w][\x20-\x7e]{10,80})\x00")

    def __init__(self, interface: str, subnet: Optional[str] = None, timeout: int = 10):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def _build_probe(self) -> bytes:
        return self.PROBE

    def scan(self) -> Dict[str, DiscoveredDevice]:
        sock = None
        try:
            sock = create_udp_socket(self.interface, timeout=2.0, broadcast=True)
            for addr in get_all_broadcast_addresses(self.interface, self.subnet):
                sendto(sock, self._build_probe(), (addr, self.PORT))
                logger.debug(f"Crestron: sent probe to {addr}:{self.PORT}")

            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(65535)
                    device = self._parse_response(data, addr[0])
                    if device:
                        with self._lock:
                            self.discovered_devices[addr[0]] = device
                            logger.debug(f"Crestron: found {addr[0]}")
                except TimeoutError:
                    pass
                except OSError as e:
                    logger.debug(f"Crestron recv error: {e}")

            logger.info(f"Crestron found {len(self.discovered_devices)} devices")
        except OSError as e:
            logger.warning(f"Crestron socket error: {e}")
        except Exception as e:
            logger.warning(f"Crestron discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")
        return self.discovered_devices

    def _parse_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse a Crestron CIP discovery reply (control byte 0x15)."""
        # Need the control byte and enough length to reach the firmware slice.
        if len(data) < 41 or data[0] != self.RESPONSE_CONTROL_BYTE:
            return None

        host_match = self._HOSTNAME_RE.search(data[9:40])
        fw_match = self._FIRMWARE_RE.search(data[265:350]) if len(data) >= 267 else None
        if not host_match and not fw_match:
            return None

        hostname = host_match.group(1).decode("ascii", "replace") if host_match else ""
        firmware = fw_match.group(1).decode("ascii", "replace") if fw_match else ""
        # The firmware string embeds the model, e.g. "DIN-AP3 [v1.503...]".
        model = firmware.split(" [")[0].strip() if firmware else ""

        crestron_data: Dict[str, Any] = {
            "hostname": hostname,
            "firmware": firmware,
            "model": model,
        }
        crestron_data = {k: v for k, v in crestron_data.items() if v}

        return DiscoveredDevice(
            ip_addresses=[ip] if ip else [],
            name=hostname or f"Crestron Device ({ip})",
            manufacturer="Crestron",
            model=model,
            device_type="AV Control System",
            description=f"Crestron {model} {firmware}".strip(),
            discovered_by=["crestron"],
            discovery_reasons=["crestron:cip"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            crestron_data=crestron_data,
        )


class ArtNetScanner:
    """Art-Net lighting-node discovery via ArtPoll (UDP 6454, broadcast).

    A single ArtPoll broadcast makes every Art-Net node reply with an
    ArtPollReply carrying IP, MAC, short/long name, OEM and firmware.

    Protocol (per Art-Net 4 spec + go-artnet):
    - ArtPoll probe (14 bytes): "Art-Net\\0" + OpCode 0x2000 (wire LE 00 20)
        + ProtVer 14 (00 0e) + TalkToMe + Priority.
    - ArtPollReply (>=239 bytes): OpCode 0x2100 (wire LE 00 21);
        IPAddress@10 (4), Port@14 (0x1936), ShortName@26 (18, ASCIIZ),
        LongName@44 (64, ASCIIZ), Oem@20 (2), ESTAman@24 (2), MAC@201 (6).

    OT-safety: safe — single read-only broadcast.
    """

    PORT = 6454
    ARTNET_ID = b"Art-Net\x00"
    OP_POLL = 0x2000
    OP_POLL_REPLY = 0x2100
    PROT_VER = 14

    # ArtPollReply field offsets (per go-artnet struct layout).
    _OFF_OPCODE = 8
    _OFF_IP = 10
    _OFF_PORT = 14
    _OFF_OEM = 20
    _OFF_ESTA = 24
    _OFF_SHORTNAME = 26
    _OFF_LONGNAME = 44
    _OFF_MAC = 201
    _MIN_LEN = _OFF_MAC + 6  # must reach the MAC field

    def __init__(self, interface: str, subnet: Optional[str] = None, timeout: int = 10):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def _build_probe(self) -> bytes:
        """Build the ArtPoll packet (OpCode + ProtVer little/expected wire bytes)."""
        return (
            self.ARTNET_ID
            + struct.pack("<H", self.OP_POLL)  # 00 20 on the wire
            + bytes((self.PROT_VER >> 8, self.PROT_VER & 0xFF))  # 00 0e
            + b"\x00"  # TalkToMe
            + b"\x00"  # Priority
        )

    def scan(self) -> Dict[str, DiscoveredDevice]:
        sock = None
        try:
            sock = create_udp_socket(self.interface, timeout=2.0, broadcast=True)
            for addr in get_all_broadcast_addresses(self.interface, self.subnet):
                sendto(sock, self._build_probe(), (addr, self.PORT))
                logger.debug(f"Art-Net: sent ArtPoll to {addr}:{self.PORT}")

            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(65535)
                    device = self._parse_response(data, addr[0])
                    if device:
                        with self._lock:
                            key = device.ip_addresses[0] if device.ip_addresses else addr[0]
                            self.discovered_devices[key] = device
                            logger.debug(f"Art-Net: found {key}")
                except TimeoutError:
                    pass
                except OSError as e:
                    logger.debug(f"Art-Net recv error: {e}")

            logger.info(f"Art-Net found {len(self.discovered_devices)} devices")
        except OSError as e:
            logger.warning(f"Art-Net socket error: {e}")
        except Exception as e:
            logger.warning(f"Art-Net discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")
        return self.discovered_devices

    @staticmethod
    def _asciiz(chunk: bytes) -> str:
        """Decode a NUL-terminated ASCII field."""
        return chunk.split(b"\x00", 1)[0].decode("ascii", "replace").strip()

    def _parse_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse an ArtPollReply into a DiscoveredDevice."""
        if len(data) < self._MIN_LEN or not data.startswith(self.ARTNET_ID):
            return None
        opcode = struct.unpack_from("<H", data, self._OFF_OPCODE)[0]
        if opcode != self.OP_POLL_REPLY:
            return None

        node_ip = ".".join(str(b) for b in data[self._OFF_IP : self._OFF_IP + 4])
        short_name = self._asciiz(data[self._OFF_SHORTNAME : self._OFF_SHORTNAME + 18])
        long_name = self._asciiz(data[self._OFF_LONGNAME : self._OFF_LONGNAME + 64])
        mac = ":".join(f"{b:02x}" for b in data[self._OFF_MAC : self._OFF_MAC + 6])
        oem = struct.unpack_from(">H", data, self._OFF_OEM)[0]
        esta = struct.unpack_from(">H", data, self._OFF_ESTA)[0]

        artnet_data: Dict[str, Any] = {
            "short_name": short_name,
            "long_name": long_name,
            "oem": f"0x{oem:04x}",
            "esta_manufacturer": f"0x{esta:04x}",
            "node_ip": node_ip,
        }
        artnet_data = {k: v for k, v in artnet_data.items() if v}

        # MAC of all zeros means the node didn't report one.
        mac_out = mac if mac != "00:00:00:00:00:00" else ""
        # A node may report 0.0.0.0; fall back to the packet source IP.
        ip_addresses = [node_ip] if node_ip != "0.0.0.0" else ([ip] if ip else [])

        return DiscoveredDevice(
            mac_address=mac_out,
            ip_addresses=ip_addresses,
            name=short_name or long_name or f"Art-Net Node ({ip})",
            manufacturer=f"ESTA 0x{esta:04x}",
            model=long_name or short_name,
            device_type="Lighting Controller",
            description=long_name or "Art-Net node",
            discovered_by=["artnet"],
            discovery_reasons=["artnet:ArtPollReply"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            artnet_data=artnet_data,
        )
