"""
Energy / solar active discovery scanners.

Multicast probes for energy-system devices (inverters, energy meters) that
announce on their own Speedwire-style groups.

Contains:
- SMASpeedwireScanner: SMA Speedwire inverter / Energy Meter / Home Manager
  discovery (UDP 9522, multicast 239.12.255.254)

References:
- Probe + discovery-response magic confirmed by the FHEM SMA-Speedwire tool:
  https://github.com/kettenbach-it/FHEM-SMA-Speedwire/blob/master/discover.py
- SMA Speedwire datagram "SMA\\0" magic / protocol (SMA Energy Meter Protocol
  TI): https://cdn.sma.de/fileadmin/content/www.developer.sma.de/docs/EMETER-Protokoll-TI-en-10.pdf

Note: the discovery response confirms an SMA device + its IP (this is what the
reference tools extract). Serial/model are NOT parsed here — the Energy Meter
datagram carries a serial but its offset is parser-dependent across sources, so
we do not guess it.
"""

import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional

from oida.protocols.discovery.core import (
    DiscoveredDevice,
    create_udp_socket,
    validate_interface,
    validate_timeout,
)
from oida.utils.rate_limiter import sendto
from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)


class SMASpeedwireScanner:
    """SMA Speedwire discovery (UDP 9522, multicast 239.12.255.254).

    A single fixed 20-byte multicast datagram makes SMA Speedwire devices
    (inverters, Sunny Home Manager, Energy Meter) reply on the group. Replies
    — and the energy meter's continuous announcements — carry the ``SMA\\0``
    magic, which is how we recognize an SMA device and its IP.

    Protocol (per FHEM SMA-Speedwire discover.py):
    - Probe (multicast 239.12.255.254:9522), 20 bytes:
        53 4d 41 00 00 04 02 a0 ff ff ff ff 00 00 00 20 00 00 00 00
    - Discovery response begins with:
        53 4d 41 00 00 04 02 a0 00 00 00 01 00 02 00 00 00 01
      More generally, any Speedwire datagram on this group starts with
      ``SMA\\0`` (0x534D4100).

    OT-safety: safe — a single small read-only multicast probe, no resend, no
    amplification surface.
    """

    MULTICAST_ADDR = "239.12.255.254"
    PORT = 9522

    # "SMA\0" magic shared by every Speedwire datagram.
    SMA_MAGIC = b"SMA\x00"  # 53 4d 41 00
    # The exact probe and the discovery-response prefix per the FHEM tool.
    PROBE = bytes.fromhex("534d4100000402a0ffffffff0000002000000000")
    DISCOVERY_RESPONSE_PREFIX = bytes.fromhex("534d4100000402a000000001000200000001")

    def __init__(self, interface: str, timeout: int = 10):
        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def _build_probe(self) -> bytes:
        """Return the fixed SMA Speedwire discovery probe."""
        return self.PROBE

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send the Speedwire multicast probe and collect SMA replies."""
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
            logger.debug(f"SMA: sent Speedwire probe to {self.MULTICAST_ADDR}:{self.PORT}")

            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(65535)
                    device = self._parse_response(data, addr[0])
                    if device:
                        with self._lock:
                            key = device.ip_addresses[0] if device.ip_addresses else addr[0]
                            self.discovered_devices[key] = device
                            logger.debug(f"SMA: found {key}")
                except TimeoutError:
                    pass  # single probe, no resend (OT safety)
                except OSError as e:
                    logger.debug(f"SMA recv error: {e}")

            logger.info(f"SMA found {len(self.discovered_devices)} devices")

        except OSError as e:
            logger.warning(f"SMA socket error: {e}")
        except Exception as e:
            logger.warning(f"SMA discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

        return self.discovered_devices

    def _parse_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Recognize an SMA Speedwire device from a reply.

        Any datagram on the Speedwire group beginning with the ``SMA\\0`` magic
        is an SMA device. We never receive our own probe (different source), so
        the magic is a reliable positive. Returns None otherwise.
        """
        if not data or not data.startswith(self.SMA_MAGIC):
            return None

        is_discovery_reply = data.startswith(self.DISCOVERY_RESPONSE_PREFIX)
        sma_data: Dict[str, Any] = {
            "magic": "SMA\\0",
            "discovery_response": is_discovery_reply,
            "raw_prefix": data[:18].hex(),
        }

        ip_addresses = [ip] if ip else []
        return DiscoveredDevice(
            ip_addresses=ip_addresses,
            name=f"SMA Speedwire Device ({ip})",
            manufacturer="SMA",
            device_type="Solar Inverter / Energy Meter",
            description="SMA Speedwire device",
            discovered_by=["sma"],
            discovery_reasons=["sma:speedwire"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            sma_data=sma_data,
        )
