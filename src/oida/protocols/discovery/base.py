"""
Base classes for discovery scanners.

Contains:
- PassiveListenerBase: ABC for passive packet listeners
"""

from abc import ABC, abstractmethod
import threading
import time
from typing import Any, Dict, Iterator, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .core import DiscoveredDevice

from logging import DEBUG as _DEBUG

from ...utils.ics_logger import get_module_logger
from ...utils.lazy_import import lazy_import

_scapy_all = lazy_import("scapy.all", "discovery")

logger = get_module_logger(__name__)


class PassiveListenerBase(ABC):
    """Abstract base class for passive discovery listeners.

    Provides common infrastructure for:
    - Live packet capture via AsyncSniffer
    - Direct packet feeding for testing
    - Thread-safe device storage

    Subclasses must:
    - Set PROTOCOL_NAME class attribute
    - Set BPF_FILTER class attribute (or None for all traffic)
    - Implement process_packet() method
    - Optionally override should_process_packet() for filtering

    Example:
        class MyListener(PassiveListenerBase):
            PROTOCOL_NAME = "my-protocol"
            BPF_FILTER = "udp port 1234"

            def process_packet(self, packet) -> None:
                with self._lock:
                    # Parse packet and update self.discovered_devices
                    pass

    Usage:
        # Live capture
        listener = MyListener(interface="eth0", timeout=30)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = MyListener(interface="eth0")
        listener.feed_packet(mock_packet)
        assert "key" in listener.discovered_devices
    """

    # Class-level configuration - subclasses must override
    PROTOCOL_NAME: str = ""  # e.g., "arp-passive", "dhcp-passive"
    BPF_FILTER: Optional[str] = None  # e.g., "arp", "udp port 67 or 68"

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize passive listener.

        Args:
            interface: Network interface to capture on
            timeout: Capture timeout in seconds
            nxc_logger: Optional NXC-style logger for user-visible output
        """
        from .core import validate_interface, validate_timeout

        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.nxc_logger = nxc_logger
        self.discovered_devices: Dict[str, "DiscoveredDevice"] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, "DiscoveredDevice"]:
        """Run discovery scan via live capture.

        Returns:
            Dict mapping device keys to DiscoveredDevice instances
        """
        return self._live_capture()

    def _live_capture(self) -> Dict[str, "DiscoveredDevice"]:
        """Capture packets from live interface using AsyncSniffer."""
        scapy = _scapy_all()
        AsyncSniffer = scapy.AsyncSniffer
        conf = scapy.conf

        conf.verb = 0
        logger.debug(f"{self.PROTOCOL_NAME}: Listening on {self.interface} for {self.timeout}s")

        sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.BPF_FILTER,
            prn=self._safe_process_packet,
            store=False,
        )

        sniffer.start()
        time.sleep(self.timeout)
        sniffer.stop()

        logger.debug(f"{self.PROTOCOL_NAME}: {len(self.discovered_devices)} devices discovered")
        return self.discovered_devices

    def _safe_process_packet(self, packet) -> None:
        """Wrapper with error handling for packet processing.

        Args:
            packet: Scapy packet to process

        Note:
            Does not return a value to avoid scapy printing the result.
        """
        try:
            if self.should_process_packet(packet):
                # Debug: dump packet before processing
                if logger.isEnabledFor(_DEBUG):
                    self._debug_dump_packet(packet)
                self.process_packet(packet)
        except Exception as e:
            logger.debug(f"{self.PROTOCOL_NAME} packet parse error: {e}")

    def _debug_dump_packet(self, packet) -> None:
        """Dump packet info and hex for debugging.

        Override in subclasses for protocol-specific dump format.
        """
        from .core import hex_dump

        try:
            from scapy.all import IP, IPv6

            # Get source/dest info
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                raw_data = bytes(packet[IP].payload) if packet[IP].payload else b""
            elif IPv6 in packet:
                src = packet[IPv6].src
                dst = packet[IPv6].dst
                raw_data = bytes(packet[IPv6].payload) if packet[IPv6].payload else b""
            else:
                src = "?"
                dst = "?"
                raw_data = bytes(packet) if packet else b""

            logger.debug(f"{self.PROTOCOL_NAME} packet: {src} -> {dst} ({len(raw_data)} bytes)")
            logger.debug(f"{self.PROTOCOL_NAME} hex dump:\n{hex_dump(raw_data)}")
        except Exception as e:
            logger.debug(f"{self.PROTOCOL_NAME} dump error: {e}")

    def should_process_packet(self, packet) -> bool:
        """Check if packet should be processed by this listener.

        Override for custom filtering beyond BPF_FILTER.
        Default: process all packets (BPF filter already applied).

        Args:
            packet: Scapy packet to check

        Returns:
            True if packet should be processed
        """
        return True

    @abstractmethod
    def process_packet(self, packet) -> None:
        """Process a single packet.

        Subclasses must implement this method.
        Use self._lock when modifying self.discovered_devices for thread safety.

        Args:
            packet: Scapy packet to process
        """

    # -------------------------------------------------------------------------
    # Testing API - for feeding packets directly without network capture
    # -------------------------------------------------------------------------

    def feed_packet(self, packet) -> None:
        """Feed a single packet for testing.

        Bypasses network capture and feeds packet directly to processing.

        Args:
            packet: Scapy packet to process
        """
        self._safe_process_packet(packet)

    def feed_packets(self, packets: Iterator) -> Dict[str, "DiscoveredDevice"]:
        """Feed multiple packets and return discovered devices.

        Useful for batch testing with packet iterables.

        Args:
            packets: Iterable of Scapy packets

        Returns:
            Dict of discovered devices after processing all packets
        """
        for packet in packets:
            self._safe_process_packet(packet)
        return self.discovered_devices
