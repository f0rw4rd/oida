#!/usr/bin/env python3
"""
CAN bus protocol scanner (Layer 1 - SerialScanner).

Provides CAN bus traffic sniffing, arbitration ID discovery, UDS service
enumeration, and ISO-TP communication using the python-can library.

This scanner follows the OIDA BaseScanner/SerialScanner pattern for
standalone library usage with explicit run_scan() calls.

Functionality is split across mixin classes:
    - TrafficMixin: Passive sniffing, traffic stats, ID classification,
      raw CAN send/receive, ID filter parsing
    - UDSMixin: UDS service enumeration, session/DID/routine scanning,
      security seed collection, ECU reset, tester present
    - XCPMixin: XCP/CCP slave discovery, info gathering, memory read
    - CANopenMixin: Node scanning, SDO read, device info, OD scanning,
      EMCY/heartbeat monitoring, NMT state, PDO discovery, gateway detection
"""

from typing import Any, Dict

from ...utils import (
    SerialScanner,
    parse_bool,
    register_protocol,
)
from ...utils.lazy_import import lazy_import
from .constants import (
    DEFAULT_BAUDRATE,
    UDS_SERVICES,
)
from .mixins import CANopenMixin, ISOTPMixin, TrafficMixin, UDSMixin, XCPMixin

# Lazy import for python-can
_python_can = lazy_import("can", "CAN")

# Module metadata
protocol_options = {
    "baudrate": {
        "type": "int",
        "description": "CAN bus baudrate in bits/sec",
        "required": False,
        "default": DEFAULT_BAUDRATE,
    },
    "extended": {
        "type": "bool",
        "description": "Scan extended (29-bit) frame IDs in addition to standard (11-bit)",
        "required": False,
        "default": False,
    },
    "sniff-time": {
        "type": "int",
        "description": "Duration to sniff CAN bus traffic in seconds",
        "required": False,
        "default": 10,
    },
    "uds-scan": {
        "type": "bool",
        "description": "Discover UDS (ISO 14229) services on the bus",
        "required": False,
        "default": False,
    },
}


@register_protocol(
    name="CAN Scanner",
    description="Controller Area Network (CAN) bus scanner and analyzer",
    authors=["f0rw4rd"],
    references=[
        {"type": "url", "ref": "https://www.iso.org/standard/63648.html"},
        {"type": "url", "ref": "https://python-can.readthedocs.io/"},
    ],
    protocol_options=protocol_options,
    protocol_type="serial",
)
class CANScanner(ISOTPMixin, TrafficMixin, UDSMixin, XCPMixin, CANopenMixin, SerialScanner):
    """
    CAN bus protocol scanner implementing the SerialScanner interface.

    Features:
        - Passive traffic sniffing with statistics
        - Arbitration ID discovery and frequency analysis
        - UDS (ISO 14229) service enumeration
        - OBD-II (ISO 15031) service probing
        - ISO-TP (ISO 15765-2) message assembly
        - CANopen node detection
        - Raw CAN frame sending
        - Traffic pattern analysis
    """

    def __init__(self, args: Dict[str, Any]):
        # Set interface before super().__init__
        args.setdefault("interface", args.get("target", "can0"))
        super().__init__(args)

        self.baudrate = int(args.get("baudrate", DEFAULT_BAUDRATE))
        self.extended = parse_bool(args.get("extended", False))
        self.sniff_time = int(args.get("sniff-time", args.get("sniff_time", 10)))
        self.uds_scan = parse_bool(args.get("uds-scan", args.get("uds_scan", False)))
        self.channel = args.get("channel", "") or self.interface
        self.bus_type = args.get("bus-type", args.get("bus_type", "socketcan"))
        self.fd = parse_bool(args.get("fd", False))

        # Arbitration ID filter (optional)
        self.id_filter = self._parse_id_filter(args.get("filter-id", args.get("filter_id", "")))

    def get_protocol_name(self) -> str:
        return "CAN"

    def get_default_port(self) -> int:
        return 0  # Not applicable for CAN bus

    def check_dependencies(self) -> bool:
        return _python_can.is_available

    def connect(self) -> Any:
        """
        Create a python-can Bus instance.

        Returns:
            can.Bus instance or None on failure
        """
        can = _python_can()
        try:
            kwargs = {
                "interface": self.bus_type,
                "channel": self.channel,
            }

            # Only pass bitrate for interfaces that need it
            if self.bus_type not in ("virtual",):
                kwargs["bitrate"] = self.baudrate

            if self.fd:
                kwargs["fd"] = True

            bus = can.Bus(**kwargs)
            self.logger.display(
                f"Connected to CAN interface: {self.channel} "
                f"(bus_type={self.bus_type}, bitrate={self.baudrate})"
            )
            return bus

        except Exception as e:
            self.logger.fail(f"Failed to connect to CAN bus: {e}")
            return None

    def disconnect(self, connection: Any) -> None:
        """Close the CAN bus connection."""
        try:
            if connection:
                connection.shutdown()
                self.logger.debug("CAN bus connection closed")
        except Exception as e:
            self.logger.debug(f"Error closing CAN bus: {e}")

    def discover(self, connection: Any) -> Dict[str, Any]:
        """
        Main discovery routine - sniff traffic and analyze the bus.

        Args:
            connection: python-can Bus instance

        Returns:
            Dict containing discovery results
        """
        results: Dict[str, Any] = {}

        # Phase 1: Passive traffic sniffing
        self.logger.display(f"[Sniff] Listening on {self.channel} for {self.sniff_time}s...")
        stats = self._sniff_traffic(connection, duration=self.sniff_time)
        results["traffic_stats"] = {
            "total_messages": stats.total_messages,
            "unique_ids": stats.unique_ids,
            "duration_seconds": stats.duration_seconds,
            "messages_per_second": stats.messages_per_second,
            "error_frames": stats.error_frames,
            "remote_frames": stats.remote_frames,
        }

        # Print traffic summary
        self._print_traffic_stats(stats)

        # Phase 2: UDS service discovery (if requested)
        if self.uds_scan:
            self.logger.display("[UDS] Scanning for UDS-capable ECUs...")
            uds_results = self._scan_uds(connection)
            results["uds_results"] = [
                {
                    "request_id": f"0x{r.request_id:03X}",
                    "response_id": f"0x{r.response_id:03X}",
                    "supported_services": [
                        f"0x{s:02X} ({UDS_SERVICES.get(s, 'Unknown')})"
                        for s in r.supported_services
                    ],
                    "diagnostic_sessions": r.diagnostic_sessions,
                    "vehicle_info": r.vehicle_info,
                    "negative_responses": {
                        f"0x{svc:02X}": f"0x{nrc:02X}"
                        for svc, nrc in r.negative_responses.items()
                    },
                }
                for r in uds_results
            ]

        # Phase 3: Classify observed traffic
        results["discovered_devices"] = self._classify_traffic(stats)

        return results
