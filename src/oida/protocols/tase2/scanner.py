#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TASE.2/ICCP Protocol Scanner

Security scanner for TASE.2/ICCP protocol used in utility control center communications.
"""

from typing import Any, Dict

from ...utils import (
    NetworkScanner,
    register_protocol,
    parse_bool,
)
from ...utils.exceptions import DependencyError
from ...utils.lazy_import import lazy_import
from .mixins import (
    ControlMixin,
    DiscoveryMixin,
    EnumerationMixin,
    InfoMessagesMixin,
    SecurityMixin,
    TransferSetsMixin,
)

_pyiec61850_tase2 = lazy_import(
    "pyiec61850.tase2", "TASE.2", install_hint="pip install pyiec61850-ng"
)


# =============================================================================
# Block 4: Information Messages Constants
# =============================================================================


class TASE2IMStorageStatus:
    """
    TASE.2 IM Transfer Store Status Values.

    Status of an Information Message store.
    """

    AVAILABLE = "AVAILABLE"  # Store can accept messages
    FULL = "FULL"  # Store is at capacity
    ERROR = "ERROR"  # Store has an error condition


class TASE2IMScope:
    """
    TASE.2 Information Message Scope Values.

    Determines whether an IM is VCC-scope or ICC-scope.
    Per IEC 60870-6-503, Information Messages can be associated with
    either a Virtual Control Center (VCC) or Invocation Control Center (ICC).
    """

    VCC = "VCC"  # Virtual Control Center scope (server-wide)
    ICC = "ICC"  # Invocation Control Center scope (bilateral-specific)


protocol_options = {
    "discover-vcc": {
        "type": "bool",
        "description": "Discover Virtual Control Centers",
        "required": False,
        "default": True,
    },
    "discover-icc": {
        "type": "bool",
        "description": "Discover Indication Control Centers",
        "required": False,
        "default": True,
    },
    "analyze-blt": {
        "type": "bool",
        "description": "Analyze bilateral tables",
        "required": False,
        "default": True,
    },
    "enumerate-points": {
        "type": "bool",
        "description": "Enumerate all data points",
        "required": False,
        "default": True,
    },
    "test-rbe": {
        "type": "bool",
        "description": "Test Report-by-Exception capability (Block 2)",
        "required": False,
        "default": False,
    },
    "test-control": {
        "type": "bool",
        "description": "Test device control operations (Block 5)",
        "required": False,
        "default": False,
    },
    "test-write": {
        "type": "bool",
        "description": "Test write access to data points",
        "required": False,
        "default": False,
    },
    "max-points": {
        "type": "int",
        "description": "Maximum points to enumerate per domain",
        "required": False,
        "default": 100,
    },
    "local-ap-title": {
        "type": "string",
        "description": "Local AP title (e.g., 1.1.1.999)",
        "required": False,
        "default": "",
    },
    "remote-ap-title": {
        "type": "string",
        "description": "Remote AP title",
        "required": False,
        "default": "",
    },
}


@register_protocol(
    name="TASE.2/ICCP Scanner",
    description="TASE.2/ICCP protocol scanner for control center security testing",
    default_port=102,
    authors=["f0rw4rd"],
    references=[
        {"type": "url", "ref": "https://en.wikipedia.org/wiki/IEC_60870-6"},
        {"type": "url", "ref": "https://github.com/f0rw4rd/pyiec61850-ng"},
    ],
    protocol_options=protocol_options,
)
class TASE2Scanner(
    DiscoveryMixin,
    EnumerationMixin,
    TransferSetsMixin,
    ControlMixin,
    InfoMessagesMixin,
    SecurityMixin,
    NetworkScanner,
):
    """TASE.2/ICCP Protocol Scanner"""

    def __init__(self, args: Dict[str, Any]):
        super().__init__(args)

        # Options
        self.discover_vcc = parse_bool(args.get("discover-vcc", True))
        self.discover_icc = parse_bool(args.get("discover-icc", True))
        self.analyze_blt = parse_bool(args.get("analyze-blt", True))
        self.enumerate_points = parse_bool(args.get("enumerate-points", True))
        self.test_rbe = parse_bool(args.get("test-rbe", False))
        self.test_control = parse_bool(args.get("test-control", False))
        self.test_write = parse_bool(args.get("test-write", False))
        self.max_points = int(args.get("max-points", 100))
        self.local_ap_title = args.get("local-ap-title", "")
        self.remote_ap_title = args.get("remote-ap-title", "")

        # Internal state
        self.client = None
        self.domains = []
        self.supported_features = {}
        self.tase2_version = None

    def get_protocol_name(self) -> str:
        return "TASE.2/ICCP"

    def get_default_port(self) -> int:
        return 102

    def check_dependencies(self) -> bool:
        """Check if pyiec61850-ng is available."""
        return _pyiec61850_tase2.is_available

    def connect(self) -> Any:
        """Establish TASE.2 connection."""
        host, port = self.get_target_info()

        _pyiec61850_tase2()  # raises DependencyError if pyiec61850-ng is missing

        try:
            self.client = _pyiec61850_tase2.TASE2Client(
                local_ap_title=self.local_ap_title if self.local_ap_title else None,
                remote_ap_title=self.remote_ap_title if self.remote_ap_title else None,
            )

            self.client.connect(host, port=port)

            if self.client.is_connected:
                self.logger.display(f"Connected to TASE.2 server at {host}:{port}")
                return self.client
            else:
                self.logger.fail(f"Failed to connect to {host}:{port}")
                return None

        except DependencyError:
            raise
        except Exception as e:
            self.logger.fail(f"TASE.2 connection failed: {e}")
            return None

    def disconnect(self, connection: Any) -> None:
        """Close TASE.2 connection."""
        if connection:
            try:
                connection.disconnect()
            except Exception as e:
                self.logger.debug(f"Disconnect error: {e}")

    def discover(self, connection: Any) -> Dict[str, Any]:
        """Perform TASE.2 discovery and security scanning."""
        results = {
            "supported_features": {},
            "server_blocks": {},
            "tase2_version": {},
            "bilateral_table": {},
            "domains": [],
            "vcc_variables": [],
            "data_points": [],
            "transfer_sets": [],
            "control_points": [],
            "device_tags": [],
            "conformance_blocks": [],
            "security_analysis": {},
        }

        try:
            # Protocol discovery (Phase 1) - fetch the conformance-block map once
            # and feed it to both consumers to avoid a double round trip and a
            # duplicate block table in the operator output.
            try:
                server_blocks = connection.get_server_blocks()
            except Exception as e:
                self.logger.debug(f"Error getting server blocks: {e}")
                server_blocks = None
            results["server_blocks"] = self._enumerate_server_blocks(connection, server_blocks)
            results["supported_features"] = self.get_supported_features(
                connection, server_blocks, display=False
            )
            results["tase2_version"] = self.get_tase2_version(connection)

            # Bilateral table info
            if self.analyze_blt:
                results["bilateral_table"] = self._analyze_bilateral_table(connection)

            # Domain discovery
            results["domains"] = self._discover_domains(connection)

            # VCC variables
            if self.discover_vcc:
                results["vcc_variables"] = self._discover_vcc_variables(connection)

            # Data point enumeration
            if self.enumerate_points:
                results["data_points"] = self._enumerate_data_points(connection)

            # Transfer sets (Block 2)
            if self.test_rbe:
                results["transfer_sets"] = self._discover_transfer_sets(connection)
                results["conformance_blocks"].append("Block 2 (RBE)")

            # Control testing (Block 5)
            if self.test_control:
                results["control_points"] = self._test_control_access(connection)
                if results["control_points"]:
                    results["conformance_blocks"].append("Block 5 (Control)")

            # Write access testing
            if self.test_write and not self.read_only:
                self._test_write_access(connection, results)

            # Security analysis
            results["security_analysis"] = self._analyze_security(results)

            # Client statistics
            try:
                stats = connection._statistics
                results["client_statistics"] = {
                    "total_reads": stats.total_reads,
                    "total_writes": stats.total_writes,
                    "total_errors": stats.total_errors,
                    "reports_received": stats.reports_received,
                    "control_operations": stats.control_operations,
                    "uptime_seconds": stats.uptime_seconds,
                }
            except Exception as e:
                self.logger.debug(f"Could not get client statistics: {e}")

            # Report findings
            self._report_findings(results)

        except Exception as e:
            self.logger.fail(f"Error during TASE.2 discovery: {e}")
            results["error"] = str(e)

        return results

    def _analyze_bilateral_table(self, connection: Any) -> Dict[str, Any]:
        """Analyze bilateral table configuration."""
        blt_info = {
            "table_id": "",
            "table_count": 0,
        }

        try:
            blt_info["table_id"] = connection.get_bilateral_table_id()
            blt_info["table_count"] = connection.get_server_bilateral_table_count()

            if blt_info["table_id"]:
                self.logger.display(f"Bilateral Table ID: {blt_info['table_id']}")
            self.logger.display(f"Server BLT Count: {blt_info['table_count']}")

        except Exception as e:
            self.logger.debug(f"Error getting bilateral table: {e}")

        return blt_info
