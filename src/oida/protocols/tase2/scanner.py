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
# TASE.2 Error Codes and Constants
# =============================================================================


class TASE2ErrorClass:
    """MMS Error Classes used in TASE.2 responses."""

    ACCESS = "ACCESS"
    INITIATE = "INITIATE"
    DEFINITION = "DEFINITION"
    RESOURCE = "RESOURCE"
    SERVICE = "SERVICE"
    FILE = "FILE"


class TASE2ErrorCode:
    """
    TASE.2/MMS Error Codes.

    Used in negative responses to indicate specific failure conditions.
    """

    # Access class errors (most common)
    OBJECT_NON_EXISTENT = "OBJECT-NON-EXISTENT"
    OBJECT_ACCESS_DENIED = "OBJECT-ACCESS-DENIED"
    OBJECT_ACCESS_UNSUPPORTED = "OBJECT-ACCESS-UNSUPPORTED"
    OBJECT_INVALIDATED = "OBJECT-INVALIDATED"

    # Hardware/system errors
    HARDWARE_FAULT = "HARDWARE-FAULT"
    TEMPORARILY_UNAVAILABLE = "TEMPORARILY-UNAVAILABLE"

    # Type/attribute errors
    TYPE_INCONSISTENT = "TYPE-INCONSISTENT"
    OBJECT_ATTRIBUTE_INCONSISTENT = "OBJECT-ATTRIBUTE-INCONSISTENT"
    OBJECT_ATTRIBUTE_UNSUPPORTED = "OBJECT-ATTRIBUTE-UNSUPPORTED"
    ATTRIBUTE_INCONSISTENT = "ATTRIBUTE-INCONSISTENT"

    # Other
    OTHER = "OTHER"


class TASE2DataAccessError:
    """
    MMS DataAccessError codes used in Read/Write responses.
    """

    SUCCESS = 0
    OBJECT_NON_EXISTENT = 1
    OBJECT_ACCESS_DENIED = 2
    OBJECT_ACCESS_UNSUPPORTED = 3
    OBJECT_INVALIDATED = 4
    HARDWARE_FAULT = 5
    TYPE_INCONSISTENT = 6
    TEMPORARILY_UNAVAILABLE = 7
    OBJECT_UNDEFINED = 8

    @classmethod
    def to_string(cls, code: int) -> str:
        """Convert error code to human-readable string."""
        mapping = {
            0: "Success",
            1: "Object does not exist",
            2: "Access denied (bilateral table)",
            3: "Access not supported",
            4: "Object invalidated",
            5: "Hardware fault",
            6: "Type inconsistent",
            7: "Temporarily unavailable (device busy/armed)",
            8: "Object undefined",
        }
        return mapping.get(code, f"Unknown error ({code})")


class TASE2DeviceState:
    """
    TASE.2 Device States.

    SBO devices have two states that affect operation execution.
    """

    IDLE = "IDLE"  # Not selected, ready for new Select
    ARMED = "ARMED"  # Selected, waiting for Operate command


class TASE2TagValue:
    """
    TASE.2 Device Tag Values.

    Tags control whether device operations are permitted.
    """

    NO_TAG = "NO_TAG"  # No restrictions
    OPEN_AND_CLOSE_INHIBIT = "OPEN_AND_CLOSE_INHIBIT"  # Full lockout
    CLOSE_ONLY_INHIBIT = "CLOSE_ONLY_INHIBIT"  # Only open operations allowed


class TASE2PointType:
    """TASE.2 Data Point Types."""

    # Real (analog) types
    REAL = "DATA_REAL"
    REAL_Q = "DATA_REAL_Q"
    REAL_Q_TIME = "DATA_REAL_Q_TIME"
    REAL_EXTENDED = "DATA_REAL_EXTENDED"

    # State (digital) types
    STATE = "DATA_STATE"
    STATE_Q = "DATA_STATE_Q"
    STATE_Q_TIME = "DATA_STATE_Q_TIME"
    STATE_EXTENDED = "DATA_STATE_EXTENDED"
    STATE_SUPPLEMENTAL = "DATA_STATE_SUPPLEMENTAL"

    # Discrete types
    DISCRETE = "DATA_DISCRETE"
    DISCRETE_Q = "DATA_DISCRETE_Q"
    DISCRETE_Q_TIME = "DATA_DISCRETE_Q_TIME"
    DISCRETE_EXTENDED = "DATA_DISCRETE_EXTENDED"


class TASE2Quality:
    """TASE.2 Quality Flags."""

    VALIDITY_GOOD = 0x00
    VALIDITY_INVALID = 0x01
    VALIDITY_RESERVED = 0x02
    VALIDITY_HELD = 0x03

    # Additional quality bits
    CURRENT_SOURCE = 0x04  # 1=substituted, 0=measured
    NORMAL_VALUE = 0x08  # 1=abnormal, 0=normal
    TIME_STAMP_QUALITY = 0x10  # 1=invalid, 0=valid

    @classmethod
    def decode(cls, quality_byte: int) -> Dict[str, Any]:
        """Decode quality byte into readable dict."""
        validity_map = {0: "good", 1: "invalid", 2: "reserved", 3: "held"}
        return {
            "validity": validity_map.get(quality_byte & 0x03, "unknown"),
            "substituted": bool(quality_byte & 0x04),
            "abnormal": bool(quality_byte & 0x08),
            "timestamp_invalid": bool(quality_byte & 0x10),
            "raw": quality_byte,
        }


class TASE2DSConditions:
    """
    TASE.2 DSConditions flags.

    These indicate which conditions triggered a transfer report.
    """

    INTERVAL_TIMEOUT = 0x01  # Report sent due to interval time
    OBJECT_CHANGE = 0x02  # Object value/status/quality changed
    OPERATOR_REQUEST = 0x04  # Operator requested the report
    INTEGRITY_TIMEOUT = 0x08  # Integrity check interval expired (RBE only)
    OTHER_EXTERNAL_EVENT = 0x10  # Other external event occurred

    @classmethod
    def decode(cls, conditions: int) -> Dict[str, bool]:
        """Decode conditions bitfield into dict."""
        return {
            "interval_timeout": bool(conditions & cls.INTERVAL_TIMEOUT),
            "object_change": bool(conditions & cls.OBJECT_CHANGE),
            "operator_request": bool(conditions & cls.OPERATOR_REQUEST),
            "integrity_timeout": bool(conditions & cls.INTEGRITY_TIMEOUT),
            "other_external_event": bool(conditions & cls.OTHER_EXTERNAL_EVENT),
        }


# =============================================================================
# Block 4: Information Messages Constants
# =============================================================================


class TASE2IMStatus:
    """
    TASE.2 Information Message Status Values.

    Status of messages in an IM store.
    """

    ACTIVE = "ACTIVE"  # Message is active/current
    ARCHIVED = "ARCHIVED"  # Message has been archived
    DELETED = "DELETED"  # Message marked for deletion


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


def parse_tase2_error(error_class: str, error_code: str) -> str:
    """
    Parse TASE.2/MMS error into human-readable description.

    Args:
        error_class: MMS error class (e.g., "ACCESS")
        error_code: MMS error code (e.g., "OBJECT-ACCESS-DENIED")

    Returns:
        Human-readable error description
    """
    descriptions = {
        (
            TASE2ErrorClass.ACCESS,
            TASE2ErrorCode.OBJECT_NON_EXISTENT,
        ): "Object does not exist - check bilateral table configuration",
        (
            TASE2ErrorClass.ACCESS,
            TASE2ErrorCode.OBJECT_ACCESS_DENIED,
        ): "Access denied - not authorized in bilateral table",
        (
            TASE2ErrorClass.ACCESS,
            TASE2ErrorCode.HARDWARE_FAULT,
        ): "Hardware fault - device is unavailable or inoperable",
        (
            TASE2ErrorClass.ACCESS,
            TASE2ErrorCode.TEMPORARILY_UNAVAILABLE,
        ): "Temporarily unavailable - device is ARMED or busy",
        (
            TASE2ErrorClass.ACCESS,
            TASE2ErrorCode.TYPE_INCONSISTENT,
        ): "Type inconsistent - wrong data type for operation",
        (
            TASE2ErrorClass.ACCESS,
            TASE2ErrorCode.OBJECT_ATTRIBUTE_INCONSISTENT,
        ): "Attribute inconsistent - invalid parameter value",
        (
            TASE2ErrorClass.INITIATE,
            TASE2ErrorCode.OTHER,
        ): "Association initiation failed - check AP titles and bilateral table",
    }
    return descriptions.get((error_class, error_code), f"Error: {error_class}/{error_code}")


def _require_lib():
    """Raise DependencyError if pyiec61850-ng is not installed."""
    _pyiec61850_tase2()  # raises DependencyError if missing


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

        # Safety gate: write/control/tag operations run only when --confirm is
        # given. BaseScanner hardwires read_only=True (the legacy "read-only"
        # arg is never surfaced by the tase2 CLI, so nothing could ever clear
        # it) which silently no-op'd every confirm-gated op. Drive read_only
        # off --confirm so the dangerous paths actually execute under --confirm.
        self.confirm = parse_bool(args.get("confirm", False))
        self.read_only = not self.confirm

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
        self.bilateral_table_id = ""
        self.supported_features = {}
        self.tase2_version = None
        self.device_states = {}  # Track SBO device states (IDLE/ARMED)

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

        _require_lib()

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
            # Protocol discovery (Phase 1)
            results["supported_features"] = self.get_supported_features(connection)
            results["server_blocks"] = self._enumerate_server_blocks(connection)
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

            # Write access testing (mutates points - gated behind --confirm)
            if self.test_write:
                if self.read_only:
                    self.logger.warning("--test-write requires --confirm; skipping write tests")
                else:
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

            self.bilateral_table_id = blt_info["table_id"]

        except Exception as e:
            self.logger.debug(f"Error getting bilateral table: {e}")

        return blt_info
