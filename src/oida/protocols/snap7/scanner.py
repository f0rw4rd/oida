#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Siemens S7 Protocol Scanner

Scanner implementation for Siemens S7 PLCs using the Snap7 library.
"""

from typing import Dict, List, Optional, Any, TYPE_CHECKING
from ...utils import (
    register_protocol,
    create_protocol_module,
    NetworkScanner,
    safe_int_conversion,
)
from ...utils.protocol_helpers import ConnectionHelper
from ...utils.lazy_import import lazy_import

from ...utils.ics_logger import get_module_logger

from .mixins import (
    SlotScanMixin,
    DeviceInfoMixin,
    SecurityMixin,
    MemoryMixin,
    BlockOperationsMixin,
)

logger = get_module_logger(__name__)

# Type hints only - no runtime import
if TYPE_CHECKING:
    pass

# Lazy import for snap7 - only loads when actually used
_snap7 = lazy_import("snap7", "Snap7")


def _get_snap7():
    """Get snap7 module, raising DependencyError if not available."""
    return _snap7()


def _get_snap7_client():
    """Get snap7.client module lazily."""
    snap7_mod = _get_snap7()
    return snap7_mod.client


def _get_block_types():
    """Get Block type constants lazily."""
    client = _get_snap7_client()
    return client.Block


from contextlib import contextmanager


@contextmanager
def _suppress_snap7_logging():
    """Context manager to suppress snap7 library logging during operations.

    The snap7 C library emits noisy error logs during normal scanning
    (e.g. probing unreachable slots, testing access). This temporarily
    raises the snap7 logger level to silence those messages and restores
    the original level on exit.
    """
    import logging

    snap7_logger = logging.getLogger("snap7")
    original_level = snap7_logger.level
    snap7_logger.setLevel(logging.CRITICAL + 1)
    try:
        yield
    finally:
        snap7_logger.setLevel(original_level)


def _run_with_timeout(func, timeout_seconds=5, error_msg="Operation timed out"):
    """
    Run a function with timeout using ThreadPoolExecutor.

    Args:
        func: Callable to execute
        timeout_seconds: Maximum time to wait
        error_msg: Error message on timeout

    Returns:
        Function result or dict with 'error' key on failure
    """
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(func)
        try:
            return future.result(timeout=timeout_seconds)
        except FuturesTimeoutError as e:
            logger.debug("run with timeout failed: %s", e)
            return {"error": error_msg}
        except Exception as e:
            # Decode bytes in error messages (snap7 returns bytes)
            logger.debug("run with timeout failed: %s", e)
            err_str = str(e)
            if "b'" in err_str and "'" in err_str:
                # Extract and decode the bytes portion
                try:
                    import re

                    match = re.search(r"b'([^']*)'", err_str)
                    if match:
                        err_str = match.group(1)
                except Exception as e:
                    logger.debug("run with timeout failed: %s", e)
                    pass  # Regex extraction failed, use original error string
            return {"error": err_str}


def _get_order_code_extended(client) -> Dict[str, Any]:
    """
    Get order code with bootloader version using raw ctypes access.

    The standard S7OrderCode structure is 24 bytes, but the actual PLC response
    contains 27 bytes with bootloader version in the last 3 bytes.

    Returns dict with: code, firmware (V1.V2.V3), bootloader (V4.V5.V6)
    """
    result = {"code": None, "firmware": None, "bootloader": None}

    try:
        # Try standard method first. python-snap7 S7OrderCode exposes
        # OrderCode (there is no "Code" attribute).
        oc = client.get_order_code()
        code = getattr(oc, "OrderCode", None)
        if code:
            if isinstance(code, bytes):
                code = code.decode("ascii", errors="ignore")
            result["code"] = str(code).strip("\x00 ")

        # Extract firmware version
        v1 = getattr(oc, "V1", 0)
        v2 = getattr(oc, "V2", 0)
        v3 = getattr(oc, "V3", 0)
        if v1 != 0 or v2 != 0 or v3 != 0:
            result["firmware"] = f"V{v1}.{v2}.{v3}"

        # Note: the bootloader (V4-V6) lived in a 27-byte extended buffer read
        # via client._lib / Cli_GetOrderCode — ctypes internals removed in
        # python-snap7 2.x, so that block always AttributeError'd and is gone.

    except Exception as e:
        logger.debug("get order code failed: %s", e)

    return result


def _identify_main_slot(slots: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Identify the main CPU slot from a list of discovered slots.

    Priority:
    1. Slot with "cpu" in module_type_name
    2. Slot with CPU-like order code (6ES7 21x, 31x, 41x, 51x)
    3. First slot in list
    """
    if not slots:
        return None

    # Priority 1: Look for "cpu" in module name
    for slot in slots:
        module_name = slot.get("module_name", "") or ""
        if "cpu" in module_name.lower():
            return slot

    # Priority 2: Look for CPU order codes
    cpu_prefixes = ("6ES7 21", "6ES7 31", "6ES7 41", "6ES7 51")  # S7-1200/1500/300/400/1500
    for slot in slots:
        order_code = slot.get("hw_order_code", "") or slot.get("order_code", "") or ""
        if any(order_code.startswith(prefix) for prefix in cpu_prefixes):
            return slot

    # Priority 3: First slot
    return slots[0]


protocol_options = {
    "rack": {
        "type": "int",
        "description": "S7 PLC rack number",
        "required": False,
        "default": 0,
    },
    "slot": {
        "type": "int",
        "description": "S7 PLC slot number (auto-detect if not specified)",
        "required": False,
        "default": None,
    },
    "password": {
        "type": "string",
        "description": "S7 password for protected PLCs",
        "required": False,
        "default": "",
    },
    "enumerate-dbs": {
        "type": "bool",
        "description": "Enumerate data blocks",
        "required": False,
        "default": False,
    },
    "test-memory-areas": {
        "type": "bool",
        "description": "Test access to memory areas (I, Q, M, C, T)",
        "required": False,
        "default": False,
    },
    "read-values": {
        "type": "bool",
        "description": "Read sample values from accessible areas",
        "required": False,
        "default": False,
    },
    "max-dbs": {
        "type": "int",
        "description": "Maximum number of data blocks to enumerate",
        "required": False,
        "default": 100,
    },
}


@register_protocol(
    name="Siemens S7 Scanner",
    description="""Siemens S7 PLC scanner using Snap7 protocol""",
    default_port=102,
    authors=["f0rw4rd"],
    references=[{"type": "url", "ref": "http://snap7.sourceforge.net"}],
    protocol_options=protocol_options,
)
class Snap7Scanner(
    SlotScanMixin,
    DeviceInfoMixin,
    SecurityMixin,
    MemoryMixin,
    BlockOperationsMixin,
    NetworkScanner,
):
    """Siemens S7 Protocol Scanner using Snap7"""

    def __init__(self, args: Dict[str, Any]):
        from ...utils import parse_bool

        super().__init__(args)
        self.rack = safe_int_conversion(args.get("rack"), 0)
        self.slot = safe_int_conversion(args.get("slot"), None)  # None = auto-scan
        self.password = args.get("password", "")
        self.enumerate_dbs = parse_bool(args.get("enumerate-dbs", False))
        self.test_memory_areas = parse_bool(args.get("test-memory-areas", False))
        self.read_values = parse_bool(args.get("read-values", False))
        self.max_dbs = safe_int_conversion(args.get("max-dbs"), 100)


    def get_protocol_name(self) -> str:
        return "S7"

    def get_default_port(self) -> int:
        return 102  # ISO-TSAP port

    def check_dependencies(self) -> bool:
        return _snap7.is_available

    def connect(self) -> Any:
        """Establish S7 connection with auto slot detection"""
        host, port = self.get_target_info()
        slot_or_auto = self.slot if self.slot is not None else "auto"
        self.logger.debug(
            "Connecting to S7: host=%s port=%s rack=%s slot=%s", host, port, self.rack, slot_or_auto
        )

        # If slot is specified, connect directly
        if self.slot is not None:
            self.logger.debug("Slot specified, direct connect")
            return self._connect_to_slot(host, port, self.rack, self.slot)

        # Auto-detect slot by scanning common slots
        self.logger.debug("Auto-detecting slot via scan_slots")
        self.logger.display("Scanning slots...")
        found_slots = self.scan_slots(host, port)

        if not found_slots:
            self.logger.fail(f"No S7 PLC found on any slot at {host}:{port}")
            return None

        # Prefer actual CPU over communication processors (S7-CP)
        # CPU series: S7-300, S7-400, S7-1200, S7-1500, ET200, SoftPLC
        cpu_series = {
            "S7-300",
            "S7-400",
            "S7-1200",
            "S7-1500",
            "S7-200",
            "ET200S",
            "ET200M",
            "ET200SP",
            "ET200pro",
            "SoftPLC",
        }
        slot_info = None
        for slot in found_slots:
            series = slot.get("series", "")
            if series in cpu_series:
                slot_info = slot
                break
        # Fallback to first slot if no CPU found
        if not slot_info:
            slot_info = found_slots[0]

        self.slot = slot_info["slot"]
        self.rack = slot_info["rack"]

        # S7-1200/1500 require S7CommPlus protocol (not supported)
        series = slot_info.get("series", "")
        firmware = slot_info.get("firmware", "")
        order_code = slot_info.get("order_code", "")

        if series in ("S7-1200", "S7-1500"):
            self._display_s7plus_not_supported(series, firmware, order_code)

        return self._connect_to_slot(host, port, self.rack, self.slot)

    def _connect_to_slot(self, host: str, port: int, rack: int, slot: int) -> Any:
        """Connect to a specific rack/slot"""
        try:
            snap7_client = _get_snap7_client()
            client = snap7_client.Client()

            # snap7 C library requires IP addresses, not hostnames
            ip = ConnectionHelper.resolve_hostname(host)
            if ip != host:
                self.logger.debug("Resolved %s -> %s", host, ip)
            client.connect(ip, rack, slot, tcp_port=port)

            if not client.get_connected():
                return None

            self.logger.debug(f"Connected to S7 PLC at {host}:{port} (Rack: {rack}, Slot: {slot})")

            # If password provided, attempt authentication
            if self.password:
                try:
                    client.set_session_password(self.password)
                    self.logger.debug("S7 password authentication successful")
                except Exception as e:
                    self.logger.warning(f"Password authentication failed: {e}")

            return client

        except Exception as e:
            self.logger.debug("connect to slot failed: %s", e)
            return None

    def disconnect(self, connection: Any) -> None:
        """Close S7 connection"""
        self.logger.debug("Disconnecting from S7 PLC")
        if connection:
            try:
                connection.disconnect()
            except Exception as e:
                self.logger.debug(f"Error disconnecting: {e}")

    def discover(self, connection: Any) -> Dict[str, Any]:
        """Perform S7 discovery and scanning"""
        self.logger.debug(
            "Starting S7 discovery workflow (enumerate_dbs=%s, test_memory=%s, "
            "read_values=%s, slot=%s, rack=%s)",
            self.enumerate_dbs,
            self.test_memory_areas,
            self.read_values,
            self.slot,
            self.rack,
        )
        results = {
            "cpu_info": {},
            "plc_status": {},
            "firmware_info": {},
            "data_blocks": [],
            "memory_areas": {},
            "security_analysis": {},
            "protection_level": None,
        }

        with _suppress_snap7_logging():
            try:
                # Get firmware version (most reliable identifier)
                self.logger.debug("Getting firmware version...")
                results["firmware_info"] = self.get_firmware_version(connection)

                # Get CPU information
                self.logger.debug("Getting CPU info...")
                results["cpu_info"] = self._get_cpu_info(connection)

                # Get PLC status
                self.logger.debug("Getting PLC status...")
                results["plc_status"] = self._get_plc_status(connection)

                # Check protection level
                self.logger.debug("Checking protection level...")
                results["protection_level"] = self._check_protection_level(connection)

                # Detect PUT/GET access for S7-1200/1500
                # Try cpu_info first, then firmware_info for series detection
                series = results.get("cpu_info", {}).get("s7_series", "")
                if not series:
                    series = results.get("firmware_info", {}).get("series", "")
                if series in ("S7-1200", "S7-1500"):
                    self.logger.debug("Detecting PUT/GET access...")
                    results["put_get_access"] = self._detect_put_get_access(connection, series)

                if self.scan_mode in ["discovery", "all"]:
                    # Enumerate data blocks
                    if self.enumerate_dbs:
                        self.logger.debug("Enumerating data blocks...")
                        results["data_blocks"] = self._enumerate_data_blocks(connection)

                    # Test memory area access
                    if self.test_memory_areas:
                        self.logger.debug("Testing memory areas...")
                        results["memory_areas"] = self._test_memory_areas(connection)

                if self.read_values and self.scan_mode in ["detailed", "all"]:
                    # Read sample values from accessible areas
                    self.logger.debug("Reading sample values...")
                    results["sample_values"] = self._read_sample_values(connection, results)

                # Security analysis
                self.logger.debug("Analyzing security...")
                results["security_analysis"] = self._analyze_security(results)

                # Report findings
                self._report_findings(results)

            except Exception as e:
                self.logger.debug("discover failed: %s", e)
                self.logger.fail(f"Error during S7 discovery: {e}")
                results["error"] = str(e)

        self.logger.debug("S7 discovery workflow complete")
        return results


# Create metadata using helper function


# Module-level metadata and run function
metadata, run = create_protocol_module(
    Snap7Scanner, dependencies_check_func=lambda: not _snap7.is_available
)
