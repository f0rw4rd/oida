"""
Modbus Scanner Discovery Mixin

Handles unit ID discovery and function code enumeration:
- Unit ID scanning with gateway/bridge detection
- Function code testing and enumeration
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class ScannerDiscoveryMixin(_ScannerBase):
    """Mixin providing unit discovery and function code testing for ModbusScanner."""

    def _discover_units(self, client: Any) -> Dict[str, Any]:
        """Discover active Modbus unit IDs

        Detects gateway/bridge mode where a single device responds to all unit IDs
        with identical data (common in Modbus TCP gateways and PLCs).

        Args:
            client: Modbus client connection

        Returns:
            dict: Map of active unit IDs to their info, or gateway detection result
        """
        from ....utils import ProtocolParser, ProgressTracker

        units = {}
        unit_range = ProtocolParser.parse_address_range(self.unit_range)

        # Phase 1: Quick gateway detection with sample unit IDs
        # Test spread across range to detect if device responds to all uniformly
        sample_ids = [1, 50, 100, 150, 200, 247]
        sample_ids = [u for u in sample_ids if u in unit_range]

        if len(sample_ids) < 3:
            # Range too small for gateway detection, use first 3 from range
            sample_ids = list(unit_range)[:3]

        self.logger.debug(f"Gateway detection: testing {len(sample_ids)} sample unit IDs...")

        sample_responses = {}
        sample_errors = {}
        for unit_id in sample_ids:
            try:
                result = client.read_holding_registers(0, count=1, device_id=unit_id)
                if not result.isError():
                    # Store register values for comparison
                    sample_responses[unit_id] = tuple(result.registers)
                else:
                    # Store error type for comparison
                    exc_code = getattr(result, "exception_code", None)
                    sample_errors[unit_id] = exc_code
            except Exception as e:
                self.logger.debug(f"Sample unit {unit_id} error: {e}")

        # Gateway detection logic
        responding_count = len(sample_responses) + len(sample_errors)

        if responding_count >= 3:
            # Check if all samples respond identically (gateway mode)
            all_responses_identical = False
            all_errors_identical = False

            if len(sample_responses) >= 3:
                response_values = list(sample_responses.values())
                all_responses_identical = all(v == response_values[0] for v in response_values)

            if len(sample_errors) >= 3:
                error_values = list(sample_errors.values())
                all_errors_identical = all(v == error_values[0] for v in error_values)

            # Gateway detected: device responds identically to all sampled unit IDs
            # (all_responses_identical is only set True when >= 3 samples were collected)
            if all_responses_identical:
                self.logger.debug("Gateway/bridge mode detected: device responds to all unit IDs")
                first_unit = min(sample_responses.keys())
                return {
                    "gateway_mode": True,
                    "actual_unit": first_unit,
                    "responding_units": list(sample_responses.keys()),
                    "note": "Single device responds to all unit IDs (gateway/bridge behavior)",
                    first_unit: {
                        "active": True,
                        "last_seen": datetime.now().isoformat(),
                    },
                }

            if all_errors_identical and len(sample_errors) == len(sample_ids):
                self.logger.debug(
                    "Gateway/bridge mode detected: device returns same error for all unit IDs"
                )
                return {
                    "gateway_mode": True,
                    "error_code": list(sample_errors.values())[0],
                    "note": "Device returns identical error for all unit IDs",
                }

        # Phase 2: Full scan - either no gateway detected or responses vary
        self.logger.debug(f"Scanning unit IDs ({self.unit_range})...")
        progress = ProgressTracker(len(unit_range), logger=self.logger, show=True)

        for unit_id in unit_range:
            progress.update()
            try:
                result = client.read_holding_registers(0, count=1, device_id=unit_id)
                if not result.isError():
                    units[unit_id] = {
                        "active": True,
                        "last_seen": datetime.now().isoformat(),
                    }
            except Exception as e:
                self.logger.debug(f"Unit {unit_id} not responding: {e}")

        # Post-scan gateway detection (fallback)
        if len(units) > 200:
            units["high_response_count"] = True
            units["high_response_warning"] = (
                f"{len(units)} units responded - likely gateway/bridge device"
            )

        return units

    def _test_function_codes(self, client: Any) -> Dict[str, Any]:
        """Test supported Modbus function codes"""
        from ..scanner import GenericPDU, execute_pdu
        from ..constants import FUNCTION_CODES
        from ....utils import ProtocolParser, ProgressTracker

        supported = {}

        # Check if verbose FC output requested (--scan-fc, --fc, or --fc-all)
        verbose_fc = self.scan_fc or self.fc_all or getattr(self, "function_code", None) is not None

        # Use full range (1-127) if --fc-all, otherwise use --fc-range
        if self.fc_all:
            fc_range_str = "1-127"
            if verbose_fc:
                self.logger.display("Scanning all function codes (1-127)...")
        else:
            fc_range_str = self.fc_range
            if verbose_fc:
                self.logger.display(f"Scanning function codes ({fc_range_str})...")

        function_range = ProtocolParser.parse_address_range(fc_range_str)

        progress = ProgressTracker(len(function_range), logger=self.logger, show=verbose_fc)

        for func_code in function_range:
            progress.update()
            try:
                # Create generic PDU with function code
                pdu = GenericPDU(function_code=func_code)
                result = execute_pdu(client, pdu, self.unit_id)

                if not result.isError():
                    supported[func_code] = {
                        "name": FUNCTION_CODES.get(func_code, f"Unknown ({func_code})"),
                        "supported": True,
                    }
                else:
                    exception_code = getattr(result, "exception_code", None)
                    if exception_code == 2:
                        supported[func_code] = {
                            "name": FUNCTION_CODES.get(func_code, f"Unknown ({func_code})"),
                            "supported": True,
                            "note": "Supported but needs valid address",
                            "exception_code": exception_code,
                        }
                    elif exception_code == 3:
                        supported[func_code] = {
                            "name": FUNCTION_CODES.get(func_code, f"Unknown ({func_code})"),
                            "supported": True,
                            "note": "Supported but needs valid data format",
                            "exception_code": exception_code,
                        }
                    elif exception_code == 1:
                        self.logger.debug(f"Function code {func_code} not supported (exception 1)")
                    elif exception_code is not None:
                        supported[func_code] = {
                            "name": FUNCTION_CODES.get(func_code, f"Unknown ({func_code})"),
                            "supported": True,
                            "note": f"Exception {exception_code}",
                            "exception_code": exception_code,
                        }
                        self.logger.debug(
                            f"Function code {func_code} returned exception {exception_code}"
                        )
            except Exception as e:
                err_str = str(e).lower()
                if "unable to decode" in err_str or "unknown response" in err_str:
                    supported[func_code] = {
                        "name": FUNCTION_CODES.get(func_code, f"Vendor Specific ({func_code})"),
                        "supported": True,
                        "note": "Vendor-specific response format",
                    }
                else:
                    self.logger.debug(f"Error testing function code {func_code}: {e}")

        # Print results after scan completes
        if verbose_fc:
            if supported:
                self.logger.display(f"[Supported Function Codes] ({len(supported)} found)")
                for fc in sorted(supported.keys()):
                    info = supported[fc]
                    fc_name = info.get("name", f"FC {fc}")
                    note = info.get("note", "")
                    if note:
                        self.logger.display(f"  FC {fc:3d}: {fc_name} ({note})")
                    else:
                        self.logger.display(f"  FC {fc:3d}: {fc_name}")
            else:
                self.logger.display("Function codes: None supported")

        return {"supported": supported}
