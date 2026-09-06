"""
Modbus Diagnostics Mixin

Handles diagnostic operations (FC 8):
- Echo test
- Read diagnostic register
- Read/clear counters
- Restart communications
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class DiagnosticsMixin(_ScannerBase):
    """Mixin providing Modbus diagnostics operations (FC 8)."""

    def _handle_diagnostics(self, tests: str):
        """Handle diagnostics (FC 8)"""
        self.logger.display(f"Running diagnostics: {tests}...")
        diag_data = getattr(self.args, "diag_data", None)
        diag_results = self.scanner._run_diagnostics(self.conn, tests, diag_data=diag_data)
        self.results["data"]["diagnostics"] = diag_results

        self.logger.display("[Diagnostics (FC 8)]")
        self.logger.display(f"  Supported: {diag_results.get('supported', False)}")

        if diag_results.get("echo_test"):
            echo = diag_results["echo_test"]
            status = "PASS" if echo.get("match") else "FAIL"
            self.logger.display(f"  Echo Test: {status} (RTT: {echo.get('rtt_ms', 0)}ms)")

        if diag_results.get("diagnostic_register") is not None:
            self.logger.display(
                f"  Diagnostic Register: 0x{diag_results['diagnostic_register']:04X}"
            )

        if diag_results.get("counters"):
            self.logger.display("  Counters:")
            for info in diag_results["counters"].values():
                self.logger.display(f"    {info['name']}: {info['value']}")
