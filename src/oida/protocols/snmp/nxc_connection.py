"""
SNMP NXC-style Connection

Provides the NXC-style callable SNMP scanner class that wraps
SNMPScanner to provide automatic execution on instantiation.

Delegates scanning logic to SNMPScanner.run_scan() while following
the standard NXC proto_flow → create_conn_obj → enum_host_info →
print_host_info contract.
"""

from ...connection import NetworkConnection
from ...utils.lazy_import import lazy_import

_pysnmp = lazy_import("pysnmp", "SNMP")


class snmp(NetworkConnection):
    """
    NXC-style SNMP scanner (callable)

    Wraps SNMPScanner to provide NXC-style callable behavior
    with automatic execution on instantiation.

    Usage:
        args = argparse.Namespace(...)
        scanner = snmp(args, None, '192.168.1.100')
        # Scan automatically executes via proto_flow()
    """

    def __init__(self, args, db, host):
        self.protocol_name = "snmp"
        self.default_port = 161
        super().__init__(args, db, host)

    def proto_flow(self):
        """Main SNMP scanning workflow — standard NXC method sequence."""

        if not self.create_conn_obj():
            return

        self.enum_host_info()
        self.print_host_info()

    def create_conn_obj(self):
        """Initialize SNMPScanner and verify dependencies."""
        from .scanner import SNMPScanner

        args_dict = self._convert_args_to_dict()
        self.scanner = SNMPScanner(args_dict)
        # Share logger so scanner output uses NXC formatting
        self.scanner.logger = self.logger

        if not self.scanner.check_dependencies():
            self.logger.fail("Missing SNMP dependencies (pysnmp)")
            self.results["success"] = False
            return False

        return True

    def enum_host_info(self):
        """Run the full SNMP scan workflow via SNMPScanner."""
        scan_results = self.scanner.run_scan()
        self.results["data"].update(scan_results)

        error = scan_results.get("error")
        if error:
            self.results["success"] = False
            if error not in ("missing_dependencies",):
                self.logger.fail(f"SNMP scan failed: {error}")
        else:
            self.results["success"] = True

    def print_host_info(self):
        """Display scan summary — banner already shown by scanner inline."""
        # ICS logger exposes `findings` (property), not get_findings(); the old
        # hasattr guard was always False so this summary never printed.
        findings = getattr(self.logger, "findings", [])
        if findings:
            self.logger.display(f"    {len(findings)} security finding(s) collected")

    @staticmethod
    def check_dependencies() -> bool:
        """Check if SNMP dependencies are available."""
        return _pysnmp.is_available
