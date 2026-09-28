"""Discovery failure reporting must not claim success (GH issue #60).

Old bugs:
- Raw-socket denial inside discover() returned a results dict with keys but
  an empty scan_mode; get_results() treated it as truthy and exported
  success: true with exit code 0. A discovery that ran nothing was
  indistinguishable from one that found nothing.
- An unknown interface name raised a bare ValueError from
  DiscoveryScanner.__init__ (via _get_local_mac) that escaped into the
  generic crash-reporter path - a typo is not a bug in OIDA.
- "[+] Listening on interface X" printed before the raw-socket capability
  check, so the banner contradicted the failure that followed.
"""

import unittest
from unittest import mock

from oida.protocols.discovery.scanner import DiscoveryScanner, discovery
from oida.utils.exceptions import ConfigurationError


def _make_scanner():
    """Build a DiscoveryScanner without running its full __init__."""
    s = DiscoveryScanner.__new__(DiscoveryScanner)
    return s


class TestDiscoverEarlyReturnErrors(unittest.TestCase):
    """discover() early-return paths must record an error in results."""

    def _base_args(self):
        return {
            "interface": "lo",
            "timeout": 1,
        }

    def test_raw_socket_denial_records_error(self):
        s = _make_scanner()
        s.logger = mock.Mock()
        with (
            mock.patch(
                "oida.protocols.discovery.scanner.check_raw_socket_capability",
                return_value=(False, "permission_error"),
            ),
            mock.patch(
                "oida.utils.permissions.raw_socket_help_lines",
                return_value=["Run with sudo:  sudo oida ..."],
                create=True,
            ),
        ):
            results = s.discover("lo")
        self.assertIn("error", results)
        self.assertIn("raw socket", results["error"])
        self.assertEqual(results["scan_mode"], [])

    def test_no_interface_records_error(self):
        s = _make_scanner()
        s.logger = mock.Mock()
        results = s.discover(None)
        self.assertIn("error", results)
        self.assertEqual(results["scan_mode"], [])


class TestGetResultsSuccessSemantics(unittest.TestCase):
    """get_results() must report success only when scan tasks ran."""

    def _make_connection(self):
        d = discovery.__new__(discovery)
        d.interface = "lo"
        d._scan_results = None
        d._scan_error = None
        return d

    def test_results_without_scan_mode_is_failure(self):
        d = self._make_connection()
        d._scan_results = {
            "devices": [],
            "protocols_used": [],
            "scan_mode": [],
            "statistics": {},
            "security_analysis": {},
            "error": "raw socket access denied (need root or CAP_NET_RAW)",
        }
        r = d.get_results()
        self.assertFalse(r["success"])
        self.assertIn("raw socket", r["error"])

    def test_results_with_scan_mode_is_success(self):
        d = self._make_connection()
        d._scan_results = {
            "devices": [],
            "protocols_used": [],
            "scan_mode": ["passive"],
            "statistics": {},
            "security_analysis": {},
        }
        r = d.get_results()
        self.assertTrue(r["success"])
        self.assertIsNone(r["error"])

    def test_no_results_carries_scan_error(self):
        d = self._make_connection()
        d._scan_error = "raw socket access denied (need root or CAP_NET_RAW)"
        r = d.get_results()
        self.assertFalse(r["success"])
        self.assertIn("raw socket", r["error"])


class TestInterfaceValidation(unittest.TestCase):
    """Unknown interface must raise ConfigurationError (operational, not a
    crash-reportable bug) with the available-interfaces hint."""

    def test_unknown_interface_raises_configuration_error(self):
        with mock.patch(
            "oida.protocols.discovery.scanner._netifaces.interfaces",
            return_value=["lo", "eth0"],
        ):
            with self.assertRaises(ConfigurationError) as ctx:
                DiscoveryScanner({"interface": "nosuchif", "timeout": 1})
        self.assertIn("nosuchif", str(ctx.exception))
        self.assertIn("eth0", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
