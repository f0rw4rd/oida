#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Snap7 SecurityMixin.

Source: src/oida/protocols/snap7/mixins/security.py
"""

import unittest
from unittest.mock import Mock, patch

from oida.protocols.snap7.mixins.security import SecurityMixin


class MockSecurityHost(SecurityMixin):
    """Mock host class providing attributes the SecurityMixin expects."""

    def __init__(self):
        self.logger = Mock()
        self.timeout = 5
        self.host = "192.168.1.100"
        self.port = 102
        self.args = {}
        self.password = ""
        self.read_only = True
        self.read_values = False
        self.max_dbs = 100
        self.interface = "eth0"

    def get_target_info(self):
        return (self.host, self.port)

    def report_credential(self, *a, **kw):
        pass

    def report_host_info(self, *a, **kw):
        pass

    def report_service_info(self, *a, **kw):
        pass

    def report_vulnerability(self, *a, **kw):
        pass

    # DeviceInfoMixin stub (needed by _analyze_security indirectly)
    def _identify_series_from_order_code(self, code):
        return "Unknown"


class TestCheckProtectionLevel(unittest.TestCase):
    """Test SecurityMixin._check_protection_level()."""

    def setUp(self):
        self.host = MockSecurityHost()
        self.conn = Mock()

    def test_all_zero_protection_is_indeterminate(self):
        """All-zero S7Protection struct is INDETERMINATE — python-snap7 returns
        a zeroed struct on CPUs that do not expose the SZL or when the read
        silently fails. Reporting level=1 / 'No protection' would be a false
        positive on modern S7-1200/1500 firmware."""
        protection = Mock()
        protection.sch_schal = 0
        protection.sch_par = 0
        protection.sch_rel = 0
        protection.bart_sch = 0
        protection.anl_sch = 0
        self.conn.get_protection.return_value = protection

        result = self.host._check_protection_level(self.conn)

        self.assertIsNotNone(result)
        self.assertEqual(result["level"], 0, "Must be INDETERMINATE, not 'No protection'")
        self.assertFalse(result["has_protection"])
        self.assertTrue(result.get("indeterminate"))
        self.assertIn("Indeterminate", result["description"])

    def test_no_protection_open_plc(self):
        """sch_schal=1 means level 1 = NO protection (open PLC).

        Regression: the old logic mapped sch_schal=1 (most dangerous, wide
        open) to "Full protection - Password required" - the exact opposite
        of reality. The field value IS the protection level, mirroring
        SZLParser._parse_0x0132 (sch_schal=1 -> level 1).
        """
        protection = Mock()
        protection.sch_schal = 1
        protection.sch_par = 1
        protection.sch_rel = 1
        protection.bart_sch = 0
        protection.anl_sch = 0
        self.conn.get_protection.return_value = protection

        result = self.host._check_protection_level(self.conn)

        self.assertEqual(result["level"], 1, "sch_schal=1 must be level 1 (no protection)")
        self.assertTrue(result["has_protection"])
        self.assertIn("No protection", result["description"])

    def test_write_protection(self):
        """Test protection level 2 - write protected (max field == 2)."""
        protection = Mock()
        protection.sch_schal = 1
        protection.sch_par = 2
        protection.sch_rel = 1
        protection.bart_sch = 0
        protection.anl_sch = 0
        self.conn.get_protection.return_value = protection

        result = self.host._check_protection_level(self.conn)

        self.assertEqual(result["level"], 2)
        self.assertTrue(result["has_protection"])
        self.assertIn("Write protected", result["description"])

    def test_full_protection(self):
        """Test protection level 3 - full protection with password."""
        protection = Mock()
        protection.sch_schal = 3
        protection.sch_par = 2
        protection.sch_rel = 1
        protection.bart_sch = 0
        protection.anl_sch = 0
        self.conn.get_protection.return_value = protection

        result = self.host._check_protection_level(self.conn)

        self.assertEqual(result["level"], 3)
        self.assertTrue(result["has_protection"])
        self.assertIn("Password required", result["description"])

    def test_exception_returns_none(self):
        """Test that exception returns None."""
        self.conn.get_protection.side_effect = Exception("access denied")

        result = self.host._check_protection_level(self.conn)

        self.assertIsNone(result)

    def test_protection_fields_in_result(self):
        """Test that all protection fields are included in result."""
        protection = Mock()
        protection.sch_schal = 1
        protection.sch_par = 2
        protection.sch_rel = 3
        protection.bart_sch = 4
        protection.anl_sch = 5
        self.conn.get_protection.return_value = protection

        result = self.host._check_protection_level(self.conn)

        fields = result["fields"]
        self.assertEqual(fields["sch_schal"], 1)
        self.assertEqual(fields["sch_par"], 2)
        self.assertEqual(fields["sch_rel"], 3)
        self.assertEqual(fields["bart_sch"], 4)
        self.assertEqual(fields["anl_sch"], 5)


class TestClearSession(unittest.TestCase):
    """Test SecurityMixin.clear_session()."""

    def setUp(self):
        self.host = MockSecurityHost()
        self.conn = Mock()

    def test_clear_session_success(self):
        """Test successful session clear."""
        self.host.clear_session(self.conn)

        self.conn.clear_session_password.assert_called_once()

    def test_clear_session_exception_ignored(self):
        """Test exception during clear is silently ignored."""
        self.conn.clear_session_password.side_effect = Exception("not supported")

        # Should not raise
        self.host.clear_session(self.conn)


class TestTestNullPassword(unittest.TestCase):
    """Test SecurityMixin.test_null_password()."""

    def setUp(self):
        self.host = MockSecurityHost()
        self.conn = Mock()

    def test_vulnerable_empty_password_accepted(self):
        """Test null password vulnerability detected."""
        result = self.host.test_null_password(self.conn)

        self.assertTrue(result["success"])
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["password"], "")
        self.host.logger.success.assert_called()

    def test_not_vulnerable_empty_rejected(self):
        """Test PLC rejects empty password."""
        self.conn.set_session_password.side_effect = Exception("refused")

        result = self.host.test_null_password(self.conn)

        self.assertFalse(result["success"])
        self.assertFalse(result["vulnerable"])

    def test_not_vulnerable_verify_fails(self):
        """Test PLC accepts set_session_password but verify fails."""
        self.conn.get_cpu_state.side_effect = Exception("access denied")

        result = self.host.test_null_password(self.conn)

        self.assertFalse(result["success"])
        self.assertFalse(result["vulnerable"])


class TestAnalyzeSecurity(unittest.TestCase):
    """Test SecurityMixin._analyze_security()."""

    def setUp(self):
        self.host = MockSecurityHost()

    def test_protection_level_1_no_protection(self):
        """Test security analysis with no protection (level 1)."""
        results = {"protection_level": {"level": 1}, "data_blocks": [], "memory_areas": {}}

        analysis = self.host._analyze_security(results)

        self.assertIn("concerns", analysis)
        concern_texts = " ".join(analysis["concerns"])
        self.assertIn("No protection", concern_texts)

    def test_level_1_reports_no_protection_finding_level_3_does_not(self):
        """Regression for the MEDIUM 'unreachable level-1 concern' finding.

        _check_protection_level emits level 1 for an unprotected (open) PLC.
        _analyze_security must surface that as the 'No protection' concern AND
        an "Insecure configuration" security_finding. Before the corrected
        max()-based level mapping, _check_protection_level never produced
        level 1, so this branch was dead and the most severe finding (an open
        PLC) never fired. Level 3 (password-protected) must NOT raise it.
        """
        # Level 1 (open PLC) -> concern + security_finding fire.
        results_open = {"protection_level": {"level": 1}, "data_blocks": [], "memory_areas": {}}
        analysis_open = self.host._analyze_security(results_open)
        self.assertIn("No protection", " ".join(analysis_open["concerns"]))
        finding_calls = [c for c in self.host.logger.security_finding.call_args_list]
        self.assertTrue(
            any(
                call.args
                and call.args[0] == "Insecure configuration"
                and call.kwargs.get("detail") == "protection_level=1"
                for call in finding_calls
            ),
            "Level-1 open PLC must raise the 'No protection' Insecure configuration finding",
        )

        # Level 3 (password protected) -> no 'No protection' concern/finding.
        self.host.logger.security_finding.reset_mock()
        results_full = {"protection_level": {"level": 3}, "data_blocks": [], "memory_areas": {}}
        analysis_full = self.host._analyze_security(results_full)
        self.assertNotIn("No protection", " ".join(analysis_full["concerns"]))
        self.assertFalse(
            any(
                call.kwargs.get("detail") == "protection_level=1"
                for call in self.host.logger.security_finding.call_args_list
            ),
            "Level-3 protected PLC must NOT raise the 'No protection' finding",
        )

    def test_protection_level_2_write_protected(self):
        """Test security analysis with write protection (level 2)."""
        results = {"protection_level": {"level": 2}, "data_blocks": [], "memory_areas": {}}

        analysis = self.host._analyze_security(results)

        concern_texts = " ".join(analysis["concerns"])
        self.assertIn("Write protection", concern_texts)

    def test_protection_level_3_full(self):
        """Test security analysis with full protection (level 3)."""
        results = {"protection_level": {"level": 3}, "data_blocks": [], "memory_areas": {}}

        analysis = self.host._analyze_security(results)

        # Level 3 should have no protection-related concerns
        protection_concerns = [c for c in analysis["concerns"] if "protection" in c.lower()]
        self.assertEqual(len(protection_concerns), 0)

    def test_data_blocks_present(self):
        """Test security analysis reports accessible data blocks."""
        results = {
            "protection_level": {"level": 3},
            "data_blocks": [{"number": 1}, {"number": 2}, {"number": 3}],
            "memory_areas": {},
        }

        analysis = self.host._analyze_security(results)

        concern_texts = " ".join(analysis["concerns"])
        self.assertIn("3 data blocks", concern_texts)

    def test_writable_areas(self):
        """Test security analysis reports writable memory areas."""
        results = {
            "protection_level": {"level": 3},
            "data_blocks": [],
            "memory_areas": {
                "M": {"writable": True},
                "Q": {"writable": True},
                "I": {"writable": False},
            },
        }

        analysis = self.host._analyze_security(results)

        concern_texts = " ".join(analysis["concerns"])
        self.assertIn("Writable", concern_texts)

    def test_protection_level_none(self):
        """Test security analysis when protection_level is None (defaults to 3)."""
        results = {"protection_level": None, "data_blocks": [], "memory_areas": {}}

        analysis = self.host._analyze_security(results)

        # Default to most restrictive: no protection-level concerns
        protection_concerns = [c for c in analysis["concerns"] if "No protection" in c]
        self.assertEqual(len(protection_concerns), 0)

    def test_protection_level_int(self):
        """Test security analysis when protection_level is an int (not dict)."""
        results = {"protection_level": 1, "data_blocks": [], "memory_areas": {}}

        analysis = self.host._analyze_security(results)

        concern_texts = " ".join(analysis["concerns"])
        self.assertIn("No protection", concern_texts)

    def test_password_set_marks_authentication(self):
        """Test that having a password marks authentication as present."""
        self.host.password = "secret"
        results = {"protection_level": {"level": 3}, "data_blocks": [], "memory_areas": {}}

        analysis = self.host._analyze_security(results)

        # Should not crash; authentication key used internally
        self.assertIsNotNone(analysis)


class TestTestWriteAccess(unittest.TestCase):
    """Test SecurityMixin._test_write_access()."""

    def setUp(self):
        self.host = MockSecurityHost()
        self.conn = Mock()

    def test_markers_writable(self):
        """Test markers area is writable."""
        self.conn.read_area.return_value = bytes([0x42])
        self.conn.write_area.return_value = None

        result = self.host._test_write_access(self.conn)

        self.assertIn("markers", result["writable_areas"])
        self.assertFalse(result["read_only"])

    def test_outputs_writable(self):
        """Test outputs area is writable (markers write fails)."""

        # Markers: read ok, write fails
        def read_side_effect(area, *args):
            return bytes([0x00])

        def write_side_effect(area, *args):
            from oida.protocols.snap7.constants import S7MemoryArea

            if area == S7MemoryArea.MK:
                raise Exception("access denied")

        self.conn.read_area.side_effect = read_side_effect
        self.conn.write_area.side_effect = write_side_effect

        result = self.host._test_write_access(self.conn)

        self.assertIn("outputs", result["writable_areas"])
        self.assertNotIn("markers", result["writable_areas"])
        self.assertFalse(result["read_only"])

    def test_both_fail_read_only(self):
        """Test both areas fail write -> read_only=True."""
        self.conn.read_area.side_effect = Exception("access denied")

        result = self.host._test_write_access(self.conn)

        self.assertEqual(result["writable_areas"], [])
        self.assertTrue(result["read_only"])

    def test_both_writable(self):
        """Test both markers and outputs are writable."""
        self.conn.read_area.return_value = bytes([0x00])
        self.conn.write_area.return_value = None

        result = self.host._test_write_access(self.conn)

        self.assertIn("markers", result["writable_areas"])
        self.assertIn("outputs", result["writable_areas"])
        self.assertFalse(result["read_only"])

    def test_read_succeeds_write_fails(self):
        """Test read succeeds but write fails for both areas."""
        self.conn.read_area.return_value = bytes([0x00])
        self.conn.write_area.side_effect = Exception("write protected")

        result = self.host._test_write_access(self.conn)

        self.assertEqual(result["writable_areas"], [])
        self.assertTrue(result["read_only"])


class TestDetectPutGetAccess(unittest.TestCase):
    """Test SecurityMixin._detect_put_get_access()."""

    def setUp(self):
        self.host = MockSecurityHost()
        self.conn = Mock()

    @patch("oida.protocols.snap7.scanner._suppress_snap7_logging")
    @patch("oida.protocols.snap7.scanner._get_snap7_client")
    def test_not_applicable_series(self, mock_client, mock_suppress):
        """Test PUT/GET not applicable for non-1200/1500 series."""
        result = self.host._detect_put_get_access(self.conn, series="S7-300")

        self.assertIsNone(result["enabled"])
        self.assertIn("not applicable", result["details"])

    def test_no_connection(self):
        """Test PUT/GET with no active connection."""
        self.conn.get_connected.return_value = False

        result = self.host._detect_put_get_access(self.conn, series="S7-1500")

        self.assertIsNone(result["enabled"])
        self.assertIn("No active connection", result["details"])

    def test_null_connection(self):
        """Test PUT/GET with None connection."""
        result = self.host._detect_put_get_access(None, series="S7-1500")

        self.assertIsNone(result["enabled"])


if __name__ == "__main__":
    unittest.main()
