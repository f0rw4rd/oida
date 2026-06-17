#!/usr/bin/env python3
"""
Unit tests for EtherNet/IP CipSecurityMixin.

Tests cover:
- _report_security_status: not supported, not configured, enabled, EIP caps, PSK, certs
- _dump_cip_security_object: state parsing, profiles bitmask, active profile, not accessible
- _dump_eip_security_object: state parsing, capability flags, PSK count, active PSK, not accessible
- _dump_certificate_management: cert state, max/installed, device cert CN, cert download, not accessible
- _dump_password_authenticator: enabled/disabled, password configured, min/max, failed attempts, lockout
- _dump_security_settings: orchestrates all 4 dump methods, handles missing conn
"""

import struct
import unittest
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.core

from oida.protocols.ethernetip.mixins.cip_security import CipSecurityMixin


class MockSecurityHost(CipSecurityMixin):
    """Test host for CipSecurityMixin."""

    def __init__(self):
        self.logger = MagicMock()
        self.debug = False
        self._attr_responses = {}

    def _read_cip_attribute(self, conn, class_id, instance, attr_id, **kwargs):
        key = (class_id, instance, attr_id)
        return self._attr_responses.get(key)

    def set_attr(self, class_id, instance, attr_id, data):
        self._attr_responses[(class_id, instance, attr_id)] = data

    def get_target_info(self):
        return ("192.168.1.100", 44818)


# =============================================================================
# _report_security_status tests
# =============================================================================


class TestReportSecurityStatus(unittest.TestCase):
    """Test _report_security_status method."""

    def setUp(self):
        self.host = MockSecurityHost()

    def test_not_supported(self):
        """CIP Security not accessible => NOT SUPPORTED."""
        security = {"cip_security": None, "eip_security": None, "certificates": None}
        self.host._report_security_status(security)
        self.host.logger.security_finding.assert_called_once()
        call_args = self.host.logger.security_finding.call_args
        # Detail is passed via the detail= kwarg (not the positional category slot).
        self.assertIn("NOT SUPPORTED", call_args.kwargs["detail"])

    def test_not_supported_accessible_false(self):
        """CIP Security with accessible=False => NOT SUPPORTED."""
        security = {
            "cip_security": {"accessible": False},
            "eip_security": None,
            "certificates": None,
        }
        self.host._report_security_status(security)
        self.host.logger.security_finding.assert_called_once()

    def test_not_configured_state_zero(self):
        """State raw = 0 => NOT CONFIGURED (Factory Default)."""
        security = {
            "cip_security": {
                "accessible": True,
                "state_raw": 0,
                "state": "Factory Default",
            },
            "eip_security": None,
            "certificates": None,
        }
        self.host._report_security_status(security)
        self.host.logger.security_finding.assert_called_once()
        call_args = self.host.logger.security_finding.call_args
        # Detail is passed via the detail= kwarg (not the positional category slot).
        self.assertIn("NOT CONFIGURED", call_args.kwargs["detail"])

    def test_enabled_state_configured(self):
        """State raw > 0 => ENABLED."""
        security = {
            "cip_security": {
                "accessible": True,
                "state_raw": 2,
                "state": "Configured",
                "profiles": ["EtherNet/IP Confidentiality"],
                "active_profile": 1,
            },
            "eip_security": None,
            "certificates": None,
        }
        self.host._report_security_status(security)
        self.host.logger.success.assert_called_once()
        call_args = self.host.logger.success.call_args
        self.assertIn("ENABLED", call_args[0][0])

    def test_enabled_with_profiles_displayed(self):
        """Profiles list displayed when present."""
        security = {
            "cip_security": {
                "accessible": True,
                "state_raw": 2,
                "state": "Configured",
                "profiles": ["EtherNet/IP Confidentiality", "CIP Authorization"],
                "active_profile": 1,
            },
            "eip_security": None,
            "certificates": None,
        }
        self.host._report_security_status(security)
        # Check that logger.display was called with profiles info
        display_calls = [str(c) for c in self.host.logger.display.call_args_list]
        found_profiles = any("Profiles" in c for c in display_calls)
        self.assertTrue(found_profiles)

    def test_eip_capabilities_displayed(self):
        """EIP Security capabilities displayed."""
        security = {
            "cip_security": {"accessible": True, "state_raw": 2, "state": "Configured"},
            "eip_security": {
                "accessible": True,
                "capabilities": ["TLS 1.2", "TLS 1.3"],
                "psk_count": 0,
            },
            "certificates": None,
        }
        self.host._report_security_status(security)
        display_calls = [str(c) for c in self.host.logger.display.call_args_list]
        found_caps = any("TLS" in c for c in display_calls)
        self.assertTrue(found_caps)

    def test_psk_info_active(self):
        """PSK information with active slot displayed."""
        security = {
            "cip_security": {"accessible": True, "state_raw": 2, "state": "Configured"},
            "eip_security": {
                "accessible": True,
                "capabilities": [],
                "psk_count": 3,
                "active_psk_slot": 2,
            },
            "certificates": None,
        }
        self.host._report_security_status(security)
        display_calls = [str(c) for c in self.host.logger.display.call_args_list]
        found_psk = any("PSK" in c for c in display_calls)
        self.assertTrue(found_psk)

    def test_psk_info_none_active(self):
        """PSK configured but none active."""
        security = {
            "cip_security": {"accessible": True, "state_raw": 2, "state": "Configured"},
            "eip_security": {
                "accessible": True,
                "capabilities": [],
                "psk_count": 2,
                "active_psk_slot": 0,
            },
            "certificates": None,
        }
        self.host._report_security_status(security)
        display_calls = [str(c) for c in self.host.logger.display.call_args_list]
        found_psk = any("none active" in c for c in display_calls)
        self.assertTrue(found_psk)

    def test_certificates_displayed(self):
        """Certificate count displayed."""
        security = {
            "cip_security": {"accessible": True, "state_raw": 2, "state": "Configured"},
            "eip_security": None,
            "certificates": {
                "accessible": True,
                "installed_certificates": 2,
                "max_certificates": 10,
            },
        }
        self.host._report_security_status(security)
        display_calls = [str(c) for c in self.host.logger.display.call_args_list]
        found_certs = any("2/10" in c for c in display_calls)
        self.assertTrue(found_certs)

    def test_no_certificates(self):
        """Certificate count 0 => not displayed."""
        security = {
            "cip_security": {"accessible": True, "state_raw": 2, "state": "Configured"},
            "eip_security": None,
            "certificates": {
                "accessible": True,
                "installed_certificates": 0,
                "max_certificates": 10,
            },
        }
        self.host._report_security_status(security)
        display_calls = [str(c) for c in self.host.logger.display.call_args_list]
        found_certs = any("Certificates" in c for c in display_calls)
        self.assertFalse(found_certs)


# =============================================================================
# _dump_cip_security_object tests
# =============================================================================


class TestDumpCipSecurityObject(unittest.TestCase):
    """Test _dump_cip_security_object method."""

    def setUp(self):
        self.host = MockSecurityHost()
        self.conn = MagicMock()

    def test_not_accessible(self):
        """State attribute returns None => returns None."""
        result = self.host._dump_cip_security_object(self.conn)
        self.assertIsNone(result)

    def test_factory_default_state(self):
        """State = 0 (Factory Default)."""
        self.host.set_attr(0x5D, 1, 1, b"\x00")
        result = self.host._dump_cip_security_object(self.conn)
        self.assertIsNotNone(result)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["state"], "Factory Default")
        self.assertEqual(result["state_raw"], 0)

    def test_configuring_state(self):
        """State = 1 (Configuring)."""
        self.host.set_attr(0x5D, 1, 1, b"\x01")
        result = self.host._dump_cip_security_object(self.conn)
        self.assertEqual(result["state"], "Configuring")
        self.assertEqual(result["state_raw"], 1)

    def test_configured_state(self):
        """State = 2 (Configured)."""
        self.host.set_attr(0x5D, 1, 1, b"\x02")
        result = self.host._dump_cip_security_object(self.conn)
        self.assertEqual(result["state"], "Configured")

    def test_incomplete_config_state(self):
        """State = 3 (Incomplete Configuration)."""
        self.host.set_attr(0x5D, 1, 1, b"\x03")
        result = self.host._dump_cip_security_object(self.conn)
        self.assertEqual(result["state"], "Incomplete Configuration")

    def test_unknown_state(self):
        """Unknown state value."""
        self.host.set_attr(0x5D, 1, 1, b"\x09")
        result = self.host._dump_cip_security_object(self.conn)
        self.assertIn("9", result["state"])

    def test_profiles_bitmask_all(self):
        """Security profiles with all bits set."""
        self.host.set_attr(0x5D, 1, 1, b"\x02")
        self.host.set_attr(0x5D, 1, 2, struct.pack("<H", 0x0F))
        result = self.host._dump_cip_security_object(self.conn)
        self.assertEqual(len(result["profiles"]), 4)
        self.assertIn("EtherNet/IP Confidentiality", result["profiles"])
        self.assertIn("CIP Authorization", result["profiles"])
        self.assertIn("CIP User Authentication", result["profiles"])
        self.assertIn("Resource-Constrained", result["profiles"])

    def test_profiles_bitmask_partial(self):
        """Only some profile bits set."""
        self.host.set_attr(0x5D, 1, 1, b"\x02")
        self.host.set_attr(0x5D, 1, 2, struct.pack("<H", 0x05))
        result = self.host._dump_cip_security_object(self.conn)
        self.assertEqual(len(result["profiles"]), 2)
        self.assertIn("EtherNet/IP Confidentiality", result["profiles"])
        self.assertIn("CIP User Authentication", result["profiles"])

    def test_profiles_bitmask_none(self):
        """No profile bits set."""
        self.host.set_attr(0x5D, 1, 1, b"\x02")
        self.host.set_attr(0x5D, 1, 2, struct.pack("<H", 0x00))
        result = self.host._dump_cip_security_object(self.conn)
        self.assertEqual(result["profiles"], [])

    def test_active_profile(self):
        """Active security profile attribute."""
        self.host.set_attr(0x5D, 1, 1, b"\x02")
        self.host.set_attr(0x5D, 1, 3, b"\x01")
        result = self.host._dump_cip_security_object(self.conn)
        self.assertEqual(result["active_profile"], 1)

    def test_no_profiles_or_active(self):
        """Only state available, no profiles or active."""
        self.host.set_attr(0x5D, 1, 1, b"\x00")
        result = self.host._dump_cip_security_object(self.conn)
        self.assertNotIn("profiles", result)
        self.assertNotIn("active_profile", result)


# =============================================================================
# _dump_eip_security_object tests
# =============================================================================


class TestDumpEipSecurityObject(unittest.TestCase):
    """Test _dump_eip_security_object method."""

    def setUp(self):
        self.host = MockSecurityHost()
        self.conn = MagicMock()

    def test_not_accessible(self):
        """State attribute returns None => returns None."""
        result = self.host._dump_eip_security_object(self.conn)
        self.assertIsNone(result)

    def test_factory_default_state(self):
        """State = 0 (Factory Default)."""
        self.host.set_attr(0x5E, 1, 1, b"\x00")
        result = self.host._dump_eip_security_object(self.conn)
        self.assertIsNotNone(result)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["state"], "Factory Default")

    def test_configured_state(self):
        """State = 1 (Configured)."""
        self.host.set_attr(0x5E, 1, 1, b"\x01")
        result = self.host._dump_eip_security_object(self.conn)
        self.assertEqual(result["state"], "Configured")

    def test_operational_state(self):
        """State = 2 (Operational)."""
        self.host.set_attr(0x5E, 1, 1, b"\x02")
        result = self.host._dump_eip_security_object(self.conn)
        self.assertEqual(result["state"], "Operational")

    def test_capability_flags_all(self):
        """All capability flags set."""
        self.host.set_attr(0x5E, 1, 1, b"\x01")
        self.host.set_attr(0x5E, 1, 2, b"\x1f")  # all 5 bits
        result = self.host._dump_eip_security_object(self.conn)
        self.assertEqual(len(result["capabilities"]), 5)
        self.assertIn("TLS 1.2", result["capabilities"])
        self.assertIn("TLS 1.3", result["capabilities"])
        self.assertIn("DTLS 1.2", result["capabilities"])
        self.assertIn("Pre-Shared Keys", result["capabilities"])
        self.assertIn("Certificates", result["capabilities"])

    def test_capability_flags_tls_only(self):
        """Only TLS 1.2 and 1.3."""
        self.host.set_attr(0x5E, 1, 1, b"\x01")
        self.host.set_attr(0x5E, 1, 2, b"\x03")
        result = self.host._dump_eip_security_object(self.conn)
        self.assertEqual(len(result["capabilities"]), 2)
        self.assertIn("TLS 1.2", result["capabilities"])
        self.assertIn("TLS 1.3", result["capabilities"])

    def test_capability_flags_none(self):
        """No capabilities."""
        self.host.set_attr(0x5E, 1, 1, b"\x01")
        self.host.set_attr(0x5E, 1, 2, b"\x00")
        result = self.host._dump_eip_security_object(self.conn)
        self.assertEqual(result["capabilities"], [])

    def test_psk_count(self):
        """Pre-Shared Key count."""
        self.host.set_attr(0x5E, 1, 1, b"\x01")
        self.host.set_attr(0x5E, 1, 4, b"\x03")
        result = self.host._dump_eip_security_object(self.conn)
        self.assertEqual(result["psk_count"], 3)

    def test_active_psk_slot(self):
        """Active PSK slot."""
        self.host.set_attr(0x5E, 1, 1, b"\x01")
        self.host.set_attr(0x5E, 1, 5, b"\x02")
        result = self.host._dump_eip_security_object(self.conn)
        self.assertEqual(result["active_psk_slot"], 2)

    def test_no_psk_attributes(self):
        """Only state available."""
        self.host.set_attr(0x5E, 1, 1, b"\x01")
        result = self.host._dump_eip_security_object(self.conn)
        self.assertNotIn("psk_count", result)
        self.assertNotIn("active_psk_slot", result)


# =============================================================================
# _dump_certificate_management tests
# =============================================================================


class TestDumpCertificateManagement(unittest.TestCase):
    """Test _dump_certificate_management method."""

    def setUp(self):
        self.host = MockSecurityHost()
        self.conn = MagicMock()

    def test_not_accessible(self):
        """State returns None => returns None."""
        result = self.host._dump_certificate_management(self.conn)
        self.assertIsNone(result)

    def test_certificates_present(self):
        """State > 0 => 'Certificates Present'."""
        self.host.set_attr(0x5F, 1, 1, b"\x01")
        result = self.host._dump_certificate_management(self.conn)
        self.assertIsNotNone(result)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["state"], "Certificates Present")

    def test_no_certificates(self):
        """State = 0 => 'No Certificates'."""
        self.host.set_attr(0x5F, 1, 1, b"\x00")
        result = self.host._dump_certificate_management(self.conn)
        self.assertEqual(result["state"], "No Certificates")

    def test_max_certificates(self):
        """Max certificates attribute."""
        self.host.set_attr(0x5F, 1, 1, b"\x01")
        self.host.set_attr(0x5F, 1, 2, b"\x0a")
        result = self.host._dump_certificate_management(self.conn)
        self.assertEqual(result["max_certificates"], 10)

    def test_installed_certificates(self):
        """Installed certificates count."""
        self.host.set_attr(0x5F, 1, 1, b"\x01")
        self.host.set_attr(0x5F, 1, 3, b"\x02")
        result = self.host._dump_certificate_management(self.conn)
        self.assertEqual(result["installed_certificates"], 2)

    def test_device_cert_cn(self):
        """Device certificate CN parsed from SHORT_STRING."""
        self.host.set_attr(0x5F, 1, 1, b"\x01")
        cn = "plc-01.example.com"
        cn_data = struct.pack("<H", len(cn)) + cn.encode("ascii")
        self.host.set_attr(0x5F, 1, 6, cn_data)
        result = self.host._dump_certificate_management(self.conn)
        self.assertEqual(result["device_cert_cn"], "plc-01.example.com")

    def test_certificate_instances_downloaded(self):
        """Certificate instances are downloaded based on installed count."""
        self.host.set_attr(0x5F, 1, 1, b"\x01")
        self.host.set_attr(0x5F, 1, 3, b"\x01")  # 1 installed

        # Set up instance 1 certificate data
        self.host.set_attr(0x5F, 1, 1, b"\x01")  # state (instance level)
        self.host.set_attr(0x5F, 1, 2, b"\x00")  # device type

        # Mock _download_certificate_instance
        self.host._download_certificate_instance = MagicMock(
            return_value={"instance": 1, "subject": "CN=Test", "raw_size": 512}
        )

        result = self.host._dump_certificate_management(self.conn)
        self.assertEqual(len(result["certificates"]), 1)
        self.host._download_certificate_instance.assert_called_once_with(self.conn, 1)

    def test_no_installed_certs_no_download(self):
        """Zero installed certificates => no download attempts."""
        self.host.set_attr(0x5F, 1, 1, b"\x01")
        self.host.set_attr(0x5F, 1, 3, b"\x00")  # 0 installed

        self.host._download_certificate_instance = MagicMock()
        result = self.host._dump_certificate_management(self.conn)
        self.assertEqual(len(result["certificates"]), 0)
        self.host._download_certificate_instance.assert_not_called()

    def test_cn_too_short(self):
        """CN data < 2 bytes not parsed."""
        self.host.set_attr(0x5F, 1, 1, b"\x01")
        self.host.set_attr(0x5F, 1, 6, b"\x01")  # only 1 byte
        result = self.host._dump_certificate_management(self.conn)
        self.assertNotIn("device_cert_cn", result)


# =============================================================================
# _dump_password_authenticator tests
# =============================================================================


class TestDumpPasswordAuthenticator(unittest.TestCase):
    """Test _dump_password_authenticator method."""

    def setUp(self):
        self.host = MockSecurityHost()
        self.conn = MagicMock()

    def test_not_accessible(self):
        """State returns None => returns None."""
        result = self.host._dump_password_authenticator(self.conn)
        self.assertIsNone(result)

    def test_enabled(self):
        """Password auth enabled."""
        self.host.set_attr(0x61, 1, 1, b"\x01")
        result = self.host._dump_password_authenticator(self.conn)
        self.assertIsNotNone(result)
        self.assertTrue(result["accessible"])
        self.assertTrue(result["enabled"])

    def test_disabled(self):
        """Password auth disabled."""
        self.host.set_attr(0x61, 1, 1, b"\x00")
        result = self.host._dump_password_authenticator(self.conn)
        self.assertFalse(result["enabled"])

    def test_password_configured(self):
        """Password is configured."""
        self.host.set_attr(0x61, 1, 1, b"\x01")
        self.host.set_attr(0x61, 1, 2, b"\x01")
        result = self.host._dump_password_authenticator(self.conn)
        self.assertTrue(result["password_configured"])

    def test_password_not_configured(self):
        """Password not configured."""
        self.host.set_attr(0x61, 1, 1, b"\x01")
        self.host.set_attr(0x61, 1, 2, b"\x00")
        result = self.host._dump_password_authenticator(self.conn)
        self.assertFalse(result["password_configured"])

    def test_max_password_length(self):
        """Max password length."""
        self.host.set_attr(0x61, 1, 1, b"\x01")
        self.host.set_attr(0x61, 1, 3, b"\x40")  # 64
        result = self.host._dump_password_authenticator(self.conn)
        self.assertEqual(result["max_password_length"], 64)

    def test_min_password_length(self):
        """Min password length."""
        self.host.set_attr(0x61, 1, 1, b"\x01")
        self.host.set_attr(0x61, 1, 4, b"\x08")  # 8
        result = self.host._dump_password_authenticator(self.conn)
        self.assertEqual(result["min_password_length"], 8)

    def test_failed_attempts(self):
        """Failed login attempts count."""
        self.host.set_attr(0x61, 1, 1, b"\x01")
        self.host.set_attr(0x61, 1, 5, struct.pack("<I", 5))
        result = self.host._dump_password_authenticator(self.conn)
        self.assertEqual(result["failed_attempts"], 5)

    def test_failed_attempts_zero(self):
        """Zero failed attempts."""
        self.host.set_attr(0x61, 1, 1, b"\x01")
        self.host.set_attr(0x61, 1, 5, struct.pack("<I", 0))
        result = self.host._dump_password_authenticator(self.conn)
        self.assertEqual(result["failed_attempts"], 0)

    def test_failed_attempts_triggers_warning(self):
        """Non-zero failed attempts triggers warning."""
        self.host.set_attr(0x61, 1, 1, b"\x01")
        self.host.set_attr(0x61, 1, 5, struct.pack("<I", 3))
        self.host._dump_password_authenticator(self.conn)
        self.host.logger.warning.assert_called()

    def test_lockout_time(self):
        """Lockout time in seconds."""
        self.host.set_attr(0x61, 1, 1, b"\x01")
        self.host.set_attr(0x61, 1, 6, struct.pack("<I", 300))
        result = self.host._dump_password_authenticator(self.conn)
        self.assertEqual(result["lockout_time_seconds"], 300)

    def test_all_attributes(self):
        """All password authenticator attributes populated."""
        self.host.set_attr(0x61, 1, 1, b"\x01")
        self.host.set_attr(0x61, 1, 2, b"\x01")
        self.host.set_attr(0x61, 1, 3, b"\x40")
        self.host.set_attr(0x61, 1, 4, b"\x08")
        self.host.set_attr(0x61, 1, 5, struct.pack("<I", 0))
        self.host.set_attr(0x61, 1, 6, struct.pack("<I", 600))
        result = self.host._dump_password_authenticator(self.conn)
        self.assertTrue(result["enabled"])
        self.assertTrue(result["password_configured"])
        self.assertEqual(result["max_password_length"], 64)
        self.assertEqual(result["min_password_length"], 8)
        self.assertEqual(result["failed_attempts"], 0)
        self.assertEqual(result["lockout_time_seconds"], 600)


# =============================================================================
# _dump_security_settings tests
# =============================================================================


class TestDumpSecuritySettings(unittest.TestCase):
    """Test _dump_security_settings method."""

    def setUp(self):
        self.host = MockSecurityHost()

    def test_orchestrates_all_dump_methods(self):
        """Calls all 4 sub-dump methods."""
        conn = MagicMock()
        conn.generic_message = MagicMock()

        self.host._dump_cip_security_object = MagicMock(return_value={"accessible": True})
        self.host._dump_eip_security_object = MagicMock(return_value={"accessible": True})
        self.host._dump_certificate_management = MagicMock(return_value={"accessible": True})
        self.host._dump_password_authenticator = MagicMock(return_value={"accessible": True})

        result = self.host._dump_security_settings(conn)

        self.host._dump_cip_security_object.assert_called_once_with(conn)
        self.host._dump_eip_security_object.assert_called_once_with(conn)
        self.host._dump_certificate_management.assert_called_once_with(conn)
        self.host._dump_password_authenticator.assert_called_once_with(conn)

        self.assertIsNotNone(result["cip_security"])
        self.assertIsNotNone(result["eip_security"])
        self.assertIsNotNone(result["certificates"])
        self.assertIsNotNone(result["password_auth"])

    def test_missing_conn(self):
        """None conn returns all None values."""
        result = self.host._dump_security_settings(None)
        self.assertIsNone(result["cip_security"])
        self.assertIsNone(result["eip_security"])
        self.assertIsNone(result["certificates"])
        self.assertIsNone(result["password_auth"])

    def test_conn_without_generic_message(self):
        """Conn without generic_message attribute returns all None."""
        conn = MagicMock(spec=[])  # no generic_message
        result = self.host._dump_security_settings(conn)
        self.assertIsNone(result["cip_security"])

    def test_partial_results(self):
        """Some dump methods return None (not accessible)."""
        conn = MagicMock()
        conn.generic_message = MagicMock()

        self.host._dump_cip_security_object = MagicMock(return_value={"accessible": True})
        self.host._dump_eip_security_object = MagicMock(return_value=None)
        self.host._dump_certificate_management = MagicMock(return_value=None)
        self.host._dump_password_authenticator = MagicMock(return_value=None)

        result = self.host._dump_security_settings(conn)
        self.assertIsNotNone(result["cip_security"])
        self.assertIsNone(result["eip_security"])
        self.assertIsNone(result["certificates"])
        self.assertIsNone(result["password_auth"])


if __name__ == "__main__":
    unittest.main()
