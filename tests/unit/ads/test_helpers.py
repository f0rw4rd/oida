#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for ADS shared helpers (helpers.py).

Covers error classification, AMS Net ID validation, lazy import,
CoE SDO read/write, SDO entry description parsing, and backward compat aliases.
"""

import ctypes
import struct
import unittest
from unittest.mock import Mock, patch


class TestValidateAmsNetid(unittest.TestCase):
    """Tests for _validate_ams_netid()"""

    def setUp(self):
        from oida.protocols.ads.helpers import _validate_ams_netid

        self.validate = _validate_ams_netid

    def test_valid_netid(self):
        """Standard 6-part numeric net ID should pass."""
        self.validate("192.168.1.100.1.1")

    def test_valid_netid_all_zeros(self):
        """All zeros is structurally valid."""
        self.validate("0.0.0.0.0.0")

    def test_valid_netid_large_numbers(self):
        """Large segment values are valid."""
        self.validate("255.255.255.255.255.255")

    def test_too_few_parts(self):
        """Fewer than 6 parts should raise ValueError."""
        with self.assertRaises(ValueError):
            self.validate("192.168.1.1")

    def test_too_many_parts(self):
        """More than 6 parts should raise ValueError."""
        with self.assertRaises(ValueError):
            self.validate("192.168.1.100.1.1.1")

    def test_non_numeric(self):
        """Non-numeric segments should raise ValueError."""
        with self.assertRaises(ValueError):
            self.validate("192.168.1.abc.1.1")

    def test_empty_string(self):
        """Empty string should raise ValueError."""
        with self.assertRaises(ValueError):
            self.validate("")

    def test_five_parts(self):
        """Exactly 5 parts should raise ValueError."""
        with self.assertRaises(ValueError):
            self.validate("1.2.3.4.5")

    def test_negative_segment(self):
        """Negative number has a dash prefix so isdigit() returns False."""
        with self.assertRaises(ValueError):
            self.validate("1.2.3.4.5.-1")

    def test_error_message_includes_netid(self):
        """Error message should include the offending net ID."""
        with self.assertRaises(ValueError) as ctx:
            self.validate("bad")
        self.assertIn("bad", str(ctx.exception))


class TestIsAdsTimeout(unittest.TestCase):
    """Tests for _is_ads_timeout()"""

    def setUp(self):
        from oida.protocols.ads.helpers import _is_ads_timeout

        self.fn = _is_ads_timeout

    def test_error_code_1861(self):
        """ADS error code 1861 means timeout."""
        self.assertTrue(self.fn("ADSError (1861): Timeout"))

    def test_timeout_keyword_lowercase(self):
        """'timeout' keyword (case insensitive) means timeout."""
        self.assertTrue(self.fn("connection timeout"))

    def test_timeout_keyword_uppercase(self):
        self.assertTrue(self.fn("TIMEOUT while waiting"))

    def test_timeout_keyword_mixed_case(self):
        self.assertTrue(self.fn("Socket Timeout occurred"))

    def test_non_timeout_error(self):
        """Normal error with no timeout indicator."""
        self.assertFalse(self.fn("ADSError (1793): Access denied"))

    def test_empty_string(self):
        self.assertFalse(self.fn(""))


class TestIsAdsConnBroken(unittest.TestCase):
    """Tests for _is_ads_conn_broken()"""

    def setUp(self):
        from oida.protocols.ads.helpers import _is_ads_conn_broken

        self.fn = _is_ads_conn_broken

    def test_negative_one(self):
        """(-1) indicates broken connection."""
        self.assertTrue(self.fn("ADSError (-1)"))

    def test_reset(self):
        """'reset' keyword means connection was reset."""
        self.assertTrue(self.fn("Connection reset by peer"))

    def test_broken_pipe(self):
        self.assertTrue(self.fn("Broken pipe"))

    def test_broken_pipe_case_insensitive(self):
        self.assertTrue(self.fn("BROKEN PIPE error"))

    def test_write_frame(self):
        """'write frame' indicates a broken connection."""
        self.assertTrue(self.fn("Error: write frame failed"))

    def test_normal_error(self):
        """Normal ADS error should not match."""
        self.assertFalse(self.fn("ADSError (1793): Access denied"))

    def test_empty_string(self):
        self.assertFalse(self.fn(""))


class TestIsAdsPortNotFound(unittest.TestCase):
    """Tests for _is_ads_port_not_found()"""

    def setUp(self):
        from oida.protocols.ads.helpers import _is_ads_port_not_found

        self.fn = _is_ads_port_not_found

    def test_error_code_24(self):
        """Error code 24 means invalid AMS port."""
        self.assertTrue(self.fn("ADSError (24)"))

    def test_invalid_ams_port_text(self):
        self.assertTrue(self.fn("Error: invalid ams port"))

    def test_invalid_ams_port_uppercase(self):
        self.assertTrue(self.fn("INVALID AMS PORT"))

    def test_normal_error(self):
        self.assertFalse(self.fn("ADSError (1793): Access denied"))

    def test_code_240_not_matched(self):
        """(240) does not contain the substring (24), so should not match."""
        self.assertFalse(self.fn("ADSError (240)"))


class TestIsAdsRealError(unittest.TestCase):
    """Tests for _is_ads_real_error()"""

    def setUp(self):
        from oida.protocols.ads.helpers import _is_ads_real_error

        self.fn = _is_ads_real_error

    def test_timeout_is_not_real(self):
        """Timeout errors should NOT be classified as real errors."""
        self.assertFalse(self.fn("ADSError (1861): Timeout"))

    def test_broken_connection_is_not_real(self):
        """Broken connections should NOT be classified as real errors."""
        self.assertFalse(self.fn("Connection reset by peer"))

    def test_access_denied_is_real(self):
        """A genuine ADS error is a real error."""
        self.assertTrue(self.fn("ADSError (1793): Access denied"))

    def test_unknown_error_is_real(self):
        self.assertTrue(self.fn("some unexpected error"))

    def test_empty_is_real(self):
        """Empty string is neither timeout nor broken, so it is 'real'."""
        self.assertTrue(self.fn(""))


class TestExtractAdsError(unittest.TestCase):
    """Tests for _extract_ads_error()"""

    def setUp(self):
        from oida.protocols.ads.helpers import _extract_ads_error

        self.fn = _extract_ads_error

    def test_known_error_code(self):
        """Known code should map to human-readable name."""
        result = self.fn("ADSError (1793)")
        self.assertIn("1793", result)
        # 1793 = 0x0701 = "Service not supported"
        self.assertIn("Service not supported", result)

    def test_known_timeout_code(self):
        """1817 = 0x0719 = Timeout"""
        result = self.fn("ADSError (1817)")
        self.assertIn("1817", result)
        self.assertIn("Timeout", result)

    def test_unknown_error_code(self):
        """Unknown code should return just the numeric code."""
        result = self.fn("ADSError (9999)")
        self.assertEqual(result, "9999")

    def test_no_code_in_string(self):
        """No parenthesized code returns the original string."""
        result = self.fn("Some random error")
        self.assertEqual(result, "Some random error")

    def test_zero_code(self):
        """Code 0 maps to 'OK'."""
        result = self.fn("ADSError (0)")
        self.assertIn("0", result)
        self.assertIn("OK", result)


class TestExtractAdsErrorCode(unittest.TestCase):
    """Tests for _extract_ads_error_code()"""

    def setUp(self):
        from oida.protocols.ads.helpers import _extract_ads_error_code

        self.fn = _extract_ads_error_code

    def test_valid_code_extraction(self):
        self.assertEqual(self.fn("ADSError (1793)"), 1793)

    def test_another_code(self):
        self.assertEqual(self.fn("error (42) happened"), 42)

    def test_no_code_returns_none(self):
        self.assertIsNone(self.fn("No error code here"))

    def test_empty_string(self):
        self.assertIsNone(self.fn(""))

    def test_negative_not_matched(self):
        """Regex \\d+ does not match negative numbers."""
        self.assertIsNone(self.fn("error (-1)"))


class TestGetPyads(unittest.TestCase):
    """Tests for _get_pyads()"""

    def test_get_pyads_available(self):
        """When pyads is available, _get_pyads() should return the module."""
        mock_module = Mock()
        with patch("oida.protocols.ads.helpers._pyads") as mock_lazy:
            mock_lazy.return_value = mock_module
            from oida.protocols.ads.helpers import _get_pyads

            result = _get_pyads()
            self.assertEqual(result, mock_module)

    def test_get_pyads_unavailable(self):
        """When pyads is unavailable, _get_pyads() should raise."""
        with patch("oida.protocols.ads.helpers._pyads") as mock_lazy:
            mock_lazy.side_effect = Exception("pyads not available")
            from oida.protocols.ads.helpers import _get_pyads

            with self.assertRaises(Exception):
                _get_pyads()


class TestReadCoeSdo(unittest.TestCase):
    """Tests for _read_coe_sdo()"""

    def setUp(self):
        from oida.protocols.ads.helpers import _read_coe_sdo

        self.fn = _read_coe_sdo

    @patch("oida.protocols.ads.helpers._read_raw")
    def test_probe_succeeds_full_read_succeeds(self, mock_read_raw):
        """Happy path: probe + full read both succeed."""
        mock_conn = Mock()
        mock_read_raw.side_effect = [
            b"\x01",  # probe (1 byte)
            b"\xab" * 256,  # full read (256 bytes)
        ]
        result = self.fn(mock_conn, 0x1008, 0)
        self.assertEqual(result, b"\xab" * 256)
        self.assertEqual(mock_read_raw.call_count, 2)

    @patch("oida.protocols.ads.helpers._read_raw")
    def test_probe_fails_returns_none(self, mock_read_raw):
        """If probe fails, the SDO doesn't exist, return None."""
        mock_conn = Mock()
        mock_read_raw.side_effect = Exception("No SDO")
        result = self.fn(mock_conn, 0x1008, 0)
        self.assertIsNone(result)

    @patch("oida.protocols.ads.helpers._read_raw")
    def test_short_read_retry(self, mock_read_raw):
        """When full read raises RuntimeError with actual size, retry with that size."""
        mock_conn = Mock()
        mock_read_raw.side_effect = [
            b"\x01",  # probe succeeds
            RuntimeError("Insufficient data (expected 256 bytes, 10 were read)"),
            b"\xcd" * 10,  # retry with actual size
        ]
        result = self.fn(mock_conn, 0x1008, 0)
        self.assertEqual(result, b"\xcd" * 10)
        self.assertEqual(mock_read_raw.call_count, 3)

    @patch("oida.protocols.ads.helpers._read_raw")
    def test_short_read_zero_bytes_returns_none(self, mock_read_raw):
        """If actual size is 0, return None."""
        mock_conn = Mock()
        mock_read_raw.side_effect = [
            b"\x01",  # probe
            RuntimeError("Insufficient data (expected 256 bytes, 0 were read)"),
        ]
        result = self.fn(mock_conn, 0x1008, 0)
        self.assertIsNone(result)

    @patch("oida.protocols.ads.helpers._read_raw")
    def test_full_read_generic_exception_returns_none(self, mock_read_raw):
        """Generic exception on full read returns None."""
        mock_conn = Mock()
        mock_read_raw.side_effect = [
            b"\x01",  # probe
            ValueError("some other error"),
        ]
        result = self.fn(mock_conn, 0x1008, 0)
        self.assertIsNone(result)

    @patch("oida.protocols.ads.helpers._read_raw")
    def test_runtime_error_without_size_returns_none(self, mock_read_raw):
        """RuntimeError that doesn't match the 'N were read' pattern returns None."""
        mock_conn = Mock()
        mock_read_raw.side_effect = [
            b"\x01",  # probe
            RuntimeError("some other runtime error"),
        ]
        result = self.fn(mock_conn, 0x1008, 0)
        self.assertIsNone(result)


class TestWriteCoeSdo(unittest.TestCase):
    """Tests for _write_coe_sdo()"""

    def setUp(self):
        from oida.protocols.ads.helpers import _write_coe_sdo

        self.fn = _write_coe_sdo

    @patch("oida.protocols.ads.helpers._write_raw")
    def test_success(self, mock_write_raw):
        """Successful write returns (True, None)."""
        mock_conn = Mock()
        ok, err = self.fn(mock_conn, 0x1008, 0, b"\x42")
        self.assertTrue(ok)
        self.assertIsNone(err)
        mock_write_raw.assert_called_once()

    @patch("oida.protocols.ads.helpers._write_raw")
    def test_exception(self, mock_write_raw):
        """Exception returns (False, error_str)."""
        mock_conn = Mock()
        mock_write_raw.side_effect = Exception("Write failed")
        ok, err = self.fn(mock_conn, 0x1008, 0, b"\x42")
        self.assertFalse(ok)
        self.assertIn("Write failed", err)


class TestReadSdoEntryDesc(unittest.TestCase):
    """Tests for _read_sdo_entry_desc()"""

    def setUp(self):
        from oida.protocols.ads.helpers import _read_sdo_entry_desc

        self.fn = _read_sdo_entry_desc

    @patch("oida.protocols.ads.helpers._read_raw")
    def test_valid_data_parsing(self, mock_read_raw):
        """Parse a valid SDO entry description response."""
        # Build a 14-byte response:
        # bytes 0-3: padding (4 bytes)
        # bytes 4-5: data_type (uint16 LE) = 5
        # bytes 6-7: bit_length (uint16 LE) = 16
        # bytes 8-9: obj_access (uint16 LE) = 0x003F
        # bytes 10+: name string "TestObj\x00"
        raw = b"\x00" * 4
        raw += struct.pack("<H", 5)  # data_type
        raw += struct.pack("<H", 16)  # bit_length
        raw += struct.pack("<H", 0x3F)  # obj_access
        raw += b"TestObj\x00"

        mock_read_raw.return_value = raw
        mock_conn = Mock()
        result = self.fn(mock_conn, 0x1008, 0)

        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "TestObj")

    @patch("oida.protocols.ads.helpers._read_raw")
    def test_short_data_returns_none(self, mock_read_raw):
        """Response shorter than 10 bytes returns None."""
        mock_read_raw.return_value = b"\x00" * 8
        mock_conn = Mock()
        result = self.fn(mock_conn, 0x1008, 0)
        self.assertIsNone(result)

    @patch("oida.protocols.ads.helpers._read_raw")
    def test_exception_returns_none(self, mock_read_raw):
        """Generic exception returns None."""
        mock_read_raw.side_effect = ValueError("read error")
        mock_conn = Mock()
        result = self.fn(mock_conn, 0x1008, 0)
        self.assertIsNone(result)

    @patch("oida.protocols.ads.helpers._read_raw")
    def test_runtime_error_with_actual_size(self, mock_read_raw):
        """RuntimeError with actual size >= 10 retries and parses."""
        raw = b"\x00" * 4
        raw += struct.pack("<H", 3)  # data_type
        raw += struct.pack("<H", 8)  # bit_length
        raw += struct.pack("<H", 0x01)  # obj_access
        raw += b"X\x00"

        mock_read_raw.side_effect = [
            RuntimeError("Insufficient data (expected 256 bytes, 12 were read)"),
            raw,
        ]
        mock_conn = Mock()
        result = self.fn(mock_conn, 0x1008, 0)

        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "X")

    @patch("oida.protocols.ads.helpers._read_raw")
    def test_runtime_error_actual_size_too_small(self, mock_read_raw):
        """RuntimeError with actual size < 10 returns None."""
        mock_read_raw.side_effect = RuntimeError(
            "Insufficient data (expected 256 bytes, 5 were read)"
        )
        mock_conn = Mock()
        result = self.fn(mock_conn, 0x1008, 0)
        self.assertIsNone(result)

    @patch("oida.protocols.ads.helpers._read_raw")
    def test_runtime_error_no_size_match(self, mock_read_raw):
        """RuntimeError without parseable size returns None."""
        mock_read_raw.side_effect = RuntimeError("something went wrong")
        mock_conn = Mock()
        result = self.fn(mock_conn, 0x1008, 0)
        self.assertIsNone(result)


class TestReadRaw(unittest.TestCase):
    """Tests for _read_raw()"""

    def test_read_raw_calls_conn_read(self):
        from oida.protocols.ads.helpers import _read_raw

        mock_conn = Mock()
        mock_conn.read.return_value = (ctypes.c_byte * 4)(1, 2, 3, 4)
        result = _read_raw(mock_conn, 0xF302, 0, 4)

        self.assertEqual(result, bytes([1, 2, 3, 4]))
        mock_conn.read.assert_called_once()


class TestWriteRaw(unittest.TestCase):
    """Tests for _write_raw()"""

    def test_write_raw_calls_conn_write(self):
        from oida.protocols.ads.helpers import _write_raw

        mock_conn = Mock()
        _write_raw(mock_conn, 0xF302, 0, b"\x01\x02")
        mock_conn.write.assert_called_once()

    def test_write_raw_converts_non_bytes(self):
        from oida.protocols.ads.helpers import _write_raw

        mock_conn = Mock()
        _write_raw(mock_conn, 0xF302, 0, bytearray([0x01, 0x02]))
        mock_conn.write.assert_called_once()


class TestReadWriteRaw(unittest.TestCase):
    """Tests for _read_write_raw()"""

    def test_read_write_raw(self):
        from oida.protocols.ads.helpers import _read_write_raw

        mock_conn = Mock()
        mock_conn.read_write.return_value = (ctypes.c_byte * 2)(0x0A, 0x0B)
        result = _read_write_raw(mock_conn, 0xF080, 0, 2, b"\x01")

        self.assertEqual(result, bytes([0x0A, 0x0B]))
        mock_conn.read_write.assert_called_once()


class TestCoeSdoOffsetAlias(unittest.TestCase):
    """Test backward-compat COE_SDO_OFFSET alias."""

    def test_alias_exists(self):
        from oida.protocols.ads.helpers import COE_SDO_OFFSET
        from oida.protocols.ethercat.coe import COE_SDO_OFFSETS

        self.assertIs(COE_SDO_OFFSET, COE_SDO_OFFSETS)

    def test_alias_is_dict(self):
        from oida.protocols.ads.helpers import COE_SDO_OFFSET

        self.assertIsInstance(COE_SDO_OFFSET, dict)
        self.assertIn("DEVICE_NAME", COE_SDO_OFFSET)


class TestProbeNetid(unittest.TestCase):
    """Tests for _probe_netid()"""

    @patch("oida.protocols.ads.helpers._read_raw")
    def test_plc_runtime_detected(self, mock_read_raw):
        """When read_device_info succeeds, type should be 'plc'."""
        mock_pyads = Mock()
        mock_conn = Mock()
        mock_pyads.Connection.return_value = mock_conn

        mock_version = Mock()
        mock_version.version = 3
        mock_version.revision = 1
        mock_version.build = 4024
        mock_conn.read_device_info.return_value = ("TwinCAT", mock_version)

        from oida.protocols.ads.helpers import _probe_netid

        result = _probe_netid(mock_pyads, "1.2.3.4.1.1", 851)

        self.assertTrue(result["active"])
        self.assertEqual(result["type"], "plc")
        self.assertIn("TwinCAT", result["detail"])

    @patch("oida.protocols.ads.helpers._read_raw")
    def test_broken_connection(self, mock_read_raw):
        """When connection is broken, type should be 'broken'."""
        mock_pyads = Mock()
        mock_conn = Mock()
        mock_pyads.Connection.return_value = mock_conn
        mock_conn.read_device_info.side_effect = Exception("Connection reset by peer")

        from oida.protocols.ads.helpers import _probe_netid

        result = _probe_netid(mock_pyads, "1.2.3.4.1.1", 851)

        self.assertFalse(result["active"])
        self.assertEqual(result["type"], "broken")

    @patch("oida.protocols.ads.helpers._read_raw")
    def test_ethercat_sdo_detected(self, mock_read_raw):
        """When device_info fails with real error but SDO probe succeeds."""
        mock_pyads = Mock()
        mock_conn = Mock()
        mock_pyads.Connection.return_value = mock_conn

        # Tier 1 fails with a real error (not timeout, not broken)
        mock_conn.read_device_info.side_effect = Exception("ADSError (1793)")
        # Tier 2 SDO probe succeeds
        mock_read_raw.return_value = b"\x01"

        from oida.protocols.ads.helpers import _probe_netid

        result = _probe_netid(mock_pyads, "1.2.3.4.1.1", 851)

        self.assertTrue(result["active"])
        self.assertEqual(result["type"], "ethercat")

    @patch("oida.protocols.ads.helpers._read_raw")
    def test_timeout_no_master_fallback(self, mock_read_raw):
        """When all tiers timeout and master_fallback=False, type is 'none'."""
        mock_pyads = Mock()
        mock_conn = Mock()
        mock_pyads.Connection.return_value = mock_conn
        mock_conn.read_device_info.side_effect = Exception("timeout")
        mock_read_raw.side_effect = Exception("timeout")

        from oida.protocols.ads.helpers import _probe_netid

        result = _probe_netid(mock_pyads, "1.2.3.4.1.1", 851, master_fallback=False)

        self.assertFalse(result["active"])
        self.assertEqual(result["type"], "none")
        self.assertEqual(result["detail"], "timeout")


class TestCaptureStderr(unittest.TestCase):
    """Tests for _capture_pyads_stderr()"""

    def test_captures_stderr(self):
        """Context manager should capture stderr output."""
        import os
        import sys
        import tempfile

        from oida.protocols.ads.helpers import _capture_pyads_stderr

        # Under pytest's capture, sys.stderr may be a non-fd-backed object
        # whose .fileno() raises io.UnsupportedOperation. The helper redirects
        # the real stderr fd, so swap in a genuine fd-backed stream for the
        # duration of the test to exercise that path deterministically.
        logger = Mock()
        real_stderr = tempfile.TemporaryFile(mode="w+")
        orig_stderr = sys.stderr
        sys.stderr = real_stderr
        try:
            with _capture_pyads_stderr(logger):
                # Write directly to stderr fd (simulating C library output)
                os.write(sys.stderr.fileno(), b"pyads warning line\n")
        finally:
            sys.stderr = orig_stderr
            real_stderr.close()

        logger.debug.assert_called()

    def test_no_logger(self):
        """Without logger, captured output is simply discarded."""
        from oida.protocols.ads.helpers import _capture_pyads_stderr

        # Should not raise
        with _capture_pyads_stderr(logger=None):
            pass


class TestGetMemoryAreas(unittest.TestCase):
    """Tests for _get_memory_areas()"""

    @patch("oida.protocols.ads.helpers._get_pyads")
    def test_returns_list_of_dicts(self, mock_get_pyads):
        """Memory areas should be a list of dicts with expected keys."""
        mock_pyads = Mock()
        mock_pyads.constants.INDEXGROUP_MEMORYBYTE = 0x4020
        mock_pyads.constants.INDEXGROUP_MEMORYBIT = 0x4021
        mock_pyads.constants.INDEXGROUP_DATA = 0x4040
        mock_get_pyads.return_value = mock_pyads
        # Clear the cache to force reload
        from oida.protocols.ads import helpers

        helpers._memory_areas_cache.clear()

        result = helpers._get_memory_areas()
        self.assertIsInstance(result, list)
        self.assertTrue(len(result) >= 4)
        for area in result:
            self.assertIn("group", area)
            self.assertIn("name", area)
            self.assertIn("offset", area)
            self.assertIn("size", area)

        # Restore cache state
        helpers._memory_areas_cache.clear()


if __name__ == "__main__":
    unittest.main()
