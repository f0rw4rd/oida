#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Snap7 SZL (System Status List) parser.

Source: src/oida/protocols/snap7/szl_parser.py
"""

import struct
import unittest


class TestSZLParserRouting(unittest.TestCase):
    """Test SZLParser.parse() routing to correct sub-parser."""

    def test_routes_0x001c(self):
        """Test parse routes SZL ID 0x001C to _parse_0x001c."""
        from oida.protocols.snap7.szl_parser import SZLParser

        # Minimal valid data (4-byte header, no records)
        data = struct.pack("<HH", 34, 1)
        result = SZLParser.parse(0x001C, 1, data)
        self.assertEqual(result["szl_id"], "0x001C")

    def test_routes_0x0011(self):
        """Test parse routes SZL ID 0x0011 to _parse_0x0011."""
        from oida.protocols.snap7.szl_parser import SZLParser

        data = struct.pack("<HH", 28, 1)
        result = SZLParser.parse(0x0011, 0, data)
        self.assertEqual(result["szl_id"], "0x0011")

    def test_routes_0x0132(self):
        """Test parse routes SZL ID 0x0132 to _parse_0x0132."""
        from oida.protocols.snap7.szl_parser import SZLParser

        data = bytes(12)
        result = SZLParser.parse(0x0132, 4, data)
        self.assertEqual(result["szl_id"], "0x0132")

    def test_unknown_szl_id(self):
        """Test unknown SZL ID returns raw hex and parsed=False."""
        from oida.protocols.snap7.szl_parser import SZLParser

        data = bytes([0xAA, 0xBB, 0xCC])
        result = SZLParser.parse(0x9999, 0, data)
        self.assertIn("raw", result)
        self.assertEqual(result["raw"], "aabbcc")
        self.assertFalse(result["parsed"])


class TestSZLParse0x001C(unittest.TestCase):
    """Test SZLParser._parse_0x001c() - Module identification."""

    def _build_0x001c_data(self, record_len, records):
        """Helper to build SZL 0x001C binary data.

        Args:
            record_len: Length of each record (index + string).
            records: List of (index, string_value) tuples.
        """
        header = struct.pack("<HH", record_len, len(records))
        body = b""
        str_len = record_len - 2
        for idx, value in records:
            body += struct.pack(">H", idx)
            encoded = value.encode("ascii")[:str_len]
            body += encoded.ljust(str_len, b"\x00")
        return header + body

    def test_valid_single_record_index_7(self):
        """Test parsing a single record at index 7 (module type)."""
        from oida.protocols.snap7.szl_parser import SZLParser

        data = self._build_0x001c_data(34, [(7, "CPU 315-2 DP")])
        result = SZLParser._parse_0x001c(data, 1)
        self.assertTrue(result["parsed"])
        self.assertEqual(result["module_type"], "CPU 315-2 DP")

    def test_valid_multiple_records(self):
        """Test parsing multiple records with known indices."""
        from oida.protocols.snap7.szl_parser import SZLParser

        data = self._build_0x001c_data(
            34,
            [
                (1, "PlantID"),
                (2, "SystemName"),
                (3, "Location"),
                (4, "Siemens"),
                (5, "SN123456"),
                (7, "CPU 1511-1 PN"),
                (9, "V2.9.0"),
                (11, "OEMData"),
            ],
        )
        result = SZLParser._parse_0x001c(data, 1)
        self.assertTrue(result["parsed"])
        self.assertEqual(result["plant_identification"], "PlantID")
        self.assertEqual(result["system_name"], "SystemName")
        self.assertEqual(result["module_location"], "Location")
        self.assertEqual(result["manufacturer"], "Siemens")
        self.assertEqual(result["serial_number"], "SN123456")
        self.assertEqual(result["module_type"], "CPU 1511-1 PN")
        self.assertEqual(result["version_info"], "V2.9.0")
        self.assertEqual(result["oem_info"], "OEMData")

    def test_empty_data(self):
        """Test _parse_0x001c with empty data."""
        from oida.protocols.snap7.szl_parser import SZLParser

        result = SZLParser._parse_0x001c(b"", 0)
        self.assertFalse(result["parsed"])

    def test_short_data(self):
        """Test _parse_0x001c with data shorter than header (< 4 bytes)."""
        from oida.protocols.snap7.szl_parser import SZLParser

        result = SZLParser._parse_0x001c(b"\x00\x01", 0)
        self.assertFalse(result["parsed"])

    def test_header_only_no_records(self):
        """Test _parse_0x001c with just header, no record data."""
        from oida.protocols.snap7.szl_parser import SZLParser

        data = struct.pack("<HH", 34, 0)
        result = SZLParser._parse_0x001c(data, 0)
        # No records parsed
        self.assertFalse(result.get("parsed", True))

    def test_zero_index_terminates(self):
        """Test that a record with index 0 terminates parsing."""
        from oida.protocols.snap7.szl_parser import SZLParser

        record_len = 10
        header = struct.pack("<HH", record_len, 2)
        # First record: index=0 (terminator)
        body = struct.pack(">H", 0) + b"\x00" * (record_len - 2)
        data = header + body
        result = SZLParser._parse_0x001c(data, 0)
        self.assertFalse(result.get("parsed", True))

    def test_non_printable_data_stored_as_hex(self):
        """Test non-printable record data is stored as hex."""
        from oida.protocols.snap7.szl_parser import SZLParser

        record_len = 6
        header = struct.pack("<HH", record_len, 1)
        body = struct.pack(">H", 1) + bytes([0x80, 0x90, 0xA0, 0xB0])
        data = header + body
        result = SZLParser._parse_0x001c(data, 0)
        # Non-printable data should be stored as hex
        self.assertTrue(result["parsed"])
        self.assertIn(1, result.get("records", {}))

    def test_record_len_stored_in_result(self):
        """Test that record_len and partial_list_len are in result."""
        from oida.protocols.snap7.szl_parser import SZLParser

        data = self._build_0x001c_data(34, [(7, "Test")])
        result = SZLParser._parse_0x001c(data, 1)
        self.assertEqual(result["record_len"], 34)
        self.assertEqual(result["partial_list_len"], 1)

    def test_zero_record_len_does_not_hang(self):
        """SZL 0x001C with record_len=0 must not infinite-loop (DoS).

        Original code: `while offset + record_len <= len(data)` plus
        `offset += record_len` => offset never advances => CPU pegged.
        Malicious or corrupt SZL response from the PLC could weaponize.
        """
        import threading
        import time
        from oida.protocols.snap7.szl_parser import SZLParser

        # Build header with record_len=0 and non-zero first index so
        # the loop cannot exit via the index==0 break.
        header = struct.pack("<HH", 0, 1)
        body = struct.pack(">H", 7) + b"AAAA" + b"\x00" * 26
        data = header + body

        holder = {}

        def run():
            holder["t0"] = time.time()
            holder["result"] = SZLParser._parse_0x001c(data, 0)
            holder["t1"] = time.time()

        t = threading.Thread(target=run, daemon=True)
        t.start()
        t.join(timeout=2.0)
        self.assertFalse(t.is_alive(), "SZL 0x001C parser hung on record_len=0")
        self.assertIsInstance(holder.get("result"), dict)


class TestSZLParse0x0011(unittest.TestCase):
    """Test SZLParser._parse_0x0011() - CPU characteristics."""

    def _build_0x0011_data(self, record_len, records):
        """Helper to build SZL 0x0011 binary data.

        SZL 0x0011 has a fixed 20-byte string field per record.
        """
        header = struct.pack("<HH", record_len, len(records))
        body = b""
        for idx, value in records:
            body += struct.pack(">H", idx)
            encoded = value.encode("ascii")[:20]
            body += encoded.ljust(20, b"\x00")
            # Pad rest of record_len - 2 - 20 bytes
            remaining = record_len - 2 - 20
            if remaining > 0:
                body += b"\x00" * remaining
        return header + body

    def test_valid_records_indices_1_6_7(self):
        """Test parsing records at known indices 1, 6, 7."""
        from oida.protocols.snap7.szl_parser import SZLParser

        data = self._build_0x0011_data(
            28,
            [
                (1, "IE_CP"),
                (6, "6ES7 611-4SB00-0YB7"),
                (7, "SN-AB-1234"),
            ],
        )
        result = SZLParser._parse_0x0011(data, 0)
        self.assertTrue(result["parsed"])
        self.assertEqual(result["module_name"], "IE_CP")
        self.assertEqual(result["order_code"], "6ES7 611-4SB00-0YB7")
        self.assertEqual(result["serial_number"], "SN-AB-1234")

    def test_empty_data(self):
        """Test _parse_0x0011 with empty data."""
        from oida.protocols.snap7.szl_parser import SZLParser

        result = SZLParser._parse_0x0011(b"", 0)
        self.assertFalse(result["parsed"])

    def test_short_data(self):
        """Test _parse_0x0011 with data shorter than header."""
        from oida.protocols.snap7.szl_parser import SZLParser

        result = SZLParser._parse_0x0011(b"\x01\x02", 0)
        self.assertFalse(result["parsed"])

    def test_header_only(self):
        """Test _parse_0x0011 with just a header, no records."""
        from oida.protocols.snap7.szl_parser import SZLParser

        data = struct.pack("<HH", 28, 0)
        result = SZLParser._parse_0x0011(data, 0)
        self.assertFalse(result.get("parsed", True))

    def test_zero_index_terminates(self):
        """Test that record with index 0 terminates parsing."""
        from oida.protocols.snap7.szl_parser import SZLParser

        record_len = 28
        header = struct.pack("<HH", record_len, 1)
        body = struct.pack(">H", 0) + b"\x00" * (record_len - 2)
        data = header + body
        result = SZLParser._parse_0x0011(data, 0)
        self.assertFalse(result.get("parsed", True))

    def test_record_len_in_result(self):
        """Test record_len and partial_list_len stored in result."""
        from oida.protocols.snap7.szl_parser import SZLParser

        data = self._build_0x0011_data(28, [(1, "Test")])
        result = SZLParser._parse_0x0011(data, 0)
        self.assertEqual(result["record_len"], 28)
        self.assertEqual(result["partial_list_len"], 1)

    def test_zero_record_len_does_not_hang(self):
        """SZL 0x0011 with record_len=0 must not infinite-loop (DoS)."""
        import threading
        from oida.protocols.snap7.szl_parser import SZLParser

        header = struct.pack("<HH", 0, 1)
        body = struct.pack(">H", 1) + b"AAAA" + b"\x00" * 26
        data = header + body

        holder = {}

        def run():
            holder["result"] = SZLParser._parse_0x0011(data, 0)

        t = threading.Thread(target=run, daemon=True)
        t.start()
        t.join(timeout=2.0)
        self.assertFalse(t.is_alive(), "SZL 0x0011 parser hung on record_len=0")
        self.assertIsInstance(holder.get("result"), dict)


class TestSZLParse0x0132(unittest.TestCase):
    """Test SZLParser._parse_0x0132() - Protection level."""

    def test_index_4_valid_data(self):
        """Test parsing SZL 0x0132 index 4 with valid 12-byte data."""
        from oida.protocols.snap7.szl_parser import SZLParser

        # Layout: bytes at offsets 2, 4, 6, 8, 10
        data = bytearray(12)
        data[2] = 1  # sch_schal
        data[4] = 2  # sch_par
        data[6] = 3  # sch_rel
        data[8] = 4  # bart_sch
        data[10] = 5  # anl_sch
        result = SZLParser._parse_0x0132(bytes(data), 4)
        self.assertTrue(result["parsed"])
        self.assertEqual(result["sch_schal"], 1)
        self.assertEqual(result["sch_par"], 2)
        self.assertEqual(result["sch_rel"], 3)
        self.assertEqual(result["bart_sch"], 4)
        self.assertEqual(result["anl_sch"], 5)

    def test_protection_level_calculation(self):
        """Test protection_level is max of sch_schal, sch_par, sch_rel."""
        from oida.protocols.snap7.szl_parser import SZLParser

        data = bytearray(12)
        data[2] = 1  # sch_schal
        data[4] = 3  # sch_par (highest)
        data[6] = 2  # sch_rel
        result = SZLParser._parse_0x0132(bytes(data), 4)
        self.assertEqual(result["protection_level"], 3)

    def test_no_protection(self):
        """Test all-zero protection fields."""
        from oida.protocols.snap7.szl_parser import SZLParser

        data = bytes(12)
        result = SZLParser._parse_0x0132(data, 4)
        self.assertTrue(result["parsed"])
        self.assertEqual(result["protection_level"], 0)

    def test_short_data_index_4(self):
        """Test index 4 with data shorter than 12 bytes skips detailed parsing."""
        from oida.protocols.snap7.szl_parser import SZLParser

        data = bytes(8)
        result = SZLParser._parse_0x0132(data, 4)
        # With < 12 bytes and index 4, no detailed fields are set
        self.assertTrue(result["parsed"])
        self.assertNotIn("protection_level", result)

    def test_other_index(self):
        """Test index != 4 still returns parsed=True."""
        from oida.protocols.snap7.szl_parser import SZLParser

        data = bytes(20)
        result = SZLParser._parse_0x0132(data, 1)
        self.assertTrue(result["parsed"])
        self.assertNotIn("protection_level", result)

    def test_empty_data_index_4(self):
        """Test empty data still returns parsed=True (no exception path)."""
        from oida.protocols.snap7.szl_parser import SZLParser

        result = SZLParser._parse_0x0132(b"", 4)
        self.assertTrue(result["parsed"])

    def test_szl_id_in_result(self):
        """Test szl_id is always '0x0132'."""
        from oida.protocols.snap7.szl_parser import SZLParser

        result = SZLParser._parse_0x0132(bytes(12), 4)
        self.assertEqual(result["szl_id"], "0x0132")

    def test_index_stored_in_result(self):
        """Test index value is stored in result."""
        from oida.protocols.snap7.szl_parser import SZLParser

        result = SZLParser._parse_0x0132(bytes(12), 4)
        self.assertEqual(result["index"], 4)


class TestSZLParserEdgeCases(unittest.TestCase):
    """Test SZL parser edge cases."""

    def test_parse_exception_in_0x001c(self):
        """Test _parse_0x001c handles internal exceptions gracefully."""
        from oida.protocols.snap7.szl_parser import SZLParser

        # Very large record_len that would cause issues
        data = struct.pack("<HH", 65535, 1) + b"\x00" * 4
        result = SZLParser._parse_0x001c(data, 0)
        # Should not raise, may have parsed=False or partial result
        self.assertIn("szl_id", result)

    def test_parse_exception_in_0x0011(self):
        """Test _parse_0x0011 handles internal exceptions gracefully."""
        from oida.protocols.snap7.szl_parser import SZLParser

        data = struct.pack("<HH", 65535, 1) + b"\x00" * 4
        result = SZLParser._parse_0x0011(data, 0)
        self.assertIn("szl_id", result)

    def test_all_zeroes_0x001c(self):
        """Test _parse_0x001c with all-zero data."""
        from oida.protocols.snap7.szl_parser import SZLParser

        data = bytes(100)
        result = SZLParser._parse_0x001c(data, 0)
        # record_len of 0 should not cause infinite loop
        self.assertIn("szl_id", result)


if __name__ == "__main__":
    unittest.main()
