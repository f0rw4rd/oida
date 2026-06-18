#!/usr/bin/env python3
"""
Unit tests for CIP (Common Industrial Protocol) definitions and parsing functions.

Tests cover:
- Data type parsing functions (USINT, UINT, DINT, REAL, etc.)
- Encoding functions
- Complex parsers (MAC, IPv4, EPATH, DLR, interface config)
- Parameter descriptor parsing
- Permission determination from descriptors
- Write error interpretation
- Object/attribute/vendor/device lookup functions
- AttrDef dataclass
- Type inference
"""

import struct
import unittest

import pytest

pytestmark = pytest.mark.core

from oida.protocols.ethernetip.cip_definitions import (
    CIP_OBJECTS,
    CIP_TYPE_CODES,
    CLASS_ATTRIBUTES,
    DEVICE_TYPES,
    PORT_TYPES,
    VENDOR_IDS,
    AttrDef,
    encode_bool,
    encode_ipv4,
    encode_string,
    encode_udint,
    encode_uint,
    encode_usint,
    get_attr_def,
    get_device_type_name,
    get_object_def,
    get_object_name,
    get_permission_from_descriptor,
    get_port_type_name,
    get_vendor_name,
    infer_type_from_data,
    interpret_write_error,
    parse_acd_last_conflict,
    parse_attribute,
    parse_bool,
    parse_bytes,
    parse_dint,
    parse_dlr_capability_flags,
    parse_dlr_node_address,
    parse_dword,
    parse_epath,
    parse_int,
    parse_interface_capability,
    parse_interface_config,
    parse_interface_control,
    parse_interface_counters,
    parse_ipv4,
    parse_lint,
    parse_lreal,
    parse_mac,
    parse_media_counters,
    parse_multicast_config,
    parse_param_descriptor,
    parse_real,
    parse_revision,
    parse_sint,
    parse_string,
    parse_string2,
    parse_udint,
    parse_uint,
    parse_ulint,
    parse_usint,
    parse_word,
)


class TestBasicParsers(unittest.TestCase):
    """Test basic CIP data type parsing functions."""

    def test_parse_usint(self):
        self.assertEqual(parse_usint(b"\x00"), 0)
        self.assertEqual(parse_usint(b"\xff"), 255)
        self.assertEqual(parse_usint(b"\x42"), 66)

    def test_parse_usint_empty(self):
        self.assertEqual(parse_usint(b""), 0)

    def test_parse_sint(self):
        self.assertEqual(parse_sint(b"\x00"), 0)
        self.assertEqual(parse_sint(b"\x7f"), 127)
        self.assertEqual(parse_sint(b"\x80"), -128)
        self.assertEqual(parse_sint(b"\xff"), -1)

    def test_parse_sint_empty(self):
        self.assertEqual(parse_sint(b""), 0)

    def test_parse_uint(self):
        self.assertEqual(parse_uint(b"\x00\x00"), 0)
        self.assertEqual(parse_uint(b"\xff\xff"), 65535)
        self.assertEqual(parse_uint(b"\x39\x05"), 1337)

    def test_parse_uint_short_data(self):
        self.assertEqual(parse_uint(b"\x01"), 0)
        self.assertEqual(parse_uint(b""), 0)

    def test_parse_int(self):
        self.assertEqual(parse_int(b"\x00\x00"), 0)
        self.assertEqual(parse_int(b"\xff\x7f"), 32767)
        self.assertEqual(parse_int(b"\x00\x80"), -32768)
        self.assertEqual(parse_int(b"\xff\xff"), -1)

    def test_parse_int_short_data(self):
        self.assertEqual(parse_int(b"\x01"), 0)

    def test_parse_udint(self):
        self.assertEqual(parse_udint(b"\x00\x00\x00\x00"), 0)
        self.assertEqual(parse_udint(b"\xff\xff\xff\xff"), 4294967295)
        self.assertEqual(parse_udint(b"\x01\x00\x00\x00"), 1)

    def test_parse_udint_short_data(self):
        self.assertEqual(parse_udint(b"\x01\x02\x03"), 0)

    def test_parse_dint(self):
        self.assertEqual(parse_dint(b"\x00\x00\x00\x00"), 0)
        self.assertEqual(parse_dint(b"\xff\xff\xff\xff"), -1)
        data = struct.pack("<i", -100000)
        self.assertEqual(parse_dint(data), -100000)

    def test_parse_ulint(self):
        self.assertEqual(parse_ulint(b"\x00" * 8), 0)
        self.assertEqual(parse_ulint(b"\xff" * 8), 2**64 - 1)

    def test_parse_ulint_short_data(self):
        self.assertEqual(parse_ulint(b"\x01\x02\x03"), 0)

    def test_parse_lint(self):
        self.assertEqual(parse_lint(b"\x00" * 8), 0)
        self.assertEqual(parse_lint(b"\xff" * 8), -1)

    def test_parse_real(self):
        data = struct.pack("<f", 3.14)
        self.assertAlmostEqual(parse_real(data), 3.14, places=2)

    def test_parse_real_zero(self):
        self.assertAlmostEqual(parse_real(b"\x00\x00\x00\x00"), 0.0)

    def test_parse_real_short_data(self):
        self.assertAlmostEqual(parse_real(b"\x01\x02"), 0.0)

    def test_parse_lreal(self):
        data = struct.pack("<d", 2.718281828)
        self.assertAlmostEqual(parse_lreal(data), 2.718281828, places=6)

    def test_parse_lreal_short_data(self):
        self.assertAlmostEqual(parse_lreal(b"\x01\x02"), 0.0)

    def test_parse_bool_true(self):
        self.assertTrue(parse_bool(b"\x01"))
        self.assertTrue(parse_bool(b"\xff"))

    def test_parse_bool_false(self):
        self.assertFalse(parse_bool(b"\x00"))

    def test_parse_bool_empty(self):
        self.assertFalse(parse_bool(b""))

    def test_parse_word(self):
        self.assertEqual(parse_word(b"\xab\xcd"), 0xCDAB)

    def test_parse_dword(self):
        self.assertEqual(parse_dword(b"\x01\x02\x03\x04"), 0x04030201)


class TestStringParsers(unittest.TestCase):
    """Test string parsing functions."""

    def test_parse_string(self):
        """Test SHORT_STRING parsing (1-byte length prefix)."""
        data = b"\x05Hello"
        self.assertEqual(parse_string(data), "Hello")

    def test_parse_string_empty(self):
        self.assertEqual(parse_string(b""), "")
        self.assertEqual(parse_string(b"\x00"), "")

    def test_parse_string2(self):
        """Test STRING2 parsing (2-byte length prefix)."""
        data = struct.pack("<H", 5) + b"World"
        self.assertEqual(parse_string2(data), "World")

    def test_parse_string2_empty(self):
        self.assertEqual(parse_string2(b""), "")
        self.assertEqual(parse_string2(b"\x00"), "")


class TestNetworkParsers(unittest.TestCase):
    """Test network-related parsing functions."""

    def test_parse_mac(self):
        data = b"\xaa\xbb\xcc\xdd\xee\xff"
        self.assertEqual(parse_mac(data), "AA:BB:CC:DD:EE:FF")

    def test_parse_mac_short_data(self):
        self.assertEqual(parse_mac(b"\x01\x02"), "")

    def test_parse_ipv4(self):
        data = b"\xc0\xa8\x01\x64"  # 192.168.1.100
        self.assertEqual(parse_ipv4(data), "192.168.1.100")

    def test_parse_ipv4_short_data(self):
        self.assertEqual(parse_ipv4(b"\x01"), "")

    def test_parse_revision(self):
        data = b"\x14\x03"  # Major 20, Minor 3
        self.assertEqual(parse_revision(data), "20.3")

    def test_parse_revision_short_data(self):
        self.assertEqual(parse_revision(b"\x01"), "")

    def test_parse_bytes(self):
        self.assertEqual(parse_bytes(b"\xab\xcd"), "abcd")
        self.assertEqual(parse_bytes(b""), "")


class TestComplexParsers(unittest.TestCase):
    """Test complex structure parsing functions."""

    def test_parse_dlr_node_address(self):
        mac = b"\x01\x02\x03\x04\x05\x06"
        ip = b"\xc0\xa8\x01\x01"
        result = parse_dlr_node_address(mac + ip)
        self.assertEqual(result["mac"], "01:02:03:04:05:06")
        self.assertEqual(result["ip"], "192.168.1.1")

    def test_parse_dlr_node_address_short(self):
        result = parse_dlr_node_address(b"\x01\x02")
        self.assertIn("raw", result)

    def test_parse_dlr_capability_flags(self):
        flags = struct.pack("<I", 0x0083)  # announce + beacon + supervisor (no redundant gw)
        result = parse_dlr_capability_flags(flags)
        self.assertTrue(result["announce_based"])
        self.assertTrue(result["beacon_based"])
        self.assertTrue(result["supervisor_capable"])
        self.assertFalse(result["redundant_gateway_capable"])

    def test_parse_dlr_capability_flags_short(self):
        result = parse_dlr_capability_flags(b"\x01")
        self.assertIn("raw", result)

    def test_parse_interface_config(self):
        ip = b"\xc0\xa8\x01\x64"  # 192.168.1.100
        mask = b"\xff\xff\xff\x00"  # 255.255.255.0
        gw = b"\xc0\xa8\x01\x01"  # 192.168.1.1
        dns1 = b"\x08\x08\x08\x08"  # 8.8.8.8
        dns2 = b"\x08\x08\x04\x04"  # 8.8.4.4
        domain = b"example.com\x00"
        data = ip + mask + gw + dns1 + dns2 + domain
        result = parse_interface_config(data)
        self.assertEqual(result["ip"], "192.168.1.100")
        self.assertEqual(result["netmask"], "255.255.255.0")
        self.assertEqual(result["gateway"], "192.168.1.1")
        self.assertEqual(result["dns1"], "8.8.8.8")
        self.assertEqual(result["dns2"], "8.8.4.4")

    def test_parse_interface_config_short(self):
        result = parse_interface_config(b"\x01\x02")
        self.assertIn("raw", result)

    def test_parse_interface_counters(self):
        data = struct.pack("<11I", 1000, 200, 50, 0, 5, 1, 800, 150, 30, 0, 2)
        result = parse_interface_counters(data)
        self.assertEqual(result["in_octets"], 1000)
        self.assertEqual(result["in_ucast"], 200)
        self.assertEqual(result["out_octets"], 800)
        self.assertEqual(result["out_errors"], 2)

    def test_parse_interface_counters_short(self):
        result = parse_interface_counters(b"\x01\x02")
        self.assertIn("raw", result)

    def test_parse_media_counters(self):
        data = struct.pack("<12I", *range(12))
        result = parse_media_counters(data)
        self.assertEqual(result["align_errors"], 0)
        self.assertEqual(result["fcs_errors"], 1)
        self.assertEqual(result["mac_rx_errors"], 11)

    def test_parse_media_counters_short(self):
        result = parse_media_counters(b"\x01")
        self.assertIn("raw", result)

    def test_parse_interface_control(self):
        # auto_neg=True, full_duplex=True, speed=100
        data = struct.pack("<HH", 0x03, 100)
        result = parse_interface_control(data)
        self.assertTrue(result["auto_negotiate"])
        self.assertEqual(result["forced_duplex"], "full")
        self.assertEqual(result["forced_speed"], "100Mbps")

    def test_parse_interface_control_half_duplex(self):
        data = struct.pack("<HH", 0x00, 10)
        result = parse_interface_control(data)
        self.assertFalse(result["auto_negotiate"])
        self.assertEqual(result["forced_duplex"], "half")
        self.assertEqual(result["forced_speed"], "10Mbps")

    def test_parse_interface_control_short(self):
        result = parse_interface_control(b"\x01")
        self.assertIn("raw", result)

    def test_parse_interface_capability(self):
        caps = struct.pack("<I", 0x07)  # manual + auto_neg + auto_mdix
        count = b"\x02"
        speed1 = struct.pack("<HH", 100, 1)  # 100Mbps/full
        speed2 = struct.pack("<HH", 1000, 1)  # 1000Mbps/full
        data = caps + count + speed1 + speed2
        result = parse_interface_capability(data)
        self.assertTrue(result["manual_speed_duplex"])
        self.assertTrue(result["auto_negotiate"])
        self.assertTrue(result["auto_mdix"])
        self.assertIn("supported_speeds", result)
        self.assertEqual(len(result["supported_speeds"]), 2)

    def test_parse_interface_capability_short(self):
        result = parse_interface_capability(b"\x01\x02")
        self.assertIn("raw", result)

    def test_parse_multicast_config(self):
        data = struct.pack("<BBH", 1, 0, 32) + b"\xef\x00\x00\x01"
        result = parse_multicast_config(data)
        self.assertEqual(result["alloc_control"], "static")
        self.assertEqual(result["num_mcast"], 32)

    def test_parse_multicast_config_short(self):
        result = parse_multicast_config(b"\x01")
        self.assertIn("raw", result)

    def test_parse_acd_last_conflict_no_conflict(self):
        data = b"\x00" * 10
        result = parse_acd_last_conflict(data)
        self.assertEqual(result["status"], "no conflict")

    def test_parse_acd_last_conflict_active(self):
        data = b"\x01" + b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x01\x02\x03"
        result = parse_acd_last_conflict(data)
        self.assertEqual(result["acd_activity"], "probe conflict")
        self.assertEqual(result["remote_mac"], "AA:BB:CC:DD:EE:FF")

    def test_parse_acd_last_conflict_short(self):
        data = b"\x00\x00\x00"
        result = parse_acd_last_conflict(data)
        self.assertEqual(result["status"], "no conflict")


class TestEpathParser(unittest.TestCase):
    """Test EPATH parsing."""

    def test_parse_epath_empty(self):
        self.assertEqual(parse_epath(b""), "")

    def test_parse_epath_port_segment(self):
        # Port segment: type=001 (port), port=1, link=2
        data = b"\x21\x02"  # Port 1, Link 2
        result = parse_epath(data)
        self.assertIn("Port", result)

    def test_parse_epath_class_segment_8bit(self):
        # Class segment: type=000 (bits 7:5=0), subtype=00 (bits 1:0=0), class=0x01
        # Byte 0x00 >> 5 = 0 (class/instance/attribute), 0x00 & 0x03 = 0 (8-bit class)
        data = b"\x00\x01"  # 8-bit class 0x01
        result = parse_epath(data)
        self.assertIn("Class", result)

    def test_parse_epath_fallback_hex(self):
        # Data that doesn't match known segment types
        data = b"\xe0\x01"
        result = parse_epath(data)
        self.assertIsInstance(result, str)


class TestEncodeFunctions(unittest.TestCase):
    """Test CIP data encoding functions."""

    def test_encode_usint(self):
        self.assertEqual(encode_usint(0), b"\x00")
        self.assertEqual(encode_usint(255), b"\xff")
        self.assertEqual(encode_usint(256), b"\x00")  # masked to 0xFF

    def test_encode_uint(self):
        self.assertEqual(encode_uint(0), b"\x00\x00")
        self.assertEqual(encode_uint(1337), struct.pack("<H", 1337))

    def test_encode_udint(self):
        self.assertEqual(encode_udint(0), b"\x00\x00\x00\x00")
        self.assertEqual(encode_udint(0xDEADBEEF), struct.pack("<I", 0xDEADBEEF))

    def test_encode_string(self):
        result = encode_string("Hello")
        self.assertEqual(result, b"\x05Hello")

    def test_encode_string_truncation(self):
        long_str = "A" * 300
        result = encode_string(long_str)
        self.assertEqual(result[0], 255)
        self.assertEqual(len(result), 256)

    def test_encode_bool(self):
        self.assertEqual(encode_bool(True), b"\x01")
        self.assertEqual(encode_bool(False), b"\x00")

    def test_encode_ipv4(self):
        result = encode_ipv4("192.168.1.100")
        self.assertEqual(result, b"\xc0\xa8\x01\x64")


class TestParameterDescriptor(unittest.TestCase):
    """Test Parameter Object descriptor parsing."""

    def test_parse_param_descriptor_read_only(self):
        result = parse_param_descriptor(0x0010)  # Bit 4: read-only
        self.assertTrue(result["read_only"])
        self.assertFalse(result["write_only"])

    def test_parse_param_descriptor_write_only(self):
        result = parse_param_descriptor(0x4000)  # Bit 14: write-only
        self.assertTrue(result["write_only"])
        self.assertFalse(result["read_only"])

    def test_parse_param_descriptor_monitor(self):
        result = parse_param_descriptor(0x0020)  # Bit 5: monitor
        self.assertTrue(result["monitor"])

    def test_parse_param_descriptor_non_displayed(self):
        result = parse_param_descriptor(0x0400)  # Bit 10: non-displayed
        self.assertTrue(result["non_displayed"])

    def test_parse_param_descriptor_scaling(self):
        result = parse_param_descriptor(0x0007)  # Bits 0-2
        self.assertTrue(result["supports_scaling"])
        self.assertTrue(result["supports_links"])
        self.assertTrue(result["scaling_required"])

    def test_parse_param_descriptor_raw(self):
        result = parse_param_descriptor(0x1234)
        self.assertEqual(result["raw"], 0x1234)

    def test_get_permission_read_only(self):
        self.assertEqual(get_permission_from_descriptor(0x0010), "R")

    def test_get_permission_write_only(self):
        self.assertEqual(get_permission_from_descriptor(0x4000), "W")

    def test_get_permission_read_write(self):
        self.assertEqual(get_permission_from_descriptor(0x0000), "RW")

    def test_get_permission_invalid_both(self):
        # Both read-only and write-only set -- invalid
        self.assertEqual(get_permission_from_descriptor(0x4010), "?")


class TestInterpretWriteError(unittest.TestCase):
    """Test CIP write error interpretation."""

    def test_success(self):
        perm, msg = interpret_write_error(0x00)
        self.assertEqual(perm, "RW")
        self.assertIn("succeeded", msg)

    def test_attribute_not_settable(self):
        perm, msg = interpret_write_error(0x0E)
        self.assertEqual(perm, "R")
        self.assertIn("read-only", msg)

    def test_privilege_violation(self):
        perm, msg = interpret_write_error(0x0F)
        self.assertEqual(perm, "R?")
        self.assertIn("Permission", msg)

    def test_service_not_supported(self):
        perm, msg = interpret_write_error(0x08)
        self.assertEqual(perm, "R?")

    def test_write_once_written(self):
        perm, msg = interpret_write_error(0x21)
        self.assertEqual(perm, "R")

    def test_unknown_error(self):
        perm, msg = interpret_write_error(0xAA)
        self.assertEqual(perm, "?")
        self.assertIn("Unknown", msg)


class TestObjectLookups(unittest.TestCase):
    """Test CIP object, attribute, vendor, and device type lookups."""

    def test_get_object_def_identity(self):
        obj = get_object_def(0x01)
        self.assertIsNotNone(obj)
        self.assertEqual(obj["name"], "Identity")

    def test_get_object_def_unknown(self):
        self.assertIsNone(get_object_def(0xFE))

    def test_get_attr_def_identity_vendor(self):
        attr = get_attr_def(0x01, 1, 1)
        self.assertIsNotNone(attr)
        self.assertEqual(attr.name, "Vendor ID")

    def test_get_attr_def_class_level(self):
        attr = get_attr_def(0x01, 0, 1)
        self.assertIsNotNone(attr)
        self.assertEqual(attr.name, "Revision")

    def test_get_attr_def_unknown_class(self):
        self.assertIsNone(get_attr_def(0xFE, 1, 1))

    def test_get_attr_def_unknown_attr(self):
        self.assertIsNone(get_attr_def(0x01, 1, 99))

    def test_get_object_name_known(self):
        self.assertEqual(get_object_name(0x01), "Identity")
        self.assertEqual(get_object_name(0x02), "Message Router")
        self.assertEqual(get_object_name(0xF5), "TCP/IP Interface")

    def test_get_object_name_unknown(self):
        result = get_object_name(0xFE)
        self.assertIn("Unknown", result)

    def test_get_vendor_name_known(self):
        self.assertEqual(get_vendor_name(1), "Rockwell Automation")

    def test_get_vendor_name_unknown(self):
        result = get_vendor_name(99999)
        self.assertIn("Unknown", result)

    def test_get_device_type_name_known(self):
        self.assertEqual(get_device_type_name(0x0E), "Programmable Logic Controller")

    def test_get_device_type_name_unknown(self):
        result = get_device_type_name(0xFD)
        self.assertIn("Unknown", result)

    def test_get_port_type_name_known(self):
        self.assertEqual(get_port_type_name(0), "Backplane")
        self.assertEqual(get_port_type_name(4), "EtherNet/IP")

    def test_get_port_type_name_unknown(self):
        result = get_port_type_name(999)
        self.assertIn("Unknown", result)


class TestParseAttribute(unittest.TestCase):
    """Test the parse_attribute function."""

    def test_parse_known_attribute(self):
        data = struct.pack("<H", 1)  # Vendor ID = 1
        name, cip_type, value = parse_attribute(0x01, 1, 1, data)
        self.assertEqual(name, "Vendor ID")
        self.assertEqual(cip_type, "UINT")
        self.assertEqual(value, 1)

    def test_parse_unknown_attribute(self):
        data = b"\x42"
        name, cip_type, value = parse_attribute(0xFE, 1, 1, data)
        self.assertEqual(name, "")  # Unknown attribute

    def test_parse_attribute_with_bad_data(self):
        # If parse function raises, should fall back to hex
        name, cip_type, value = parse_attribute(0x01, 1, 7, b"")
        self.assertIsInstance(name, str)


class TestInferTypeFromData(unittest.TestCase):
    """Test data type inference."""

    def test_infer_empty(self):
        self.assertEqual(infer_type_from_data(b""), "?")

    def test_infer_usint(self):
        self.assertEqual(infer_type_from_data(b"\x42"), "USINT")

    def test_infer_uint(self):
        self.assertEqual(infer_type_from_data(b"\x42\x00"), "UINT")

    def test_infer_udint(self):
        self.assertEqual(infer_type_from_data(b"\x42\x00\x00\x00"), "UDINT")

    def test_infer_mac(self):
        self.assertEqual(infer_type_from_data(b"\x01\x02\x03\x04\x05\x06"), "MAC")

    def test_infer_ulint(self):
        self.assertEqual(infer_type_from_data(b"\x00" * 8), "ULINT")

    def test_infer_string(self):
        # Length prefix matches: data[0] == len(data) - 1
        data = b"\x03ABC"
        self.assertEqual(infer_type_from_data(data), "STRING")

    def test_infer_arbitrary_size(self):
        data = b"\x00" * 10
        result = infer_type_from_data(data)
        self.assertIn("BYTE", result)


class TestAttrDef(unittest.TestCase):
    """Test AttrDef dataclass."""

    def test_create_basic(self):
        attr = AttrDef("Test", "UINT", parse_uint)
        self.assertEqual(attr.name, "Test")
        self.assertEqual(attr.cip_type, "UINT")
        self.assertIsNone(attr.encode)
        self.assertEqual(attr.perm, "R")

    def test_create_with_encode(self):
        attr = AttrDef("Test", "UINT", parse_uint, encode_uint, "A description", "RW")
        self.assertEqual(attr.perm, "RW")
        self.assertEqual(attr.desc, "A description")
        self.assertIsNotNone(attr.encode)


class TestCipTypeCodes(unittest.TestCase):
    """Test CIP type code definitions."""

    def test_type_codes_populated(self):
        self.assertGreater(len(CIP_TYPE_CODES), 0)

    def test_known_types(self):
        self.assertEqual(CIP_TYPE_CODES[0xC1], "BOOL")
        self.assertEqual(CIP_TYPE_CODES[0xC3], "INT")
        self.assertEqual(CIP_TYPE_CODES[0xCA], "REAL")
        self.assertEqual(CIP_TYPE_CODES[0xD0], "STRING")

    def test_class_attributes_defined(self):
        self.assertIn(1, CLASS_ATTRIBUTES)
        self.assertEqual(CLASS_ATTRIBUTES[1].name, "Revision")


class TestCipObjectDefinitions(unittest.TestCase):
    """Test CIP object definition completeness."""

    def test_identity_object_defined(self):
        self.assertIn(0x01, CIP_OBJECTS)
        self.assertEqual(CIP_OBJECTS[0x01]["name"], "Identity")

    def test_message_router_defined(self):
        self.assertIn(0x02, CIP_OBJECTS)

    def test_assembly_object_defined(self):
        self.assertIn(0x04, CIP_OBJECTS)

    def test_connection_manager_defined(self):
        self.assertIn(0x06, CIP_OBJECTS)

    def test_tcp_ip_interface_defined(self):
        self.assertIn(0xF5, CIP_OBJECTS)

    def test_ethernet_link_defined(self):
        self.assertIn(0xF6, CIP_OBJECTS)

    def test_cip_security_defined(self):
        self.assertIn(0x5D, CIP_OBJECTS)

    def test_all_objects_have_name(self):
        for class_id, obj_def in CIP_OBJECTS.items():
            self.assertIn("name", obj_def, f"Object 0x{class_id:02X} missing 'name'")

    def test_all_objects_have_inst_attrs(self):
        for class_id, obj_def in CIP_OBJECTS.items():
            self.assertIn("inst_attrs", obj_def, f"Object 0x{class_id:02X} missing 'inst_attrs'")


class TestVendorAndDeviceMaps(unittest.TestCase):
    """Test vendor and device type lookup maps."""

    def test_vendor_ids_populated(self):
        self.assertGreater(len(VENDOR_IDS), 0)

    def test_rockwell_vendor(self):
        self.assertEqual(VENDOR_IDS[1], "Rockwell Automation")

    def test_device_types_populated(self):
        self.assertGreater(len(DEVICE_TYPES), 0)

    def test_plc_device_type(self):
        self.assertEqual(DEVICE_TYPES[0x0E], "Programmable Logic Controller")

    def test_port_types_populated(self):
        self.assertGreater(len(PORT_TYPES), 0)

    def test_backplane_port(self):
        self.assertEqual(PORT_TYPES[0], "Backplane")


if __name__ == "__main__":
    unittest.main()
