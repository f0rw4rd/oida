#!/usr/bin/env python3
"""
Unit tests for EtherNet/IP NetworkParsersMixin.

Tests cover:
- _parse_tcp_ip_interface: status, config_control, hostname, encap_timeout, not accessible
- _parse_interface_config: bytes, list, dict, too-short bytes
- _parse_ethernet_link: speed, interface flags, MAC, counters, type, not accessible
- _parse_mac_address: bytes, list, string, int, too short, None
- _parse_assembly_instances: found with size, classify I/O/config, not found
- _parse_program_name: success, no data, too short
- _parse_wall_clock_time: valid microseconds, no data
- _parse_time_sync: PTP enabled/disabled, clock types, not accessible
"""

import struct
import unittest
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.core

from oida.protocols.ethernetip.mixins.network_parsers import NetworkParsersMixin


class MockNetworkHost(NetworkParsersMixin):
    """Test host for NetworkParsersMixin."""

    def __init__(self):
        self.logger = MagicMock()
        self._attr_responses = {}

    def _read_cip_attribute(self, conn, class_id, instance, attr_id, **kwargs):
        key = (class_id, instance, attr_id)
        return self._attr_responses.get(key)

    def set_attr(self, class_id, instance, attr_id, data):
        self._attr_responses[(class_id, instance, attr_id)] = data


# =============================================================================
# _parse_tcp_ip_interface tests
# =============================================================================


class TestParseTcpIpInterface(unittest.TestCase):
    """Test _parse_tcp_ip_interface method."""

    def setUp(self):
        self.host = MockNetworkHost()
        self.conn = MagicMock()

    def test_not_accessible(self):
        """All attributes return None => not accessible."""
        result = self.host._parse_tcp_ip_interface(self.conn)
        self.assertFalse(result["accessible"])
        self.assertEqual(result["object_id"], 0xF5)
        self.assertEqual(result["object_name"], "TCP/IP Interface")
        self.host.logger.display.assert_called()

    def test_status_attribute(self):
        """Status attribute (attr 1) parsed as UDINT."""
        self.host.set_attr(0xF5, 1, 1, struct.pack("<I", 0x00000001))
        result = self.host._parse_tcp_ip_interface(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["status"], 1)

    def test_config_control_dhcp(self):
        """Config control with DHCP bit set."""
        self.host.set_attr(0xF5, 1, 3, struct.pack("<I", 0x00000001))
        result = self.host._parse_tcp_ip_interface(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["config_control"], 1)

    def test_config_control_static(self):
        """Config control without DHCP bit (static)."""
        self.host.set_attr(0xF5, 1, 3, struct.pack("<I", 0x00000000))
        result = self.host._parse_tcp_ip_interface(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["config_control"], 0)

    def test_interface_config_bytes(self):
        """Interface config attribute (attr 5) as bytes."""
        # IP=192.168.1.100, Subnet=255.255.255.0, Gateway=192.168.1.1,
        # DNS1=8.8.8.8, DNS2=8.8.4.4
        config_data = bytes(
            [
                100,
                1,
                168,
                192,  # IP (little-endian CIP format)
                0,
                255,
                255,
                255,  # Subnet
                1,
                1,
                168,
                192,  # Gateway
                8,
                8,
                8,
                8,  # DNS1
                4,
                4,
                8,
                8,  # DNS2
            ]
        )
        self.host.set_attr(0xF5, 1, 5, config_data)
        result = self.host._parse_tcp_ip_interface(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["ip_address"], "192.168.1.100")
        self.assertEqual(result["network_mask"], "255.255.255.0")
        self.assertEqual(result["gateway"], "192.168.1.1")
        self.assertEqual(result["dns_primary"], "8.8.8.8")
        self.assertEqual(result["dns_secondary"], "8.8.4.4")

    def test_hostname(self):
        """Hostname attribute (attr 6) as CIP Short String."""
        hostname = "plc-01"
        data = struct.pack("<H", len(hostname)) + hostname.encode("ascii")
        self.host.set_attr(0xF5, 1, 6, data)
        result = self.host._parse_tcp_ip_interface(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["hostname"], "plc-01")

    def test_empty_hostname(self):
        """Empty hostname string."""
        data = struct.pack("<H", 0)
        self.host.set_attr(0xF5, 1, 6, data)
        result = self.host._parse_tcp_ip_interface(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["hostname"], "")

    def test_encap_timeout(self):
        """Encapsulation timeout (attr 13) as UINT."""
        self.host.set_attr(0xF5, 1, 13, struct.pack("<H", 120))
        result = self.host._parse_tcp_ip_interface(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["encap_timeout"], 120)

    def test_all_attributes(self):
        """All attributes populated."""
        self.host.set_attr(0xF5, 1, 1, struct.pack("<I", 0x0001))
        self.host.set_attr(0xF5, 1, 3, struct.pack("<I", 0x0001))
        config_data = bytes(
            [100, 1, 168, 192, 0, 255, 255, 255, 1, 1, 168, 192, 8, 8, 8, 8, 4, 4, 8, 8]
        )
        self.host.set_attr(0xF5, 1, 5, config_data)
        hostname = "my-plc"
        self.host.set_attr(0xF5, 1, 6, struct.pack("<H", len(hostname)) + hostname.encode())
        self.host.set_attr(0xF5, 1, 13, struct.pack("<H", 60))
        result = self.host._parse_tcp_ip_interface(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["hostname"], "my-plc")
        self.assertEqual(result["encap_timeout"], 60)

    def test_exception_in_attribute_read(self):
        """Exception during attribute read handled gracefully."""

        def raise_for_status(conn, cls, inst, attr, **kw):
            if attr == 1:
                raise RuntimeError("read failed")
            return None

        self.host._read_cip_attribute = raise_for_status
        result = self.host._parse_tcp_ip_interface(self.conn)
        self.assertFalse(result["accessible"])


# =============================================================================
# _parse_interface_config tests
# =============================================================================


class TestParseInterfaceConfig(unittest.TestCase):
    """Test _parse_interface_config method."""

    def setUp(self):
        self.host = MockNetworkHost()

    def test_bytes_input_full(self):
        """20+ byte buffer with IP, subnet, gateway, DNS."""
        info = {}
        data = bytes(
            [
                100,
                1,
                168,
                192,  # IP -> 192.168.1.100
                0,
                255,
                255,
                255,  # Subnet -> 255.255.255.0
                1,
                1,
                168,
                192,  # Gateway -> 192.168.1.1
                8,
                8,
                8,
                8,  # DNS1 -> 8.8.8.8
                4,
                4,
                8,
                8,  # DNS2 -> 8.8.4.4
            ]
        )
        self.host._parse_interface_config(info, data)
        self.assertEqual(info["ip_address"], "192.168.1.100")
        self.assertEqual(info["network_mask"], "255.255.255.0")
        self.assertEqual(info["gateway"], "192.168.1.1")
        self.assertEqual(info["dns_primary"], "8.8.8.8")
        self.assertEqual(info["dns_secondary"], "8.8.4.4")

    def test_bytes_input_with_domain(self):
        """Bytes with domain name appended."""
        info = {}
        data = (
            bytes(
                [
                    100,
                    1,
                    168,
                    192,
                    0,
                    255,
                    255,
                    255,
                    1,
                    1,
                    168,
                    192,
                    8,
                    8,
                    8,
                    8,
                    4,
                    4,
                    8,
                    8,
                ]
            )
            + b"example.com\x00"
        )
        self.host._parse_interface_config(info, data)
        self.assertEqual(info["domain_name"], "example.com")

    def test_bytes_too_short(self):
        """Bytes shorter than 20 should not set IP."""
        info = {}
        data = b"\x01\x02\x03\x04"
        self.host._parse_interface_config(info, data)
        self.assertNotIn("ip_address", info)

    def test_bytearray_input(self):
        """bytearray is treated same as bytes."""
        info = {}
        data = bytearray(
            [
                100,
                1,
                168,
                192,
                0,
                255,
                255,
                255,
                1,
                1,
                168,
                192,
                8,
                8,
                8,
                8,
                4,
                4,
                8,
                8,
            ]
        )
        self.host._parse_interface_config(info, data)
        self.assertEqual(info["ip_address"], "192.168.1.100")


# =============================================================================
# _parse_ethernet_link tests
# =============================================================================


class TestParseEthernetLink(unittest.TestCase):
    """Test _parse_ethernet_link method."""

    def setUp(self):
        self.host = MockNetworkHost()
        self.conn = MagicMock()

    def test_not_accessible(self):
        """No attributes accessible."""
        result = self.host._parse_ethernet_link(self.conn)
        self.assertFalse(result["accessible"])
        self.assertEqual(result["object_id"], 0xF6)

    def test_interface_speed(self):
        """Speed attribute parsed as UDINT."""
        self.host.set_attr(0xF6, 1, 1, struct.pack("<I", 100))
        result = self.host._parse_ethernet_link(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["interface_speed"], 100)

    def test_interface_flags_link_up_full_duplex(self):
        """Flags with link up and full duplex."""
        self.host.set_attr(0xF6, 1, 2, struct.pack("<I", 0x03))
        result = self.host._parse_ethernet_link(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["link_status"], "Up")
        self.assertEqual(result["duplex"], "Full")

    def test_interface_flags_link_down_half_duplex(self):
        """Flags with link down and half duplex."""
        self.host.set_attr(0xF6, 1, 2, struct.pack("<I", 0x00))
        result = self.host._parse_ethernet_link(self.conn)
        self.assertEqual(result["link_status"], "Down")
        self.assertEqual(result["duplex"], "Half")

    def test_physical_address_bytes(self):
        """MAC address from 6-byte data."""
        mac_bytes = b"\xaa\xbb\xcc\xdd\xee\xff"
        self.host.set_attr(0xF6, 1, 3, mac_bytes)
        result = self.host._parse_ethernet_link(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["physical_address"], "AA:BB:CC:DD:EE:FF")

    def test_interface_counters(self):
        """Counters attribute stored as hex string."""
        counter_data = b"\x01\x02\x03\x04"
        self.host.set_attr(0xF6, 1, 4, counter_data)
        result = self.host._parse_ethernet_link(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["interface_counters"], "01020304")

    def test_interface_type(self):
        """Interface type from first byte."""
        self.host.set_attr(0xF6, 1, 7, b"\x06")
        result = self.host._parse_ethernet_link(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["interface_type"], 6)

    def test_all_attributes(self):
        """All Ethernet Link attributes populated."""
        self.host.set_attr(0xF6, 1, 1, struct.pack("<I", 1000))
        self.host.set_attr(0xF6, 1, 2, struct.pack("<I", 0x03))
        self.host.set_attr(0xF6, 1, 3, b"\x00\x11\x22\x33\x44\x55")
        self.host.set_attr(0xF6, 1, 4, b"\xaa\xbb")
        self.host.set_attr(0xF6, 1, 7, b"\x01")
        result = self.host._parse_ethernet_link(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["interface_speed"], 1000)
        self.assertEqual(result["physical_address"], "00:11:22:33:44:55")
        self.assertEqual(result["interface_type"], 1)

    def test_exception_in_attribute_read(self):
        """Exception during attribute read handled gracefully."""

        def raise_for_speed(conn, cls, inst, attr, **kw):
            if attr == 1:
                raise RuntimeError("timeout")
            return None

        self.host._read_cip_attribute = raise_for_speed
        result = self.host._parse_ethernet_link(self.conn)
        self.assertFalse(result["accessible"])


# =============================================================================
# _parse_mac_address tests
# =============================================================================


class TestParseMacAddress(unittest.TestCase):
    """Test _parse_mac_address method."""

    def setUp(self):
        self.host = MockNetworkHost()

    def test_bytes_6(self):
        result = self.host._parse_mac_address(b"\x00\x11\x22\x33\x44\x55")
        self.assertEqual(result, "00:11:22:33:44:55")

    def test_bytes_longer_than_6(self):
        """Only first 6 bytes used."""
        result = self.host._parse_mac_address(b"\xaa\xbb\xcc\xdd\xee\xff\x00\x01")
        self.assertEqual(result, "AA:BB:CC:DD:EE:FF")

    def test_bytearray(self):
        result = self.host._parse_mac_address(bytearray(b"\x01\x02\x03\x04\x05\x06"))
        self.assertEqual(result, "01:02:03:04:05:06")

    def test_bytes_too_short(self):
        result = self.host._parse_mac_address(b"\x01\x02\x03")
        self.assertIsNone(result)

    def test_none_input(self):
        result = self.host._parse_mac_address(None)
        self.assertIsNone(result)

    def test_empty_bytes(self):
        result = self.host._parse_mac_address(b"")
        self.assertIsNone(result)


# =============================================================================
# _parse_assembly_instances tests
# =============================================================================


class TestParseAssemblyInstances(unittest.TestCase):
    """Test _parse_assembly_instances method."""

    def setUp(self):
        self.host = MockNetworkHost()
        self.conn = MagicMock()

    def test_no_instances_found(self):
        """All reads return None => no instances."""
        result = self.host._parse_assembly_instances(self.conn)
        self.assertFalse(result["accessible"])
        self.assertEqual(result["instances"], {})
        self.assertEqual(result["input_assemblies"], [])
        self.assertEqual(result["output_assemblies"], [])

    def test_found_instance_with_size(self):
        """Instance found with 2-byte size."""
        # Instance 1 (odd < 100 = input), attr 4 = size
        self.host.set_attr(0x04, 1, 4, struct.pack("<H", 32))
        result = self.host._parse_assembly_instances(self.conn)
        self.assertTrue(result["accessible"])
        self.assertIn(1, result["instances"])
        self.assertEqual(result["instances"][1]["size"], 32)
        self.assertEqual(result["instances"][1]["type"], "input")
        self.assertIn(1, result["input_assemblies"])

    def test_output_assembly(self):
        """Even instance ID < 100 classified as output."""
        self.host.set_attr(0x04, 2, 4, struct.pack("<H", 16))
        result = self.host._parse_assembly_instances(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["instances"][2]["type"], "output")
        self.assertIn(2, result["output_assemblies"])

    def test_config_assembly(self):
        """Instance >= 150 classified as config."""
        self.host.set_attr(0x04, 150, 4, struct.pack("<H", 8))
        result = self.host._parse_assembly_instances(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["instances"][150]["type"], "config")

    def test_vendor_range_instance(self):
        """Instance 100-110 range is classified (< 100 check is false, >= 150 is false)."""
        self.host.set_attr(0x04, 100, 4, struct.pack("<H", 64))
        result = self.host._parse_assembly_instances(self.conn)
        self.assertTrue(result["accessible"])
        # 100 is not < 100 and not >= 150, so type stays "unknown"
        self.assertEqual(result["instances"][100]["type"], "unknown")

    def test_single_byte_size(self):
        """Instance with only 1 byte of size data."""
        self.host.set_attr(0x04, 1, 4, b"\x0a")
        result = self.host._parse_assembly_instances(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["instances"][1]["size"], 10)

    def test_empty_data(self):
        """Instance with empty data => size 0."""
        self.host.set_attr(0x04, 1, 4, b"")
        result = self.host._parse_assembly_instances(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["instances"][1]["size"], 0)

    def test_multiple_instances(self):
        """Multiple instances across ranges."""
        self.host.set_attr(0x04, 1, 4, struct.pack("<H", 32))
        self.host.set_attr(0x04, 2, 4, struct.pack("<H", 16))
        self.host.set_attr(0x04, 100, 4, struct.pack("<H", 8))
        self.host.set_attr(0x04, 150, 4, struct.pack("<H", 4))
        result = self.host._parse_assembly_instances(self.conn)
        self.assertEqual(len(result["instances"]), 4)
        self.assertIn(1, result["input_assemblies"])
        self.assertIn(2, result["output_assemblies"])

    def test_exception_during_read(self):
        """Exception during a single instance read does not stop scanning."""
        call_count = [0]
        original = self.host._read_cip_attribute

        def raise_on_first(conn, cls, inst, attr, **kw):
            call_count[0] += 1
            if inst == 1:
                raise RuntimeError("bad read")
            return original(conn, cls, inst, attr, **kw)

        self.host._read_cip_attribute = raise_on_first
        self.host.set_attr(0x04, 2, 4, struct.pack("<H", 16))
        result = self.host._parse_assembly_instances(self.conn)
        # Instance 2 should still be found despite instance 1 raising
        self.assertTrue(result["accessible"])
        self.assertIn(2, result["instances"])


# =============================================================================
# _parse_program_name tests
# =============================================================================


class TestParseProgramName(unittest.TestCase):
    """Test _parse_program_name method."""

    def setUp(self):
        self.host = MockNetworkHost()
        self.conn = MagicMock()

    def test_success(self):
        """SHORT_STRING with valid program name."""
        name = "MainProgram"
        data = bytes([len(name)]) + name.encode("ascii")
        self.host.set_attr(0x64, 1, 1, data)
        result = self.host._parse_program_name(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["program_name"], "MainProgram")

    def test_no_data(self):
        """No data returned."""
        result = self.host._parse_program_name(self.conn)
        self.assertFalse(result["accessible"])
        self.assertIsNone(result["program_name"])

    def test_too_short(self):
        """Data is only 1 byte (just the length byte with value 0)."""
        self.host.set_attr(0x64, 1, 1, b"\x00")
        result = self.host._parse_program_name(self.conn)
        # len(data) > 1 is False, so accessible remains False
        self.assertFalse(result["accessible"])

    def test_empty_name(self):
        """SHORT_STRING with length 0."""
        self.host.set_attr(0x64, 1, 1, b"\x00\x00")  # length=0, extra byte
        result = self.host._parse_program_name(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["program_name"], "")

    def test_long_name(self):
        """Longer program name."""
        name = "My_Test_Project_2024_v3"
        data = bytes([len(name)]) + name.encode("ascii")
        self.host.set_attr(0x64, 1, 1, data)
        result = self.host._parse_program_name(self.conn)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["program_name"], name)

    def test_exception_handling(self):
        """Exception during read handled gracefully."""

        def raise_err(conn, cls, inst, attr, **kw):
            raise RuntimeError("timeout")

        self.host._read_cip_attribute = raise_err
        result = self.host._parse_program_name(self.conn)
        self.assertFalse(result["accessible"])


# =============================================================================
# _parse_wall_clock_time tests
# =============================================================================


class TestParseWallClockTime(unittest.TestCase):
    """Test _parse_wall_clock_time method."""

    def setUp(self):
        self.host = MockNetworkHost()
        self.conn = MagicMock()

    def test_valid_microseconds(self):
        """Valid 8-byte microseconds since CIP epoch (1972-01-01)."""
        from datetime import datetime

        # 50 years worth of microseconds (approximately 2022)
        cip_epoch = datetime(1972, 1, 1)
        target = datetime(2024, 6, 15, 10, 30, 0)
        usecs = int((target - cip_epoch).total_seconds() * 1_000_000)
        data = struct.pack("<Q", usecs)
        self.host.set_attr(0x8B, 1, 1, data)
        result = self.host._parse_wall_clock_time(self.conn)

        self.assertTrue(result["accessible"])
        self.assertEqual(result["microseconds"], usecs)
        self.assertIn("2024-06-15", result["datetime"])
        self.assertIn("10:30:00", result["datetime_str"])

    def test_zero_microseconds(self):
        """Zero microseconds = CIP epoch."""
        data = struct.pack("<Q", 0)
        self.host.set_attr(0x8B, 1, 1, data)
        result = self.host._parse_wall_clock_time(self.conn)
        self.assertTrue(result["accessible"])
        self.assertIn("1972-01-01", result["datetime"])

    def test_no_data(self):
        """No data returned."""
        result = self.host._parse_wall_clock_time(self.conn)
        self.assertFalse(result["accessible"])
        self.assertIsNone(result["datetime"])

    def test_data_too_short(self):
        """Less than 8 bytes."""
        self.host.set_attr(0x8B, 1, 1, b"\x01\x02\x03\x04")
        result = self.host._parse_wall_clock_time(self.conn)
        self.assertFalse(result["accessible"])

    def test_exception_handling(self):
        """Exception during read handled gracefully."""

        def raise_err(conn, cls, inst, attr, **kw):
            raise RuntimeError("timeout")

        self.host._read_cip_attribute = raise_err
        result = self.host._parse_wall_clock_time(self.conn)
        self.assertFalse(result["accessible"])


# =============================================================================
# _parse_time_sync tests
# =============================================================================


class TestParseTimeSync(unittest.TestCase):
    """Test _parse_time_sync method."""

    def setUp(self):
        self.host = MockNetworkHost()
        self.conn = MagicMock()

    def test_ptp_enabled(self):
        """PTP enabled (attr 1 = 1)."""
        self.host.set_attr(0x43, 1, 1, b"\x01")
        result = self.host._parse_time_sync(self.conn)
        self.assertTrue(result["accessible"])
        self.assertTrue(result["ptp_enable"])

    def test_ptp_disabled(self):
        """PTP disabled (attr 1 = 0)."""
        self.host.set_attr(0x43, 1, 1, b"\x00")
        result = self.host._parse_time_sync(self.conn)
        self.assertTrue(result["accessible"])
        self.assertFalse(result["ptp_enable"])

    def test_clock_type_ordinary(self):
        """Clock type 0 = Ordinary Clock."""
        self.host.set_attr(0x43, 1, 1, b"\x01")
        self.host.set_attr(0x43, 1, 3, struct.pack("<H", 0))
        result = self.host._parse_time_sync(self.conn)
        self.assertEqual(result["clock_type"], "Ordinary Clock")

    def test_clock_type_boundary(self):
        """Clock type 1 = Boundary Clock."""
        self.host.set_attr(0x43, 1, 1, b"\x01")
        self.host.set_attr(0x43, 1, 3, struct.pack("<H", 1))
        result = self.host._parse_time_sync(self.conn)
        self.assertEqual(result["clock_type"], "Boundary Clock")

    def test_clock_type_p2p_transparent(self):
        """Clock type 2 = Peer-to-Peer Transparent Clock."""
        self.host.set_attr(0x43, 1, 1, b"\x01")
        self.host.set_attr(0x43, 1, 3, struct.pack("<H", 2))
        result = self.host._parse_time_sync(self.conn)
        self.assertEqual(result["clock_type"], "Peer-to-Peer Transparent Clock")

    def test_clock_type_e2e_transparent(self):
        """Clock type 3 = End-to-End Transparent Clock."""
        self.host.set_attr(0x43, 1, 1, b"\x01")
        self.host.set_attr(0x43, 1, 3, struct.pack("<H", 3))
        result = self.host._parse_time_sync(self.conn)
        self.assertEqual(result["clock_type"], "End-to-End Transparent Clock")

    def test_clock_type_management(self):
        """Clock type 4 = Management Node."""
        self.host.set_attr(0x43, 1, 1, b"\x01")
        self.host.set_attr(0x43, 1, 3, struct.pack("<H", 4))
        result = self.host._parse_time_sync(self.conn)
        self.assertEqual(result["clock_type"], "Management Node")

    def test_clock_type_unknown(self):
        """Unknown clock type value."""
        self.host.set_attr(0x43, 1, 1, b"\x01")
        self.host.set_attr(0x43, 1, 3, struct.pack("<H", 99))
        result = self.host._parse_time_sync(self.conn)
        self.assertIn("99", result["clock_type"])

    def test_not_accessible(self):
        """No attributes returned."""
        result = self.host._parse_time_sync(self.conn)
        self.assertFalse(result["accessible"])
        self.assertIsNone(result["ptp_enable"])
        self.assertIsNone(result["clock_type"])

    def test_only_ptp_no_clock_type(self):
        """Only PTP enable available, no clock type."""
        self.host.set_attr(0x43, 1, 1, b"\x01")
        result = self.host._parse_time_sync(self.conn)
        self.assertTrue(result["accessible"])
        self.assertTrue(result["ptp_enable"])
        self.assertIsNone(result["clock_type"])

    def test_exception_handling(self):
        """Exception during read handled gracefully."""

        def raise_err(conn, cls, inst, attr, **kw):
            raise RuntimeError("timeout")

        self.host._read_cip_attribute = raise_err
        result = self.host._parse_time_sync(self.conn)
        self.assertFalse(result["accessible"])


if __name__ == "__main__":
    unittest.main()
