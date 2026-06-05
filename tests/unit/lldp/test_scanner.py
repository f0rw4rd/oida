#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for LLDP (Link Layer Discovery Protocol) scanner functionality.
"""

import unittest
from unittest.mock import Mock, patch


class MockEthernetPacket:
    """Mock Ethernet packet for testing"""

    def __init__(self, src="aa:bb:cc:dd:ee:ff", dst="01:80:c2:00:00:0e"):
        self.src = src
        self.dst = dst


class MockLLDPDU:
    """Mock LLDPDU packet for testing"""

    def __init__(self):
        self.payload = None


class MockLLDPDUChassisID:
    """Mock LLDP Chassis ID TLV"""

    def __init__(self, subtype=4, chassis_id=b"\xaa\xbb\xcc\xdd\xee\xff"):
        self.subtype = subtype
        self.chassis_id = chassis_id


class MockLLDPDUPortID:
    """Mock LLDP Port ID TLV"""

    def __init__(self, subtype=3, port_id=b"\x00\x01"):
        self.subtype = subtype
        self.port_id = port_id


class MockLLDPDUTimeToLive:
    """Mock LLDP TTL TLV"""

    def __init__(self, ttl=120):
        self.ttl = ttl


class MockLLDPDUSystemName:
    """Mock LLDP System Name TLV"""

    def __init__(self, name="switch-001"):
        self.system_name = name.encode()


class MockLLDPDUSystemDescription:
    """Mock LLDP System Description TLV"""

    def __init__(self, desc="Cisco Catalyst 2960"):
        self.system_description = desc.encode()


class MockLLDPDUSystemCapabilities:
    """Mock LLDP System Capabilities TLV"""

    def __init__(
        self,
        bridge=False,
        router=False,
        station_only=False,
        repeater=False,
        wlan_ap=False,
        telephone=False,
    ):
        # Scapy uses individual boolean fields for capabilities
        self.mac_bridge_enabled = bridge
        self.router_enabled = router
        self.station_only_enabled = station_only
        self.repeater_enabled = repeater
        self.wlan_access_point_enabled = wlan_ap
        self.telephone_enabled = telephone
        self.docsis_cable_device_enabled = False
        self.c_vlan_component_enabled = False
        self.s_vlan_component_enabled = False


class MockLLDPDUManagementAddress:
    """Mock LLDP Management Address TLV"""

    def __init__(self, subtype=1, address=b"\xc0\xa8\x01\x64"):  # 192.168.1.100
        self.management_address_subtype = subtype
        self.management_address = address


class MockAsyncSniffer:
    """Mock async packet sniffer"""

    def __init__(self, iface, filter, prn, store, timeout):
        self.iface = iface
        self.filter = filter
        self.prn = prn
        self.store = store
        self.timeout = timeout
        self.started = False

    def start(self):
        self.started = True

    def stop(self):
        self.started = False


class TestLLDPScannerInit(unittest.TestCase):
    """Test LLDP scanner initialization"""

    def setUp(self):
        from oida.protocols.discovery.lldp import LLDPScanner

        self.LLDPScanner = LLDPScanner

    def test_basic_initialization(self):
        """Test basic scanner initialization"""
        args = {"interface": "eth0"}
        scanner = self.LLDPScanner(args)

        self.assertEqual(scanner.interface, "eth0")
        self.assertEqual(scanner.get_protocol_name(), "LLDP")
        self.assertEqual(scanner.get_default_port(), 0)  # No port for LLDP
        self.assertEqual(scanner.discovered_devices, {})
        self.assertEqual(scanner.packet_count, 0)

    def test_initialization_with_options(self):
        """Test scanner initialization with various options"""
        args = {"interface": "wlan0", "capture-time": 300, "filter-industrial": True}
        scanner = self.LLDPScanner(args)

        self.assertEqual(scanner.interface, "wlan0")
        self.assertEqual(scanner.capture_time, 300)
        self.assertTrue(scanner.filter_industrial)


class TestLLDPProtocolLogic(unittest.TestCase):
    """Test LLDP protocol implementation logic"""

    def setUp(self):
        from oida.protocols.discovery.lldp import LLDPScanner, LLDPDevice

        self.LLDPScanner = LLDPScanner
        self.LLDPDevice = LLDPDevice
        self.args = {"interface": "eth0"}

    @patch("oida.protocols.discovery.lldp.check_raw_socket_capability")
    def test_interface_validation(self, mock_raw_socket):
        """Test network interface validation"""
        from oida.protocols.discovery import lldp

        scanner = self.LLDPScanner(self.args)
        mock_raw_socket.return_value = (True, "")

        # Patch get_if_list in the _scapy_classes dict
        mock_get_if_list = Mock(return_value=["eth0", "eth1", "lo"])
        orig = lldp._scapy_classes.get("get_if_list")
        lldp._scapy_classes["get_if_list"] = mock_get_if_list
        try:
            result = scanner.connect()
        finally:
            if orig is not None:
                lldp._scapy_classes["get_if_list"] = orig
            else:
                lldp._scapy_classes.pop("get_if_list", None)

        self.assertEqual(result, "eth0")
        mock_get_if_list.assert_called_once()

    def test_chassis_id_formatting(self):
        """Test chassis ID formatting logic"""
        scanner = self.LLDPScanner(self.args)

        # Test MAC address format
        tlv = MockLLDPDUChassisID(subtype=4, chassis_id=b"\xaa\xbb\xcc\xdd\xee\xff")
        result = scanner._format_chassis_id(tlv)
        self.assertEqual(result, "aa:bb:cc:dd:ee:ff")

        # Test string format
        tlv = MockLLDPDUChassisID(subtype=7, chassis_id=b"switch-001")
        result = scanner._format_chassis_id(tlv)
        self.assertEqual(result, "switch-001")

    def test_capability_parsing(self):
        """Test capability parsing logic"""
        scanner = self.LLDPScanner(self.args)

        tlv = MockLLDPDUSystemCapabilities(bridge=True, router=True)
        capabilities = scanner._parse_capabilities(tlv)

        self.assertIn("Bridge", capabilities)
        self.assertIn("Router", capabilities)
        self.assertEqual(len(capabilities), 2)

    def test_management_address_parsing(self):
        """Test management address parsing"""
        scanner = self.LLDPScanner(self.args)

        # Test IPv4 address
        tlv = MockLLDPDUManagementAddress(subtype=1, address=b"\xc0\xa8\x01\x64")
        result = scanner._parse_management_address(tlv)
        self.assertEqual(result, "192.168.1.100")

        # Test IPv6 address (simplified)
        tlv = MockLLDPDUManagementAddress(
            subtype=2, address=b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
        )
        result = scanner._parse_management_address(tlv)
        self.assertIsNotNone(result)


class TestLLDPMockOperations(unittest.TestCase):
    """Test LLDP operations with mocked dependencies"""

    def setUp(self):
        from oida.protocols.discovery.lldp import LLDPScanner

        self.LLDPScanner = LLDPScanner
        self.args = {"interface": "eth0"}

    @patch("oida.protocols.discovery.lldp.sleep")
    def test_packet_capture_workflow(self, mock_sleep):
        """Test LLDP packet capture workflow"""
        from oida.protocols.discovery import lldp

        scanner = self.LLDPScanner(self.args)
        scanner.capture_time = 2  # Short capture for testing

        # Patch AsyncSniffer in the _scapy_classes dict
        orig = lldp._scapy_classes.get("AsyncSniffer")
        lldp._scapy_classes["AsyncSniffer"] = MockAsyncSniffer
        try:
            results = scanner._capture_lldp_packets("eth0")
        finally:
            if orig is not None:
                lldp._scapy_classes["AsyncSniffer"] = orig
            else:
                lldp._scapy_classes.pop("AsyncSniffer", None)

        self.assertIn("capture_info", results)
        self.assertEqual(results["capture_info"]["interface"], "eth0")
        self.assertEqual(results["capture_info"]["capture_duration"], 2)
        self.assertEqual(mock_sleep.call_count, 2)

    def test_packet_processing(self):
        """Test LLDP packet processing"""
        scanner = self.LLDPScanner(self.args)

        # Create mock packet with LLDP layers
        packet = Mock()
        packet.__getitem__ = Mock(
            side_effect=lambda x: MockEthernetPacket() if x.__name__ == "Ether" else None
        )
        packet.haslayer = Mock(side_effect=lambda x: x.__name__ == "LLDPDU")

        # Mock Ethernet layer
        eth_layer = MockEthernetPacket(src="aa:bb:cc:dd:ee:ff")
        lldp_layer = MockLLDPDU()
        packet.__getitem__ = Mock(
            side_effect=lambda x: eth_layer if x.__name__ == "Ether" else lldp_layer
        )

        scanner._process_lldp_packet(packet)

        self.assertEqual(scanner.packet_count, 1)
        self.assertIn("aa:bb:cc:dd:ee:ff", scanner.discovered_devices)

    def test_tlv_processing(self):
        """Test LLDP TLV processing doesn't crash with unknown TLV types"""
        from oida.protocols.discovery.lldp import LLDPDevice

        scanner = self.LLDPScanner(self.args)
        device = LLDPDevice(mac_address="aa:bb:cc:dd:ee:ff")

        # Process various mock TLVs (isinstance checks will fail, but shouldn't crash)
        scanner._process_lldp_tlv(device, MockLLDPDUChassisID())
        scanner._process_lldp_tlv(device, MockLLDPDUPortID())
        scanner._process_lldp_tlv(device, MockLLDPDUTimeToLive())
        scanner._process_lldp_tlv(device, MockLLDPDUSystemName())
        scanner._process_lldp_tlv(device, MockLLDPDUSystemDescription())
        scanner._process_lldp_tlv(device, MockLLDPDUSystemCapabilities(bridge=True))
        scanner._process_lldp_tlv(device, MockLLDPDUManagementAddress())

        # Verify device still has valid structure (mocks don't match isinstance checks)
        self.assertEqual(device.mac_address, "aa:bb:cc:dd:ee:ff")
        self.assertIsInstance(device.capabilities, list)
        self.assertIsInstance(device.management_addresses, list)

    def test_industrial_device_filtering(self):
        """Test industrial device filtering"""
        from oida.protocols.discovery.lldp import LLDPDevice

        scanner = self.LLDPScanner(self.args)

        devices = [
            LLDPDevice(
                mac_address="aa:bb:cc:dd:ee:f1",
                system_name="plc-001",
                system_description="Siemens S7-1500",
                port_description="",
            ),
            LLDPDevice(
                mac_address="aa:bb:cc:dd:ee:f2",
                system_name="switch-001",
                system_description="Cisco Catalyst",
                port_description="",
            ),
            LLDPDevice(
                mac_address="aa:bb:cc:dd:ee:f3",
                system_name="hmi-panel",
                system_description="Rockwell PanelView",
                port_description="",
            ),
        ]

        industrial = scanner._filter_industrial_devices(devices)

        self.assertEqual(len(industrial), 2)  # PLC and HMI
        industrial_names = [d.system_name for d in industrial]
        self.assertIn("plc-001", industrial_names)
        self.assertIn("hmi-panel", industrial_names)

    def test_statistics_generation(self):
        """Test statistics generation"""
        scanner = self.LLDPScanner(self.args)

        # Add test devices
        from oida.protocols.discovery.lldp import LLDPDevice

        device1 = LLDPDevice(mac_address="aa:bb:cc:dd:ee:f1", capabilities=["Bridge", "Router"])
        device2 = LLDPDevice(mac_address="aa:bb:cc:dd:ee:f2", capabilities=["Bridge"])

        scanner.discovered_devices = {device1.mac_address: device1, device2.mac_address: device2}
        scanner.packet_count = 50

        with patch("oida.protocols.discovery.lldp.mac_lookup", return_value="Cisco"):
            stats = scanner._generate_statistics()

        self.assertEqual(stats["total_devices"], 2)
        self.assertEqual(stats["total_packets"], 50)
        self.assertEqual(stats["vendor_distribution"]["Cisco"], 2)
        self.assertEqual(stats["capability_distribution"]["Bridge"], 2)
        self.assertEqual(stats["capability_distribution"]["Router"], 1)


class TestLLDPErrorHandling(unittest.TestCase):
    """Test LLDP error handling"""

    def setUp(self):
        from oida.protocols.discovery.lldp import LLDPScanner

        self.LLDPScanner = LLDPScanner
        self.args = {"interface": "eth0"}

    @patch("oida.protocols.discovery.lldp.check_raw_socket_capability")
    def test_invalid_interface(self, mock_raw_socket):
        """Test handling of invalid network interface"""
        from oida.protocols.discovery import lldp

        scanner = self.LLDPScanner(self.args)
        mock_raw_socket.return_value = (True, "")

        # Patch get_if_list in the _scapy_classes dict
        mock_get_if_list = Mock(return_value=["eth1", "lo"])
        orig = lldp._scapy_classes.get("get_if_list")
        lldp._scapy_classes["get_if_list"] = mock_get_if_list
        try:
            result = scanner.connect()
        finally:
            if orig is not None:
                lldp._scapy_classes["get_if_list"] = orig
            else:
                lldp._scapy_classes.pop("get_if_list", None)

        self.assertIsNone(result)

    def test_packet_processing_error(self):
        """Test handling of packet processing errors"""
        scanner = self.LLDPScanner(self.args)

        # Create invalid packet
        packet = Mock()
        packet.haslayer = Mock(return_value=False)

        # Should not crash
        scanner._process_lldp_packet(packet)

        # Packet count should still increment
        self.assertEqual(scanner.packet_count, 1)

    def test_tlv_processing_error(self):
        """Test handling of TLV processing errors"""
        scanner = self.LLDPScanner(self.args)
        from oida.protocols.discovery.lldp import LLDPDevice

        device = LLDPDevice(mac_address="aa:bb:cc:dd:ee:ff")

        # Create invalid TLV
        invalid_tlv = Mock()
        invalid_tlv.side_effect = Exception("TLV error")

        # Should not crash
        scanner._process_lldp_tlv(device, invalid_tlv)

        # Device should remain unchanged
        self.assertEqual(device.system_name, "")

    def test_capture_error(self):
        """Test handling of packet capture errors"""
        from oida.protocols.discovery import lldp

        scanner = self.LLDPScanner(self.args)

        # Patch AsyncSniffer in the _scapy_classes dict to raise
        mock_sniffer_class = Mock(side_effect=Exception("Permission denied"))
        orig = lldp._scapy_classes.get("AsyncSniffer")
        lldp._scapy_classes["AsyncSniffer"] = mock_sniffer_class
        try:
            results = scanner._capture_lldp_packets("eth0")
        finally:
            if orig is not None:
                lldp._scapy_classes["AsyncSniffer"] = orig
            else:
                lldp._scapy_classes.pop("AsyncSniffer", None)

        self.assertIn("error", results)
        self.assertIn("Permission denied", results["error"])


if __name__ == "__main__":
    unittest.main()
