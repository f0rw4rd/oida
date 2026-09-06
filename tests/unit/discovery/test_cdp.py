"""
Tests for CDPPassiveListener class
"""

import pytest


@pytest.fixture
def cdp_scanner_class():
    """Get CDPPassiveListener class"""
    from oida.protocols.discovery import CDPPassiveListener

    return CDPPassiveListener


def build_cdp_packet(
    src_mac: str = "aa:bb:cc:dd:ee:ff",
    device_id: str = None,
    port_id: str = None,
    platform: str = None,
    software_version: str = None,
    capabilities: int = None,
    native_vlan: int = None,
    duplex: int = None,
):
    """Build a real scapy CDP packet (Ether / CDPv2_HDR / CDPMsg*).

    Impl uses scapy's native CDP layers via ``packet[CDPMsg...]`` lookups, so
    the test fixtures must produce real scapy packets — not raw bytes.
    """
    from scapy.all import Ether
    from scapy.contrib.cdp import (
        CDPv2_HDR,
        CDPMsgDeviceID,
        CDPMsgPortID,
        CDPMsgPlatform,
        CDPMsgSoftwareVersion,
        CDPMsgCapabilities,
        CDPMsgNativeVLAN,
        CDPMsgDuplex,
    )

    cdp = CDPv2_HDR(vers=2, ttl=180)
    if device_id is not None:
        cdp /= CDPMsgDeviceID(val=device_id.encode())
    if port_id is not None:
        cdp /= CDPMsgPortID(iface=port_id.encode())
    if platform is not None:
        cdp /= CDPMsgPlatform(val=platform.encode())
    if software_version is not None:
        cdp /= CDPMsgSoftwareVersion(val=software_version.encode())
    if capabilities is not None:
        cdp /= CDPMsgCapabilities(cap=capabilities)
    if native_vlan is not None:
        cdp /= CDPMsgNativeVLAN(vlan=native_vlan)
    if duplex is not None:
        cdp /= CDPMsgDuplex(duplex=duplex)

    return Ether(src=src_mac, dst="01:00:0c:cc:cc:cc") / cdp


class TestCDPPassiveListenerInit:
    """Test CDPPassiveListener initialization"""

    def test_default_timeout_60s(self, cdp_scanner_class):
        """Test default timeout is 60 seconds"""
        scanner = cdp_scanner_class("eth0")

        assert scanner.interface == "eth0"
        assert scanner.timeout == 60
        assert scanner.discovered_devices == {}

    def test_multicast_mac_constant(self, cdp_scanner_class):
        """Test CDP multicast MAC constant"""
        scanner = cdp_scanner_class("eth0")

        assert scanner.CDP_MULTICAST_MAC == "01:00:0c:cc:cc:cc"

    def test_custom_timeout(self, cdp_scanner_class):
        """Test custom timeout"""
        scanner = cdp_scanner_class("eth0", timeout=30)

        assert scanner.timeout == 30


class TestCDPPassiveListenerScan:
    """Test CDPPassiveListener scan method"""

    def test_scapy_not_available(self, cdp_scanner_class):
        """Test handling when scapy is not installed"""
        scanner = cdp_scanner_class("eth0", timeout=1)

        from oida.protocols.discovery import network

        lazy_mod = network._scapy_all
        orig_available = lazy_mod._available
        lazy_mod._available = False
        try:
            devices = scanner.scan()
            assert devices == {}
        finally:
            lazy_mod._available = orig_available


class TestCDPFrameParsing:
    """Test CDP frame parsing through scapy's CDP layers"""

    def test_parse_cdp_header(self, cdp_scanner_class):
        """Test that a CDP packet creates a device keyed by src MAC"""
        scanner = cdp_scanner_class("eth0")

        scanner._parse_cdp_frame(build_cdp_packet(device_id="switch01"))

        assert "aa:bb:cc:dd:ee:ff" in scanner.discovered_devices

    def test_extract_device_id(self, cdp_scanner_class):
        """Test extraction of Device ID TLV"""
        scanner = cdp_scanner_class("eth0")

        scanner._parse_cdp_frame(build_cdp_packet(device_id="core-switch-01"))

        device = scanner.discovered_devices["aa:bb:cc:dd:ee:ff"]
        assert device.name == "core-switch-01"
        assert device.cdp_data["device_id"] == "core-switch-01"

    def test_extract_port_id(self, cdp_scanner_class):
        """Test extraction of Port ID TLV"""
        scanner = cdp_scanner_class("eth0")

        scanner._parse_cdp_frame(build_cdp_packet(port_id="GigabitEthernet0/1"))

        device = scanner.discovered_devices["aa:bb:cc:dd:ee:ff"]
        assert device.cdp_data["port_id"] == "GigabitEthernet0/1"

    def test_extract_platform(self, cdp_scanner_class):
        """Test extraction of Platform TLV"""
        scanner = cdp_scanner_class("eth0")

        scanner._parse_cdp_frame(build_cdp_packet(platform="Cisco Catalyst 3750"))

        device = scanner.discovered_devices["aa:bb:cc:dd:ee:ff"]
        assert device.model == "Cisco Catalyst 3750"
        assert device.cdp_data["platform"] == "Cisco Catalyst 3750"

    def test_extract_software_version(self, cdp_scanner_class):
        """Test extraction of Software Version TLV"""
        scanner = cdp_scanner_class("eth0")

        scanner._parse_cdp_frame(build_cdp_packet(software_version="Cisco IOS 15.2(4)M5"))

        device = scanner.discovered_devices["aa:bb:cc:dd:ee:ff"]
        assert device.description == "Cisco IOS 15.2(4)M5"


class TestCDPTLVParsing:
    """Test CDP TLV parsing through scapy's CDP layers"""

    def test_tlv_type_0x0001_device_id(self, cdp_scanner_class):
        """Device ID TLV (0x0001) populates cdp_data['device_id']"""
        scanner = cdp_scanner_class("eth0")

        scanner._parse_cdp_frame(build_cdp_packet(device_id="test-device"))

        device = scanner.discovered_devices["aa:bb:cc:dd:ee:ff"]
        assert device.cdp_data["device_id"] == "test-device"

    def test_tlv_type_0x000a_native_vlan(self, cdp_scanner_class):
        """Native VLAN TLV (0x000a) populates cdp_data['native_vlan']"""
        scanner = cdp_scanner_class("eth0")

        scanner._parse_cdp_frame(build_cdp_packet(device_id="sw", native_vlan=100))

        device = scanner.discovered_devices["aa:bb:cc:dd:ee:ff"]
        assert device.cdp_data["native_vlan"] == 100

    def test_tlv_type_0x000b_duplex_full(self, cdp_scanner_class):
        """Duplex TLV (0x000b) = 1 -> 'full'"""
        scanner = cdp_scanner_class("eth0")

        scanner._parse_cdp_frame(build_cdp_packet(device_id="sw", duplex=1))

        device = scanner.discovered_devices["aa:bb:cc:dd:ee:ff"]
        assert device.cdp_data["duplex"] == "full"

    def test_tlv_type_0x000b_duplex_half(self, cdp_scanner_class):
        """Duplex TLV (0x000b) = 0 -> 'half'"""
        scanner = cdp_scanner_class("eth0")

        scanner._parse_cdp_frame(build_cdp_packet(device_id="sw", duplex=0))

        device = scanner.discovered_devices["aa:bb:cc:dd:ee:ff"]
        assert device.cdp_data["duplex"] == "half"

    def test_packet_without_cdp_layer_ignored(self, cdp_scanner_class):
        """Packets without a CDPv2_HDR layer must not create a device"""
        from scapy.all import Ether

        scanner = cdp_scanner_class("eth0")
        # Plain Ethernet frame, no CDP layer attached
        scanner._parse_cdp_frame(Ether(src="aa:bb:cc:dd:ee:ff", dst="01:00:0c:cc:cc:cc"))

        assert scanner.discovered_devices == {}


class TestCDPCapabilitiesParsing:
    """Test CDP capabilities parsing"""

    def test_router_bit(self, cdp_scanner_class):
        """Test Router capability bit (0x01)"""
        scanner = cdp_scanner_class("eth0")

        result = scanner._parse_cdp_capabilities(0x01)

        assert "Router" in result

    def test_switch_bit(self, cdp_scanner_class):
        """Test Switch capability bit (0x08)"""
        scanner = cdp_scanner_class("eth0")

        result = scanner._parse_cdp_capabilities(0x08)

        assert "Switch" in result

    def test_host_bit(self, cdp_scanner_class):
        """Test Host capability bit (0x10)"""
        scanner = cdp_scanner_class("eth0")

        result = scanner._parse_cdp_capabilities(0x10)

        assert "Host" in result

    def test_multiple_capabilities(self, cdp_scanner_class):
        """Test multiple capabilities"""
        scanner = cdp_scanner_class("eth0")

        result = scanner._parse_cdp_capabilities(0x09)  # Router + Switch

        assert "Router" in result
        assert "Switch" in result

    def test_zero_capabilities(self, cdp_scanner_class):
        """Test zero capabilities"""
        scanner = cdp_scanner_class("eth0")

        result = scanner._parse_cdp_capabilities(0x00)

        assert result == "Unknown"

    def test_all_capabilities(self, cdp_scanner_class):
        """Test all capability bits"""
        scanner = cdp_scanner_class("eth0")

        result = scanner._parse_cdp_capabilities(0x7F)  # All bits

        assert "Router" in result
        assert "Trans-Bridge" in result
        assert "Source-Route-Bridge" in result
        assert "Switch" in result
        assert "Host" in result
        assert "IGMP" in result
        assert "Repeater" in result


class TestCDPDeviceCreation:
    """Test CDP device creation from parsed packets"""

    def test_device_manufacturer_set_to_cisco(self, cdp_scanner_class):
        """Test that manufacturer is set to Cisco"""
        scanner = cdp_scanner_class("eth0")

        scanner._parse_cdp_frame(build_cdp_packet(device_id="switch01"))

        device = scanner.discovered_devices["aa:bb:cc:dd:ee:ff"]
        assert device.manufacturer == "Cisco"

    def test_discovered_by_includes_cdp(self, cdp_scanner_class):
        """Test that discovered_by includes 'cdp'"""
        scanner = cdp_scanner_class("eth0")

        scanner._parse_cdp_frame(build_cdp_packet(device_id="switch01"))

        device = scanner.discovered_devices["aa:bb:cc:dd:ee:ff"]
        assert "cdp" in device.discovered_by
