"""
Tests for discovery module helper functions
"""

import pytest
from unittest.mock import patch


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
        """Test that valid interface returns CIDR notation.

        The autouse ``mock_netifaces`` conftest fixture patches
        ``oida.utils.iface_info`` so "eth0" resolves to 192.168.1.100/24.
        """
        from oida.protocols.discovery import get_interface_network

        result = get_interface_network("eth0")
        assert result is not None
        assert result.endswith("/24")

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
