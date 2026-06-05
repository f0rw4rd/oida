"""
Comprehensive tests for new discovery protocols:
- FINS/Omron (UDP 9600)
- HSRP (UDP 1985)
- IGMP (IP protocol 2)
- DHCPv6 (UDP 546/547)
- DHCP (UDP 67/68)
"""

import struct
import socket
import pytest


# ============================================================================
# FINS/Omron Tests
# ============================================================================


class TestFINSScanner:
    """Tests for FINS/Omron UDP discovery."""

    @pytest.fixture
    def fins_scanner(self):
        """Create FINSScanner instance."""
        from oida.protocols.discovery.fins import FINSScanner

        return FINSScanner(interface="eth0", subnet="192.168.1.0/24", timeout=1.0)

    @pytest.fixture
    def fins_passive(self):
        """Create FINSPassiveListener instance."""
        from oida.protocols.discovery.fins import FINSPassiveListener

        return FINSPassiveListener(interface="eth0", timeout=1)

    def test_fins_scanner_init(self, fins_scanner):
        """Test FINSScanner initialization."""
        assert fins_scanner.interface == "eth0"
        assert fins_scanner.subnet == "192.168.1.0/24"
        assert fins_scanner.timeout == 1.0
        assert fins_scanner.discovered_devices == {}

    def test_fins_passive_init(self, fins_passive):
        """Test FINSPassiveListener initialization."""
        assert fins_passive.interface == "eth0"
        assert fins_passive.timeout == 1
        assert fins_passive.discovered_devices == {}

    def test_fins_build_request(self, fins_scanner):
        """Test FINS request packet building."""
        packet = fins_scanner._build_fins_request()

        # Should be 12 bytes: 10 byte header + 2 byte command
        assert len(packet) == 12

        # Check header values
        icf = packet[0]
        assert icf == 0x80  # Command, need response

        da1 = packet[4]
        assert da1 == 0xFF  # Broadcast

        # Check command code (0x05, 0x01 = Controller Data Read)
        assert packet[10] == 0x05
        assert packet[11] == 0x01

    def test_fins_process_response_valid(self, fins_scanner):
        """Test processing valid FINS response."""
        # Build mock response
        # 10 byte header + 2 byte command + 2 byte response code + 20 byte model
        header = bytes(
            [
                0xC0,  # ICF - bit 7 (command/response) + bit 6 (response flag) = 0xC0
                0x00,  # RSV
                0x02,  # GCT
                0x00,  # DNA
                0x01,  # DA1 - source node
                0x00,  # DA2
                0x00,  # SNA
                0x05,  # SA1 - responder's node
                0x00,  # SA2
                0x01,  # SID
            ]
        )
        command = struct.pack(">HH", 0x05, 0x01)
        response_code = struct.pack(">BB", 0x00, 0x00)  # Success
        model = b"CJ2M-CPU31".ljust(20, b"\x00")

        data = header + command + response_code + model
        addr = ("192.168.1.100", 9600)

        fins_scanner._process_response(data, addr)

        assert len(fins_scanner.discovered_devices) == 1
        device = list(fins_scanner.discovered_devices.values())[0]
        assert "192.168.1.100" in device.ip_addresses
        assert device.manufacturer == "Omron"
        assert device.device_type == "PLC"
        assert "fins" in device.discovered_by

    def test_fins_process_response_short_packet(self, fins_scanner):
        """Test handling short FINS packet."""
        data = bytes([0x80, 0x00, 0x02])  # Too short
        addr = ("192.168.1.100", 9600)

        fins_scanner._process_response(data, addr)
        assert len(fins_scanner.discovered_devices) == 0

    def test_fins_process_response_error_code(self, fins_scanner):
        """Test handling FINS error response - device still recorded."""
        header = bytes(
            [0xC0, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01]
        )  # ICF=0xC0 for response
        command = struct.pack(">HH", 0x05, 0x01)
        response_code = struct.pack(">BB", 0x01, 0x00)  # Error

        data = header + command + response_code
        addr = ("192.168.1.100", 9600)

        fins_scanner._process_response(data, addr)

        # Device should still be recorded even with error
        assert len(fins_scanner.discovered_devices) == 1


class TestFINSPassiveListener:
    """Tests for FINS passive traffic listener."""

    @pytest.fixture
    def listener(self):
        from oida.protocols.discovery.fins import FINSPassiveListener

        return FINSPassiveListener(interface="eth0", timeout=1)

    def test_listener_initialization(self, listener):
        """Test that FINSPassiveListener initializes correctly."""
        assert listener.interface == "eth0"
        assert listener.timeout == 1
        assert listener.discovered_devices == {}

    def test_listener_has_lock(self, listener):
        """Test that listener has thread lock for safety."""
        import threading

        assert hasattr(listener, "_lock")
        assert isinstance(listener._lock, type(threading.Lock()))


# ============================================================================
# HSRP Tests
# ============================================================================


class TestHSRPPassiveListener:
    """Tests for HSRP passive listener."""

    @pytest.fixture
    def hsrp_listener(self):
        """Create HSRPPassiveListener instance."""
        from oida.protocols.discovery.hsrp import HSRPPassiveListener

        return HSRPPassiveListener(interface="eth0", timeout=1)

    def test_hsrp_listener_init(self, hsrp_listener):
        """Test HSRPPassiveListener initialization."""
        assert hsrp_listener.interface == "eth0"
        assert hsrp_listener.timeout == 1
        assert hsrp_listener.discovered_devices == {}

    def test_hsrp_parse_hello(self, hsrp_listener):
        """Test parsing HSRPv1 Hello packet."""
        # HSRPv1 Hello packet (20 bytes)
        # Version=0, Opcode=0 (Hello), State=16 (Active)
        # Hellotime=3, Holdtime=10, Priority=100, Group=1
        # Auth="cisco\x00\x00\x00", Virtual IP=192.168.1.1
        packet = bytes(
            [
                0x00,  # Version (0 = v1)
                0x00,  # Opcode (0 = Hello)
                0x10,  # State (16 = Active)
                0x03,  # Hellotime
                0x0A,  # Holdtime
                0x64,  # Priority (100)
                0x01,  # Group
                0x00,  # Reserved
            ]
        )
        auth = b"cisco\x00\x00\x00"
        vip = socket.inet_aton("192.168.1.1")
        packet = packet + auth + vip

        result = hsrp_listener._parse_hsrp_v1_raw(packet)

        assert result is not None
        assert result["version"] == 1
        assert result["opcode_name"] == "Hello"
        assert result["state_name"] == "Active"
        assert result["priority"] == 100
        assert result["group"] == 1
        assert result["virtual_ip"] == "192.168.1.1"
        assert result["auth_data"] == "cisco"

    def test_hsrp_parse_standby_state(self, hsrp_listener):
        """Test parsing HSRP Standby state."""
        packet = bytes(
            [
                0x00,  # Version
                0x00,  # Opcode (Hello)
                0x08,  # State (8 = Standby)
                0x03,
                0x0A,
                0x50,
                0x02,
                0x00,  # Times, priority, group
            ]
        )
        auth = b"cisco\x00\x00\x00"
        vip = socket.inet_aton("10.0.0.1")
        packet = packet + auth + vip

        result = hsrp_listener._parse_hsrp_v1_raw(packet)

        assert result["state_name"] == "Standby"
        assert result["priority"] == 80
        assert result["virtual_ip"] == "10.0.0.1"

    def test_hsrp_parse_coup_message(self, hsrp_listener):
        """Test parsing HSRP Coup message."""
        packet = bytes(
            [
                0x00,  # Version
                0x01,  # Opcode (1 = Coup)
                0x10,  # State
                0x03,
                0x0A,
                0xC8,
                0x01,
                0x00,  # Priority 200
            ]
        )
        auth = b"cisco\x00\x00\x00"
        vip = socket.inet_aton("172.16.0.1")
        packet = packet + auth + vip

        result = hsrp_listener._parse_hsrp_v1_raw(packet)

        assert result["opcode_name"] == "Coup"
        assert result["priority"] == 200

    def test_hsrp_parse_short_packet(self, hsrp_listener):
        """Test handling short HSRP packet."""
        packet = bytes([0x00, 0x00, 0x10])  # Too short
        result = hsrp_listener._parse_hsrp_v1_raw(packet)
        assert result is None

    def test_hsrp_states_mapping(self):
        """Test HSRP state values."""
        from oida.protocols.discovery.hsrp import HSRP_V1_STATES

        assert HSRP_V1_STATES[0] == "Initial"
        assert HSRP_V1_STATES[1] == "Learn"
        assert HSRP_V1_STATES[2] == "Listen"
        assert HSRP_V1_STATES[4] == "Speak"
        assert HSRP_V1_STATES[8] == "Standby"
        assert HSRP_V1_STATES[16] == "Active"


# ============================================================================
# IGMP Tests
# ============================================================================


class TestIGMPPassiveListener:
    """Tests for IGMP passive listener."""

    @pytest.fixture
    def igmp_listener(self):
        """Create IGMPPassiveListener instance."""
        from oida.protocols.discovery.igmp import IGMPPassiveListener

        return IGMPPassiveListener(interface="eth0", timeout=1)

    def test_igmp_listener_init(self, igmp_listener):
        """Test IGMPPassiveListener initialization."""
        assert igmp_listener.interface == "eth0"
        assert igmp_listener.timeout == 1
        assert igmp_listener.discovered_devices == {}
        assert igmp_listener.multicast_memberships == {}

    def test_igmp_parse_v2_report(self, igmp_listener):
        """Test parsing IGMPv2 Membership Report."""
        # IGMPv2 Membership Report
        # Type=0x16, Max Response=0, Checksum, Group=224.0.0.251 (mDNS)
        group_ip = socket.inet_aton("224.0.0.251")
        packet = bytes([0x16, 0x00, 0x00, 0x00]) + group_ip

        result = igmp_listener._parse_igmp_raw(packet)

        assert result is not None
        assert result["type_name"] == "Report"
        assert result["version"] == 2
        assert result["group_address"] == "224.0.0.251"
        assert result["group_name"] == "mDNS"

    def test_igmp_parse_v1_report(self, igmp_listener):
        """Test parsing IGMPv1 Membership Report."""
        group_ip = socket.inet_aton("224.0.0.1")
        packet = bytes([0x12, 0x00, 0x00, 0x00]) + group_ip

        result = igmp_listener._parse_igmp_raw(packet)

        assert result["type_name"] == "Report"
        assert result["version"] == 1
        assert result["group_address"] == "224.0.0.1"

    def test_igmp_parse_query(self, igmp_listener):
        """Test parsing IGMP General Query."""
        # General query has 0.0.0.0 as group
        group_ip = socket.inet_aton("0.0.0.0")
        packet = bytes([0x11, 0x64, 0x00, 0x00]) + group_ip  # Max resp = 100

        result = igmp_listener._parse_igmp_raw(packet)

        assert result["type_name"] == "Query"
        assert result["version"] == 2
        assert result["max_response_time"] == 100

    def test_igmp_parse_v2_leave(self, igmp_listener):
        """Test parsing IGMPv2 Leave Group."""
        group_ip = socket.inet_aton("239.255.255.250")  # SSDP
        packet = bytes([0x17, 0x00, 0x00, 0x00]) + group_ip

        result = igmp_listener._parse_igmp_raw(packet)

        assert result["type_name"] == "Leave"
        assert result["version"] == 2
        assert result["group_address"] == "239.255.255.250"

    def test_igmp_parse_v3_report(self, igmp_listener):
        """Test parsing IGMPv3 Membership Report."""
        # IGMPv3 report: type=0x22, reserved, checksum, reserved, num groups
        packet = bytes([0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])

        result = igmp_listener._parse_igmp_raw(packet, dst_ip="224.0.0.22")

        assert result["type_name"] == "Report"
        assert result["version"] == 3

    def test_igmp_parse_short_packet(self, igmp_listener):
        """Test handling short IGMP packet."""
        packet = bytes([0x16, 0x00])  # Too short
        result = igmp_listener._parse_igmp_raw(packet)
        assert result is None

    def test_igmp_ics_multicast_groups(self):
        """Test ICS multicast group detection."""
        from oida.protocols.discovery.igmp import ICS_MULTICAST_GROUPS

        assert "224.0.0.120" in ICS_MULTICAST_GROUPS  # BACnet
        assert ICS_MULTICAST_GROUPS["224.0.0.120"] == "BACnet/IP"


class TestIGMPQueryScanner:
    """Tests for IGMP active query scanner."""

    @pytest.fixture
    def igmp_scanner(self):
        """Create IGMPQueryScanner instance."""
        from oida.protocols.discovery.igmp import IGMPQueryScanner

        return IGMPQueryScanner(interface="eth0", timeout=1.0)

    def test_igmp_scanner_init(self, igmp_scanner):
        """Test IGMPQueryScanner initialization."""
        assert igmp_scanner.interface == "eth0"
        assert igmp_scanner.timeout == 1.0
        assert igmp_scanner.discovered_devices == {}

# ============================================================================
# DHCPv6 Tests
# ============================================================================


class TestDHCPv6PassiveListener:
    """Tests for DHCPv6 passive listener."""

    @pytest.fixture
    def dhcpv6_listener(self):
        """Create DHCPv6PassiveListener instance."""
        from oida.protocols.discovery.dhcpv6 import DHCPv6PassiveListener

        return DHCPv6PassiveListener(interface="eth0", timeout=1)

    def test_dhcpv6_listener_init(self, dhcpv6_listener):
        """Test DHCPv6PassiveListener initialization."""
        assert dhcpv6_listener.interface == "eth0"
        assert dhcpv6_listener.timeout == 1
        assert dhcpv6_listener.discovered_devices == {}
        assert dhcpv6_listener.dhcpv6_servers == {}

    def test_dhcpv6_message_types(self):
        """Test DHCPv6 message type mapping."""
        from oida.protocols.discovery.dhcpv6 import DHCPV6_MSG_TYPES

        assert DHCPV6_MSG_TYPES[1] == "Solicit"
        assert DHCPV6_MSG_TYPES[2] == "Advertise"
        assert DHCPV6_MSG_TYPES[3] == "Request"
        assert DHCPV6_MSG_TYPES[7] == "Reply"
        assert DHCPV6_MSG_TYPES[11] == "Information-Request"


class TestDHCPv6ServerScanner:
    """Tests for DHCPv6 server scanner."""

    @pytest.fixture
    def dhcpv6_scanner(self):
        """Create DHCPv6ServerScanner instance."""
        from oida.protocols.discovery.dhcpv6 import DHCPv6ServerScanner

        return DHCPv6ServerScanner(interface="eth0", timeout=1.0)

    def test_dhcpv6_scanner_init(self, dhcpv6_scanner):
        """Test DHCPv6ServerScanner initialization."""
        assert dhcpv6_scanner.interface == "eth0"
        assert dhcpv6_scanner.timeout == 1.0
        assert dhcpv6_scanner.discovered_devices == {}

# ============================================================================
# DHCP Tests
# ============================================================================


class TestDHCPPassiveListener:
    """Tests for DHCP passive listener."""

    @pytest.fixture
    def dhcp_listener(self):
        """Create DHCPPassiveListener instance."""
        from oida.protocols.discovery.dhcp import DHCPPassiveListener

        return DHCPPassiveListener(interface="eth0", timeout=1)

    def test_dhcp_listener_init(self, dhcp_listener):
        """Test DHCPPassiveListener initialization."""
        assert dhcp_listener.interface == "eth0"
        assert dhcp_listener.timeout == 1
        assert dhcp_listener.discovered_devices == {}
        assert dhcp_listener.dhcp_servers == {}

    def test_dhcp_options_parsing(self, dhcp_listener):
        """Test DHCP options parsing (scapy tuple format)."""
        # Scapy returns options as list of (name, value) tuples
        options = [
            ("hostname", b"testhost"),
            ("message-type", 3),
            ("requested_addr", "192.168.1.100"),
            "end",
        ]

        result = dhcp_listener._parse_dhcp_options(options)

        assert result.get("hostname") == b"testhost"
        assert result.get("message-type") == 3
        assert result.get("requested_addr") == "192.168.1.100"

    def test_dhcp_vendor_class_parsing(self, dhcp_listener):
        """Test DHCP vendor class parsing."""
        options = [("vendor_class_id", b"Siemens"), "end"]

        result = dhcp_listener._parse_dhcp_options(options)

        assert result.get("vendor_class_id") == b"Siemens"

    def test_dhcp_server_id_parsing(self, dhcp_listener):
        """Test DHCP server ID parsing."""
        options = [("server_id", "10.0.0.1"), "end"]

        result = dhcp_listener._parse_dhcp_options(options)

        assert result.get("server_id") == "10.0.0.1"

    def test_dhcp_param_list_parsing(self, dhcp_listener):
        """Test DHCP parameter request list parsing."""
        options = [("param_req_list", [1, 3, 6, 15, 26, 28, 51, 58, 59]), "end"]

        result = dhcp_listener._parse_dhcp_options(options)

        assert result.get("param_req_list") == [1, 3, 6, 15, 26, 28, 51, 58, 59]


class TestDHCPServerScanner:
    """Tests for DHCP server scanner."""

    @pytest.fixture
    def dhcp_scanner(self):
        """Create DHCPServerScanner instance."""
        from oida.protocols.discovery.dhcp import DHCPServerScanner

        return DHCPServerScanner(interface="eth0", timeout=1.0)

    def test_dhcp_scanner_init(self, dhcp_scanner):
        """Test DHCPServerScanner initialization."""
        assert dhcp_scanner.interface == "eth0"
        assert dhcp_scanner.timeout == 1.0
        assert dhcp_scanner.servers == {}

    def test_scanner_has_xid(self, dhcp_scanner):
        """Test that DHCPServerScanner has transaction ID."""
        # The scanner generates a random transaction ID
        assert hasattr(dhcp_scanner, "_xid")
        assert dhcp_scanner._xid > 0
        assert dhcp_scanner._xid <= 0xFFFFFFFF


# ============================================================================
# Integration Tests
# ============================================================================


class TestDiscoveredDeviceDataFields:
    """Test that DiscoveredDevice has all new protocol data fields."""

    def test_new_data_fields_exist(self):
        """Test that all new protocol data fields exist on DiscoveredDevice."""
        from oida.protocols.discovery.core import DiscoveredDevice

        device = DiscoveredDevice()

        # FINS
        assert hasattr(device, "fins_data")
        assert device.fins_data is None

        # HSRP
        assert hasattr(device, "hsrp_data")
        assert device.hsrp_data is None

        # IGMP
        assert hasattr(device, "igmp_data")
        assert device.igmp_data is None

        # DHCPv6
        assert hasattr(device, "dhcpv6_data")
        assert device.dhcpv6_data is None

        # DHCP (v4)
        assert hasattr(device, "dhcp_data")
        assert device.dhcp_data is None

    def test_merge_new_data_fields(self):
        """Test merging devices with new protocol data."""
        from oida.protocols.discovery.core import DiscoveredDevice

        device1 = DiscoveredDevice(
            mac_address="00:11:22:33:44:55",
            ip_addresses=["192.168.1.100"],
        )
        device1.fins_data = {"node_address": 1, "model": "CJ2M"}

        device2 = DiscoveredDevice(
            mac_address="00:11:22:33:44:55",
            ip_addresses=["192.168.1.100"],
        )
        device2.hsrp_data = {"group": 1, "state": "Active"}

        # Merge device2 into device1
        updated = device1.merge_from(device2)

        assert "hsrp_data" in updated
        assert device1.fins_data is not None  # Original preserved
        assert device1.hsrp_data is not None  # New data added


class TestScannerRegistration:
    """Test that all new scanners are registered in scanner.py."""

    def test_scanner_configs_contain_new_protocols(self):
        """Test that _SCANNER_CONFIGS has all new scanner types."""
        from oida.protocols.discovery.scanner import _SCANNER_CONFIGS

        # FINS
        assert "fins" in _SCANNER_CONFIGS
        assert "fins-passive" in _SCANNER_CONFIGS

        # HSRP
        assert "hsrp-passive" in _SCANNER_CONFIGS

        # IGMP
        assert "igmp-passive" in _SCANNER_CONFIGS

        # DHCPv6
        assert "dhcpv6-passive" in _SCANNER_CONFIGS
        assert "dhcpv6-servers" in _SCANNER_CONFIGS

        # DHCP (v4)
        assert "dhcp-passive" in _SCANNER_CONFIGS
        assert "dhcp-servers" in _SCANNER_CONFIGS

    def test_scanner_class_types(self):
        """Test that scanner configs point to correct classes."""
        from oida.protocols.discovery.scanner import _SCANNER_CONFIGS
        from oida.protocols.discovery.fins import FINSScanner, FINSPassiveListener
        from oida.protocols.discovery.hsrp import HSRPPassiveListener
        from oida.protocols.discovery.igmp import IGMPPassiveListener
        from oida.protocols.discovery.dhcpv6 import DHCPv6PassiveListener, DHCPv6ServerScanner
        from oida.protocols.discovery.dhcp import DHCPPassiveListener, DHCPServerScanner

        assert _SCANNER_CONFIGS["fins"][0] == FINSScanner
        assert _SCANNER_CONFIGS["fins-passive"][0] == FINSPassiveListener
        assert _SCANNER_CONFIGS["hsrp-passive"][0] == HSRPPassiveListener
        assert _SCANNER_CONFIGS["igmp-passive"][0] == IGMPPassiveListener
        assert _SCANNER_CONFIGS["dhcpv6-passive"][0] == DHCPv6PassiveListener
        assert _SCANNER_CONFIGS["dhcpv6-servers"][0] == DHCPv6ServerScanner
        assert _SCANNER_CONFIGS["dhcp-passive"][0] == DHCPPassiveListener
        assert _SCANNER_CONFIGS["dhcp-servers"][0] == DHCPServerScanner


class TestModuleExports:
    """Test that new scanners are exported from __init__.py."""

    def test_exports(self):
        """Test that all new classes are exported."""
        from oida.protocols.discovery import (
            FINSScanner,
            FINSPassiveListener,
            HSRPPassiveListener,
            IGMPPassiveListener,
            DHCPv6PassiveListener,
            DHCPv6ServerScanner,
            DHCPPassiveListener,
            DHCPServerScanner,
        )

        # If we got here without ImportError, all exports work
        assert FINSScanner is not None
        assert FINSPassiveListener is not None
        assert HSRPPassiveListener is not None
        assert IGMPPassiveListener is not None
        assert DHCPv6PassiveListener is not None
        assert DHCPv6ServerScanner is not None
        assert DHCPPassiveListener is not None
        assert DHCPServerScanner is not None


# ============================================================================
# Protocol Constants Tests
# ============================================================================


class TestProtocolConstants:
    """Test protocol constants are correctly defined."""

    def test_fins_constants(self):
        """Test FINS protocol constants."""
        from oida.protocols.discovery.fins import FINS_UDP_PORT

        assert FINS_UDP_PORT == 9600

    def test_hsrp_constants(self):
        """Test HSRP protocol constants."""
        from oida.protocols.discovery.hsrp import (
            HSRP_PORT,
            HSRP_V1_MULTICAST,
            HSRP_OPCODES,
        )

        assert HSRP_PORT == 1985
        assert HSRP_V1_MULTICAST == "224.0.0.2"
        assert HSRP_OPCODES[0] == "Hello"

    def test_igmp_constants(self):
        """Test IGMP protocol constants."""
        from oida.protocols.discovery.igmp import (
            IGMP_PROTOCOL,
            IGMP_MEMBERSHIP_QUERY,
            IGMP_V2_MEMBERSHIP_REPORT,
        )

        assert IGMP_PROTOCOL == 2
        assert IGMP_MEMBERSHIP_QUERY == 0x11
        assert IGMP_V2_MEMBERSHIP_REPORT == 0x16

    def test_dhcpv6_constants(self):
        """Test DHCPv6 protocol constants."""
        from oida.protocols.discovery.dhcpv6 import (
            DHCPV6_CLIENT_PORT,
            DHCPV6_SERVER_PORT,
            DHCPV6_MULTICAST_ADDR,
        )

        assert DHCPV6_CLIENT_PORT == 546
        assert DHCPV6_SERVER_PORT == 547
        assert DHCPV6_MULTICAST_ADDR == "ff02::1:2"

    def test_dhcp_constants(self):
        """Test DHCP protocol constants."""
        from oida.protocols.discovery.dhcp import (
            DHCP_CLIENT_PORT,
            DHCP_SERVER_PORT,
        )

        assert DHCP_CLIENT_PORT == 68
        assert DHCP_SERVER_PORT == 67
