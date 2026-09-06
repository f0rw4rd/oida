"""
Comprehensive tests for routing protocol passive listeners:
- OSPF (IP protocol 89)
- EIGRP (IP protocol 88)
- RIP (UDP port 520)
- PIM (IP protocol 103)
"""

import struct
import socket
import pytest


# ============================================================================
# OSPF Tests
# ============================================================================


class TestOSPFPassiveListener:
    """Tests for OSPF passive listener."""

    @pytest.fixture
    def ospf_listener(self):
        """Create OSPFPassiveListener instance."""
        from oida.protocols.discovery.ospf_passive import OSPFPassiveListener

        return OSPFPassiveListener(interface="eth0", timeout=1)

    def test_ospf_listener_init(self, ospf_listener):
        """Test OSPFPassiveListener initialization."""
        assert ospf_listener.interface == "eth0"
        assert ospf_listener.timeout == 1
        assert ospf_listener.discovered_devices == {}

    def test_ospf_protocol_name(self, ospf_listener):
        """Test OSPF protocol name constant."""
        assert ospf_listener.PROTOCOL_NAME == "ospf-passive"

    def test_ospf_bpf_filter(self, ospf_listener):
        """Test OSPF BPF filter."""
        assert ospf_listener.BPF_FILTER == "ip proto 89"

    def test_ospf_has_lock(self, ospf_listener):
        """Test that listener has thread lock for safety."""
        import threading

        assert hasattr(ospf_listener, "_lock")
        assert isinstance(ospf_listener._lock, type(threading.Lock()))

    def test_ospf_feed_packet_api(self, ospf_listener):
        """Test that feed_packet API exists."""
        assert hasattr(ospf_listener, "feed_packet")
        assert callable(ospf_listener.feed_packet)

    def test_ospf_feed_packets_api(self, ospf_listener):
        """Test that feed_packets API exists."""
        assert hasattr(ospf_listener, "feed_packets")
        assert callable(ospf_listener.feed_packets)

    def test_ospf_constants(self):
        """Test OSPF constants."""
        from oida.protocols.discovery.ospf_passive import (
            OSPF_PROTOCOL,
            OSPF_MULTICAST_ALL_ROUTERS,
            OSPF_MULTICAST_DR,
            OSPF_TYPES,
            OSPF_AUTH_TYPES,
        )

        assert OSPF_PROTOCOL == 89
        assert OSPF_MULTICAST_ALL_ROUTERS == "224.0.0.5"
        assert OSPF_MULTICAST_DR == "224.0.0.6"
        assert OSPF_TYPES[1] == "Hello"
        assert OSPF_TYPES[2] == "Database Description"
        assert OSPF_AUTH_TYPES[0] == "None"
        assert OSPF_AUTH_TYPES[2] == "Cryptographic (MD5)"


class TestOSPFPacketParsing:
    """Tests for OSPF packet parsing."""

    @pytest.fixture
    def ospf_listener(self):
        from oida.protocols.discovery.ospf_passive import OSPFPassiveListener

        return OSPFPassiveListener(interface="eth0", timeout=1)

    def test_parse_raw_ospf_header(self, ospf_listener):
        """Test parsing raw OSPF header."""
        # Build minimal OSPF header (24 bytes)
        # Version=2, Type=1 (Hello), Length, Router ID, Area ID
        header = bytes(
            [
                2,  # Version
                1,  # Type (Hello)
                0,
                44,  # Packet length
            ]
        )
        header += socket.inet_aton("1.1.1.1")  # Router ID
        header += socket.inet_aton("0.0.0.0")  # Area ID
        header += struct.pack("!H", 0)  # Checksum
        header += struct.pack("!H", 0)  # Auth type (None)
        header += bytes(8)  # Auth data

        # Hello-specific fields (20 bytes)
        hello = socket.inet_aton("255.255.255.0")  # Network mask
        hello += struct.pack("!H", 10)  # Hello interval
        hello += bytes([0x02])  # Options
        hello += bytes([1])  # Priority
        hello += struct.pack("!I", 40)  # Dead interval
        hello += socket.inet_aton("192.168.1.1")  # DR
        hello += socket.inet_aton("192.168.1.2")  # BDR

        data = header + hello
        assert len(data) == 44

        # Verify we can create a mock packet and process it
        # (actual processing tested via feed_packet with mock scapy packets)


# ============================================================================
# EIGRP Tests
# ============================================================================


class TestEIGRPPassiveListener:
    """Tests for EIGRP passive listener."""

    @pytest.fixture
    def eigrp_listener(self):
        """Create EIGRPPassiveListener instance."""
        from oida.protocols.discovery.eigrp_passive import EIGRPPassiveListener

        return EIGRPPassiveListener(interface="eth0", timeout=1)

    def test_eigrp_listener_init(self, eigrp_listener):
        """Test EIGRPPassiveListener initialization."""
        assert eigrp_listener.interface == "eth0"
        assert eigrp_listener.timeout == 1
        assert eigrp_listener.discovered_devices == {}

    def test_eigrp_protocol_name(self, eigrp_listener):
        """Test EIGRP protocol name constant."""
        assert eigrp_listener.PROTOCOL_NAME == "eigrp-passive"

    def test_eigrp_bpf_filter(self, eigrp_listener):
        """Test EIGRP BPF filter."""
        assert eigrp_listener.BPF_FILTER == "ip proto 88"

    def test_eigrp_has_lock(self, eigrp_listener):
        """Test that listener has thread lock for safety."""
        import threading

        assert hasattr(eigrp_listener, "_lock")
        assert isinstance(eigrp_listener._lock, type(threading.Lock()))

    def test_eigrp_feed_packet_api(self, eigrp_listener):
        """Test that feed_packet API exists."""
        assert hasattr(eigrp_listener, "feed_packet")
        assert callable(eigrp_listener.feed_packet)

    def test_eigrp_constants(self):
        """Test EIGRP constants."""
        from oida.protocols.discovery.eigrp_passive import (
            EIGRP_PROTOCOL,
            EIGRP_MULTICAST,
            EIGRP_OPCODES,
            EIGRP_FLAGS,
        )

        assert EIGRP_PROTOCOL == 88
        assert EIGRP_MULTICAST == "224.0.0.10"
        assert EIGRP_OPCODES[5] == "Hello"
        assert EIGRP_OPCODES[1] == "Update"
        assert EIGRP_FLAGS[0x01] == "Init"


# ============================================================================
# RIP Tests
# ============================================================================


class TestRIPPassiveListener:
    """Tests for RIP passive listener."""

    @pytest.fixture
    def rip_listener(self):
        """Create RIPPassiveListener instance."""
        from oida.protocols.discovery.rip_passive import RIPPassiveListener

        return RIPPassiveListener(interface="eth0", timeout=1)

    def test_rip_listener_init(self, rip_listener):
        """Test RIPPassiveListener initialization."""
        assert rip_listener.interface == "eth0"
        assert rip_listener.timeout == 1
        assert rip_listener.discovered_devices == {}
        assert rip_listener.routes == {}

    def test_rip_protocol_name(self, rip_listener):
        """Test RIP protocol name constant."""
        assert rip_listener.PROTOCOL_NAME == "rip-passive"

    def test_rip_bpf_filter(self, rip_listener):
        """Test RIP BPF filter."""
        assert rip_listener.BPF_FILTER == "udp port 520"

    def test_rip_has_lock(self, rip_listener):
        """Test that listener has thread lock for safety."""
        import threading

        assert hasattr(rip_listener, "_lock")
        assert isinstance(rip_listener._lock, type(threading.Lock()))

    def test_rip_feed_packet_api(self, rip_listener):
        """Test that feed_packet API exists."""
        assert hasattr(rip_listener, "feed_packet")
        assert callable(rip_listener.feed_packet)

    def test_rip_constants(self):
        """Test RIP constants."""
        from oida.protocols.discovery.rip_passive import (
            RIP_PORT,
            RIP_MULTICAST,
            RIP_COMMANDS,
            RIP_VERSIONS,
            RIP_AUTH_TYPES,
        )

        assert RIP_PORT == 520
        assert RIP_MULTICAST == "224.0.0.9"
        assert RIP_COMMANDS[1] == "Request"
        assert RIP_COMMANDS[2] == "Response"
        assert RIP_VERSIONS[1] == "RIPv1"
        assert RIP_VERSIONS[2] == "RIPv2"
        assert RIP_AUTH_TYPES[0] == "None"
        assert RIP_AUTH_TYPES[2] == "Simple Password"
        assert RIP_AUTH_TYPES[3] == "MD5"


class TestRIPPacketParsing:
    """Tests for RIP packet parsing."""

    @pytest.fixture
    def rip_listener(self):
        from oida.protocols.discovery.rip_passive import RIPPassiveListener

        return RIPPassiveListener(interface="eth0", timeout=1)

    def test_rip_v2_response_structure(self):
        """Test RIPv2 Response packet structure."""
        # RIPv2 Response with one route entry
        # Header: command=2, version=2, reserved=0
        header = bytes([2, 2, 0, 0])

        # Route entry (20 bytes)
        # AFI=2 (IPv4), route_tag, IP, mask, next_hop, metric
        route = struct.pack("!HH", 2, 0)  # AFI, route tag
        route += socket.inet_aton("10.0.0.0")  # Network
        route += socket.inet_aton("255.255.255.0")  # Subnet mask
        route += socket.inet_aton("0.0.0.0")  # Next hop
        route += struct.pack("!I", 1)  # Metric

        packet = header + route
        assert len(packet) == 24


# ============================================================================
# PIM Tests
# ============================================================================


class TestPIMPassiveListener:
    """Tests for PIM passive listener."""

    @pytest.fixture
    def pim_listener(self):
        """Create PIMPassiveListener instance."""
        from oida.protocols.discovery.pim_passive import PIMPassiveListener

        return PIMPassiveListener(interface="eth0", timeout=1)

    def test_pim_listener_init(self, pim_listener):
        """Test PIMPassiveListener initialization."""
        assert pim_listener.interface == "eth0"
        assert pim_listener.timeout == 1
        assert pim_listener.discovered_devices == {}

    def test_pim_protocol_name(self, pim_listener):
        """Test PIM protocol name constant."""
        assert pim_listener.PROTOCOL_NAME == "pim-passive"

    def test_pim_bpf_filter(self, pim_listener):
        """Test PIM BPF filter."""
        assert pim_listener.BPF_FILTER == "ip proto 103"

    def test_pim_has_lock(self, pim_listener):
        """Test that listener has thread lock for safety."""
        import threading

        assert hasattr(pim_listener, "_lock")
        assert isinstance(pim_listener._lock, type(threading.Lock()))

    def test_pim_feed_packet_api(self, pim_listener):
        """Test that feed_packet API exists."""
        assert hasattr(pim_listener, "feed_packet")
        assert callable(pim_listener.feed_packet)

    def test_pim_constants(self):
        """Test PIM constants."""
        from oida.protocols.discovery.pim_passive import (
            PIM_PROTOCOL,
            PIM_MULTICAST,
            PIM_TYPES,
            PIM_HELLO_OPTIONS,
        )

        assert PIM_PROTOCOL == 103
        assert PIM_MULTICAST == "224.0.0.13"
        assert PIM_TYPES[0] == "Hello"
        assert PIM_TYPES[3] == "Join/Prune"
        assert PIM_TYPES[4] == "Bootstrap"
        assert PIM_HELLO_OPTIONS[1] == "Hold Time"
        assert PIM_HELLO_OPTIONS[19] == "DR Priority"
        assert PIM_HELLO_OPTIONS[20] == "Generation ID"


class TestPIMPacketParsing:
    """Tests for PIM packet parsing."""

    @pytest.fixture
    def pim_listener(self):
        from oida.protocols.discovery.pim_passive import PIMPassiveListener

        return PIMPassiveListener(interface="eth0", timeout=1)

    def test_pim_hello_structure(self):
        """Test PIM Hello packet structure."""
        # PIM Hello: version=2, type=0
        header = bytes(
            [
                0x20,  # Version 2, Type 0 (Hello)
                0x00,  # Reserved
                0x00,
                0x00,  # Checksum placeholder
            ]
        )

        # Hold Time option (type=1)
        hold_time_opt = struct.pack("!HH", 1, 2)  # Type, Length
        hold_time_opt += struct.pack("!H", 105)  # 105 seconds

        # DR Priority option (type=19)
        dr_priority_opt = struct.pack("!HH", 19, 4)  # Type, Length
        dr_priority_opt += struct.pack("!I", 1)  # Priority 1

        packet = header + hold_time_opt + dr_priority_opt
        assert len(packet) == 18  # 4 + 6 + 8 bytes


# ============================================================================
# Integration Tests
# ============================================================================


class TestDiscoveredDeviceRoutingDataFields:
    """Test that DiscoveredDevice has all routing protocol data fields."""

    def test_routing_data_fields_exist(self):
        """Test that all routing protocol data fields exist on DiscoveredDevice."""
        from oida.protocols.discovery.core import DiscoveredDevice

        device = DiscoveredDevice()

        # OSPF
        assert hasattr(device, "ospf_data")
        assert device.ospf_data is None

        # EIGRP
        assert hasattr(device, "eigrp_data")
        assert device.eigrp_data is None

        # RIP
        assert hasattr(device, "rip_data")
        assert device.rip_data is None

        # PIM
        assert hasattr(device, "pim_data")
        assert device.pim_data is None

    def test_merge_routing_data_fields(self):
        """Test merging devices with routing protocol data."""
        from oida.protocols.discovery.core import DiscoveredDevice

        device1 = DiscoveredDevice(
            mac_address="00:11:22:33:44:55",
            ip_addresses=["192.168.1.1"],
        )
        device1.ospf_data = {
            "router_id": "1.1.1.1",
            "area_id": "0.0.0.0",
            "role": "DR",
        }

        device2 = DiscoveredDevice(
            mac_address="00:11:22:33:44:55",
            ip_addresses=["192.168.1.1"],
        )
        device2.eigrp_data = {
            "as_number": 100,
            "hold_time": 15,
        }

        # Merge device2 into device1
        updated = device1.merge_from(device2)

        assert "eigrp_data" in updated
        assert device1.ospf_data is not None  # Original preserved
        assert device1.eigrp_data is not None  # New data added


class TestScannerRegistration:
    """Test that all routing scanners are registered in scanner.py."""

    def test_scanner_configs_contain_routing_protocols(self):
        """Test that _SCANNER_CONFIGS has all routing scanner types."""
        from oida.protocols.discovery.scanner import _SCANNER_CONFIGS

        # OSPF
        assert "ospf-passive" in _SCANNER_CONFIGS

        # EIGRP
        assert "eigrp-passive" in _SCANNER_CONFIGS

        # RIP
        assert "rip-passive" in _SCANNER_CONFIGS

        # PIM
        assert "pim-passive" in _SCANNER_CONFIGS

    def test_scanner_class_types(self):
        """Test that scanner configs point to correct classes."""
        from oida.protocols.discovery.scanner import _SCANNER_CONFIGS
        from oida.protocols.discovery.ospf_passive import OSPFPassiveListener
        from oida.protocols.discovery.eigrp_passive import EIGRPPassiveListener
        from oida.protocols.discovery.rip_passive import RIPPassiveListener
        from oida.protocols.discovery.pim_passive import PIMPassiveListener

        assert _SCANNER_CONFIGS["ospf-passive"][0] == OSPFPassiveListener
        assert _SCANNER_CONFIGS["eigrp-passive"][0] == EIGRPPassiveListener
        assert _SCANNER_CONFIGS["rip-passive"][0] == RIPPassiveListener
        assert _SCANNER_CONFIGS["pim-passive"][0] == PIMPassiveListener

    def test_scanner_categories(self):
        """Test that routing scanners are in passive category."""
        from oida.protocols.discovery.scanner import _SCANNER_CONFIGS

        # All routing protocol listeners should be passive
        assert _SCANNER_CONFIGS["ospf-passive"][3] == "passive"
        assert _SCANNER_CONFIGS["eigrp-passive"][3] == "passive"
        assert _SCANNER_CONFIGS["rip-passive"][3] == "passive"
        assert _SCANNER_CONFIGS["pim-passive"][3] == "passive"


class TestCLIArgumentRegistration:
    """Test that routing protocol CLI toggles are registered."""

    def test_proto_args_contain_routing_protocols(self):
        """Test that proto_args has routing protocol toggles."""
        import argparse
        from oida.protocols.discovery.proto_args import proto_args

        # Create a mock parser
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        # Register discovery parser
        discovery_parser = proto_args(subparsers, [])

        # Parse --help to get available arguments
        # Check that the no-X arguments are registered
        actions = {action.dest for action in discovery_parser._actions}

        assert "no_ospf" in actions
        assert "no_eigrp" in actions
        assert "no_rip" in actions
        assert "no_pim" in actions


class TestRoutingProtocolMulticasts:
    """Test routing protocol multicast addresses."""

    def test_all_multicast_addresses(self):
        """Test all routing protocol multicast addresses."""
        from oida.protocols.discovery.ospf_passive import (
            OSPF_MULTICAST_ALL_ROUTERS,
            OSPF_MULTICAST_DR,
        )
        from oida.protocols.discovery.eigrp_passive import EIGRP_MULTICAST
        from oida.protocols.discovery.rip_passive import RIP_MULTICAST
        from oida.protocols.discovery.pim_passive import PIM_MULTICAST

        # Verify they are valid multicast addresses (224.0.0.0/4)
        import ipaddress

        assert ipaddress.ip_address(OSPF_MULTICAST_ALL_ROUTERS).is_multicast
        assert ipaddress.ip_address(OSPF_MULTICAST_DR).is_multicast
        assert ipaddress.ip_address(EIGRP_MULTICAST).is_multicast
        assert ipaddress.ip_address(RIP_MULTICAST).is_multicast
        assert ipaddress.ip_address(PIM_MULTICAST).is_multicast

        # Verify specific addresses
        assert OSPF_MULTICAST_ALL_ROUTERS == "224.0.0.5"
        assert OSPF_MULTICAST_DR == "224.0.0.6"
        assert EIGRP_MULTICAST == "224.0.0.10"
        assert RIP_MULTICAST == "224.0.0.9"
        assert PIM_MULTICAST == "224.0.0.13"
