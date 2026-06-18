"""
Shared pytest fixtures for OIDA testing.

This module provides common fixtures used across all test modules.
"""

import pytest
from pathlib import Path

# Check for scapy availability at module level
try:
    from scapy.all import rdpcap

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    rdpcap = None


# PCAP fixtures directory
PCAP_FIXTURES = Path(__file__).parent / "fixtures" / "pcap"


@pytest.fixture(scope="session")
def pcap_dir():
    """Path to PCAP test fixtures directory."""
    return PCAP_FIXTURES


@pytest.fixture
def load_pcap():
    """Factory fixture to load PCAP files.

    Usage:
        def test_something(load_pcap):
            packets = load_pcap("hsrp/filtered_hsrp.pcap")
    """
    if not SCAPY_AVAILABLE:
        pytest.skip("scapy not available")

    def _load(filename: str):
        path = PCAP_FIXTURES / filename
        if not path.exists():
            pytest.fail(f"PCAP fixture not found: {filename}")
        return rdpcap(str(path))

    return _load


# Protocol-specific PCAP fixtures


@pytest.fixture
def hsrp_packets(load_pcap):
    """Load HSRP test packets."""
    return load_pcap("hsrp/filtered_hsrp.pcap")


@pytest.fixture
def dhcp_packets(load_pcap):
    """Load DHCP test packets."""
    return load_pcap("dhcp/filtered_dhcp.pcap")


@pytest.fixture
def dhcpv6_packets(load_pcap):
    """Load DHCPv6 test packets."""
    return load_pcap("dhcpv6/filtered_dhcpv6.pcap")


@pytest.fixture
def igmp_packets(load_pcap):
    """Load IGMP test packets."""
    return load_pcap("igmp/filtered_igmp.pcap")


@pytest.fixture
def arp_packets(load_pcap):
    """Load ARP test packets."""
    return load_pcap("arp/filtered_arp.pcap")


@pytest.fixture
def ssdp_packets(load_pcap):
    """Load SSDP test packets."""
    return load_pcap("ssdp/filtered_ssdp.pcap")


@pytest.fixture
def mdns_packets(load_pcap):
    """Load mDNS test packets."""
    return load_pcap("mdns/filtered_mdns.pcap")


@pytest.fixture
def ipv6_nd_packets(load_pcap):
    """Load IPv6 Neighbor Discovery test packets."""
    return load_pcap("ipv6/filtered_ipv6_nd.pcap")


@pytest.fixture
def vrrp_packets(load_pcap):
    """Load VRRP test packets."""
    return load_pcap("vrrp/filtered_vrrp.pcap")


@pytest.fixture
def snmp_packets(load_pcap):
    """Load SNMP test packets."""
    return load_pcap("snmp/filtered_snmp.pcap")


@pytest.fixture
def lldp_packets(load_pcap):
    """Load LLDP test packets."""
    return load_pcap("lldp/filtered_lldp.pcap")


@pytest.fixture
def cdp_packets(load_pcap):
    """Load CDP test packets."""
    return load_pcap("cdp/filtered_cdp.pcap")


@pytest.fixture
def ntp_packets(load_pcap):
    """Load NTP test packets."""
    return load_pcap("ntp/filtered_ntp.pcap")


@pytest.fixture
def modbus_packets(load_pcap):
    """Load Modbus TCP test packets."""
    return load_pcap("modbus/filtered_modbus.pcap")


@pytest.fixture
def dnp3_packets(load_pcap):
    """Load DNP3 test packets."""
    return load_pcap("dnp3/filtered_dnp3.pcap")


@pytest.fixture
def bacnet_packets(load_pcap):
    """Load BACnet test packets."""
    return load_pcap("bacnet/filtered_bacnet.pcap")


@pytest.fixture
def s7_mms_packets(load_pcap):
    """Load S7/MMS test packets."""
    return load_pcap("s7comm/filtered_s7_mms.pcap")


# Pytest configuration


def pytest_configure(config):
    """Register custom markers for test categorization."""
    config.addinivalue_line("markers", "pcap: tests using PCAP fixtures")
    config.addinivalue_line("markers", "discovery: discovery protocol tests")
    config.addinivalue_line("markers", "slow: marks tests as slow running")
    config.addinivalue_line("markers", "network: marks tests requiring network access")
