"""
Shared fixtures for discovery tests.

Mocks netifaces and interface capabilities so tests don't require
real network interfaces (e.g., eth0).
"""

import pytest
from unittest.mock import patch, MagicMock


# Known test interfaces and their addresses
_KNOWN_INTERFACES = ["lo", "eth0", "wlan0"]

_INTERFACE_ADDRESSES = {
    "eth0": {
        17: [{"addr": "00:11:22:33:44:55"}],  # AF_LINK
        2: [{"addr": "192.168.1.100", "netmask": "255.255.255.0"}],  # AF_INET
    },
    "wlan0": {
        17: [{"addr": "aa:bb:cc:dd:ee:ff"}],
        2: [{"addr": "192.168.2.50", "netmask": "255.255.255.0"}],
    },
    "lo": {
        17: [{"addr": "00:00:00:00:00:00"}],
        2: [{"addr": "127.0.0.1", "netmask": "255.0.0.0"}],
    },
}


def _mock_ifaddresses(interface):
    """Return mock addresses for known interfaces, raise for unknown."""
    if interface not in _INTERFACE_ADDRESSES:
        raise ValueError("You must specify a valid interface name.")
    return _INTERFACE_ADDRESSES[interface]


def _make_mock_netifaces():
    """Create a mock netifaces module with realistic behavior."""
    mock_nf = MagicMock()
    mock_nf.AF_LINK = 17  # Standard AF_LINK constant
    mock_nf.AF_INET = 2
    mock_nf.AF_INET6 = 10
    mock_nf.interfaces.return_value = list(_KNOWN_INTERFACES)
    mock_nf.ifaddresses.side_effect = _mock_ifaddresses
    return mock_nf


@pytest.fixture(autouse=True)
def mock_netifaces():
    """Mock interface enumeration for all discovery tests.

    Since the netifaces2 migration, core.py and scanner.py both bind
    ``from ...utils import iface_info as _netifaces`` (the same module
    object). Its ``AF_INET``/``AF_INET6``/``AF_LINK`` constants are real and
    already match the keys in ``_INTERFACE_ADDRESSES``, so we only need to
    patch the two enumeration functions to avoid touching real interfaces.
    """
    mock_nf = _make_mock_netifaces()

    from oida.utils import iface_info

    with (
        patch.object(iface_info, "interfaces", return_value=list(_KNOWN_INTERFACES)),
        patch.object(iface_info, "ifaddresses", side_effect=_mock_ifaddresses),
    ):
        yield mock_nf


@pytest.fixture(autouse=True)
def mock_interface_capabilities():
    """Mock interface capability detection to avoid real interface queries."""
    with patch(
        "oida.protocols.discovery.scanner.DiscoveryScanner._get_interface_capabilities",
        return_value={},
    ):
        yield
