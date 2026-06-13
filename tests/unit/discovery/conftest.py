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
    """Mock netifaces module for all discovery tests.

    core.py uses lazy_import("netifaces") which calls importlib.import_module.
    We patch sys.modules so the lazy import resolves to our mock, and reset
    the LazyModule's internal cache so it re-evaluates.
    """
    mock_nf = _make_mock_netifaces()

    # Get the LazyModule instances from core.py and scanner.py (they are separate instances)
    from oida.protocols.discovery import core
    from oida.protocols.discovery import scanner as disc_scanner

    lazy_mods = [core._netifaces, disc_scanner._netifaces]

    # Save original state for all lazy modules
    saved_states = [(m._module, m._loaded, m._available) for m in lazy_mods]

    patches = [
        patch.dict("sys.modules", {"netifaces": mock_nf}),
    ]

    for p in patches:
        p.start()

    # Force all lazy imports to use our mock
    for m in lazy_mods:
        m._module = mock_nf
        m._loaded = True
        m._available = True

    yield mock_nf

    # Restore original state
    for m, (orig_module, orig_loaded, orig_available) in zip(lazy_mods, saved_states):
        m._module = orig_module
        m._loaded = orig_loaded
        m._available = orig_available

    for p in reversed(patches):
        p.stop()


@pytest.fixture(autouse=True)
def mock_interface_capabilities():
    """Mock interface capability detection to avoid real interface queries."""
    with patch(
        "oida.protocols.discovery.scanner.DiscoveryScanner._get_interface_capabilities",
        return_value={},
    ):
        yield
