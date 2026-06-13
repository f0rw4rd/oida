"""
Test that every registered protocol fuzzer's _define_protocol() completes without error.

This parameterized test imports each fuzzer from the PROTOCOL_FUZZERS registry,
instantiates it with mocked connections, and verifies that _define_protocol()
can run to completion.  This catches import errors, missing constants, broken
request definitions, and other structural issues early.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS

pytestmark = pytest.mark.core

# Protocols that cannot run _define_protocol() in a unit-test environment
# (e.g. need real serial ports, BLE devices, raw sockets, or seed files).
SKIP_DEFINE = {
    # Raw socket protocols require root and real interfaces
    "icmp",
    "icmpv6",
    "ipv4",
    "ipv6",
    "ethernet",
    "industrial_ethernet",
    "profinet_dcp",
    # Serial protocols require a real serial device
    "modbus_rtu",
    # BLE requires a device address
    "gatt",
    # Mutation fuzzer requires seed files
    "mutation",
}


@pytest.fixture
def mock_config():
    """Create a FuzzerConfig suitable for offline testing."""
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=9999,
        protocol_type=ProtocolType.TCP,
        enumerate=False,
    )
    config.log_session = False
    config.console_output = False
    config.skip_pre_send_checks = True
    config.web_interface = False
    return config


@pytest.fixture
def mock_factory():
    return MockConnectionFactory()


@pytest.mark.parametrize(
    "protocol_name",
    sorted(PROTOCOL_FUZZERS.keys()),
)
def test_define_protocol_completes(protocol_name, mock_config, mock_factory):
    """Verify _define_protocol() runs without error for each registered fuzzer."""
    if protocol_name in SKIP_DEFINE:
        pytest.skip(f"{protocol_name} requires special environment")

    fuzzer_class = PROTOCOL_FUZZERS[protocol_name]
    if fuzzer_class is None:
        pytest.skip(f"{protocol_name} not available (optional dependency)")

    try:
        fuzzer = fuzzer_class(config=mock_config, connection_factory=mock_factory)
    except ImportError as e:
        pytest.skip(f"Missing dependency for {protocol_name}: {e}")
    except Exception as e:
        pytest.fail(f"Failed to instantiate {protocol_name}: {type(e).__name__}: {e}")

    # Access the session property which triggers _define_protocol() internally
    try:
        _ = fuzzer.session
    except ImportError as e:
        pytest.skip(f"Missing dependency for {protocol_name}: {e}")
    except Exception as e:
        pytest.fail(f"_define_protocol() failed for {protocol_name}: {type(e).__name__}: {e}")


@pytest.mark.parametrize(
    "protocol_name",
    sorted(PROTOCOL_FUZZERS.keys()),
)
def test_get_request_definitions(protocol_name):
    """Verify get_request_definitions() returns a non-empty list for each fuzzer."""
    fuzzer_class = PROTOCOL_FUZZERS[protocol_name]
    if fuzzer_class is None:
        pytest.skip(f"{protocol_name} not available")

    if not hasattr(fuzzer_class, "get_request_definitions"):
        pytest.skip(f"{protocol_name} does not implement get_request_definitions")

    try:
        defs = fuzzer_class.get_request_definitions()
        assert isinstance(defs, list), (
            f"{protocol_name}.get_request_definitions() returned {type(defs).__name__}, expected list"
        )
        # Most fuzzers should define at least one request
        assert len(defs) >= 1, f"{protocol_name}.get_request_definitions() returned empty list"
    except NotImplementedError:
        pytest.skip(f"{protocol_name} has not implemented get_request_definitions")
    except ImportError as e:
        pytest.skip(f"Missing dependency: {e}")
