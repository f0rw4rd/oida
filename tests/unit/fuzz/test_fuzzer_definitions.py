"""
Test that all registered protocol fuzzer definitions can be instantiated.

Parameterized test that discovers every fuzzer class in PROTOCOL_FUZZERS
and verifies it can be created with minimal mock arguments.
"""

import pytest

from oida.fuzz.protocols import PROTOCOL_FUZZERS
from oida.fuzz.core.config import FuzzerConfig
from oida.fuzz.core.connections import MockConnectionFactory


# Protocols requiring raw sockets, serial, BLE, or optional deps -- mark xfail
XFAIL_PROTOCOLS = {
    "icmp",
    "icmpv6",
    "ipv4",
    "ipv6",
    "ethernet",
    "profinet_dcp",
    "industrial_ethernet",
    "modbus_rtu",
    "gatt",
}


def _make_config(protocol_name: str) -> FuzzerConfig:
    """Create a minimal FuzzerConfig for testing instantiation."""
    return FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=9999,
        protocol=protocol_name,
        log_session=False,
        console_output=False,
        skip_pre_send_checks=True,
        web_interface=False,
    )


@pytest.mark.parametrize(
    "protocol_name",
    sorted(PROTOCOL_FUZZERS.keys()),
    ids=sorted(PROTOCOL_FUZZERS.keys()),
)
def test_fuzzer_instantiation(protocol_name):
    """Each registered fuzzer can be instantiated without error."""
    if protocol_name in XFAIL_PROTOCOLS:
        pytest.xfail(f"{protocol_name} requires special system access or optional deps")

    fuzzer_class = PROTOCOL_FUZZERS[protocol_name]
    config = _make_config(protocol_name)
    factory = MockConnectionFactory()

    try:
        fuzzer = fuzzer_class(config=config, connection_factory=factory)
    except ImportError as exc:
        pytest.skip(f"Missing dependency: {exc}")
        return

    assert fuzzer is not None, f"{protocol_name} fuzzer returned None"
    assert fuzzer.config is config, f"{protocol_name} config not set correctly"
    assert fuzzer.connection_factory is factory, f"{protocol_name} factory not set correctly"
