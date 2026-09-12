"""
Test that all registered protocol fuzzer definitions can be instantiated.

Parameterized test that discovers every fuzzer class in PROTOCOL_FUZZERS
and verifies it can be created with minimal mock arguments.
"""

import pytest

from oida.fuzz.protocols import PROTOCOL_FUZZERS
from oida.fuzz.core.config import FuzzerConfig
from oida.fuzz.core.connections import MockConnectionFactory
from tests.service_gate import require_service


# Empty: instantiation only builds the boofuzz request tree (no I/O), so it
# never needs raw sockets / serial / root — those are only required to *send*.
# The previous entries (icmp/icmpv6/ipv4/ipv6/ethernet/modbus_rtu) all
# instantiate fine and now run for real; profinet_dcp/industrial_ethernet were
# dead (not in PROTOCOL_FUZZERS). Genuinely missing optional deps are still
# handled by the ImportError -> skip fallback below.
XFAIL_PROTOCOLS: set[str] = set()


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
        enumerate=False,
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
        require_service(f"Missing dependency: {exc}")
        return

    assert fuzzer is not None, f"{protocol_name} fuzzer returned None"
    assert fuzzer.config is config, f"{protocol_name} config not set correctly"
    assert fuzzer.connection_factory is factory, f"{protocol_name} factory not set correctly"
