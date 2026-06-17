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

# Protocols that need an extra option supplied before _define_protocol() can run
# offline. The mutation fuzzer refuses to build without at least one seed; we
# provide a throwaway seed directory in the test rather than skipping it.
SEED_REQUIRED = {"mutation"}


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
def test_define_protocol_completes(protocol_name, mock_config, mock_factory, tmp_path):
    """Verify _define_protocol() runs without error for each registered fuzzer."""
    if protocol_name in SEED_REQUIRED:
        seed = tmp_path / "seed.bin"
        seed.write_bytes(b"AAAA")
        mock_config.protocol_options["seed_directory"] = f"{tmp_path}/"

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


def test_mdns_request_definitions_match_connected(mock_config, mock_factory):
    """mDNS static request inventory must match the requests actually connected.

    get_request_definitions() drives --list-requests / --requests /
    --disable-requests selection; a request connected via session.connect()
    but absent from the inventory can be fuzzed yet never listed or
    individually selected (and vice versa). This asserts set-equality between
    the two sources of truth for the mDNS fuzzer, guarding the drift fixed in
    src/oida/fuzz/protocols/mdns.py.
    """
    fuzzer_class = PROTOCOL_FUZZERS["mdns"]
    if fuzzer_class is None:
        pytest.skip("mdns fuzzer not available (optional dependency)")

    try:
        fuzzer = fuzzer_class(config=mock_config, connection_factory=mock_factory)
        session = fuzzer.session
    except ImportError as e:
        pytest.skip(f"Missing dependency for mdns: {e}")

    defined = {d.name for d in fuzzer_class.get_request_definitions()}

    # session.nodes maps node-id -> request node; exclude the synthetic root.
    connected = {node.name for node in session.nodes.values()} - {session.root.name}

    assert connected == defined, (
        "mDNS request inventory drift: "
        f"connected-but-not-listed={sorted(connected - defined)}, "
        f"listed-but-not-connected={sorted(defined - connected)}"
    )
