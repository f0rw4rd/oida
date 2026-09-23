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
from tests.service_gate import require_service

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
        require_service(f"{protocol_name} not available (optional dependency)")

    try:
        fuzzer = fuzzer_class(config=mock_config, connection_factory=mock_factory)
    except ImportError as e:
        require_service(f"Missing dependency for {protocol_name}: {e}")
    except Exception as e:
        pytest.fail(f"Failed to instantiate {protocol_name}: {type(e).__name__}: {e}")

    # Access the session property which triggers _define_protocol() internally
    try:
        session = fuzzer.session
    except ImportError as e:
        require_service(f"Missing dependency for {protocol_name}: {e}")
    except Exception as e:
        pytest.fail(f"_define_protocol() failed for {protocol_name}: {type(e).__name__}: {e}")
        return

    # _define_protocol() is expected to register at least one boofuzz request
    # node into the session graph (via s_initialize/register_request). If it
    # silently did nothing, the fuzzer would have no mutations to send.
    assert len(session.nodes) >= 1, (
        f"_define_protocol() for {protocol_name} registered no nodes in the session graph"
    )


@pytest.mark.parametrize(
    "protocol_name",
    sorted(PROTOCOL_FUZZERS.keys()),
)
def test_get_request_definitions(protocol_name):
    """Verify get_request_definitions() returns a non-empty list for each fuzzer."""
    fuzzer_class = PROTOCOL_FUZZERS[protocol_name]
    if fuzzer_class is None:
        require_service(f"{protocol_name} not available")

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
        require_service(f"Missing dependency: {e}")


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
        require_service("mdns fuzzer not available (optional dependency)")

    try:
        fuzzer = fuzzer_class(config=mock_config, connection_factory=mock_factory)
        session = fuzzer.session
    except ImportError as e:
        require_service(f"Missing dependency for mdns: {e}")

    defined = {d.name for d in fuzzer_class.get_request_definitions()}

    # session.nodes maps node-id -> request node; exclude the synthetic root.
    connected = {node.name for node in session.nodes.values()} - {session.root.name}

    assert connected == defined, (
        "mDNS request inventory drift: "
        f"connected-but-not-listed={sorted(connected - defined)}, "
        f"listed-but-not-connected={sorted(defined - connected)}"
    )


def _mdns_connected_names(config, factory):
    """Build an mDNS fuzzer and return the set of actually-connected request names."""
    fuzzer_class = PROTOCOL_FUZZERS["mdns"]
    if fuzzer_class is None:
        require_service("mdns fuzzer not available (optional dependency)")
    try:
        fuzzer = fuzzer_class(config=config, connection_factory=factory)
        session = fuzzer.session
    except ImportError as e:
        require_service(f"Missing dependency for mdns: {e}")
    return {node.name for node in session.nodes.values()} - {session.root.name}


def test_mdns_enable_connects_only_selected(mock_config, mock_factory):
    """--enable (whitelist) must connect only the named mDNS request, nothing else.

    Guards is_request_enabled() wiring in mdns.py: before the fix every request
    was connected unconditionally, so --enable was silently ineffective and a
    subset run (e.g. only Circular_Compression to repro the infinite-loop crash)
    was impossible.
    """
    mock_config.enabled_requests = ["Circular_Compression"]
    connected = _mdns_connected_names(mock_config, mock_factory)
    assert connected == {"Circular_Compression"}, (
        f"--enable should connect only Circular_Compression, got {sorted(connected)}"
    )


def test_mdns_disable_excludes_selected(mock_config, mock_factory):
    """--disable (blacklist) must drop the named mDNS requests and keep the rest."""
    fuzzer_class = PROTOCOL_FUZZERS["mdns"]
    if fuzzer_class is None:
        require_service("mdns fuzzer not available (optional dependency)")

    all_names = {d.name for d in fuzzer_class.get_request_definitions()}

    mock_config.disabled_requests = ["Oversized_Packet", "Long_Name"]
    connected = _mdns_connected_names(mock_config, mock_factory)

    assert "Oversized_Packet" not in connected
    assert "Long_Name" not in connected
    assert connected == all_names - {"Oversized_Packet", "Long_Name"}


def test_enable_unknown_request_warns(mock_config, mock_factory, monkeypatch):
    """An --enable name not in the registry must emit a WARNING, not silently fuzz nothing.

    Guards _validate_request_filters() in base_fuzzer.py: a typo such as
    --enable Circular_Compressio (missing trailing 'n') otherwise puts the
    fuzzer in whitelist mode that matches no registered request, so it connects
    zero requests and exits 'successfully' without sending anything. The warning
    makes the mistake visible.
    """
    fuzzer_class = PROTOCOL_FUZZERS["mdns"]
    if fuzzer_class is None:
        require_service("mdns fuzzer not available (optional dependency)")

    from oida.utils.ics_logger import ICSLogger

    warnings: list[str] = []
    orig_warning = ICSLogger.warning

    def capture(self, msg, *args):
        warnings.append(msg % args if args else msg)
        return orig_warning(self, msg, *args)

    monkeypatch.setattr(ICSLogger, "warning", capture)

    # Real registered request is "Circular_Compression"; this is a typo.
    mock_config.enabled_requests = ["Circular_Compressio"]
    try:
        fuzzer_class(config=mock_config, connection_factory=mock_factory)
    except ImportError as e:
        require_service(f"Missing dependency for mdns: {e}")

    typo_warnings = [w for w in warnings if "Circular_Compressio" in w and "not found" in w]
    assert typo_warnings, (
        f"expected a 'not found in registry' warning for the typo'd --enable name, "
        f"got warnings: {warnings}"
    )


def test_known_enable_request_does_not_warn(mock_config, mock_factory, monkeypatch):
    """A valid --enable name must NOT trigger the unknown-request warning."""
    fuzzer_class = PROTOCOL_FUZZERS["mdns"]
    if fuzzer_class is None:
        require_service("mdns fuzzer not available (optional dependency)")

    from oida.utils.ics_logger import ICSLogger

    warnings: list[str] = []
    orig_warning = ICSLogger.warning

    def capture(self, msg, *args):
        warnings.append(msg % args if args else msg)
        return orig_warning(self, msg, *args)

    monkeypatch.setattr(ICSLogger, "warning", capture)

    mock_config.enabled_requests = ["Circular_Compression"]
    try:
        fuzzer_class(config=mock_config, connection_factory=mock_factory)
    except ImportError as e:
        require_service(f"Missing dependency for mdns: {e}")

    assert not [w for w in warnings if "not found in registry" in w], (
        f"valid --enable name should not warn, got: {warnings}"
    )
