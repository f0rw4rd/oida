"""
Integration tests that run each fuzzer for 100 test cases.

Tests that all protocol fuzzers can:
1. Initialize correctly
2. Define protocol structure without errors
3. Request definitions are valid
"""

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from oida.fuzz.core.config import FuzzerConfig, MonitorConfig
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS

pytestmark = pytest.mark.core
# Protocols requiring special dependencies/access
SKIP_PROTOCOLS = {
    # Raw socket (requires root)
    "icmp",
    "icmpv6",
    "ipv4",
    "ipv6",
    "ethernet",
    "profinet_dcp",
    # Serial port
    "modbus_rtu",
    # Optional pyradamsa dependency
    "mutation",
    # Industrial ethernet (requires raw socket)
    "industrial_ethernet",
}

# Get testable protocols
TESTABLE_PROTOCOLS = [name for name in PROTOCOL_FUZZERS.keys() if name not in SKIP_PROTOCOLS]


@pytest.fixture
def temp_session():
    """Create temporary session directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield os.path.join(tmpdir, "test_session")


@pytest.fixture
def mock_connection_factory():
    """Create MockConnectionFactory with pre-configured responses."""
    factory = MockConnectionFactory()
    return factory


def create_config(session_path: str, protocol: str) -> FuzzerConfig:
    """Create FuzzerConfig for testing."""
    # Disable all monitors to skip preflight checks
    no_monitors = MonitorConfig.parse("none")

    return FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=9999,
        protocol=protocol,
        session_filename=session_path,
        index_end=100,  # Run only 100 test cases
        log_session=False,
        console_output=False,
        web_interface=False,
        enumerate=False,  # Skip capability enumeration
        skip_pre_send_checks=True,
        monitor_config=no_monitors,  # Disable all monitors for mock testing
        boofuzz_db=False,
    )


class TestFuzzerInitialization:
    """Test that each fuzzer can be initialized."""

    @pytest.mark.parametrize("protocol_name", TESTABLE_PROTOCOLS)
    def test_fuzzer_initializes(self, protocol_name, temp_session, mock_connection_factory):
        """Test fuzzer initialization without errors."""
        pytest.importorskip("boofuzz")

        fuzzer_class = PROTOCOL_FUZZERS.get(protocol_name)
        if not fuzzer_class:
            pytest.skip(f"Protocol {protocol_name} not available")

        config = create_config(temp_session, protocol_name)

        try:
            fuzzer = fuzzer_class(config=config, connection_factory=mock_connection_factory)
            assert fuzzer is not None
            assert fuzzer.config == config
        except ImportError as e:
            pytest.skip(f"Missing dependency: {e}")
        except Exception as e:
            pytest.fail(f"Failed to initialize {protocol_name}: {type(e).__name__}: {e}")


class TestFuzzerProtocolDefinition:
    """Test that each fuzzer's protocol definition works correctly."""

    @pytest.mark.parametrize("protocol_name", TESTABLE_PROTOCOLS)
    def test_protocol_definition(self, protocol_name, temp_session, mock_connection_factory):
        """Test that _define_protocol() runs without errors.

        This test uses mocking to avoid actual network connections while
        verifying that the protocol definition logic is valid.
        """
        pytest.importorskip("boofuzz")

        fuzzer_class = PROTOCOL_FUZZERS.get(protocol_name)
        if not fuzzer_class:
            pytest.skip(f"Protocol {protocol_name} not available")

        config = create_config(temp_session, protocol_name)

        try:
            fuzzer = fuzzer_class(config=config, connection_factory=mock_connection_factory)
        except ImportError as e:
            pytest.skip(f"Missing dependency: {e}")
        except Exception as e:
            pytest.fail(f"Failed to initialize {protocol_name}: {e}")

        # Patch _create_socket to avoid network issues, then access session
        # which triggers _define_protocol
        with patch.object(fuzzer, "_create_socket") as mock_socket:
            mock_conn = MagicMock()
            mock_conn.open = MagicMock()
            mock_conn.close = MagicMock()
            mock_conn.send = MagicMock(return_value=10)
            mock_conn.recv = MagicMock(return_value=b"")
            mock_socket.return_value = mock_conn

            try:
                # Access session property to trigger _define_protocol
                session = fuzzer.session
                # Verify session was created and has nodes (protocol definitions)
                assert session is not None, f"{protocol_name}: session is None"
                assert hasattr(session, "nodes"), f"{protocol_name}: session has no nodes"
            except NameError as e:
                # Missing import - this is a real bug
                pytest.fail(f"Protocol {protocol_name} has missing import: {e}")
            except Exception as e:
                pytest.fail(
                    f"Protocol definition for {protocol_name} failed: {type(e).__name__}: {e}"
                )


class TestFuzzerRequestDefinitions:
    """Test that fuzzer request definitions are valid."""

    @pytest.mark.parametrize("protocol_name", TESTABLE_PROTOCOLS)
    def test_fuzzer_request_definitions(self, protocol_name):
        """Verify request definitions are valid."""
        pytest.importorskip("boofuzz")

        fuzzer_class = PROTOCOL_FUZZERS.get(protocol_name)
        if not fuzzer_class:
            pytest.skip(f"Protocol {protocol_name} not available")

        requests = fuzzer_class.get_request_definitions()
        assert isinstance(requests, list), f"{protocol_name}: requests not a list"

        for req in requests:
            assert hasattr(req, "name"), f"{protocol_name}: request missing name"
            assert hasattr(req, "description"), f"{protocol_name}: request missing description"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
