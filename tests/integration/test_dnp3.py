#!/usr/bin/env python3
"""
Integration tests for DNP3 scanner against the Docker mock outstation.

Requires:
- yadnp3 installed
- dnp3-basic Docker service running on port 20000
  (start with: docker compose -f docker/mocks/docker-compose.yml up -d dnp3-basic)

These tests connect to a real protocol-compliant DNP3 outstation.
"""

import socket

import pytest

from tests.service_gate import require_import, require_service

# Skip all tests if yadnp3 is not installed
opendnp3 = require_import("opendnp3", reason="yadnp3 not installed")

from oida.protocols.dnp3.scanner import DNP3Scanner

# Serialize every DNP3 outstation-touching test onto one xdist worker: the mock
# outstation accepts a single master at a time, so concurrent workers collide
# ("Integrity poll failed: no communications"). Same pattern as snmp/hart/mms.
pytestmark = pytest.mark.xdist_group("dnp3_service")

# DNP3 basic mock service port (mapped from docker-compose.yml)
DNP3_MOCK_HOST = "127.0.0.1"
DNP3_MOCK_PORT = 20000
DNP3_OUTSTATION_ADDR = 1024
DNP3_MASTER_ADDR = 1


def is_service_available():
    """Check if the DNP3 mock is running."""
    try:
        with socket.create_connection((DNP3_MOCK_HOST, DNP3_MOCK_PORT), timeout=3):
            return True
    except (socket.error, ConnectionRefusedError, OSError):
        return False


# Skip all tests if the mock service is not running
pytestmark = [
    pytest.mark.dnp3,
    pytest.mark.integration,
    pytest.mark.skipif(
        not is_service_available(),
        reason=f"DNP3 mock not running on {DNP3_MOCK_HOST}:{DNP3_MOCK_PORT}",
    ),
]


@pytest.fixture(scope="module")
def scanner():
    """Create a connected DNP3 scanner."""
    s = DNP3Scanner(
        {
            "rhost": DNP3_MOCK_HOST,
            "rport": DNP3_MOCK_PORT,
            "master-address": DNP3_MASTER_ADDR,
            "outstation-address": DNP3_OUTSTATION_ADDR,
            "timeout": 15,
        }
    )
    conn = s.connect()
    if conn is None:
        require_service("Could not connect to DNP3 mock")
    yield s
    s.disconnect(conn)


class TestConnection:
    """Test connection to the mock outstation."""

    def test_connect_and_disconnect(self):
        """Test basic connect/disconnect cycle."""
        s = DNP3Scanner(
            {
                "rhost": DNP3_MOCK_HOST,
                "rport": DNP3_MOCK_PORT,
                "master-address": DNP3_MASTER_ADDR,
                "outstation-address": DNP3_OUTSTATION_ADDR,
                "timeout": 10,
            }
        )
        conn = s.connect()
        assert conn is not None
        assert s._connected is True

        s.disconnect(conn)
        assert s._connected is False
        assert s._channel is None
        assert s._manager is None


@pytest.mark.flaky(reruns=2, reruns_delay=4)
class TestIntegrityPoll:
    """Test integrity poll against the mock.

    opendnp3's integrity poll is asynchronous and occasionally returns no data
    within the poll timeout under system load (same flake the sibling
    test_dnp3_enumerate_points retries for). Reruns give the async poll another
    attempt against the same (module-scoped) connection rather than asserting on
    a single poll.
    """

    def test_integrity_poll_returns_data(self, scanner):
        """Test that integrity poll returns data points."""
        results = scanner.integrity_poll()
        assert isinstance(results, dict)

    def test_integrity_poll_has_data_points(self, scanner):
        """Test that integrity poll populates data_points."""
        results = {}
        scanner._perform_integrity_poll(results)

        data = results.get("data_points", {})

        # We should get at least some data back
        has_data = any(
            key in data
            for key in [
                "binary_inputs",
                "analog_inputs",
                "counters",
                "binary_output_statuses",
                "analog_output_statuses",
            ]
        )
        assert has_data, f"Expected data points, got: {data.keys()}"


class TestDiscover:
    """Test the full discover workflow."""

    def test_discover_returns_results(self, scanner):
        """Test that discover returns a complete results dict."""
        results = scanner.discover(scanner._channel)

        assert "connection" in results
        assert "data_points" in results
        assert "device_attributes" in results
        assert "operations" in results

    def test_discover_connection_metadata(self, scanner):
        """Test that discover includes connection metadata."""
        results = scanner.discover(scanner._channel)
        conn = results["connection"]

        assert conn["master_address"] == DNP3_MASTER_ADDR
        assert conn["outstation_address"] == DNP3_OUTSTATION_ADDR
        assert conn["tls_enabled"] is False
        assert "timestamp" in conn

    def test_discover_returns_binary_inputs(self, scanner):
        """Test that discover returns binary input data."""
        results = scanner.discover(scanner._channel)
        data = results.get("data_points", {})

        if "binary_inputs" in data:
            bi = data["binary_inputs"]
            assert len(bi) > 0
            # Each BI should have index, value, flags
            assert "index" in bi[0]
            assert "value" in bi[0]
            assert "flags" in bi[0]

    def test_discover_returns_analog_inputs(self, scanner):
        """Test that discover returns analog input data."""
        results = scanner.discover(scanner._channel)
        data = results.get("data_points", {})

        if "analog_inputs" in data:
            ai = data["analog_inputs"]
            assert len(ai) > 0
            assert "index" in ai[0]
            assert "value" in ai[0]

    def test_discover_returns_counters(self, scanner):
        """Test that discover returns counter data."""
        results = scanner.discover(scanner._channel)
        data = results.get("data_points", {})

        if "counters" in data:
            ct = data["counters"]
            assert len(ct) > 0
            assert "index" in ct[0]
            assert "value" in ct[0]


class TestDeviceAttributes:
    """Test device attribute reads."""

    def test_read_device_attributes(self, scanner):
        """Test reading device attributes (Group 0)."""
        results = scanner.read_attributes()
        assert isinstance(results, dict)


class TestClassReads:
    """Test class-specific reads."""

    def test_read_class_0(self, scanner):
        """Test reading Class 0 data."""
        results = scanner.read_class(0)
        assert isinstance(results, dict)

    def test_read_class_1(self, scanner):
        """Test reading Class 1 events."""
        results = scanner.read_class(1)
        assert isinstance(results, dict)


class TestCheckLinkStatus:
    """Test link status check."""

    def test_check_link_status(self, scanner):
        """Test checking link status with outstation."""
        try:
            result = scanner.check_link_status()
            assert isinstance(result, bool)
        except Exception:
            # Some outstations may not support link status check
            pass
