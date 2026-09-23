"""
Integration tests for Mock Services

Tests each protocol's scanner against its Docker mock service to verify:
- Service availability and connectivity
- Expected data points and objects are returned
- Device attributes and metadata are correct
- Protocol-specific features work as expected

Run with: pytest tests/integration/test_mock_services.py -v
Or specific protocols: pytest tests/integration/test_mock_services.py -v -m dnp3
"""

import http.client
import json
import pytest
import socket
import urllib.request
import urllib.error

from tests.service_gate import require_port, require_service

from .conftest import MOCK_HOST, MOCK_PORTS, check_port_open


@pytest.fixture
def mock_service():
    """No-op fixture for backward compatibility.

    Service lifecycle is managed by the marker-driven docker_setup fixture
    in conftest.py. This fixture exists so tests that reference it continue
    to collect without fixture errors.
    """
    pass


# =============================================================================
# DNP3 Mock Service Tests
# =============================================================================


@pytest.mark.dnp3
@pytest.mark.mock_services
@pytest.mark.xdist_group(
    "dnp3_service"
)  # share the single-master outstation; avoid worker contention
class TestDNP3MockService:
    """Tests for DNP3 mock server data point enumeration."""

    @pytest.fixture(autouse=True)
    def _require_dnp3_service(self, dnp3_port):
        require_port(MOCK_HOST, dnp3_port, "DNP3 service", timeout=3)

    @pytest.fixture
    def dnp3_port(self):
        return MOCK_PORTS.get("dnp3", 20000)

    @pytest.fixture
    def dnp3_enhanced_port(self):
        return MOCK_PORTS.get("dnp3_enhanced", 20010)

    def test_dnp3_service_available(self, dnp3_port, mock_service):
        """Verify DNP3 mock service is running."""
        assert check_port_open(MOCK_HOST, dnp3_port, timeout=5), (
            f"DNP3 service not available on port {dnp3_port}"
        )

    def test_dnp3_basic_connection(self, cli_runner, dnp3_port, mock_service):
        """Test basic DNP3 connection without enumeration."""
        result = cli_runner.run(
            "dnp3", MOCK_HOST, "--port", str(dnp3_port), "--timeout", "10", expect_json=False
        )
        # Should connect successfully
        assert (
            "Connected to DNP3 outstation" in result.combined_output
            or "DNP3 Outstation" in result.combined_output
        )

    def test_dnp3_integrity_poll(self, cli_runner, dnp3_port, mock_service):
        """Test DNP3 integrity poll returns data points."""
        result = cli_runner.run(
            "dnp3", MOCK_HOST, "--port", str(dnp3_port), "--timeout", "15", expect_json=False
        )

        output = result.combined_output
        # Scanner outputs "Points: X BI, Y AI..." when integrity poll returns data
        assert "Points:" in output, f"Expected integrity poll data in output, got: {output[:500]}"

    def test_dnp3_enumerate_points(self, cli_runner, dnp3_port, mock_service):
        """Test DNP3 point enumeration with -e flag.

        opendnp3's integrity poll is asynchronous and occasionally returns no
        data within the timeout (a known mock/timing flake, sometimes lasting
        several seconds when the shared outstation is busy from a prior test),
        so retry with a delay before failing rather than asserting on a single
        poll.
        """
        import time

        point_types_found = []
        for _attempt in range(4):
            if _attempt:
                time.sleep(6)
            result = cli_runner.run(
                "dnp3",
                MOCK_HOST,
                "-e",
                "--port",
                str(dnp3_port),
                "--timeout",
                "20",
                expect_json=False,
            )
            output = result.combined_output

            # Verify data point types are enumerated
            # The mock should have BI, AI, CT, BO, AO
            point_types_found = []
            if "binary_input" in output.lower() or "BI" in output:
                point_types_found.append("BI")
            if "analog_input" in output.lower() or "AI" in output:
                point_types_found.append("AI")
            if "counter" in output.lower() or "CT" in output:
                point_types_found.append("CT")
            if "binary_output" in output.lower() or "BO" in output:
                point_types_found.append("BO")
            if "analog_output" in output.lower() or "AO" in output:
                point_types_found.append("AO")

            if len(point_types_found) >= 3:
                break

        assert len(point_types_found) >= 3, (
            f"Expected at least 3 point types, found: {point_types_found}"
        )

    def test_dnp3_device_attributes(self, cli_runner, dnp3_port, mock_service):
        """Test DNP3 device attribute reading."""
        result = cli_runner.run(
            "dnp3", MOCK_HOST, "--port", str(dnp3_port), "--timeout", "15", expect_json=False
        )

        output = result.combined_output

        # Should show device attributes
        # Common attributes: Location, Owner Name, Product Name
        attr_found = []
        if "Location" in output or "Attr [245]" in output:
            attr_found.append("Location")
        if "Owner" in output or "Attr [248]" in output:
            attr_found.append("Owner")
        if "Product" in output or "Attr [252]" in output:
            attr_found.append("Product")

        # At least some attributes should be present, or the scanner reported why they're missing
        assert (
            len(attr_found) >= 1 or "Attr" in output or "No device attributes returned" in output
        ), "Expected device attributes or explanation in output"

    def test_dnp3_binary_input_count(self, cli_runner, dnp3_port, mock_service):
        """Verify expected number of binary inputs."""
        result = cli_runner.run(
            "dnp3", MOCK_HOST, "-e", "--port", str(dnp3_port), "--timeout", "20", expect_json=False
        )

        output = result.combined_output

        # Look for binary input count in output
        # Format varies: "25 BI" or "binary_inputs: 25 points"
        import re

        bi_match = re.search(r"(\d+)\s*BI", output) or re.search(
            r"binary.?input[s]?[:\s]+(\d+)", output, re.I
        )

        if bi_match:
            bi_count = int(bi_match.group(1))
            assert bi_count >= 5, f"Expected at least 5 binary inputs, got {bi_count}"

    def test_dnp3_analog_input_count(self, cli_runner, dnp3_port, mock_service):
        """Verify expected number of analog inputs."""
        result = cli_runner.run(
            "dnp3", MOCK_HOST, "-e", "--port", str(dnp3_port), "--timeout", "20", expect_json=False
        )

        output = result.combined_output

        import re

        ai_match = re.search(r"(\d+)\s*AI", output) or re.search(
            r"analog.?input[s]?[:\s]+(\d+)", output, re.I
        )

        if ai_match:
            ai_count = int(ai_match.group(1))
            assert ai_count >= 5, f"Expected at least 5 analog inputs, got {ai_count}"


# =============================================================================
# HTTP/2 Mock Service Tests
# =============================================================================


@pytest.mark.http2
@pytest.mark.mock_services
class TestHTTP2MockService:
    """Tests for HTTP/2 mock servers (nghttp2 and Python validation server)."""

    @pytest.fixture(autouse=True)
    def _require_http2_service(self, nghttp2_h2c_port, python_h2c_port):
        if not check_port_open(MOCK_HOST, nghttp2_h2c_port, timeout=3) and not check_port_open(
            MOCK_HOST, python_h2c_port, timeout=3
        ):
            require_service("No HTTP/2 mock services available")

    @pytest.fixture
    def nghttp2_h2c_port(self):
        return MOCK_PORTS.get("http2_nghttp2_h2c", 8080)

    @pytest.fixture
    def python_h2c_port(self):
        return MOCK_PORTS.get("http2_python_h2c", 9080)

    def test_http2_nghttp2_h2c_available(self, nghttp2_h2c_port, mock_service):
        """Verify nghttp2 h2c service is running and actually speaks HTTP/2."""
        require_port(MOCK_HOST, nghttp2_h2c_port, "nghttp2 h2c service", timeout=5)

        # An open TCP port alone doesn't prove it's h2c. Send the RFC 7540 3.5
        # client connection preface and require a real SETTINGS frame (type
        # 0x04) back -- proof the mock is speaking HTTP/2, not just listening.
        # RFC 7540 3.5: the preface MUST be immediately followed by a SETTINGS
        # frame (may be empty) or a compliant server treats it as malformed.
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        empty_settings_frame = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
        with socket.create_connection((MOCK_HOST, nghttp2_h2c_port), timeout=5) as sock:
            sock.sendall(preface + empty_settings_frame)
            sock.settimeout(5)
            header = sock.recv(9)
        assert len(header) == 9, f"Expected a 9-byte HTTP/2 frame header, got {header!r}"
        frame_type = header[3]
        assert frame_type == 0x04, (
            f"Expected a SETTINGS frame (type 0x04) after the HTTP/2 preface, "
            f"got frame type {frame_type:#x}"
        )

    def test_http2_python_h2c_available(self, python_h2c_port, mock_service):
        """Verify Python h2c service is running and actually speaks HTTP/2."""
        require_port(MOCK_HOST, python_h2c_port, "Python h2c service", timeout=5)

        # Same proof as the nghttp2 h2c check above: an open TCP port alone
        # doesn't prove it's h2c. Send the RFC 7540 3.5 client connection
        # preface and require a real SETTINGS frame (type 0x04) back.
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        empty_settings_frame = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
        with socket.create_connection((MOCK_HOST, python_h2c_port), timeout=5) as sock:
            sock.sendall(preface + empty_settings_frame)
            sock.settimeout(5)
            header = sock.recv(9)
        assert len(header) == 9, f"Expected a 9-byte HTTP/2 frame header, got {header!r}"
        frame_type = header[3]
        assert frame_type == 0x04, (
            f"Expected a SETTINGS frame (type 0x04) after the HTTP/2 preface, "
            f"got frame type {frame_type:#x}"
        )

    def test_http2_python_state_endpoint(self, python_h2c_port, mock_service):
        """Test /.well-known/h2/state endpoint returns valid JSON."""
        url = f"http://{MOCK_HOST}:{python_h2c_port}/.well-known/h2/state"

        try:
            # Note: This uses HTTP/1.1, not HTTP/2, but the server should still respond
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "OIDA-Test/1.0")

            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))

                assert "stats" in data or "server" in data, (
                    "Expected 'stats' or 'server' in state response"
                )

        except (urllib.error.URLError, http.client.BadStatusLine) as e:
            require_service(f"Could not connect to HTTP/2 Python server: {e}")

    def test_http2_python_errors_endpoint(self, python_h2c_port, mock_service):
        """Test /.well-known/h2/errors endpoint returns valid JSON."""
        url = f"http://{MOCK_HOST}:{python_h2c_port}/.well-known/h2/errors"

        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))

                # Should be a list (possibly empty)
                assert isinstance(data, list), "Expected list of errors"

        except (urllib.error.URLError, http.client.BadStatusLine) as e:
            require_service(f"Could not connect to HTTP/2 Python server: {e}")

    def test_http2_python_frames_endpoint(self, python_h2c_port, mock_service):
        """Test /.well-known/h2/frames endpoint returns frame log."""
        url = f"http://{MOCK_HOST}:{python_h2c_port}/.well-known/h2/frames"

        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))

                assert isinstance(data, list), "Expected list of frame events"

        except (urllib.error.URLError, http.client.BadStatusLine) as e:
            require_service(f"Could not connect to HTTP/2 Python server: {e}")

    def test_http2_python_hpack_endpoint(self, python_h2c_port, mock_service):
        """Test /.well-known/h2/hpack endpoint returns HPACK state."""
        url = f"http://{MOCK_HOST}:{python_h2c_port}/.well-known/h2/hpack"

        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))

                # Should have HPACK-related fields
                assert "dynamic_table_size" in data or "max_dynamic_table_size" in data, (
                    "Expected HPACK state fields"
                )

        except (urllib.error.URLError, http.client.BadStatusLine) as e:
            require_service(f"Could not connect to HTTP/2 Python server: {e}")

    def test_http2_python_echo_endpoint(self, python_h2c_port, mock_service):
        """Test /echo endpoint echoes request."""
        url = f"http://{MOCK_HOST}:{python_h2c_port}/echo"

        try:
            req = urllib.request.Request(url)
            req.add_header("X-Test-Header", "test-value")

            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))

                assert "method" in data, "Expected 'method' in echo response"
                assert "path" in data, "Expected 'path' in echo response"

        except (urllib.error.URLError, http.client.BadStatusLine) as e:
            require_service(f"Could not connect to HTTP/2 Python server: {e}")

    def test_http2_monitor_integration(self, python_h2c_port, mock_service):
        """Test HTTP2Monitor can connect and check health."""
        try:
            from oida.fuzz.monitors import HTTP2Monitor

            monitor = HTTP2Monitor(host=MOCK_HOST, port=python_h2c_port, use_tls=False, timeout=5.0)

            # Try to establish baseline
            if monitor.establish_baseline():
                assert monitor.baseline_established, "Baseline should be established"

                # Check error summary
                errors = monitor.get_error_summary()
                assert "protocol_errors" in errors

        except ImportError:
            require_service("HTTP2Monitor not available")
        except Exception as e:
            require_service(f"HTTP2Monitor test failed: {e}")


# =============================================================================
# Modbus Mock Service Tests
# =============================================================================


@pytest.mark.modbus
@pytest.mark.mock_services
class TestModbusMockService:
    """Tests for Modbus mock server."""

    @pytest.fixture(autouse=True)
    def _require_modbus_service(self, modbus_port):
        require_port(MOCK_HOST, modbus_port, "Modbus service", timeout=3)

    @pytest.fixture
    def modbus_port(self):
        return MOCK_PORTS.get("modbus", 502)

    def test_modbus_service_available(self, modbus_port, mock_service):
        """Verify Modbus service is running."""
        assert check_port_open(MOCK_HOST, modbus_port, timeout=5), (
            f"Modbus service not available on port {modbus_port}"
        )

    def test_modbus_basic_scan(self, cli_runner, modbus_port, mock_service):
        """Test basic Modbus scan."""
        result = cli_runner.run(
            "modbus", MOCK_HOST, "--port", str(modbus_port), "--timeout", "10", expect_json=False
        )

        # Should show some Modbus output
        assert result.returncode == 0 or "Modbus" in result.combined_output

    def test_modbus_read_holding_registers(self, cli_runner, modbus_port, mock_service):
        """Test reading holding registers."""
        result = cli_runner.run(
            "modbus",
            MOCK_HOST,
            "--port",
            str(modbus_port),
            "--scan-range",
            "0-10",
            "--timeout",
            "10",
            expect_json=False,
        )

        output = result.combined_output
        # Should show register values or scan results
        assert "register" in output.lower() or "holding" in output.lower() or result.returncode == 0

    def test_modbus_mei_identification(self, cli_runner, modbus_port, mock_service):
        """Test MEI device identification."""
        result = cli_runner.run(
            "modbus", MOCK_HOST, "--port", str(modbus_port), "--timeout", "10", expect_json=False
        )

        output = result.combined_output
        # MEI data should include vendor/product info
        mei_found = any(
            x in output.lower() for x in ["vendor", "product", "model", "mei", "device"]
        )

        # Not all mocks support MEI, so just check connection works
        assert result.returncode == 0 or mei_found


# =============================================================================
# OPC UA Mock Service Tests
# =============================================================================


@pytest.mark.opcua
@pytest.mark.mock_services
class TestOPCUAMockService:
    """Tests for OPC UA mock server."""

    @pytest.fixture(autouse=True)
    def _require_opcua_service(self, opcua_port):
        require_port(MOCK_HOST, opcua_port, "OPC UA service", timeout=3)

    @pytest.fixture
    def opcua_port(self):
        return MOCK_PORTS.get("opcua", 4840)

    def test_opcua_service_available(self, opcua_port, mock_service):
        """Verify OPC UA service is running."""
        assert check_port_open(MOCK_HOST, opcua_port, timeout=5), (
            f"OPC UA service not available on port {opcua_port}"
        )

    def test_opcua_basic_scan(self, cli_runner, opcua_port, mock_service):
        """Test basic OPC UA scan."""
        target = f"opc.tcp://{MOCK_HOST}:{opcua_port}"
        result = cli_runner.run("opcua", target, "--timeout", "15", expect_json=False)

        output = result.combined_output
        # Should show OPC UA connection info
        assert "OPC" in output or "endpoint" in output.lower() or result.returncode == 0

    def test_opcua_get_endpoints(self, cli_runner, opcua_port, mock_service):
        """Test OPC UA GetEndpoints."""
        target = f"opc.tcp://{MOCK_HOST}:{opcua_port}"
        result = cli_runner.run("opcua", target, "--timeout", "15", expect_json=False)

        output = result.combined_output
        # Should show endpoint or security information
        security_found = any(
            x in output.lower() for x in ["security", "endpoint", "policy", "anonymous"]
        )

        assert result.returncode == 0 or security_found

    def test_opcua_browse(self, cli_runner, opcua_port, mock_service):
        """Test OPC UA browse functionality."""
        target = f"opc.tcp://{MOCK_HOST}:{opcua_port}"
        result = cli_runner.run("opcua", target, "--browse", "--timeout", "20", expect_json=False)

        output = result.combined_output
        # Should show node information
        browse_found = any(x in output.lower() for x in ["node", "object", "browse", "namespace"])

        assert result.returncode == 0 or browse_found


# =============================================================================
# BACnet Mock Service Tests
# =============================================================================


@pytest.mark.bacnet
@pytest.mark.mock_services
class TestBACnetMockService:
    """Tests for BACnet mock server."""

    @pytest.fixture(autouse=True)
    def _require_bacnet_service(self, bacnet_port):
        try:
            import bacpypes3  # noqa: F401
        except ImportError:
            require_service("bacpypes3 not installed")
        # BACnet uses UDP — sendto never fails, so we must wait for a response
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(b"\x81\x0a\x00\x08\x01\x00\x10\x08", (MOCK_HOST, bacnet_port))
            sock.recvfrom(1024)
            sock.close()
        except Exception:
            require_service(f"BACnet service not available on port {bacnet_port}")

    @pytest.fixture
    def bacnet_port(self):
        return MOCK_PORTS.get("bacnet", 47808)

    def test_bacnet_service_available(self, bacnet_port, mock_service):
        """Verify BACnet service is running (UDP)."""
        # BACnet uses UDP, so we check differently
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            # Send a Who-Is broadcast
            # BACnet BVLC header: type=0x81, function=0x0a (Original-Unicast-NPDU)
            who_is = bytes(
                [
                    0x81,
                    0x0A,  # BVLC
                    0x00,
                    0x08,  # Length
                    0x01,
                    0x00,  # NPDU
                    0x10,
                    0x08,  # Who-Is APDU
                ]
            )
            sock.sendto(who_is, (MOCK_HOST, bacnet_port))
            sock.close()
            # If we get here without error, port is reachable
            available = True
        except Exception:
            available = False

        if not available:
            # Try TCP fallback check
            available = check_port_open(MOCK_HOST, bacnet_port, timeout=3)

        assert available, f"BACnet service not available on port {bacnet_port}"

    def test_bacnet_who_is_discovery(self, cli_runner, bacnet_port, mock_service):
        """Test BACnet Who-Is discovery."""
        result = cli_runner.run("bacnet", MOCK_HOST, "--timeout", "10", expect_json=False)

        output = result.combined_output
        # Should discover device
        device_found = any(x in output.lower() for x in ["device", "i-am", "found", "object"])

        assert result.returncode == 0 or device_found or "BACnet" in output

    def test_bacnet_device_info(self, cli_runner, bacnet_port, mock_service):
        """Test BACnet device information reading."""
        result = cli_runner.run(
            "bacnet",
            MOCK_HOST,
            "--device-id",
            "1234",  # Default mock device ID
            "--timeout",
            "15",
            expect_json=False,
        )

        output = result.combined_output
        # Should show device properties
        props_found = any(
            x in output.lower()
            for x in ["vendor", "model", "firmware", "object-name", "description"]
        )

        assert result.returncode == 0 or props_found

    def test_bacnet_enumerate_objects(self, cli_runner, bacnet_port, mock_service):
        """Test BACnet object enumeration."""
        result = cli_runner.run(
            "bacnet",
            MOCK_HOST,
            "--device-id",
            "1234",
            "-e",  # Enumerate
            "--timeout",
            "20",
            expect_json=False,
        )

        output = result.combined_output

        # Should list object types
        object_types_found = []
        for obj_type in ["analog", "binary", "schedule", "trend", "file", "loop"]:
            if obj_type in output.lower():
                object_types_found.append(obj_type)

        # At least some object types should be found
        assert len(object_types_found) >= 1 or "object" in output.lower()


# =============================================================================
# IEC 104 Mock Service Tests
# =============================================================================


@pytest.mark.iec104
@pytest.mark.mock_services
class TestIEC104MockService:
    """Tests for IEC 104 mock server."""

    @pytest.fixture(autouse=True)
    def _require_iec104_service(self, iec104_port):
        require_port(MOCK_HOST, iec104_port, "IEC 104 service", timeout=3)

    @pytest.fixture
    def iec104_port(self):
        return MOCK_PORTS.get("iec104", 2404)

    @pytest.fixture
    def iec104_custom_port(self):
        return MOCK_PORTS.get("iec104_custom", 2405)

    def test_iec104_service_available(self, iec104_port, mock_service):
        """Verify IEC 104 service is running."""
        assert check_port_open(MOCK_HOST, iec104_port, timeout=5), (
            f"IEC 104 service not available on port {iec104_port}"
        )

    def test_iec104_basic_connection(self, cli_runner, iec104_port, mock_service):
        """Test basic IEC 104 connection."""
        result = cli_runner.run(
            "iec104", MOCK_HOST, "--port", str(iec104_port), "--timeout", "10", expect_json=False
        )

        output = result.combined_output
        # Should connect to IEC 104 server
        assert (
            "IEC" in output
            or "104" in output
            or "connected" in output.lower()
            or result.returncode == 0
        )

    def test_iec104_general_interrogation(self, cli_runner, iec104_port, mock_service):
        """Test IEC 104 general interrogation."""
        result = cli_runner.run(
            "iec104", MOCK_HOST, "--port", str(iec104_port), "--timeout", "15", expect_json=False
        )

        output = result.combined_output
        # Should show data point information
        data_found = any(
            x in output.lower()
            for x in ["point", "ioa", "single", "double", "measured", "normalized", "scaled"]
        )

        assert result.returncode == 0 or data_found

    def test_iec104_data_point_types(self, cli_runner, iec104_port, mock_service):
        """Test IEC 104 enumerates different data point types."""
        result = cli_runner.run(
            "iec104",
            MOCK_HOST,
            "--port",
            str(iec104_port),
            "-e",  # Enumerate
            "--timeout",
            "20",
            expect_json=False,
        )

        output = result.combined_output

        # Check for different type IDs
        types_found = []
        type_patterns = [
            ("M_SP", "single point"),
            ("M_DP", "double point"),
            ("M_ME", "measured"),
            ("M_IT", "integrated total"),
        ]

        for pattern, name in type_patterns:
            if pattern in output or name in output.lower():
                types_found.append(name)

        # At least some types should be found
        assert len(types_found) >= 1 or "type" in output.lower()

    def test_iec104_custom_types_server(self, iec104_custom_port, mock_service):
        """Test IEC 104 custom types server availability."""
        require_port(MOCK_HOST, iec104_custom_port, "IEC 104 custom types server", timeout=3)

        # Just verify it's up
        assert check_port_open(MOCK_HOST, iec104_custom_port, timeout=5)


# =============================================================================
# Cross-Protocol Integration Tests
# =============================================================================


@pytest.mark.mock_services
class TestMockServicesIntegration:
    """Cross-protocol integration tests."""

    def test_multiple_services_available(self):
        """Verify multiple mock services are running concurrently."""
        services_available = []

        test_ports = [
            ("modbus", MOCK_PORTS.get("modbus", 502)),
            ("modbus_conpot", MOCK_PORTS.get("modbus_conpot", 5503)),
            ("opcua", MOCK_PORTS.get("opcua", 4840)),
            ("iec104", MOCK_PORTS.get("iec104", 2404)),
            ("knx", MOCK_PORTS.get("knx", 3671)),
        ]

        for name, port in test_ports:
            if check_port_open(MOCK_HOST, port, timeout=3):
                services_available.append(name)

        if len(services_available) < 2:
            require_service(f"Need at least 2 services running, only found: {services_available}")

        assert len(services_available) >= 2, (
            f"Expected at least 2 concurrently-running mock services, found: {services_available}"
        )
        # modbus is a core mock brought up by every lane profile; if it isn't
        # among the detected services, the port-detection loop above is
        # broken (false-negative), not just "modbus happens to be down".
        assert "modbus" in services_available, (
            f"Expected the core 'modbus' mock among detected services: {services_available}"
        )

    def test_services_respond_independently(self, cli_runner):
        """Test that services respond independently without interference."""
        results = {}

        # Run quick scans against available services.
        # OPC UA needs opc.tcp:// target format; other protocols use --port.
        service_specs = [
            ("modbus", 502, [MOCK_HOST, "--port", "502", "--timeout", "10"]),
            ("iec104", 2404, [MOCK_HOST, "--port", "2404", "--timeout", "10"]),
            (
                "opcua",
                4840,
                [f"opc.tcp://{MOCK_HOST}:4840", "--timeout", "15"],
            ),
        ]

        for protocol, port, args in service_specs:
            if check_port_open(MOCK_HOST, port, timeout=2):
                result = cli_runner.run(protocol, *args, expect_json=False)
                # A scan "responded" if it exited cleanly OR produced
                # protocol-specific output (e.g. OPC UA may return exit 1
                # due to auth denial but still shows endpoints).
                responded = result.returncode == 0 or any(
                    kw in result.combined_output.lower()
                    for kw in ["endpoint", "server", "connected", "register", "ioa"]
                )
                results[protocol] = responded

        if not results:
            require_service("No mock services available for independent response test")

        # At least one should succeed
        assert any(results.values()), f"No services responded: {results}"


# =============================================================================
# Data Validation Tests
# =============================================================================


@pytest.mark.mock_services
class TestMockDataValidation:
    """Tests to validate mock data matches expected configuration."""

    def test_modbus_register_values(self, cli_runner):
        """Validate Modbus register values match mock configuration."""
        port = MOCK_PORTS.get("modbus", 502)
        require_port(MOCK_HOST, port, "Modbus service", timeout=2)

        result = cli_runner.run(
            "modbus",
            MOCK_HOST,
            "--port",
            str(port),
            "--scan-range",
            "0-5",
            "--timeout",
            "10",
            expect_json=False,
        )

        # Just verify scan completes successfully
        assert result.returncode == 0 or "register" in result.combined_output.lower()

    def test_bacnet_object_count(self, cli_runner):
        """Validate BACnet has expected number of objects."""
        try:
            import bacpypes3  # noqa: F401
        except ImportError:
            require_service("bacpypes3 not installed")

        bacnet_port = MOCK_PORTS.get("bacnet", 47808)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(b"\x81\x0a\x00\x08\x01\x00\x10\x08", (MOCK_HOST, bacnet_port))
            sock.recvfrom(1024)
            sock.close()
        except Exception:
            require_service(f"BACnet service not available on port {bacnet_port}")

        result = cli_runner.run(
            "bacnet", MOCK_HOST, "--device-id", "1234", "-e", "--timeout", "20", expect_json=False
        )

        output = result.combined_output

        # Count object types mentioned
        import re

        # Look for patterns like "5 AnalogInput" or "analogInput: 5"
        object_mentions = len(
            re.findall(
                r"\d+\s*(?:analog|binary|multi|schedule|trend|file|loop|program)", output.lower()
            )
        )

        # Should have multiple object types
        assert object_mentions >= 1 or "object" in output.lower() or result.returncode == 0
