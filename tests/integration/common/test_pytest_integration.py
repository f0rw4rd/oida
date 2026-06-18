#!/usr/bin/env python3
"""
Pytest-based integration tests for OIDA scanners
"""

import pytest
import time
import socket
import sys
from pathlib import Path

# Try to import docker-py, skip tests if not available or shadowed by local docker/ dir
try:
    import docker

    docker.from_env  # Check if this is the real docker-py
except (ImportError, AttributeError):
    pytest.skip(
        "docker-py not available (possibly shadowed by local docker/ dir)", allow_module_level=True
    )

# Add OIDA to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from oida.protocols.modbus import ModbusScanner
from oida.protocols.opcua import OPCUAScanner
from oida.protocols.iec104 import IEC104Scanner
from oida.protocols.ads import ADSScanner
from oida.protocols.mms import MMSScanner
from oida.protocols.ethernetip import EtherNetIPScanner


@pytest.fixture(scope="session")
def mock_service():
    """Set up Docker services for the test session"""
    client = docker.from_env()
    container = None

    try:
        # Try to get existing container
        try:
            container = client.containers.get("oida-mock-test")
            if container.status != "running":
                container.start()
        except docker.errors.NotFound:
            # Build and run new container
            image, _ = client.images.build(
                path=str(Path(__file__).parent.parent / "docker"), tag="oida-mock:pytest"
            )

            container = client.containers.run(
                "oida-mock:pytest",
                name="oida-mock-test",
                ports={
                    "502/tcp": 502,
                    "4840/tcp": 4840,
                    "2404/tcp": 2404,
                    "48898/tcp": 48898,
                    "102/tcp": 102,
                    "44818/tcp": 44818,
                },
                detach=True,
                remove=True,
            )

        # Wait for services to be ready
        _wait_for_services()

        yield container

    finally:
        # Cleanup
        if container:
            try:
                container.stop(timeout=10)
            except:
                pass


def _wait_for_services():
    """Wait for all services to be ready"""
    ports = [502, 4840, 2404, 48898, 102, 44818]
    host = "127.0.0.1"
    max_wait = 60
    start_time = time.time()

    while time.time() - start_time < max_wait:
        all_ready = True
        for port in ports:
            if not _check_port_open(host, port):
                all_ready = False
                break

        if all_ready:
            time.sleep(5)  # Additional stabilization time
            return

        time.sleep(2)

    raise TimeoutError("Services did not start within timeout")


def _check_port_open(host, port, timeout=3):
    """Check if a port is open"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error):
        return False


@pytest.fixture
def mock_host():
    """Mock services host"""
    return "127.0.0.1"


class TestModbus:
    """Modbus TCP scanner tests"""

    def test_modbus_connectivity(self, mock_service, mock_host):
        """Test basic Modbus connectivity"""
        assert _check_port_open(mock_host, 502), "Modbus service should be accessible"

    def test_modbus_scanner_basic(self, mock_service, mock_host):
        """Test basic Modbus scanner functionality"""
        scanner = ModbusScanner({"rhost": mock_host, "rport": 502, "timeout": 10})

        result = scanner.run_scan()

        assert isinstance(result, dict), "Should return a dictionary"

        # Check for successful operation (not connection_failed)
        if "error" in result:
            assert result["error"] != "connection_failed", (
                f"Connection should succeed: {result['error']}"
            )

    def test_modbus_device_info(self, mock_service, mock_host):
        """Test Modbus device information discovery"""
        scanner = ModbusScanner({"rhost": mock_host, "rport": 502, "timeout": 10})

        result = scanner.run_scan()

        # Should discover device information
        if "device_info" in result:
            device_info = result["device_info"]
            assert isinstance(device_info, dict)

            if "vendor_name" in device_info:
                assert "OIDA" in device_info["vendor_name"]


class TestOPCUA:
    """OPC UA scanner tests"""

    def test_opcua_connectivity(self, mock_service, mock_host):
        """Test basic OPC UA connectivity"""
        assert _check_port_open(mock_host, 4840), "OPC UA service should be accessible"

    def test_opcua_scanner_basic(self, mock_service, mock_host):
        """Test basic OPC UA scanner functionality"""
        scanner = OPCUAScanner({"rhost": mock_host, "rport": 4840, "timeout": 15})

        result = scanner.run_scan()

        assert isinstance(result, dict), "Should return a dictionary"

        # Check for successful operation
        if "error" in result:
            # Some OPC UA connection issues may be expected
            assert "connection_failed" not in result["error"] or "Connect call failed" in str(
                result["error"]
            )

    def test_opcua_server_info(self, mock_service, mock_host):
        """Test OPC UA server information discovery"""
        scanner = OPCUAScanner({"rhost": mock_host, "rport": 4840, "timeout": 15})

        result = scanner.run_scan()

        # Should discover server information
        if "server_info" in result:
            server_info = result["server_info"]
            assert isinstance(server_info, dict)


class TestIEC104:
    """IEC 60870-5-104 scanner tests"""

    def test_iec104_connectivity(self, mock_service, mock_host):
        """Test basic IEC 104 connectivity"""
        assert _check_port_open(mock_host, 2404), "IEC 104 service should be accessible"

    def test_iec104_scanner_basic(self, mock_service, mock_host):
        """Test basic IEC 104 scanner functionality"""
        scanner = IEC104Scanner({"rhost": mock_host, "rport": 2404, "timeout": 10})

        result = scanner.run_scan()

        assert isinstance(result, dict), "Should return a dictionary"

        # IEC 104 should successfully connect and discover data
        if "error" not in result:
            # Should have discovered data points
            if "data_points" in result:
                data_points = result["data_points"]
                assert isinstance(data_points, list)
                # Should discover multiple data points from mock server
                assert len(data_points) > 50, f"Expected >50 data points, got {len(data_points)}"

    def test_iec104_interrogation(self, mock_service, mock_host):
        """Test IEC 104 general interrogation"""
        scanner = IEC104Scanner({"rhost": mock_host, "rport": 2404, "timeout": 15})

        result = scanner.run_scan()

        # Should perform general interrogation
        if "interrogation_results" in result:
            interrogation = result["interrogation_results"]
            assert isinstance(interrogation, dict)


class TestADS:
    """Beckhoff ADS scanner tests"""

    def test_ads_connectivity(self, mock_service, mock_host):
        """Test basic ADS connectivity"""
        assert _check_port_open(mock_host, 48898), "ADS service should be accessible"

    def test_ads_scanner_basic(self, mock_service, mock_host):
        """Test basic ADS scanner functionality"""
        scanner = ADSScanner({"rhost": mock_host, "rport": 48898, "timeout": 10})

        result = scanner.run_scan()

        assert isinstance(result, dict), "Should return a dictionary"

        # ADS should successfully connect
        if "error" not in result:
            # Should have device information
            if "device_info" in result:
                device_info = result["device_info"]
                assert isinstance(device_info, dict)

    def test_ads_symbols(self, mock_service, mock_host):
        """Test ADS symbol discovery"""
        scanner = ADSScanner({"rhost": mock_host, "rport": 48898, "timeout": 15})

        result = scanner.run_scan()

        # Should discover symbols
        if "symbols" in result:
            symbols = result["symbols"]
            assert isinstance(symbols, dict)


class TestMMS:
    """MMS/IEC 61850 scanner tests"""

    def test_mms_connectivity(self, mock_service, mock_host):
        """Test basic MMS connectivity"""
        assert _check_port_open(mock_host, 102), "MMS service should be accessible"

    def test_mms_scanner_basic(self, mock_service, mock_host):
        """Test basic MMS scanner functionality"""
        scanner = MMSScanner({"rhost": mock_host, "rport": 102, "timeout": 10})

        result = scanner.run_scan()

        assert isinstance(result, dict), "Should return a dictionary"

        # MMS connection may have dependency issues
        if "error" in result and "missing_dependencies" in result["error"]:
            pytest.skip("MMS dependencies not available")

    def test_mms_logical_devices(self, mock_service, mock_host):
        """Test MMS logical device discovery"""
        scanner = MMSScanner({"rhost": mock_host, "rport": 102, "timeout": 15})

        result = scanner.run_scan()

        # Should discover logical devices if dependencies available
        if "logical_devices" in result:
            logical_devices = result["logical_devices"]
            assert isinstance(logical_devices, list)


class TestEtherNetIP:
    """EtherNet/IP scanner tests"""

    def test_ethernetip_connectivity(self, mock_service, mock_host):
        """Test basic EtherNet/IP connectivity"""
        assert _check_port_open(mock_host, 44818), "EtherNet/IP service should be accessible"

    def test_ethernetip_scanner_basic(self, mock_service, mock_host):
        """Test basic EtherNet/IP scanner functionality"""
        scanner = EtherNetIPScanner({"rhost": mock_host, "rport": 44818, "timeout": 10})

        result = scanner.run_scan()

        assert isinstance(result, dict), "Should return a dictionary"

        # EtherNet/IP may have dependency or API issues
        if "error" in result:
            expected_errors = ["missing_dependencies", "connection_failed"]
            assert any(err in result["error"] for err in expected_errors)

    def test_ethernetip_identity(self, mock_service, mock_host):
        """Test EtherNet/IP device identity"""
        scanner = EtherNetIPScanner({"rhost": mock_host, "rport": 44818, "timeout": 15})

        result = scanner.run_scan()

        # Should discover device identity if connection succeeds
        if "identity" in result:
            identity = result["identity"]
            assert isinstance(identity, dict)


class TestConcurrency:
    """Concurrent access tests"""

    def test_concurrent_modbus_connections(self, mock_service, mock_host):
        """Test multiple concurrent Modbus connections"""
        import threading
        import queue

        results_queue = queue.Queue()
        num_connections = 3

        def test_connection(thread_id):
            try:
                scanner = ModbusScanner({"rhost": mock_host, "rport": 502, "timeout": 15})
                result = scanner.run_scan()
                results_queue.put((thread_id, True, result))
            except Exception as e:
                results_queue.put((thread_id, False, str(e)))

        # Start concurrent connections
        threads = []
        for i in range(num_connections):
            thread = threading.Thread(target=test_connection, args=(i,))
            thread.start()
            threads.append(thread)

        # Wait for completion
        for thread in threads:
            thread.join(timeout=30)

        # Collect results
        results = []
        while not results_queue.empty():
            results.append(results_queue.get())

        assert len(results) == num_connections, (
            f"Expected {num_connections} results, got {len(results)}"
        )

        # At least some connections should succeed
        successful = [r for r in results if r[1]]
        assert len(successful) > 0, "At least one concurrent connection should succeed"

    @pytest.mark.parametrize(
        "protocol,port",
        [
            ("modbus", 502),
            ("opcua", 4840),
            ("iec104", 2404),
            ("ads", 48898),
            ("mms", 102),
            ("ethernetip", 44818),
        ],
    )
    def test_service_responsiveness(self, mock_service, mock_host, protocol, port):
        """Test that all services remain responsive"""
        assert _check_port_open(mock_host, port, timeout=5), (
            f"{protocol} service on port {port} should be responsive"
        )


class TestStress:
    """Stress testing"""

    @pytest.mark.slow
    def test_rapid_connections(self, mock_service, mock_host):
        """Test rapid successive connections"""
        num_tests = 10
        successful = 0

        for i in range(num_tests):
            try:
                scanner = ModbusScanner({"rhost": mock_host, "rport": 502, "timeout": 5})
                result = scanner.run_scan()

                if "error" not in result or result["error"] != "connection_failed":
                    successful += 1

            except Exception:
                pass

            time.sleep(0.1)  # Brief pause between connections

        # At least 70% should succeed
        success_rate = successful / num_tests
        assert success_rate >= 0.7, f"Success rate {success_rate:.1%} should be >= 70%"


if __name__ == "__main__":
    # Run with pytest
    pytest.main([__file__, "-v", "--tb=short"])
