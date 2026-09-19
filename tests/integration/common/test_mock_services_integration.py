#!/usr/bin/env python3
"""
Integration tests for OIDA scanners against mock services
"""

import unittest
import time
import socket
import sys
import os
import json
from typing import Dict, Any

# Try to import Docker library (may not be available)
try:
    import docker

    DOCKER_AVAILABLE = hasattr(docker, "from_env")
except ImportError:
    DOCKER_AVAILABLE = False
    docker = None

# Import OIDA scanners
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from oida.protocols.modbus import ModbusScanner
from oida.protocols.opcua import OPCUAScanner
from oida.protocols.iec104 import IEC104Scanner
from oida.protocols.ads import ADSScanner
from oida.protocols.mms import MMSScanner
from oida.protocols.ethernetip import EtherNetIPScanner


class MockServicesIntegrationTest(unittest.TestCase):
    """Integration tests for OIDA scanners against Docker mock services"""

    @classmethod
    def setUpClass(cls):
        """Set up mock services container before running tests"""
        if not DOCKER_AVAILABLE:
            raise unittest.SkipTest("Docker library not available - skipping integration tests")

        cls.docker_client = docker.from_env()
        cls.container = None
        cls.mock_host = "127.0.0.1"

        # Protocol configurations. opcua targets the insecure anonymous-only
        # server (compose "opcua-insecure", host port 4842) rather than the
        # 4840 default, which requires credentials this harness doesn't supply.
        cls.protocols = {
            "modbus": {"port": 502, "scanner": ModbusScanner},
            "opcua": {"port": 4842, "scanner": OPCUAScanner},
            "iec104": {"port": 2404, "scanner": IEC104Scanner},
            "ads": {"port": 48898, "scanner": ADSScanner},
            "mms": {"port": 102, "scanner": MMSScanner},
            "ethernetip": {"port": 44818, "scanner": EtherNetIPScanner},
        }

        # This legacy harness builds a single monolithic "oida-mock-test"
        # container; the project has since moved to per-service compose mocks
        # (see services.py / docker/mocks/compose.yml) and the dedicated
        # test_<proto>_integration.py suites. If the compose mocks are already
        # serving the required ports, use them (same fallback as
        # test_pytest_integration.py's mock_service fixture); otherwise try the
        # legacy build, and if that is unavailable skip rather than error —
        # the per-protocol suites are the real coverage.
        try:
            if all(
                cls._check_port_open(cls.mock_host, cfg["port"]) for cfg in cls.protocols.values()
            ):
                print("Per-service compose mocks already serving required ports")
                return
            cls._start_mock_services()
            cls._wait_for_services()
        except Exception as e:
            raise unittest.SkipTest(
                f"Legacy monolithic mock container unavailable ({e}); "
                "per-protocol test_<proto>_integration.py suites cover these scanners"
            )

    @classmethod
    def tearDownClass(cls):
        """Clean up mock services container after tests"""
        cls._stop_mock_services()

    @classmethod
    def _start_mock_services(cls):
        """Start the mock services Docker container"""
        print("Starting OIDA mock services container...")

        try:
            # Check if container already exists
            try:
                cls.container = cls.docker_client.containers.get("oida-mock-test")
                if cls.container.status != "running":
                    cls.container.start()
                else:
                    print("Container already running")
                    return
            except docker.errors.NotFound:
                # Build and run new container
                print("Building mock services container...")

                # Build image
                docker_path = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docker"
                )
                image, logs = cls.docker_client.images.build(path=docker_path, tag="oida-mock:test")

                # Run container
                cls.container = cls.docker_client.containers.run(
                    "oida-mock:test",
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

            print(f"Container started: {cls.container.id[:12]}")

        except Exception as e:
            print(f"Failed to start mock services: {e}")
            raise

    @classmethod
    def _stop_mock_services(cls):
        """Stop the mock services container"""
        if cls.container:
            try:
                print("Stopping mock services container...")
                cls.container.stop(timeout=10)
                print("Container stopped")
            except Exception as e:
                print(f"Error stopping container: {e}")

    @classmethod
    def _wait_for_services(cls):
        """Wait for all services to be ready"""
        print("Waiting for services to be ready...")

        max_wait = 60  # seconds
        start_time = time.time()

        while time.time() - start_time < max_wait:
            all_ready = True

            for protocol, config in cls.protocols.items():
                if not cls._check_port_open(cls.mock_host, config["port"]):
                    all_ready = False
                    print(f"  Waiting for {protocol} on port {config['port']}...")
                    break

            if all_ready:
                print("All services are ready!")
                time.sleep(5)  # Additional time for services to fully initialize
                return

            time.sleep(2)

        raise TimeoutError("Services did not start within timeout period")

    @classmethod
    def _check_port_open(cls, host: str, port: int, timeout: int = 3) -> bool:
        """Check if a port is open"""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, socket.error):
            return False

    def _run_scanner_test(self, protocol: str, expected_results: Dict[str, Any]) -> Dict[str, Any]:
        """Run a scanner test and validate results"""
        config = self.protocols[protocol]
        scanner_class = config["scanner"]

        # Create scanner with test parameters
        args = {"rhost": self.mock_host, "rport": config["port"], "timeout": 10, "debug": False}

        # Add protocol-specific parameters
        if protocol == "knx":
            args["interface"] = "enp0s3"
        elif protocol == "ethercat":
            args["interface"] = "enp0s3"
        elif protocol == "modbus":
            # _scan_registers() requires a parseable address range; the
            # per-protocol integration suite exercises the full flag matrix,
            # here we just need a small window for the register tables.
            args["scan-range"] = "0-30"

        print(f"\nTesting {protocol.upper()} scanner...")

        try:
            scanner = scanner_class(args)
            result = scanner.run_scan()

            # Validate basic result structure
            self.assertIsInstance(result, dict, f"{protocol} should return a dictionary")

            # Check for successful connection (no connection errors)
            if "error" in result:
                error = result["error"]
                # Some connection failures are expected for certain protocols
                if error in ["connection_failed", "missing_dependencies"]:
                    print(f"  Expected connection issue for {protocol}: {error}")
                    return result
                else:
                    self.fail(f"{protocol} returned unexpected error: {error}")

            # Validate expected results
            for key, expected_value in expected_results.items():
                if key in result:
                    actual_value = result[key]
                    if isinstance(expected_value, type):
                        self.assertIsInstance(
                            actual_value,
                            expected_value,
                            f"{protocol} {key} should be {expected_value}",
                        )
                    elif isinstance(expected_value, dict):
                        self.assertIsInstance(
                            actual_value, dict, f"{protocol} {key} should be a dictionary"
                        )
                        # Check nested requirements
                        for nested_key, nested_expected in expected_value.items():
                            if nested_key in actual_value:
                                if isinstance(nested_expected, type):
                                    self.assertIsInstance(actual_value[nested_key], nested_expected)
                    else:
                        self.assertEqual(
                            actual_value,
                            expected_value,
                            f"{protocol} {key} should be {expected_value}",
                        )

            print(f"  ✅ {protocol.upper()} test passed")
            return result

        except Exception as e:
            print(f"  ❌ {protocol.upper()} test failed: {e}")
            raise

    def test_modbus_scanner(self):
        """Test Modbus TCP scanner against mock service"""
        expected = {
            "device_info": dict,
            "holding_registers": dict,
            "input_registers": dict,
            "coils": dict,
            "discrete_inputs": dict,
            "security_analysis": dict,
        }

        result = self._run_scanner_test("modbus", expected)

        # Modbus-specific validations
        if "device_info" in result:
            device_info = result["device_info"]
            if "vendor_name" in device_info:
                self.assertIn("OIDA", device_info["vendor_name"])

    def test_opcua_scanner(self):
        """Test OPC UA scanner against mock service"""
        expected = {
            "server_info": dict,
            "namespaces": list,
            "nodes": dict,
            "security_analysis": dict,
        }

        result = self._run_scanner_test("opcua", expected)

        # OPC UA-specific validations
        if "server_info" in result:
            server_info = result["server_info"]
            if "server_name" in server_info:
                self.assertIn("OIDA", server_info["server_name"])

    def test_iec104_scanner(self):
        """Test IEC 60870-5-104 scanner against mock service"""
        expected = {
            "station_info": dict,
            "data_points": dict,
            "interrogation_results": dict,
            "security_analysis": dict,
        }

        result = self._run_scanner_test("iec104", expected)

        # IEC 104-specific validations (data_points: IOA -> discovered-point
        # dict since the scanner refactor; count via keys)
        if "data_points" in result:
            data_points = result["data_points"]
            if data_points:
                self.assertGreater(len(data_points), 5, "Should discover multiple data points")

    def test_ads_scanner(self):
        """Test Beckhoff ADS scanner against mock service"""
        # routes became a dict (netid-keyed) and the scan now also reports
        # the route/state-discovery summary (local/target/discovered[...]).
        expected = {"device_info": dict, "symbols": dict, "routes": dict, "security_analysis": dict}

        result = self._run_scanner_test("ads", expected)

        # ADS-specific validations
        if "device_info" in result:
            device_info = result["device_info"]
            if "device_name" in device_info:
                self.assertIn("TwinCAT", device_info["device_name"])

    def test_mms_scanner(self):
        """Test MMS/IEC 61850 scanner against mock service"""
        expected = {
            "server_info": dict,
            "logical_devices": list,
            "logical_nodes": list,
            "data_objects": list,
            "security_analysis": dict,
        }

        result = self._run_scanner_test("mms", expected)

        # MMS-specific validations
        if "logical_devices" in result:
            logical_devices = result["logical_devices"]
            if logical_devices:
                self.assertGreater(len(logical_devices), 0, "Should discover logical devices")

    def test_ethernetip_scanner(self):
        """Test EtherNet/IP scanner against mock service"""
        expected = {
            "device_info": dict,
            "identity": dict,
            "classes": list,
            "security_analysis": dict,
        }

        result = self._run_scanner_test("ethernetip", expected)

        # EtherNet/IP-specific validations
        if "identity" in result:
            identity = result["identity"]
            if "vendor_name" in identity:
                self.assertIsInstance(identity["vendor_name"], str)

    def test_all_services_responsive(self):
        """Test that all mock services are responsive"""
        print("\nTesting service responsiveness...")

        for protocol, config in self.protocols.items():
            port = config["port"]
            with self.subTest(protocol=protocol, port=port):
                is_open = self._check_port_open(self.mock_host, port, timeout=5)
                self.assertTrue(is_open, f"{protocol} service on port {port} should be responsive")
                print(f"  ✅ {protocol.upper()} port {port} is responsive")

    def test_container_health(self):
        """Test that the mock services container is healthy"""
        if self.container:
            # Refresh container info
            self.container.reload()

            # Check container status
            self.assertEqual(self.container.status, "running", "Container should be running")

            # Check container logs for errors
            logs = self.container.logs(tail=50).decode("utf-8")

            # Should not contain critical errors
            error_indicators = ["CRITICAL", "FATAL", "Failed to start"]
            for indicator in error_indicators:
                self.assertNotIn(
                    indicator, logs, f"Container logs should not contain '{indicator}'"
                )

            # Should contain startup messages
            success_indicators = ["started successfully", "server running", "All services started"]
            found_success = any(
                indicator.lower() in logs.lower() for indicator in success_indicators
            )
            self.assertTrue(found_success, "Container logs should indicate successful startup")

    def test_concurrent_connections(self):
        """Test multiple concurrent connections to services"""
        print("\nTesting concurrent connections...")

        import threading
        import queue

        results_queue = queue.Queue()

        def test_protocol(protocol_name):
            try:
                config = self.protocols[protocol_name]
                scanner_class = config["scanner"]

                args = {
                    "rhost": self.mock_host,
                    "rport": config["port"],
                    "timeout": 15,
                    "debug": False,
                }

                if protocol_name in ["knx", "ethercat"]:
                    args["interface"] = "enp0s3"

                scanner = scanner_class(args)
                result = scanner.run_scan()

                results_queue.put((protocol_name, True, result))

            except Exception as e:
                results_queue.put((protocol_name, False, str(e)))

        # Start all tests concurrently
        threads = []
        for protocol in self.protocols.keys():
            thread = threading.Thread(target=test_protocol, args=(protocol,))
            thread.start()
            threads.append(thread)

        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=30)

        # Collect results
        results = {}
        while not results_queue.empty():
            protocol, success, result = results_queue.get()
            results[protocol] = (success, result)

        # Validate results
        for protocol, (success, result) in results.items():
            with self.subTest(protocol=protocol):
                if success:
                    print(f"  ✅ {protocol.upper()} concurrent test passed")
                    self.assertIsInstance(result, dict, f"{protocol} should return a dictionary")
                else:
                    # Some failures are expected due to dependencies or connection issues
                    if any(
                        err in str(result) for err in ["missing_dependencies", "connection_failed"]
                    ):
                        print(f"  ⚠️  {protocol.upper()} expected issue: {result}")
                    else:
                        print(f"  ❌ {protocol.upper()} unexpected failure: {result}")
                        self.fail(f"{protocol} failed unexpectedly: {result}")


class TestRunner:
    """Test runner with enhanced reporting"""

    def __init__(self):
        self.results = {}

    def run_tests(self, verbosity=2):
        """Run all integration tests with detailed reporting"""
        print("=" * 80)
        print("OIDA Mock Services Integration Tests")
        print("=" * 80)

        # Discover and run tests
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromTestCase(MockServicesIntegrationTest)

        # Custom test runner with detailed output
        runner = unittest.TextTestRunner(verbosity=verbosity, stream=sys.stdout, buffer=False)

        result = runner.run(suite)

        # Generate summary report
        self._generate_report(result)

        return result.wasSuccessful()

    def _generate_report(self, result):
        """Generate detailed test report"""
        print("\n" + "=" * 80)
        print("TEST SUMMARY REPORT")
        print("=" * 80)

        total_tests = result.testsRun
        failures = len(result.failures)
        errors = len(result.errors)
        skipped = len(result.skipped) if hasattr(result, "skipped") else 0
        passed = total_tests - failures - errors - skipped

        print(f"Total Tests:    {total_tests}")
        print(f"Passed:         {passed}")
        print(f"Failed:         {failures}")
        print(f"Errors:         {errors}")
        print(f"Skipped:        {skipped}")
        print(f"Success Rate:   {(passed / total_tests) * 100:.1f}%" if total_tests > 0 else "N/A")

        if result.failures:
            print(f"\nFAILURES ({len(result.failures)}):")
            for test, traceback in result.failures:
                print(f"  - {test}: {traceback.split('AssertionError:')[-1].strip()}")

        if result.errors:
            print(f"\nERRORS ({len(result.errors)}):")
            for test, traceback in result.errors:
                print(f"  - {test}: {traceback.split('Error:')[-1].strip()}")

        print("\n" + "=" * 80)

        # Write detailed results to file
        self._write_json_report(result)

    def _write_json_report(self, result):
        """Write JSON test report"""
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_tests": result.testsRun,
            "passed": result.testsRun - len(result.failures) - len(result.errors),
            "failed": len(result.failures),
            "errors": len(result.errors),
            "success_rate": (
                (
                    (result.testsRun - len(result.failures) - len(result.errors))
                    / result.testsRun
                    * 100
                )
                if result.testsRun > 0
                else 0
            ),
            "failures": [{"test": str(test), "message": tb} for test, tb in result.failures],
            "errors": [{"test": str(test), "message": tb} for test, tb in result.errors],
        }

        test_dir = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(test_dir, "test_results.json"), "w") as f:
            json.dump(report, f, indent=2)

        print("Detailed results written to: test_results.json")


if __name__ == "__main__":
    # Check for required dependencies
    if not DOCKER_AVAILABLE:
        print("Error: docker library required. Install with: pip install docker")
        sys.exit(1)

    # Run tests
    runner = TestRunner()
    success = runner.run_tests(verbosity=2)

    sys.exit(0 if success else 1)
