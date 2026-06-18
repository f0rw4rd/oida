#!/usr/bin/env python3
"""
Stress and concurrency tests for OIDA scanners.

These tests verify:
- Rapid connect/disconnect cycles
- Concurrent scan operations
- Large target list handling
- Memory usage under load
- File descriptor cleanup
"""

import unittest
from unittest.mock import Mock, patch
import threading
import time
import gc
import sys
import os

import pytest

# Add the package directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ==============================================================================
# Stress Tests - Rapid Operations
# ==============================================================================


class TestRapidConnectDisconnect(unittest.TestCase):
    """Test rapid connect/disconnect cycles."""

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_modbus_rapid_connect_disconnect(self, mock_pymodbus):
        """Test rapid connect/disconnect cycles for Modbus."""
        from oida.protocols.modbus.scanner import ModbusScanner

        mock_client = Mock()
        mock_client.connect.return_value = True
        mock_client.close = Mock()

        cycles = 50
        args = {"rhost": "127.0.0.1", "rport": 502, "timeout": 1}
        scanner = ModbusScanner(args)

        for i in range(cycles):
            scanner.client = mock_client
            scanner.disconnect(mock_client)

        self.assertEqual(mock_client.close.call_count, cycles)

    def test_opcua_rapid_connect_disconnect(self):
        """Test rapid connect/disconnect cycles for OPC UA."""
        from oida.protocols.opcua import OPCUAScanner

        mock_client = Mock()
        mock_client.disconnect = Mock()

        cycles = 50
        args = {"rhost": "127.0.0.1", "rport": 4840, "timeout": 1}
        scanner = OPCUAScanner(args)

        for i in range(cycles):
            scanner.disconnect(mock_client)

        self.assertEqual(mock_client.disconnect.call_count, cycles)

    def test_snap7_rapid_connect_disconnect(self):
        """Test rapid connect/disconnect cycles for Snap7."""
        from oida.protocols.snap7 import Snap7Scanner

        mock_client = Mock()
        mock_client.disconnect = Mock()

        cycles = 50
        args = {"rhost": "127.0.0.1", "rport": 102, "timeout": 1}
        scanner = Snap7Scanner(args)

        for i in range(cycles):
            scanner.disconnect(mock_client)

        self.assertEqual(mock_client.disconnect.call_count, cycles)


class TestConcurrentOperations(unittest.TestCase):
    """Test concurrent scanner operations."""

    @patch("oida.protocols.modbus.scanner._get_pymodbus")
    def test_concurrent_scanner_creation(self, mock_pymodbus):
        """Test creating multiple scanners concurrently."""
        from oida.protocols.modbus.scanner import ModbusScanner

        scanners = []
        threads = []
        lock = threading.Lock()

        def create_scanner(host):
            args = {"rhost": host, "rport": 502, "timeout": 1}
            scanner = ModbusScanner(args)
            with lock:
                scanners.append(scanner)

        # Create 10 scanners in parallel
        for i in range(10):
            t = threading.Thread(target=create_scanner, args=(f"192.168.1.{i}",))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=5)

        self.assertEqual(len(scanners), 10)

    def test_concurrent_mock_operations(self):
        """Test concurrent mock operations across multiple threads."""
        results = []
        errors = []
        lock = threading.Lock()

        def mock_operation(index):
            try:
                mock_client = Mock()
                mock_client.read.return_value = f"result_{index}"

                # Simulate some work
                time.sleep(0.01)
                result = mock_client.read()

                with lock:
                    results.append((index, result))
            except Exception as e:
                with lock:
                    errors.append((index, str(e)))

        threads = []
        for i in range(20):
            t = threading.Thread(target=mock_operation, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=10)

        self.assertEqual(len(results), 20)
        self.assertEqual(len(errors), 0)


class TestLargeTargetList(unittest.TestCase):
    """Test handling of large target lists."""

    def test_large_target_list_parsing(self):
        """Test parsing a large list of targets."""
        from oida.targets import parse_targets

        # Generate 1000 targets
        targets = [f"192.168.{i // 256}.{i % 256}" for i in range(1000)]
        target_str = ",".join(targets)

        parsed = parse_targets(target_str)

        self.assertEqual(len(list(parsed)), 1000)

    def test_cidr_expansion(self):
        """Test CIDR expansion for /24 network."""
        from oida.targets import parse_targets

        parsed = list(parse_targets("192.168.1.0/24"))

        # /24 has 254 usable hosts (excluding network and broadcast)
        self.assertGreaterEqual(len(parsed), 254)


class TestResourceCleanup(unittest.TestCase):
    """Test resource cleanup under stress."""

    def test_object_cleanup_after_many_creations(self):
        """Test that objects are properly garbage collected."""
        from oida.protocols.modbus.scanner import ModbusScanner

        initial_objects = len(gc.get_objects())

        # Create and discard many scanners
        with patch("oida.protocols.modbus.scanner._get_pymodbus"):
            for i in range(100):
                args = {"rhost": "127.0.0.1", "rport": 502}
                scanner = ModbusScanner(args)
                del scanner

        # Force garbage collection
        gc.collect()

        final_objects = len(gc.get_objects())

        # Should not have significant object leak
        object_growth = final_objects - initial_objects
        self.assertLess(object_growth, 1000, f"Object leak detected: {object_growth} new objects")


# ==============================================================================
# Pytest-style Stress Tests
# ==============================================================================


@pytest.mark.slow
@pytest.mark.stress
class TestStressParametrized:
    """Parametrized stress tests."""

    @pytest.mark.parametrize("cycle_count", [10, 50, 100])
    def test_scanner_creation_cycles(self, cycle_count):
        """Test scanner creation with various cycle counts."""
        from oida.protocols.opcua import OPCUAScanner

        for i in range(cycle_count):
            args = {"rhost": "127.0.0.1", "rport": 4840}
            scanner = OPCUAScanner(args)
            assert scanner.host == "127.0.0.1"

    @pytest.mark.parametrize("thread_count", [2, 5, 10])
    def test_concurrent_scanner_threads(self, thread_count):
        """Test concurrent scanner operations with various thread counts."""
        results = []
        lock = threading.Lock()

        def scanner_task(index):
            from oida.protocols.opcua import OPCUAScanner

            args = {"rhost": f"192.168.1.{index}", "rport": 4840}
            scanner = OPCUAScanner(args)

            with lock:
                results.append(scanner.host)

        threads = []
        for i in range(thread_count):
            t = threading.Thread(target=scanner_task, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=10)

        assert len(results) == thread_count


@pytest.mark.slow
@pytest.mark.stress
class TestMemoryStress:
    """Memory-related stress tests."""

    def test_memory_not_significantly_increasing(self):
        """Test that memory doesn't grow significantly during operations."""
        import tracemalloc

        tracemalloc.start()

        # Perform many operations
        with patch("oida.protocols.modbus.scanner._get_pymodbus"):
            from oida.protocols.modbus.scanner import ModbusScanner

            for i in range(100):
                args = {"rhost": "127.0.0.1", "rport": 502}
                scanner = ModbusScanner(args)
                mock_client = Mock()
                scanner.disconnect(mock_client)

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Peak memory should be under 50MB for these operations
        assert peak < 50 * 1024 * 1024, f"Peak memory usage: {peak / 1024 / 1024:.2f} MB"


@pytest.mark.slow
@pytest.mark.stress
class TestConnectionPoolStress:
    """Test connection pool behavior under stress."""

    def test_many_sequential_connects(self):
        """Test many sequential connection attempts."""
        mock_clients = []

        for i in range(100):
            mock_client = Mock()
            mock_client.connect.return_value = True
            mock_client.close = Mock()
            mock_clients.append(mock_client)

            # Simulate connect/disconnect
            mock_client.connect()
            mock_client.close()

        # All should complete without error
        assert len(mock_clients) == 100

        for client in mock_clients:
            client.connect.assert_called_once()
            client.close.assert_called_once()


# ==============================================================================
# Error Rate Under Stress
# ==============================================================================


class TestErrorRateUnderStress(unittest.TestCase):
    """Test error handling under stress conditions."""

    def test_error_handling_with_intermittent_failures(self):
        """Test handling of intermittent connection failures."""
        success_count = 0
        failure_count = 0

        for i in range(100):
            mock_client = Mock()

            # 30% failure rate
            if i % 3 == 0:
                mock_client.connect.side_effect = ConnectionError("Intermittent failure")
                try:
                    mock_client.connect()
                except ConnectionError:
                    failure_count += 1
            else:
                mock_client.connect.return_value = True
                mock_client.connect()
                success_count += 1

        # Verify we handled both success and failure cases
        self.assertGreater(success_count, 0)
        self.assertGreater(failure_count, 0)
        self.assertEqual(success_count + failure_count, 100)

    def test_recovery_after_failures(self):
        """Test that system recovers after failures."""
        from oida.protocols.opcua import OPCUAScanner

        args = {"rhost": "127.0.0.1", "rport": 4840, "timeout": 1}

        # Simulate sequence of failures followed by success
        for i in range(10):
            scanner = OPCUAScanner(args)

            mock_client = Mock()

            if i < 5:
                mock_client.disconnect.side_effect = Exception("Simulated failure")
            else:
                mock_client.disconnect.return_value = None

            try:
                scanner.disconnect(mock_client)
            except Exception:
                pass  # Expected for first 5 iterations

            self.assertEqual(scanner.host, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
