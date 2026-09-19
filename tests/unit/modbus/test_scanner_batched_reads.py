#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for batched register reading in ModbusScanner._scan_register_type().

Verifies that registers are read in batches rather than one at a time,
that the --max-registers argument controls batch size, that partial
batches at the end of a range work correctly, and that batch failures
fall back to individual reads.
"""

import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch, call

from tests.service_gate import require_import

require_import("pymodbus", reason="pymodbus library not installed")


# =============================================================================
# Helpers
# =============================================================================


def _make_register_response(values):
    """Create a mock Modbus response with register values."""
    resp = MagicMock()
    resp.isError.return_value = False
    resp.registers = list(values)
    return resp


def _make_bits_response(values):
    """Create a mock Modbus response with bit values."""
    resp = MagicMock(spec=["isError", "bits"])
    resp.isError.return_value = False
    resp.bits = list(values)
    return resp


def _make_error_response():
    """Create a mock Modbus error response."""
    resp = MagicMock()
    resp.isError.return_value = True
    return resp


def _create_scanner(args_overrides=None):
    """Create a mock ModbusScanner with sensible defaults."""
    from oida.protocols.modbus.scanner import ModbusScanner

    defaults = {
        "rhost": "127.0.0.1",
        "rport": 502,
        "timeout": 5,
        "unit-id": 1,
        "scan-range": "0-9",
        "register-type": "holding",
        "serial-port": "",
        "baudrate": 9600,
        "get-device-id": False,
        "decode-all": False,
        "decode": None,
        "endian": "big",
        "filter-zero": False,
        "read-only": True,
        "max_registers": 125,
    }
    if args_overrides:
        defaults.update(args_overrides)

    with patch.object(ModbusScanner, "__init__", lambda self, *a, **kw: None):
        scanner = ModbusScanner.__new__(ModbusScanner)
        scanner.args = defaults
        scanner.host = defaults["rhost"]
        scanner.port = defaults["rport"]
        scanner.timeout = defaults["timeout"]
        scanner.unit_id = defaults["unit-id"]
        scanner.scan_range = defaults["scan-range"]
        scanner.register_type = defaults["register-type"]
        scanner.read_only = defaults.get("read-only", True)
        scanner.logger = MagicMock()
        scanner.security = MagicMock()
        return scanner


# =============================================================================
# _build_batches tests
# =============================================================================


class TestBuildBatches:
    """Tests for the static _build_batches helper that groups addresses."""

    def test_contiguous_range_single_batch(self):
        """A contiguous range <= max_batch produces one batch."""
        from oida.protocols.modbus.scanner import ModbusScanner

        batches = ModbusScanner._build_batches(list(range(10)), max_batch=125)
        assert len(batches) == 1
        start, count, addrs = batches[0]
        assert start == 0
        assert count == 10
        assert addrs == list(range(10))

    def test_contiguous_range_multiple_batches(self):
        """A contiguous range > max_batch is split into multiple batches."""
        from oida.protocols.modbus.scanner import ModbusScanner

        batches = ModbusScanner._build_batches(list(range(300)), max_batch=125)
        assert len(batches) == 3  # 125 + 125 + 50
        assert batches[0] == (0, 125, list(range(0, 125)))
        assert batches[1] == (125, 125, list(range(125, 250)))
        assert batches[2] == (250, 50, list(range(250, 300)))

    def test_non_contiguous_range(self):
        """Non-contiguous addresses produce separate batches."""
        from oida.protocols.modbus.scanner import ModbusScanner

        addrs = [0, 1, 2, 10, 11, 12]
        batches = ModbusScanner._build_batches(addrs, max_batch=125)
        assert len(batches) == 2
        assert batches[0] == (0, 3, [0, 1, 2])
        assert batches[1] == (10, 3, [10, 11, 12])

    def test_single_address(self):
        """A single address produces a single batch of size 1."""
        from oida.protocols.modbus.scanner import ModbusScanner

        batches = ModbusScanner._build_batches([42], max_batch=125)
        assert len(batches) == 1
        assert batches[0] == (42, 1, [42])

    def test_empty_range(self):
        """Empty address range produces no batches."""
        from oida.protocols.modbus.scanner import ModbusScanner

        batches = ModbusScanner._build_batches([], max_batch=125)
        assert batches == []

    def test_range_not_starting_at_zero(self):
        """Address range starting at a non-zero offset works correctly."""
        from oida.protocols.modbus.scanner import ModbusScanner

        addrs = list(range(1000, 1010))
        batches = ModbusScanner._build_batches(addrs, max_batch=125)
        assert len(batches) == 1
        assert batches[0] == (1000, 10, addrs)

    def test_max_batch_of_one(self):
        """max_batch=1 produces one batch per address (individual reads)."""
        from oida.protocols.modbus.scanner import ModbusScanner

        addrs = list(range(5))
        batches = ModbusScanner._build_batches(addrs, max_batch=1)
        assert len(batches) == 5
        for i, (start, count, batch_addrs) in enumerate(batches):
            assert start == i
            assert count == 1
            assert batch_addrs == [i]

    def test_batch_boundary_exact(self):
        """Range exactly divisible by max_batch produces correct batches."""
        from oida.protocols.modbus.scanner import ModbusScanner

        batches = ModbusScanner._build_batches(list(range(250)), max_batch=125)
        assert len(batches) == 2
        assert batches[0][1] == 125
        assert batches[1][1] == 125


# =============================================================================
# Batched reading via _scan_register_type
# =============================================================================


class TestBatchedHoldingRegisterReads:
    """Tests that holding registers are read in batches."""

    def test_small_range_single_batch(self):
        """A range of 10 addresses issues one batch read, not 10 individual reads."""
        scanner = _create_scanner()
        client = MagicMock()

        resp = _make_register_response(list(range(10)))
        client.read_holding_registers.return_value = resp

        results = scanner._scan_register_type(client, "holding_registers", list(range(10)))

        # Should have been called once with count=10, not 10 times with count=1
        assert client.read_holding_registers.call_count == 1
        call_args = client.read_holding_registers.call_args
        assert call_args == call(0, count=10, device_id=1)

        # All 10 addresses should have results
        assert len(results) == 10
        for addr in range(10):
            assert addr in results
            assert results[addr]["readable"] is True
            assert results[addr]["value"] == addr

    def test_large_range_multiple_batches(self):
        """A range of 200 addresses uses multiple batch reads."""
        scanner = _create_scanner()
        client = MagicMock()

        def side_effect(start, count, device_id):
            return _make_register_response(list(range(start, start + count)))

        client.read_holding_registers.side_effect = side_effect

        results = scanner._scan_register_type(client, "holding_registers", list(range(200)))

        # 200 addresses / 125 max = 2 batch calls
        assert client.read_holding_registers.call_count == 2
        assert len(results) == 200

    def test_custom_max_registers(self):
        """--max-registers controls batch size."""
        scanner = _create_scanner({"max_registers": 10})
        client = MagicMock()

        def side_effect(start, count, device_id):
            return _make_register_response([0] * count)

        client.read_holding_registers.side_effect = side_effect

        scanner._scan_register_type(client, "holding_registers", list(range(25)))

        # 25 addresses / 10 batch size = 3 batch calls
        assert client.read_holding_registers.call_count == 3

        # Verify batch sizes: 10, 10, 5
        calls = client.read_holding_registers.call_args_list
        assert calls[0] == call(0, count=10, device_id=1)
        assert calls[1] == call(10, count=10, device_id=1)
        assert calls[2] == call(20, count=5, device_id=1)

    def test_partial_batch_at_end(self):
        """Partial batch at the end of a range returns correct results."""
        scanner = _create_scanner({"max_registers": 4})
        client = MagicMock()

        def side_effect(start, count, device_id):
            return _make_register_response([100 + i for i in range(count)])

        client.read_holding_registers.side_effect = side_effect

        results = scanner._scan_register_type(client, "holding_registers", list(range(7)))

        # 7 addresses / 4 batch = 2 calls (4 + 3)
        assert client.read_holding_registers.call_count == 2
        assert len(results) == 7

    def test_results_match_individual_reads(self):
        """Batched reads produce the same result dict as individual reads would."""
        scanner = _create_scanner({"max_registers": 5})
        client = MagicMock()

        values = [100, 200, 300, 400, 500, 600, 700]

        def side_effect(start, count, device_id):
            return _make_register_response(values[start : start + count])

        client.read_holding_registers.side_effect = side_effect

        results = scanner._scan_register_type(client, "holding_registers", list(range(7)))

        for addr in range(7):
            assert results[addr]["value"] == values[addr]
            assert results[addr]["readable"] is True


class TestBatchedInputRegisterReads:
    """Tests that input registers are batched correctly."""

    def test_input_registers_batched(self):
        """Input registers use batched reads."""
        scanner = _create_scanner()
        client = MagicMock()

        resp = _make_register_response([42] * 5)
        client.read_input_registers.return_value = resp

        results = scanner._scan_register_type(client, "input_registers", list(range(5)))

        assert client.read_input_registers.call_count == 1
        call_args = client.read_input_registers.call_args
        assert call_args == call(0, count=5, device_id=1)
        assert len(results) == 5


class TestBatchedCoilReads:
    """Tests that coils are batched correctly."""

    def test_coils_batched(self):
        """Coils use batched reads."""
        scanner = _create_scanner()
        client = MagicMock()

        resp = _make_bits_response([True, False, True, True, False])
        client.read_coils.return_value = resp

        results = scanner._scan_register_type(client, "coils", list(range(5)))

        assert client.read_coils.call_count == 1
        call_args = client.read_coils.call_args
        assert call_args == call(0, count=5, device_id=1)
        assert len(results) == 5
        assert results[0]["value"] is True
        assert results[1]["value"] is False

    def test_coils_higher_batch_limit(self):
        """Coils default to batch size 2000, not 125."""
        scanner = _create_scanner({"max_registers": 2000})
        client = MagicMock()

        n = 500
        resp = _make_bits_response([True] * n)
        client.read_coils.return_value = resp

        scanner._scan_register_type(client, "coils", list(range(n)))

        # All 500 coils in a single request (2000 max for coils)
        assert client.read_coils.call_count == 1


class TestBatchedDiscreteInputReads:
    """Tests that discrete inputs are batched correctly."""

    def test_discrete_inputs_batched(self):
        """Discrete inputs use batched reads."""
        scanner = _create_scanner()
        client = MagicMock()

        resp = _make_bits_response([False, True, False])
        client.read_discrete_inputs.return_value = resp

        results = scanner._scan_register_type(client, "discrete_inputs", list(range(3)))

        assert client.read_discrete_inputs.call_count == 1
        assert len(results) == 3


# =============================================================================
# Fallback to individual reads on batch failure
# =============================================================================


class TestBatchFallback:
    """Tests that batch failures trigger fallback to individual reads."""

    def test_fallback_on_error_response(self):
        """Error response from batch read triggers individual reads."""
        scanner = _create_scanner({"max_registers": 5})
        client = MagicMock()

        # First batch fails, individual reads succeed
        call_count = {"n": 0}

        def side_effect(start, count, device_id):
            call_count["n"] += 1
            if count > 1:
                return _make_error_response()
            return _make_register_response([start * 10])

        client.read_holding_registers.side_effect = side_effect

        results = scanner._scan_register_type(client, "holding_registers", list(range(3)))

        # 1 batch call (fails) + 3 individual calls = 4 total
        assert client.read_holding_registers.call_count == 4
        assert len(results) == 3
        for addr in range(3):
            assert results[addr]["value"] == addr * 10

    def test_fallback_on_exception(self):
        """Exception from batch read triggers individual reads."""
        scanner = _create_scanner({"max_registers": 10})
        client = MagicMock()

        def side_effect(start, count, device_id):
            if count > 1:
                raise ConnectionError("Connection reset")
            return _make_register_response([99])

        client.read_holding_registers.side_effect = side_effect

        results = scanner._scan_register_type(client, "holding_registers", list(range(5)))

        # 1 batch (exception) + 5 individual = 6
        assert client.read_holding_registers.call_count == 6
        assert len(results) == 5

    def test_fallback_partial_success(self):
        """Some individual reads fail during fallback, others succeed."""
        scanner = _create_scanner({"max_registers": 5})
        client = MagicMock()

        def side_effect(start, count, device_id):
            if count > 1:
                return _make_error_response()
            # Only even addresses succeed
            if start % 2 == 0:
                return _make_register_response([start])
            return _make_error_response()

        client.read_holding_registers.side_effect = side_effect

        results = scanner._scan_register_type(client, "holding_registers", list(range(5)))

        # Only addresses 0, 2, 4 should succeed
        assert len(results) == 3
        assert 0 in results
        assert 2 in results
        assert 4 in results
        assert 1 not in results
        assert 3 not in results

    def test_fallback_individual_exception(self):
        """Individual reads that raise exceptions are counted as errors."""
        scanner = _create_scanner({"max_registers": 5})
        client = MagicMock()

        def side_effect(start, count, device_id):
            if count > 1:
                return _make_error_response()
            if start == 2:
                raise TimeoutError("Read timed out")
            return _make_register_response([start])

        client.read_holding_registers.side_effect = side_effect

        results = scanner._scan_register_type(client, "holding_registers", list(range(5)))

        # Address 2 should be missing (exception), others present
        assert 2 not in results
        assert len(results) == 4
        # Warning should have been logged about failed addresses
        scanner.logger.warning.assert_called()

    def test_short_response_triggers_fallback(self):
        """A batch response with fewer values than expected triggers fallback."""
        scanner = _create_scanner({"max_registers": 10})
        client = MagicMock()

        call_num = {"n": 0}

        def side_effect(start, count, device_id):
            call_num["n"] += 1
            if call_num["n"] == 1:
                # First call: batch returns too few registers
                return _make_register_response([1, 2])  # Expected 5, got 2
            # Individual reads succeed
            return _make_register_response([start * 10])

        client.read_holding_registers.side_effect = side_effect

        results = scanner._scan_register_type(client, "holding_registers", list(range(5)))

        # 1 batch (short) + 5 individual = 6
        assert client.read_holding_registers.call_count == 6
        assert len(results) == 5


# =============================================================================
# Non-contiguous address ranges
# =============================================================================


class TestNonContiguousRanges:
    """Tests for non-contiguous address ranges."""

    def test_gap_in_range(self):
        """A gap in the address range produces separate batch reads."""
        scanner = _create_scanner()
        client = MagicMock()

        def side_effect(start, count, device_id):
            return _make_register_response([start + i for i in range(count)])

        client.read_holding_registers.side_effect = side_effect

        # Two contiguous runs: 0-2 and 10-12
        addrs = [0, 1, 2, 10, 11, 12]
        results = scanner._scan_register_type(client, "holding_registers", addrs)

        # Two batch calls: one for 0-2, one for 10-12
        assert client.read_holding_registers.call_count == 2
        assert len(results) == 6

        # Values should match their addresses
        assert results[0]["value"] == 0
        assert results[10]["value"] == 10
        assert results[12]["value"] == 12

    def test_scattered_addresses(self):
        """Fully scattered addresses each get individual reads."""
        scanner = _create_scanner()
        client = MagicMock()

        def side_effect(start, count, device_id):
            return _make_register_response([start] * count)

        client.read_holding_registers.side_effect = side_effect

        # Non-contiguous: each address is its own batch
        addrs = [0, 5, 10, 15, 20]
        results = scanner._scan_register_type(client, "holding_registers", addrs)

        assert client.read_holding_registers.call_count == 5
        assert len(results) == 5


# =============================================================================
# Write access testing in batch mode
# =============================================================================


class TestBatchedWriteAccess:
    """Tests that write access testing still works in batch mode."""

    def test_write_access_tested_when_not_read_only(self):
        """Write access is tested for each address when read_only=False."""
        scanner = _create_scanner({"read-only": False})
        client = MagicMock()

        resp = _make_register_response([100, 200, 300])
        client.read_holding_registers.return_value = resp

        # Ordinary read scans use the safe (same-value) write test, not the
        # destructive one -- see _scan_register_type.
        scanner._test_write_access_safe = MagicMock(return_value={"writable": True})

        results = scanner._scan_register_type(client, "holding_registers", list(range(3)))

        assert scanner._test_write_access_safe.call_count == 3
        for addr in range(3):
            assert results[addr]["writable"] is True

    def test_write_access_skipped_in_read_only_mode(self):
        """Write access is not tested when read_only=True."""
        scanner = _create_scanner({"read-only": True})
        client = MagicMock()

        resp = _make_register_response([100, 200, 300])
        client.read_holding_registers.return_value = resp

        scanner._test_write_access_safe = MagicMock()

        results = scanner._scan_register_type(client, "holding_registers", list(range(3)))

        scanner._test_write_access_safe.assert_not_called()
        for addr in range(3):
            assert "writable" not in results[addr]


# =============================================================================
# Edge cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases in batched register reading."""

    def test_empty_address_range(self):
        """Empty address range returns empty results."""
        scanner = _create_scanner()
        client = MagicMock()

        results = scanner._scan_register_type(client, "holding_registers", [])

        assert results == {}
        client.read_holding_registers.assert_not_called()

    def test_single_address(self):
        """Single address still works (batch of 1)."""
        scanner = _create_scanner()
        client = MagicMock()

        resp = _make_register_response([42])
        client.read_holding_registers.return_value = resp

        results = scanner._scan_register_type(client, "holding_registers", [100])

        assert client.read_holding_registers.call_count == 1
        assert client.read_holding_registers.call_args == call(100, count=1, device_id=1)
        assert results[100]["value"] == 42

    def test_max_registers_capped_at_125_for_registers(self):
        """max-registers larger than 125 is capped for holding/input registers."""
        scanner = _create_scanner({"max_registers": 500})
        client = MagicMock()

        def side_effect(start, count, device_id):
            return _make_register_response([0] * count)

        client.read_holding_registers.side_effect = side_effect

        scanner._scan_register_type(client, "holding_registers", list(range(200)))

        # Should cap at 125, so 200 / 125 = 2 calls
        assert client.read_holding_registers.call_count == 2
        first_call = client.read_holding_registers.call_args_list[0]
        assert first_call == call(0, count=125, device_id=1)

    def test_max_registers_capped_at_2000_for_coils(self):
        """max-registers larger than 2000 is capped for coils."""
        scanner = _create_scanner({"max_registers": 5000})
        client = MagicMock()

        def side_effect(start, count, device_id):
            return _make_bits_response([True] * count)

        client.read_coils.side_effect = side_effect

        scanner._scan_register_type(client, "coils", list(range(3000)))

        # Should cap at 2000, so 3000 / 2000 = 2 calls
        assert client.read_coils.call_count == 2
        first_call = client.read_coils.call_args_list[0]
        assert first_call == call(0, count=2000, device_id=1)

    def test_unknown_register_type(self):
        """Unknown register type returns empty results."""
        scanner = _create_scanner()
        client = MagicMock()

        results = scanner._scan_register_type(client, "unknown_type", list(range(5)))

        # _read_batch returns None for unknown types, triggering fallback
        # which also returns None -- no results
        assert len(results) == 0

    def test_all_batches_fail(self):
        """All batch reads fail, all individual reads fail -- error count is correct."""
        scanner = _create_scanner({"max_registers": 5})
        client = MagicMock()

        client.read_holding_registers.return_value = _make_error_response()

        results = scanner._scan_register_type(client, "holding_registers", list(range(5)))

        assert len(results) == 0
        # Should log a warning about failed addresses
        scanner.logger.warning.assert_called_once()
        warning_msg = scanner.logger.warning.call_args[0][0]
        assert "5/5" in warning_msg

    def test_results_contain_timestamps(self):
        """Each result entry contains a timestamp."""
        scanner = _create_scanner()
        client = MagicMock()

        resp = _make_register_response([42, 43])
        client.read_holding_registers.return_value = resp

        results = scanner._scan_register_type(client, "holding_registers", [0, 1])

        for addr in [0, 1]:
            assert "timestamp" in results[addr]
            # Should be a valid ISO format timestamp
            datetime.fromisoformat(results[addr]["timestamp"])


# =============================================================================
# Integration with _scan_registers
# =============================================================================


class TestScanRegistersIntegration:
    """Tests that _scan_registers correctly uses the batched _scan_register_type."""

    def test_scan_registers_holding_only(self):
        """_scan_registers with register_type='holding' only scans holding registers."""
        scanner = _create_scanner({"register-type": "holding", "scan-range": "0-4"})
        client = MagicMock()

        resp = _make_register_response([10, 20, 30, 40, 50])
        client.read_holding_registers.return_value = resp

        results = scanner._scan_registers(client)

        assert len(results["holding_registers"]) == 5
        assert results["coils"] == {}
        assert results["discrete_inputs"] == {}
        assert results["input_registers"] == {}
        # Single batch call
        assert client.read_holding_registers.call_count == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
