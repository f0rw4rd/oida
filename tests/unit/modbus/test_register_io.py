"""
Unit tests for oida.protocols.modbus.register_io -- shared batched register utilities.
"""

import pytest
from unittest.mock import MagicMock

from tests.service_gate import require_import

require_import("pymodbus", reason="pymodbus library not installed")

from oida.protocols.modbus.register_io import (
    normalize_register_type,
    build_batches,
    read_registers_batched,
)


# =============================================================================
# Helpers
# =============================================================================


def _reg_response(values):
    resp = MagicMock()
    resp.isError.return_value = False
    resp.registers = list(values)
    return resp


def _bits_response(values):
    resp = MagicMock(spec=["isError", "bits"])
    resp.isError.return_value = False
    resp.bits = list(values)
    return resp


def _error_response():
    resp = MagicMock()
    resp.isError.return_value = True
    return resp


# =============================================================================
# normalize_register_type
# =============================================================================


class TestNormalizeRegisterType:
    def test_short_holding(self):
        assert normalize_register_type("holding") == "holding_registers"

    def test_short_input(self):
        assert normalize_register_type("input") == "input_registers"

    def test_short_coil(self):
        assert normalize_register_type("coil") == "coils"

    def test_short_discrete(self):
        assert normalize_register_type("discrete") == "discrete_inputs"

    def test_canonical_passthrough(self):
        assert normalize_register_type("holding_registers") == "holding_registers"
        assert normalize_register_type("input_registers") == "input_registers"
        assert normalize_register_type("coils") == "coils"
        assert normalize_register_type("discrete_inputs") == "discrete_inputs"

    def test_unknown_passthrough(self):
        assert normalize_register_type("foobar") == "foobar"


# =============================================================================
# build_batches
# =============================================================================


class TestBuildBatches:
    def test_contiguous_single_batch(self):
        batches = build_batches(list(range(10)), 125)
        assert len(batches) == 1
        assert batches[0] == (0, 10, list(range(10)))

    def test_contiguous_split(self):
        batches = build_batches(list(range(300)), 125)
        assert len(batches) == 3
        assert batches[0] == (0, 125, list(range(0, 125)))
        assert batches[1] == (125, 125, list(range(125, 250)))
        assert batches[2] == (250, 50, list(range(250, 300)))

    def test_non_contiguous(self):
        batches = build_batches([0, 1, 2, 10, 11, 12], 125)
        assert len(batches) == 2
        assert batches[0] == (0, 3, [0, 1, 2])
        assert batches[1] == (10, 3, [10, 11, 12])

    def test_single_address(self):
        batches = build_batches([42], 125)
        assert batches == [(42, 1, [42])]

    def test_empty(self):
        assert build_batches([], 125) == []

    def test_max_batch_one(self):
        batches = build_batches(list(range(3)), 1)
        assert len(batches) == 3
        assert batches[0] == (0, 1, [0])
        assert batches[1] == (1, 1, [1])
        assert batches[2] == (2, 1, [2])

    def test_exact_boundary(self):
        batches = build_batches(list(range(250)), 125)
        assert len(batches) == 2
        assert batches[0][1] == 125
        assert batches[1][1] == 125

    def test_non_zero_start(self):
        addrs = list(range(1000, 1010))
        batches = build_batches(addrs, 125)
        assert batches == [(1000, 10, addrs)]


# =============================================================================
# read_registers_batched
# =============================================================================


class TestReadRegisteredBatched:
    def test_basic_holding(self):
        client = MagicMock()
        client.read_holding_registers.return_value = _reg_response([10, 20, 30])

        result = read_registers_batched(client, "holding_registers", [0, 1, 2])
        assert result == {0: 10, 1: 20, 2: 30}
        client.read_holding_registers.assert_called_once_with(0, count=3, device_id=1)

    def test_short_name_alias(self):
        client = MagicMock()
        client.read_holding_registers.return_value = _reg_response([5])

        result = read_registers_batched(client, "holding", [0])
        assert result == {0: 5}

    def test_input_registers(self):
        client = MagicMock()
        client.read_input_registers.return_value = _reg_response([7, 8])

        result = read_registers_batched(client, "input_registers", [0, 1])
        assert result == {0: 7, 1: 8}

    def test_coils(self):
        client = MagicMock()
        client.read_coils.return_value = _bits_response([True, False])

        result = read_registers_batched(client, "coils", [0, 1])
        assert result == {0: True, 1: False}

    def test_discrete_inputs(self):
        client = MagicMock()
        client.read_discrete_inputs.return_value = _bits_response([False, True])

        result = read_registers_batched(client, "discrete_inputs", [0, 1])
        assert result == {0: False, 1: True}

    def test_empty_addresses(self):
        client = MagicMock()
        assert read_registers_batched(client, "holding", []) == {}

    def test_unknown_type(self):
        client = MagicMock()
        assert read_registers_batched(client, "nonexistent", [0, 1]) == {}

    def test_custom_unit_id(self):
        client = MagicMock()
        client.read_holding_registers.return_value = _reg_response([1])

        read_registers_batched(client, "holding", [0], unit_id=5)
        client.read_holding_registers.assert_called_once_with(0, count=1, device_id=5)

    def test_custom_max_batch(self):
        client = MagicMock()

        def side_effect(start, count, device_id):
            return _reg_response(list(range(count)))

        client.read_holding_registers.side_effect = side_effect

        read_registers_batched(client, "holding", list(range(10)), max_batch=4)
        # 10 / 4 = 3 batches (4 + 4 + 2)
        assert client.read_holding_registers.call_count == 3

    def test_non_contiguous_multiple_batches(self):
        client = MagicMock()

        def side_effect(start, count, device_id):
            return _reg_response([start + i for i in range(count)])

        client.read_holding_registers.side_effect = side_effect

        result = read_registers_batched(client, "holding", [0, 1, 2, 10, 11])
        assert client.read_holding_registers.call_count == 2
        assert result == {0: 0, 1: 1, 2: 2, 10: 10, 11: 11}

    def test_fallback_on_error(self):
        client = MagicMock()

        def side_effect(start, count, device_id):
            if count > 1:
                return _error_response()
            return _reg_response([start * 10])

        client.read_holding_registers.side_effect = side_effect

        result = read_registers_batched(client, "holding", [0, 1, 2], fallback_individual=True)
        # 1 batch + 3 individual
        assert client.read_holding_registers.call_count == 4
        assert result == {0: 0, 1: 10, 2: 20}

    def test_no_fallback(self):
        client = MagicMock()
        client.read_holding_registers.return_value = _error_response()

        result = read_registers_batched(client, "holding", [0, 1, 2], fallback_individual=False)
        # Only the batch call, no individual fallback
        assert client.read_holding_registers.call_count == 1
        assert result == {}

    def test_fallback_on_exception(self):
        client = MagicMock()

        def side_effect(start, count, device_id):
            if count > 1:
                raise ConnectionError("reset")
            return _reg_response([99])

        client.read_holding_registers.side_effect = side_effect

        result = read_registers_batched(client, "holding", [0, 1])
        assert client.read_holding_registers.call_count == 3  # 1 batch + 2 individual
        assert result == {0: 99, 1: 99}

    def test_short_response_triggers_fallback(self):
        client = MagicMock()
        call_n = {"n": 0}

        def side_effect(start, count, device_id):
            call_n["n"] += 1
            if call_n["n"] == 1:
                return _reg_response([1])  # short -- expected 3
            return _reg_response([start])

        client.read_holding_registers.side_effect = side_effect

        result = read_registers_batched(client, "holding", [0, 1, 2])
        # 1 batch (short) + 3 individual
        assert client.read_holding_registers.call_count == 4
        assert len(result) == 3

    def test_coil_default_batch_2000(self):
        """Coils default to max_batch=2000."""
        client = MagicMock()
        n = 500
        client.read_coils.return_value = _bits_response([True] * n)

        read_registers_batched(client, "coils", list(range(n)))
        # All 500 in one call (default 2000)
        assert client.read_coils.call_count == 1
