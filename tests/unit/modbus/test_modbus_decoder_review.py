"""Regression tests for the ModbusEncoder "bool" type gap.

Bug: ModbusEncoder.encode() had no branch for data_type == "bool", even though
"bool" is a documented, decoder-supported type (REGISTERS_PER_TYPE, VALID_TYPES,
and ModbusDecoder._decode_bool all support it). A bool-typed holding register
could therefore be READ but never WRITTEN by name via MapNameResolver.encode_value.

These tests must fail against the pre-fix decoder.py (ValueError: "Encoding not
implemented for type: bool") and pass once ModbusEncoder.encode gains a "bool"
branch.
"""

import pytest

from oida.protocols.modbus.decoder import ModbusDecoder, ModbusEncoder, MapNameResolver


class TestModbusEncoderBool:
    """ModbusEncoder.encode() must support data_type == "bool"."""

    @pytest.mark.parametrize(
        "value,expected_register",
        [
            ("1", 1),
            ("true", 1),
            ("True", 1),
            ("yes", 1),
            ("y", 1),
            ("0", 0),
            ("false", 0),
            ("False", 0),
            ("no", 0),
            ("random-garbage", 0),  # parse_bool falls back to False, not an error
        ],
    )
    def test_encode_bool_accepts_common_truthy_spellings(self, value, expected_register):
        encoder = ModbusEncoder()
        regs = encoder.encode(value, "bool")
        assert regs == [expected_register]

    def test_encode_bool_produces_exactly_one_register(self):
        encoder = ModbusEncoder()
        assert len(encoder.encode("1", "bool")) == 1
        assert len(encoder.encode("0", "bool")) == 1

    def test_encode_bool_accepts_boolean_alias(self):
        # "boolean" and "coil" are TYPE_ALIASES that normalize to "bool".
        encoder = ModbusEncoder()
        assert encoder.encode("true", "boolean") == [1]
        assert encoder.encode("false", "coil") == [0]


class TestBoolEncodeDecodeRoundTrip:
    """encode/decode must round-trip through the shared bool representation."""

    def test_round_trip_true(self):
        encoder = ModbusEncoder()
        decoder = ModbusDecoder()

        registers = encoder.encode("true", "bool")
        decoded = decoder.decode(registers, "bool")

        assert decoded[0]["value"] is True

    def test_round_trip_false(self):
        encoder = ModbusEncoder()
        decoder = ModbusDecoder()

        registers = encoder.encode("false", "bool")
        decoded = decoder.decode(registers, "bool")

        assert decoded[0]["value"] is False


class TestMapNameResolverBoolWrite:
    """A bool-typed holding_registers map entry must be writable by name."""

    @staticmethod
    def _make_bool_entry():
        # Mirrors the shape MapNameResolver.resolve() hands back (see
        # tests/unit/modbus/test_map_name_resolver.py), built synthetically
        # here since the bundled "oida-mock" map has no bool-typed entry.
        return {
            "name": "test_bool_flag",
            "address": 100,
            "type": "bool",
            "section": "registers",
            "function_code": 3,
            "access": "rw",
        }

    @pytest.fixture
    def resolver(self):
        # MapNameResolver.__init__ requires a real, loadable register map; the
        # bundled "oida-mock" map is used purely as a vehicle to get a real
        # encoder/decoder pair wired up.
        return MapNameResolver("oida-mock")

    def test_encode_value_writes_bool_true(self, resolver):
        entry = self._make_bool_entry()
        regs = resolver.encode_value(entry, "true")
        assert regs == [1]

    def test_encode_value_writes_bool_false(self, resolver):
        entry = self._make_bool_entry()
        regs = resolver.encode_value(entry, "false")
        assert regs == [0]

    def test_encode_value_bool_round_trips_through_decode_value(self, resolver):
        entry = self._make_bool_entry()
        regs = resolver.encode_value(entry, "true")
        decoded = resolver.decode_value(entry, regs)
        # NOTE: MapNameResolver.decode_value's default scale/offset path
        # (_decode_map_entry) multiplies the decoded bool by `scale` (1.0),
        # which coerces True/False to 1.0/0.0 in the "value" field -- a
        # separate, pre-existing quirk out of scope for this fix. The
        # unscaled "raw_value" still preserves the real bool.
        assert decoded["raw_value"] is True
        assert decoded["value"] == 1.0


class TestBoolMapEntryNotScaledToFloat:
    """bool is a subclass of int in Python, so `_decode_map_entry`'s
    `isinstance(raw_value, (int, float))` branch caught bool registers and ran
    `raw_value * scale + offset` on them. A boolean register therefore reported
    "value": 1.0 / 0.0 instead of true/false (raw_value still held the real
    bool), which is what lands in the JSON/CSV scan report.
    """

    def _entry(self, regs):
        from oida.protocols.modbus.decoder import ModbusDecoder, _decode_map_entry

        return _decode_map_entry(
            {"name": "run_flag", "type": "bool", "address": 100}, regs, ModbusDecoder()
        )

    def test_true_stays_boolean(self):
        out = self._entry([1])
        assert out["value"] is True, f"got {out['value']!r} ({type(out['value']).__name__})"

    def test_false_stays_boolean(self):
        out = self._entry([0])
        assert out["value"] is False, f"got {out['value']!r} ({type(out['value']).__name__})"

    def test_numeric_scaling_is_unaffected(self):
        """Guard: the fix must not disturb ordinary numeric scaling."""
        from oida.protocols.modbus.decoder import ModbusDecoder, _decode_map_entry

        dec = ModbusDecoder()
        assert _decode_map_entry({"name": "x", "type": "u16", "address": 1}, [5], dec)[
            "value"
        ] == 5.0
        assert _decode_map_entry(
            {"name": "y", "type": "u16", "address": 1, "scale": 0.1}, [50], dec
        )["value"] == 5.0
