"""Regression tests for A2: register-map `scale: 0` causes ZeroDivisionError.

`validate_maps.py` accepted `scale: 0` as "numeric" without rejecting it, and
`decoder.py:MapNameResolver.encode_value` divided by `scale` unconditionally
for numeric types whenever `scale != 1.0`, raising a bare ZeroDivisionError
instead of a clear, typed error.
"""

import json

import pytest

from oida.protocols.modbus.decoder import MapNameResolver, ModbusDecoder, ModbusEncoder
from oida.protocols.modbus.validate_maps import validate_register_map


def _resolver() -> MapNameResolver:
    """Build a bare MapNameResolver without needing a real map file on disk."""
    resolver = MapNameResolver.__new__(MapNameResolver)
    resolver._encoder = ModbusEncoder(byte_order="big", word_order="big")
    resolver._decoder = ModbusDecoder(byte_order="big", word_order="big")
    return resolver


def test_validator_rejects_zero_scale(tmp_path):
    """A register map declaring `scale: 0` must fail validation with a clear error."""
    map_data = {
        "vendor": "Acme",
        "model": "Widget",
        "holding_registers": {
            "bad_reg": {"address": 100, "type": "u16", "scale": 0},
        },
    }
    map_file = tmp_path / "bad_scale.json"
    map_file.write_text(json.dumps(map_data))

    result = validate_register_map(map_file)

    assert not result.is_valid, "validator should reject scale: 0"
    assert any("scale" in err.lower() and "0" in err for err in result.errors), (
        f"expected a scale-related error mentioning 0, got: {result.errors}"
    )


def test_encode_value_zero_scale_raises_clear_error():
    """encode_value with scale: 0 must raise a clear, typed error, not ZeroDivisionError."""
    resolver = _resolver()
    entry = {"type": "u16", "scale": 0}

    with pytest.raises(ValueError) as excinfo:
        resolver.encode_value(entry, "5")

    assert not isinstance(excinfo.value, ZeroDivisionError)
    assert "scale" in str(excinfo.value).lower()


def test_encode_value_nonzero_scale_still_works():
    """Regression: a normal non-zero scale must still encode correctly.

    Uses f32 (not an integer type) so this test isolates the scale==0 fix
    from the unrelated pre-existing quirk where `int("50.0")` raises for
    integer types when the inverse-scaled value repr()s with a decimal
    point.
    """
    resolver = _resolver()
    entry = {"type": "f32", "scale": 0.1}

    raw_regs = resolver.encode_value(entry, "5.0")

    # 5.0 / 0.1 == 50.0 -> two registers encoding float32(50.0)
    assert len(raw_regs) == 2


def test_validator_still_accepts_nonzero_scale(tmp_path):
    """Regression: a normal non-zero scale must still validate cleanly."""
    map_data = {
        "vendor": "Acme",
        "model": "Widget",
        "holding_registers": {
            "good_reg": {"address": 100, "type": "u16", "scale": 0.1},
        },
    }
    map_file = tmp_path / "good_scale.json"
    map_file.write_text(json.dumps(map_data))

    result = validate_register_map(map_file)

    assert result.is_valid, f"unexpected errors: {result.errors}"


# =============================================================================
# A7 — scaled integer writes crash with `int("50.0")` because encode_value
# always repr()s the inverse-scaled float, but the integer encoders (encode
# for u16/i16/u32/i32/u64/i64/bcd) do a bare int(value_str) that rejects any
# string containing a decimal point.
# =============================================================================


@pytest.mark.parametrize(
    "data_type,value_str,expected_regs",
    [
        ("u16", "5.0", [50]),
        ("i16", "5.0", [50]),
        ("u32", "5.0", [0, 50]),
        ("i32", "5.0", [0, 50]),
    ],
)
def test_encode_value_scaled_integer_type(data_type, value_str, expected_regs):
    """Scaled integer-typed registers (the entire point of `scale`) must encode.

    Before the fix, `encode_value` repr()'d the inverse-scaled float
    unconditionally (e.g. "50.0"), and the integer encoders do a bare
    `int(value)`, which raises ValueError on any decimal-point string.
    """
    resolver = _resolver()
    entry = {"type": data_type, "scale": 0.1}

    raw_regs = resolver.encode_value(entry, value_str)

    assert raw_regs == expected_regs


def test_encode_value_scaled_negative_signed_int():
    """A negative engineering value on a signed, scaled integer register."""
    resolver = _resolver()
    entry = {"type": "i16", "scale": 0.1}

    raw_regs = resolver.encode_value(entry, "-5.0")

    # -5.0 / 0.1 == -50 -> encoded as an unsigned 16-bit two's complement value.
    assert raw_regs == [65536 - 50]


def test_encode_value_scaled_float_unchanged():
    """Regression: the f32/f64 path must keep using the float repr, unrounded."""
    resolver = _resolver()
    entry = {"type": "f32", "scale": 0.1}

    raw_regs = resolver.encode_value(entry, "5.0")

    assert len(raw_regs) == 2
    decoded = resolver._decoder.decode(raw_regs, "f32")
    assert decoded[0]["value"] == pytest.approx(50.0)


def test_encode_decode_scaled_int_round_trip():
    """Round-trip an engineering value through encode_value then decode_value."""
    resolver = _resolver()
    entry = {"type": "i16", "scale": 0.1}

    raw_regs = resolver.encode_value(entry, "12.3")
    decoded = resolver.decode_value(entry, raw_regs)

    assert decoded["value"] == pytest.approx(12.3, abs=0.05)
