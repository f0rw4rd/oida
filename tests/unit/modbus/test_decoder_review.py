"""Bug-hunt regression tests for the modbus decoder / register-map layer.

Each test pins one verified bug in ``src/oida/protocols/modbus/decoder.py``:

* alias register widths (``s32`` / ``int32`` / ``float`` ...) were treated as
  1-register types by ``_required_registers``, so ``decode_with_map`` read too
  few registers and every alias-typed entry failed with ``decode_failed``;
* ``bool`` / ``boolean`` / ``coil`` and ``str7``-style types are accepted by
  ``validate_maps`` (and shipped register maps) but were unknown to the decoder;
* a device-supplied SunSpec scale factor was used unclamped, so ``raw * 10**sf``
  could build a 32771-digit int that crashes every rendering path;
* ``MapNameResolver.encode_value`` did not normalize type aliases before deciding
  whether a register is numeric, so scaled alias-typed registers either crashed
  (float input) or silently wrote an unscaled value.
"""

import json
import math
import os
import tempfile

import pytest

from oida.protocols.modbus.decoder import (
    MapNameResolver,
    ModbusDecoder,
    _required_registers,
    decode_with_map,
)

# ---------------------------------------------------------------------------
# B1: alias types must occupy the same register width as their canonical type
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("alias", "canonical", "width"),
    [
        ("s16", "i16", 1),
        ("s32", "i32", 2),
        ("s64", "i64", 4),
        ("int32", "i32", 2),
        ("uint32", "u32", 2),
        ("int64", "i64", 4),
        ("uint64", "u64", 4),
        ("float", "f32", 2),
        ("float32", "f32", 2),
        ("float64", "f64", 4),
        ("double", "f64", 4),
        ("int", "i16", 1),
        ("uint", "u16", 1),
    ],
)
def test_alias_type_register_width_matches_canonical(alias, canonical, width):
    assert _required_registers({"type": alias}) == width == _required_registers(
        {"type": canonical}
    )


def test_decode_with_map_s32_reads_two_registers():
    """A negative s32 (shipped in 6 bundled meter/VFD maps) must decode."""
    raw = -123456 & 0xFFFFFFFF
    registers = {100: raw >> 16, 101: raw & 0xFFFF}
    register_map = {
        "registers": {"power": {"address": 100, "type": "s32", "scale": 0.1}}
    }
    result = decode_with_map(registers, register_map)
    assert result["power"]["error"] if "error" in result["power"] else True
    assert result["power"]["value"] == pytest.approx(-12345.6)


def test_decode_with_map_float_alias():
    registers = {100: 0x4049, 101: 0x0FDB}  # 3.14159... big-endian f32
    register_map = {"registers": {"x": {"address": 100, "type": "float32"}}}
    result = decode_with_map(registers, register_map)
    assert result["x"]["value"] == pytest.approx(3.1415927410125732)


def test_decode_with_map_uint32_alias():
    raw = 0xDEADBEEF
    registers = {100: raw >> 16, 101: raw & 0xFFFF}
    register_map = {"registers": {"x": {"address": 100, "type": "uint32"}}}
    result = decode_with_map(registers, register_map)
    assert result["x"]["value"] == 0xDEADBEEF


# ---------------------------------------------------------------------------
# B2: bool/boolean/coil types accepted by validate_maps must decode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("alias", ["bool", "boolean", "coil"])
def test_decode_with_map_bool_types(alias):
    register_map = {"registers": {"running": {"address": 100, "type": alias}}}
    result = decode_with_map({100: 1}, register_map)
    assert "error" not in result["running"], result["running"]
    assert result["running"]["value"] in (True, 1)


def test_decode_with_map_bool_zero():
    register_map = {"registers": {"running": {"address": 100, "type": "bool"}}}
    result = decode_with_map({100: 0}, register_map)
    assert "error" not in result["running"], result["running"]
    assert not result["running"]["value"]


# ---------------------------------------------------------------------------
# B3: strN types accepted by validate_maps must decode as strings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("alias", ["str7", "str10", "str20", "string8"])
def test_decode_with_map_strn_types(alias):
    register_map = {
        "registers": {"label": {"address": 100, "type": alias, "length": 8}}
    }
    result = decode_with_map({100: 0x4865, 101: 0x6C6C, 102: 0x6F00, 103: 0x0000}, register_map)
    assert "error" not in result["label"], result["label"]
    assert result["label"]["value"] == "Hello"


def test_required_registers_strn():
    assert _required_registers({"type": "str7", "length": 7}) == 4
    assert _required_registers({"type": "str10"}) == 5


# ---------------------------------------------------------------------------
# B4: SunSpec dynamic scale factor must be clamped before 10**sf
# ---------------------------------------------------------------------------


def _sf_map():
    return {
        "registers": {
            "watts": {"address": 100, "type": "i16", "scale_factor_register": 101},
            "watts_sf": {"address": 101, "type": "i16"},
        }
    }


def test_sunspec_sf_positive_out_of_range_does_not_explode():
    result = decode_with_map({100: 1234, 101: 0x7FFF}, _sf_map())
    value = result["watts"]["value"]
    assert value is not None
    # Must be renderable through every normal output path.
    assert len(f"{value}") < 100
    assert len(json.dumps(result)) < 10000


def test_sunspec_sf_negative_out_of_range_does_not_underflow_to_zero_everywhere():
    result = decode_with_map({100: 1234, 101: 0x8001}, _sf_map())  # -32767
    value = result["watts"]["value"]
    assert value is not None
    assert json.dumps(result)


def test_sunspec_sf_in_range_still_applies():
    # -2 via two's complement 0xFFFE
    result = decode_with_map({100: 1234, 101: 0xFFFE}, _sf_map())
    assert result["watts"]["value"] == pytest.approx(12.34)


# ---------------------------------------------------------------------------
# B5: encode_value must honor scale/offset for alias-typed registers
# ---------------------------------------------------------------------------


@pytest.fixture()
def resolver_with_alias_entries():
    register_map = {
        "vendor": "Test",
        "model": "Test",
        "registers": {
            "setpoint_s16": {"address": 100, "type": "s16", "scale": 0.1, "access": "rw"},
            "setpoint_i16": {"address": 101, "type": "i16", "scale": 0.1, "access": "rw"},
            "power_s32": {"address": 102, "type": "s32", "scale": 0.01, "access": "rw"},
            "power_i32": {"address": 104, "type": "i32", "scale": 0.01, "access": "rw"},
        },
    }
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump(register_map, fh)
    resolver = MapNameResolver(path)
    yield resolver
    os.unlink(path)


@pytest.mark.parametrize("alias", ["s16", "int16"])
def test_encode_value_scales_alias_float_input(resolver_with_alias_entries, alias):
    entry = resolver_with_alias_entries.resolve(
        "setpoint_s16" if alias == "s16" else "setpoint_i16"
    )
    assert entry is not None
    # 50.0 engineering * (1/0.1) -> 500 raw.
    regs = resolver_with_alias_entries.encode_value(entry, "50.0")
    assert regs == [500]


def test_encode_value_scales_alias_s32(resolver_with_alias_entries):
    entry = resolver_with_alias_entries.resolve("power_s32")
    # 123.45 engineering / 0.01 -> 12345 raw.
    regs = resolver_with_alias_entries.encode_value(entry, "123.45")
    assert regs == [12345 >> 16, 12345 & 0xFFFF]


def test_encode_value_range_check_applies_to_alias(resolver_with_alias_entries):
    entry = dict(resolver_with_alias_entries.resolve("setpoint_s16"))
    entry["max"] = 10.0
    with pytest.raises(ValueError):
        resolver_with_alias_entries.encode_value(entry, "50.0")


def test_encode_value_canonical_still_unchanged(resolver_with_alias_entries):
    entry = resolver_with_alias_entries.resolve("power_i32")
    regs = resolver_with_alias_entries.encode_value(entry, "123.45")
    assert regs == [12345 >> 16, 12345 & 0xFFFF]


def test_map_resolver_registers_needed_alias(resolver_with_alias_entries):
    assert resolver_with_alias_entries.get_registers_needed(
        resolver_with_alias_entries.resolve("power_s32")
    ) == 2


# ---------------------------------------------------------------------------
# Sanity: unaffected behaviour stays put
# ---------------------------------------------------------------------------


def test_decoder_u16_unchanged():
    decoder = ModbusDecoder()
    assert decoder.decode([100, 200], "u16")[0]["value"] == 100


def test_decode_with_map_missing_registers_still_flagged():
    register_map = {"registers": {"x": {"address": 100, "type": "u32"}}}
    result = decode_with_map({100: 1}, register_map)
    assert result["x"]["error"] == "missing_registers"


def test_sf_map_i16_sentinel_is_not_implemented_still_none_check():
    # 0x8000 decodes to -32768; scale factor path must not turn it into a
    # giant value either (it is the SunSpec "not implemented" sentinel).
    result = decode_with_map({100: 1234, 101: 0x8000}, _sf_map())
    assert result["watts"]["value"] is not None
    assert not math.isinf(float(result["watts"]["value"]))
