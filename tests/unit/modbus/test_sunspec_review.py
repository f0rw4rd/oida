"""
Regression tests for a confirmed sunspec.py bug (staff-review follow-up).

Bug: `_is_not_implemented(value, dtype)` had explicit signed/unsigned dual
branches for "i16"/"i32"/"i64" but NOT for "sunssf", even though "sunssf"
is aliased to "i16" in `_SUNSPEC_TYPE_ALIASES` and therefore decodes to a
*signed* value via `_raw_regs_to_value`. The real call site in
`_sunspec_display_mapped_model` (sunspec.py:560-563) always passes the
*decoded* value, so a not-implemented sunssf register (raw 0x8000) decoded
to -32768 was never recognized as "not implemented" and was displayed/
exported as the garbage value -32768 instead of being flagged "N/I".

Fix: `_is_not_implemented` now checks `dtype in ("i16", "sunssf")` for the
combined 0x8000 / -32768 sentinel check.
"""

from oida.protocols.modbus.mixins.sunspec import (
    SunSpecMixin,
    _is_not_implemented,
    _raw_regs_to_value,
)


class FakeLogger:
    """Minimal logger mock - only `display` is exercised by print_table/callers."""

    def __init__(self):
        self.messages = []

    def display(self, msg):
        self.messages.append(msg)

    def success(self, msg):
        self.messages.append(msg)

    def warning(self, msg):
        self.messages.append(msg)

    def fail(self, msg):
        self.messages.append(msg)

    def debug(self, msg):
        pass


class FakeDisplayMixin:
    """Minimal mock exposing SunSpecMixin._sunspec_display_mapped_model bound."""

    def __init__(self):
        self.logger = FakeLogger()
        self.args = type("Args", (), {"verbose": 0})()
        self._display = SunSpecMixin._sunspec_display_mapped_model.__get__(self, type(self))


class TestIsNotImplementedSunssfDecoded:
    """
    The bug: _is_not_implemented only handled the raw-unsigned sunssf sentinel
    (0x8000), not the signed value (-32768) that _raw_regs_to_value actually
    produces for dtype="sunssf" (aliased to i16, a signed decode).
    """

    def test_sunssf_raw_unsigned_sentinel_still_flagged(self):
        """Regression guard for the raw-unsigned call site (sunspec.py:500)."""
        assert _is_not_implemented(0x8000, "sunssf") is True

    def test_sunssf_decoded_signed_sentinel_is_flagged(self):
        """
        This is the exact failure mode from the bug report: decode a raw
        not-implemented sunssf register the same way the real call site at
        sunspec.py:560 does, then check it. Fails on the pre-fix code because
        _raw_regs_to_value([0x8000], "sunssf") == -32768, and the old
        _is_not_implemented had no "sunssf" branch, so it fell through to the
        generic `value == sentinel` check against the *unsigned* 0x8000 (32768),
        and -32768 != 32768.
        """
        decoded = _raw_regs_to_value([0x8000], "sunssf")
        assert decoded == -32768
        assert _is_not_implemented(decoded, "sunssf") is True

    def test_sunssf_decoded_normal_value_not_flagged(self):
        # 0xFFFC decodes to -4 (a legitimate scale factor), must not be
        # mistaken for "not implemented".
        decoded = _raw_regs_to_value([0xFFFC], "sunssf")
        assert decoded == -4
        assert _is_not_implemented(decoded, "sunssf") is False


class TestSunspecDisplayMappedModelFlagsNotImplementedSunssf:
    """
    End-to-end-ish coverage through the real call site that triggered the bug:
    _sunspec_display_mapped_model() decodes each register via
    _raw_regs_to_value(reg_slice, dtype) and then checks
    _is_not_implemented(raw_value, dtype) before populating result_data.

    Build a minimal one-register SunSpec model map with a "sunssf" register
    whose raw wire value is the not-implemented sentinel (0x8000), and verify
    it is reported as not_implemented rather than as the decoded garbage
    value -32768.
    """

    def _reg_map(self):
        return {
            "description": "Test Model",
            "registers": {
                "SF": {
                    "address": 2,
                    "type": "sunssf",
                    "description": "not-implemented scale factor",
                }
            },
        }

    def test_not_implemented_sunssf_register_is_flagged(self):
        mixin = FakeDisplayMixin()
        result_data = {"registers": {}}

        # Raw register list starting at data_offset (JSON address 2); the SF
        # register itself is not-implemented (0x8000 on the wire).
        raw_data = [0x8000]

        mixin._display(
            model_id=999,
            name="Test Model",
            reg_map=self._reg_map(),
            raw_data=raw_data,
            data_address=40002,
            verbose=0,
            result_data=result_data,
        )

        entry = result_data["registers"]["SF"]
        assert entry["not_implemented"] is True
        assert entry["value"] is None

    def test_normal_sunssf_register_is_not_flagged(self):
        mixin = FakeDisplayMixin()
        result_data = {"registers": {}}

        # 0xFFFC decodes to -4, a legitimate (non-sentinel) scale factor.
        raw_data = [0xFFFC]

        mixin._display(
            model_id=999,
            name="Test Model",
            reg_map=self._reg_map(),
            raw_data=raw_data,
            data_address=40002,
            verbose=0,
            result_data=result_data,
        )

        entry = result_data["registers"]["SF"]
        assert "not_implemented" not in entry
        assert entry["raw"] == -4
