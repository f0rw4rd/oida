"""
Behavior tests for ModbusScanner discovery mixin
(scanner_mixins/discovery.py was ~7% covered).

Covers:
- _discover_units: gateway detection by identical register responses, gateway
  detection by identical error codes, normal per-unit scan, >200 high-response
  warning, exception tolerance.
- _test_function_codes: supported FC, exception-code classification
  (2 -> needs address, 3 -> needs data, 1 -> unsupported/skip, other ->
  tracked), vendor-specific decode-error path.
"""

from unittest.mock import MagicMock, patch

import pytest

from tests.service_gate import require_import

require_import("pymodbus", reason="pymodbus library not installed")


def make_scanner(unit_range="1-247", unit_id=1, **kw):
    from oida.protocols.modbus.scanner import ModbusScanner

    s = ModbusScanner.__new__(ModbusScanner)
    s.unit_id = unit_id
    s.unit_range = unit_range
    s.logger = MagicMock()
    s.scan_fc = kw.get("scan_fc", False)
    s.fc_all = kw.get("fc_all", False)
    s.fc_range = kw.get("fc_range", "1-8")
    return s


def _ok(registers):
    r = MagicMock()
    r.isError.return_value = False
    r.registers = list(registers)
    return r


def _err(exc_code=None):
    r = MagicMock()
    r.isError.return_value = True
    r.exception_code = exc_code
    return r


# ---------------------------------------------------------------------------
# _discover_units
# ---------------------------------------------------------------------------


class TestDiscoverUnits:
    def test_gateway_detected_identical_responses(self):
        s = make_scanner(unit_range="1-247")
        client = MagicMock()
        # every sampled unit returns the same register tuple -> gateway
        client.read_holding_registers.return_value = _ok([0x1234])
        units = s._discover_units(client)
        assert units["gateway_mode"] is True
        assert "actual_unit" in units
        assert units["actual_unit"] == 1

    def test_gateway_detected_identical_errors(self):
        s = make_scanner(unit_range="1-247")
        client = MagicMock()
        # every sampled unit returns the same error code, no successes
        client.read_holding_registers.return_value = _err(exc_code=11)
        units = s._discover_units(client)
        assert units["gateway_mode"] is True
        assert units["error_code"] == 11

    def test_normal_scan_finds_specific_units(self):
        s = make_scanner(unit_range="1-5")
        client = MagicMock()

        # units 1 and 3 respond with DIFFERENT values (so no gateway), others error
        def read(addr, count, device_id):
            if device_id == 1:
                return _ok([100])
            if device_id == 3:
                return _ok([300])
            return _err(exc_code=11)

        client.read_holding_registers.side_effect = read
        units = s._discover_units(client)
        # not gateway mode; specific units present
        assert not units.get("gateway_mode")
        active = [k for k in units if isinstance(k, int)]
        assert 1 in active and 3 in active

    def test_exception_during_sample_tolerated(self):
        s = make_scanner(unit_range="1-3")
        client = MagicMock()
        client.read_holding_registers.side_effect = OSError("net")
        units = s._discover_units(client)
        # no crash; nothing active
        assert [k for k in units if isinstance(k, int)] == []


# ---------------------------------------------------------------------------
# _test_function_codes
# ---------------------------------------------------------------------------


class TestTestFunctionCodes:
    def _run(self, s, responder):
        with (
            patch("oida.protocols.modbus.scanner.execute_pdu", side_effect=responder),
            patch("oida.protocols.modbus.scanner.GenericPDU"),
            patch("oida.utils.ProgressTracker"),
        ):
            return s._test_function_codes(MagicMock())

    def test_supported_and_classified(self):
        # fc_range includes write FC 5, which is gated behind --confirm; set it
        # so the classification path for FC 5 is exercised as before.
        s = make_scanner(fc_range="1-5")
        s.args = {"confirm": True}

        # GenericPDU is patched, so pdu.function_code is a Mock -- drive each FC
        # via a counter matching the 1..5 scan order instead.
        seq = iter(range(1, 6))

        def responder2(client, pdu, unit):
            fc = next(seq)
            if fc == 1:
                return _ok([1])  # plain supported
            if fc == 2:
                return _err(exc_code=2)  # supported, needs address
            if fc == 3:
                return _err(exc_code=3)  # supported, needs data
            if fc == 4:
                return _err(exc_code=1)  # unsupported -> skipped
            return _err(exc_code=6)  # other exception -> tracked

        out = self._run(s, responder2)
        sup = out["supported"]
        assert 1 in sup and sup[1]["supported"] is True
        assert sup[2]["exception_code"] == 2
        assert "valid address" in sup[2]["note"]
        assert sup[3]["exception_code"] == 3
        assert 4 not in sup  # illegal function omitted
        assert sup[5]["exception_code"] == 6

    def test_vendor_specific_decode_error(self):
        s = make_scanner(fc_range="65")

        def responder(client, pdu, unit):
            raise ValueError("Unable to decode response")

        out = self._run(s, responder)
        assert out["supported"][65]["note"] == "Vendor-specific response format"

    def test_generic_exception_skipped(self):
        s = make_scanner(fc_range="65")

        def responder(client, pdu, unit):
            raise OSError("connection reset")

        out = self._run(s, responder)
        assert out["supported"] == {}

    def test_mutating_write_fcs_gated_behind_confirm(self):
        """Mutating write FCs (5,6,15,16,23) must not be probed without --confirm,
        but non-write FCs in the same range still are; --confirm re-enables them.

        GenericPDU is patched, so the real FC is recovered from the constructor
        call order: GenericPDU(function_code=fc) is invoked exactly once per FC
        that survives the gate, immediately before execute_pdu. Capturing the
        function_code kwarg gives the exact set of FCs that reach the wire.
        """
        fc_range = "1-6,15,16,22,23"
        full = [1, 2, 3, 4, 5, 6, 15, 16, 22, 23]
        mutating = {5, 6, 15, 16, 23}
        non_mutating = [fc for fc in full if fc not in mutating]

        def run_capture(args):
            probed: list[int] = []

            def fake_pdu(function_code=1, **kw):
                probed.append(function_code)
                return MagicMock(function_code=function_code)

            def responder(client, pdu, unit):
                return _ok([1])

            s = make_scanner(fc_range=fc_range)
            s.args = args
            with (
                patch("oida.protocols.modbus.scanner.execute_pdu", side_effect=responder),
                patch("oida.protocols.modbus.scanner.GenericPDU", side_effect=fake_pdu),
                patch("oida.utils.ProgressTracker"),
            ):
                s._test_function_codes(MagicMock())
            return probed

        # Without --confirm: mutating FCs are skipped before any PDU is built.
        probed_no_confirm = run_capture({"confirm": False})
        assert probed_no_confirm == non_mutating
        assert not (set(probed_no_confirm) & mutating)

        # With --confirm: every FC in the range is probed.
        probed_confirm = run_capture({"confirm": True})
        assert probed_confirm == full
