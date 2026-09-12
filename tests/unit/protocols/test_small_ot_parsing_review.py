#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hostile-peer parsing review for the smaller OT protocol modules.

Every test here feeds a *malformed, truncated or hostile* response to a real
parse/enumeration routine and asserts the scanner degrades gracefully instead
of crashing (IndexError/struct.error/ValueError), hanging, or over-allocating.

Each test was written fail-first: it reproduced a concrete defect against the
code as it stood, and only then was the minimal fix applied.
"""

import struct

import pytest

from tests.service_gate import require_import

pytestmark = [pytest.mark.unit]


class _TooManyRequests(BaseException):
    """Escape hatch for runaway loops.

    Derives from BaseException on purpose: the code under test wraps its
    per-iteration body in ``except Exception``, so an ordinary exception would
    be swallowed and the loop would keep spinning.
    """


# ---------------------------------------------------------------------------
# HART -- Command 85 sub-device count is peer-controlled (0..65535) and drives
# one network round-trip plus a 0.1s sleep per iteration in list_sub_devices().
# A hostile gateway reporting 0xFFFF pins the scanner for hours.
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, response_code=0, payload=b""):
        self.response_code = response_code
        self.payload = payload


class _CountingClient:
    """HART-IP client that claims a huge sub-device count.

    Raises _TooManyRequests once the scanner has issued more Command-84 reads
    than any sane gateway could host, which is what proves the loop is bounded
    only by the attacker-supplied count.
    """

    def __init__(self, claimed_count=0xFFFF, abort_after=2000):
        self.claimed_count = claimed_count
        self.abort_after = abort_after
        self.cmd84_calls = 0

    def send_command(self, command, address=0, data=b""):
        if command == 85:
            return _FakeResponse(0, struct.pack(">H", self.claimed_count))
        if command == 84:
            self.cmd84_calls += 1
            if self.cmd84_calls > self.abort_after:
                raise _TooManyRequests(f"issued {self.cmd84_calls} sub-device reads")
            idx = struct.unpack(">H", data)[0] if len(data) >= 2 else 0
            return _FakeResponse(0, bytes([0x26, 0x2A, idx & 0xFF, 0x00, 0x01]) + b"\x00" * 30)
        return _FakeResponse(response_code=1)

    def close(self):
        pass


def _hart_scanner(client):
    from oida.protocols.hart.scanner import HARTScanner

    scanner = HARTScanner({"rhost": "10.0.0.5"})
    scanner.client = client
    return scanner


def test_hart_sub_device_count_is_bounded(monkeypatch):
    """A hostile Command-85 count must not drive an unbounded enumeration loop."""
    import time as _time

    from oida.protocols.hart.mixins import enumeration as enum_mod

    # Neutralise the per-device pacing sleep so the test measures the loop
    # bound, not wall-clock. Without a bound this test takes ~2 hours for real.
    monkeypatch.setattr(enum_mod.time, "sleep", lambda *_a, **_k: None)
    assert _time is not None

    client = _CountingClient(claimed_count=0xFFFF, abort_after=2000)
    scanner = _hart_scanner(client)

    subs = scanner.list_sub_devices()

    assert client.cmd84_calls <= enum_mod.MAX_SUB_DEVICES
    assert len(subs) <= enum_mod.MAX_SUB_DEVICES


def test_hart_sub_device_listing_still_works_for_honest_gateway(monkeypatch):
    """No semantic change for a well-formed response: every device is returned."""
    from oida.protocols.hart.mixins import enumeration as enum_mod

    monkeypatch.setattr(enum_mod.time, "sleep", lambda *_a, **_k: None)

    client = _CountingClient(claimed_count=3, abort_after=100)
    scanner = _hart_scanner(client)

    subs = scanner.list_sub_devices()

    assert len(subs) == 3
    assert [s["index"] for s in subs] == [0, 1, 2]
    assert subs[0]["manufacturer_id"] == 0x26


# ---------------------------------------------------------------------------
# Modbus SunSpec -- the scale factor (sunssf) register is read off the wire and
# used as an exponent: raw_value * (10 ** sf). SunSpec only defines -10..10,
# but any i16 except the 0x8000 sentinel is accepted, so a device answering
# with sf=0x7FFF produces a 32769-digit int whose str() raises ValueError, and
# a float measurement overflows outright.
# ---------------------------------------------------------------------------


class _FakeLogger:
    def __init__(self):
        self.lines = []

    def _rec(self, msg, *a, **k):
        self.lines.append(str(msg))

    display = success = fail = warning = debug = highlight = _rec


def _sunspec_mixin():
    from unittest.mock import MagicMock

    from oida.protocols.modbus.mixins.sunspec import SunSpecMixin

    class _FakeSunSpec:
        pass

    obj = _FakeSunSpec()
    obj.logger = _FakeLogger()
    obj.conn = MagicMock()
    obj.results = {"data": {"sunspec": {}}}
    obj._sunspec_display_mapped_model = SunSpecMixin._sunspec_display_mapped_model.__get__(
        obj, _FakeSunSpec
    )
    return obj


def _inverter_103_map():
    import json
    from pathlib import Path

    import oida.protocols.modbus as modbus_pkg

    path = (
        Path(modbus_pkg.__file__).parent / "register_maps" / "sunspec" / "sunspec-inverter-103.json"
    )
    return json.loads(path.read_text())


@pytest.mark.parametrize("hostile_sf", [0x7FFF, 0x8001])
def test_sunspec_hostile_scale_factor_does_not_crash(hostile_sf):
    """A hostile sunssf exponent must not blow up int->str / float conversion.

    raw_data index 0 == JSON address 2 (ac_current); index 4 == address 6
    (ac_current_sf, the scale factor referenced by ac_current).
    0x7FFF -> +32767, 0x8001 -> -32767 once decoded as i16.
    """
    obj = _sunspec_mixin()
    reg_map = _inverter_103_map()

    raw_data = [0] * 50
    raw_data[0] = 7  # ac_current
    raw_data[4] = hostile_sf  # ac_current_sf

    result_data = {"registers": {}}

    # Must not raise ValueError / OverflowError.
    obj._sunspec_display_mapped_model(103, "Inverter", reg_map, raw_data, 40070, 0, result_data)

    assert "ac_current" in result_data["registers"]


def test_sunspec_infinite_f32_measurement_does_not_crash():
    """f32 = +inf is not the NaN sentinel, so it reaches int(scaled_value)."""
    import json
    from pathlib import Path

    import oida.protocols.modbus as modbus_pkg

    reg_map = json.loads(
        (
            Path(modbus_pkg.__file__).parent
            / "register_maps"
            / "sunspec"
            / "sunspec-inverter-113.json"
        ).read_text()
    )
    obj = _sunspec_mixin()

    raw_data = [0] * 60
    # ac_current (f32) at JSON address 2 -> raw index 0; 0x7F800000 == +inf
    raw_data[0] = 0x7F80
    raw_data[1] = 0x0000

    result_data = {"registers": {}}
    obj._sunspec_display_mapped_model(113, "Inverter", reg_map, raw_data, 40070, 0, result_data)

    assert "ac_current" in result_data["registers"]


def test_sunspec_legal_scale_factor_still_scales():
    """No semantic change for a well-formed response: sf=-1 still divides by 10."""
    obj = _sunspec_mixin()
    reg_map = _inverter_103_map()

    raw_data = [0] * 50
    raw_data[0] = 75  # ac_current
    raw_data[4] = 0xFFFF  # ac_current_sf = -1

    result_data = {"registers": {}}
    obj._sunspec_display_mapped_model(103, "Inverter", reg_map, raw_data, 40070, 0, result_data)

    entry = result_data["registers"]["ac_current"]
    assert entry["value"] == pytest.approx(7.5)


# ---------------------------------------------------------------------------
# Modbus FC 8 sub-function 0x02 -- pymodbus decodes a diagnostic response with
# >=4 data bytes into a *tuple* of words (pymodbus/pdu/diag_message.py decode).
# The scanner passed that straight into f"0x{...:04X}", which TypeErrors and
# aborts the whole scan.
# ---------------------------------------------------------------------------


class _FakeDiagResult:
    def __init__(self, message):
        self.message = message

    def isError(self):
        return False


def _diag_scanner(result):
    from oida.protocols.modbus.scanner_mixins.diagnostics import ScannerDiagnosticsMixin

    class _FakeDiag(ScannerDiagnosticsMixin):
        def __init__(self):
            self.logger = _FakeLogger()
            self.unit_id = 1

    obj = _FakeDiag()

    class _Client:
        def diag_read_diagnostic_register(self, device_id=None):
            return result

    return obj, _Client()


@pytest.mark.parametrize(
    "wire_message",
    [
        (0x1234, 0x5678),  # >=4 data bytes -> tuple of words
        [0x1234],  # 1-element sequence
        b"\x12\x34",  # raw bytes
    ],
)
def test_modbus_diagnostic_register_normalized_to_int(wire_message):
    """A multi-word / bytes FC8 response must not escape as a non-int."""
    obj, client = _diag_scanner(_FakeDiagResult(wire_message))

    value = obj._diagnostic_read_register(client)

    assert value is None or isinstance(value, int)
    if value is not None:
        # The formatting the display layer performs must not raise.
        assert f"0x{value:04X}".startswith("0x")


def test_modbus_diagnostic_register_scalar_unchanged():
    """No semantic change for a well-formed single-word response."""
    obj, client = _diag_scanner(_FakeDiagResult(0x1234))
    assert obj._diagnostic_read_register(client) == 0x1234


# ---------------------------------------------------------------------------
# DNP3 -- _probe_supported_groups sweeps 123 object groups, each costing a full
# _sync_scan timeout when the outstation stays silent. The "outstation not
# responding" abort was gated on `and not supported`, so a hostile outstation
# that answers exactly one group and then goes mute permanently disabled the
# escape hatch and held the scanner for the whole sweep.
# ---------------------------------------------------------------------------


def _dnp3_scanner():
    opendnp3 = require_import("opendnp3", reason="yadnp3 (opendnp3) not installed")
    assert opendnp3 is not None

    from oida.protocols.dnp3.scanner import DNP3Scanner

    class _Handler:
        def __init__(self):
            for attr in (
                "binary_inputs",
                "double_bit_binary_inputs",
                "binary_output_statuses",
                "counters",
                "frozen_counters",
                "analog_inputs",
                "analog_output_statuses",
                "octet_strings",
                "security_stats",
            ):
                setattr(self, attr, [])
            self.string_attrs = []

        def clear(self):
            pass

    scanner = DNP3Scanner({"rhost": "127.0.0.1", "rport": 20000})
    scanner._connected = True
    scanner._master = object()
    handler = _Handler()
    scanner._handler = handler
    scanner._scan_handler = handler
    scanner._app = type("_App", (), {"iin": None})()
    return scanner


def test_dnp3_probe_aborts_after_one_success_then_silence():
    """One answered group must not disable the not-responding abort."""
    import opendnp3

    scanner = _dnp3_scanner()
    calls = {"n": 0}

    def fake_sync_scan(scan_fn, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            # The single group the hostile outstation deigns to answer.
            scanner._last_task_info = type("_T", (), {"result": opendnp3.TaskCompletion.SUCCESS})()
            return True
        scanner._last_task_info = type(
            "_T", (), {"result": opendnp3.TaskCompletion.FAILURE_RESPONSE_TIMEOUT}
        )()
        return False

    scanner._sync_scan = fake_sync_scan
    results = {"operations": {}}
    scanner._probe_supported_groups(results)

    op = results["operations"]["probe_objects"]
    assert op["total_supported"] == 1
    # 1 success + at most max_consecutive_failures(10) timeouts, plus slack.
    assert calls["n"] <= 20, f"probe kept polling a dead outstation ({calls['n']} scans)"


def test_dnp3_probe_still_sweeps_a_responsive_outstation():
    """No semantic change when the outstation keeps answering: full sweep runs."""
    import opendnp3

    scanner = _dnp3_scanner()
    calls = {"n": 0}

    def fake_sync_scan(scan_fn, timeout=None):
        calls["n"] += 1
        scanner._last_task_info = type("_T", (), {"result": opendnp3.TaskCompletion.SUCCESS})()
        return True

    scanner._sync_scan = fake_sync_scan
    results = {"operations": {}}
    scanner._probe_supported_groups(results)

    op = results["operations"]["probe_objects"]
    assert op["total_supported"] == calls["n"] > 20
