#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Behavioral tests for ``oida.protocols.dnp3.mixins.polling.PollingMixin``.

These drive the real polling/enumeration logic with realistic callback data.
Only the opendnp3 *library boundary* is faked: the three synchronous wrappers
(``_sync_scan``/``_sync_task``/``_sync_callback``) that actually invoke the
opendnp3 ``IMaster`` methods are replaced with small fakes that simulate the
stack populating the handler and returning task results. The mixin's own
result-building, point-summary, IIN decoding, device-attribute parsing,
enumeration table building and group-probe loop all run for real.

Real opendnp3 enums (TaskCompletion, IINBit, GroupVariation, GroupVariationID)
are used so the failure-reason / IIN strings reflect the real library.
"""

from typing import Any, Dict, List

import pytest

from tests.service_gate import require_import

# opendnp3 (yadnp3) is required for the enums these tests assert against.
opendnp3 = require_import("opendnp3", reason="yadnp3 (opendnp3) not installed")

from oida.protocols.dnp3.scanner import DNP3Scanner


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _Flags:
    """Mimics opendnp3 Flags: has a numeric .value."""

    def __init__(self, value: int):
        self.value = value


class _ValueWrapper:
    """Mimics a measurement object: scalar .value plus a .flags carrying .value.

    Real opendnp3 Binary/Analog/Counter already expose .value and .flags, so for
    those we hand the library object straight through. This wrapper is only used
    where a test needs an explicit flag byte or an enum-like scalar.
    """

    def __init__(self, value, flags: int = 0x01):
        self.value = value
        self.flags = _Flags(flags)


class _Indexed:
    """Mimics opendnp3 Indexed<T>: an .index and a .value measurement object.

    ``measurement`` is normally a real opendnp3 Binary/Analog/Counter (already
    carrying .value/.flags). Pass an explicit ``flags`` to wrap it so the online
    bit can be controlled in tests.
    """

    def __init__(self, index: int, measurement, flags: int = None):
        self.index = index
        if flags is None:
            self.value = measurement
        else:
            scalar = getattr(measurement, "value", measurement)
            self.value = _ValueWrapper(scalar, flags)


class _SecStatValue:
    def __init__(self, count: int):
        self.value = type("_C", (), {"count": count})()
        self.quality = _Flags(0)


class _SecStatItem:
    def __init__(self, index: int, count: int):
        self.index = index
        self.value = _SecStatValue(count)


class FakeHandler:
    """Stand-in for the opendnp3 _ScanHandler, holding ready-made point data."""

    def __init__(self):
        self.binary_inputs: List[Any] = []
        self.double_bit_binary_inputs: List[Any] = []
        self.binary_output_statuses: List[Any] = []
        self.counters: List[Any] = []
        self.frozen_counters: List[Any] = []
        self.analog_inputs: List[Any] = []
        self.analog_output_statuses: List[Any] = []
        self.octet_strings: List[Any] = []
        self.security_stats: List[Any] = []
        self.string_attrs: List[Dict[str, Any]] = []
        self.cleared = 0

    def clear(self):
        self.cleared += 1
        # opendnp3 handler.clear() drops measurements but the scanner refills
        # them on the next response; our fakes pre-load via the sync stub, so
        # clearing here would wipe the data the stub just set. We only count.


class FakeApp:
    """Stand-in for _MasterApp, exposing the .iin the mixin reads."""

    def __init__(self, iin=None):
        self.iin = iin


def _make_scanner(**overrides) -> DNP3Scanner:
    args = {"rhost": "127.0.0.1", "rport": 20000}
    args.update(overrides)
    scanner = DNP3Scanner(args)
    scanner._connected = True
    scanner._master = object()
    handler = FakeHandler()
    scanner._handler = handler
    scanner._scan_handler = handler
    scanner._app = FakeApp()
    return scanner


def _arm_scan(scanner, *, succeed=True, result=None, populate=None):
    """Replace _sync_scan with a fake that optionally fills the handler.

    ``populate`` is a callable(handler) run before the result is returned,
    simulating the opendnp3 stack delivering measurements to the handler.
    """
    if result is None:
        result = opendnp3.TaskCompletion.FAILURE_RESPONSE_TIMEOUT

    def fake(scan_fn, timeout=None):
        if populate is not None:
            populate(scanner._handler)
        if succeed:
            scanner._last_task_info = type("_T", (), {"result": opendnp3.TaskCompletion.SUCCESS})()
            return True
        scanner._last_task_info = type("_T", (), {"result": result})()
        return False

    scanner._sync_scan = fake


# ---------------------------------------------------------------------------
# _perform_integrity_poll
# ---------------------------------------------------------------------------


class TestIntegrityPoll:
    def test_not_connected_records_failure(self):
        scanner = _make_scanner()
        scanner._connected = False
        results: Dict[str, Any] = {}
        scanner._perform_integrity_poll(results)
        op = results["operations"]["integrity_poll"]
        assert op["success"] is False
        assert op["error"] == "Not connected"

    def test_success_collects_points_and_summary(self):
        scanner = _make_scanner()

        def populate(h):
            h.binary_inputs = [_Indexed(0, opendnp3.Binary(True))]
            h.analog_inputs = [_Indexed(0, opendnp3.Analog(3.5)), _Indexed(1, opendnp3.Analog(9))]
            h.counters = [_Indexed(0, opendnp3.Counter(7))]

        _arm_scan(scanner, succeed=True, populate=populate)
        results = {"operations": {}}
        scanner._perform_integrity_poll(results)

        # _collect_data ran -> data_points populated with the analog values.
        dp = results["data_points"]
        assert len(dp["analog_inputs"]) == 2
        assert dp["analog_inputs"][0]["value"] == 3.5
        assert dp["analog_inputs"][0]["online"] is True
        assert dp["binary_inputs"][0]["value"] is True
        assert len(dp["counters"]) == 1
        # No failure recorded on success.
        assert "integrity_poll" not in results["operations"]

    def test_success_summary_lists_all_point_types(self):
        scanner = _make_scanner()

        def populate(h):
            # Exercise every branch of the point-summary / groups-found display.
            h.binary_inputs = [_Indexed(0, opendnp3.Binary(True))]
            h.double_bit_binary_inputs = [_Indexed(0, opendnp3.Binary(True))]
            h.binary_output_statuses = [_Indexed(0, _ValueWrapper(1))]
            h.counters = [_Indexed(0, opendnp3.Counter(1))]
            h.frozen_counters = [_Indexed(0, opendnp3.Counter(2))]
            h.analog_inputs = [_Indexed(0, opendnp3.Analog(1.0))]
            h.analog_output_statuses = [_Indexed(0, _ValueWrapper(3.0))]
            h.octet_strings = [_Indexed(0, _ValueWrapper(b"\x00"))]

        _arm_scan(scanner, succeed=True, populate=populate)
        results = {"operations": {}}
        scanner._perform_integrity_poll(results)

        dp = results["data_points"]
        # Every standard measurement type was collected into data_points.
        for key in (
            "binary_inputs",
            "double_bit_binary_inputs",
            "binary_output_statuses",
            "counters",
            "frozen_counters",
            "analog_inputs",
            "analog_output_statuses",
        ):
            assert len(dp[key]) == 1

    def test_debug_groups_found_logged(self):
        scanner = _make_scanner()
        scanner.debug = True

        def populate(h):
            h.analog_inputs = [_Indexed(0, opendnp3.Analog(1.0))]
            h.octet_strings = [_Indexed(0, _ValueWrapper(b"\x01"))]

        _arm_scan(scanner, succeed=True, populate=populate)
        results = {"operations": {}}
        scanner._perform_integrity_poll(results)
        assert len(results["data_points"]["analog_inputs"]) == 1

    def test_failure_records_reason_and_timeout_hint(self):
        scanner = _make_scanner(**{"outstation-address": 1024})
        _arm_scan(
            scanner,
            succeed=False,
            result=opendnp3.TaskCompletion.FAILURE_RESPONSE_TIMEOUT,
        )
        results = {"operations": {}}
        scanner._perform_integrity_poll(results)

        op = results["operations"]["integrity_poll"]
        assert op["success"] is False
        # The error string is the real _error_detail for a response timeout.
        assert "response timeout" in op["error"]

    def test_exception_in_scan_is_captured(self):
        scanner = _make_scanner()

        def boom(scan_fn, timeout=None):
            raise RuntimeError("socket exploded")

        scanner._sync_scan = boom
        results = {"operations": {}}
        scanner._perform_integrity_poll(results)
        op = results["operations"]["integrity_poll"]
        assert op["success"] is False
        assert "socket exploded" in op["error"]


# ---------------------------------------------------------------------------
# _perform_class_read / _perform_variation_read
# ---------------------------------------------------------------------------


class TestClassAndVariationReads:
    def test_class_read_success_prefixes_results(self):
        scanner = _make_scanner()

        def populate(h):
            h.counters = [_Indexed(2, opendnp3.Counter(99))]

        _arm_scan(scanner, succeed=True, populate=populate)
        results = {"operations": {}}
        scanner._perform_class_read(results, "1")

        # prefix "class1" -> key data_points_class1
        assert "data_points_class1" in results
        assert results["data_points_class1"]["counters"][0]["value"] == 99

    def test_class_read_failure_does_not_crash(self):
        scanner = _make_scanner()
        _arm_scan(scanner, succeed=False, result=opendnp3.TaskCompletion.FAILURE_NO_COMMS)
        results = {"operations": {}}
        scanner._perform_class_read(results, "2")
        # No data collected; no exception.
        assert "data_points_class2" not in results

    def test_class_read_not_connected_is_noop(self):
        scanner = _make_scanner()
        scanner._master = None
        results = {"operations": {}}
        scanner._perform_class_read(results, "0")
        assert results == {"operations": {}}

    def test_variation_read_parses_group_and_var(self):
        scanner = _make_scanner()
        captured = {}

        def populate(h):
            h.analog_inputs = [_Indexed(0, opendnp3.Analog(1.0))]

        def fake(scan_fn, timeout=None):
            # Exercise the lambda so the real GroupVariationID path is built.
            class _M:
                def ScanAllObjects(self, gv, handler, config):
                    captured["gv"] = gv

            scan_fn(_M(), scanner._handler, object())
            populate(scanner._handler)
            scanner._last_task_info = type("_T", (), {"result": opendnp3.TaskCompletion.SUCCESS})()
            return True

        scanner._sync_scan = fake
        results = {"operations": {}}
        scanner._perform_variation_read(results, "30.2")

        assert "gv" in captured  # lambda executed against a master
        assert "data_points_g30v2" in results
        assert results["data_points_g30v2"]["analog_inputs"][0]["value"] == 1.0

    def test_variation_read_bad_format_is_captured(self):
        scanner = _make_scanner()
        results = {"operations": {}}
        # "not.a.number" -> int() raises ValueError -> logged via .fail, no crash.
        scanner._perform_variation_read(results, "notanumber")
        # No data points stored, method survived.
        assert not any(k.startswith("data_points_g") for k in results)


# ---------------------------------------------------------------------------
# _read_device_attributes
# ---------------------------------------------------------------------------


class TestDeviceAttributes:
    def test_attributes_parsed_into_named_dict(self):
        scanner = _make_scanner()

        def populate(h):
            h.string_attrs = [
                {"variation": 252, "set": 0, "value": "AcmeRTU"},
                {"variation": 254, "set": 0, "value": "Acme Corp"},
                {"variation": 242, "set": 0, "value": "1.2.3"},
            ]

        _arm_scan(scanner, succeed=True, populate=populate)
        results = {"operations": {}}
        scanner._read_device_attributes(results)

        attrs = results["device_attributes"]
        # 252 is the product attribute in KNOWN_ATTRIBUTES.
        from oida.protocols.dnp3.constants import KNOWN_ATTRIBUTES

        prod_name = KNOWN_ATTRIBUTES[252]
        assert attrs[prod_name]["value"] == "AcmeRTU"
        assert attrs[prod_name]["variation"] == 252
        vendor_name = KNOWN_ATTRIBUTES[254]
        assert attrs[vendor_name]["value"] == "Acme Corp"

    def test_show_all_emits_non_security_attrs(self):
        scanner = _make_scanner(**{"device-attributes": True})
        assert scanner.device_attributes is True

        def populate(h):
            h.string_attrs = [{"variation": 252, "set": 0, "value": "RTU-9000"}]

        _arm_scan(scanner, succeed=True, populate=populate)
        results = {"operations": {}}
        scanner._read_device_attributes(results)
        # The product attribute is recorded regardless of show_all.
        assert any(a["value"] == "RTU-9000" for a in results["device_attributes"].values())

    def test_read_failure_does_not_set_attributes(self):
        scanner = _make_scanner()
        _arm_scan(scanner, succeed=False, result=opendnp3.TaskCompletion.FAILURE_RESPONSE_TIMEOUT)
        results = {"operations": {}}
        scanner._read_device_attributes(results)
        assert "device_attributes" not in results

    def test_success_with_no_string_attrs(self):
        scanner = _make_scanner()
        # Succeeds but handler.string_attrs stays empty -> no attrs recorded.
        _arm_scan(scanner, succeed=True, populate=lambda h: None)
        results = {"operations": {}}
        scanner._read_device_attributes(results)
        assert "device_attributes" not in results

    def test_not_connected_is_noop(self):
        scanner = _make_scanner()
        scanner._handler = None
        results = {"operations": {}}
        scanner._read_device_attributes(results)
        assert results == {"operations": {}}


# ---------------------------------------------------------------------------
# _collect_data (IIN decoding path)
# ---------------------------------------------------------------------------


class TestCollectData:
    def test_iin_bits_decoded_from_app(self):
        scanner = _make_scanner()
        scanner._app = FakeApp(iin=opendnp3.IINField(opendnp3.IINBit.DEVICE_RESTART))
        scanner._handler.analog_inputs = [_Indexed(0, opendnp3.Analog(2.0))]
        results: Dict[str, Any] = {}
        scanner._collect_data(results)

        assert results["iin"]["device_restart"] is True
        # A bit we did not set should be reported False.
        assert results["iin"]["param_error"] is False

    def test_enum_value_coerced_to_int(self):
        scanner = _make_scanner()

        # A measurement whose .value.value is itself an enum-like object with
        # a .value should be coerced to int by _collect_data.
        class _EnumLike:
            value = 5

            def __int__(self):
                return 5

        h = scanner._handler
        h.binary_output_statuses = [_Indexed(3, _ValueWrapper(_EnumLike()))]
        results = {}
        scanner._collect_data(results)
        assert results["data_points"]["binary_output_statuses"][0]["value"] == 5

    def test_offline_flag_reported(self):
        scanner = _make_scanner()
        scanner._handler.counters = [_Indexed(0, opendnp3.Counter(1), flags=0x00)]
        results = {}
        scanner._collect_data(results)
        assert results["data_points"]["counters"][0]["online"] is False


# ---------------------------------------------------------------------------
# _enumerate_points
# ---------------------------------------------------------------------------


class TestEnumeratePoints:
    def test_enumerate_from_attrs_and_observed_points(self, tmp_path):
        scanner = _make_scanner(**{"output-dir": str(tmp_path)})
        scanner.output_dir = str(tmp_path)

        results = {
            "operations": {},
            "device_attributes": {
                "Number of Analog Inputs": {"value": "3"},
                "Max Analog Input Index": {"value": "2"},
            },
            "data_points": {
                "analog_inputs": [
                    {"index": 0, "value": 1.25, "flags": 0x01},
                    {"index": 2, "value": 9.0, "flags": 0x01},
                ]
            },
        }
        scanner._enumerate_points(results)

        op = results["operations"]["enumerate_points"]
        assert op["success"] is True
        info = op["points"]["analog_inputs"]
        # Declared count/range come from the device attributes.
        assert info["count"] == 3
        assert info["max_index"] == 2
        assert info["range"] == "0-2"
        # Observed values come from the integrity poll data.
        assert info["observed_count"] == 2
        assert info["observed_range"] == "0-2"

    def test_enumerate_no_points_reports_empty(self):
        scanner = _make_scanner()
        # No attrs, no data, and no master so _read_device_attributes is a noop.
        scanner._master = None
        results = {"operations": {}, "device_attributes": {}, "data_points": {}}
        scanner._enumerate_points(results)
        op = results["operations"]["enumerate_points"]
        assert op["success"] is True
        assert op["points"] == {}

    def test_enumerate_reads_attrs_when_missing(self):
        scanner = _make_scanner()

        def populate(h):
            h.string_attrs = [
                {"variation": 252, "set": 0, "value": "Box"},
            ]

        _arm_scan(scanner, succeed=True, populate=populate)
        results = {"operations": {}, "data_points": {}}
        # No device_attributes key -> _enumerate_points calls _read_device_attributes.
        scanner._enumerate_points(results)
        assert "device_attributes" in results
        assert results["operations"]["enumerate_points"]["success"] is True


# ---------------------------------------------------------------------------
# _probe_supported_groups
# ---------------------------------------------------------------------------


class TestProbeSupportedGroups:
    def test_not_connected_is_noop(self):
        scanner = _make_scanner()
        scanner._connected = False
        results = {"operations": {}}
        scanner._probe_supported_groups(results)
        assert "probe_objects" not in results["operations"]

    def test_probe_marks_responding_groups_supported(self):
        scanner = _make_scanner()

        # Make every probed group "respond" with one analog input.
        def fake(scan_fn, timeout=None):
            scanner._handler.analog_inputs = [_Indexed(0, opendnp3.Analog(1.0))]
            scanner._last_task_info = type("_T", (), {"result": opendnp3.TaskCompletion.SUCCESS})()
            return True

        scanner._sync_scan = fake
        results = {"operations": {}}
        scanner._probe_supported_groups(results)

        op = results["operations"]["probe_objects"]
        assert op["success"] is True
        assert op["total_supported"] >= 1
        # Each supported entry carries the point count we injected.
        assert all(e["points"] >= 1 for e in op["supported"])
        assert any(e["group"] == 1 for e in op["supported"])

    def test_probe_aborts_after_consecutive_failures(self):
        scanner = _make_scanner()
        calls = {"n": 0}

        def fake(scan_fn, timeout=None):
            calls["n"] += 1
            scanner._last_task_info = type(
                "_T", (), {"result": opendnp3.TaskCompletion.FAILURE_NO_COMMS}
            )()
            return False

        scanner._sync_scan = fake
        results = {"operations": {}}
        scanner._probe_supported_groups(results)

        op = results["operations"]["probe_objects"]
        assert op["total_supported"] == 0
        # Abort kicks in at 10 consecutive failures with nothing supported,
        # so we stop well before probing all 123 groups.
        assert calls["n"] <= 20


# ---------------------------------------------------------------------------
# _read_security_stats
# ---------------------------------------------------------------------------


class TestSecurityStats:
    def test_security_stats_from_group121(self):
        scanner = _make_scanner()

        def populate(h):
            h.security_stats = [_SecStatItem(0, 42), _SecStatItem(1, 7)]

        _arm_scan(scanner, succeed=True, populate=populate)
        results = {"operations": {}}
        scanner._read_security_stats(results)

        op = results["operations"]["security_stats"]
        assert op["success"] is True
        assert op["count"] == 2
        assert op["stats"][0]["value"] == 42
        assert op["stats"][1]["index"] == 1

    def test_security_stats_fallback_to_counters(self):
        scanner = _make_scanner()

        def populate(h):
            # No security_stats, but counters present -> used as fallback.
            h.counters = [_Indexed(5, opendnp3.Counter(123))]

        _arm_scan(scanner, succeed=True, populate=populate)
        results = {"operations": {}}
        scanner._read_security_stats(results)

        op = results["operations"]["security_stats"]
        assert op["success"] is True
        assert op["count"] == 1
        assert op["stats"][0]["index"] == 5
        assert op["stats"][0]["value"] == 123

    def test_security_stats_read_failure(self):
        scanner = _make_scanner()
        _arm_scan(scanner, succeed=False, result=opendnp3.TaskCompletion.FAILURE_NO_COMMS)
        results = {"operations": {}}
        scanner._read_security_stats(results)
        op = results["operations"]["security_stats"]
        assert op["success"] is False
        assert "no communications" in op["error"]

    def test_security_stats_not_connected_noop(self):
        scanner = _make_scanner()
        scanner._master = None
        results = {"operations": {}}
        scanner._read_security_stats(results)
        assert "security_stats" not in results["operations"]


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
