#!/usr/bin/env python3
"""Unit tests for the NXC-style ``mms`` callable connection class.

The base NetworkConnection runs proto_flow() during __init__, so we patch
proto_flow to a no-op to build a bare instance, then drive the individual
workflow methods directly with a mocked MMSScanner and mocked native _Lib.
"""

import argparse
from enum import IntEnum
from unittest.mock import MagicMock, patch

import pytest

from oida.protocols.mms.cli_runner import mms
from oida.protocols.mms import _Lib


class _FC(IntEnum):
    """Stand-in for pyiec61850.mms.FC."""

    ST = 0
    MX = 1
    SP = 2
    DC = 5
    CO = 12


class _ReadError(Exception):
    """Stand-in for pyiec61850.mms.ReadError."""


def _make(**arg_overrides):
    """Construct an mms instance without running the scan."""
    base = dict(port=102, timeout=5, debug=False, verbose=0, quiet=False)
    base.update(arg_overrides)
    args = argparse.Namespace(**base)
    with patch.object(mms, "proto_flow", lambda self: None):
        inst = mms(args, None, "127.0.0.1")
    return inst


class TestProtoFlow:
    def test_proto_flow_aborts_on_failed_connection(self):
        inst = _make()
        scanner = MagicMock()
        scanner.connect.return_value = None
        with (
            patch("oida.protocols.mms.cli_runner.MMSScanner", return_value=scanner),
            # The cause probe would dial a real socket; pin it like the
            # connect-failure contract tests do.
            patch(
                "oida.utils.protocol_helpers.probe_connect_failure_cause",
                return_value="refused",
            ),
            patch.object(inst, "enum_host_info") as enum,
            patch.object(inst, "_execute_scan") as exec_scan,
        ):
            mms.proto_flow(inst)
        assert inst.results["success"] is False
        # Canonical contract error (GH #59), not the old generic string.
        assert inst.results["error"].startswith("connect refused")
        enum.assert_not_called()
        exec_scan.assert_not_called()

    def test_proto_flow_runs_full_chain_on_success(self):
        inst = _make()
        scanner = MagicMock()
        scanner.connect.return_value = MagicMock()
        with (
            patch("oida.protocols.mms.cli_runner.MMSScanner", return_value=scanner),
            patch.object(inst, "enum_host_info") as enum,
            patch.object(inst, "print_host_info") as printer,
            patch.object(inst, "_execute_scan") as exec_scan,
        ):
            mms.proto_flow(inst)
        enum.assert_called_once()
        printer.assert_called_once()
        exec_scan.assert_called_once()
        assert inst.conn is scanner.connect.return_value


class TestCreateConnObj:
    def test_sets_conn_on_success(self):
        inst = _make()
        inst.scanner = MagicMock()
        conn = MagicMock()
        inst.scanner.connect.return_value = conn
        inst.create_conn_obj()
        assert inst.conn is conn

    def test_conn_none_on_failure(self):
        inst = _make()
        inst.scanner = MagicMock()
        inst.scanner.connect.return_value = None
        inst.create_conn_obj()
        assert inst.conn is None


class TestEnumHostInfo:
    def test_stores_server_info(self):
        inst = _make()
        inst.conn = MagicMock()
        inst.scanner = MagicMock()
        inst.scanner._get_server_info.return_value = {"vendor": "ACME"}
        inst.enum_host_info()
        assert inst.results["data"]["device_info"] == {"vendor": "ACME"}

    def test_no_conn_does_nothing(self):
        inst = _make()
        inst.conn = None
        inst.scanner = MagicMock()
        inst.enum_host_info()
        assert "device_info" not in inst.results["data"]
        inst.scanner._get_server_info.assert_not_called()

    def test_enum_exception_recorded(self):
        inst = _make()
        inst.conn = MagicMock()
        inst.scanner = MagicMock()
        inst.scanner._get_server_info.side_effect = RuntimeError("nope")
        inst.enum_host_info()
        info = inst.results["data"]["device_info"]
        assert info["connected"] is True
        assert "nope" in info["enum_error"]


class TestPrintHostInfo:
    def test_quiet_suppresses_output(self):
        inst = _make(quiet=True)
        inst.results["data"]["device_info"] = {"vendor": "ACME"}
        inst.logger = MagicMock()
        inst.print_host_info()
        inst.logger.display.assert_not_called()

    def test_prints_present_fields_only(self):
        inst = _make()
        inst.results["data"]["device_info"] = {
            "vendor": "ACME",
            "revision": "R1",
            "logical_device_count": 4,
        }
        inst.logger = MagicMock()
        inst.print_host_info()
        printed = " ".join(c.args[0] for c in inst.logger.display.call_args_list)
        assert "Vendor: ACME" in printed
        assert "Revision: R1" in printed
        assert "Logical Devices: 4" in printed
        assert "Model" not in printed  # absent field not printed


class TestExecuteScan:
    def test_runs_discover_and_stores_results(self):
        inst = _make()
        inst.conn = MagicMock()
        inst.scanner = MagicMock()
        inst.results["data"]["device_info"] = {"vendor": "X"}
        scan_res = {"data_objects": []}
        inst.scanner.discover.return_value = scan_res
        inst.logger = MagicMock()
        inst._execute_scan()
        inst.scanner.discover.assert_called_once_with(inst.conn, server_info={"vendor": "X"})
        assert inst.results["data"]["scan_results"] is scan_res

    def test_triggers_fuzz_when_flag_set(self):
        inst = _make(fuzz=True)
        inst.conn = MagicMock()
        inst.scanner = MagicMock()
        inst.scanner.discover.return_value = {"write_test_results": {}}
        inst.logger = MagicMock()
        with patch.object(inst, "_handle_fuzz") as handle:
            inst._execute_scan()
        handle.assert_called_once()

    def test_no_conn_skips(self):
        inst = _make()
        inst.conn = None
        inst.scanner = MagicMock()
        inst._execute_scan()
        inst.scanner.discover.assert_not_called()


class TestHandleFuzz:
    def test_fuzz_requires_confirm(self):
        inst = _make(fuzz=True, confirm=False)
        inst.logger = MagicMock()
        with patch.object(inst, "_fuzz_data_object") as fdo:
            inst._handle_fuzz({"write_test_results": {"successful_writes": [{"reference": "r"}]}})
        fdo.assert_not_called()
        inst.logger.fail.assert_called()

    def test_fuzz_reference_path(self):
        inst = _make(fuzz=True, confirm=True, fuzz_reference="LD0/A", fuzz_iterations=5)
        inst.logger = MagicMock()
        with patch.object(inst, "_fuzz_data_object") as fdo:
            inst._handle_fuzz({})
        fdo.assert_called_once_with("LD0/A", 5)

    def test_fuzz_warns_when_no_writable_objects(self):
        inst = _make(fuzz=True, confirm=True, fuzz_reference=None)
        inst.logger = MagicMock()
        with patch.object(inst, "_fuzz_data_object") as fdo:
            inst._handle_fuzz({"write_test_results": {"successful_writes": []}})
        fdo.assert_not_called()
        inst.logger.warning.assert_called()

    def test_fuzz_iterates_writable_objects(self):
        inst = _make(
            fuzz=True,
            confirm=True,
            fuzz_reference=None,
            fuzz_iterations=3,
            fuzz_max_targets=2,
        )
        inst.logger = MagicMock()
        writes = {
            "write_test_results": {
                "successful_writes": [
                    {"reference": "LD0/A"},
                    {"reference": "LD0/B"},
                    {"reference": "LD0/C"},  # beyond max_targets=2
                ]
            }
        }
        with patch.object(inst, "_fuzz_data_object") as fdo:
            inst._handle_fuzz(writes)
        called_refs = [c.args[0] for c in fdo.call_args_list]
        assert called_refs == ["LD0/A", "LD0/B"]

    def test_fuzz_disabled_returns_immediately(self):
        inst = _make(fuzz=False)
        inst.logger = MagicMock()
        with patch.object(inst, "_fuzz_data_object") as fdo:
            inst._handle_fuzz({})
        fdo.assert_not_called()


class TestFuzzDataObject:
    """Fuzz loop tests against a high-level MMSClient connection.

    ``self.conn`` is an MMSClient mock (``read_value`` stubbed); writes go
    through the module-level ``_write_under_fc`` shim (patched here). The
    scanner's ``_normalize_read`` is wired to pass its argument through so the
    raw ``read_value`` return is what the fuzz loop sees.
    """

    def _prep(self, **arg_overrides):
        inst = _make(**arg_overrides)
        inst.conn = MagicMock()
        inst.scanner = MagicMock()
        # _normalize_read is a no-op passthrough for these tests; the scanner is
        # a MagicMock, so wire it explicitly.
        inst.scanner._normalize_read.side_effect = lambda v: v
        inst.logger = MagicMock()
        return inst

    def test_read_value_int_to_signed_le_bytes(self):
        # Drives _fuzz_data_object's inner read/write closures via a fuzz()
        # that yields a single payload, then asserts the write shim received
        # the round-tripped little-endian signed int under the discovered FC.
        inst = self._prep(fuzz=True, confirm=True, fuzz_iterations=1)
        inst.conn.read_value.return_value = -1  # signed value read back

        with (
            patch.object(_Lib, "require"),
            patch.object(_Lib, "FC", _FC),
            patch.object(_Lib, "ReadError", _ReadError),
            patch("oida.protocols.mms.cli_runner._write_under_fc", return_value=True) as wuf,
            patch("oida.utils.fuzzer.fuzz", return_value=[(b"\x01\x00\x00\x00", "desc")]),
            patch("time.sleep"),
        ):
            inst._fuzz_data_object("LD0/A", 1)

        # write_value packs payload[:4] little-endian signed -> 1
        written_values = [c.args[2] for c in wuf.call_args_list]
        assert 1 in written_values  # the fuzz payload \x01\x00\x00\x00 -> 1
        # a status line was emitted
        assert inst.logger.display.called

    def test_anomaly_detected_when_readback_differs(self):
        # original read = 0; writes succeed; readback differs from both the
        # payload and the original -> anomaly counter + warning.
        inst = self._prep(fuzz=True, confirm=True, fuzz_iterations=1)
        # read_value returns: probe(0), original(0), readback(999), restore-read N/A.
        inst.conn.read_value.side_effect = [0, 0, 999, 0, 0, 0]

        with (
            patch.object(_Lib, "require"),
            patch.object(_Lib, "FC", _FC),
            patch.object(_Lib, "ReadError", _ReadError),
            patch("oida.protocols.mms.cli_runner._write_under_fc", return_value=True),
            patch("oida.utils.fuzzer.fuzz", return_value=[(b"\x05\x00\x00\x00", "desc")]),
            patch("time.sleep"),
        ):
            inst._fuzz_data_object("LD0/A", 1)

        # the anomaly path logs a warning
        warned = " ".join(c.args[0] for c in inst.logger.warning.call_args_list)
        assert "Anomaly" in warned

    def test_float_original_restored_with_typed_value_not_bogus_int(self):
        # Regression: a non-integer object (float) must be restored to its
        # ORIGINAL typed value (the float), never reinterpreted as a signed
        # integer from its packed bytes (which would corrupt the device).
        inst = self._prep(fuzz=True, confirm=True, fuzz_iterations=1)
        # every read returns the same float
        inst.conn.read_value.return_value = 23.4

        with (
            patch.object(_Lib, "require"),
            patch.object(_Lib, "FC", _FC),
            patch.object(_Lib, "ReadError", _ReadError),
            patch("oida.protocols.mms.cli_runner._write_under_fc", return_value=True) as wuf,
            patch("oida.utils.fuzzer.fuzz", return_value=[(b"\x01\x00\x00\x00", "desc")]),
            patch("time.sleep"),
        ):
            inst._fuzz_data_object("LD0/A", 1)

        written_values = [c.args[2] for c in wuf.call_args_list]
        # The final restore write must pass the ORIGINAL typed float, so
        # python_to_mms_value reconstructs the correct MMS type downstream.
        assert wuf.call_args_list[-1].args[2] == 23.4
        # The packed float bytes (0x41bb3333 -> 1102957363) must NEVER be
        # written back as an integer during restore.
        assert 1102957363 not in written_values

    def test_fuzz_write_uses_discovered_fc_not_hardcoded_co(self):
        # Regression: the object is writable ONLY under FC_SP (a setpoint), not
        # FC_CO. The fuzz writer must target the discovered FC_SP, otherwise
        # every write fails (successful=0) and no real fuzzing happens.
        inst = self._prep(fuzz=True, confirm=True, fuzz_iterations=1)
        inst.conn.read_value.return_value = 7

        # _write_under_fc accepts a write only under FC_SP.
        def fake_write(client, reference, value, fc):
            return fc == _FC.SP

        with (
            patch.object(_Lib, "require"),
            patch.object(_Lib, "FC", _FC),
            patch.object(_Lib, "ReadError", _ReadError),
            patch("oida.protocols.mms.cli_runner._write_under_fc", side_effect=fake_write) as wuf,
            patch("oida.utils.fuzzer.fuzz", return_value=[(b"\x01\x00\x00\x00", "desc")]),
            patch("time.sleep"),
        ):
            inst._fuzz_data_object("LD0/Setpoint", 1)

        # The fuzz-payload write packs the int 1; isolate those writes.
        fuzz_write_fcs = [c.args[3] for c in wuf.call_args_list if c.args[2] == 1]
        assert fuzz_write_fcs, "expected the fuzz payload to be written at least once"
        # The fuzz write must target the DISCOVERED FC_SP, never the old
        # hardcoded FC_CO.
        assert all(fc == _FC.SP for fc in fuzz_write_fcs)
        assert _FC.CO not in fuzz_write_fcs
        # Reads must use the same discovered FC_SP, never the old FC_MX default.
        read_fcs = [c.kwargs["fc"] for c in inst.conn.read_value.call_args_list]
        assert _FC.MX not in read_fcs

    def test_read_value_none_returns_zero_bytes(self):
        inst = self._prep(fuzz=True, confirm=True)
        inst.conn.read_value.return_value = None

        with (
            patch.object(_Lib, "require"),
            patch.object(_Lib, "FC", _FC),
            patch.object(_Lib, "ReadError", _ReadError),
            patch("oida.protocols.mms.cli_runner._write_under_fc", return_value=False),
            patch("oida.utils.fuzzer.fuzz", return_value=[]),
            patch("time.sleep"),
        ):
            # no fuzz iterations -> just exercises read_value() == zero bytes
            inst._fuzz_data_object("LD0/A", 0)
        # original read returned None -> restored write skipped, but display ran
        assert inst.logger.display.called


class TestCleanupAndDeps:
    def test_cleanup_disconnects_and_clears_conn(self):
        inst = _make()
        conn = MagicMock()
        inst.conn = conn
        inst.scanner = MagicMock()
        inst.logger = MagicMock()
        with patch("time.sleep"):
            inst.cleanup()
        inst.scanner.disconnect.assert_called_once_with(conn)
        assert inst.conn is None

    def test_cleanup_no_conn_is_noop(self):
        inst = _make()
        inst.conn = None
        inst.scanner = MagicMock()
        inst.cleanup()
        inst.scanner.disconnect.assert_not_called()

    def test_cleanup_swallows_disconnect_error(self):
        inst = _make()
        inst.conn = MagicMock()
        inst.scanner = MagicMock()
        inst.scanner.disconnect.side_effect = RuntimeError("boom")
        inst.logger = MagicMock()
        with patch("time.sleep"):
            inst.cleanup()  # must not raise
        assert inst.conn is None

    def test_check_dependencies_reflects_availability(self):
        with patch("oida.protocols.mms.cli_runner._pyiec61850") as dep:
            dep.is_available = True
            assert mms.check_dependencies() is True
            dep.is_available = False
            assert mms.check_dependencies() is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
