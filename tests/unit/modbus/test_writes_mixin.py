"""
Unit tests for oida.protocols.modbus.mixins.writes.WritesMixin.

Covers the write-command dispatch and the safety / confirm-gating logic:
- _handle_write: spec parsing, typed (-d) encoding, confirm gating (dry-run
  rendering when --confirm absent), single vs multiple register dispatch,
  success/fail rendering, broadcast routing.
- _handle_write_coil / _handle_write_multiple / _handle_write_multiple_coils:
  spec validation, confirm gating, scanner delegation.
- _handle_broadcast_write* : unit-id-0 path, no-response success, exceptions.
- _handle_test_write: destructive-mode confirm gate, safe-mode default,
  writable-register security finding emission.

Methods are bound onto a bare object (the mixin has no __init__ state of its
own) with fake conn / logger / scanner / args, the same approach as the
existing FakeSunSpecMixin in test_sunspec.py.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

try:
    import pymodbus  # noqa: F401

    PYMODBUS_AVAILABLE = True
except ImportError:
    PYMODBUS_AVAILABLE = False

pytestmark = pytest.mark.skipif(not PYMODBUS_AVAILABLE, reason="pymodbus library not installed")


class FakeLogger:
    def __init__(self):
        self.display_msgs = []
        self.success_msgs = []
        self.warning_msgs = []
        self.fail_msgs = []
        self.findings = []

    def display(self, msg=""):
        self.display_msgs.append(msg)

    def success(self, msg):
        self.success_msgs.append(msg)

    def warning(self, msg):
        self.warning_msgs.append(msg)

    def fail(self, msg):
        self.fail_msgs.append(msg)

    def debug(self, msg):
        pass

    def security_finding(self, title, category="", detail=""):
        self.findings.append({"title": title, "category": category, "detail": detail})


class FakeWrites:
    """Bind WritesMixin methods onto a configurable bare object."""

    def __init__(self, args=None, decode_type=None, endian="big", broadcast=False):
        from oida.protocols.modbus.mixins.writes import WritesMixin

        self.logger = FakeLogger()
        self.conn = MagicMock()
        self.scanner = MagicMock()
        self.results = {"data": {}}
        self.args = args if args is not None else SimpleNamespace()
        self.decode_type = decode_type
        self.endian = endian
        self._broadcast = broadcast
        for name in (
            "_handle_write",
            "_handle_write_coil",
            "_handle_write_multiple",
            "_handle_write_multiple_coils",
            "_handle_broadcast_write",
            "_handle_broadcast_write_coil",
            "_handle_broadcast_write_multiple_coils",
            "_handle_test_write",
        ):
            setattr(self, name, getattr(WritesMixin, name).__get__(self, FakeWrites))

    @property
    def broadcast_mode(self):
        return self._broadcast


# ---------------------------------------------------------------------------
# _handle_write
# ---------------------------------------------------------------------------


class TestHandleWrite:
    def test_no_write_spec_noop(self):
        fw = FakeWrites(args=SimpleNamespace(write=None))
        fw._handle_write()
        assert fw.results["data"] == {}

    def test_invalid_spec_fails(self):
        fw = FakeWrites(args=SimpleNamespace(write="notaspec"))
        fw._handle_write()
        assert any("Invalid write spec" in m for m in fw.logger.fail_msgs)

    def test_non_integer_value_without_type_fails(self):
        fw = FakeWrites(args=SimpleNamespace(write="10=abc"))
        fw._handle_write()
        assert any("Invalid integer value" in m for m in fw.logger.fail_msgs)

    def test_confirm_required_dry_run_single(self):
        # No --confirm: must NOT write, must render a dry-run message.
        fw = FakeWrites(args=SimpleNamespace(write="10=42", confirm=False))
        fw._handle_write()
        assert any("requires --confirm" in m for m in fw.logger.fail_msgs)
        fw.scanner._write_register_safe.assert_not_called()
        assert any("Would write 42 to register 10" in m for m in fw.logger.display_msgs)

    def test_single_register_write_success(self):
        fw = FakeWrites(args=SimpleNamespace(write="10=42", confirm=True, restore_on_exit=False))
        fw.scanner._write_register_safe.return_value = {"success": True}
        fw._handle_write()
        fw.scanner._write_register_safe.assert_called_once()
        # value 42 went to address 10
        args, kwargs = fw.scanner._write_register_safe.call_args
        assert args[1] == 10 and args[2] == 42
        assert fw.results["data"]["write"] == {"success": True}
        assert any("written to 10" in m for m in fw.logger.success_msgs)

    def test_single_register_write_failure_reported(self):
        fw = FakeWrites(args=SimpleNamespace(write="10=42", confirm=True, restore_on_exit=False))
        fw.scanner._write_register_safe.return_value = {"success": False, "error": "denied"}
        fw._handle_write()
        assert any("denied" in m for m in fw.logger.fail_msgs)

    def test_restored_value_message(self):
        fw = FakeWrites(args=SimpleNamespace(write="10=42", confirm=True, restore_on_exit=True))
        fw.scanner._write_register_safe.return_value = {
            "success": True,
            "restored": True,
            "original_value": 7,
        }
        fw._handle_write()
        assert any("Original value 7 restored" in m for m in fw.logger.display_msgs)

    def test_typed_encoding_multi_register(self):
        # f32 encodes to 2 registers -> goes through _write_multiple_registers
        fw = FakeWrites(
            args=SimpleNamespace(write="100=3.14", confirm=True, restore_on_exit=False),
            decode_type="f32",
        )
        fw.scanner._write_multiple_registers.return_value = {"success": True}
        fw._handle_write()
        fw.scanner._write_multiple_registers.assert_called_once()
        args, _ = fw.scanner._write_multiple_registers.call_args
        assert args[1] == 100
        assert len(args[2]) == 2  # two registers for f32

    def test_typed_encoding_invalid_value_fails(self):
        fw = FakeWrites(
            args=SimpleNamespace(write="100=notafloat", confirm=True),
            decode_type="f32",
        )
        fw._handle_write()
        assert any("Failed to encode" in m for m in fw.logger.fail_msgs)

    def test_broadcast_routes_to_broadcast_write(self):
        fw = FakeWrites(args=SimpleNamespace(write="10=42", confirm=True), broadcast=True)
        fw._handle_write()
        # broadcast path sends via conn.write_register with device_id 0
        fw.conn.write_register.assert_called_once()
        _, kwargs = fw.conn.write_register.call_args
        assert kwargs.get("device_id") == 0


# ---------------------------------------------------------------------------
# _handle_write_coil
# ---------------------------------------------------------------------------


class TestHandleWriteCoil:
    def test_invalid_coil_value_fails(self):
        fw = FakeWrites(args=SimpleNamespace(write_coil="5=2"))
        fw._handle_write_coil()
        assert any("Invalid write-coil spec" in m for m in fw.logger.fail_msgs)

    def test_confirm_required(self):
        fw = FakeWrites(args=SimpleNamespace(write_coil="5=1", confirm=False))
        fw._handle_write_coil()
        assert any("requires --confirm" in m for m in fw.logger.fail_msgs)
        fw.scanner._write_register_safe.assert_not_called()

    def test_write_coil_success(self):
        fw = FakeWrites(args=SimpleNamespace(write_coil="5=1", confirm=True, restore_on_exit=False))
        fw.scanner._write_register_safe.return_value = {"success": True}
        fw._handle_write_coil()
        _, kwargs = fw.scanner._write_register_safe.call_args
        assert kwargs.get("register_type") == "coil"
        assert any("written to coil 5" in m for m in fw.logger.success_msgs)

    def test_broadcast_coil(self):
        fw = FakeWrites(args=SimpleNamespace(write_coil="5=1", confirm=True), broadcast=True)
        fw._handle_write_coil()
        _, kwargs = fw.conn.write_coil.call_args
        assert kwargs.get("device_id") == 0


# ---------------------------------------------------------------------------
# _handle_write_multiple / _handle_write_multiple_coils
# ---------------------------------------------------------------------------


class TestHandleWriteMultiple:
    def test_parse_error(self):
        fw = FakeWrites(args=SimpleNamespace(write_multiple="bad"))
        fw._handle_write_multiple()
        assert any("Invalid write-multiple spec" in m for m in fw.logger.fail_msgs)

    def test_confirm_required(self):
        fw = FakeWrites(args=SimpleNamespace(write_multiple="10=1,2,3", confirm=False))
        fw._handle_write_multiple()
        fw.scanner._write_multiple_registers.assert_not_called()

    def test_success(self):
        fw = FakeWrites(
            args=SimpleNamespace(write_multiple="10=1,2,3", confirm=True, restore_on_exit=False)
        )
        fw.scanner._write_multiple_registers.return_value = {"success": True}
        fw._handle_write_multiple()
        args, _ = fw.scanner._write_multiple_registers.call_args
        assert args[1] == 10 and args[2] == [1, 2, 3]

    def test_multiple_coils_parse(self):
        fw = FakeWrites(
            args=SimpleNamespace(
                write_multiple_coils="0=1,0,1", confirm=True, restore_on_exit=False
            )
        )
        fw.scanner._write_multiple_coils.return_value = {"success": True}
        fw._handle_write_multiple_coils()
        args, _ = fw.scanner._write_multiple_coils.call_args
        assert args[2] == [True, False, True]


# ---------------------------------------------------------------------------
# broadcast helpers
# ---------------------------------------------------------------------------


class TestBroadcastHelpers:
    def test_broadcast_write_multiple_registers(self):
        fw = FakeWrites(args=SimpleNamespace())
        fw._handle_broadcast_write(10, [1, 2], "2 values")
        fw.conn.write_registers.assert_called_once_with(10, [1, 2], device_id=0)
        assert fw.results["data"]["broadcast_write"]["broadcast"] is True

    def test_broadcast_write_exception_recorded(self):
        fw = FakeWrites(args=SimpleNamespace())
        fw.conn.write_register.side_effect = OSError("net down")
        fw._handle_broadcast_write(10, [1], "1")
        assert "error" in fw.results["data"]["broadcast_write"]
        assert any("Write failed" in m for m in fw.logger.fail_msgs)

    def test_broadcast_write_coil(self):
        fw = FakeWrites(args=SimpleNamespace())
        fw._handle_broadcast_write_coil(3, True)
        fw.conn.write_coil.assert_called_once_with(3, True, device_id=0)
        assert fw.results["data"]["broadcast_write_coil"]["value"] is True

    def test_broadcast_write_multiple_coils(self):
        fw = FakeWrites(args=SimpleNamespace())
        fw._handle_broadcast_write_multiple_coils(0, [True, False])
        fw.conn.write_coils.assert_called_once_with(0, [True, False], device_id=0)
        assert fw.results["data"]["broadcast_write_multiple_coils"]["count"] == 2


# ---------------------------------------------------------------------------
# _handle_test_write
# ---------------------------------------------------------------------------


class TestHandleTestWrite:
    def test_destructive_requires_confirm(self):
        fw = FakeWrites(
            args=SimpleNamespace(test_write_thorough=True, confirm=False, scan_range="0-5")
        )
        fw._handle_test_write()
        assert any("destructive" in m and "--confirm" in m for m in fw.logger.fail_msgs)
        fw.scanner._scan_write_access.assert_not_called()

    def test_safe_mode_runs_without_confirm(self):
        fw = FakeWrites(
            args=SimpleNamespace(
                test_write_thorough=False, scan_range="0-2", register_type="holding"
            )
        )
        fw.scanner._scan_write_access.return_value = {
            "writable": [],
            "read_only": [0, 1, 2],
            "errors": [],
        }
        fw._handle_test_write()
        fw.scanner._scan_write_access.assert_called_once()
        _, kwargs = fw.scanner._scan_write_access.call_args
        assert kwargs["mode"] == "safe"
        assert kwargs["register_type"] == "holding_registers"

    def test_writable_registers_emit_security_finding(self):
        fw = FakeWrites(args=SimpleNamespace(test_write_thorough=False, scan_range="0-2"))
        fw.scanner._scan_write_access.return_value = {
            "writable": [{"address": 0, "value": 1}, {"address": 1, "value": 2}],
            "read_only": [],
            "errors": [],
        }
        fw._handle_test_write()
        assert any(f["title"] == "Writable access" for f in fw.logger.findings)
        assert fw.results["data"]["test_write"]["writable"]

    def test_coil_register_type_mapped(self):
        fw = FakeWrites(
            args=SimpleNamespace(test_write_thorough=False, scan_range="0-1", register_type="coil")
        )
        fw.scanner._scan_write_access.return_value = {
            "writable": [],
            "read_only": [],
            "errors": [],
        }
        fw._handle_test_write()
        _, kwargs = fw.scanner._scan_write_access.call_args
        assert kwargs["register_type"] == "coils"
