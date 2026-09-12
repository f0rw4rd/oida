"""
Regression tests for two write-restore safety bugs found in review:

- A9 (src/oida/protocols/modbus/mixins/fuzz.py, _fuzz_registers): a failed
  pre-fuzz read of addr+1 during a 2-register typed fuzz run used to leave
  addr+1 permanently holding fuzzed data with no visible warning.
- A10 (src/oida/protocols/modbus/scanner_mixins/write_ops.py,
  _write_multiple_registers / _write_multiple_coils): restoration was
  gated on a truthy-list check instead of `is not None`, so an empty
  original_values list silently skipped restore reporting -- unlike the
  single-register path, which already used `is not None`.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock


from tests.service_gate import require_import

require_import("pymodbus", reason="pymodbus library not installed")


class FakeLogger:
    def __init__(self):
        self.display_msgs = []
        self.success_msgs = []
        self.warning_msgs = []
        self.fail_msgs = []
        self.debug_msgs = []

    def display(self, msg=""):
        self.display_msgs.append(msg)

    def success(self, msg):
        self.success_msgs.append(msg)

    def warning(self, msg):
        self.warning_msgs.append(msg)

    def fail(self, msg):
        self.fail_msgs.append(msg)

    def debug(self, msg):
        self.debug_msgs.append(msg)


def _ok(**extra):
    r = MagicMock()
    r.isError.return_value = False
    for k, v in extra.items():
        setattr(r, k, v)
    return r


def make_modbus(args=None, unit_id=1):
    from oida.protocols.modbus.cli_runner import modbus

    inst = modbus.__new__(modbus)
    inst.logger = FakeLogger()
    inst.conn = MagicMock()
    inst.scanner = MagicMock()
    inst.scanner.unit_id = unit_id
    inst.results = {"data": {}}
    inst.args = args if args is not None else SimpleNamespace()
    return inst


# ---------------------------------------------------------------------------
# A9 -- fuzz.py _fuzz_registers: 2-register typed restore
# ---------------------------------------------------------------------------


class TestA9TypedRestoreWarning:
    def _run(self, inst, hi_read_ok, hi_value=5678, write_registers_raises=None):
        """Drive a single-address, 2-register typed (u32) fuzz run with
        register_io.read_registers_batched only returning addr's original
        value (as it does when addr+1 wasn't part of the batch), forcing
        the fallback single read of addr+1 at fuzz.py:110-118.
        """
        from unittest.mock import patch

        inst.conn.write_register.return_value = _ok()
        if write_registers_raises:
            inst.conn.write_registers.side_effect = write_registers_raises
        else:
            inst.conn.write_registers.return_value = _ok()

        if hi_read_ok:
            inst.conn.read_holding_registers.return_value = _ok(registers=[hi_value])
        else:
            inst.conn.read_holding_registers.side_effect = TimeoutError("read timed out")

        with patch(
            "oida.protocols.modbus.register_io.read_registers_batched",
            return_value={0: 1234},  # only addr=0's original value known
        ):
            stats = inst._fuzz_registers(2, "boundary")
        return stats

    def test_hi_read_failure_warns_and_restores_addr_only(self):
        """A9: pre-fuzz read of addr+1 fails -> must WARN naming addr+1,
        and addr itself must still be restored via write_register."""
        inst = make_modbus(SimpleNamespace(scan_range="0-0", decode="u32", fuzz_max_addresses=10))
        stats = self._run(inst, hi_read_ok=False)

        # addr (0) restored with its known original value.
        inst.conn.write_register.assert_any_call(0, 1234, device_id=1)
        # addr+1 (1) was never restored via write_registers with a real pair
        # -- write_registers should not have been called with a restore pair
        # containing a valid hi value, since we never learned it.
        warn_text = " ".join(inst.logger.warning_msgs)
        assert "1" in warn_text and (
            "could not restore" in warn_text.lower() or "restore" in warn_text.lower()
        )
        assert stats["restore_warnings"], "expected a restore_warnings entry in stats"
        assert any(w["address"] == 1 for w in stats["restore_warnings"])

    def test_hi_read_success_restores_pair_no_warning(self):
        """Control case: hi read succeeds -> full pair restored via
        write_registers, and no restore warning is emitted."""
        inst = make_modbus(SimpleNamespace(scan_range="0-0", decode="u32", fuzz_max_addresses=10))
        stats = self._run(inst, hi_read_ok=True, hi_value=5678)

        inst.conn.write_registers.assert_any_call(0, [1234, 5678], device_id=1)
        assert stats["restore_warnings"] == []
        assert inst.logger.warning_msgs == []

    def test_restore_write_failure_warns(self):
        """A9: the actual restore write raising must be a WARNING, not a
        debug-only message that operators never see."""
        inst = make_modbus(SimpleNamespace(scan_range="0-0", decode="u32", fuzz_max_addresses=10))
        stats = self._run(
            inst, hi_read_ok=True, hi_value=5678, write_registers_raises=OSError("conn reset")
        )
        assert inst.logger.warning_msgs, "restore failure must be warned, not just debug-logged"
        assert stats["restore_warnings"]


# ---------------------------------------------------------------------------
# A10 -- write_ops.py: empty original_values must behave like None
# ---------------------------------------------------------------------------


class ScannerHarness:
    """Minimal harness exposing the write-ops mixin with the attributes it
    needs (self.unit_id, self.logger)."""

    def __init__(self):
        from oida.protocols.modbus.scanner_mixins.write_ops import ScannerWriteOpsMixin

        self.unit_id = 1
        self.logger = FakeLogger()
        self._mixin = ScannerWriteOpsMixin


def make_scanner():
    from oida.protocols.modbus.scanner_mixins.write_ops import ScannerWriteOpsMixin

    class _Scanner(ScannerWriteOpsMixin):
        def __init__(self):
            self.unit_id = 1
            self.logger = FakeLogger()

    return _Scanner()


class TestA10EmptyOriginalValuesParity:
    def test_single_register_none_skips_restore(self):
        scanner = make_scanner()
        client = MagicMock()
        client.read_holding_registers.return_value = _ok()
        client.read_holding_registers.return_value.registers = []
        # Simulate a read error so original_value stays None (the documented
        # "restore skipped" case for the single-register path).
        client.read_holding_registers.return_value.isError.return_value = True
        client.write_register.return_value = _ok()

        result = scanner._write_register_safe(client, 0, 99, register_type="holding")
        assert result["original_value"] is None
        # write_register called once for the test write only, not for restore.
        assert client.write_register.call_count == 1

    def test_multi_register_empty_list_still_attempts_restore(self):
        """A10 parity: `[] is not None` is True, so -- exactly like the
        single-register path's `is not None` gate -- a successful-but-empty
        read must still be treated as "we have a (trivial) original value"
        and a restore must be attempted, not silently skipped via a bare
        truthy check on the list."""
        scanner = make_scanner()
        client = MagicMock()
        # read succeeds but returns zero registers -> original_values == []
        ok = _ok()
        ok.registers = []
        client.read_holding_registers.return_value = ok
        client.write_registers.return_value = _ok()

        result = scanner._write_multiple_registers(client, 0, [1, 2], restore_on_exit=True)
        assert result["original_values"] == []
        # One call for the test write, one restore attempt -- parity with
        # the single-register path's `is not None` semantics.
        assert client.write_registers.call_count == 2
        client.write_registers.assert_any_call(0, [], device_id=1)

    def test_multi_coil_empty_list_still_attempts_restore(self):
        scanner = make_scanner()
        client = MagicMock()
        ok = _ok()
        ok.bits = []
        client.read_coils.return_value = ok
        client.write_coils.return_value = _ok()

        result = scanner._write_multiple_coils(client, 0, [True, False], restore_on_exit=True)
        assert result["original_values"] == []
        assert client.write_coils.call_count == 2
        client.write_coils.assert_any_call(0, [], device_id=1)
