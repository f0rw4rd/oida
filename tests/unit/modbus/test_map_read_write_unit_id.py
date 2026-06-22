"""
Unit tests for unit-id resolution in the Modbus map read/write-by-name mixin.

Regression coverage for the bug where an explicit `--unit-id 1` was silently
overridden by the register map's `default_unit_id`: the old code treated the
sentinel value 1 as "unset", so an operator deliberately targeting slave 1 had
their read/write redirected to the map default. The fix keys off the argparse
default (None == unset) instead.

The mixin methods are bound onto a bare instance with fake conn/logger/args and
a fake resolver, mirroring the FakeLogger / make_modbus pattern in
test_nxc_map_read.py (no __init__ / proto_flow / live scan).
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

from oida.protocols.modbus.mixins.read_write import MapReadWriteMixin


class FakeLogger:
    def __init__(self):
        self.display_msgs = []
        self.success_msgs = []
        self.warning_msgs = []
        self.fail_msgs = []

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


class FakeResolver:
    """Minimal MapNameResolver stand-in for read/write-by-name."""

    def __init__(self, default_unit_id, entry):
        self.map_data = {}
        if default_unit_id is not None:
            self.map_data["default_unit_id"] = default_unit_id
        self._entry = entry

    def resolve(self, name):
        return self._entry

    def search(self, name):
        return []

    def get_registers_needed(self, entry):
        return 1

    def encode_value(self, entry, value_str):
        return [int(value_str)]


def _reg_resp(values):
    r = MagicMock()
    r.isError.return_value = False
    r.registers = list(values)
    return r


def make_mixin(args, resolver):
    inst = MapReadWriteMixin.__new__(MapReadWriteMixin)
    inst.logger = FakeLogger()
    inst.conn = MagicMock()
    inst.args = args
    inst.results = {"data": {}, "success": True}
    inst._map_resolver = resolver
    # _get_resolver returns the cached resolver
    return inst


# ---------------------------------------------------------------------------
# Read by name
# ---------------------------------------------------------------------------

READ_ENTRY = {
    "name": "speed",
    "address": 10,
    "function_code": 3,
    "type": "u16",
    "section": "holding_registers",
}


def test_read_explicit_unit_id_1_not_overridden_by_map_default():
    """Explicit `-u 1` must reach the wire even when the map default is 7."""
    resolver = FakeResolver(default_unit_id=7, entry=READ_ENTRY)
    args = SimpleNamespace(read_name="speed", unit_id=1, register_map="m")
    inst = make_mixin(args, resolver)
    inst.conn.read_holding_registers.return_value = _reg_resp([1234])

    inst._handle_read_name()

    inst.conn.read_holding_registers.assert_called_once_with(10, count=1, device_id=1)


def test_read_unset_unit_id_uses_map_default():
    resolver = FakeResolver(default_unit_id=7, entry=READ_ENTRY)
    args = SimpleNamespace(read_name="speed", unit_id=None, register_map="m")
    inst = make_mixin(args, resolver)
    inst.conn.read_holding_registers.return_value = _reg_resp([1234])

    inst._handle_read_name()

    inst.conn.read_holding_registers.assert_called_once_with(10, count=1, device_id=7)


def test_read_unset_unit_id_no_default_falls_back_to_one():
    resolver = FakeResolver(default_unit_id=None, entry=READ_ENTRY)
    args = SimpleNamespace(read_name="speed", unit_id=None, register_map="m")
    inst = make_mixin(args, resolver)
    inst.conn.read_holding_registers.return_value = _reg_resp([1234])

    inst._handle_read_name()

    inst.conn.read_holding_registers.assert_called_once_with(10, count=1, device_id=1)


def test_read_explicit_nonone_unit_id_honoured():
    resolver = FakeResolver(default_unit_id=7, entry=READ_ENTRY)
    args = SimpleNamespace(read_name="speed", unit_id=3, register_map="m")
    inst = make_mixin(args, resolver)
    inst.conn.read_holding_registers.return_value = _reg_resp([1234])

    inst._handle_read_name()

    inst.conn.read_holding_registers.assert_called_once_with(10, count=1, device_id=3)


# ---------------------------------------------------------------------------
# Write by name (state-changing; the bug is most dangerous here)
# ---------------------------------------------------------------------------

WRITE_ENTRY = {
    "name": "setpoint",
    "address": 20,
    "function_code": 6,
    "type": "u16",
    "section": "holding_registers",
    "access": "rw",
}


def test_write_explicit_unit_id_1_not_overridden_by_map_default():
    """A write-by-name with explicit `-u 1` must land on slave 1, not the map default."""
    resolver = FakeResolver(default_unit_id=7, entry=WRITE_ENTRY)
    args = SimpleNamespace(write_name="setpoint=42", unit_id=1, register_map="m", confirm=True)
    inst = make_mixin(args, resolver)
    inst.conn.write_register.return_value = _reg_resp([])

    inst._handle_write_name()

    inst.conn.write_register.assert_called_once_with(20, 42, device_id=1)


def test_write_unset_unit_id_uses_map_default():
    resolver = FakeResolver(default_unit_id=7, entry=WRITE_ENTRY)
    args = SimpleNamespace(write_name="setpoint=42", unit_id=None, register_map="m", confirm=True)
    inst = make_mixin(args, resolver)
    inst.conn.write_register.return_value = _reg_resp([])

    inst._handle_write_name()

    inst.conn.write_register.assert_called_once_with(20, 42, device_id=7)


def test_write_unset_unit_id_no_default_falls_back_to_one():
    resolver = FakeResolver(default_unit_id=None, entry=WRITE_ENTRY)
    args = SimpleNamespace(write_name="setpoint=42", unit_id=None, register_map="m", confirm=True)
    inst = make_mixin(args, resolver)
    inst.conn.write_register.return_value = _reg_resp([])

    inst._handle_write_name()

    inst.conn.write_register.assert_called_once_with(20, 42, device_id=1)
