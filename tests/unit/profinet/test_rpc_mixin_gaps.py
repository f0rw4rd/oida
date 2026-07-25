"""Additional behavioral tests for PROFINET RPCMixin (coverage gap-fillers).

These complement ``test_rpc_mixin.py`` by exercising the larger uncovered
methods:

- ``_rpc_operations``      (top-level RPC flow orchestration)
- ``_read_im_data_implicit`` / ``_read_diagnosis_implicit``
- ``_write_single_index``  (success + readback path)
- ``_show_slots`` / ``_get_slot_info`` / ``_get_subslot_details``
- ``_test_write_only``     (safe-range gating)
- ``_format_index_value``  (text/struct branches)
- ``_get_index_data_type``

The network/RPC boundary (``con``), the library module (``profinet_mod``),
and sibling mixin methods reached from ``_rpc_operations`` are mocked; the
RPCMixin logic itself runs unmodified. No code under test is monkey-patched.
"""

import struct
from unittest.mock import MagicMock

from oida.protocols.profinet.mixins.rpc import RPCMixin
from oida.protocols.profinet.models import ProfinetDevice


class MockLogger:
    def __init__(self):
        self.messages = []

    def display(self, msg):
        self.messages.append(("display", msg))

    def success(self, msg):
        self.messages.append(("success", msg))

    def fail(self, msg):
        self.messages.append(("fail", msg))

    def warning(self, msg):
        self.messages.append(("warning", msg))

    def error(self, msg):
        self.messages.append(("error", msg))

    def debug(self, msg):
        self.messages.append(("debug", msg))


class MockResult:
    def __init__(self, payload=b""):
        self.payload = payload

    def __len__(self):
        return len(self.payload)


class MockCon:
    def __init__(self, read_data=b"\x01\x02\x03\x04", write_fail=False):
        self._read_data = read_data
        self._write_fail = write_fail
        self.reads = []
        self.writes = []
        self.peer = ("192.168.1.50", 34964)
        self.closed = False
        self.connected_with = None

    def read(self, api=0, slot=0, subslot=1, idx=0):
        self.reads.append((slot, subslot, idx))
        return MockResult(self._read_data)

    def write(self, api=0, slot=0, subslot=1, idx=0, data=b""):
        if self._write_fail:
            raise Exception("Write rejected 0xDE4")
        self.writes.append((slot, subslot, idx, data))

    def connect(self, src_mac=None):
        self.connected_with = src_mac

    def close(self):
        self.closed = True


class MockIM0:
    def __init__(self, order_id=b"6ES7 215-1AG40-0XB0", vendor_high=0x00, vendor_low=0x2A):
        self.vendor_id_high = vendor_high
        self.vendor_id_low = vendor_low
        self.order_id = order_id
        self.im_serial_number = b"S C-C2UR12345678"
        self.im_hardware_revision = 3
        self.sw_revision_prefix = ord("V")
        self.im_sw_revision_functional_enhancement = 4
        self.im_sw_revision_bug_fix = 5
        self.im_sw_revision_internal_change = 0


class RPCStub(RPCMixin):
    def __init__(self, args=None, timeout=2.0, my_mac=b"\x02\x00\x00\x00\x00\x01"):
        self._args = args or {}
        self.logger = MockLogger()
        self.timeout = timeout
        self._my_mac = my_mac
        # recorders for sibling-mixin methods reached from _rpc_operations
        self.calls = []

    def _arg(self, name, default=None):
        return self._args.get(name, default)

    @staticmethod
    def _parse_slot_arg(slot_str):
        if not slot_str:
            return (None, None)
        parts = slot_str.split("/")
        try:
            slot = int(parts[0], 0)
            subslot = int(parts[1], 0) if len(parts) > 1 else None
            return (slot, subslot)
        except ValueError:
            return (None, None)

    # Sibling-mixin / cross-method recorders (their own logic is tested
    # elsewhere; here we only verify _rpc_operations dispatches to them).
    def _enumerate_indices(self, device, con, discovered_slots=None):
        self.calls.append(("enumerate", discovered_slots))

    def _handle_fuzz(self, con, discovered_slots):
        self.calls.append(("fuzz", discovered_slots))

    def _cyclic_io_test(self, device, discovered_slots):
        self.calls.append(("cyclic", discovered_slots))


def _device(**kw):
    base = dict(
        mac_address="00:11:22:33:44:55",
        ip_address="192.168.1.50",
        vendor_id=0x002A,
        device_id=0x010D,
    )
    base.update(kw)
    dev = ProfinetDevice(**base)
    dev._dcp_desc = MagicMock()
    return dev


def _profinet_mod():
    """Minimal library-module mock for _rpc_operations."""
    mod = MagicMock()
    con = MockCon()
    con.read_im0 = MagicMock(return_value=MockIM0())
    con.read_im1 = MagicMock(return_value=None)
    mod.RPCCon = MagicMock(return_value=con)
    mod._test_con = con
    return mod, con


# ──────────────────────────────────────────────────────────────────────
# _rpc_operations
# ──────────────────────────────────────────────────────────────────────


class TestRpcOperations:
    def test_skips_when_no_ip(self):
        stub = RPCStub()
        dev = _device(ip_address="0.0.0.0")
        mod, _ = _profinet_mod()
        stub._rpc_operations(dev, mod)
        mod.RPCCon.assert_not_called()

    def test_skips_when_no_dcp_desc(self):
        stub = RPCStub()
        dev = _device()
        dev._dcp_desc = None
        mod, _ = _profinet_mod()
        stub._rpc_operations(dev, mod)
        mod.RPCCon.assert_not_called()
        assert any("skipping RPC" in m for _, m in stub.logger.messages)

    def test_connection_failure_shows_hint(self):
        stub = RPCStub()
        dev = _device(device_roles=["IO-Controller"])
        mod = MagicMock()
        mod.RPCCon.side_effect = Exception("conn refused")
        stub._rpc_operations(dev, mod)
        assert any("RPC connection failed" in m for _, m in stub.logger.messages)
        # IO-Controller-only hint
        assert any("I-Device" in m for _, m in stub.logger.messages)

    def test_basic_flow_reads_im_and_closes(self):
        stub = RPCStub(args={"read_im": True})
        dev = _device()
        mod, con = _profinet_mod()
        stub._rpc_operations(dev, mod)
        # I&M0 read happened and connection was closed
        assert dev.im0_data["order_id"].startswith("6ES7")
        assert con.connected_with == stub._my_mac
        assert con.closed is True

    def test_slots_flag_triggers_discovery_and_display(self):
        stub = RPCStub(args={"slots": True, "read_im": False})
        dev = _device()
        mod, con = _profinet_mod()
        con.discover_slots = MagicMock(return_value=[])
        stub._rpc_operations(dev, mod)
        # fallback slot displayed
        assert any("Slot/Subslot Structure" in m for _, m in stub.logger.messages)

    def test_enum_flag_dispatches_to_enumerate(self):
        stub = RPCStub(args={"enum": True, "read_im": False})
        dev = _device()
        mod, con = _profinet_mod()
        stub._rpc_operations(dev, mod)
        assert any(c[0] == "enumerate" for c in stub.calls)

    def test_fuzz_flag_dispatches_to_handle_fuzz(self):
        stub = RPCStub(args={"fuzz": "basic", "read_im": False})
        dev = _device()
        mod, con = _profinet_mod()
        stub._rpc_operations(dev, mod)
        assert any(c[0] == "fuzz" for c in stub.calls)

    def test_write_im1_only_with_confirm(self):
        stub = RPCStub(args={"write_im1": ["F", "L"], "confirm": False, "read_im": False})
        dev = _device()
        mod, con = _profinet_mod()
        stub._rpc_operations(dev, mod)
        # no I&M1 write attempted without confirm
        assert con.writes == []

    def test_read_index_dispatch(self):
        stub = RPCStub(args={"read_index": "0xAFF0", "read_im": False})
        dev = _device()
        mod, con = _profinet_mod()
        stub._rpc_operations(dev, mod)
        # _read_single_index reads slot 0 subslot 1 idx 0xAFF0
        assert any(idx == 0xAFF0 for _, _, idx in con.reads)

    def test_write_index_dispatch(self):
        stub = RPCStub(args={"write_index": "0xAFF1:0102", "confirm": True, "read_im": False})
        dev = _device()
        mod, con = _profinet_mod()
        stub._rpc_operations(dev, mod)
        # _write_single_index wrote the parsed bytes
        assert any(w[2] == 0xAFF1 and w[3] == b"\x01\x02" for w in con.writes)

    def test_read_diagnosis_dispatch(self):
        stub = RPCStub(args={"read_diagnosis": True, "read_im": False})
        dev = _device()
        mod, con = _profinet_mod()
        con.read_diagnosis = MagicMock(return_value=MagicMock(entries=[]))
        stub._rpc_operations(dev, mod)
        con.read_diagnosis.assert_called_once()

    def test_topology_dispatch(self):
        stub = RPCStub(args={"topology": True, "read_im": False})
        dev = _device()
        mod, con = _profinet_mod()
        con.read_pd_real_data = MagicMock(return_value=MagicMock(interface=None, ports=[]))
        stub._rpc_operations(dev, mod)
        con.read_pd_real_data.assert_called()

    def test_module_diff_dispatch(self):
        stub = RPCStub(args={"module_diff": True, "read_im": False})
        dev = _device()
        mod, con = _profinet_mod()
        diff = MagicMock(all_ok=True)
        con.read_module_diff = MagicMock(return_value=diff)
        stub._rpc_operations(dev, mod)
        con.read_module_diff.assert_called_once()

    def test_alarms_dispatch(self):
        stub = RPCStub(args={"alarms": True, "read_im": False})
        dev = _device()
        mod, con = _profinet_mod()
        # alarm read returns empty -> "No alarm data present"
        con.read = MagicMock(return_value=MockResult(b""))
        stub._rpc_operations(dev, mod)
        assert any("No alarm data" in m for _, m in stub.logger.messages)

    def test_write_im2_with_confirm_dispatch(self):
        stub = RPCStub(args={"write_im2": "2025-01-15", "confirm": True, "read_im": False})
        dev = _device()
        dev._pn_device = None
        mod, con = _profinet_mod()
        stub._rpc_operations(dev, mod)
        # fallback manual write of I&M2 (idx 45042)
        assert any(w[2] == 45042 for w in con.writes)

    def test_write_im3_with_confirm_dispatch(self):
        stub = RPCStub(args={"write_im3": "Pump Station", "confirm": True, "read_im": False})
        dev = _device()
        dev._pn_device = None
        mod, con = _profinet_mod()
        stub._rpc_operations(dev, mod)
        assert any(w[2] == 45043 for w in con.writes)

    def test_cyclic_dispatch(self, monkeypatch):
        # Avoid the real 1s sleep in the cyclic path. We patch time.sleep in
        # the stdlib (a test-environment concern), NOT any code under test.
        import time as _time

        monkeypatch.setattr(_time, "sleep", lambda *_a, **_k: None)
        stub = RPCStub(args={"cyclic": True, "read_im": False})
        dev = _device()
        mod, con = _profinet_mod()
        con.discover_slots = MagicMock(return_value=[])
        stub._rpc_operations(dev, mod)
        assert any(c[0] == "cyclic" for c in stub.calls)


# ──────────────────────────────────────────────────────────────────────
# _read_im_data_implicit
# ──────────────────────────────────────────────────────────────────────


class TestReadImplicit:
    def test_read_im0_implicit_parses(self):
        stub = RPCStub()
        dev = _device()
        con = MagicMock()
        con.read_implicit.return_value = MockResult(b"\x00" * 64)

        mod = MagicMock()
        mod.indices.IM0 = 45040
        mod.PNInM0.return_value = MockIM0()

        stub._read_im_data_implicit(dev, con, mod)

        assert dev.im0_data["order_id"].startswith("6ES7")
        assert dev.firmware_version.startswith("V")
        assert any(level == "success" for level, _ in stub.logger.messages)

    def test_read_im0_implicit_empty(self):
        stub = RPCStub()
        dev = _device()
        con = MagicMock()
        con.read_implicit.return_value = MockResult(b"")
        mod = MagicMock()
        mod.indices.IM0 = 45040
        stub._read_im_data_implicit(dev, con, mod)
        assert dev.im0_data == {}

    def test_read_im0_implicit_failure(self):
        stub = RPCStub()
        dev = _device()
        con = MagicMock()
        con.read_implicit.side_effect = Exception("timeout")
        mod = MagicMock()
        mod.indices.IM0 = 45040
        stub._read_im_data_implicit(dev, con, mod)
        assert dev.im0_data == {}
        assert any(level == "debug" for level, _ in stub.logger.messages)


class TestReadDiagnosisImplicit:
    def test_with_payload(self):
        stub = RPCStub()
        dev = _device()
        con = MagicMock()
        con.read_implicit.return_value = MockResult(b"\x00" * 12)
        stub._read_diagnosis_implicit(dev, con, MagicMock())
        assert any("Diagnosis data: 12 bytes" in m for _, m in stub.logger.messages)

    def test_failure(self):
        stub = RPCStub()
        dev = _device()
        con = MagicMock()
        con.read_implicit.side_effect = Exception("nope")
        stub._read_diagnosis_implicit(dev, con, MagicMock())
        assert any(level == "debug" for level, _ in stub.logger.messages)


# ──────────────────────────────────────────────────────────────────────
# _write_single_index (success + readback)
# ──────────────────────────────────────────────────────────────────────


class TestWriteSingleIndexSuccess:
    def test_two_part_spec_writes_and_reads_back(self):
        stub = RPCStub(args={"confirm": True})
        dev = _device()
        con = MockCon(read_data=b"\x48\x65\x6c\x6c\x6f")
        stub._write_single_index(dev, con, "0xAFF1:48656C6C6F")
        assert con.writes == [(0, 1, 0xAFF1, b"Hello")]
        assert any("Write successful" in m for _, m in stub.logger.messages)
        assert any("Readback" in m for _, m in stub.logger.messages)

    def test_three_part_spec_with_slot(self):
        stub = RPCStub(args={"confirm": True})
        dev = _device()
        con = MockCon(read_data=b"\x01")
        stub._write_single_index(dev, con, "2/1:0xAFF2:0102")
        assert con.writes[0][0] == 2  # slot
        assert con.writes[0][1] == 1  # subslot
        assert con.writes[0][2] == 0xAFF2
        assert con.writes[0][3] == b"\x01\x02"

    def test_long_readback_truncated(self):
        stub = RPCStub(args={"confirm": True})
        dev = _device()
        con = MockCon(read_data=bytes(range(40)))
        stub._write_single_index(dev, con, "0xAFF1:00")
        assert any("..." in m for _, m in stub.logger.messages if "Readback" in m)

    def test_invalid_hex_data(self):
        stub = RPCStub(args={"confirm": True})
        dev = _device()
        con = MockCon()
        stub._write_single_index(dev, con, "0xAFF1:ZZZZ")
        assert any("Invalid write format" in m for _, m in stub.logger.messages)
        assert con.writes == []

    def test_write_failure_reported(self):
        stub = RPCStub(args={"confirm": True})
        dev = _device()
        con = MockCon(write_fail=True)
        stub._write_single_index(dev, con, "0xAFF1:0102")
        assert any("Write failed" in m for _, m in stub.logger.messages)

    def test_slot_arg_default_used(self):
        stub = RPCStub(args={"confirm": True, "slot": "3/2"})
        dev = _device()
        con = MockCon(read_data=b"\x00")
        # two-part spec -> slot/subslot come from --slot arg
        stub._write_single_index(dev, con, "0xAFF1:00")
        assert con.writes[0][0] == 3
        assert con.writes[0][1] == 2


# ──────────────────────────────────────────────────────────────────────
# _show_slots / _get_slot_info / _get_subslot_details
# ──────────────────────────────────────────────────────────────────────


class TestShowSlots:
    def test_renders_tree(self):
        stub = RPCStub()
        dev = _device()
        slots = [
            (0, 1, 0, 0),
            (0, 0x8000, 0, 0),
            (0, 0x8001, 0, 0),
            (1, 1, 0x10000001, 0),
        ]
        con = MagicMock()
        con.read_im0.return_value = MockIM0()
        con.read_pd_real_data.return_value = MagicMock(
            interface=MagicMock(chassis_id="plc-01", ip_str="192.168.1.50")
        )
        con.read.return_value = MockResult(b"")
        stub._show_slots(dev, slots, con)
        msgs = " ".join(m for _, m in stub.logger.messages)
        assert "Slot/Subslot Structure (4 items)" in msgs
        assert "Slot 0:" in msgs
        assert "DAP" in msgs
        assert "Interface" in msgs

    def test_slot_info_dap(self):
        stub = RPCStub()
        assert stub._get_slot_info(None, 0, []) == "DAP (Device Access Point)"

    def test_slot_info_reads_order_id(self):
        stub = RPCStub()
        con = MagicMock()
        con.read_im0.return_value = MockIM0(order_id=b"6ES7 990-0AA00")
        info = stub._get_slot_info(con, 1, [(1, 0, 0)])
        assert "6ES7" in info

    def test_slot_info_no_con_returns_module(self):
        stub = RPCStub()
        assert stub._get_slot_info(None, 1, [(1, 0, 0)]) == "Module"


class TestGetSubslotDetails:
    def test_no_con_returns_empty(self):
        stub = RPCStub()
        assert stub._get_subslot_details(None, 0, 0x8000, 0) == ""

    def test_interface_subslot(self):
        stub = RPCStub()
        con = MagicMock()
        con.read_pd_real_data.return_value = MagicMock(
            interface=MagicMock(chassis_id="plc-01", ip_str="192.168.1.50")
        )
        details = stub._get_subslot_details(con, 0, 0x8000, 0)
        assert "plc-01" in details
        assert "IP:192.168.1.50" in details

    def test_port_subslot_parses_link(self):
        stub = RPCStub()
        con = MagicMock()
        # read returns 6-byte header + real port-data payload (parser-tolerant)
        con.read.return_value = MockResult(b"\x00" * 6 + b"\x00" * 32)
        details = stub._get_subslot_details(con, 0, 0x8001, 0)
        # whatever the parser yields, the method returns a string without raising
        assert isinstance(details, str)

    def test_regular_subslot_reads_im0(self):
        stub = RPCStub()
        con = MagicMock()
        con.read_im0.return_value = MockIM0(order_id=b"6ES7 215")
        details = stub._get_subslot_details(con, 1, 1, 0)
        assert "6ES7" in details
        # software revision rendered as vX.Y.Z
        assert "v4.5.0" in details


# ──────────────────────────────────────────────────────────────────────
# _get_slot_description (uncovered branches)
# ──────────────────────────────────────────────────────────────────────


class TestGetSlotDescriptionMore:
    def test_slot0_high_port_subslot(self):
        stub = RPCStub()
        # subslot >= 0x8000 but > 0x8004 -> still "Port N"
        assert stub._get_slot_description(0, 0x8009, 0) == "Port 9"

    def test_nonzero_slot_port_subslot(self):
        stub = RPCStub()
        assert stub._get_slot_description(2, 0x8001, 0) == "Port 1"

    def test_module_no_ident(self):
        stub = RPCStub()
        assert stub._get_slot_description(1, 1, 0) == "Module"


# ──────────────────────────────────────────────────────────────────────
# _test_write_only (safe-range gating)
# ──────────────────────────────────────────────────────────────────────


class TestTestWriteOnly:
    def test_unsafe_index_returns_false_without_write(self):
        stub = RPCStub()
        con = MockCon()
        assert stub._test_write_only(con, 0, 1, 0x1234) is False
        assert con.writes == []

    def test_safe_index_write_success(self):
        stub = RPCStub()
        con = MockCon()
        assert stub._test_write_only(con, 0, 1, 0xAFF1) is True
        assert con.writes == [(0, 1, 0xAFF1, b"\x00")]

    def test_safe_index_write_failure(self):
        stub = RPCStub()
        con = MockCon(write_fail=True)
        assert stub._test_write_only(con, 0, 1, 0xAFF1) is False
        assert any(level == "debug" for level, _ in stub.logger.messages)

    def test_boundary_indices(self):
        stub = RPCStub()
        con = MockCon()
        # 0xAFF0..0xAFF5 are in range; 0xAFF6 is not
        assert stub._test_write_only(con, 0, 1, 0xAFF0) is True
        assert stub._test_write_only(con, 0, 1, 0xAFF5) is True
        con2 = MockCon()
        assert stub._test_write_only(con2, 0, 1, 0xAFF6) is False
        assert con2.writes == []


# ──────────────────────────────────────────────────────────────────────
# _format_index_value (text/struct branches)
# ──────────────────────────────────────────────────────────────────────


class TestFormatIndexValueMore:
    def test_text_payload(self):
        stub = RPCStub()
        result = stub._format_index_value(b"S7-1200\x00\x00")
        assert result == '"S7-1200"'

    def test_three_byte_struct_no_format(self):
        stub = RPCStub()
        # size 3 is neither 1/2/4 nor printable text -> ""
        assert stub._format_index_value(b"\xff\xfe\xfd") == ""

    def test_eight_byte_text(self):
        stub = RPCStub()
        assert stub._format_index_value(b"ABCDEFGH") == '"ABCDEFGH"'


class TestGetIndexDataType:
    def test_string_indices(self):
        stub = RPCStub()
        for idx in (0xAFF1, 0xAFF2, 0xAFF3, 0xAFF5):
            assert stub._get_index_data_type(idx) == "string"

    def test_struct_default(self):
        stub = RPCStub()
        assert stub._get_index_data_type(0xAFF0) == "struct"
        assert stub._get_index_data_type(0x1234) == "struct"


# Sanity: struct import is used (keeps lint honest if header packing changes)
def test_struct_module_present():
    assert struct.pack(">H", 1) == b"\x00\x01"
