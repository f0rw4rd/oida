"""Tests for PROFINET RPCMixin - new 0.6.0 features.

Tests cover:
- _read_topology (PDRealData)
- _read_module_diff (ModuleDiffBlock)
- _read_alarms
- _write_im1, _write_im2, _write_im3
- _read_im_data (I&M0, I&M1)
- _read_diagnosis
- _discover_slots
- _read_single_index, _write_single_index
- _format_index_value
- _get_slot_description
- _show_rpc_hint
- _test_write_access
"""

from unittest.mock import MagicMock, patch


from oida.protocols.profinet.models import ProfinetDevice


class MockLogger:
    """Minimal logger mock matching test_fuzz_mixin pattern."""

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
    """Mock RPC read result."""

    def __init__(self, payload=b""):
        self.payload = payload

    def __len__(self):
        return len(self.payload)


class MockCon:
    """Mock RPC connection."""

    def __init__(self, read_data=b"test1234", write_fail=False):
        self._read_data = read_data
        self._write_fail = write_fail
        self._src_mac = b"\x02\x00\x00\x00\x00\x01"
        self.writes = []

    def read(self, api=0, slot=0, subslot=1, idx=0):
        return MockResult(self._read_data)

    def write(self, api=0, slot=0, subslot=1, idx=0, data=b""):
        if self._write_fail:
            raise Exception("Write rejected")
        self.writes.append((slot, subslot, idx, data))

    def connect(self, src_mac=None):
        pass

    def close(self):
        pass


class MockIM0:
    """Mock I&M0 data returned by con.read_im0()."""

    def __init__(self):
        self.vendor_id_high = 0x00
        self.vendor_id_low = 0x2A
        self.order_id = b"6ES7 215-1AG40-0XB0    "
        self.im_serial_number = b"S C-C2UR12345678"
        self.im_hardware_revision = 3
        self.sw_revision_prefix = ord("V")
        self.im_sw_revision_functional_enhancement = 4
        self.im_sw_revision_bug_fix = 5
        self.im_sw_revision_internal_change = 0


class MockIM1:
    """Mock I&M1 data returned by con.read_im1()."""

    def __init__(self, tag_func=b"Motor A", tag_loc=b"Hall 3"):
        self.im_tag_function = tag_func.ljust(32, b" ")
        self.im_tag_location = tag_loc.ljust(22, b" ")


class MockSlotInfo:
    """Mock SlotInfo from con.discover_slots()."""

    def __init__(self, slot, subslot, module_ident=0, submodule_ident=0):
        self.slot = slot
        self.subslot = subslot
        self.module_ident = module_ident
        self.submodule_ident = submodule_ident


class MockPDRealData:
    """Mock PDRealData from con.read_pd_real_data()."""

    def __init__(self):
        self.interface = MagicMock()
        self.interface.chassis_id = "plc-test-01"
        self.interface.ip_str = "192.168.1.100"
        self.interface.netmask_str = "255.255.255.0"
        self.interface.gateway_str = "192.168.1.1"

        port1 = MagicMock()
        port1.subslot = 0x8001
        port1.link_state_link = 1  # Up
        port1.mau_type_name = "100BaseTXFD"
        port1.peers = []
        port1.mau_type = 16

        port2 = MagicMock()
        port2.subslot = 0x8002
        port2.link_state_link = 2  # Down
        port2.mau_type_name = "Unknown"
        port2.peers = [MagicMock(chassis_id="switch-01", port_id="port1")]
        port2.mau_type = 0

        self.ports = [port1, port2]


class MockModuleDiff:
    """Mock ModuleDiffBlock from con.read_module_diff()."""

    def __init__(self, all_ok=True, mismatches=None):
        self.all_ok = all_ok
        self._mismatches = mismatches or []

    def get_mismatches(self):
        return self._mismatches


class MockDiagnosisEntry:
    """Mock diagnosis entry."""

    def __init__(self, channel=0, error_type=0):
        self.channel_number = channel
        # profinet DiagnosisEntry field is error_type (not channel_error_type)
        self.error_type = error_type


class MockDiagnosis:
    """Mock diagnosis result."""

    def __init__(self, entries=None):
        self.entries = entries or []


# Build a stub class for RPCMixin testing
from oida.protocols.profinet.mixins.rpc import RPCMixin


class RPCMixinStub:
    """Stub class that mixes in RPCMixin for testing."""

    def __init__(self, args=None):
        self._args = args or {}
        self.logger = MockLogger()

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


# Patch RPCMixin methods onto stub
for attr in dir(RPCMixin):
    if not attr.startswith("__"):
        method = getattr(RPCMixin, attr)
        if callable(method):
            setattr(RPCMixinStub, attr, method)


# ──────────────────────────────────────────────────────────────────────
# Test classes
# ──────────────────────────────────────────────────────────────────────


class TestReadIMData:
    """Test _read_im_data method."""

    def _make_stub(self, **kwargs):
        stub = RPCMixinStub(kwargs)
        return stub

    def test_read_im0_success(self):
        stub = self._make_stub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        con.read_im0.return_value = MockIM0()
        con.read_im1.return_value = None

        stub._read_im_data(device, con, MagicMock())

        assert device.im0_data["vendor_id"] == 0x002A
        assert "6ES7" in device.im0_data["order_id"]
        assert device.firmware_version.startswith("V")
        assert "4.5.0" in device.firmware_version

    def test_read_im0_failure(self):
        stub = self._make_stub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        con.read_im0.side_effect = Exception("RPC timeout")
        con.read_im1.return_value = None

        stub._read_im_data(device, con, MagicMock())

        assert device.im0_data == {}  # No data written
        assert any("debug" == level for level, _ in stub.logger.messages)

    def test_read_im1_success(self):
        stub = self._make_stub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        con.read_im0.return_value = MockIM0()
        con.read_im1.return_value = MockIM1()

        stub._read_im_data(device, con, MagicMock())

        assert device.im1_data["tag_function"] == "Motor A"
        assert device.im1_data["tag_location"] == "Hall 3"

    def test_read_im1_empty_tags(self):
        stub = self._make_stub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        con.read_im0.return_value = MockIM0()
        con.read_im1.return_value = MockIM1(tag_func=b"", tag_loc=b"")

        stub._read_im_data(device, con, MagicMock())

        # Empty tags should still be stored but not displayed
        assert device.im1_data["tag_function"] == ""
        assert device.im1_data["tag_location"] == ""


class TestReadTopology:
    """Test _read_topology method."""

    def test_read_topology_success(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        pd_real = MockPDRealData()
        con.read_pd_real_data.return_value = pd_real

        stub._read_topology(device, con)

        assert device.topology is pd_real
        assert any("plc-test-01" in msg for _, msg in stub.logger.messages)
        assert any("192.168.1.100" in msg for _, msg in stub.logger.messages)

    def test_read_topology_port_up(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        con.read_pd_real_data.return_value = MockPDRealData()

        stub._read_topology(device, con)

        assert any("Port 1: Up" in msg for _, msg in stub.logger.messages)

    def test_read_topology_port_down(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        con.read_pd_real_data.return_value = MockPDRealData()

        stub._read_topology(device, con)

        assert any("Port 2: Down" in msg for _, msg in stub.logger.messages)

    def test_read_topology_peer_info(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        con.read_pd_real_data.return_value = MockPDRealData()

        stub._read_topology(device, con)

        assert any("switch-01" in msg for _, msg in stub.logger.messages)

    def test_read_topology_no_peers(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        pd_real = MockPDRealData()
        # Port 1 has no peers
        con.read_pd_real_data.return_value = pd_real

        stub._read_topology(device, con)

        assert any("No peer detected" in msg for _, msg in stub.logger.messages)

    def test_read_topology_failure(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        con.read_pd_real_data.side_effect = Exception("timeout")

        stub._read_topology(device, con)

        assert device.topology is None
        assert any("debug" == level for level, _ in stub.logger.messages)


class TestReadModuleDiff:
    """Test _read_module_diff method."""

    def test_read_module_diff_all_ok(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        con.read_module_diff.return_value = MockModuleDiff(all_ok=True)

        stub._read_module_diff(device, con)

        assert device.module_diff is not None
        assert any("matches" in msg for _, msg in stub.logger.messages)

    def test_read_module_diff_with_mismatches(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        mismatches = [(1, 1, "Wrong module"), (2, 1, "Missing submodule")]
        con.read_module_diff.return_value = MockModuleDiff(all_ok=False, mismatches=mismatches)

        stub._read_module_diff(device, con)

        assert device.module_diff is not None
        assert any("2 configuration mismatch" in msg for _, msg in stub.logger.messages)
        assert any("Wrong module" in msg for _, msg in stub.logger.messages)

    def test_read_module_diff_failure(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        con.read_module_diff.side_effect = Exception("not supported")

        stub._read_module_diff(device, con)

        assert device.module_diff is None

    def test_read_module_diff_no_get_mismatches(self):
        """Test fallback when diff object has entries but no get_mismatches."""
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()

        diff = MagicMock(spec=["entries"])
        diff.entries = [MagicMock(), MagicMock()]
        del diff.all_ok  # Remove all_ok attr
        con.read_module_diff.return_value = diff

        stub._read_module_diff(device, con)

        assert any("2 entries" in msg for _, msg in stub.logger.messages)


class TestReadAlarms:
    """Test _read_alarms method."""

    def test_read_alarms_empty(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        con.read.return_value = MockResult(b"")

        stub._read_alarms(device, con)

        assert device.alarms == []
        assert any("No alarm data" in msg for _, msg in stub.logger.messages)

    def test_read_alarms_too_short(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        con.read.return_value = MockResult(b"\x00" * 10)

        stub._read_alarms(device, con)

        assert device.alarms == []

    def test_read_alarms_with_parse(self):
        """Test alarm parsing with mock parse_alarm_notification."""
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        # Need at least 28 bytes to trigger parsing
        con.read.return_value = MockResult(b"\x00" * 40)

        alarm_obj = MagicMock()
        alarm_obj.alarm_type = 1
        alarm_obj.alarm_type_name = "Process"
        # profinet AlarmNotification fields are slot_number / subslot_number
        alarm_obj.slot_number = 1
        alarm_obj.subslot_number = 1

        # Create a mock alarms module with parse_alarm_notification
        mock_alarms = MagicMock()
        mock_alarms.parse_alarm_notification = MagicMock(return_value=alarm_obj)

        with patch(
            "oida.protocols.profinet.helpers.get_alarms_module",
            return_value=mock_alarms,
        ):
            stub._read_alarms(device, con)

        assert len(device.alarms) == 1
        assert device.alarms[0]["type"] == "Process"
        assert device.alarms[0]["slot"] == 1

    def test_read_alarms_parse_import_error(self):
        """Test graceful fallback when profinet.alarms not importable."""
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        con.read.return_value = MockResult(b"\x00" * 40)

        with patch(
            "oida.protocols.profinet.helpers.get_alarms_module",
            return_value=None,
        ):
            stub._read_alarms(device, con)

        # Should show raw byte count instead
        assert any("raw" in msg or "bytes" in msg for _, msg in stub.logger.messages)

    def test_read_alarms_failure(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        con.read.side_effect = Exception("timeout")

        stub._read_alarms(device, con)

        assert device.alarms == []


class TestWriteIM1:
    """Test _write_im1 method."""

    def test_write_im1_wrong_value_count(self):
        stub = RPCMixinStub(args={"confirm": True})
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MockCon()

        stub._write_im1(device, con, ["only_one"], None)

        assert any("requires exactly 2" in msg for _, msg in stub.logger.messages)

    def test_write_im1_with_library_api(self):
        stub = RPCMixinStub(args={"confirm": True})
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MockCon()

        pn_dev = MagicMock()
        pn_dev.write_im1 = MagicMock()

        stub._write_im1(device, con, ["Motor A", "Hall 3"], pn_dev)

        pn_dev.write_im1.assert_called_once_with(tag_function="Motor A", tag_location="Hall 3")
        assert pn_dev._rpc is con
        assert pn_dev._connected is True
        assert any("success" == level for level, _ in stub.logger.messages)

    def test_write_im1_fallback_manual(self):
        """Test manual I&M1 write when library device not available."""
        stub = RPCMixinStub(args={"confirm": True})
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MockCon()

        with patch("profinet.indices") as mock_idx:
            mock_idx.IM1 = 0xAFF1
            stub._write_im1(device, con, ["Motor A", "Hall 3"], None)

        assert len(con.writes) == 1
        assert con.writes[0][2] == 0xAFF1  # index
        assert any("success" == level for level, _ in stub.logger.messages)

    def test_write_im1_failure(self):
        stub = RPCMixinStub(args={"confirm": True})
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")

        pn_dev = MagicMock()
        pn_dev.write_im1.side_effect = Exception("PNIO error")

        con = MockCon()
        stub._write_im1(device, con, ["Motor A", "Hall 3"], pn_dev)

        assert any("Failed to write I&M1" in msg for _, msg in stub.logger.messages)


class TestWriteIM2:
    """Test _write_im2 method."""

    def test_write_im2_with_library_api(self):
        stub = RPCMixinStub(args={"confirm": True})
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MockCon()

        pn_dev = MagicMock()
        pn_dev.write_im2 = MagicMock()

        stub._write_im2(device, con, "2025-01-15", pn_dev)

        pn_dev.write_im2.assert_called_once_with(date="2025-01-15")
        assert any("success" == level for level, _ in stub.logger.messages)

    def test_write_im2_fallback_manual(self):
        stub = RPCMixinStub(args={"confirm": True})
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MockCon()

        with patch("profinet.indices") as mock_idx:
            mock_idx.IM2 = 0xAFF2
            stub._write_im2(device, con, "2025-01-15", None)

        assert len(con.writes) == 1
        assert con.writes[0][2] == 0xAFF2

    def test_write_im2_failure(self):
        stub = RPCMixinStub(args={"confirm": True})
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MockCon()

        pn_dev = MagicMock()
        pn_dev.write_im2.side_effect = Exception("PNIO error")

        stub._write_im2(device, con, "2025-01-15", pn_dev)

        assert any("Failed to write I&M2" in msg for _, msg in stub.logger.messages)


class TestWriteIM3:
    """Test _write_im3 method."""

    def test_write_im3_with_library_api(self):
        stub = RPCMixinStub(args={"confirm": True})
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MockCon()

        pn_dev = MagicMock()
        pn_dev.write_im3 = MagicMock()

        stub._write_im3(device, con, "Pump Station North", pn_dev)

        pn_dev.write_im3.assert_called_once_with(descriptor="Pump Station North")
        assert any("success" == level for level, _ in stub.logger.messages)

    def test_write_im3_fallback_manual(self):
        stub = RPCMixinStub(args={"confirm": True})
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MockCon()

        with patch("profinet.indices") as mock_idx:
            mock_idx.IM3 = 0xAFF3
            stub._write_im3(device, con, "Pump Station", None)

        assert len(con.writes) == 1
        assert con.writes[0][2] == 0xAFF3

    def test_write_im3_failure(self):
        stub = RPCMixinStub(args={"confirm": True})
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MockCon()

        pn_dev = MagicMock()
        pn_dev.write_im3.side_effect = Exception("access denied")

        stub._write_im3(device, con, "Test", pn_dev)

        assert any("Failed to write I&M3" in msg for _, msg in stub.logger.messages)


class TestReadDiagnosis:
    """Test _read_diagnosis method."""

    def test_read_diagnosis_with_entries(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        diag = MockDiagnosis(entries=[MockDiagnosisEntry(1, 0x8000), MockDiagnosisEntry(2, 0x8001)])
        con.read_diagnosis.return_value = diag

        stub._read_diagnosis(device, con, MagicMock())

        assert len(device.diagnosis) == 2
        assert device.diagnosis[0]["channel"] == 1
        assert device.diagnosis[1]["error_type"] == 0x8001

    def test_read_diagnosis_empty(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        diag = MockDiagnosis(entries=[])
        con.read_diagnosis.return_value = diag

        stub._read_diagnosis(device, con, MagicMock())

        assert device.diagnosis == []

    def test_read_diagnosis_failure(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        con.read_diagnosis.side_effect = Exception("not supported")

        stub._read_diagnosis(device, con, MagicMock())

        assert device.diagnosis == []


class TestDiscoverSlots:
    """Test _discover_slots method."""

    def test_discover_slots_success(self):
        stub = RPCMixinStub()
        con = MagicMock()
        con.discover_slots.return_value = [
            MockSlotInfo(0, 1, 0x0001, 0x0001),
            MockSlotInfo(0, 0x8000, 0x0001, 0x0002),
            MockSlotInfo(0, 0x8001, 0x0001, 0x0003),
            MockSlotInfo(1, 1, 0x0010, 0x0001),
        ]

        slots = stub._discover_slots(con)

        assert len(slots) == 4
        assert slots[0] == (0, 1, 0x0001, 0x0001)
        assert slots[3] == (1, 1, 0x0010, 0x0001)

    def test_discover_slots_failure_fallback(self):
        stub = RPCMixinStub()
        con = MagicMock()
        con.discover_slots.side_effect = Exception("not supported")

        slots = stub._discover_slots(con)

        assert slots == [(0, 1, 0, 0)]

    def test_discover_slots_empty_fallback(self):
        stub = RPCMixinStub()
        con = MagicMock()
        con.discover_slots.return_value = []

        slots = stub._discover_slots(con)

        assert slots == [(0, 1, 0, 0)]


class TestFormatIndexValue:
    """Test _format_index_value method."""

    def test_empty(self):
        stub = RPCMixinStub()
        assert stub._format_index_value(b"") == ""

    def test_single_byte(self):
        stub = RPCMixinStub()
        result = stub._format_index_value(b"\x42")
        assert "66" in result
        assert "0x42" in result

    def test_two_bytes(self):
        stub = RPCMixinStub()
        result = stub._format_index_value(b"\x00\x2a")
        assert "42" in result
        assert "0x002A" in result

    def test_four_bytes(self):
        stub = RPCMixinStub()
        result = stub._format_index_value(b"\x00\x00\x00\x01")
        assert "1" in result
        assert "0x00000001" in result

    def test_ascii_string(self):
        stub = RPCMixinStub()
        result = stub._format_index_value(b"Hello World")
        assert '"Hello World"' in result

    def test_binary_data_no_decode(self):
        stub = RPCMixinStub()
        result = stub._format_index_value(b"\xff\xfe\xfd\xfc\xfb")
        # Binary data that's not printable should return empty
        assert result == ""


class TestGetSlotDescription:
    """Test _get_slot_description method."""

    def test_dap(self):
        stub = RPCMixinStub()
        assert stub._get_slot_description(0, 1, 0) == "DAP"

    def test_interface(self):
        stub = RPCMixinStub()
        assert stub._get_slot_description(0, 0x8000, 0) == "Interface"

    def test_port(self):
        stub = RPCMixinStub()
        assert stub._get_slot_description(0, 0x8001, 0) == "Port 1"
        assert stub._get_slot_description(0, 0x8002, 0) == "Port 2"

    def test_io_module(self):
        stub = RPCMixinStub()
        # 0x10000000 prefix = I/O Module
        assert stub._get_slot_description(1, 1, 0x10000001) == "I/O Module"

    def test_comm_module(self):
        stub = RPCMixinStub()
        # 0x20000000 prefix = Comm Module
        assert stub._get_slot_description(1, 1, 0x20000001) == "Comm Module"

    def test_generic_module(self):
        stub = RPCMixinStub()
        assert stub._get_slot_description(1, 1, 0x50000001) == "Module"

    def test_submodule(self):
        stub = RPCMixinStub()
        assert stub._get_slot_description(1, 2, 0) == "Submodule"


class TestShowRPCHint:
    """Test _show_rpc_hint method."""

    def test_io_controller_hint(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(
            mac_address="00:11:22:33:44:55",
            device_roles=["IO-Controller"],
        )
        stub._show_rpc_hint(device)
        assert any("I-Device" in msg for _, msg in stub.logger.messages)

    def test_io_device_hint(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(
            mac_address="00:11:22:33:44:55",
            device_roles=["IO-Device"],
        )
        stub._show_rpc_hint(device)
        assert any("configuration" in msg for _, msg in stub.logger.messages)

    def test_no_device_hint(self):
        stub = RPCMixinStub()
        stub._show_rpc_hint(None)
        assert any("configuration" in msg for _, msg in stub.logger.messages)


class TestTestWriteAccess:
    """Test _test_write_access method."""

    def test_writable(self):
        stub = RPCMixinStub()
        con = MockCon()
        result = stub._test_write_access(con, 0, 1, 0xAFF1, b"test")
        assert result == "RW"

    def test_read_only(self):
        stub = RPCMixinStub()
        con = MockCon(write_fail=True)
        result = stub._test_write_access(con, 0, 1, 0xAFF1, b"test")
        assert result.startswith("RO")

    def test_read_only_with_error_code(self):
        stub = RPCMixinStub()
        con = MagicMock()
        con.write.side_effect = Exception("PNIO error 0xDE4")
        result = stub._test_write_access(con, 0, 1, 0xAFF1, b"test")
        assert "RO" in result
        assert "0xDE4" in result


class TestReadSingleIndex:
    """Test _read_single_index method."""

    def test_read_valid_index(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        con.read.return_value = MockResult(b"Hello Test Data")

        with patch(
            "oida.protocols.profinet.mixins.rpc.RPCMixin._format_index_value",
            return_value='"Hello Test Data"',
        ):
            stub._read_single_index(device, con, "0xAFF0")

        assert any("success" == level for level, _ in stub.logger.messages)

    def test_read_invalid_index_format(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MockCon()

        stub._read_single_index(device, con, "not_a_number")

        assert any("Invalid index" in msg for _, msg in stub.logger.messages)

    def test_read_empty_result(self):
        stub = RPCMixinStub()
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MagicMock()
        con.read.return_value = MockResult(b"")

        stub._read_single_index(device, con, "0xAFF0")

        assert any("empty" in msg for _, msg in stub.logger.messages)


class TestWriteSingleIndex:
    """Test _write_single_index method."""

    def test_write_requires_confirm(self):
        stub = RPCMixinStub(args={"confirm": False})
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MockCon()

        stub._write_single_index(device, con, "0xAFF1:48656C6C6F")

        assert any("--confirm" in msg for _, msg in stub.logger.messages)

    def test_write_invalid_format(self):
        stub = RPCMixinStub(args={"confirm": True})
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MockCon()

        stub._write_single_index(device, con, "bad_format")

        assert any("Invalid" in msg for _, msg in stub.logger.messages)

    def test_write_proceeds_with_confirm(self):
        # --confirm is the only gate; there is no --read-only/--no-read-only flag,
        # so a confirmed write of a valid spec must actually reach con.write().
        stub = RPCMixinStub(args={"confirm": True})
        device = ProfinetDevice(mac_address="00:11:22:33:44:55")
        con = MockCon()

        stub._write_single_index(device, con, "0xAFF1:48656C6C6F")

        assert con.writes == [(0, 1, 0xAFF1, b"Hello")]
        assert not any("read-only" in msg for _, msg in stub.logger.messages)
