"""Tests for PROFINET EnumerationMixin.

These tests drive the index-enumeration logic with realistic in-memory
connection mocks. Only the network/RPC boundary (``con``) and the optional
GSDML descriptor (``self._gsdml``) are mocked - the enumeration logic itself
(probe-list construction, slot filtering, adaptive probing, table building,
hex dumps, write-only detection) runs unmodified against the real
``profinet.indices`` module.

The code under test is never monkey-patched.
"""

from unittest.mock import MagicMock

from oida.protocols.profinet.mixins.enumeration import EnumerationMixin
from oida.protocols.profinet.mixins.rpc import RPCMixin
from oida.protocols.profinet.models import ProfinetDevice


class MockLogger:
    """Minimal logger mock recording (level, message) tuples."""

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

    def progress(self, *args, **kwargs):
        self.messages.append(("progress", args))


class MockResult:
    """Mock RPC read result."""

    def __init__(self, payload=b""):
        self.payload = payload

    def __len__(self):
        return len(self.payload)


class MockCon:
    """Mock RPC connection (the network boundary).

    ``readable_indices`` controls which idx values return non-empty payloads;
    if None, every read returns ``read_data``.
    ``read_fail_indices`` makes the matching idx raise (simulating a read error).
    """

    def __init__(
        self,
        read_data=b"\x01\x02\x03\x04",
        readable_indices=None,
        read_fail_indices=None,
        write_fail=False,
    ):
        self._read_data = read_data
        self._readable = readable_indices
        self._read_fail = read_fail_indices or set()
        self._write_fail = write_fail
        self.reads = []
        self.writes = []

    def read(self, api=0, slot=0, subslot=1, idx=0):
        self.reads.append((slot, subslot, idx))
        if idx in self._read_fail:
            raise OSError("read error")
        if self._readable is not None and idx not in self._readable:
            return MockResult(b"")
        return MockResult(self._read_data)

    def write(self, api=0, slot=0, subslot=1, idx=0, data=b""):
        self.writes.append((slot, subslot, idx, data))
        if self._write_fail:
            raise Exception("Write rejected 0xDE4")

    def close(self):
        pass


class EnumStub(EnumerationMixin, RPCMixin):
    """Stub mixing both Enumeration and RPC mixins (enumeration depends on
    ``_format_index_value`` / ``_test_write_access`` / ``_test_write_only``
    from RPCMixin)."""

    def __init__(self, args=None, gsdml=None, timeout=2.0):
        self._args = args or {}
        self.logger = MockLogger()
        self._gsdml = gsdml
        self.timeout = timeout

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


def _real_indices():
    from profinet import indices

    return indices


# ──────────────────────────────────────────────────────────────────────
# _get_enum_options
# ──────────────────────────────────────────────────────────────────────


class TestGetEnumOptions:
    def test_defaults(self):
        stub = EnumStub()
        opts = stub._get_enum_options()
        assert opts == {
            "enum_all": False,
            "enum_smart": False,
            "enum_range": None,
            "show_data": False,
            "test_write": False,
            "detect_write_only": False,
            "slot_arg": None,
        }

    def test_reflects_args(self):
        stub = EnumStub(
            args={
                "enum_smart": True,
                "enum_range": "0x10-0x20",
                "show_data": True,
                "test_write": True,
                "detect_write_only": True,
                "slot": "1/1",
            }
        )
        opts = stub._get_enum_options()
        assert opts["enum_smart"] is True
        assert opts["enum_range"] == "0x10-0x20"
        assert opts["show_data"] is True
        assert opts["test_write"] is True
        assert opts["detect_write_only"] is True
        assert opts["slot_arg"] == "1/1"


# ──────────────────────────────────────────────────────────────────────
# _filter_slots
# ──────────────────────────────────────────────────────────────────────


class TestFilterSlots:
    def test_none_uses_default(self):
        stub = EnumStub()
        assert stub._filter_slots(None, None, None) == [(0, 1)]

    def test_no_filter_keeps_all(self):
        stub = EnumStub()
        slots = [(0, 1, 0, 0), (1, 1, 0, 0), (1, 0x8001, 0, 0)]
        assert stub._filter_slots(slots, None, None) == [(0, 1), (1, 1), (1, 0x8001)]

    def test_filter_by_slot(self):
        stub = EnumStub()
        slots = [(0, 1, 0, 0), (1, 1, 0, 0), (1, 0x8001, 0, 0)]
        assert stub._filter_slots(slots, 1, None) == [(1, 1), (1, 0x8001)]

    def test_filter_by_slot_and_subslot(self):
        stub = EnumStub()
        slots = [(0, 1, 0, 0), (1, 1, 0, 0), (1, 0x8001, 0, 0)]
        assert stub._filter_slots(slots, 1, 0x8001) == [(1, 0x8001)]

    def test_filter_no_match(self):
        stub = EnumStub()
        slots = [(0, 1, 0, 0)]
        assert stub._filter_slots(slots, 99, None) == []


# ──────────────────────────────────────────────────────────────────────
# _build_probe_list
# ──────────────────────────────────────────────────────────────────────


class TestBuildProbeList:
    def test_range_hex(self):
        stub = EnumStub()
        idx = _real_indices()
        opts = {"enum_range": "0x10-0x13", "enum_all": False, "enum_smart": False}
        result = stub._build_probe_list(idx, opts, use_gsdml=False)
        assert [i for i, _ in result] == [0x10, 0x11, 0x12, 0x13]
        # names come from the real indices module
        assert all(isinstance(name, str) for _, name in result)

    def test_range_single_value(self):
        stub = EnumStub()
        idx = _real_indices()
        opts = {"enum_range": "0x20", "enum_all": False, "enum_smart": False}
        result = stub._build_probe_list(idx, opts, use_gsdml=False)
        assert [i for i, _ in result] == [0x20]

    def test_range_decimal(self):
        stub = EnumStub()
        idx = _real_indices()
        opts = {"enum_range": "10-12", "enum_all": False, "enum_smart": False}
        result = stub._build_probe_list(idx, opts, use_gsdml=False)
        assert [i for i, _ in result] == [10, 11, 12]

    def test_range_start_greater_than_end(self):
        stub = EnumStub()
        idx = _real_indices()
        opts = {"enum_range": "0x30-0x10", "enum_all": False, "enum_smart": False}
        result = stub._build_probe_list(idx, opts, use_gsdml=False)
        assert result is None
        assert any("Invalid range" in m for _, m in stub.logger.messages)

    def test_range_bad_format(self):
        stub = EnumStub()
        idx = _real_indices()
        opts = {"enum_range": "zzz-yyy", "enum_all": False, "enum_smart": False}
        result = stub._build_probe_list(idx, opts, use_gsdml=False)
        assert result is None
        assert any("Invalid range format" in m for _, m in stub.logger.messages)

    def test_enum_all_full_space(self):
        stub = EnumStub()
        idx = _real_indices()
        opts = {"enum_range": None, "enum_all": True, "enum_smart": False}
        result = stub._build_probe_list(idx, opts, use_gsdml=False)
        assert len(result) == 0x10000
        assert result[0][0] == 0
        assert result[-1][0] == 0xFFFF

    def test_enum_smart_delegates(self):
        stub = EnumStub()
        idx = _real_indices()
        opts = {"enum_range": None, "enum_all": False, "enum_smart": True}
        result = stub._build_probe_list(idx, opts, use_gsdml=False)
        # smart list is sorted and unique
        indices = [i for i, _ in result]
        assert indices == sorted(indices)
        assert len(indices) == len(set(indices))
        # contains the special gateway indices
        assert 0x200F in indices
        assert 0xB02E in indices

    def test_default_standard_plus_user(self):
        stub = EnumStub()
        idx = _real_indices()
        opts = {"enum_range": None, "enum_all": False, "enum_smart": False}
        result = stub._build_probe_list(idx, opts, use_gsdml=False)
        indices = [i for i, _ in result]
        # default appends user-specific 0-20 and 32*6 channel/param entries
        assert 0 in indices
        assert 20 in indices
        # channel 1 param 1 -> 100 + ... actually channel*100+param => 101
        assert 101 in indices
        # 41 standard + 21 user + 192 channel entries
        assert len(result) == len(idx.ALL_STANDARD_INDICES) + 21 + 32 * 6

    def test_use_gsdml(self):
        gsdml = MagicMock()
        gsdml.get_all_indices.return_value = [(0x100, "GSDML A"), (0x200, "GSDML B")]
        stub = EnumStub(gsdml=gsdml)
        idx = _real_indices()
        result = stub._build_probe_list(idx, {"enum_range": None}, use_gsdml=True)
        assert result == [(0x100, "GSDML A"), (0x200, "GSDML B")]
        assert any("GSDML defines 2 indices" in m for _, m in stub.logger.messages)


# ──────────────────────────────────────────────────────────────────────
# _build_smart_probe_list
# ──────────────────────────────────────────────────────────────────────


class TestBuildSmartProbeList:
    def test_includes_fixed_ranges(self):
        stub = EnumStub()
        idx = _real_indices()
        result = stub._build_smart_probe_list(idx)
        indices = {i for i, _ in result}
        # PROFIdrive data set 47
        assert 47 in indices
        # subslot full scan 0x8000-0x80FF
        assert 0x8000 in indices and 0x80FF in indices
        # I&M range full scan
        assert 0xAFF0 in indices and 0xAFFF in indices
        # API/device range full scan
        assert 0xF000 in indices and 0xFFFF in indices

    def test_far_fewer_than_full_space(self):
        stub = EnumStub()
        idx = _real_indices()
        result = stub._build_smart_probe_list(idx)
        # Smart list is a large but bounded subset, much smaller than 65536
        assert 0 < len(result) < 0x10000


# ──────────────────────────────────────────────────────────────────────
# _deduplicate_probe_list
# ──────────────────────────────────────────────────────────────────────


class TestDeduplicate:
    def test_removes_dupes_keeps_first_order(self):
        stub = EnumStub()
        probe = [(1, "a"), (2, "b"), (1, "dup"), (3, "c"), (2, "dup2")]
        result = stub._deduplicate_probe_list(probe)
        assert result == [(1, "a"), (2, "b"), (3, "c")]

    def test_no_dupes_unchanged(self):
        stub = EnumStub()
        probe = [(1, "a"), (2, "b")]
        assert stub._deduplicate_probe_list(probe) == probe


# ──────────────────────────────────────────────────────────────────────
# _probe_slot
# ──────────────────────────────────────────────────────────────────────


class TestProbeSlot:
    def test_finds_readable_indices(self):
        stub = EnumStub()
        idx = _real_indices()
        con = MockCon(read_data=b"DATA", readable_indices={0xAFF0, 0xAFF1})
        probe = [(0xAFF0, "I&M0"), (0xAFF1, "I&M1"), (0xAFF2, "I&M2")]
        options = {"enum_smart": False, "test_write": False, "detect_write_only": False}
        access_stats = {}

        readable, failed, results, total = stub._probe_slot(
            con, 0, 1, probe, idx, options, access_stats
        )

        assert total == 3
        found = {key[2] for key, _ in readable}
        assert found == {0xAFF0, 0xAFF1}
        assert results[(0, 1, 0xAFF0)]["access"] == "R"
        assert results[(0, 1, 0xAFF0)]["size"] == 4

    def test_detect_write_only_collects_failed_reads(self):
        stub = EnumStub()
        idx = _real_indices()
        con = MockCon(read_data=b"DATA", readable_indices={0xAFF0})
        probe = [(0xAFF0, "I&M0"), (0xAFF1, "I&M1")]
        options = {"enum_smart": False, "test_write": False, "detect_write_only": True}
        access_stats = {}

        readable, failed, results, total = stub._probe_slot(
            con, 0, 1, probe, idx, options, access_stats
        )

        # 0xAFF1 returned empty payload -> not readable -> recorded as failed
        assert (0xAFF1, "I&M1") in failed
        assert {key[2] for key, _ in readable} == {0xAFF0}

    def test_test_write_records_access_stats(self):
        stub = EnumStub()
        idx = _real_indices()
        # writable connection => _test_write_access returns "RW"
        con = MockCon(read_data=b"DATA", readable_indices={0xAFF1}, write_fail=False)
        probe = [(0xAFF1, "I&M1")]
        options = {"enum_smart": False, "test_write": True, "detect_write_only": False}
        access_stats = {}

        readable, failed, results, total = stub._probe_slot(
            con, 0, 1, probe, idx, options, access_stats
        )

        assert access_stats.get("RW") == 1
        assert results[(0, 1, 0xAFF1)]["access"] == "RW"

    def test_test_write_read_only_records_ro(self):
        stub = EnumStub()
        idx = _real_indices()
        con = MockCon(read_data=b"DATA", readable_indices={0xAFF1}, write_fail=True)
        probe = [(0xAFF1, "I&M1")]
        options = {"enum_smart": False, "test_write": True, "detect_write_only": False}
        access_stats = {}

        stub._probe_slot(con, 0, 1, probe, idx, options, access_stats)
        # write_fail raises an exception containing 0xDE4 -> "RO (0x...)"
        assert any(k.startswith("RO") for k in access_stats)

    def test_adaptive_mode_expands_probes(self):
        stub = EnumStub()
        idx = _real_indices()
        # In adaptive (smart) mode, a hit at idx < 0x8000 schedules idx+1..idx+10.
        # Make 0x100 readable; expansions 0x101..0x10A also readable.
        readable = {0x100} | set(range(0x101, 0x10B))
        con = MockCon(read_data=b"X", readable_indices=readable)
        probe = [(0x100, "base")]
        options = {"enum_smart": True, "test_write": False, "detect_write_only": False}
        access_stats = {}

        found, failed, results, total = stub._probe_slot(
            con, 0, 1, probe, idx, options, access_stats
        )

        # total_ops grew beyond the single starting probe due to adaptive expansion
        assert total > 1
        found_indices = {key[2] for key, _ in found}
        assert 0x100 in found_indices
        assert 0x101 in found_indices

    def test_adaptive_mode_no_expand_above_0x8000(self):
        stub = EnumStub()
        idx = _real_indices()
        con = MockCon(read_data=b"X", readable_indices={0x8050})
        probe = [(0x8050, "subslot")]
        options = {"enum_smart": True, "test_write": False, "detect_write_only": False}
        access_stats = {}

        found, failed, results, total = stub._probe_slot(
            con, 0, 1, probe, idx, options, access_stats
        )
        # No adaptive expansion above 0x8000
        assert total == 1

    def test_read_exception_handled(self):
        stub = EnumStub()
        idx = _real_indices()
        con = MockCon(read_fail_indices={0xAFF0})
        probe = [(0xAFF0, "I&M0")]
        options = {"enum_smart": False, "test_write": False, "detect_write_only": False}
        access_stats = {}

        found, failed, results, total = stub._probe_slot(
            con, 0, 1, probe, idx, options, access_stats
        )
        assert found == []
        assert total == 1


# ──────────────────────────────────────────────────────────────────────
# _detect_write_only_indices
# ──────────────────────────────────────────────────────────────────────


class TestDetectWriteOnly:
    def test_no_failed_reads_returns_empty(self):
        stub = EnumStub()
        con = MockCon()
        assert stub._detect_write_only_indices(con, 0, 1, [], {}) == []

    def test_safe_index_writes_succeed_marked_write_only(self):
        stub = EnumStub()
        # 0xAFF1 is in the safe write-probe range -> _test_write_only writes b"\x00"
        con = MockCon(write_fail=False)
        access_stats = {}
        failed = [(0xAFF1, "I&M1")]

        result = stub._detect_write_only_indices(con, 0, 1, failed, access_stats)

        assert len(result) == 1
        key, info = result[0]
        assert key == (0, 1, 0xAFF1)
        assert info["access"] == "W"
        assert access_stats["W"] == 1

    def test_unsafe_index_not_probed(self):
        stub = EnumStub()
        con = MockCon(write_fail=False)
        failed = [(0x1234, "User")]  # outside the safe range
        result = stub._detect_write_only_indices(con, 0, 1, failed, {})
        assert result == []
        # nothing written for an unsafe index
        assert con.writes == []

    def test_write_failure_not_marked(self):
        stub = EnumStub()
        con = MockCon(write_fail=True)
        failed = [(0xAFF1, "I&M1")]
        result = stub._detect_write_only_indices(con, 0, 1, failed, {})
        assert result == []


# ──────────────────────────────────────────────────────────────────────
# _build_table_data
# ──────────────────────────────────────────────────────────────────────


class TestBuildTableData:
    def test_basic_row(self):
        stub = EnumStub()
        all_indices = [
            (
                (1, 1, 0xAFF0),
                {"name": "I&M0", "size": 4, "access": "R", "data": b"\x01\x02\x03\x04"},
            )
        ]
        rows = stub._build_table_data(all_indices, show_data=False)
        assert rows == [["1/1", "0xAFF0", "I&M0", "4", "R"]]

    def test_subslot_hex_format(self):
        stub = EnumStub()
        all_indices = [
            ((0, 0x8001, 0x1234), {"name": "Port", "size": 0, "access": "R", "data": b""})
        ]
        rows = stub._build_table_data(all_indices, show_data=False)
        # subslot >= 0x8000 -> hex; size 0 -> "-"
        assert rows[0][0] == "0/0x8001"
        assert rows[0][3] == "-"

    def test_show_data_adds_value_and_hex(self):
        stub = EnumStub()
        all_indices = [
            ((0, 1, 0xAFF0), {"name": "x", "size": 2, "access": "R", "data": b"\x00\x2a"})
        ]
        rows = stub._build_table_data(all_indices, show_data=True)
        row = rows[0]
        assert len(row) == 7  # 5 base + value + hex
        # _format_index_value of b"\x00\x2a" -> "42 (0x002A)"
        assert "42" in row[5]
        assert row[6] == "00 2A"

    def test_show_data_long_payload_truncated(self):
        stub = EnumStub()
        data = bytes(range(20))  # 20 bytes > 16
        all_indices = [((0, 1, 0x100), {"name": "x", "size": 20, "access": "R", "data": data})]
        rows = stub._build_table_data(all_indices, show_data=True)
        assert rows[0][6].endswith("...")


# ──────────────────────────────────────────────────────────────────────
# _display_results
# ──────────────────────────────────────────────────────────────────────


class TestDisplayResults:
    def test_summary_no_table(self):
        stub = EnumStub()
        options = {"test_write": False, "detect_write_only": False, "show_data": False}
        stub._display_results([], [1, 2], [], {}, options, total_ops=10)
        assert any("Found 2 readable out of 10 tested" in m for _, m in stub.logger.messages)

    def test_summary_with_access_stats(self):
        stub = EnumStub()
        options = {"test_write": True, "detect_write_only": False, "show_data": False}
        access_stats = {"RO": 3, "RW": 2, "W": 0}
        stub._display_results([], [1, 2, 3, 4, 5], [], access_stats, options, total_ops=20)
        msg = " ".join(m for _, m in stub.logger.messages)
        assert "5 readable" in msg
        assert "3 RO" in msg
        assert "2 RW" in msg

    def test_summary_with_write_only(self):
        # With empty table_data the method returns after the summary line
        # (the legend lives past the `if not table_data: return` guard).
        stub = EnumStub()
        options = {"test_write": False, "detect_write_only": True, "show_data": False}
        access_stats = {"W": 1}
        stub._display_results([], [1], [("k", {})], access_stats, options, total_ops=5)
        msg = " ".join(m for _, m in stub.logger.messages)
        assert "1 write-only" in msg

    def test_legend_printed_when_table_present(self):
        # With non-empty table data, _display_results exports the table (via the
        # real export_table API) and then prints the legend - no exception. This
        # guards the regression where a bogus `logger=` kwarg made export_table
        # raise TypeError, silently swallowed by the caller so nothing printed.
        stub = EnumStub()
        options = {"test_write": False, "detect_write_only": False, "show_data": False}
        stub._display_results(
            [["1/1", "0xAFF0", "I&M0", "4", "R"]], [1], [], {}, options, total_ops=1
        )
        msg = " ".join(m for _, m in stub.logger.messages)
        # Summary emitted before the export...
        assert "Found 1 readable out of 1 tested" in msg
        # ...and the legend prints after the table (the previously-dead lines).
        assert "Legend: R=Readable" in msg


# ──────────────────────────────────────────────────────────────────────
# _display_hex_dumps
# ──────────────────────────────────────────────────────────────────────


class TestDisplayHexDumps:
    def test_dumps_data_in_chunks(self):
        stub = EnumStub()
        data = bytes(range(40))  # 40 bytes -> 2 chunks of 32
        all_readable = [((1, 1, 0xAFF0), {"name": "I&M0", "size": 40, "data": data})]
        stub._display_hex_dumps(all_readable)
        msgs = [m for _, m in stub.logger.messages]
        # header line with name + byte count
        assert any("I&M0 (40 bytes)" in m for m in msgs)
        # ascii rendering of printable bytes (e.g. ' !"#...' for 32..)
        assert any("!" in m for m in msgs)

    def test_subslot_hex_in_header(self):
        stub = EnumStub()
        all_readable = [((0, 0x8001, 0x100), {"name": "x", "size": 1, "data": b"\x41"})]
        stub._display_hex_dumps(all_readable)
        assert any("[0/0x8001]" in m for _, m in stub.logger.messages)


# ──────────────────────────────────────────────────────────────────────
# _enumerate_indices (top-level orchestration)
# ──────────────────────────────────────────────────────────────────────


class TestEnumerateIndices:
    def _device(self, vendor_id=0x002A, device_id=0x010D):
        return ProfinetDevice(
            mac_address="00:11:22:33:44:55",
            vendor_id=vendor_id,
            device_id=device_id,
        )

    def test_test_write_requires_confirm(self):
        stub = EnumStub(args={"test_write": True, "confirm": False})
        con = MockCon()
        stub._enumerate_indices(self._device(), con)
        assert any("--test-write requires --confirm" in m for _, m in stub.logger.messages)
        # No reads attempted because we bailed early
        assert con.reads == []

    def test_detect_write_only_requires_confirm(self):
        stub = EnumStub(args={"detect_write_only": True, "confirm": False})
        con = MockCon()
        stub._enumerate_indices(self._device(), con)
        assert any("--detect-write-only requires --confirm" in m for _, m in stub.logger.messages)

    def test_no_matching_slots(self):
        stub = EnumStub(args={"slot": "5/1"})
        con = MockCon()
        # discovered slots only has slot 0; filter 5 -> empty
        stub._enumerate_indices(self._device(), con, discovered_slots=[(0, 1, 0, 0)])
        assert any("No matching slots found" in m for _, m in stub.logger.messages)

    def test_range_enumeration_finds_readable(self):
        # Probe a small explicit range; mark 0xAFF1 readable.
        stub = EnumStub(args={"enum_range": "0xAFF0-0xAFF2"})
        con = MockCon(read_data=b"\x00\x2a", readable_indices={0xAFF1})
        device = self._device()

        stub._enumerate_indices(device, con, discovered_slots=[(0, 1, 0, 0)])

        # Reads were attempted for the 3 indices in the range
        read_indices = {idx for _, _, idx in con.reads}
        assert {0xAFF0, 0xAFF1, 0xAFF2} <= read_indices
        # Summary message reports 1 readable found
        assert any("Found 1 readable" in m for _, m in stub.logger.messages)

    def test_gsdml_match_uses_gsdml_indices(self):
        gsdml = MagicMock()
        gsdml.vendor_id = 0x002A
        gsdml.device_id = 0x010D
        gsdml.vendor_name = "Siemens"
        gsdml.get_all_indices.return_value = [(0xAFF0, "I&M0")]
        stub = EnumStub(gsdml=gsdml)
        con = MockCon(read_data=b"data", readable_indices={0xAFF0})

        stub._enumerate_indices(self._device(), con, discovered_slots=[(0, 1, 0, 0)])

        assert any("Using GSDML indices" in m for _, m in stub.logger.messages)
        gsdml.get_all_indices.assert_called_once()

    def test_gsdml_mismatch_reports_and_uses_default(self):
        gsdml = MagicMock()
        gsdml.vendor_id = 0x1111
        gsdml.device_id = 0x2222
        gsdml.get_all_indices.return_value = [(0xAFF0, "I&M0")]
        stub = EnumStub(gsdml=gsdml)
        con = MockCon(read_data=b"", readable_indices=set())

        stub._enumerate_indices(self._device(), con, discovered_slots=[(0, 1, 0, 0)])

        assert any("GSDML mismatch" in m for _, m in stub.logger.messages)
        # default probe list used, not the GSDML one
        gsdml.get_all_indices.assert_not_called()

    def test_invalid_range_aborts(self):
        stub = EnumStub(args={"enum_range": "0x30-0x10"})
        con = MockCon()
        stub._enumerate_indices(self._device(), con, discovered_slots=[(0, 1, 0, 0)])
        assert any("Invalid range" in m for _, m in stub.logger.messages)
        # aborted before reading
        assert con.reads == []

    def test_detect_write_only_with_confirm_runs(self):
        stub = EnumStub(args={"detect_write_only": True, "confirm": True, "enum_range": "0xAFF1"})
        # 0xAFF1 read returns empty (failed read) -> write-only probe writes b"\x00"
        con = MockCon(read_data=b"", readable_indices=set())

        stub._enumerate_indices(self._device(), con, discovered_slots=[(0, 1, 0, 0)])

        # write-only probe occurred on the safe index
        assert any(w[2] == 0xAFF1 for w in con.writes)
        assert any("write-only" in m for _, m in stub.logger.messages)
