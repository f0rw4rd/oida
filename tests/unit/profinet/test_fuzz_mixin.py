"""Tests for PROFINET FuzzMixin."""

from unittest.mock import MagicMock


class MockLogger:
    """Minimal logger mock."""

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


class FuzzMixinStub:
    """Stub class that mixes in FuzzMixin for testing."""

    def __init__(self, args=None):
        self._args = args or {}
        self.logger = MockLogger()

    def _arg(self, name, default=None):
        return self._args.get(name, default)

    def _test_write_access(self, con, slot, subslot, idx, data):
        return "RW"

    def _get_index_data_type(self, idx):
        if idx in (0xAFF1, 0xAFF2, 0xAFF3, 0xAFF5):
            return "string"
        return "struct"


# Patch FuzzMixin into the stub
from oida.protocols.profinet.mixins.fuzz import FuzzMixin

for attr in dir(FuzzMixin):
    if (
        not attr.startswith("_")
        or attr.startswith("_handle")
        or attr.startswith("_fuzz")
        or attr.startswith("_discover")
        or attr.startswith("_parse_fuzz")
    ):
        method = getattr(FuzzMixin, attr)
        if callable(method):
            setattr(FuzzMixinStub, attr, method)


class TestParsesFuzzIndices:
    """Test _parse_fuzz_indices."""

    def test_single_index(self):
        stub = FuzzMixinStub()
        result = stub._parse_fuzz_indices("0xAFF1")
        assert result == [(0, 1, 0xAFF1)]

    def test_multiple_indices(self):
        stub = FuzzMixinStub()
        result = stub._parse_fuzz_indices("0xAFF1,0xAFF2,0xAFF3")
        assert result == [(0, 1, 0xAFF1), (0, 1, 0xAFF2), (0, 1, 0xAFF3)]

    def test_range(self):
        stub = FuzzMixinStub()
        result = stub._parse_fuzz_indices("0xAFF1-0xAFF3")
        assert result == [(0, 1, 0xAFF1), (0, 1, 0xAFF2), (0, 1, 0xAFF3)]

    def test_decimal_index(self):
        stub = FuzzMixinStub()
        result = stub._parse_fuzz_indices("100")
        assert result == [(0, 1, 100)]

    def test_invalid_format(self):
        stub = FuzzMixinStub()
        result = stub._parse_fuzz_indices("not_a_number")
        assert result == []
        assert any(level == "fail" for level, _ in stub.logger.messages)


class TestDiscoverWritableIndices:
    """Test _discover_writable_indices."""

    def test_discovers_rw_indices(self):
        stub = FuzzMixinStub()
        con = MockCon(read_data=b"Hello World 1234")
        result = stub._discover_writable_indices(con)
        # Should find I&M1, I&M2, I&M3 as writable
        assert len(result) == 3
        assert (0, 1, 0xAFF1) in result
        assert (0, 1, 0xAFF2) in result
        assert (0, 1, 0xAFF3) in result

    def test_empty_when_read_fails(self):
        stub = FuzzMixinStub()
        con = MockCon(read_data=b"")
        result = stub._discover_writable_indices(con)
        assert result == []

    def test_default_slots_when_none(self):
        stub = FuzzMixinStub()
        con = MockCon(read_data=b"test")
        result = stub._discover_writable_indices(con, discovered_slots=None)
        # Should use default [(0, 1, 0, 0)]
        assert len(result) > 0

    def test_connection_loss_returns_partial(self):
        stub = FuzzMixinStub()

        call_count = 0

        class FailingCon(MockCon):
            def read(self, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count > 1:
                    raise OSError("Connection reset")
                return MockResult(b"test data here!!")

        con = FailingCon()
        # _test_write_access returns "RW" so first index is found
        result = stub._discover_writable_indices(con)
        assert len(result) == 1  # Got one before connection died
        assert any("Connection lost" in msg for _, msg in stub.logger.messages)


class TestHandleFuzz:
    """Test _handle_fuzz."""

    def test_requires_confirm(self):
        stub = FuzzMixinStub(args={"fuzz": "basic"})
        device = MagicMock()
        con = MockCon()
        stub._handle_fuzz(device, con)
        assert any("--confirm" in msg for _, msg in stub.logger.messages)

    def test_no_mode_returns_early(self):
        stub = FuzzMixinStub(args={"fuzz": None, "confirm": True})
        device = MagicMock()
        con = MockCon()
        stub._handle_fuzz(device, con)
        # Should return without doing anything
        assert not any("Fuzzing" in msg for _, msg in stub.logger.messages)

    def test_user_specified_indices(self):
        stub = FuzzMixinStub(
            args={
                "fuzz": "basic",
                "confirm": True,
                "fuzz_iterations": 2,
                "fuzz_indices": "0xAFF1",
                "fuzz_delay": 0.001,
            }
        )
        device = MagicMock()
        con = MockCon(read_data=b"A" * 32)
        stub._handle_fuzz(device, con)
        assert any("Fuzzing 1 index" in msg for _, msg in stub.logger.messages)


class TestFuzzWritableIndices:
    """Test _fuzz_writable_indices."""

    def test_restores_original_value(self):
        stub = FuzzMixinStub(args={"fuzz_delay": 0.001})
        con = MockCon(read_data=b"original_data_xx")
        indices = [(0, 1, 0xAFF1)]

        stub._fuzz_writable_indices(con, indices, iterations=2, mode="basic")

        # Last write should be the restore (original data)
        assert con.writes[-1] == (0, 1, 0xAFF1, b"original_data_xx")

    def test_reports_results(self):
        stub = FuzzMixinStub(args={"fuzz_delay": 0.001})
        con = MockCon(read_data=b"test_data_123456")
        indices = [(0, 1, 0xAFF1)]

        stub._fuzz_writable_indices(con, indices, iterations=3, mode="basic")

        # Should have a result summary line
        assert any("tests:" in msg for _, msg in stub.logger.messages)

    def test_write_failure_counts(self):
        stub = FuzzMixinStub(args={"fuzz_delay": 0.001})

        class FailWriteCon(MockCon):
            def write(self, **kwargs):
                raise Exception("PNIO error 0xDE4")

        con = FailWriteCon(read_data=b"test_data_123456")
        indices = [(0, 1, 0xAFF1)]

        stub._fuzz_writable_indices(con, indices, iterations=2, mode="basic")

        # Should report failures and restore failure
        assert any(level == "error" for level, _ in stub.logger.messages)
