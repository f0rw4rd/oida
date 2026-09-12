"""Regression tests for TestCaseManager / database-interface bugs (loop 2).

C4 -- ``store_payload`` / ``get_payload`` were called by ``TestCaseManager`` but
     were NOT part of the ``DatabaseInterface`` contract: only the SQLAlchemy
     backend happened to implement them. Any conforming custom backend (and the
     in-tree ``MockDatabase``) blew up with ``AttributeError`` at runtime in
     ``--store-all-payloads`` mode and on the replay path.

C6 -- read-only commands (``list`` / ``detail`` / ``replay``) construct a
     ``TestCaseManager``, whose ``__init__`` unconditionally re-wrote session
     metadata: ``created_at``, ``protocol_version`` (the CURRENT git hash),
     ``seed`` and ``config_options`` of the ALREADY-RECORDED session were
     clobbered -- destroying exactly the provenance replay validation tells the
     user to check on a CRC mismatch.

C7 -- ``replay_test_case`` created and opened the socket OUTSIDE the
     ``try/finally``: if ``open()`` raised (target down -- the common case when
     replaying a crash), the socket object was never closed and the fd leaked
     for every case in a replayed range.
"""

from types import SimpleNamespace

import pytest

from src.oida.fuzz.core.database.interface import DatabaseInterface
from src.oida.fuzz.core.database.mock import MockDatabase
from src.oida.fuzz.core.session.manager import TestCaseManager


class _FakeLog:
    def display(self, *a, **k):
        pass

    success = warning = fail = debug = display


def _make_fuzzer(**overrides):
    config = SimpleNamespace(
        session_filename="unused",
        monitor_check_interval=2,
        protocol="modbus",
        seed=None,
        options={},
        target_ip="127.0.0.1",
        target_port=502,
    )
    for k, v in overrides.items():
        setattr(config, k, v)
    return SimpleNamespace(config=config, log=_FakeLog(), session=None)


def _make_manager(db=None, store_all_payloads=False, **kwargs):
    db = db if db is not None else MockDatabase()
    db.init_schema(store_all_payloads=store_all_payloads)
    mgr = TestCaseManager(
        _make_fuzzer(), database=db, store_all_payloads=store_all_payloads, **kwargs
    )
    return mgr, db


# ---------------------------------------------------------------------------
# C4: payload storage is part of the DatabaseInterface contract
# ---------------------------------------------------------------------------


def test_payload_methods_are_part_of_the_abstract_contract():
    """A backend that omits store_payload/get_payload must not be instantiable."""
    assert "store_payload" in DatabaseInterface.__abstractmethods__
    assert "get_payload" in DatabaseInterface.__abstractmethods__


def test_mock_database_implements_payload_roundtrip():
    db = MockDatabase()
    db.init_schema(store_all_payloads=True)
    assert db.get_payload(1) is None

    db.store_payload(1, b"\x01\x02", b"\x03")
    stored = db.get_payload(1)
    assert stored is not None
    assert stored["request"] == b"\x01\x02"
    assert stored["response"] == b"\x03"


def test_store_all_payloads_recording_works_on_a_conforming_backend():
    """record_test_case(--store-all-payloads) must not AttributeError."""
    mgr, db = _make_manager(store_all_payloads=True)
    mgr.record_test_case(1, "case-1", b"\xde\xad\xbe\xef", "pass")

    assert [tc.id for tc in db.get_test_cases()] == [1]
    assert db.get_payload(1)["request"] == b"\xde\xad\xbe\xef"


def test_payload_storage_respects_disabled_flag():
    """With payload storage off, store_payload is a no-op (matches the ORM)."""
    db = MockDatabase()
    db.init_schema(store_all_payloads=False)
    db.store_payload(7, b"abc")
    assert db.get_payload(7) is None


def test_get_payload_falls_back_to_crash_table():
    from src.oida.fuzz.core.database.interface import Crash

    db = MockDatabase()
    db.init_schema(store_all_payloads=False)
    db.store_crash(Crash(test_case_id=5, payload=b"boom", crash_info="x"))
    assert db.get_payload(5) == {"request": b"boom", "response": None}


# ---------------------------------------------------------------------------
# C6: read-only paths must not mutate persisted session metadata
# ---------------------------------------------------------------------------

_RECORDED = {
    "protocol_name": "modbus",
    "protocol_version": "cafebabe",
    "boofuzz_version": "0.4.1",
    "seed": "1234",
    "config_options": '{"depth": 3}',
    "created_at": "2020-01-01T00:00:00",
    "lightweight_mode": "True",
    "last_test_case": "9999",
}


def test_constructing_manager_preserves_recorded_session_metadata():
    """list/detail/replay build a manager -- it must not rewrite provenance."""
    db = MockDatabase()
    db.init_schema()
    for k, v in _RECORDED.items():
        db.store_metadata(k, v)

    _make_manager(db=db)

    for k, v in _RECORDED.items():
        assert db.get_metadata(k) == v, f"metadata key {k!r} was clobbered"


def test_read_only_manager_writes_no_metadata_at_all():
    db = MockDatabase()
    db.init_schema()
    _make_manager(db=db, read_only=True)
    assert db.get_all_metadata() == {}


def test_fresh_session_still_records_metadata():
    """The non-read-only, first-run path must still populate metadata."""
    _, db = _make_manager()
    md = db.get_all_metadata()
    assert md["protocol_name"] == "modbus"
    assert "created_at" in md


def test_read_only_manager_refuses_to_record():
    mgr, db = _make_manager(read_only=True, store_all_payloads=True)
    with pytest.raises(RuntimeError):
        mgr.record_test_case(1, "c", b"x", "pass")
    assert db.get_test_cases() == []


# ---------------------------------------------------------------------------
# C7: replay must never leak the socket
# ---------------------------------------------------------------------------


class _FakeSocket:
    def __init__(self, fail_on_open=False, fail_on_send=False):
        self.fail_on_open = fail_on_open
        self.fail_on_send = fail_on_send
        self.closed = False
        self.opened = False

    def open(self):
        if self.fail_on_open:
            raise ConnectionRefusedError("target down")
        self.opened = True

    def send(self, data):
        if self.fail_on_send:
            raise BrokenPipeError("gone")
        return len(data)

    def recv(self, n):
        return b""

    def close(self):
        self.closed = True


def _replay_manager(sock):
    from src.oida.fuzz.core.database.interface import Crash

    db = MockDatabase()
    db.init_schema()
    fuzzer = _make_fuzzer()
    fuzzer._create_socket = lambda: sock
    mgr = TestCaseManager(fuzzer, database=db, read_only=True)
    from src.oida.fuzz.core.database.interface import TestCase as TC

    db.store_test_case(TC(id=1, name="c1", timestamp="t", result="crash", crc32=0))
    db.store_crash(Crash(test_case_id=1, payload=b"\x01\x02", crash_info="boom"))
    return mgr, db


def test_replay_closes_socket_when_open_fails():
    sock = _FakeSocket(fail_on_open=True)
    mgr, _ = _replay_manager(sock)
    assert mgr.replay_test_case(1) is False
    assert sock.closed, "socket leaked when open() raised"


def test_replay_closes_socket_when_send_fails():
    sock = _FakeSocket(fail_on_send=True)
    mgr, _ = _replay_manager(sock)
    assert mgr.replay_test_case(1) is False
    assert sock.closed


def test_replay_closes_socket_on_success():
    sock = _FakeSocket()
    mgr, _ = _replay_manager(sock)
    assert mgr.replay_test_case(1) is True
    assert sock.closed
