"""Unit tests for KNXScanner orchestration (scanner.py).

Drives the real ``KNXScanner`` (mixins + NetworkScanner base) against a
mocked xknx connection (``start``/``stop`` AsyncMocks, ``_xknx_cls``
faked) to cover ``connect``/``disconnect``, ``_parse_device_range`` and
the ``discover`` -> ``_async_discover`` action dispatch.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from oida.protocols.knx.scanner import KNXScanner
from tests.unit.knx._harness import (
    FakeP2P,
    SpyLogger,
    install_fake_xknx_cls,
    make_mgmt,
    make_response,
)


@pytest.fixture
def fake_xknx(monkeypatch):
    return install_fake_xknx_cls(monkeypatch)


def make_scanner(args, p2p=None):
    base = {"host": "10.0.0.5", "port": 3671}
    base.update(args)
    s = KNXScanner(base, logger=SpyLogger())
    return s


def make_conn(p2p=None, *, start_error=None):
    """Build a mock xknx connection object with awaitable start/stop."""
    conn = MagicMock()
    if start_error is not None:
        conn.start = AsyncMock(side_effect=start_error)
    else:
        conn.start = AsyncMock()
    conn.stop = AsyncMock()
    conn.management = make_mgmt(p2p if p2p is not None else FakeP2P([]))
    conn.telegrams = MagicMock()
    conn.telegrams.put = AsyncMock()
    conn.connection_manager = MagicMock(connection_type="TUNNELING")
    return conn


class TestParseDeviceRange:
    def test_valid_range(self, fake_xknx):
        # use the REAL IndividualAddress arithmetic by un-faking it
        import xknx.telegram

        from oida.protocols.knx.scanner import _xknx_cls

        s = make_scanner({})
        _xknx_cls.IndividualAddress = xknx.telegram.IndividualAddress
        out = s._parse_device_range("1.1.1-1.1.4")
        assert out == ["1.1.1", "1.1.2", "1.1.3", "1.1.4"]

    def test_single_address(self, fake_xknx):
        s = make_scanner({})
        assert s._parse_device_range("1.1.9") == ["1.1.9"]

    def test_invalid_range_aborts_to_empty(self, fake_xknx):
        from oida.protocols.knx.scanner import _xknx_cls

        # IndividualAddress that raises -> abort and return [] rather than
        # silently scanning a hardcoded 255-address fallback.
        _xknx_cls.IndividualAddress = MagicMock(side_effect=ValueError("bad"))
        s = make_scanner({})
        out = s._parse_device_range("garbage-range")
        assert out == []


class TestConnect:
    def test_connect_udp(self, fake_xknx):
        from oida.protocols.knx.scanner import _xknx_cls

        _xknx_cls.ConnectionConfig = MagicMock()
        _xknx_cls.ConnectionType = MagicMock()
        _xknx_cls.XKNX = MagicMock(return_value="XKNX_OBJ")
        s = make_scanner({"tcp": False})
        conn = s.connect()
        assert conn == "XKNX_OBJ"
        assert any("UDP tunneling" in m for m in s.logger.records["display"])

    def test_connect_tcp(self, fake_xknx):
        from oida.protocols.knx.scanner import _xknx_cls

        _xknx_cls.ConnectionConfig = MagicMock()
        _xknx_cls.ConnectionType = MagicMock()
        _xknx_cls.XKNX = MagicMock(return_value="XKNX_TCP")
        s = make_scanner({"tcp": True})
        conn = s.connect()
        assert conn == "XKNX_TCP"
        assert any("TCP tunneling" in m for m in s.logger.records["display"])

    def test_connect_failure_returns_none(self, fake_xknx):
        from oida.protocols.knx.scanner import _xknx_cls

        _xknx_cls.ConnectionConfig = MagicMock(side_effect=RuntimeError("boom"))
        s = make_scanner({})
        assert s.connect() is None
        assert s.logger.records["fail"]


class TestDisconnect:
    def test_disconnect_calls_stop(self, fake_xknx):
        s = make_scanner({})
        conn = make_conn()
        s.disconnect(conn)
        conn.stop.assert_awaited()

    def test_disconnect_none_is_noop(self, fake_xknx):
        s = make_scanner({})
        s.disconnect(None)  # should not raise


class TestDiscoverConnectionFailure:
    def test_start_timeout_returns_error(self, fake_xknx):
        import asyncio

        s = make_scanner({})
        conn = make_conn(start_error=asyncio.TimeoutError())
        res = s.discover(conn)
        assert res["error"] == "Connection timeout"

    def test_start_exception_returns_error(self, fake_xknx):
        s = make_scanner({})
        conn = make_conn(start_error=OSError("refused"))
        res = s.discover(conn)
        assert "refused" in res["error"]

    def test_invalid_individual_address_rejected(self, fake_xknx):
        s = make_scanner({"individual-address": "not-an-address"})
        conn = make_conn()
        res = s.discover(conn)
        assert "error" in res
        # connection never started
        conn.start.assert_not_awaited()


class TestDiscoverActions:
    def test_device_info_action(self, fake_xknx):
        # descriptor read + 12 property reads (all empty) + 2 mem fallbacks
        p2p = FakeP2P(
            [make_response(payload=MagicMock(value=b"\x07\xb0"))]
            + [make_response(data=None)] * 12
            + [make_response(data=None), make_response(data=None)]
        )
        s = make_scanner({"device-info": True, "individual-address": "1.1.5"})
        conn = make_conn(p2p)
        res = s.discover(conn)
        assert "device_info" in res
        assert res["device_info"]["address"] == "1.1.5"
        # security analysis always added on success
        assert "security_analysis" in res

    def test_property_read_action(self, fake_xknx):
        p2p = FakeP2P([make_response(data=b"\xab\xcd")])
        s = make_scanner({"property-read": "0:78", "individual-address": "1.1.5"})
        conn = make_conn(p2p)
        res = s.discover(conn)
        assert res["property_read"]["data"] == "abcd"

    def test_auth_test_single_key(self, fake_xknx):
        # AuthorizeResponse level 0 => valid key
        p2p = FakeP2P([make_response(level=0)])
        s = make_scanner({"auth-test": "DEADBEEF", "individual-address": "1.1.5"})
        conn = make_conn(p2p)
        res = s.discover(conn)
        assert res["auth_brute"]["valid_keys"][0]["key"] == "DEADBEEF"

    def test_key_write_requires_confirm(self, fake_xknx):
        s = make_scanner(
            {"key-write": "FFFFFFFF:0", "individual-address": "1.1.5", "confirm": False}
        )
        conn = make_conn()
        res = s.discover(conn)
        assert res["key_write"]["error"] == "Missing --confirm flag"

    def test_group_write_requires_confirm(self, fake_xknx):
        s = make_scanner({"group-write": "1/2/3:01", "confirm": False})
        conn = make_conn()
        res = s.discover(conn)
        assert res["group_write"]["error"] == "Missing --confirm flag"
        conn.telegrams.put.assert_not_awaited()

    def test_group_write_action(self, fake_xknx):
        s = make_scanner({"group-write": "1/2/3:01", "confirm": True})
        conn = make_conn()
        res = s.discover(conn)
        assert res["group_write"]["success"] is True
        conn.telegrams.put.assert_awaited()

    def test_domain_serial_action_skips_device_sweep(self, fake_xknx):
        p2p = FakeP2P([make_response(payload=MagicMock(domain_address=b"\x01\xa2"))])
        s = make_scanner({"domain-serial": "00010052177F"})
        conn = make_conn(p2p)
        res = s.discover(conn)
        assert res["domain_serial"]["success"] is True
        assert res["domain_serial"]["domain_address"] == "01A2"
        # targeted lookup must skip the 255-address discovery sweep
        assert "devices" not in res

    def test_master_reset_requires_confirm(self, fake_xknx):
        s = make_scanner(
            {"master-reset": "factory", "individual-address": "1.1.5", "confirm": False}
        )
        conn = make_conn()
        res = s.discover(conn)
        assert res["master_reset"]["error"] == "Missing --confirm flag"

    def test_master_reset_action(self, fake_xknx):
        p2p = FakeP2P([make_response(payload=MagicMock(error_code=0, process_time=3))])
        s = make_scanner(
            {"master-reset": "confirmed", "individual-address": "1.1.5", "confirm": True}
        )
        conn = make_conn(p2p)
        res = s.discover(conn)
        assert res["master_reset"]["success"] is True
        assert res["master_reset"]["erase_code"] == 0x01


class TestConfirmSafetyGates:
    """The --confirm gate must actually BLOCK dangerous writes.

    These live at unit level on purpose. The Calimero mock never establishes a
    tunnel connection, so discover() bails out at its "connection_ok" check long
    before any write-handling code runs -- which means an integration test
    against that mock can never reach these gates and passes no matter what the
    gate does (verified by mutation: disabling the gate entirely left the
    integration test green). Driving discover() with a working stub connection
    is what makes the gate reachable, and therefore what makes these real.
    """

    def test_group_write_without_confirm_is_blocked(self, fake_xknx):
        s = make_scanner({"group-write": "1/0/1:01"})
        res = s.discover(make_conn())
        assert res["group_write"]["error"] == "Missing --confirm flag"
        assert res["group_write"].get("success") is not True

    def test_key_write_without_confirm_is_blocked(self, fake_xknx):
        s = make_scanner({"key-write": "FFFFFFFF:0", "individual-address": "1.1.5"})
        res = s.discover(make_conn())
        assert res["key_write"]["error"] == "Missing --confirm flag"
        assert res["key_write"].get("success") is not True

    def test_property_write_without_confirm_is_blocked(self, fake_xknx):
        s = make_scanner({"property-write": "0:19:00", "individual-address": "1.1.5"})
        res = s.discover(make_conn())
        assert res["property_write"]["error"] == "Missing --confirm flag"
        assert res["property_write"].get("success") is not True

    def test_memory_write_without_confirm_is_blocked(self, fake_xknx):
        """memory-write is gated harder than the rest.

        It refuses outright ("BLOCKED: ... brick device") rather than asking for
        --confirm, so assert the property that matters -- the write was refused
        and not performed -- instead of one exact message.
        """
        s = make_scanner({"memory-write": "0x0060:01", "individual-address": "1.1.5"})
        res = s.discover(make_conn())
        err = res["memory_write"]["error"]
        assert "BLOCKED" in err or err == "Missing --confirm flag"
        assert res["memory_write"].get("success") is not True

    def test_group_write_with_confirm_passes_the_gate(self, fake_xknx):
        """With --confirm the gate must NOT be what stops us.

        Guards against a gate that rejects unconditionally, which would make the
        blocked-tests above pass for the wrong reason.
        """
        s = make_scanner({"group-write": "1/0/1:01", "confirm": True})
        res = s.discover(make_conn())
        assert res.get("group_write", {}).get("error") != "Missing --confirm flag"
