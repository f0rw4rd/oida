"""
Unit tests for RawQueryMixin.

Covers _make_oid OID classification, the async walk/get parsers, and the
_async_raw_queries dispatcher (list: prefix resolution, unknown list error).
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

from tests.unit.snmp.conftest import FakeVarBind, make_get, make_walk, make_walk_error, patch_pysnmp


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# _make_oid -- numeric vs symbolic classification
# ---------------------------------------------------------------------------


class TestMakeOid:
    def test_numeric_with_leading_dot(self, scanner):
        captured = {}

        def fake_oi(*a, **k):
            captured["args"] = a
            return ("OI", a)

        with patch("pysnmp.hlapi.asyncio.ObjectIdentity", fake_oi):
            scanner._make_oid(".1.3.6.1.2.1.1.1.0")
        assert captured["args"] == (".1.3.6.1.2.1.1.1.0",)

    def test_bare_numeric_no_dot(self, scanner):
        captured = {}

        def fake_oi(*a, **k):
            captured["args"] = a
            return ("OI", a)

        with patch("pysnmp.hlapi.asyncio.ObjectIdentity", fake_oi):
            scanner._make_oid("1.3.6.1.2.1.1.1.0")
        assert captured["args"] == ("1.3.6.1.2.1.1.1.0",)

    def test_symbolic_with_index(self, scanner):
        captured = []

        class FakeOI:
            def __init__(self, *a):
                captured.append(a)

            def addAsn1MibSource(self, src):
                return self

        with patch("pysnmp.hlapi.asyncio.ObjectIdentity", FakeOI):
            scanner._make_oid("IF-MIB::ifDescr.2")
        # MIB, object, index(int)
        assert captured[0] == ("IF-MIB", "ifDescr", 2)

    def test_symbolic_non_integer_index_falls_back(self, scanner):
        captured = []

        class FakeOI:
            def __init__(self, *a):
                captured.append(a)

            def addAsn1MibSource(self, src):
                return self

        with patch("pysnmp.hlapi.asyncio.ObjectIdentity", FakeOI):
            scanner._make_oid("IF-MIB::ifDescr.foo")
        assert captured[0] == ("IF-MIB", "ifDescr")


# ---------------------------------------------------------------------------
# _raw_walk / _raw_get parsing
# ---------------------------------------------------------------------------


class TestRawWalk:
    def test_walk_collects_oid_type_value(self, scanner, monkeypatch):
        monkeypatch.setattr(scanner, "_resolve_oid_name", lambda e, o: "ifDescr")
        walk = make_walk(
            [FakeVarBind("1.3.6.1.2.1.2.2.1.2.1", "eth0", "OctetString")],
            [FakeVarBind("1.3.6.1.2.1.2.2.1.2.2", "eth1", "OctetString")],
        )
        with patch_pysnmp(walk=walk):
            entries = run(scanner._raw_walk(None, None, None, None, ".1.3.6.1.2.1.2.2.1.2"))
        assert len(entries) == 2
        assert entries[0]["oid"] == "1.3.6.1.2.1.2.2.1.2.1"
        assert entries[0]["value"] == "eth0"
        assert entries[0]["type"] == "OctetString"
        assert entries[0]["name"] == "ifDescr"

    def test_walk_breaks_on_error(self, scanner, monkeypatch):
        monkeypatch.setattr(scanner, "_resolve_oid_name", lambda e, o: "")
        with patch_pysnmp(walk=make_walk_error("timeout")):
            entries = run(scanner._raw_walk(None, None, None, None, ".1.3.6"))
        assert entries == []


class TestRawGet:
    def test_get_parses_multiple_oids(self, scanner, monkeypatch):
        monkeypatch.setattr(scanner, "_resolve_oid_name", lambda e, o: "")
        var_binds = [
            FakeVarBind("1.3.6.1.2.1.1.1.0", "Linux", "OctetString"),
            FakeVarBind("1.3.6.1.2.1.1.5.0", "router", "OctetString"),
        ]
        with patch_pysnmp(get=make_get(var_binds=var_binds)):
            out = run(
                scanner._raw_get(None, None, None, None, ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"])
            )
        assert len(out) == 2
        assert out[0]["value"] == "Linux"
        assert out[1]["value"] == "router"

    def test_get_error_indication_returns_empty(self, scanner, monkeypatch):
        monkeypatch.setattr(scanner, "_resolve_oid_name", lambda e, o: "")
        with patch_pysnmp(get=make_get(error_indication="timeout")):
            out = run(scanner._raw_get(None, None, None, None, ["1.3.6"]))
        assert out == []


# ---------------------------------------------------------------------------
# _async_raw_queries -- dispatcher + list resolution
# ---------------------------------------------------------------------------


class TestAsyncRawQueries:
    def test_unknown_walk_list_fails(self, scanner):
        scanner.walk_oid = "list:doesnotexist"
        scanner.get_oids = None
        with patch("oida.utils.export_utils.export_table", MagicMock()):
            out = run(scanner._async_raw_queries(None, None, None, None))
        assert out == {}
        scanner.logger.fail.assert_called()

    def test_single_walk_oid(self, scanner, monkeypatch):
        scanner.walk_oid = ".1.3.6.1.2.1.1"
        scanner.get_oids = None

        async def fake_walk(engine, auth, tr, ctx, oid):
            return [
                {"oid": "1.3.6.1.2.1.1.1.0", "name": "", "type": "OctetString", "value": "Linux"}
            ]

        monkeypatch.setattr(scanner, "_raw_walk", fake_walk)
        with patch("oida.utils.export_utils.export_table", MagicMock()) as et:
            out = run(scanner._async_raw_queries(None, None, None, None))
        assert out["walk"]["oid"] == ".1.3.6.1.2.1.1"
        assert len(out["walk"]["entries"]) == 1
        et.assert_called_once()

    def test_get_oids_dispatch(self, scanner, monkeypatch):
        scanner.walk_oid = None
        scanner.get_oids = "1.3.6.1.2.1.1.1.0, 1.3.6.1.2.1.1.5.0"

        async def fake_get(engine, auth, tr, ctx, oid_list):
            assert oid_list == ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"]
            return [{"oid": o, "name": "", "type": "OctetString", "value": "v"} for o in oid_list]

        monkeypatch.setattr(scanner, "_raw_get", fake_get)
        with patch("oida.utils.export_utils.export_table", MagicMock()):
            out = run(scanner._async_raw_queries(None, None, None, None))
        assert len(out["get"]) == 2

    def test_walk_list_all_resolves(self, scanner, monkeypatch):
        from oida.protocols.snmp.constants import WALK_LISTS

        assert "all" in WALK_LISTS  # guard the fixture assumption
        scanner.walk_oid = "list:all"
        scanner.get_oids = None
        seen = []

        async def fake_walk(engine, auth, tr, ctx, oid):
            seen.append(oid)
            return []

        monkeypatch.setattr(scanner, "_raw_walk", fake_walk)
        with patch("oida.utils.export_utils.export_table", MagicMock()):
            out = run(scanner._async_raw_queries(None, None, None, None))
        assert out["walk"]["oid"] == "list:all"
        # every OID in the 'all' list was walked
        assert len(seen) == len(WALK_LISTS["all"])
