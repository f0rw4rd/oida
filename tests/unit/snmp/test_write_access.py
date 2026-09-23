"""
Unit tests for WriteAccessMixin.

Drives the async VACM/SET-probe coroutines directly with a mocked pysnmp
command layer, plus the synchronous _raw_set type-coercion / error mapping.
"""

from __future__ import annotations

import asyncio

from tests.unit.snmp.conftest import FakeVarBind, make_get, make_get_sequence, patch_pysnmp


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# _vacm_check
# ---------------------------------------------------------------------------


class TestVacmCheck:
    def test_no_entries_inconclusive(self, scanner):
        from tests.unit.snmp.conftest import make_walk_error

        scanner.version = "3"
        # walk returns nothing (timeout immediately) for both view walks
        with patch_pysnmp(walk=make_walk_error("timeout")):
            out = run(scanner._vacm_check(None, None, None, None))
        assert out["conclusive"] is False
        assert out["writable"] is False

    def test_all_write_views_empty_conclusive_readonly(self, scanner):
        from oida.protocols.snmp.constants import VACM_OIDS

        write_oid = VACM_OIDS["vacmAccessWriteViewName"].lstrip(".")
        read_oid = VACM_OIDS["vacmAccessReadViewName"].lstrip(".")

        def walk(*args, **kwargs):
            from tests.unit.snmp.conftest import _base_oid_from_args

            base = _base_oid_from_args(args).lstrip(".")

            async def gen():
                if base == write_oid:
                    yield None, None, None, [FakeVarBind(f"{write_oid}.1", "none")]
                elif base == read_oid:
                    yield None, None, None, [FakeVarBind(f"{read_oid}.1", "_all_")]

            return gen()

        with patch_pysnmp(walk=walk):
            out = run(scanner._vacm_check(None, None, None, None))
        assert out["conclusive"] is True
        assert out["writable"] is False
        assert "all write views empty" in out["detail"]

    def test_nonempty_write_view_needs_set_probe(self, scanner):
        from oida.protocols.snmp.constants import VACM_OIDS

        write_oid = VACM_OIDS["vacmAccessWriteViewName"].lstrip(".")

        def walk(*args, **kwargs):
            from tests.unit.snmp.conftest import _base_oid_from_args

            base = _base_oid_from_args(args).lstrip(".")

            async def gen():
                if base == write_oid:
                    yield None, None, None, [FakeVarBind(f"{write_oid}.1", "writeView")]

            return gen()

        with patch_pysnmp(walk=walk):
            out = run(scanner._vacm_check(None, None, None, None))
        assert out["conclusive"] is False
        assert out["write_views"] == ["writeView"]


# ---------------------------------------------------------------------------
# _set_probe -- idempotent write test on sysContact.0
# ---------------------------------------------------------------------------


class TestSetProbe:
    def test_readonly_error_status_is_conclusive(self, scanner):
        from pysnmp.hlapi.asyncio import OctetString

        # GET returns a real OctetString, SET returns readOnly(4).
        get_resp = [(None, 0, [FakeVarBind("contact", "admin@x")])]
        # but we need the var_bind[1] to be a true OctetString for the type guard.
        contact = OctetString("admin@example.com")
        get_seq = make_get_sequence([(None, 0, [_VB("contact", contact)])])
        set_resp = make_get(error_indication=None, error_status=4)

        with patch_pysnmp(get=get_seq, set_=set_resp):
            out = run(scanner._set_probe(None, None, None, None))
        assert out["conclusive"] is True
        assert out["writable"] is False
        assert "readOnly" in out["detail"]
        _ = get_resp

    def test_writable_when_set_succeeds(self, scanner):
        from pysnmp.hlapi.asyncio import OctetString

        contact = OctetString("noc@example.com")
        # GET (initial) -> contact ; SET -> ok ; GET (read-back) -> same value
        get_seq = make_get_sequence(
            [
                (None, 0, [_VB("contact", contact)]),
                (None, 0, [_VB("contact", contact)]),
            ]
        )
        set_ok = make_get(error_indication=None, error_status=0)

        with patch_pysnmp(get=get_seq, set_=set_ok):
            out = run(scanner._set_probe(None, None, None, None))
        assert out["conclusive"] is True
        assert out["writable"] is True

    def test_absent_contact_is_skipped(self, scanner):
        from pysnmp.proto import rfc1905

        sentinel = rfc1905.NoSuchInstance("")
        get_seq = make_get_sequence([(None, 0, [_VB("contact", sentinel)])])
        with patch_pysnmp(get=get_seq, set_=make_get()):
            out = run(scanner._set_probe(None, None, None, None))
        assert out["conclusive"] is False
        assert out["detail"] == "sysContact.0 absent"

    def test_get_error_status_skips(self, scanner):
        get_seq = make_get_sequence([(None, 5, [])])  # genErr on GET
        with patch_pysnmp(get=get_seq, set_=make_get()):
            out = run(scanner._set_probe(None, None, None, None))
        assert out["conclusive"] is False
        assert "GET error" in out["detail"]


class _VB:
    """Var bind whose value is a *real* pysnmp object (for isinstance checks)."""

    def __init__(self, oid, value_obj):
        self._oid = oid
        self._val = value_obj

    def __getitem__(self, idx):
        if idx == 0:
            return _Oid(self._oid)
        if idx == 1:
            return self._val
        raise IndexError


class _Oid:
    def __init__(self, oid):
        self._oid = oid

    def __str__(self):
        return self._oid


# ---------------------------------------------------------------------------
# _get_usm_protocol_maps -- shared protocol table
# ---------------------------------------------------------------------------


class TestUsmProtocolMaps:
    def test_maps_have_expected_keys(self, scanner):
        auth, priv = scanner._get_usm_protocol_maps()
        assert set(auth) == {"MD5", "SHA", "SHA256", "SHA384", "SHA512"}
        assert set(priv) == {"DES", "3DES", "AES128", "AES192", "AES256"}
        # values are distinct pysnmp protocol objects
        assert auth["MD5"] is not auth["SHA"]


# ---------------------------------------------------------------------------
# _raw_set -- type coercion + error mapping (synchronous wrapper)
# ---------------------------------------------------------------------------


class TestRawSet:
    def _conn(self):
        return (None, None, None, None)

    def test_unknown_type_char_rejected(self, scanner):
        out = scanner._raw_set(self._conn(), "1.3.6.1.2.1.1.4.0", "z", "x")
        assert out["success"] is False
        assert "unknown type" in out["error"]
        scanner.logger.fail.assert_called()

    def test_invalid_hex_value_rejected(self, scanner):
        out = scanner._raw_set(self._conn(), "1.3.6.1.2.1.1.4.0", "x", "0xZZ")
        assert out["success"] is False
        assert "invalid value" in out["error"]

    def test_invalid_integer_value_rejected(self, scanner):
        out = scanner._raw_set(self._conn(), "1.3.6.1.2.1.1.4.0", "i", "notanint")
        assert out["success"] is False
        assert "invalid value" in out["error"]

    def test_successful_set(self, scanner):
        from unittest.mock import patch

        with patch(
            "oida.protocols.snmp.mixins.write_access.asyncio.run",
            return_value=(None, 0),
        ):
            out = scanner._raw_set(self._conn(), "1.3.6.1.2.1.1.4.0", "s", "noc@x")
        assert out["success"] is True
        assert out["error"] is None
        scanner.logger.success.assert_called()

    def test_readonly_error_status_mapped(self, scanner):
        from unittest.mock import patch

        with patch(
            "oida.protocols.snmp.mixins.write_access.asyncio.run",
            return_value=(None, 17),  # notWritable
        ):
            out = scanner._raw_set(self._conn(), "1.3.6.1.2.1.1.4.0", "s", "x")
        assert out["success"] is False
        assert out["error"] == "notWritable"

    def test_error_indication_mapped(self, scanner):
        from unittest.mock import patch

        with patch(
            "oida.protocols.snmp.mixins.write_access.asyncio.run",
            return_value=("requestTimedOut", 0),
        ):
            out = scanner._raw_set(self._conn(), "1.3.6.1.2.1.1.4.0", "i", "5")
        assert out["success"] is False
        assert "requestTimedOut" in out["error"]


# ---------------------------------------------------------------------------
# _async_walk_write -- per-OID idempotent SET enumeration
# ---------------------------------------------------------------------------


class TestWalkWrite:
    def test_empty_subtree(self, scanner, monkeypatch):
        async def fake_walk(*a, **k):
            return []

        monkeypatch.setattr(scanner, "_raw_walk", fake_walk)
        out = run(scanner._async_walk_write(None, None, None, None, "1.3.6.1.2.1.1"))
        assert out["total"] == 0
        assert out["writable_count"] == 0

    def test_writable_oid_emits_finding(self, scanner, monkeypatch):
        from pysnmp.hlapi.asyncio import OctetString

        async def fake_walk(*a, **k):
            return [{"oid": "1.3.6.1.2.1.1.4.0"}]

        monkeypatch.setattr(scanner, "_raw_walk", fake_walk)

        contact = OctetString("admin")
        # GET returns the value; SET succeeds.
        import pysnmp.hlapi.asyncio as hl

        async def fake_get(*a, **k):
            return None, 0, 0, [_VB("1.3.6.1.2.1.1.4.0", contact)]

        async def fake_set(*a, **k):
            return None, 0, 0, []

        class _UT:
            @staticmethod
            async def create(*a, **k):
                return object()

        monkeypatch.setattr(hl, "get_cmd", fake_get)
        monkeypatch.setattr(hl, "set_cmd", fake_set)
        monkeypatch.setattr(hl, "SnmpEngine", lambda *a, **k: object())
        monkeypatch.setattr(hl, "UdpTransportTarget", _UT)
        monkeypatch.setattr(hl, "ObjectIdentity", lambda *a, **k: a)
        monkeypatch.setattr(hl, "ObjectType", lambda *a, **k: a)

        out = run(scanner._async_walk_write(None, None, None, None, "1.3.6.1.2.1.1"))
        assert out["total"] == 1
        assert out["writable_count"] == 1
        assert "Writable OIDs found" in scanner.logger.finding_titles
