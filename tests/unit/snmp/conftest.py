"""
Shared fixtures and pysnmp test doubles for the SNMP unit suite.

The real pysnmp transport is never available in CI, so every test mocks the
command layer (``walk_cmd`` / ``get_cmd`` / ``set_cmd``) exposed at
``pysnmp.hlapi.asyncio.*``. The mixins import those symbols lazily *inside*
each coroutine (``from pysnmp.hlapi.asyncio import ...``), so patching the
module attribute is sufficient and reaches every caller.
"""

from __future__ import annotations

import contextlib
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# pysnmp value/varbind doubles
# ---------------------------------------------------------------------------


class FakeValue:
    """A pysnmp value proxy: ``prettyPrint()`` + ``__class__.__name__``."""

    def __init__(self, value, type_name: str = "OctetString"):
        self._value = value
        self._type_name = type_name

    def prettyPrint(self):
        return self._value

    @property
    def __class__(self):  # spoof type(var_bind[1]).__name__ used by raw queries
        return type(self._type_name, (), {})


class FakeVarBind:
    """Simulate a pysnmp (ObjectName, value) tuple.

    ``str(var_bind[0])`` yields the OID without a leading dot (pysnmp v7
    behavior); ``var_bind[1].prettyPrint()`` yields the value.
    """

    def __init__(self, oid_str: str, value: str, type_name: str = "OctetString"):
        self._oid = oid_str.lstrip(".")
        self._val = FakeValue(value, type_name)

    def __getitem__(self, idx):
        if idx == 0:
            return _OidProxy(self._oid)
        if idx == 1:
            return self._val
        raise IndexError(idx)


class _OidProxy:
    def __init__(self, oid: str):
        self._oid = oid

    def __str__(self):
        return self._oid


def make_walk(*var_bind_lists):
    """Build an async-generator factory yielding ``(None, None, None, vb)`` rows.

    Each positional arg is a list of FakeVarBind objects forming one PDU's
    var_binds. ``walk_cmd(...)`` returns the async generator.
    """

    async def _gen(*_a, **_k):
        for vb in var_bind_lists:
            yield None, None, None, vb

    return lambda *a, **k: _gen(*a, **k)


def _base_oid_from_args(args):
    """Extract the base OID string from a walk_cmd/get_cmd positional call.

    With ObjectIdentity/ObjectType patched to identity lambdas,
    ``ObjectType(ObjectIdentity(base))`` becomes nested tuples ``((base,),)``.
    The 5th positional arg (index 4) is that ObjectType wrapper.
    """
    ot = args[4]
    # Unwrap nested 1-tuples until we hit the OID string.
    while isinstance(ot, tuple) and ot:
        ot = ot[0]
    return ot


def walk_router(col_data):
    """Return a walk_cmd double routing by base OID to per-column var binds.

    ``col_data`` maps base-OID strings to lists of FakeVarBind objects.
    """

    def walk(*args, **kwargs):
        base = _base_oid_from_args(args)

        async def gen():
            # Each FakeVarBind is yielded as its own single-element PDU so
            # _walk_table iterates var_binds correctly (matching make_walk).
            for vb in col_data.get(base, []):
                yield None, None, None, [vb]

        return gen()

    return walk


def get_router(responses):
    """Return a get_cmd double routing by base OID.

    ``responses`` maps base-OID strings to value strings. A miss returns an
    empty var_binds list (no value).
    """

    async def get(*args, **kwargs):
        base = _base_oid_from_args(args)
        val = responses.get(base)
        if val is None:
            return None, 0, 0, []
        return None, 0, 0, [FakeVarBind(base, val)]

    return get


def make_walk_error(error_indication="timeout"):
    """An async generator that immediately yields an error_indication row."""

    async def _gen(*_a, **_k):
        yield error_indication, None, None, []

    return lambda *a, **k: _gen(*a, **k)


def make_get(error_indication=None, error_status=0, var_binds=None):
    """Build an async ``get_cmd``/``set_cmd`` replacement returning a 4-tuple."""

    async def _get(*_a, **_k):
        return error_indication, error_status, 0, (var_binds or [])

    return _get


def make_get_sequence(responses):
    """Return a ``get_cmd`` double that yields successive 4-tuples per call.

    ``responses`` is a list of (error_indication, error_status, var_binds).
    """
    calls = {"i": 0}

    async def _get(*_a, **_k):
        idx = min(calls["i"], len(responses) - 1)
        calls["i"] += 1
        ei, es, vb = responses[idx]
        return ei, es, 0, vb

    return _get


@contextlib.contextmanager
def patch_pysnmp(walk=None, get=None, set_=None):
    """Patch the pysnmp command + object factory symbols used by the mixins."""
    patches = [
        patch("pysnmp.hlapi.asyncio.ObjectIdentity", lambda *a, **k: a),
        patch("pysnmp.hlapi.asyncio.ObjectType", lambda *a, **k: a),
    ]
    if walk is not None:
        patches.append(patch("pysnmp.hlapi.asyncio.walk_cmd", side_effect=walk))
    if get is not None:
        patches.append(patch("pysnmp.hlapi.asyncio.get_cmd", side_effect=get))
    if set_ is not None:
        patches.append(patch("pysnmp.hlapi.asyncio.set_cmd", side_effect=set_))
    with contextlib.ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        yield


class RecordingLogger(MagicMock):
    """MagicMock logger that also exposes a flat list of finding titles."""

    @property
    def finding_titles(self):
        return [c.args[0] for c in self.security_finding.call_args_list]

    @property
    def finding_details(self):
        out = []
        for c in self.security_finding.call_args_list:
            args = list(c.args)
            out.append(" | ".join(str(a) for a in args))
        return out


@pytest.fixture
def scanner():
    """Minimal SNMPScanner with a recording logger and export disabled."""
    from oida.protocols.snmp.scanner import SNMPScanner

    s = SNMPScanner(
        {
            "host": "10.0.0.5",
            "port": 161,
            "timeout": 1,
            "community": "public",
            "snmp_version": "2c",
        }
    )
    s.logger = RecordingLogger()
    return s


@pytest.fixture(autouse=True)
def _no_export():
    """Neutralize export_table so handlers don't touch the filesystem."""
    with patch("oida.utils.export_utils.export_table", MagicMock()):
        yield
