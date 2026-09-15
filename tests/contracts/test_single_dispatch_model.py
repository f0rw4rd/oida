"""Contract: OIDA has exactly ONE protocol dispatch model.

The architecture refactor collapsed the old two-layer dispatch (a CLI branch on
``issubclass(BaseScanner)`` vs. the Layer-2 ``connection`` path) into a single
model: **every registered protocol's dispatched class is a Layer-2 ``connection``
subclass** that the CLI constructs as ``protocol_class(args, db, host)`` and that
auto-scans via ``proto_flow()`` on construct (``autostart=True``).

These tests fail CI if that invariant regresses, e.g. someone:
  * registers a bare ``*Scanner`` (Layer-1 ``BaseScanner``) as a protocol's
    dispatched class — which the removed ``scan_target`` branch used to special-case
    and which now silently breaks (its ``__init__`` takes ``(args)`` only), or
  * removes the construction/execution split (``autostart`` kwarg + ``run()``) that
    makes a scanner constructible without side effects.

Pure class introspection — no network, no mocks. Mirrors the runtime-introspection
idiom of ``test_reserved_short_flags.py``.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from oida.connection import connection
from oida.loader import ProtocolLoader
from oida.utils.base_scanner import BaseScanner

_PROTOCOLS_DIR = Path(__file__).resolve().parents[2] / "src" / "oida" / "protocols"


def _dispatched_classes() -> dict[str, type]:
    """{protocol_name: the class the CLI/loader dispatches to}."""
    loader = ProtocolLoader(str(_PROTOCOLS_DIR))
    out: dict[str, type] = {}
    for name in sorted(loader.get_protocols()):
        cls = loader.get_protocol_class(name)
        if cls is not None:
            out[name] = cls
    return out


def test_every_protocol_dispatches_to_a_layer2_connection():
    """The single dispatch entrypoint is a ``connection`` subclass — for all of them."""
    dispatched = _dispatched_classes()
    assert dispatched, "no protocols discovered — loader/introspection broke"

    not_connection = {
        name: cls.__name__
        for name, cls in dispatched.items()
        if not (isinstance(cls, type) and issubclass(cls, connection))
    }
    assert not not_connection, (
        "these protocols do not dispatch to a Layer-2 `connection` subclass "
        f"(single-dispatch-model violation): {not_connection}"
    )


def test_no_protocol_dispatches_to_a_bare_basescanner():
    """A bare Layer-1 ``BaseScanner`` at the seam is exactly what the removed
    ``scan_target`` ``issubclass`` branch used to handle. Constructing it as
    ``(args, db, host)`` now fails, so registering one is a latent break."""
    dispatched = _dispatched_classes()
    layer1_only = {
        name: cls.__name__
        for name, cls in dispatched.items()
        if isinstance(cls, type)
        and issubclass(cls, BaseScanner)
        and not issubclass(cls, connection)
    }
    assert not layer1_only, (
        "these protocols dispatch to a bare BaseScanner (Layer-1) — give them a "
        f"Layer-2 `connection` wrapper instead: {layer1_only}"
    )


def test_connection_preserves_construction_execution_split():
    """The God-constructor fix: ``connection`` must keep the ``autostart`` opt-out
    and an explicit ``run()`` so objects are constructible without scanning."""
    sig = inspect.signature(connection.__init__)
    assert "autostart" in sig.parameters, (
        "connection.__init__ lost its `autostart` parameter — construction can no "
        "longer be separated from execution"
    )
    autostart = sig.parameters["autostart"]
    assert autostart.default is True, (
        "connection.__init__ `autostart` must default to True to preserve the "
        f"scan-on-construct CLI contract (got default={autostart.default!r})"
    )
    assert autostart.kind is inspect.Parameter.KEYWORD_ONLY, (
        "`autostart` must be keyword-only so positional (args, db, host) calls in "
        "subclasses and the dispatcher stay unchanged"
    )
    assert callable(getattr(connection, "run", None)), (
        "connection.run() was removed — the scan flow must stay an explicit method, "
        "not a construction side effect"
    )


@pytest.mark.parametrize("proto", ["modbus", "opcua", "snap7", "pcap", "discovery"])
def test_representative_protocols_expose_get_results(proto):
    """The typed envelope boundary: dispatched classes expose ``get_results``."""
    cls = ProtocolLoader(str(_PROTOCOLS_DIR)).get_protocol_class(proto)
    assert cls is not None, f"{proto} did not resolve to a dispatched class"
    assert callable(getattr(cls, "get_results", None)), (
        f"{proto} dispatched class has no get_results() — the result envelope boundary is missing"
    )
