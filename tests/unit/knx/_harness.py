"""Shared fixtures/harness for KNX mixin unit tests.

The KNX scanner is built by mixing five behaviour mixins
(``DiscoveryMixin``, ``DeviceInfoMixin``, ``PropertiesMixin``,
``MemoryMixin``, ``SecurityMixin``) onto a ``NetworkScanner`` base.  The
mixin methods themselves only use a handful of host attributes
(``self.logger``, ``self.args``, ``self.read_only``, ``self.debug``,
``self.discovery_timeout``, ``self.get_target_info`` and a couple of
report helpers) plus the lazily-populated ``_xknx_cls`` namespace.

These fixtures provide:

* a ``SpyLogger`` that records every NXC-style log call so tests can
  assert on emitted security findings / display lines,
* a lightweight ``KnxHost`` that mixes in the real mixins without
  dragging in the whole ``NetworkScanner`` machinery,
* helpers to build an ``AsyncMock`` xknx management connection whose
  ``p2p.request`` returns a queue of canned responses, and
* ``patch_xknx_cls`` to install fake ``_xknx_cls`` request/response
  classes so the mixins can run with no real xknx behaviour.

xknx itself is importable in this environment, so the mixins are imported
normally (unlike ``test_helpers.py`` which loads helpers in isolation).
"""

from __future__ import annotations

from typing import Any, List
from unittest.mock import AsyncMock, MagicMock

from oida.protocols.knx.mixins.discovery import DiscoveryMixin
from oida.protocols.knx.mixins.device_info import DeviceInfoMixin
from oida.protocols.knx.mixins.properties import PropertiesMixin
from oida.protocols.knx.mixins.memory import MemoryMixin
from oida.protocols.knx.mixins.security import SecurityMixin


class SpyLogger:
    """Records every NXC-style log call for later assertions."""

    def __init__(self):
        self.records: dict[str, list] = {
            "debug": [],
            "display": [],
            "success": [],
            "warning": [],
            "fail": [],
            "security_finding": [],
        }

    def debug(self, msg, *a, **k):
        self.records["debug"].append(msg)

    def display(self, msg, *a, **k):
        self.records["display"].append(msg)

    def success(self, msg, *a, **k):
        self.records["success"].append(msg)

    def warning(self, msg, *a, **k):
        self.records["warning"].append(msg)

    def fail(self, msg, *a, **k):
        self.records["fail"].append(msg)

    def security_finding(self, title, detail=None, **k):
        self.records["security_finding"].append((title, detail))

    # convenience accessors -------------------------------------------------
    def all_text(self) -> str:
        """Flatten every logged message into one searchable blob."""
        out = []
        for key, items in self.records.items():
            for it in items:
                if key == "security_finding":
                    out.append(f"{it[0]} {it[1]}")
                else:
                    out.append(str(it))
        return "\n".join(out)

    def findings(self):
        return self.records["security_finding"]


class KnxHost(
    DiscoveryMixin,
    DeviceInfoMixin,
    PropertiesMixin,
    MemoryMixin,
    SecurityMixin,
):
    """Minimal host that exposes the mixins under test.

    Provides exactly the attributes the mixin methods reach for, without
    the ``NetworkScanner`` base (which needs a full args object).
    """

    def __init__(self, args=None, logger=None, read_only=True):
        self.args = args if args is not None else {}
        self.logger = logger or SpyLogger()
        self.read_only = read_only
        self.debug = True
        self.discovery_timeout = 1
        self._target = ("10.0.0.5", 3671)
        # capture report_* calls
        self.reported_hosts: list = []
        self.reported_services: list = []
        self.reported_vulns: list = []

    # base-scanner helpers the mixins call -------------------------------
    def get_target_info(self):
        return self._target

    def report_host_info(self, host):
        self.reported_hosts.append(host)

    def report_service_info(self, host, port=None, name=None, proto=None):
        self.reported_services.append((host, port, name, proto))

    def report_vulnerability(self, host, vuln_type, description=None):
        self.reported_vulns.append((host, vuln_type, description))

    def _parse_device_range(self, device_range: str):
        """Simplified range parser sufficient for discovery tests."""
        if "-" not in device_range:
            return [device_range.strip()]
        start, end = device_range.split("-", 1)
        # only the final octet varies in the test ranges we use
        a, b, c0 = start.strip().split(".")
        _, _, c1 = end.strip().split(".")
        return [f"{a}.{b}.{i}" for i in range(int(c0), int(c1) + 1)]


# ---------------------------------------------------------------------------
# response / connection plumbing
# ---------------------------------------------------------------------------


def make_payload(data: bytes = None, **attrs):
    """Build a response.payload-like object with .data and arbitrary attrs."""
    p = MagicMock()
    p.data = data
    for k, v in attrs.items():
        setattr(p, k, v)
    return p


def make_response(payload=None, data: bytes = None, **attrs):
    """Build a response object exposing ``.payload``."""
    resp = MagicMock()
    if payload is None and (data is not None or attrs):
        payload = make_payload(data=data, **attrs)
    resp.payload = payload
    return resp


class FakeP2P:
    """Stand-in for the management connection's per-request object.

    ``request`` returns successive items from ``responses``; an item that
    is an Exception is raised instead of returned (lets tests exercise the
    per-property error branches).
    """

    def __init__(self, responses: List[Any]):
        self._responses = list(responses)
        self.requests: list = []
        self.call_count = 0

    async def request(self, payload, response_cls=None):
        self.requests.append((payload, response_cls))
        self.call_count += 1
        if self._responses:
            item = self._responses.pop(0)
        else:
            item = None
        if isinstance(item, BaseException):
            raise item
        return item


class ScriptedP2P:
    """P2P stand-in that answers based on the *request class name*.

    ``handlers`` maps an xknx request class attribute name (e.g.
    ``"PropertyValueRead"``) to either a fixed response or a callable
    ``(payload) -> response``.  Unmapped requests return ``default``
    (None by default).  Useful for enumerate/dump loops that issue many
    homogeneous requests in an order that is awkward to script positionally.
    """

    def __init__(self, handlers: dict, default=None):
        self.handlers = handlers
        self.default = default
        self.call_count = 0
        self.by_class: dict = {}

    async def request(self, payload, response_cls=None):
        self.call_count += 1
        cls_name = getattr(type(payload), "__name__", "")
        # the fake request constructors are MagicMock instances; recover the
        # intended class name from the side_effect marker if present
        name = getattr(payload, "_req_name", cls_name)
        self.by_class[name] = self.by_class.get(name, 0) + 1
        h = self.handlers.get(name, self.default)
        if callable(h):
            h = h(payload)
        if isinstance(h, BaseException):
            raise h
        return h


def make_mgmt(p2p: FakeP2P = None, *, connection_error: Exception = None):
    """Build a ``knx.management`` whose ``connection(addr)`` is an async ctx mgr.

    When ``connection_error`` is set the context manager raises on enter,
    exercising the outer connection-failure branch.
    """
    p2p = p2p if p2p is not None else FakeP2P([])

    class _Conn:
        async def __aenter__(self_):
            if connection_error is not None:
                raise connection_error
            return p2p

        async def __aexit__(self_, *exc):
            return False

    mgmt = MagicMock()
    mgmt.connection = MagicMock(return_value=_Conn())
    return mgmt


def make_knx(p2p: FakeP2P = None, *, connection_error: Exception = None):
    """Build a fake xknx instance with ``.management`` and ``.telegrams``."""
    knx = MagicMock()
    knx.management = make_mgmt(p2p, connection_error=connection_error)
    knx.telegrams = MagicMock()
    knx.telegrams.put = AsyncMock()
    return knx


def install_fake_xknx_cls(monkeypatch):
    """Install simple fakes for the ``_xknx_cls`` request/response classes.

    Mixins reference ``_xknx_cls.X`` at call time, so patching the shared
    namespace object's attributes is enough.  Returns the namespace so a
    test can override specifics.

    NOTE: we deliberately take the ``_xknx_cls`` object *via the imported
    mixin module* rather than re-importing ``oida.protocols.knx.constants``.
    ``test_helpers.py`` swaps ``sys.modules["oida.protocols.knx.constants"]``
    with an isolated copy and restores a (possibly different) module object
    afterwards, so a fresh ``import constants`` can yield a *different*
    ``_xknx_cls`` than the one the already-imported mixins bound at import
    time.  The mixins all did ``from ..constants import _xknx_cls`` against
    the original object, so reading it back off a mixin module is the
    reliable handle.
    """
    from oida.protocols.knx.mixins import security as _sec_mod

    cls = _sec_mod._xknx_cls

    def _make_ctor(req_name):
        def _ident(*a, **k):  # generic constructor that records its args
            m = MagicMock()
            m.args = a
            m.kwargs = k
            m._req_name = req_name  # lets ScriptedP2P dispatch on request type
            return m

        return _ident

    names = [
        "IndividualAddress",
        "GroupAddress",
        "Telegram",
        "DPTArray",
        "MemoryRead",
        "MemoryWrite",
        "MemoryResponse",
        "UserMemoryRead",
        "UserMemoryResponse",
        "DeviceDescriptorRead",
        "DeviceDescriptorResponse",
        "PropertyValueRead",
        "PropertyValueWrite",
        "PropertyValueResponse",
        "PropertyDescriptionRead",
        "PropertyDescriptionResponse",
        "ADCRead",
        "ADCResponse",
        "GroupValueWrite",
        "GroupValueRead",
        "AuthorizeRequest",
        "AuthorizeResponse",
        "MemoryExtendedRead",
        "MemoryExtendedReadResponse",
        "IndividualAddressSerialRead",
        "IndividualAddressSerialResponse",
    ]
    for n in names:
        monkeypatch.setattr(cls, n, MagicMock(side_effect=_make_ctor(n)), raising=False)

    # dm_restart / nm_individual_address_check are awaited
    monkeypatch.setattr(cls, "dm_restart", AsyncMock(return_value=None), raising=False)
    monkeypatch.setattr(
        cls, "nm_individual_address_check", AsyncMock(return_value=False), raising=False
    )
    return cls
