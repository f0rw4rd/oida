"""The tunnel branch of cli_runner.knx must not claim success without a tunnel.

``scanner.connect()`` performs no network I/O -- it only builds an ``XKNX``
object -- so ``self.conn`` is truthy for any syntactically valid target. The
tunnel is opened later, by ``knx.start()`` inside ``scanner.discover()``. Before
the gate in ``_execute_scan``, that combination meant a run against a host that
refused tunnelling inherited ``NetworkConnection.run()``'s default
``success=True`` and published ``device_info.connected: true`` right next to an
``error`` in ``scan_results`` (the connection-1 false-positive class; the
passive gateway-discovery branch was already gated, this branch was not).

``_execute_scan`` only touches ``conn``/``scanner``/``results``/``logger``, so
the class is built via ``__new__`` rather than running the network
``proto_flow``.
"""

from unittest.mock import MagicMock

import pytest

from oida.protocols.knx.cli_runner import knx as KnxConn
from tests.unit.knx._harness import SpyLogger


def make_runner(scan_results):
    c = KnxConn.__new__(KnxConn)
    c.logger = SpyLogger()
    c.conn = MagicMock()  # truthy: connect() succeeded at building the object
    c.scanner = MagicMock()
    c.scanner.discover = MagicMock(return_value=scan_results)
    # record_connect_failure() (the GH #59 contract path the tunnel failure
    # now routes through) reads args.timeout and the TCP-probe branch reads
    # args.tcp/args.port; the real flow always has args set.
    c.args = MagicMock(port=3671, tcp=False, timeout=2)
    c.host = "127.0.0.1"
    c.ip = "127.0.0.1"
    c.default_port = 3671
    c.results = {
        "success": True,  # what NetworkConnection.run() defaults to
        "port": 3671,
        "data": {"device_info": {"gateway_ip": "127.0.0.1", "gateway_port": 3671}},
    }
    return c


@pytest.mark.parametrize(
    "scan_results",
    [
        pytest.param({"error": "Tunnel connection could not be established"}, id="tunnel-refused"),
        pytest.param({"error": "Connection timeout"}, id="start-timeout"),
        pytest.param({}, id="empty-result"),
    ],
)
def test_failed_tunnel_is_not_success(scan_results):
    c = make_runner(scan_results)
    c._execute_scan()
    assert c.results["success"] is False
    assert c.results["data"]["device_info"]["connected"] is False
    assert c.results["error"]


def test_failed_tunnel_surfaces_the_underlying_error():
    c = make_runner({"error": "Tunnel connection could not be established"})
    c._execute_scan()
    # The tunnel failure routes through the GH #59 contract: error becomes
    # "connect <cause> (...detail)" with the tunnel reason folded in, not
    # the old bare scanner error string.
    assert c.results["error"].startswith("connect timeout")
    assert "Tunnel connection could not be established" in c.results["error"]


def test_established_tunnel_is_still_success():
    """The control: a real scan must not be downgraded by the gate."""
    c = make_runner({"gateway_info": {"name": "mock"}, "devices": ["1.1.1"]})
    c._execute_scan()
    assert c.results["success"] is True
    assert c.results["data"]["device_info"]["connected"] is True
    assert "error" not in c.results


def test_enum_host_info_does_not_claim_connectivity():
    """device_info must not assert a session before anything is sent."""
    c = KnxConn.__new__(KnxConn)
    c.logger = SpyLogger()
    c.conn = MagicMock()
    c.host = "127.0.0.1"
    c.args = MagicMock(port=3671, tcp=False)
    c.results = {"success": True, "data": {}}
    c.enum_host_info()
    assert "connected" not in c.results["data"]["device_info"]
