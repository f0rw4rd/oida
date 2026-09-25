"""Regression test: TLS server certificate direction on non-standard ports.

Server-vs-client classification used ``is_server_cert = src_port in
self._SERVER_PORTS`` alone. TLS services on non-standard ports are extremely
common in ICS/OT (this tool's target). When such a server sends its
Certificate message, ``src_port`` is not in ``_SERVER_PORTS``, so the cert was
recorded as a *client* certificate (``client_cert_used=True``,
``client_cert=cert_info``), the real server cert was never stored, and harvest()
later raised bogus mTLS alerts.

The fix mirrors the direction logic used elsewhere in the module (e.g. the
ServerHello handler and ``_process_certificate_request``): treat the cert as a
server cert when ``src_port in _SERVER_PORTS OR dst_port not in _SERVER_PORTS``,
i.e. only classify as a client cert when ``dst_port`` is a known server port and
``src_port`` is not.

These tests drive ``_process_certificate`` directly with a fake tls layer; no
pyshark / tshark / pcap fixture is required.
"""

from oida.pcap.tls import TLSPassiveListener


_SERVER_IP = "10.0.0.10"
_CLIENT_IP = "10.0.0.5"
_SERVER_MAC = "aa:bb:cc:00:00:02"
_CLIENT_MAC = "aa:bb:cc:00:00:01"

_FAKE_CERT = {
    "thumbprint": "deadbeef",
    "subject": "CN=plc.example.local",
    "issuer": "CN=plant-ca",
}


class _FakeTLSLayer:
    """Minimal stand-in; _process_certificate reads via self.get_field, which
    we stub on the listener, so this object only needs to be truthy."""


def _make_listener():
    listener = TLSPassiveListener(interface="lo", timeout=1)

    # Stub get_field: any "certificate" lookup yields a non-empty value so
    # _process_certificate proceeds past the early return; version lookups
    # return None (no tls_version assertion needed here).
    def fake_get_field(layer, name, default=None):
        if "certificate" in name:
            return "deadbeef"
        return default

    listener.get_field = fake_get_field  # type: ignore[method-assign]
    # _parse_cert wraps _display_cert_info (gated behind --x509); bypass it.
    listener._parse_cert = lambda cert_data: dict(_FAKE_CERT)  # type: ignore[method-assign]
    return listener


def _process(listener, src_ip, dst_ip, src_port, dst_port):
    listener._process_certificate(
        _FakeTLSLayer(),
        packet=None,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        src_mac=_SERVER_MAC if src_ip == _SERVER_IP else _CLIENT_MAC,
        dst_mac=_CLIENT_MAC if dst_ip == _CLIENT_IP else _SERVER_MAC,
    )


def test_server_cert_on_nonstandard_port_classified_as_server():
    """Server on a non-standard port (44818) sends its Certificate. Before the
    fix this was recorded as a *client* cert with the server cert dropped."""
    listener = _make_listener()
    server_port = 44818  # EtherNet/IP-over-TLS-ish; NOT in _SERVER_PORTS
    assert server_port not in TLSPassiveListener._SERVER_PORTS

    # Server -> client: src is the server, src_port is the non-standard listen
    # port; dst is the client on an ephemeral port (also not a server port).
    _process(listener, _SERVER_IP, _CLIENT_IP, server_port, 51000)

    conn_key = (_CLIENT_IP, _SERVER_IP, server_port)
    assert conn_key in listener._connections
    conn = listener._connections[conn_key]
    assert conn["server_cert"] == _FAKE_CERT
    assert conn["client_cert_used"] is False
    assert conn.get("client_cert") is None
    # Server cert stored in the global certificate table by thumbprint.
    assert listener.certificates.get("deadbeef") == _FAKE_CERT


def test_client_cert_still_classified_as_client():
    """A genuine client cert (client ephemeral src -> known server port dst)
    must still be recorded as a client cert, not regressed into a server cert."""
    listener = _make_listener()

    # Client -> server on standard 443: dst_port IS a server port, src is not.
    _process(listener, _CLIENT_IP, _SERVER_IP, 50000, 443)

    conn_key = (_CLIENT_IP, _SERVER_IP, 443)
    assert conn_key in listener._connections
    conn = listener._connections[conn_key]
    assert conn["client_cert_used"] is True
    assert conn["client_cert"] == _FAKE_CERT
    assert conn["server_cert"] is None
    # Client cert must NOT pollute the server certificate table.
    assert "deadbeef" not in listener.certificates


def test_server_cert_on_standard_port_still_classified_as_server():
    """Sanity: the standard-port server-cert path is unchanged."""
    listener = _make_listener()

    _process(listener, _SERVER_IP, _CLIENT_IP, 443, 50000)

    conn = listener._connections[(_CLIENT_IP, _SERVER_IP, 443)]
    assert conn["server_cert"] == _FAKE_CERT
    assert conn["client_cert_used"] is False
