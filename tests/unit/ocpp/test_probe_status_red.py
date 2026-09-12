"""RED test: _probe_path status-code extraction must not match digits in refused-port numbers."""

import argparse

from oida.protocols.ocpp.scanner import OCPPScanner


def _make_scanner():
    main = argparse.ArgumentParser()
    sub = main.add_subparsers(dest="cmd")
    p = None
    from oida.protocols.ocpp.proto_args import proto_args

    p = proto_args(sub, [])
    ns, _ = p.parse_known_args(["ws://h:9000/CP"])
    d = {"rhost": "h"}
    for key, value in vars(ns).items():
        if value is None:
            continue
        d[key] = value
        h = key.replace("_", "-")
        if h != key:
            d[h] = value
    s = OCPPScanner(d)
    s.timeout = 2
    return s


def test_refused_port_containing_401_not_reported_as_auth():
    """A TCP-refused connection on port 14010 must NOT be 'auth required (401)'.

    The old code matched '401' as a substring of the errno message containing
    the port number 14010, fabricating a reachable auth-protected endpoint.
    """
    import socket as _s

    try:
        with _s.socket() as sk:
            sk.bind(("127.0.0.1", 14010))
        assert True  # port free, refused connect guaranteed
    except OSError:
        pass

    s = _make_scanner()
    result = s._probe_path("ws://127.0.0.1:14010", "/x", "CP1")
    assert result["reachable"] is False, f"refused port reported reachable: {result}"
    assert result["status_code"] in (None, 0), f"refused port got HTTP status: {result}"
