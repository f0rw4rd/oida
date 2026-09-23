"""RED test: ws_brute_force mangles bare IPv6 targets into unparseable ws:// URLs."""

import argparse
from unittest.mock import MagicMock

from oida.protocols.ocpp import ocpp as OcppClass
from websockets.uri import parse_uri


def test_bare_ipv6_target_produces_parseable_probe_url():
    inst = object.__new__(OcppClass)
    ns = argparse.Namespace()
    for k, v in dict(
        target="2001:db8::1",
        port=None,
        charge_point_id="CP1",
        ws_brute=True,
        brute_rate=0,
        verbose=0,
    ).items():
        setattr(ns, k, v)
    inst.args = ns
    inst.ip = "2001:db8::1"
    inst.results = {"data": {}}
    inst.logger = MagicMock()
    inst.scanner = MagicMock()
    captured = {}

    def fake_probe(base_url, path, cp_id):
        captured["url"] = f"{base_url}{path}/{cp_id}"
        return {"reachable": False, "status_code": None, "reason": "no"}

    inst.scanner._probe_path.side_effect = fake_probe
    inst._load_ws_paths = lambda: ["/ocpp"]
    inst._add_finding = lambda *a, **k: None

    inst.ws_brute_force()

    url = captured["url"]
    # The URL handed to websockets must actually parse, or every probe raises
    # InvalidURI and ws_brute silently reports zero endpoints.
    parsed = parse_uri(url)
    # The bare IPv6 literal must be bracketed and preserved verbatim, and the
    # charge-point path must have been appended correctly.
    assert "[2001:db8::1]" in url
    assert parsed.host == "2001:db8::1"
    assert parsed.path == "/ocpp/CP1"
