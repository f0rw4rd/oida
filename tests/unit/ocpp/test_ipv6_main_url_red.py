"""Companion fix: __init__ target-URL construction must bracket bare IPv6 hosts,
else the main connect URL "ws://2001:db8::1:9000/CP1" is unparseable and every
scan against a bare IPv6 target fails with an InvalidURI-style error."""

import argparse
import unittest.mock

from oida.protocols.ocpp import ocpp as OcppClass
from websockets.uri import parse_uri


def test_main_target_url_brackets_bare_ipv6():
    inst = object.__new__(OcppClass)
    ns = argparse.Namespace()
    ns.target = "2001:db8::1"
    ns.port = 9000
    ns.charge_point_id = "CP1"
    ns.ws_path = None
    inst.args = ns
    inst.logger = unittest.mock.MagicMock()

    # Run only the URL-resolution block copied from __init__ via the real code:
    # easiest is to call __init__ with stubbed super().__init__.
    with unittest.mock.patch("oida.connection.NetworkConnection.__init__", return_value=None):
        OcppClass.__init__(inst, ns, None, "2001:db8::1")

    parse_uri(inst._target_url)
    assert "[2001:db8::1]" in inst._target_url, inst._target_url
