"""Regression tests for FINS (Omron) passive-listener BASE_HEX parse bugs.

Two bugs of the same class as the dnp3 IIN bug: ``omron.icf.dtb`` (request/
response bit) and ``omron.mode_code`` are both FT/BASE_HEX, so in pyshark XML
mode -- which is what the production live-capture path uses, because
``pyshark_base`` builds LiveCapture without ``use_ek`` -- their values render as
``"0x01"`` / ``"0xNN"``.  A bare ``int()`` raised ValueError, the exception was
swallowed, and:

1. every interaction was labelled "request" (responses were mislabelled),
   corrupting the direction label, the client/server role assignment and
   ``get_write_operations()``; and
2. no PLC Run/Program mode-change ever recorded ``details["mode"]``.

The shared ``_run_listener_test`` helper prefers EK mode, so these tests load
in XML mode explicitly.
"""

import collections
import glob
import os

import pytest

from tests.service_gate import require_service

from tests.integration.pcap.conftest import FIXTURE_DIR, _skip_unless_pyshark

pytestmark = [pytest.mark.integration]


def _fins_pcaps():
    paths = sorted(glob.glob(os.path.join(FIXTURE_DIR, "fins", "*.pcap")))
    if not paths:
        require_service("no FINS fixtures present")
    return paths


def _feed_all(use_ek):
    """Run the FINS listener over every FINS fixture in the requested mode."""
    import pyshark

    from oida.pcap.fins import FINSPassiveListener

    listener = FINSPassiveListener(interface="lo", timeout=10)
    for pcap in _fins_pcaps():
        kwargs = {"input_file": str(pcap), "display_filter": "omron"}
        if use_ek:
            kwargs["use_ek"] = True
        cap = pyshark.FileCapture(**kwargs)
        packets = list(cap)
        try:
            cap.close()
        except Exception:
            pass
        listener.feed_packets(iter(packets))
    return listener


def _summarize(listener):
    directions = collections.Counter(ix.direction for ix in listener.interactions)
    modes = sum(1 for ix in listener.interactions if ix.details.get("mode"))
    return directions, modes


class TestFinsBaseHexParsing:
    def test_xml_mode_distinguishes_requests_from_responses(self):
        _skip_unless_pyshark()
        listener = _feed_all(use_ek=False)
        directions, _ = _summarize(listener)
        assert directions.get("response", 0) > 0, (
            "no interaction classified as a response in XML mode -- omron.icf.dtb "
            "(BASE_HEX '0x01') is being parsed base-10 again, so every packet reads "
            "as a request"
        )
        assert directions.get("request", 0) > 0, "expected some requests too"

    def test_xml_mode_decodes_plc_mode_changes(self):
        _skip_unless_pyshark()
        listener = _feed_all(use_ek=False)
        _, modes = _summarize(listener)
        assert modes > 0, (
            "no PLC mode-change detail decoded in XML mode -- omron.mode_code "
            "(BASE_HEX) parse is dead on the live path"
        )

    def test_xml_and_ek_modes_agree(self):
        _skip_unless_pyshark()
        from tests.integration.pcap.conftest import _ek_mode_available

        if not _ek_mode_available:
            require_service("pyshark EK-mode fork not installed")
        xml_dirs, xml_modes = _summarize(_feed_all(use_ek=False))
        ek_dirs, ek_modes = _summarize(_feed_all(use_ek=True))
        assert dict(xml_dirs) == dict(ek_dirs), (
            f"direction classification differs between modes: xml={dict(xml_dirs)} "
            f"ek={dict(ek_dirs)}"
        )
        assert xml_modes == ek_modes, (
            f"mode-change decode differs between modes: xml={xml_modes} ek={ek_modes}"
        )
