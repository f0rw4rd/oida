"""Regression: MongoDB "data exfiltration" (large result set) detection must fire.

``src/oida/pcap/mongodb.py`` advertised "Data exfiltration indicators (large
result sets)" in its class docstring and had a ``self._alerts`` list plus a
``harvest()`` branch to surface those alerts -- but nothing anywhere appended
to ``_alerts``, so the advertised capability silently never fired and the
``harvest()`` branch was unreachable dead code.

This test uses the repo's own fixture
``tests/fixtures/pcap/mongodb/wireshark_mongodb.pcap`` (localhost traffic, so
it feeds packets directly rather than asserting device counts, which the
loopback filter would zero out), which contains an OP_REPLY carrying 1134
documents (frame 1879) -- an exfiltration-scale result set -- and asserts the
listener raises the alert once and it reaches ``harvest()``.

Mode: the conftest EK-first loader is not used here; the packets are loaded
explicitly in EK mode when the fork is present (falling back to XML).  The
detection sits downstream of ``get_field``/``_parse_int`` and
``mongo.number_returned`` is FT_INT32/BASE_DEC, so both modes render a
decimal int and the logic is mode-independent.
"""

import asyncio

import pytest

from tests.service_gate import require_service

from .conftest import _ek_mode_available, _pcap_path, _skip_unless_pyshark

pytestmark = [pytest.mark.integration]

from oida.pcap.mongodb import LARGE_RESULT_THRESHOLD


def _run_listener(pcap_path, use_ek):
    """Feed every mongo packet in *pcap_path* to a fresh listener."""
    import pyshark

    from oida.pcap.mongodb import MongoDBPassiveListener

    asyncio.set_event_loop(asyncio.new_event_loop())
    kwargs = {"input_file": str(pcap_path), "display_filter": "mongo"}
    if use_ek:
        kwargs["use_ek"] = True
    cap = pyshark.FileCapture(**kwargs)
    packets = list(cap)
    try:
        cap.close()
    except Exception:
        pass
    listener = MongoDBPassiveListener(interface="lo", timeout=10)
    listener.feed_packets(iter(packets))
    return listener


@pytest.fixture()
def listener():
    _skip_unless_pyshark()
    pcap = _pcap_path("mongodb/wireshark_mongodb.pcap")
    return _run_listener(pcap, use_ek=_ek_mode_available)


def test_large_reply_raises_exfil_alert(listener):
    big = [
        ix
        for ix in listener.interactions
        if ix.details.get("number_returned")
        and int(ix.details["number_returned"]) > LARGE_RESULT_THRESHOLD
    ]
    assert big, (
        "fixture no longer contains an OP_REPLY above the threshold; "
        "pick another fixture or lower LARGE_RESULT_THRESHOLD"
    )

    exfil = [a for a in listener._alerts if a.get("category") == "exfiltration_alert"]
    assert exfil, (
        f"a {big[0].details['number_returned']}-doc reply produced no exfiltration alert; "
        f"_alerts={listener._alerts}"
    )
    a = exfil[0]
    assert a["level"] == "warn"
    assert str(big[0].details["number_returned"]) in a["message"]


def test_alert_fires_once_per_pair(listener):
    exfil = [a for a in listener._alerts if a.get("category") == "exfiltration_alert"]
    assert len(exfil) == 1, f"expected a single deduped exfil alert, got {exfil}"


def test_small_replies_do_not_alert(listener):
    normal = [
        ix
        for ix in listener.interactions
        if ix.details.get("number_returned")
        and int(ix.details["number_returned"]) <= LARGE_RESULT_THRESHOLD
    ]
    assert normal, "fixture had no normal-size replies to check against"
    assert not any(
        "1134" in a.get("message", "") and int("1134") <= LARGE_RESULT_THRESHOLD
        for a in listener._alerts
    ), "a below-threshold reply produced an alert"


def test_alerts_reach_harvest(listener):
    result = listener.harvest()
    alerts = result.get("alerts", [])
    assert any(a.get("category") == "exfiltration_alert" for a in alerts), (
        f"exfil alert did not reach harvest(); harvest alerts={alerts}"
    )


def test_xml_mode_agrees(listener):
    """XML mode must raise the same single alert (mode-independence)."""
    _skip_unless_pyshark()
    if not _ek_mode_available:
        require_service("pyshark EK-mode fork absent; the fixture ran in XML mode already")
    pcap = _pcap_path("mongodb/wireshark_mongodb.pcap")
    xml = _run_listener(pcap, use_ek=False)
    exfil = [a for a in xml._alerts if a.get("category") == "exfiltration_alert"]
    assert len(exfil) == 1, f"XML mode exfil alerts: {exfil}"
