"""Regression: ICMP-embedded HART-IP must be detected in BOTH pyshark modes.

``src/oida/pcap/hartip.py`` reached into ``object.__getattribute__(packet.icmp,
"_fields_dict")`` (``should_process_packet`` and ``_process_icmp_embedded``).
``_fields_dict`` only exists on the EK-mode ``EkLayer``; the XML-mode layers
store their fields in ``_all_fields``.  On the XML path the attribute access
raised ``AttributeError``, ``should_process_packet()`` returned False, and the
packet was dropped BEFORE ``process_packet`` could run -- so HART-IP quoted in
an ICMP Port Unreachable produced zero interactions in XML mode (verified
end-to-end: EK mode recorded an "ICMP Error (HART-IP)" interaction with
data_str='Session Init', XML mode recorded nothing at all).

The XML path matters in production: the pcap-file scanner falls back to XML
mode when EK parsing yields zero packets.

Fixture ``hart/iti_hart_ip_icmp_unreachable.pcap`` was crafted for this test
(ICMP type 3/code 3 quoting a UDP datagram to port 5094 carrying a minimal
HART-IP header with message id 0).
"""

import asyncio

import pytest

from .conftest import _ek_mode_available, _pcap_path, _skip_unless_pyshark

pytestmark = [pytest.mark.integration]

FIXTURE = "hart/iti_hart_ip_icmp_unreachable.pcap"


def _run_listener(pcap_path, use_ek):
    """Feed every packet of *pcap_path* to a fresh HART-IP listener."""
    import pyshark

    from oida.pcap.hartip import HARTIPPassiveListener

    asyncio.set_event_loop(asyncio.new_event_loop())
    kwargs = {"input_file": str(pcap_path)}
    if use_ek:
        kwargs["use_ek"] = True
    cap = pyshark.FileCapture(**kwargs)
    packets = list(cap)
    try:
        cap.close()
    except Exception:
        pass
    listener = HARTIPPassiveListener(interface="lo", timeout=10)
    accepted = [listener.should_process_packet(p) for p in packets]
    return listener.feed_packets(iter(packets)), listener, accepted


def test_icmp_embedded_detected_in_xml_mode():
    """XML mode (the live/fallback path) must not drop the packet."""
    _skip_unless_pyshark()
    pcap = _pcap_path(FIXTURE)
    _devices, listener, accepted = _run_listener(pcap, use_ek=False)
    assert any(accepted), "should_process_packet() rejected the ICMP-embedded packet in XML mode"
    assert listener.interactions, (
        "ICMP-embedded HART-IP produced ZERO interactions in XML mode "
        "(the _fields_dict EkLayer-only access bug)"
    )


def test_icmp_embedded_detected_in_ek_mode():
    _skip_unless_pyshark()
    if not _ek_mode_available:
        pytest.skip("pyshark EK-mode fork not installed (this run: XML mode only)")
    pcap = _pcap_path(FIXTURE)
    _devices, listener, _accepted = _run_listener(pcap, use_ek=True)
    assert listener.interactions, "EK mode lost the ICMP-embedded packet (regression)"


def test_modes_agree_on_icmp_embedded():
    _skip_unless_pyshark()
    if not _ek_mode_available:
        pytest.skip("pyshark EK-mode fork not installed (this run: XML mode only)")
    pcap = _pcap_path(FIXTURE)
    _d, xml_l, _a = _run_listener(pcap, use_ek=False)
    _d, ek_l, _a = _run_listener(pcap, use_ek=True)
    assert len(xml_l.interactions) == len(ek_l.interactions) == 1, (
        f"XML={len(xml_l.interactions)} EK={len(ek_l.interactions)} interactions; both must be 1"
    )
    assert xml_l.interactions[0].details.get("icmp_embedded") is True
    assert ek_l.interactions[0].details.get("icmp_embedded") is True
