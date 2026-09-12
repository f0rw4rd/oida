"""Regression: IKE version string must be identical in BOTH pyshark modes.

``src/oida/pcap/ipsec.py`` built ``ike_version`` as ``f"v{mjver}"``.
``isakmp.mjver`` is an FT_UINT8/BASE_HEX field, which pyshark renders as the
string ``"0x01"``/``"0x02"`` in XML mode -- the mode the listener's own live
path uses (``pyshark_base._live_capture()`` builds a LiveCapture without
``use_ek``) -- and as the native int ``1``/``2`` in EK mode.  So live captures
reported ``ike_version = "v0x01"`` while every fixture-based test (which run
EK-first via conftest) saw the clean ``"v1"`` and never noticed.  The
correctly-written ``isakmp.version`` fallback that handles both renderings was
unreachable dead code because ``mjver`` is present on essentially every
ISAKMP packet.

These tests run the listener over the same fixture in BOTH modes and assert
the two agree, and that the value is the clean ``v1``/``v2`` form.  They skip
honestly when a mode (or pyshark) is unavailable, and state which mode ran.
"""

import asyncio

import pytest

from .conftest import _ek_mode_available, _pcap_path, _skip_unless_pyshark

pytestmark = [pytest.mark.integration]

FIXTURES = [
    ("ipsec/wireshark_isakmp.cap", "v1"),
    ("ipsec/weberblog_ikev1.pcap", "v1"),
    ("ipsec/wireshark_ikev2.pcap", "v2"),
]


def _run_listener(pcap_path, use_ek):
    """Run the IPsec listener over *pcap_path* in the requested mode."""
    import pyshark

    from oida.pcap.ipsec import IPsecPassiveListener

    asyncio.set_event_loop(asyncio.new_event_loop())
    kwargs = {"input_file": str(pcap_path), "display_filter": "isakmp"}
    if use_ek:
        kwargs["use_ek"] = True
    cap = pyshark.FileCapture(**kwargs)
    packets = list(cap)
    try:
        cap.close()
    except Exception:
        pass
    listener = IPsecPassiveListener(interface="lo", timeout=10)
    listener.feed_packets(iter(packets))
    return listener


@pytest.mark.parametrize("subpath,expected_version", FIXTURES)
def test_ike_version_clean_in_xml_mode(subpath, expected_version):
    """XML mode (the live-capture path) must report v1/v2, not v0x01/v0x02."""
    _skip_unless_pyshark()
    pcap = _pcap_path(subpath)
    listener = _run_listener(pcap, use_ek=False)
    versions = {ix.details.get("ike_version") for ix in listener.interactions}
    assert versions, "no interactions produced; fixture or listener broken"
    assert expected_version in versions, (
        f"XML mode did not report {expected_version!r}; saw {sorted(map(str, versions))}. "
        f"This is the exact symptom of the mjver '0x01' hex-string bug."
    )
    assert not any(isinstance(v, str) and v.startswith("v0x") for v in versions), (
        f"hex-string ike_version leaked: {sorted(map(str, versions))}"
    )


@pytest.mark.parametrize("subpath,expected_version", FIXTURES)
def test_ike_version_clean_in_ek_mode(subpath, expected_version):
    """EK mode (file-scan path) must still report v1/v2 after the fix."""
    _skip_unless_pyshark()
    if not _ek_mode_available:
        pytest.skip("pyshark EK-mode fork not installed (this run: XML mode only)")
    pcap = _pcap_path(subpath)
    listener = _run_listener(pcap, use_ek=True)
    versions = {ix.details.get("ike_version") for ix in listener.interactions}
    assert versions, "no interactions produced; fixture or listener broken"
    assert expected_version in versions, f"EK mode saw {sorted(map(str, versions))}"


@pytest.mark.parametrize("subpath,expected_version", FIXTURES)
def test_ike_version_modes_agree(subpath, expected_version):
    """The two pyshark modes must classify IKE version identically."""
    _skip_unless_pyshark()
    if not _ek_mode_available:
        pytest.skip("pyshark EK-mode fork not installed (this run: XML mode only)")
    pcap = _pcap_path(subpath)
    xml = {ix.details.get("ike_version") for ix in _run_listener(pcap, False).interactions}
    ek = {ix.details.get("ike_version") for ix in _run_listener(pcap, True).interactions}
    assert xml == ek, f"XML mode {sorted(map(str, xml))} != EK mode {sorted(map(str, ek))}"


def test_ike_version_in_operation_summary():
    """The operation string must not carry the hex form either."""
    _skip_unless_pyshark()
    pcap = _pcap_path("ipsec/wireshark_isakmp.cap")
    listener = _run_listener(pcap, use_ek=False)
    ops = [ix.operation for ix in listener.interactions if ix.operation]
    assert any("IKE v1" in op for op in ops), f"no 'IKE v1' operation in XML mode; saw {ops[:5]}"
    assert not any("v0x" in op for op in ops), f"hex form leaked into operation: {ops[:5]}"
