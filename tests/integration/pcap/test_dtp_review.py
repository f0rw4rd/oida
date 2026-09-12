"""Regression: DTP operating-status and admin-type labels must match tshark.

``src/oida/pcap/dtp.py`` applied the ``DTP_STATUS`` admin-status table
(1=On/2=Off/3=Desirable/4=Auto) to the OPERATING status field ``dtp.tos``.
But ``dtp.tos`` is a different enumeration in Wireshark: only
0x0="Access" and 0x1="Trunk" (``tshark -G values | grep dtp.tos``).
Since DTP_STATUS happens to have key 1 -> "On", a trunking port's operating
status rendered as "On" instead of "Trunk" on the repo's own fixture
(``dtp/wireshark_dtp.pcapng`` frames show ``Trunk Operating Status: Trunk
(0x1)`` in tshark -V). A non-trunking port (0x0) would fall through to the
raw string "0" instead of "Access". This is operator-facing output on a
listener whose purpose is flagging VLAN-hopping trunk exposure.

Also: ``DTP_TYPES`` lacked 0x00 -> "Negotiated" for ``dtp.tat`` (a real
registered value), so an admin type of 0 rendered as raw "0".

Runs against the repo fixture in BOTH pyshark modes (XML is the live-capture
path; the fixture assertions are mode-independent since they sit downstream
of get_field).
"""

import asyncio

import pytest

from tests.service_gate import require_service

from .conftest import _ek_mode_available, _pcap_path, _skip_unless_pyshark

pytestmark = [pytest.mark.integration]


def _run_listener(pcap_path, use_ek):
    import pyshark

    from oida.pcap.dtp import DTPPassiveListener

    asyncio.set_event_loop(asyncio.new_event_loop())
    kwargs = {"input_file": str(pcap_path), "display_filter": "dtp"}
    if use_ek:
        kwargs["use_ek"] = True
    cap = pyshark.FileCapture(**kwargs)
    packets = list(cap)
    try:
        cap.close()
    except Exception:
        pass
    listener = DTPPassiveListener(interface="lo", timeout=10)
    listener.feed_packets(iter(packets))
    return listener


@pytest.fixture()
def listener():
    _skip_unless_pyshark()
    pcap = _pcap_path("dtp/wireshark_dtp.pcapng")
    return _run_listener(pcap, use_ek=_ek_mode_available)


def test_operating_status_says_trunk(listener):
    """Fixture tos=0x1 must render 'Trunk', not the admin-mode 'On'."""
    names = {ix.details.get("oper_status_name") for ix in listener.interactions}
    assert names, "no interactions recorded"
    assert "Trunk" in names, f"operating status rendered as {names}, expected 'Trunk'"


def test_operating_status_table_has_access(listener):
    """0x0 must resolve to 'Access', not fall through to the raw '0'."""
    from oida.pcap.dtp import DTP_OPER_STATUS

    assert DTP_OPER_STATUS.get(0) == "Access"
    assert DTP_OPER_STATUS.get(1) == "Trunk"


def test_admin_status_table_unchanged(listener):
    """tas still uses its own admin enumeration (1=On...)."""
    from oida.pcap.dtp import DTP_STATUS

    assert DTP_STATUS[1] == "On"
    assert DTP_STATUS[3] == "Desirable"


def test_admin_type_negotiated_resolves(listener):
    """DTP_TYPES must cover dtp.tat 0x0 'Negotiated'."""
    from oida.pcap.dtp import DTP_TYPES

    assert DTP_TYPES.get(0) == "Negotiated"


def test_xml_mode_agrees(listener):
    """XML mode (live path) must label the same fixture identically."""
    _skip_unless_pyshark()
    if not _ek_mode_available:
        require_service("pyshark EK-mode fork absent; fixture already ran in XML mode")
    pcap = _pcap_path("dtp/wireshark_dtp.pcapng")
    xml = _run_listener(pcap, use_ek=False)
    names = {ix.details.get("oper_status_name") for ix in xml.interactions}
    assert "Trunk" in names, f"XML mode rendered {names}"
