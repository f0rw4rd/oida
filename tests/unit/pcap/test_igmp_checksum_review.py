"""Regression: IGMP bad-checksum (forgery) detection must actually fire.

``src/oida/pcap/igmp.py`` mapped ``igmp.checksum.status`` as if the dissector
emitted "1=Good, 2=Bad" (the module docstring says exactly that).  Wireshark's
``igmp.checksum.status`` is a standard FT_UINT8 checksum-status field: it
emits **0 for Bad** and **1 for Good**.  The listener treated ``2`` as "Bad",
so a genuinely bad checksum landed in the ``else`` branch and was rendered as
the literal string ``"0"`` -- never ``"Bad"`` -- which made the
``_bad_checksums`` forgery-alert list dead code in every capture.

Empirically confirmed in BOTH pyshark modes with a crafted IGMPv2 report
carrying checksum 0xdead (status 0) and a correct one (status 1):
listener reported statuses {"0"} for the bad packet, {"Good"} for the good
one, and ``_bad_checksums`` stayed empty in both cases.

The mapping tests here drive ``_parse_igmp()`` directly with a fake layer
(no pyshark needed, mode-independent).
"""

import pytest

from oida.pcap.igmp import IGMPPassiveListener


class _Layer:
    """Minimal stand-in for a pyshark igmp layer: attribute access only."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


def _parse(listener, raw_status):
    layer = _Layer(
        type="0x16",
        maddr="239.1.1.1",
        checksum="0xdead",
        checksum_status=raw_status,
        version="2",
    )
    return listener._parse_igmp(layer, "239.1.1.1")


@pytest.mark.parametrize("raw", [0, "0"])
def test_bad_checksum_maps_to_bad(raw):
    """Wireshark emits 0 for a bad checksum; it must read as 'Bad'."""
    listener = IGMPPassiveListener(interface="lo", timeout=1)
    info = _parse(listener, raw)
    assert info is not None
    assert info["checksum_status"] == "Bad", (
        f"raw {raw!r} (Wireshark bad-checksum value) rendered as "
        f"{info['checksum_status']!r} -- the forgery alert can never fire"
    )


@pytest.mark.parametrize("raw", [1, "1"])
def test_good_checksum_maps_to_good(raw):
    listener = IGMPPassiveListener(interface="lo", timeout=1)
    info = _parse(listener, raw)
    assert info["checksum_status"] == "Good"


def test_value_two_is_not_bad():
    """2 is not emitted by tshark for checksum status; it must not read 'Bad'."""
    listener = IGMPPassiveListener(interface="lo", timeout=1)
    info = _parse(listener, 2)
    assert info["checksum_status"] != "Bad"


def test_missing_status_is_unknown():
    listener = IGMPPassiveListener(interface="lo", timeout=1)
    info = _parse(listener, None)
    assert info["checksum_status"] == "?"
