"""Regression tests for BACnet I-Am parsing in discovery.ics.BACnetScanner.

Covers two bugs found in the discovery bug hunt:

1. The I-Am APDU parser matched context-specific tags (0/1/3) while a conformant
   I-Am-Request (ASHRAE 135 clause 21) encodes its parameters with APPLICATION
   tags (12 = object identifier, 2 = unsigned, 9 = enumerated). No branch ever
   fired, so every discovered device came back as instance 0 / vendor 0.
2. The NPDU skip added the hop-count octet directly after DADR instead of after
   SADR, so a routed I-Am carrying both DNET and SNET read SADR[0] as SLEN and
   skipped past the end of the frame, dropping the device entirely.
"""

import threading

import pytest

from oida.protocols.discovery.ics import BACnetScanner

# Conformant I-Am APDU:
#   10       unconfirmed-request PDU
#   00       service choice 0 (i-Am)
#   C4 ...   app tag 12 len 4 -> object id 0x02000003 (device, instance 3)
#   22 01E0  app tag 2  len 2 -> maxAPDULengthAccepted 480
#   91 00    app tag 9  len 1 -> segmentationSupported 0
#   21 4B    app tag 2  len 1 -> vendorID 75
IAM_APDU = bytes.fromhex("1000c4020000032201e09100214b")


def _bvlc(npdu: bytes, apdu: bytes) -> bytes:
    """Wrap an NPDU+APDU in an Original-Broadcast-NPDU BVLC header."""
    total = 4 + len(npdu) + len(apdu)
    return bytes.fromhex("810b") + total.to_bytes(2, "big") + npdu + apdu


def _parse(packet: bytes, ip: str = "10.0.0.5"):
    scanner = BACnetScanner.__new__(BACnetScanner)
    scanner.discovered_devices = {}
    scanner._lock = threading.Lock()
    scanner._parse_i_am_response(packet, ip)
    device = scanner.discovered_devices.get(ip)
    return device.bacnet_data if device else None


def test_iam_application_tags_are_decoded():
    """A plain global-broadcast I-Am yields the real instance/vendor/max-APDU."""
    data = _parse(_bvlc(bytes.fromhex("0100"), IAM_APDU))

    assert data is not None
    assert data["device_instance"] == 3
    assert data["vendor_id"] == 75
    assert data["max_apdu"] == 480


def test_iam_max_apdu_is_not_truncated_to_one_byte():
    """maxAPDULengthAccepted is a 2-octet unsigned; 480 must not become 0x01."""
    data = _parse(_bvlc(bytes.fromhex("0100"), IAM_APDU))

    assert data["max_apdu"] == 480


@pytest.mark.parametrize(
    "npdu_hex,label",
    [
        ("0100", "no routing info"),
        ("0120ffff00fe", "DNET only, hop count present"),
        ("0128ffff0000050121fe", "DNET and SNET, hop count after SADR"),
    ],
)
def test_iam_survives_npdu_routing_fields(npdu_hex, label):
    """Hop count trails SADR, so routed I-Am frames must still parse.

    The DNET+SNET case previously misread SADR[0] (0x21) as SLEN, advanced the
    cursor 33 bytes past the end of the frame and returned without recording the
    device at all.
    """
    data = _parse(_bvlc(bytes.fromhex(npdu_hex), IAM_APDU))

    assert data is not None, f"device dropped for {label}"
    assert data["device_instance"] == 3, label
    assert data["vendor_id"] == 75, label
    assert data["max_apdu"] == 480, label


def test_iam_one_byte_max_apdu_and_two_byte_vendor():
    """The 1st app-tag-2 unsigned is max APDU, the 2nd is vendor id, any width."""
    apdu = bytes.fromhex("1000c4020003e82150910022029a")

    data = _parse(_bvlc(bytes.fromhex("0100"), apdu))

    assert data["device_instance"] == 1000
    assert data["max_apdu"] == 0x50
    assert data["vendor_id"] == 0x029A


def test_iam_context_tagged_fallback_still_works():
    """Non-conformant context-tagged senders keep decoding via the fallback."""
    apdu = bytes.fromhex("10000c020000031a01e03a004b")

    data = _parse(_bvlc(bytes.fromhex("0100"), apdu))

    assert data["device_instance"] == 3
    assert data["max_apdu"] == 480
    assert data["vendor_id"] == 75


def test_iam_object_identifier_instance_mask_is_22_bits():
    """Device instance is the low 22 bits; the object type must be stripped."""
    apdu = bytes.fromhex("1000c4023fffff2201e09100214b")

    data = _parse(_bvlc(bytes.fromhex("0100"), apdu))

    assert data["device_instance"] == 0x3FFFFF


def test_iam_opening_closing_tags_do_not_desync_the_parser():
    """LVT 6/7 are opening/closing tags and carry no content octets."""
    apdu = bytes.fromhex("10002ec4020000032201e09100214b2f")

    data = _parse(_bvlc(bytes.fromhex("0100"), apdu))

    assert data["device_instance"] == 3
    assert data["vendor_id"] == 75


def test_iam_truncated_frame_does_not_raise():
    """A frame cut mid-parameter must be tolerated, not crash the recv loop."""
    apdu = bytes.fromhex("1000c4020000032201")

    assert _parse(_bvlc(bytes.fromhex("0100"), apdu)) is not None
