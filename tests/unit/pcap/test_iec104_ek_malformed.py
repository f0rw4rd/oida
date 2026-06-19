"""Regression test for the IEC104 EK multi-APDU S-frame mislabel bug.

In the EK-array branch of ``process_packet`` the S-frame test was
``if frame_type_vals <= {0x01}``.  For a multi-APDU segment whose sub-PDUs
carry no parseable ``iec60870_104_iec60870_104_type`` field, ``frame_type_vals``
is the empty set and ``set() <= {0x01}`` evaluates True, so the frame was
recorded as an ``S-frame (ACK)`` instead of falling through to the
malformed-APDU handler.

The fix guards the branch with a non-empty check
(``if frame_type_vals and frame_type_vals <= {0x01}``).  This test pins
that behaviour: an EK frame with no parseable type must NOT be recorded as
an S-frame, and must be recorded as a Malformed APDU.
"""

from oida.pcap.passive.iec104 import IEC104PassiveListener


class _FakeLayer:
    """Minimal stand-in for a PyShark EK layer wrapping multiple PDUs.

    ``_fields_dict`` is a *list* (the multi-APDU EK case), and none of the
    sub-dicts carry ``iec60870_104_iec60870_104_type``, so the listener can
    derive no frame type.
    """

    def __init__(self, fields_dict):
        # Stored via object.__setattr__ so attribute access of unrelated
        # fields (e.g. "type") cleanly raises AttributeError -> None default.
        object.__setattr__(self, "_fields_dict", fields_dict)


class _FakePacket:
    def __init__(self, layer):
        self.iec60870_104 = layer


def _make_listener():
    listener = IEC104PassiveListener("test0")
    # Stub the base PyShark helpers so process_packet runs without a real
    # capture. Direction/flow/stream values are arbitrary but well-formed.
    listener.get_ip_info = lambda packet: ("10.0.0.1", "10.0.0.2")
    listener.get_port_info = lambda packet: (50000, 2404)
    listener.get_mac_info = lambda packet: ("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")
    listener.get_flow_id = lambda packet: "flow-1"
    listener.get_stream_id = lambda packet: "stream-1"
    return listener


def test_ek_unparseable_frame_not_recorded_as_s_frame():
    """Empty/unparseable frame_type_vals must not produce an S-frame (ACK)."""
    listener = _make_listener()
    # Two sub-PDUs, neither carrying a parseable type field -> empty set.
    layer = _FakeLayer([{"iec60870_104_iec60870_104_apdulen": "4"}, {"foo": "bar"}])
    packet = _FakePacket(layer)

    listener.process_packet(packet)

    operations = [ix.operation for ix in listener.interactions]
    assert "S-frame (ACK)" not in operations, (
        f"Unparseable EK frame was mislabeled as an S-frame: {operations}"
    )
    assert "Malformed APDU" in operations, (
        f"Unparseable EK frame should fall through to the malformed handler: {operations}"
    )


def test_ek_s_frame_still_recorded():
    """A genuine S-frame (type 0x01) must still be recorded as an ACK."""
    listener = _make_listener()
    layer = _FakeLayer([{"iec60870_104_iec60870_104_type": "0x01"}])
    packet = _FakePacket(layer)

    listener.process_packet(packet)

    operations = [ix.operation for ix in listener.interactions]
    assert "S-frame (ACK)" in operations, (
        f"Genuine S-frame should still be recorded as an ACK: {operations}"
    )
    assert "Malformed APDU" not in operations
