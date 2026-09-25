"""Regression test: CANopen SDO read counter (src/oida/pcap/canopen.py).

In ``_process_sdo`` the read tally was
``elif not is_server_tx: node.sdo_reads += 1``. That branch fired for ANY
client (RX, func 0xC) frame that was neither a write (ccs 1/6) nor an abort,
including SDO *Download Segment* frames (ccs=0, part of a write transfer) and
*Upload Segment* requests (ccs=3). A multi-segment SDO write therefore
incremented ``sdo_writes`` once (initiate) and ``sdo_reads`` once per
subsequent download-segment frame -- inflating ``sdo_reads`` and mislabeling
write-transfer segments as reads.

The fix only counts a read on ccs==2 (Upload Initiate). These tests drive
``_process_sdo`` with lightweight fake layers (no pyshark / tshark / pcap).
"""

from oida.pcap.canopen import CANopenPassiveListener

SDO_TX = 0xB  # server -> client (response)
SDO_RX = 0xC  # client -> server (request)


class _Layer:
    """Minimal pyshark-layer stand-in: only the passed fields exist."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


def _make_listener():
    return CANopenPassiveListener(interface="lo", timeout=1)


def _sdo(listener, node_id, func_code, **fields):
    layer = _Layer(**fields)
    listener._process_sdo(
        layer,
        func_code,
        node_id,
        now="2026-06-22T00:00:00",
        src_mac="aa:bb:cc:00:00:01",
        dst_mac="aa:bb:cc:00:00:02",
        flow_id="flow-1",
    )


def test_upload_initiate_counts_as_read():
    listener = _make_listener()
    _sdo(listener, 5, SDO_RX, sdo_ccs="2", sdo_main_idx="0x1000")
    node = listener.canopen_nodes[5]
    assert node.sdo_reads == 1
    assert node.sdo_writes == 0


def test_download_segment_is_not_a_read():
    """ccs=0 (Download Segment) is part of a write transfer, not a read."""
    listener = _make_listener()
    _sdo(listener, 5, SDO_RX, sdo_ccs="0", sdo_main_idx="0x1000")
    node = listener.canopen_nodes[5]
    assert node.sdo_reads == 0
    assert node.sdo_writes == 0


def test_upload_segment_is_not_a_fresh_read():
    """ccs=3 (Upload Segment) is a continuation, not a new read transfer."""
    listener = _make_listener()
    _sdo(listener, 5, SDO_RX, sdo_ccs="3", sdo_main_idx="0x1000")
    node = listener.canopen_nodes[5]
    assert node.sdo_reads == 0


def test_segmented_write_does_not_inflate_reads():
    """Download Initiate (ccs=1) + two Download Segments (ccs=0).

    Pre-fix: sdo_writes==1, sdo_reads==2 (the two segments miscounted).
    Post-fix: sdo_writes==1, sdo_reads==0.
    """
    listener = _make_listener()
    _sdo(listener, 7, SDO_RX, sdo_ccs="1", sdo_main_idx="0x2000")  # initiate write
    _sdo(listener, 7, SDO_RX, sdo_ccs="0", sdo_main_idx="0x2000")  # segment 1
    _sdo(listener, 7, SDO_RX, sdo_ccs="0", sdo_main_idx="0x2000")  # segment 2
    node = listener.canopen_nodes[7]
    assert node.sdo_writes == 1
    assert node.sdo_reads == 0


def test_server_response_never_counts_as_read():
    listener = _make_listener()
    _sdo(listener, 9, SDO_TX, sdo_scs="2", sdo_main_idx="0x1000")
    node = listener.canopen_nodes[9]
    assert node.sdo_reads == 0
    assert node.sdo_writes == 0
