"""Regression test for unbounded memory growth in S7comm block-transfer tracking.

``S7commPassiveListener._parse_block_payload`` (reached via ``process_packet``
-> ``_process_block_control`` for Download Block / Upload, func codes 0x1B /
0x1E) appends every decoded segment to ``self._block_transfers[flow_id]
["segments"]`` with no cap on segment count or total retained bytes. The
transfer entry is only ever popped by ``_finalize_block_transfer`` on a
Download Ended / End Upload (0x1C / 0x1F) PDU -- a PDU an attacker can simply
never send. A sustained stream of 0x1B Download-Block PDUs (optionally across
many spoofed flow_ids) therefore grows RSS without bound.

These tests drive the real listener (no pyshark/tshark needed -- a minimal
fake layer object with attribute access is enough for ``get_field``) and
assert that retained segment count/bytes for a single in-flight transfer stay
bounded no matter how many oversized/unterminated Download Block PDUs are fed
in. They also verify a normal, terminated block download is unaffected.
"""

from oida.pcap.s7comm import S7commPassiveListener


class _Layer:
    """Minimal stand-in for a pyshark layer (attribute access only)."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


def _make_listener():
    return S7commPassiveListener(interface="lo", timeout=1)


def _block_payload_hex(size: int, fill: str = "41") -> str:
    """Plain (non-header) block payload of `size` bytes, as a hex string."""
    return fill * size


def test_unbounded_download_block_stream_stays_bounded():
    """A never-terminated flood of Download Block (0x1B) PDUs must not let
    retained segment bytes/count grow without limit."""
    listener = _make_listener()
    flow_id = "flow-attacker-1"
    details: dict = {}

    # 10,000 segments of 4KB each = ~39MB of raw payload if fully retained.
    segment_size = 4096
    num_segments = 10_000
    payload_hex = _block_payload_hex(segment_size)

    for _ in range(num_segments):
        layer = _Layer(resp_data=payload_hex)
        listener._parse_block_payload(layer, "10.0.0.1", "10.0.0.2", 0x1B, flow_id, details)

    transfer = listener._block_transfers[flow_id]
    retained_segments = len(transfer["segments"])
    retained_bytes = sum(len(s) for s in transfer["segments"])

    # Confirms the fix: retained state must be far smaller than what an
    # unbounded implementation would have accumulated (10_000 segments /
    # ~39MB), and bounded by an explicit, documented cap.
    assert retained_segments <= listener.MAX_BLOCK_SEGMENTS
    assert retained_bytes <= listener.MAX_BLOCK_BYTES
    assert retained_segments < num_segments, (
        "all segments were retained -- no cap is being enforced"
    )


def test_unbounded_single_giant_segment_stays_bounded():
    """A single pathologically large Download Block PDU must also be capped
    on retained bytes, not just on segment count."""
    listener = _make_listener()
    flow_id = "flow-attacker-2"
    details: dict = {}

    huge_size = listener.MAX_BLOCK_BYTES + (10 * 1024 * 1024)  # cap + 10MB
    payload_hex = _block_payload_hex(huge_size)

    layer = _Layer(resp_data=payload_hex)
    listener._parse_block_payload(layer, "10.0.0.1", "10.0.0.2", 0x1B, flow_id, details)

    transfer = listener._block_transfers[flow_id]
    retained_bytes = sum(len(s) for s in transfer["segments"])
    assert retained_bytes <= listener.MAX_BLOCK_BYTES


def test_normal_completed_block_transfer_still_harvested():
    """Control: a small, normal, properly-terminated block download must
    still retain all of its segments and be finalized/harvested normally."""
    listener = _make_listener()
    flow_id = "flow-normal-1"
    details: dict = {}

    # First segment carries a valid 36-byte S7 block header (DB block, type
    # 0x0A) followed by some interface/author strings.
    header = bytearray(36)
    header[0:2] = b"\x70\x70"
    header[4] = 0x05  # language: DB
    header[5] = 0x0A  # block type: DB
    header[6:8] = (1).to_bytes(2, "big")  # block number
    header[8:12] = (128).to_bytes(4, "big")  # load memory length
    header[32:36] = (64).to_bytes(4, "big")  # mc7 code length
    footer = b"AUTHOR01" + b"FAMILY01" + b"MYBLOCK1"
    first_segment = bytes(header) + footer

    layer1 = _Layer(resp_data=first_segment.hex())
    listener._parse_block_payload(layer1, "10.0.0.1", "10.0.0.2", 0x1B, flow_id, details)

    second_segment = b"\x00" * 32
    layer2 = _Layer(resp_data=second_segment.hex())
    listener._parse_block_payload(layer2, "10.0.0.1", "10.0.0.2", 0x1B, flow_id, details)

    transfer = listener._block_transfers[flow_id]
    assert len(transfer["segments"]) == 2
    assert transfer.get("truncated") is not True
    assert transfer["block_type"] == "DB"
    assert transfer["block_number"] == 1

    # Finalize (Download Ended, 0x1C) and confirm it lands in the completed
    # harvest table with the expected segment count.
    listener._finalize_block_transfer(flow_id, "10.0.0.1", "10.0.0.2", 0x1C, details)
    assert flow_id not in listener._block_transfers
    assert len(listener._completed_blocks) == 1
    record = listener._completed_blocks[0]
    assert record["segments"] == 2
    assert record["block_type"] == "DB"
    assert record["block_number"] == 1
