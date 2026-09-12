"""Regression tests for two confirmed bugs in OPCUAPassiveListener's raw TCP
payload recovery path (``_recover_from_tcp_payload``, opcua.py):

BUG 1 (DoS / unbounded amplification): a single crafted TCP payload made of
many repeated minimal ``MSG`` headers (8 bytes each: message type + chunk
type + declared size) makes the recovery loop record one interaction per
8-byte chunk with no cap. A 64KB payload yields ~8000 interactions from one
packet, and ``self.interactions`` is never bounded.

BUG 2 (off-by-one -> IndexError): the loop's bounds check allows
``offset + msg_size == len(payload_bytes) + 1`` (an off-by-one from a stray
``+ 1``), and downstream service-node-id parsing indexes/slices against the
*declared* ``offset + msg_size`` instead of the *actual* payload length,
so a truncated/lying ``MSG`` message can drive an out-of-bounds read.
"""

from __future__ import annotations

from typing import Dict


from oida.pcap.opcua import OPCUAPassiveListener


class _FakeTcpLayer:
    """Minimal stand-in for a pyshark tcp layer exposing ``_all_fields``."""

    def __init__(self, payload_hex: str):
        self._all_fields: Dict[str, str] = {"tcp.payload": payload_hex}


class _FakePacket:
    def __init__(self, payload_hex: str):
        self.tcp = _FakeTcpLayer(payload_hex)


def _make_listener() -> OPCUAPassiveListener:
    return OPCUAPassiveListener(interface="lo", timeout=1)


def _call_recover(listener: OPCUAPassiveListener, payload_hex: str) -> None:
    packet = _FakePacket(payload_hex)
    listener._recover_from_tcp_payload(
        packet,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        flow_id="flow-1",
        src_port=12345,
        dst_port=4840,
        is_request=True,
        server_port_val=4840,
        client_ip="10.0.0.1",
        server_ip="10.0.0.2",
        client_mac="",
        server_mac="",
    )


# A single minimal, well-formed OPC UA message: type MSG, chunk F, declared
# size 8 (header only, no body) -- the smallest valid recoverable message.
_MINI_MSG = b"MSG" + b"F" + (8).to_bytes(4, "little")


class TestBug1UnboundedRecoveryLoop:
    """A single packet must not be able to produce unbounded interactions."""

    def test_huge_payload_is_capped(self):
        """Repro: ~8000 minimal MSG headers packed into one ~64KB payload.

        Before the fix this records one interaction per 8-byte chunk
        (thousands per packet); after the fix the number of recorded
        interactions for a single call must stay bounded by a sane cap.
        """
        num_chunks = 8192  # 8192 * 8 bytes == 65536 bytes, one "packet"
        payload = _MINI_MSG * num_chunks
        listener = _make_listener()

        _call_recover(listener, payload.hex())

        recorded = len(listener.interactions)
        assert recorded < num_chunks, (
            f"recovery loop recorded {recorded} interactions from a single "
            f"crafted payload of {num_chunks} chunks -- unbounded "
            "amplification (DoS)"
        )
        # Generous upper bound: any sane per-payload cap is well under 1000.
        assert recorded <= 1000, (
            f"recovery loop recorded {recorded} interactions from one "
            "payload; expected a tight, documented cap"
        )


class TestBug2OffByOneIndexError:
    """A lying/truncated declared message size must not over-read the buffer."""

    def test_truncated_msg_does_not_raise(self):
        """Repro from the bug report: an 8-byte MSG header declaring
        msg_size=25 (0x19) followed by only 16 more bytes (24-byte payload
        total) used to raise IndexError while reading the service node id at
        payload_bytes[24].
        """
        header = bytes.fromhex("4d53474619000000")  # "MSG" + "F" + size=25 LE
        assert header[:3] == b"MSG"
        payload = header + b"\x00" * 16  # 24 bytes total; msg_size claims 25
        assert len(payload) == 24

        listener = _make_listener()

        # Must not raise -- a truncated/lying message should be skipped
        # cleanly, not read out of bounds.
        _call_recover(listener, payload.hex())

    def test_well_formed_multi_message_payload_still_recorded(self):
        """Control: a normal, well-formed multi-message payload (legit
        harvesting scenario) must still record one interaction per message.
        """
        listener = _make_listener()
        payload = _MINI_MSG * 3

        _call_recover(listener, payload.hex())

        assert len(listener.interactions) == 3
