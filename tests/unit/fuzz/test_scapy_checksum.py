"""
Regression tests for ScapyRawConnection transport-checksum handling.

Background:
    The fuzzer's default TCP header carries chksum=0. ScapyRawConnection.send()
    dissects the raw bytes with self.TCP(...), which stores chksum=0 as an
    explicit field value. Scapy only recomputes checksum fields left as None, so
    the literal 0x0000 shipped on the wire. A zero TCP checksum is INVALID for
    IPv4/IPv6 TCP, so mainstream stacks silently drop the segment and the whole
    `oida fuzz tcp` campaign reached the target with zero coverage.

    The fix nulls a *zero* transport checksum so Scapy recomputes it, while
    preserving a deliberately-fuzzed NON-zero checksum as-is.
"""

import struct


from tests.service_gate import require_import

scapy_all = require_import("scapy.all")

from oida.fuzz.core.connections.scapy import ScapyRawConnection  # noqa: E402


def _tcp_header(chksum: int) -> bytes:
    """A minimal 20-byte TCP header (sport=1234, dport=80, SYN) with the
    given checksum field."""
    return struct.pack(
        ">HHIIBBHHH",
        1234,  # sport
        80,  # dport
        1,  # seq
        0,  # ack
        0x50,  # data offset (5 words << 4)
        0x02,  # flags = SYN
        8192,  # window
        chksum,  # checksum
        0,  # urgent pointer
    )


def _tcp_checksum_on_wire(packet) -> int:
    """Extract the TCP checksum from a built IPv4 packet's raw bytes."""
    wire = scapy_all.raw(packet)
    ihl = (wire[0] & 0x0F) * 4  # IPv4 header length in bytes
    return int.from_bytes(wire[ihl + 16 : ihl + 18], "big")


class _CapturingConnection(ScapyRawConnection):
    """ScapyRawConnection that captures the built packet instead of sending it.

    No real socket is ever opened: scapy_send is replaced with a capturing
    stub so send() runs its full packet-build path offline.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.captured = None

    def open(self):  # noqa: D401 - avoid touching the network/routing table
        self._init_scapy()
        self._sock = True
        # Pin a deterministic source IP so raw() never triggers a route lookup.
        self.source_ip = "10.0.0.1"

        # Replace the real sender with a capturing stub.
        def _capture(pkt, *a, **k):
            self.captured = pkt

        self.scapy_send = _capture


def _build_and_capture(header: bytes, host: str = "10.0.0.2"):
    conn = _CapturingConnection(host=host, port=80)
    conn.open()
    conn.send(header)
    conn.close()
    assert conn.captured is not None, "send() did not build/capture a packet"
    return conn.captured


def test_zero_checksum_is_recomputed():
    """A fuzzer TCP header with chksum=0 must ship with a valid, non-zero
    checksum after send() builds the packet."""
    packet = _build_and_capture(_tcp_header(0))
    on_wire = _tcp_checksum_on_wire(packet)
    assert on_wire != 0, "zero TCP checksum shipped as 0x0000 (invalid segment)"

    # It must be the *correct* checksum: re-dissecting a packet and letting
    # Scapy recompute must agree with what shipped.
    rebuilt = scapy_all.IP(scapy_all.raw(packet))
    expected = _tcp_checksum_on_wire(scapy_all.IP(scapy_all.raw(rebuilt)))
    assert on_wire == expected, "recomputed checksum is not spec-valid"


def test_nonzero_checksum_is_preserved():
    """A deliberately-fuzzed NON-zero checksum is a valid fuzz case and must be
    shipped as-is, not clobbered by recomputation."""
    packet = _build_and_capture(_tcp_header(0xDEAD))
    on_wire = _tcp_checksum_on_wire(packet)
    assert on_wire == 0xDEAD, "intentional bogus checksum was overwritten"


def test_fix_transport_checksum_helper():
    """Unit-level guard on the helper: 0 -> None (recompute), non-zero kept."""
    conn = ScapyRawConnection(host="10.0.0.2", port=80)
    conn._init_scapy()

    zero = conn.TCP(_tcp_header(0))
    conn._fix_transport_checksum(zero)
    assert zero.chksum is None

    bogus = conn.TCP(_tcp_header(0xBEEF))
    conn._fix_transport_checksum(bogus)
    assert bogus.chksum == 0xBEEF
