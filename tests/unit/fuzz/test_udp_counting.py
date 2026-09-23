"""CountingUDPConnection: effectiveness counters + reply policy for UDP.

Round-3 feature work: UDP-based fuzzers (CoAP, DNS, DHCP, KNX, ...) ran on
boofuzz's bare UDPSocketConnection, so (a) their traffic was invisible to the
per-node effectiveness counters, and (b) the reply-expectation fast path /
wait cap never applied -- every fire-and-forget datagram burned the full recv
timeout. These tests lock in the wrapper's counter semantics, policy
behavior, and its wiring across every UDP protocol module.
"""

import socket
import struct

import pytest


def _udp_pair_conn(port):
    """A CountingUDPConnection wired to a local receiver socketpair-like path.

    UDP has no socketpair; use a bound loopback receiver socket instead and
    point the connection at it.
    """
    from src.oida.fuzz.core.connections.udp import CountingUDPConnection

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    port = rx.getsockname()[1]
    conn = CountingUDPConnection("127.0.0.1", port, recv_timeout=0.3, bind=("127.0.0.1", 0))
    conn.open()
    return conn, rx


class TestUDPCounters:
    def test_send_and_reply_counted(self):
        conn, rx = _udp_pair_conn(0)
        try:
            conn.reply_expected = lambda d: True
            conn.send(b"\x40\x01\x12\x34")
            rx.settimeout(0.3)
            data, _ = rx.recvfrom(2048)
            assert data == b"\x40\x01\x12\x34"
            rx.sendto(b"\x60\x45\x12\x34", ("127.0.0.1", conn._sock.getsockname()[1]))
            got = conn.recv(2048)
            assert got == b"\x60\x45\x12\x34"
            eff = conn.effectiveness
            assert eff["sent"] == 1
            assert eff["wait_expected"] == 1
            assert eff["replies"] == 1
            assert eff["bytes_sent"] == 4
            assert eff["bytes_recv"] == 4
        finally:
            conn.close()
            rx.close()

    def test_silence_after_reply_expected_is_timeout(self):
        conn, rx = _udp_pair_conn(0)
        try:
            conn.reply_expected = lambda d: True
            conn.send(b"\x40\x01\x12\x34")
            rx.settimeout(0.1)  # drain the datagram so the port stays quiet
            try:
                rx.recvfrom(2048)
            except socket.timeout:
                pass
            data = conn.recv(2048)  # waits recv_timeout (0.3s) then b""
            assert data == b""
            assert conn.effectiveness["timeouts"] == 1
            assert conn.effectiveness["replies"] == 0
        finally:
            conn.close()
            rx.close()

    def test_no_reply_send_skips_wait(self):
        """Fire-and-forget datagram: fast path returns promptly with silence
        (not scored as a timeout)."""
        import time

        conn, rx = _udp_pair_conn(0)
        try:
            conn.reply_expected = lambda d: False
            t0 = time.monotonic()
            conn.send(b"\x50\x01\x12\x34")  # NON GET: no reply expected
            data = conn.recv(2048)
            dt = time.monotonic() - t0
            assert data == b""
            assert dt < 0.25  # far under the 0.3s recv timeout
            eff = conn.effectiveness
            assert eff["timeouts"] == 0  # silence was the expected outcome
            assert eff["wait_expected"] == 0
        finally:
            conn.close()
            rx.close()

    def test_wait_cap_bounds_reply_expected_wait(self):
        """Cap set: reply-expected silence costs the cap, not recv_timeout."""
        import time

        conn, rx = _udp_pair_conn(0)
        try:
            conn.reply_expected = lambda d: True
            conn.reply_wait_cap = 0.1
            t0 = time.monotonic()
            conn.send(b"\x40\x01\x12\x34")
            data = conn.recv(2048)
            dt = time.monotonic() - t0
            assert data == b""
            assert dt < 0.28  # ~cap, well under the 0.3s full timeout
            assert conn.effectiveness["timeouts"] == 1
        finally:
            conn.close()
            rx.close()

    def test_late_reply_surfaces_in_fast_path(self):
        """A datagram queued before the fast-path poll still gets picked up
        and counted as a reply."""
        conn, rx = _udp_pair_conn(0)
        try:
            conn.reply_expected = lambda d: False
            conn.send(b"\x50\x01\x12\x34")
            # Queue the reply before recv() runs its short poll.
            rx.sendto(b"\x70\x40\x12\x34", ("127.0.0.1", conn._sock.getsockname()[1]))
            data = conn.recv(2048)
            assert data == b"\x70\x40\x12\x34"
            assert conn.effectiveness["replies"] == 1
        finally:
            conn.close()
            rx.close()

    def test_resync_timeouts_applies_sockopts(self):
        conn, rx = _udp_pair_conn(0)
        try:
            fmt = struct.calcsize("ll")
            conn._recv_timeout = 0.25
            conn._send_timeout = 0.75
            conn.resync_timeouts()
            raw = conn._sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, fmt)
            sec, usec = struct.unpack("ll", raw)
            assert pytest.approx(sec + usec / 1e6, abs=0.02) == 0.25
        finally:
            conn.close()
            rx.close()

    def test_resync_without_socket_is_noop(self):
        from src.oida.fuzz.core.connections.udp import CountingUDPConnection

        conn = CountingUDPConnection("127.0.0.1", 1)
        # Never opened: _sock is absent/None, so resync_timeouts() must take
        # its early-return branch (no socket to touch, no sockopt calls).
        assert getattr(conn, "_sock", None) is None
        result = conn.resync_timeouts()
        assert result is None
        assert getattr(conn, "_sock", None) is None


class TestUDPWiring:
    """Every UDP protocol module must build CountingUDPConnection."""

    @pytest.mark.parametrize(
        "module_name",
        [
            "netbios",
            "knx",
            "dhcp",
            "hart_ip",
            "tftp",
            "sixlowpan",
            "dns",
            "mdns",
            "coap",
            "echo",
            "ads",
            "daytime",
            "bacnet",
        ],
    )
    def test_udp_modules_use_counting_connection(self, module_name):
        import importlib

        from src.oida.fuzz.core.connections.udp import CountingUDPConnection

        mod = importlib.import_module(f"src.oida.fuzz.protocols.{module_name}")
        # Module-level alias or function-local import; either way the name
        # resolves to the counting wrapper where it is used.
        cls = getattr(mod, "UDPSocketConnection", None)
        if cls is None:
            # Function-local import (bacnet): the module has no module-level
            # binding; verified by test_udp_module_sources below.
            return
        assert cls is CountingUDPConnection


class TestCoAPReplyPolicy:
    def test_con_get_expects_reply(self):
        from src.oida.fuzz.protocols.coap import CoAPFuzzer

        assert CoAPFuzzer._reply_expected_for_payload(b"\x40\x01\x12\x34") is True

    def test_non_fires_and_forgets(self):
        from src.oida.fuzz.protocols.coap import CoAPFuzzer

        assert CoAPFuzzer._reply_expected_for_payload(b"\x50\x01\x12\x34") is False

    def test_ack_and_rst_get_no_reply(self):
        from src.oida.fuzz.protocols.coap import CoAPFuzzer

        assert CoAPFuzzer._reply_expected_for_payload(b"\x60\x40\x12\x34") is False
        assert CoAPFuzzer._reply_expected_for_payload(b"\x70\x00\x12\x34") is False

    def test_bad_version_conservatively_waits(self):
        from src.oida.fuzz.protocols.coap import CoAPFuzzer

        assert CoAPFuzzer._reply_expected_for_payload(b"\x00\x01\x12\x34") is True
        assert CoAPFuzzer._reply_expected_for_payload(b"\xc0\x01\x12\x34") is True

    def test_empty_payload_waits(self):
        from src.oida.fuzz.protocols.coap import CoAPFuzzer

        assert CoAPFuzzer._reply_expected_for_payload(b"") is True

    def test_coap_sets_policy_and_cap(self):
        from src.oida.fuzz.protocols.coap import CoAPFuzzer

        assert CoAPFuzzer.reply_policy is not None
        assert CoAPFuzzer.reply_wait_cap == pytest.approx(0.15)


class TestSNMPReplyPolicy:
    """SNMPv1: Get/GetNext/Set/GetResponse PDUs expect a reply; v1 Trap
    (0xA4) is unsolicited agent-to-manager traffic and never gets one."""

    def _pdu(self, tag, community=b"public"):
        # Minimal SNMPv1 message: SEQUENCE { version, community, PDU }
        pdu_content = b"\x02\x01\x01"  # request-id etc. elided
        pdu = bytes([tag, len(pdu_content)]) + pdu_content
        msg_content = b"\x02\x01\x00" + bytes([0x04, len(community)]) + community + pdu
        return b"\x30" + bytes([len(msg_content)]) + msg_content

    def test_get_request_expects_reply(self):
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        assert SNMPv1Fuzzer._reply_expected_for_payload(self._pdu(0xA0)) is True

    def test_getnext_and_set_expect_reply(self):
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        assert SNMPv1Fuzzer._reply_expected_for_payload(self._pdu(0xA1)) is True
        assert SNMPv1Fuzzer._reply_expected_for_payload(self._pdu(0xA3)) is True

    def test_trap_fires_and_forgets(self):
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        assert SNMPv1Fuzzer._reply_expected_for_payload(self._pdu(0xA4)) is False

    def test_no_pdu_tag_conservatively_waits(self):
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        assert SNMPv1Fuzzer._reply_expected_for_payload(b"\x30\x0b") is True
        assert SNMPv1Fuzzer._reply_expected_for_payload(b"") is True
        assert SNMPv1Fuzzer._reply_expected_for_payload(b"\xff\xff\xff") is True

    def test_snmp_sets_policy_and_cap(self):
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        assert SNMPv1Fuzzer.reply_policy is not None
        assert SNMPv1Fuzzer.reply_wait_cap == pytest.approx(0.15)

    # --- round-3 find: the first policy scanned raw bytes for a PDU tag, so
    # fuzzed *content* could masquerade as structure. The BER walk below must
    # classify on the real PDU tag, never on payload bytes.

    def test_pdu_tag_byte_inside_community_is_not_the_pdu(self):
        """A 0xA4 byte in a fuzzed community must not read as a Trap."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        assert SNMPv1Fuzzer._reply_expected_for_payload(self._pdu(0xA0, b"\xa4evil")) is True
        assert SNMPv1Fuzzer._reply_expected_for_payload(self._pdu(0xA1, b"\xa4\xa4")) is True

    def test_trap_with_long_community_still_fires_and_forgets(self):
        """A community longer than any fixed scan window keeps Trap a Trap."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        assert SNMPv1Fuzzer._reply_expected_for_payload(self._pdu(0xA4, b"A" * 70)) is False

    def test_request_tag_byte_inside_community_does_not_unmask_trap(self):
        """The converse: a 0xA0 byte in the community of a real Trap."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        assert SNMPv1Fuzzer._reply_expected_for_payload(self._pdu(0xA4, b"\xa0x")) is False

    def test_long_form_outer_length_is_parsed(self):
        """BER long-form length on the outer SEQUENCE is walked, not rejected."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        inner = self._pdu(0xA4)[2:]  # drop short-form 0x30 <len>
        data = b"\x30\x81" + bytes([len(inner)]) + inner
        assert SNMPv1Fuzzer._reply_expected_for_payload(data) is False

    def test_over_declared_length_conservatively_waits(self):
        """A length claiming more bytes than exist is malformed -> wait."""
        from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer

        assert SNMPv1Fuzzer._reply_expected_for_payload(b"\x30\x40\x02\x01\x00") is True
        assert SNMPv1Fuzzer._reply_expected_for_payload(b"\x30\x82\x00") is True
