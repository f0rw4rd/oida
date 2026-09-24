"""Regression tests for the reply-expectation policy wiring.

These lock in the pieces of the no-reply recv fast path whose breakage made
the feature silently inactive in live fuzzing (MQTT sat at ~5s/case instead
of ~20ms):

1. The factory must return ResilientTCPConnection for default TCP so the
   reply_expected / reply_wait_cap hooks exist on the live connection (a
   plain boofuzz TCPSocketConnection silently bypasses them).
2. The policy must be attached via boofuzz Target's ``_target_connection``
   attribute (this boofuzz version has no public ``.connection``; attaching
   to a missing attribute made the attach a silent no-op).
3. A preflight-opened session keeps boofuzz's 5.0s constructor defaults in
   the socket; the pre-fuzz hook must re-sync calibrated timeouts onto it.
4. send() must evaluate the policy and arm the recv fast path; recv() must
   take the fast path instead of waiting the full recv timeout.
5. MQTT's reply policy table itself (which packet types wait vs skip).
"""

import socket
import time

import pytest


class _FakeLog:
    def display(self, *a, **k):
        pass

    success = warning = debug = fail = display


class TestFactoryReturnsPolicyCapableConnection:
    def _tcp_config(self):
        from oida.fuzz.core.config import FuzzerConfig, ProtocolType

        config = FuzzerConfig(target_ip="127.0.0.1", target_port=1234)
        config.protocol_type = ProtocolType.TCP
        # CLI default: -R off (the dataclass default True is a pre-CLI value).
        config.reuse_target_connection = False
        return config

    def test_default_tcp_is_resilient_wrapper(self):
        """Default TCP connections carry the reply-policy hooks."""
        from oida.fuzz.core.connections.tcp import (
            RealConnectionFactory,
            ResilientTCPConnection,
        )

        conn = RealConnectionFactory().create_connection(self._tcp_config())
        assert isinstance(conn, ResilientTCPConnection)
        assert hasattr(conn, "reply_expected")
        assert hasattr(conn, "reply_wait_cap")

    def test_default_tcp_not_resilient_without_flag(self):
        """The wrapper is present but auto-reconnect stays opt-in (-R)."""
        from oida.fuzz.core.connections.tcp import RealConnectionFactory

        conn = RealConnectionFactory().create_connection(self._tcp_config())
        assert conn.resilient is False


class TestPolicyAttachThroughTarget:
    def _fake_fuzzer_with_target(self, connection):
        from oida.fuzz.core.base_fuzzer import BaseFuzzer

        class _ConcreteFuzzer(BaseFuzzer):
            def _define_protocol(self):
                pass

        f = _ConcreteFuzzer.__new__(_ConcreteFuzzer)
        f.config = type("C", (), {"recv_timeout": 0.5, "send_timeout": 5.0})()
        f.log = _FakeLog()
        f._session = type(
            "S", (), {"targets": [type("T", (), {"_target_connection": connection})()]}
        )()
        return f

    def _offline_connection(self):
        """A real wrapper instance (no socket opened; boofuzz defers connect)."""
        from oida.fuzz.core.connections.tcp import ResilientTCPConnection

        return ResilientTCPConnection("127.0.0.1", 1)

    def test_attach_uses_target_connection_attribute(self):
        """Policy lands on Target._target_connection (current boofuzz layout)."""
        from oida.fuzz.core.base_fuzzer import BaseFuzzer

        conn = self._offline_connection()

        def policy(data):
            return True

        f = self._fake_fuzzer_with_target(conn)
        f.reply_policy = policy
        BaseFuzzer._attach_reply_policy(f)
        assert conn.reply_expected is policy

    def test_attach_sets_wait_cap(self):
        """reply_wait_cap rides along with the policy."""
        from oida.fuzz.core.base_fuzzer import BaseFuzzer
        from oida.fuzz.protocols.mqtt import MQTTFuzzer

        conn = self._offline_connection()
        f = self._fake_fuzzer_with_target(conn)
        f.reply_policy = MQTTFuzzer._reply_expected_for_payload
        f.reply_wait_cap = 0.15
        BaseFuzzer._attach_reply_policy(f)
        assert conn.reply_expected.__func__ is MQTTFuzzer._reply_expected_for_payload.__func__
        assert conn.reply_wait_cap == pytest.approx(0.15)

    def test_no_policy_is_noop(self):
        """No reply_policy defined -> nothing attached, no error."""
        from oida.fuzz.core.base_fuzzer import BaseFuzzer

        conn = self._offline_connection()
        f = self._fake_fuzzer_with_target(conn)
        assert BaseFuzzer.reply_policy is None
        BaseFuzzer._attach_reply_policy(f)
        assert conn.reply_expected is None


class TestTimeoutResync:
    def test_preflight_opened_session_gets_calibrated_timeouts(self):
        """A connection built pre-calibration is re-synced post-calibration."""
        from oida.fuzz.core.base_fuzzer import BaseFuzzer

        class _Conn:
            _recv_timeout = 5.0
            _send_timeout = 5.0

            def resync_timeouts(self):
                self.resynced = True

        conn = _Conn()

        class _ConcreteFuzzer(BaseFuzzer):
            def _define_protocol(self):
                pass

        f = _ConcreteFuzzer.__new__(_ConcreteFuzzer)
        f.config = type("C", (), {"recv_timeout": 0.5, "send_timeout": None})()
        f.log = _FakeLog()
        f._session = type("S", (), {"targets": [type("T", (), {"_target_connection": conn})()]})()
        BaseFuzzer._resync_connection_timeouts(f)
        assert conn._recv_timeout == pytest.approx(0.5)
        assert conn.resynced is True
        # send_timeout unset -> left alone
        assert conn._send_timeout == pytest.approx(5.0)

    def test_resync_skipped_without_connection(self):
        """No session/targets -> silent no-op."""
        from oida.fuzz.core.base_fuzzer import BaseFuzzer

        class _ConcreteFuzzer(BaseFuzzer):
            def _define_protocol(self):
                pass

        f = _ConcreteFuzzer.__new__(_ConcreteFuzzer)
        f.config = type(
            "C",
            (),
            {
                "recv_timeout": 0.5,
                "send_timeout": None,
                "log_session": False,
                "web_interface": False,
            },
        )()
        f.log = _FakeLog()
        f._session = None
        f.state_machine = None
        # The lazy build now happens inside _data_connection; stub it so the
        # "no targets" path is what's exercised (empty targets -> None).
        f._create_session = lambda: type("S", (), {"targets": []})()
        result = BaseFuzzer._resync_connection_timeouts(f)  # must not raise
        assert result is None
        # No target connection exists, so the resync must have taken the
        # early-return branch instead of touching a (nonexistent) socket.
        assert BaseFuzzer._data_connection(f) is None


class TestLazySessionAttach:
    """Round-2 find: _data_connection must use the lazy session property, so
    _pre_fuzz_hook attaches the policy / resyncs timeouts even when nothing
    built the session beforehand (a plain non-stateful fuzzer with a policy).
    Reading the raw _session attribute silently no-ops both."""

    def test_data_connection_builds_session_lazily(self):
        from oida.fuzz.core.base_fuzzer import BaseFuzzer

        class _ConcreteFuzzer(BaseFuzzer):
            def _define_protocol(self):
                pass

        f = _ConcreteFuzzer.__new__(_ConcreteFuzzer)
        f.config = type(
            "C",
            (),
            {
                "recv_timeout": 0.5,
                "send_timeout": None,
                "log_session": False,
                "web_interface": False,
            },
        )()
        f.log = _FakeLog()
        f._session = None
        f.state_machine = None
        conn = type("C2", (), {"marker": "built"})()

        def _fake_create_session():
            return type(
                "S",
                (),
                {"targets": [type("T", (), {"_target_connection": conn})()]},
            )()

        f._create_session = _fake_create_session
        # Must go through the lazy property (builds via _create_session),
        # not read the raw _session attribute (None -> silent no-op).
        assert BaseFuzzer._data_connection(f) is conn

    def test_attach_policy_works_when_session_not_yet_built(self):
        """End-to-end: hook on a policy-defining plain fuzzer attaches."""
        from oida.fuzz.core.base_fuzzer import BaseFuzzer
        from oida.fuzz.core.connections.tcp import ResilientTCPConnection

        class _ConcreteFuzzer(BaseFuzzer):
            def _define_protocol(self):
                pass

            @classmethod
            def _policy(cls, data):
                return False

            reply_policy = _policy

        f = _ConcreteFuzzer.__new__(_ConcreteFuzzer)
        f.log = _FakeLog()
        f._session = None
        conn = ResilientTCPConnection("127.0.0.1", 1)

        # Bypass the heavy lazy build: hand the property's product directly.
        f._session = type(
            "S",
            (),
            {"targets": [type("T", (), {"_target_connection": conn})()]},
        )()
        f.config = type("C", (), {"recv_timeout": None, "send_timeout": None})()
        BaseFuzzer._attach_reply_policy(f)
        # Bound classmethod vs the plain function: compare the underlying func.
        assert conn.reply_expected.__func__ is _ConcreteFuzzer.__dict__["_policy"].__func__


class TestReplyPolicyFastPath:
    """End-to-end over a real socketpair: policy -> send -> fast recv."""

    @pytest.fixture()
    def pair(self):
        a, b = socket.socketpair()
        yield a, b
        a.close()
        b.close()

    def _conn(self, pair):
        from oida.fuzz.core.connections.tcp import ResilientTCPConnection

        conn = ResilientTCPConnection("127.0.0.1", 1, recv_timeout=0.4)
        conn._sock = pair[0]
        conn._log = _FakeLog()
        # boofuzz's open() applies the constructor timeouts via SO_RCVTIMEO/
        # SO_SNDTIMEO; emulate that for the socketpair (nonblocking default).
        pair[0].settimeout(0.4)
        pair[1].settimeout(0.4)
        return conn

    def test_no_reply_payload_skips_wait(self, pair):
        """Policy says no-reply -> recv returns quickly without data."""
        conn = self._conn(pair)
        conn.reply_expected = lambda data: False
        conn.send(b"\x30\x00")  # PUBLISH QoS0 header: no reply expected

        t0 = time.perf_counter()
        data = conn.recv(1024)
        elapsed = time.perf_counter() - t0
        assert data == b""
        assert elapsed < 0.35  # poll_seconds(0.05) + slack, not 0.4s

    def test_reply_expected_uses_full_wait(self, pair):
        """Policy says reply -> full recv timeout applies (nothing arrives)."""
        conn = self._conn(pair)
        conn.reply_expected = lambda data: True
        conn.send(b"\x10\x00")  # CONNECT: reply expected, none arrives

        t0 = time.perf_counter()
        data = conn.recv(1024)
        elapsed = time.perf_counter() - t0
        assert data == b""
        assert elapsed >= 0.35  # waited (would have returned in ~0.05s if broken)

    def test_reply_wait_cap_bounds_the_wait(self, pair):
        """reply-expected + cap -> bounded wait, not the full recv timeout."""
        conn = self._conn(pair)
        conn.reply_expected = lambda data: True
        conn.reply_wait_cap = 0.12
        conn.send(b"\x10\x00")

        t0 = time.perf_counter()
        data = conn.recv(1024)
        elapsed = time.perf_counter() - t0
        assert data == b""
        assert 0.10 <= elapsed < 0.30  # capped near 0.12, not 0.4

    def test_queued_reply_surfaces_in_fast_path(self, pair):
        """Fast path still returns data the peer already queued."""
        conn = self._conn(pair)
        conn.reply_expected = lambda data: False
        conn.send(b"\x30\x00")
        pair[1].sendall(b"PONG")

        t0 = time.perf_counter()
        data = conn.recv(1024)
        assert data == b"PONG"
        assert time.perf_counter() - t0 < 0.35

    def test_policy_exception_defaults_to_wait(self, pair):
        """A raising policy must not break send; default is to wait."""
        conn = self._conn(pair)

        def boom(_):
            raise RuntimeError("policy bug")

        conn.reply_expected = boom
        conn.send(b"\x30\x00")  # must not raise

        t0 = time.perf_counter()
        data = conn.recv(1024)
        assert data == b""
        assert elapsed_ok(time.perf_counter() - t0, 0.35)  # full wait


def elapsed_ok(elapsed, bound):
    return elapsed >= bound


class TestResyncTimeoutsSocket:
    def test_resync_applies_sockopts_to_live_socket(self):
        """resync_timeouts() rewrites SO_RCVTIMEO/SO_SNDTIMEO on the socket."""
        import struct

        from oida.fuzz.core.connections.tcp import ResilientTCPConnection

        a, b = socket.socketpair()
        try:
            conn = ResilientTCPConnection("127.0.0.1", 1, recv_timeout=5.0)
            conn._sock = a
            conn._log = _FakeLog()
            # Emulate boofuzz open(): 5.0s baked in at construction time.
            a.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 5, 0))
            a.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, struct.pack("ll", 5, 0))
            # Post-calibration update + resync.
            conn._recv_timeout = 0.5
            conn.resync_timeouts()

            got = a.getsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.calcsize("ll"))
            secs, usecs = struct.unpack("ll", got)
            assert secs == 0 and 400000 <= usecs <= 600000  # ~0.5s, not 5s
        finally:
            a.close()
            b.close()

    def test_resync_without_socket_is_noop(self):
        """Unopened connection (no _sock) -> silent no-op."""
        from oida.fuzz.core.connections.tcp import ResilientTCPConnection

        conn = ResilientTCPConnection("127.0.0.1", 1)
        conn._log = _FakeLog()
        # Never opened: _sock is absent/None, so resync_timeouts() must take
        # its early-return branch (no socket to touch, no sockopt calls).
        assert getattr(conn, "_sock", None) is None
        result = conn.resync_timeouts()  # must not raise
        assert result is None
        assert getattr(conn, "_sock", None) is None


class TestMQTTReplyPolicyTable:
    """MQTT's reply-expectation table (packet type -> wait or skip)."""

    @pytest.mark.parametrize(
        "byte0,label,expected",
        [
            (0x10, "CONNECT", True),
            (0x82, "SUBSCRIBE", True),
            (0xA2, "UNSUBSCRIBE", True),
            (0xC0, "PINGREQ", True),
            (0x62, "PUBREL", True),
            (0xF0, "AUTH", True),
            (0x30, "PUBLISH QoS0", False),
            (0x34, "PUBLISH QoS2", True),
            (0x40, "PUBACK", False),
            (0x50, "PUBREC", False),
            (0x70, "PUBCOMP", False),
            (0xE0, "DISCONNECT", False),
        ],
    )
    def test_packet_type_table(self, byte0, label, expected):
        from oida.fuzz.protocols.mqtt import MQTTFuzzer

        assert MQTTFuzzer._reply_expected_for_payload(bytes([byte0])) is expected

    def test_publish_qos1_waits(self):
        from oida.fuzz.protocols.mqtt import MQTTFuzzer

        assert MQTTFuzzer._reply_expected_for_payload(bytes([0x33])) is True  # QoS1

    def test_publish_qos2_waits(self):
        from oida.fuzz.protocols.mqtt import MQTTFuzzer

        assert MQTTFuzzer._reply_expected_for_payload(bytes([0x34])) is True  # QoS2

    def test_empty_payload_waits(self):
        from oida.fuzz.protocols.mqtt import MQTTFuzzer

        assert MQTTFuzzer._reply_expected_for_payload(b"") is True

    def test_mqtt_sets_wait_cap(self):
        from oida.fuzz.protocols.mqtt import MQTTFuzzer

        assert 0 < MQTTFuzzer.reply_wait_cap <= 1.0
