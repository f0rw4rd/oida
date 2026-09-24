"""Regression tests for round-2 bug-hunt finds.

1. Burst-recovery loop bound: the immediate post-crash burst must honor the
   verdict-aware effective limit (UNRESPONSIVE episodes get the doubled
   budget) instead of the raw max_recovery_attempts, and abort with the
   verdict-specific message -- not the generic "Recovery failed".
2. Effectiveness counters must cover the EAGAIN-retry recv path and the
   boofuzz-exception reset path (reconnect_and_return_empty_recv), which
   were silently uncounted.
3. CoAP/snmpv1 UDP monitors: a TCP-connect health check against a UDP
   service can never succeed; the fuzzers must use UDP probes
   (CoAPHealthMonitor / SNMPHealthMonitor). Locks in the wiring plus the
   CoAP CON-GET probe bytes.
"""

import socket
import struct

import pytest
from boofuzz.exception import BoofuzzFailure

from oida.fuzz.monitors.base import ProtocolMonitor
from tests.unit.fuzz.test_reply_policy_wiring import _FakeLog


class _VerdictMonitor(ProtocolMonitor):
    """Scripted probe whose result/evidence sequence repeats the last entry."""

    def __init__(self, script, **kwargs):
        kwargs.setdefault("max_recovery_attempts", 0)
        super().__init__("127.0.0.1", 9999, **kwargs)
        self._script = list(script)
        self._idx = 0
        self.corroboration_delay = 0.0
        self.recovery_backoff_base = 0.0
        self.recovery_backoff_cap = 0.0
        self.recovery_probe_timeout = 0.0

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        if self._idx < len(self._script):
            result, evidence = self._script[self._idx]
        else:
            result, evidence = self._script[-1]
        self._idx += 1
        self._set_probe_evidence(evidence)
        return result


class TestBurstRecoveryBudget:
    def test_unresponsive_episode_gets_doubled_budget_in_burst(self):
        """Burst loop must run 2x budget for UNRESPONSIVE, not max+1."""
        m = _VerdictMonitor(
            [(False, "timeout")],
            check_interval=1,
            retry_count=1,
            failure_threshold=1,
            max_recovery_attempts=2,
        )
        m.last_check_time = None
        with pytest.raises(BoofuzzFailure, match="UNRESPONSIVE"):
            m._check_alive(None)
        # Crossing probe + corroboration probe + 4 recovery probes (2x budget).
        assert m._idx == 6

    def test_dead_episode_burst_uses_hard_budget(self):
        """DEAD episode keeps max_recovery_attempts as the burst bound."""
        m = _VerdictMonitor(
            [(False, "refused")],
            check_interval=1,
            retry_count=1,
            failure_threshold=1,
            max_recovery_attempts=2,
        )
        m.last_check_time = None
        with pytest.raises(BoofuzzFailure, match="DEAD"):
            m._check_alive(None)
        # Crossing probe + 2 recovery probes (hard budget, no corroboration).
        assert m._idx == 3


class TestEffectivenessEdgePaths:
    """Counters on the paths found uncounted in round 2."""

    def _conn(self, sock):
        from oida.fuzz.core.connections.tcp import ResilientTCPConnection

        conn = ResilientTCPConnection("127.0.0.1", 1, recv_timeout=0.3)
        conn._sock = sock
        conn._log = _FakeLog()
        return conn

    def test_resilient_reset_via_boofuzz_exception_counted(self):
        """A RST surfacing as BoofuzzTargetConnectionReset counts as a reset."""
        from boofuzz.exception import BoofuzzTargetConnectionReset

        a, b = socket.socketpair()
        try:
            conn = self._conn(a)
            conn.set_resilient(True)
            a.settimeout(0.3)
            b.settimeout(0.3)
            conn._reconnect = lambda **kw: True  # reconnect "succeeds"
            before = conn.effectiveness["resets"]
            try:
                conn._reconnect_and_return_empty_recv(errno_reset(), "Connection reset")
            except BoofuzzTargetConnectionReset:
                pass
            assert conn.effectiveness["resets"] == before + 1
        finally:
            a.close()
            b.close()

    def test_eagain_retry_recv_counts_reply(self):
        """A reply landing on the EAGAIN-retry path still counts."""

        a, b = socket.socketpair()
        try:
            conn = self._conn(a)
            conn.reply_expected = lambda d: True
            a.settimeout(0.3)
            b.settimeout(0.3)
            # Peer sends after a short delay: first recv raises EAGAIN only in
            # nonblocking mode; emulate with an empty first poll via delayed send.
            import threading

            threading.Timer(0.15, lambda: b.sendall(b"ACK")).start()
            data = conn._eagain_retry_recv(1024, eagain_type="builtin")
            assert data == b"ACK"
            assert conn.effectiveness["replies"] == 1
        finally:
            a.close()
            b.close()

    def test_eagain_exhausted_reconnect_counts_timeout(self):
        """EAGAIN retries exhausted -> reconnect -> b"" scored as silence."""

        a, b = socket.socketpair()
        try:
            conn = self._conn(a)
            conn.reply_expected = lambda d: True
            a.settimeout(0.05)
            b.settimeout(0.05)
            conn._reconnect = lambda **kw: True
            data = conn._eagain_retry_recv(1024, eagain_type="builtin")
            assert data == b""
            assert conn.effectiveness["timeouts"] == 1
        finally:
            a.close()
            b.close()


def errno_reset():
    import errno

    return errno.ECONNRESET


class TestCoAPMonitor:
    def test_con_get_probe_bytes(self):
        """The probe is a well-formed CON GET: ver=1, CON, TKL=0, code 0.01."""
        from oida.fuzz.monitors.network import CoAPHealthMonitor

        pkt = CoAPHealthMonitor._build_con_get(0xABCD)
        assert len(pkt) == 4
        ver_type_tkl, code, mid = struct.unpack(">BBH", pkt)
        assert ver_type_tkl >> 6 == 1  # version 1
        assert (ver_type_tkl >> 4) & 0x3 == 0  # CON
        assert ver_type_tkl & 0xF == 0  # no token
        assert code == 0x01  # GET
        assert mid == 0xABCD

    def test_coap_fuzzer_uses_udp_monitor(self):
        """CoAPFuzzer wires CoAPHealthMonitor, not the TCP SocketHealthMonitor."""
        from oida.fuzz.protocols.coap import CoAPFuzzer
        from oida.fuzz.monitors import CoAPHealthMonitor

        cfg_mod = __import__("oida.fuzz.core.config", fromlist=["FuzzerConfig", "ProtocolType"])
        config = cfg_mod.FuzzerConfig(target_ip="127.0.0.1", target_port=5683)
        f = CoAPFuzzer.__new__(CoAPFuzzer)
        f.config = config
        monitors = CoAPFuzzer.setup_custom_monitors(f)
        assert any(isinstance(m, CoAPHealthMonitor) for m in monitors)
        assert not any(type(m).__name__ == "SocketHealthMonitor" for m in monitors)

    def test_snmpv1_fuzzer_uses_udp_monitor(self):
        """SNMPv1 wires SNMPHealthMonitor, not the TCP SocketHealthMonitor."""
        from oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer
        from oida.fuzz.monitors import SNMPHealthMonitor

        cfg_mod = __import__("oida.fuzz.core.config", fromlist=["FuzzerConfig"])
        config = cfg_mod.FuzzerConfig(target_ip="127.0.0.1", target_port=161)
        f = SNMPv1Fuzzer.__new__(SNMPv1Fuzzer)
        f.config = config
        monitors = SNMPv1Fuzzer.setup_custom_monitors(f)
        assert any(isinstance(m, SNMPHealthMonitor) for m in monitors)

    def test_probe_evidence_set_by_coap_monitor_paths(self):
        """CoAP monitor classifies its failure modes for the verdict split."""
        from oida.fuzz.monitors.network import CoAPHealthMonitor

        m = CoAPHealthMonitor("127.0.0.1", 1, timeout=0.2)
        # Port 1 with a connected UDP socket: no listener -> ICMP unreachable
        # on recv (Linux), or timeout elsewhere. Either way evidence is set.
        ok = m._check_alive_once()
        assert m._probe_evidence in ("refused", "timeout", "unknown")
        assert isinstance(ok, bool)


class TestSNTuning:
    """SNMP monitor still healthy after the network.py surgery."""

    def test_snmp_get_probe_bytes(self):
        from oida.fuzz.monitors.network import SNMPHealthMonitor

        m = SNMPHealthMonitor("127.0.0.1", 161, community="public", version=1)
        pkt = m._build_get()
        assert pkt.startswith(b"\x30")  # SEQUENCE
        assert b"public" in pkt
        assert b"\x2b\x06\x01\x02\x01\x01\x01\x00" in pkt  # sysDescr.0


class TestEffectivenessResumeMerge:
    """Round-2 find: a --resume run must MERGE into stored effectiveness
    counters, not clobber them, and must not double-count its own periodic
    flushes."""

    def _manager(self, tmp_path):
        from oida.fuzz.core.session.manager import TestCaseManager
        from oida.fuzz.core.database.mock import MockDatabase

        class _Cfg:
            session_filename = str(tmp_path / "s")
            monitor_check_interval = 3

        class _Fuzzer:
            log = _FakeLog()
            config = _Cfg()

        mgr = TestCaseManager.__new__(TestCaseManager)
        mgr.fuzzer = _Fuzzer()
        mgr._log = _FakeLog()
        mgr.read_only = False
        mgr.database = MockDatabase()
        mgr._effectiveness = {}
        mgr._eff_base = None
        return mgr

    def test_resume_merges_instead_of_clobbering(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            from pathlib import Path

            mgr = self._manager(Path(td))
            # Earlier session already stored counters for two nodes.
            mgr.database.store_metadata(
                "effectiveness",
                json.dumps({"MQTT_Connect": {"sent": 100, "replies": 90}}),
            )
            # This (resumed) process only saw one node so far.
            mgr._effectiveness = {
                "MQTT_Connect": {"sent": 10, "replies": 2},
                "MQTT_Publish": {"sent": 5},
            }
            mgr._flush_effectiveness()
            stored = json.loads(mgr.database.get_metadata("effectiveness"))
            assert stored["MQTT_Connect"] == {"sent": 110, "replies": 92}
            assert stored["MQTT_Publish"] == {"sent": 5}

    def test_periodic_flushes_do_not_double_count(self):
        """Flush 1, then more traffic, then flush 2 -> additive, not 2x."""
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            from pathlib import Path

            mgr = self._manager(Path(td))
            mgr._effectiveness = {"N": {"sent": 10}}
            mgr._flush_effectiveness()
            mgr._effectiveness["N"]["sent"] += 15
            mgr._flush_effectiveness()
            stored = json.loads(mgr.database.get_metadata("effectiveness"))
            assert stored["N"]["sent"] == 25

    def test_garbage_prior_value_does_not_crash(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            from pathlib import Path

            mgr = self._manager(Path(td))
            mgr.database.store_metadata("effectiveness", "not-json{")
            mgr._effectiveness = {"N": {"sent": 3}}
            mgr._flush_effectiveness()  # must not raise
            stored = json.loads(mgr.database.get_metadata("effectiveness"))
            assert stored["N"]["sent"] == 3
