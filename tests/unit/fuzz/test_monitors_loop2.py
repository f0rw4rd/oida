"""
Regression tests for verified monitor-layer bugs (review loop 2).

M2 -- UDP liveness probes (SNMPHealthMonitor, BACnetMonitor) treated a recv
    timeout as "target alive". For a connectionless probe a timeout is the
    absence of any evidence of life; reporting it as alive makes the monitor
    permanently blind (a dead UDP service that stops answering but no longer
    emits ICMP port-unreachable -- e.g. behind a drop-policy firewall or a
    hung-but-bound process -- is reported healthy forever). The fix returns
    False so base's streak logic consumes it as a failed probe; a single
    timeout still does not flip ``crashed`` (that needs failure_threshold
    consecutive failed rounds).

M3 -- CombinedMonitor returned True (healthy) when it had zero active
    sub-monitors (empty list, or every monitor disabled by graceful
    degradation). An aggregator with no checks has no signal and must not
    assert health. The fix records an explicit "unknown" verdict.

M5 -- ModbusRTUMonitor._validate_rtu_response computed the frame CRC and then
    ignored a mismatch, so a corrupt/garbage frame counted as a valid reply
    (and could be stored as the baseline). The fix rejects bad-CRC frames.

M6 -- Poisoned baselines: _BannerProtocolMonitor stored an empty / non-status
    -code reply as the baseline (``sock.recv`` returning b"" on a closed peer
    is not None, so the "probe failed" guard missed it), and HTTPGetMonitor
    baselined a 5xx server-error response. Later comparisons then compared
    against garbage. The fix only baselines a successful probe.
"""

import socket
from unittest.mock import MagicMock, Mock, patch

import pytest


# ---------------------------------------------------------------------------
# M2: UDP timeout must not mean "alive"
# ---------------------------------------------------------------------------


def _timing_out_udp_socket():
    """MagicMock UDP socket whose recv() always times out."""
    sock = MagicMock()
    sock.recv.side_effect = socket.timeout()
    return sock


def test_snmp_udp_timeout_is_not_reported_alive():
    """A silent SNMP agent (no datagram, no ICMP) is NOT evidence of life."""
    from src.oida.fuzz.monitors.network import SNMPHealthMonitor

    with patch("socket.socket", return_value=_timing_out_udp_socket()):
        monitor = SNMPHealthMonitor("192.168.1.1", timeout=0.01)
        assert monitor._check_alive_once(Mock()) is False


def test_snmp_single_timeout_does_not_flip_crashed():
    """One timed-out round counts as a failure but must not declare a crash."""
    from src.oida.fuzz.monitors.network import SNMPHealthMonitor

    with patch("socket.socket", return_value=_timing_out_udp_socket()):
        monitor = SNMPHealthMonitor("192.168.1.1", timeout=0.01, retry_count=1, failure_threshold=2)
        monitor.last_check_time = None

        assert monitor._check_alive(Mock()) is False
        assert monitor.consecutive_failures == 1
        assert monitor.crashed is False


def test_snmp_datagram_reply_still_alive():
    """A real datagram reply is still reported alive (no over-correction)."""
    from src.oida.fuzz.monitors.network import SNMPHealthMonitor

    sock = MagicMock()
    sock.recv.return_value = b"\x30\x26\x02\x01\x01"
    with patch("socket.socket", return_value=sock):
        monitor = SNMPHealthMonitor("192.168.1.1", timeout=0.01)
        assert monitor._check_alive_once(Mock()) is True


def test_bacnet_udp_timeout_is_not_reported_alive():
    """A Who-Is with no I-Am and no ICMP error is NOT evidence of life."""
    from src.oida.fuzz.monitors.industrial import BACnetMonitor

    with patch("socket.socket", return_value=_timing_out_udp_socket()):
        monitor = BACnetMonitor("192.168.1.1", timeout=0.01)
        assert monitor._check_alive_once(Mock()) is False
        assert monitor.baseline_established is False


def test_bacnet_timeout_does_not_flip_crashed():
    from src.oida.fuzz.monitors.industrial import BACnetMonitor

    with patch("socket.socket", return_value=_timing_out_udp_socket()):
        monitor = BACnetMonitor("192.168.1.1", timeout=0.01, retry_count=1, failure_threshold=2)
        monitor.last_check_time = None

        assert monitor._check_alive(Mock()) is False
        assert monitor.consecutive_failures == 1
        assert monitor.crashed is False


def test_bacnet_bvlc_reply_still_alive():
    """A BVLC I-Am reply is still alive and still establishes the baseline."""
    from src.oida.fuzz.monitors.industrial import BACnetMonitor

    sock = MagicMock()
    sock.recv.return_value = bytes([0x81, 0x0B, 0x00, 0x0C, 0x01, 0x20, 0x10, 0x00])
    with patch("socket.socket", return_value=sock):
        monitor = BACnetMonitor("192.168.1.1", timeout=0.01)
        assert monitor._check_alive_once(Mock()) is True
        assert monitor.baseline_established is True


# ---------------------------------------------------------------------------
# M3: an aggregator with no active monitors has no health signal
# ---------------------------------------------------------------------------


class _StubMonitor:
    """Minimal sub-monitor stub for CombinedMonitor aggregation tests."""

    def __init__(self, result=True):
        self.result = result
        self.crashed = False
        self.consecutive_failures = 0
        self.test_case_count = 0
        self.test_case_name = None

    def _check_alive(self, fuzz_data_logger=None):
        return self.result


def test_combined_monitor_with_no_monitors_reports_unknown():
    """Zero monitors == zero checks: must not claim the target is healthy."""
    from src.oida.fuzz.monitors import CombinedMonitor

    monitor = CombinedMonitor(host="127.0.0.1", port=80, monitors=[])

    monitor._check_monitors(None, Mock(), None, "post-send")

    assert monitor.health_signal_available is False
    assert monitor.last_verdict is None
    assert monitor.get_crash_summary()["health_signal"] == "unknown"


def test_combined_monitor_all_disabled_reports_unknown():
    """All sub-monitors disabled by graceful degradation -> no-signal, not healthy."""
    from src.oida.fuzz.monitors import CombinedMonitor

    stub = _StubMonitor(result=True)
    monitor = CombinedMonitor(host="127.0.0.1", port=80, monitors=[stub], graceful_degradation=True)
    monitor.mark_monitor_failed(stub, "boom")

    monitor._check_monitors(None, Mock(), None, "post-send")

    assert monitor.health_signal_available is False
    assert monitor.last_verdict is None
    assert monitor.get_crash_summary()["health_signal"] == "unknown"


def test_combined_monitor_no_signal_does_not_clear_failure_history():
    """A no-signal round must not reset the aggregator's failure streak."""
    from src.oida.fuzz.monitors import CombinedMonitor

    monitor = CombinedMonitor(host="127.0.0.1", port=80, monitors=[])
    monitor.consecutive_failures = 3

    monitor._check_monitors(None, Mock(), None, "post-send")

    assert monitor.consecutive_failures == 3
    assert monitor.actual_check_count == 0


def test_combined_monitor_with_active_monitor_still_reports_healthy():
    """A real passing check is still a confident healthy verdict."""
    from src.oida.fuzz.monitors import CombinedMonitor

    monitor = CombinedMonitor(host="127.0.0.1", port=80, monitors=[_StubMonitor(True)])

    assert monitor._check_monitors(None, Mock(), None, "post-send") is True
    assert monitor.health_signal_available is True
    assert monitor.last_verdict is True
    assert monitor.get_crash_summary()["health_signal"] == "healthy"


def test_combined_monitor_failing_monitor_reports_failed():
    from src.oida.fuzz.monitors import CombinedMonitor

    monitor = CombinedMonitor(host="127.0.0.1", port=80, monitors=[_StubMonitor(False)])

    assert monitor._check_monitors(None, Mock(), None, "post-send") is False
    assert monitor.last_verdict is False
    assert monitor.get_crash_summary()["health_signal"] == "failed"


# ---------------------------------------------------------------------------
# M5: Modbus RTU CRC must be validated
# ---------------------------------------------------------------------------


def _rtu_frame(pdu: bytes, monitor) -> bytes:
    return pdu + monitor._calculate_crc(pdu)


def test_rtu_response_with_bad_crc_is_rejected():
    from src.oida.fuzz.monitors.industrial import ModbusRTUMonitor

    monitor = ModbusRTUMonitor("127.0.0.1", transport="tcp")
    pdu = b"\x01\x03\x02\x00\x2a"
    good = _rtu_frame(pdu, monitor)
    bad = good[:-2] + bytes([good[-2] ^ 0xFF, good[-1]])

    assert monitor._validate_rtu_response(good) is True
    assert monitor._validate_rtu_response(bad) is False


def test_rtu_bad_crc_is_not_evidence_of_life_and_never_baselined():
    from src.oida.fuzz.monitors.industrial import ModbusRTUMonitor

    monitor = ModbusRTUMonitor("127.0.0.1", transport="tcp")
    pdu = b"\x01\x03\x02\x00\x2a"
    bad = pdu + b"\xff\xff"

    assert monitor._process_response(bad, Mock()) is False
    assert monitor.baseline_established is False
    assert monitor.baseline_function_code is None


def test_rtu_good_crc_still_establishes_baseline():
    from src.oida.fuzz.monitors.industrial import ModbusRTUMonitor

    monitor = ModbusRTUMonitor("127.0.0.1", transport="tcp")
    good = _rtu_frame(b"\x01\x03\x02\x00\x2a", monitor)

    assert monitor._process_response(good, Mock()) is True
    assert monitor.baseline_established is True
    assert monitor.baseline_function_code == 0x03


def test_rtu_exception_response_is_alive_not_a_crash():
    """A CRC-valid FC|0x80 exception frame proves liveness, not a crash.

    Liveness != content drift (BUG-6): a Modbus exception reply means the slave
    received the request and deliberately rejected it, so it is framing correctly
    and answering. _validate_rtu_response now validates framing/CRC only (so the
    frame is a valid frame), and _process_response scores the exception as alive
    without drift-comparing it.
    """
    from src.oida.fuzz.monitors.industrial import ModbusRTUMonitor

    monitor = ModbusRTUMonitor("127.0.0.1", transport="tcp")
    frame = _rtu_frame(b"\x01\x83\x02", monitor)

    # Framing/CRC is valid ...
    assert monitor._validate_rtu_response(frame) is True
    # ... and the exception reply is treated as a live target.
    assert monitor._process_response(frame, Mock()) is True


# ---------------------------------------------------------------------------
# M6: baselines must only come from a successful probe
# ---------------------------------------------------------------------------


def test_ftp_empty_reply_does_not_poison_baseline():
    """recv() == b"" (peer closed) is a failed probe, not a baseline."""
    from src.oida.fuzz.monitors.application import FTPCommandMonitor

    monitor = FTPCommandMonitor("127.0.0.1")
    with patch.object(monitor, "_send_command", return_value=b""):
        assert monitor._check_alive_once(Mock()) is False

    assert monitor.baseline_established is False
    assert monitor.baseline_code is None


def test_ftp_non_status_reply_does_not_poison_baseline():
    """A reply with no 3-digit status code is not a usable baseline."""
    from src.oida.fuzz.monitors.application import FTPCommandMonitor

    monitor = FTPCommandMonitor("127.0.0.1")
    with patch.object(monitor, "_send_command", return_value=b"\x00\x01garbage"):
        assert monitor._check_alive_once(Mock()) is False

    assert monitor.baseline_established is False
    assert monitor.baseline_code is None


def test_ftp_valid_reply_still_baselines():
    from src.oida.fuzz.monitors.application import FTPCommandMonitor

    monitor = FTPCommandMonitor("127.0.0.1")
    with patch.object(monitor, "_send_command", return_value=b'257 "/" is cwd\r\n'):
        assert monitor._check_alive_once(Mock()) is True

    assert monitor.baseline_established is True
    assert monitor.baseline_code == "257"


def test_smtp_empty_reply_does_not_poison_baseline():
    from src.oida.fuzz.monitors.application import SMTPCommandMonitor

    monitor = SMTPCommandMonitor("127.0.0.1")
    with patch.object(monitor, "_send_command", return_value=b""):
        assert monitor._check_alive_once(Mock()) is False

    assert monitor.baseline_established is False


def test_http_server_error_is_not_baselined():
    """A 5xx first probe is a failed probe -- do not freeze it as the reference."""
    from src.oida.fuzz.monitors.application import HTTPGetMonitor

    monitor = HTTPGetMonitor("127.0.0.1")
    bad = Mock()
    bad.status_code = 503
    bad.text = "Service Unavailable"
    bad.content = b"Service Unavailable"

    with patch.object(monitor, "_make_request", return_value=bad):
        assert monitor._check_alive_once(Mock()) is False

    assert monitor.baseline_established is False
    assert monitor.baseline_status is None


def test_http_ok_first_probe_still_baselines():
    from src.oida.fuzz.monitors.application import HTTPGetMonitor

    monitor = HTTPGetMonitor("127.0.0.1")
    ok = Mock()
    ok.status_code = 200
    ok.text = "hello"
    ok.content = b"hello"

    with patch.object(monitor, "_make_request", return_value=ok):
        assert monitor._check_alive_once(Mock()) is True

    assert monitor.baseline_established is True
    assert monitor.baseline_status == 200


def test_http_later_server_error_is_alive_but_logged():
    """After a good baseline, a later 5xx is drift -> still alive, but logged.

    Liveness != content drift (BUG-6). A live server answering 500 is up, not
    crashed -- and during fuzzing a 500 is extremely common, so scoring it as a
    crash halts the run on a false positive. The behavioural change is still
    surfaced (log_fail) for the operator; it just no longer reports the target
    as down. (A 5xx as the *first* probe is still refused as a baseline -- see
    test_http_server_error_is_not_baselined.)
    """
    from src.oida.fuzz.monitors.application import HTTPGetMonitor

    monitor = HTTPGetMonitor("127.0.0.1")
    ok = Mock()
    ok.status_code = 200
    ok.text = "hello"
    ok.content = b"hello"
    bad = Mock()
    bad.status_code = 500
    bad.text = "boom"
    bad.content = b"boom"

    with patch.object(monitor, "_make_request", return_value=ok):
        assert monitor._check_alive_once(Mock()) is True

    drift_logger = Mock()
    with patch.object(monitor, "_make_request", return_value=bad):
        assert monitor._check_alive_once(drift_logger) is True
    # The drift is not fatal, but it must still be surfaced.
    assert drift_logger.log_fail.called


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
