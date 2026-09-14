"""Regression: application-layer monitors must not read content drift as a crash.

Mirrors the Modbus health-probe fix (BUG-6). The HTTP / FTP / SMTP / DNS monitors
previously (a) defaulted to failure_threshold=1 (one bad check == crash) and
(b) routed liveness through their content-drift `_compare_responses`, so a *live*
server that returned a changed status code, a different-sized body, or a drifted
DNS answer was scored DOWN and could halt the run.

After the fix:
  * a well-framed reply proves liveness -> `_check_alive_once` returns True even
    when the content drifts from baseline (the drift is still logged, not fatal);
  * failure_threshold defaults to 2 so a single blip is not an instant crash.
"""

from __future__ import annotations

import types

from oida.fuzz.monitors.application import (
    DNSQueryMonitor,
    FTPCommandMonitor,
    HTTPGetMonitor,
    SMTPCommandMonitor,
)


def _http_response(status_code: int, body: str):
    """Minimal requests.Response stand-in for the HTTP monitor."""
    return types.SimpleNamespace(
        status_code=status_code,
        content=body.encode(),
        text=body,
        headers={},
    )


def test_failure_threshold_defaults_are_debounced():
    """No app monitor should crash on a single failed check anymore."""
    assert HTTPGetMonitor("127.0.0.1").failure_threshold == 2
    assert FTPCommandMonitor("127.0.0.1").failure_threshold == 2
    assert SMTPCommandMonitor("127.0.0.1").failure_threshold == 2
    assert DNSQueryMonitor("127.0.0.1").failure_threshold == 2


def test_http_status_and_body_drift_is_alive():
    mon = HTTPGetMonitor("127.0.0.1")
    responses = [_http_response(200, "hello world\n"), _http_response(500, "totally different\n")]
    mon._make_request = lambda: responses.pop(0)  # type: ignore[method-assign]

    # First probe establishes baseline (200).
    assert mon._check_alive_once(None) is True
    # Second probe: a live server returning 500 with a different body is a
    # behavioural change, NOT a crash -> still alive.
    assert mon._check_alive_once(None) is True


def test_ftp_response_code_drift_is_alive():
    mon = FTPCommandMonitor("127.0.0.1")
    replies = [b"220 service ready\r\n", b"500 syntax error\r\n"]
    mon._send_command = lambda cmd: replies.pop(0)  # type: ignore[method-assign]

    assert mon._check_alive_once(None) is True  # baseline 220
    assert mon._check_alive_once(None) is True  # 500 == drift, still alive


def test_dns_size_drift_is_alive():
    mon = DNSQueryMonitor("127.0.0.1")
    # >=12 bytes = well-framed; second reply is >20% larger (drift).
    replies = [b"\x00" * 30, b"\x00" * 60]
    mon._send_query = lambda: replies.pop(0)  # type: ignore[method-assign]

    assert mon._check_alive_once(None) is True  # baseline
    assert mon._check_alive_once(None) is True  # size drift, still alive


def test_genuinely_no_reply_still_reads_down():
    """The fix must not blind the monitors: no reply at all is still DOWN."""
    http = HTTPGetMonitor("127.0.0.1")
    http._make_request = lambda: None  # type: ignore[method-assign]
    assert http._check_alive_once(None) is False

    ftp = FTPCommandMonitor("127.0.0.1")
    ftp._send_command = lambda cmd: None  # type: ignore[method-assign]
    assert ftp._check_alive_once(None) is False

    dns = DNSQueryMonitor("127.0.0.1")
    dns._send_query = lambda: None  # type: ignore[method-assign]
    assert dns._check_alive_once(None) is False
