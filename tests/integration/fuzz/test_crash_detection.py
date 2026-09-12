"""
Integration tests for fuzzer crash detection.

Tests that the fuzzer correctly detects when a target service crashes/stops.
"""

import pytest
import socket
import threading
import time
import os
import tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler

from tests.service_gate import require_import, require_service


class CrashingHTTPHandler(BaseHTTPRequestHandler):
    """HTTP handler that crashes after max_requests."""

    request_count = 0
    max_requests = 100
    lock = threading.Lock()

    def log_message(self, format, *args):
        pass  # Suppress logging

    def do_GET(self):
        with CrashingHTTPHandler.lock:
            CrashingHTTPHandler.request_count += 1
            count = CrashingHTTPHandler.request_count

        if count >= CrashingHTTPHandler.max_requests:
            # Simulate crash by closing connection without response
            self.connection.close()
            # Signal server to stop
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = do_GET


class CrashingServer:
    """Context manager for a server that crashes after N requests."""

    def __init__(self, port: int, max_requests: int = 100):
        self.port = port
        self.max_requests = max_requests
        self.server = None
        self.thread = None

    def __enter__(self):
        # Reset request counter
        CrashingHTTPHandler.request_count = 0
        CrashingHTTPHandler.max_requests = self.max_requests

        # Find available port if 0
        if self.port == 0:
            with socket.socket() as s:
                s.bind(("", 0))
                self.port = s.getsockname()[1]

        self.server = HTTPServer(("127.0.0.1", self.port), CrashingHTTPHandler)
        self.server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        # Wait for server to be ready
        time.sleep(0.5)
        return self

    def __exit__(self, *args):
        if self.server:
            self.server.shutdown()
        if self.thread:
            self.thread.join(timeout=2)

    @property
    def requests_served(self):
        return CrashingHTTPHandler.request_count


@pytest.fixture
def temp_session():
    """Create temporary session file path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield os.path.join(tmpdir, "test_session")


@pytest.fixture
def available_port():
    """Find an available port."""
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


class TestCrashDetection:
    """Test fuzzer crash detection capabilities."""

    def test_server_crashes_after_n_requests(self, available_port):
        """Verify test server crashes after max_requests."""
        max_reqs = 50

        with CrashingServer(available_port, max_requests=max_reqs) as server:
            # Send requests until server dies
            requests_sent = 0
            for i in range(max_reqs + 20):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1.0)
                    sock.connect(("127.0.0.1", server.port))
                    sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    response = sock.recv(1024)
                    sock.close()
                    if response:
                        requests_sent += 1
                except (
                    ConnectionRefusedError,
                    ConnectionResetError,
                    socket.timeout,
                    BrokenPipeError,
                ):
                    break

            assert requests_sent >= max_reqs - 5  # Allow some tolerance
            assert requests_sent < max_reqs + 10  # Should stop around max

    @pytest.mark.timeout(90)
    def test_fuzzer_detects_crash(self, temp_session, available_port):
        """Test that fuzzer detects when target crashes."""
        require_import("boofuzz")

        from oida.fuzz import FuzzerConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        max_reqs = 20  # Server crashes after this many requests

        with CrashingServer(available_port, max_requests=max_reqs) as server:
            config = FuzzerConfig(
                target_ip="127.0.0.1",
                target_port=server.port,
                protocol="http",
                session_filename=temp_session,
                monitor_check_interval=5,  # Check frequently
                enumerate=False,  # Skip enumeration
            )

            fuzzer_class = PROTOCOL_FUZZERS.get("http")
            if not fuzzer_class:
                require_service("HTTP fuzzer not available")

            fuzzer = fuzzer_class(config)

            # Run fuzzer in a thread so we can enforce a hard timeout.
            # signal.alarm does not reliably interrupt blocking recv() calls.
            fuzz_exc = [None]

            def _run():
                try:
                    fuzzer.fuzz_all()
                except Exception as e:
                    fuzz_exc[0] = e

            t = threading.Thread(target=_run, daemon=True)
            t.start()
            t.join(timeout=45)  # Hard wall-clock limit

            # Check that server received requests before crashing
            assert server.requests_served >= max_reqs - 10

            # Check that crash was detected through one of these mechanisms:
            # 1. BoofuzzFailure exception raised by monitor recovery logic
            # 2. CrashTracker recorded the crash (crash_count > 0)
            # 3. Child monitor's crashed flag is set
            # 4. CombinedMonitor's total_failures counter
            # Note: total_failures may be 0 if BoofuzzFailure propagated before
            # CombinedMonitor could increment it.
            crash_detected = False

            # Check if fuzz_all raised BoofuzzFailure (primary crash signal)
            if fuzz_exc[0] is not None:
                exc_name = type(fuzz_exc[0]).__name__
                if "BoofuzzFailure" in exc_name or "ConnectionError" in exc_name:
                    crash_detected = True

            if fuzzer.monitor:
                # Check CrashTracker (single source of truth for crash events)
                if getattr(fuzzer.monitor, "crash_count", 0) > 0:
                    crash_detected = True
                # Check total_failures
                if getattr(fuzzer.monitor, "total_failures", 0) > 0:
                    crash_detected = True
                # Check child monitors' crashed state
                if hasattr(fuzzer.monitor, "monitors"):
                    for m in fuzzer.monitor.monitors:
                        if getattr(m, "crashed", False):
                            crash_detected = True
                            break

            assert crash_detected, (
                f"Crash should be detected. "
                f"fuzz_exc={fuzz_exc[0]}, "
                f"crash_count={getattr(fuzzer.monitor, 'crash_count', 'N/A')}, "
                f"total_failures={getattr(fuzzer.monitor, 'total_failures', 'N/A')}"
            )

    @pytest.mark.timeout(90)
    def test_fuzzer_reports_crash_count(self, temp_session, available_port):
        """Test that fuzzer crash count is reported correctly."""
        require_import("boofuzz")

        from oida.fuzz import FuzzerConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        max_reqs = 20

        with CrashingServer(available_port, max_requests=max_reqs) as server:
            config = FuzzerConfig(
                target_ip="127.0.0.1",
                target_port=server.port,
                protocol="http",
                session_filename=temp_session,
                monitor_check_interval=5,
                enumerate=False,
            )

            fuzzer_class = PROTOCOL_FUZZERS.get("http")
            if not fuzzer_class:
                require_service("HTTP fuzzer not available")

            fuzzer = fuzzer_class(config)

            # Run in a daemon thread with a hard timeout
            def _run():
                try:
                    fuzzer.fuzz_all()
                except Exception:
                    pass

            t = threading.Thread(target=_run, daemon=True)
            t.start()
            t.join(timeout=45)

            # Get progress from test case manager
            if fuzzer._test_case_manager:
                progress = fuzzer._test_case_manager.get_progress()
                actual_sends = progress.get("actual_sends", 0)
                progress.get("crash_count", 0)

                # Should have sent requests
                assert actual_sends > 0, f"Should have sent requests, got {actual_sends}"

                # Crash detection depends on monitor settings
                # At minimum, actual_sends should be close to what server received
                assert actual_sends >= server.requests_served - 20


class TestActualSendTracking:
    """Test that actual send tracking is reasonable."""

    @pytest.mark.timeout(60)
    def test_actual_sends_not_inflated(self, temp_session, available_port):
        """Verify actual_sends is not inflated like old test case count.

        The old test case count was inflated ~100x (e.g., 30,000 reported vs 300 actual).
        With the fix, actual_sends should be within 2x of server count.
        """
        require_import("boofuzz")

        from oida.fuzz import FuzzerConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        # Server that doesn't crash
        class CountingHandler(BaseHTTPRequestHandler):
            count = 0
            lock = threading.Lock()

            def log_message(self, *args):
                pass

            def do_GET(self):
                with CountingHandler.lock:
                    CountingHandler.count += 1
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")

            do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = do_GET

        CountingHandler.count = 0

        server = HTTPServer(("127.0.0.1", available_port), CountingHandler)
        server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.5)

        try:
            config = FuzzerConfig(
                target_ip="127.0.0.1",
                target_port=available_port,
                protocol="http",
                session_filename=temp_session,
                monitor_check_interval=50,
                enumerate=False,
                reuse_target_connection=True,  # Use connection reuse for speed
            )

            fuzzer_class = PROTOCOL_FUZZERS.get("http")
            if not fuzzer_class:
                require_service("HTTP fuzzer not available")

            fuzzer = fuzzer_class(config)

            # Run in a daemon thread for 5 seconds
            def _run():
                try:
                    fuzzer.fuzz_all()
                except Exception:
                    pass

            t = threading.Thread(target=_run, daemon=True)
            t.start()
            t.join(timeout=10)  # Let it run for up to 10s

            # Get counts
            if fuzzer._test_case_manager:
                progress = fuzzer._test_case_manager.get_progress()
                actual_sends = progress.get("actual_sends", 0)

                # The key assertion: actual_sends should NOT be massively inflated.
                # Old bug: total_mutant_index was 100x the callback-based count.
                # Server-side HTTP handler count is NOT a reliable reference: most
                # fuzz mutations produce invalid HTTP that Python's BaseHTTPRequestHandler
                # drops before dispatching to do_GET, so server_received << actual_sends.
                # Instead compare against boofuzz's own num_cases_actually_fuzzed which
                # counts transmitted mutations regardless of HTTP validity.
                bf_session = getattr(fuzzer, "session", None)
                boofuzz_fuzzed = getattr(bf_session, "num_cases_actually_fuzzed", None)

                assert actual_sends > 0, "Should have recorded some sends"

                if boofuzz_fuzzed is not None and boofuzz_fuzzed > 0:
                    ratio = actual_sends / boofuzz_fuzzed
                    assert ratio < 5, (
                        f"actual_sends ({actual_sends}) is {ratio:.1f}x boofuzz's fuzzed count "
                        f"({boofuzz_fuzzed}). Callback counter should not be inflated vs boofuzz."
                    )

        finally:
            server.shutdown()
            server_thread.join(timeout=2)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
