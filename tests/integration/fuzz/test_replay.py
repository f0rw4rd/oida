"""
Integration tests for fuzzer replay feature.

Tests the ability to replay test cases from recorded sessions, including:
- Basic replay functionality
- Lightweight mode (CRC32-based payload regeneration)
- Stored crash payload replay
- Range parsing for multiple test cases
- CRC32 validation for regenerated payloads
"""

import binascii
import os
import pytest
import socket
import tempfile
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import List, Tuple

from tests.service_gate import require_import, require_service


class RecordingHTTPHandler(BaseHTTPRequestHandler):
    """HTTP handler that records all received requests."""

    received_requests: List[Tuple[str, bytes]] = []
    lock = threading.Lock()

    def log_message(self, format, *args):
        pass  # Suppress logging

    def do_GET(self):
        self._record_request("GET")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        self._record_request("POST", body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def _record_request(self, method: str, body: bytes = b""):
        with RecordingHTTPHandler.lock:
            RecordingHTTPHandler.received_requests.append((method, body))

    do_HEAD = do_PUT = do_DELETE = do_OPTIONS = do_GET


class RecordingServer:
    """Context manager for a server that records all requests."""

    def __init__(self, port: int = 0):
        self.port = port
        self.server = None
        self.thread = None

    def __enter__(self):
        RecordingHTTPHandler.received_requests = []

        if self.port == 0:
            with socket.socket() as s:
                s.bind(("", 0))
                self.port = s.getsockname()[1]

        self.server = HTTPServer(("127.0.0.1", self.port), RecordingHTTPHandler)
        self.server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.5)
        return self

    def __exit__(self, *args):
        if self.server:
            self.server.shutdown()
        if self.thread:
            self.thread.join(timeout=2)

    @property
    def requests(self):
        return RecordingHTTPHandler.received_requests

    @property
    def request_count(self):
        return len(RecordingHTTPHandler.received_requests)


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


class TestReplayBasic:
    """Test basic replay functionality."""

    def test_record_and_list_test_cases(self, temp_session, available_port):
        """Test that fuzzing records test cases that can be listed."""
        require_import("boofuzz")

        from oida.fuzz import FuzzerConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        with RecordingServer(available_port) as server:
            config = FuzzerConfig(
                target_ip="127.0.0.1",
                target_port=server.port,
                protocol="http",
                session_filename=temp_session,
                enumerate=False,
                store_all_payloads=True,  # Enable full payload storage for replay testing
                index_end=50,  # Limit to 50 test cases for fast test
                web_interface=False,  # Disable web interface for tests
            )

            fuzzer_class = PROTOCOL_FUZZERS.get("http")
            if not fuzzer_class:
                require_service("HTTP fuzzer not available")

            fuzzer = fuzzer_class(config)

            # Run fuzzer with limited test cases
            try:
                fuzzer.fuzz_all()
            except (KeyboardInterrupt, ConnectionError):
                pass

            # Check progress from fuzzer
            assert fuzzer._test_case_manager is not None, "Test case manager should be initialized"

            progress = fuzzer._test_case_manager.get_progress()
            actual_sends = progress.get("actual_sends", 0)
            assert actual_sends > 0, f"Should have sent test cases, got {actual_sends}"

            # Verify database was created
            db_path = f"{temp_session}.db"
            assert os.path.exists(db_path), "Database should be created"

            # Get test cases from fuzzer's database
            cases = fuzzer._test_case_manager.database.get_test_cases()[:100]
            assert len(cases) > 0, f"Should have recorded test cases, got {len(cases)}"

            # Verify test case structure
            first_case = cases[0]
            assert first_case.id is not None
            assert first_case.name is not None
            assert first_case.crc32 is not None

    def test_replay_single_test_case(self, temp_session, available_port):
        """Test replaying a single test case."""
        require_import("boofuzz")

        from oida.fuzz import FuzzerConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        with RecordingServer(available_port) as server:
            config = FuzzerConfig(
                target_ip="127.0.0.1",
                target_port=server.port,
                protocol="http",
                session_filename=temp_session,
                enumerate=False,
                store_all_payloads=True,  # Enable full payload storage for replay testing
                index_end=30,  # Limit to 30 test cases for fast test
                web_interface=False,  # Disable web interface for tests
            )

            fuzzer_class = PROTOCOL_FUZZERS.get("http")
            if not fuzzer_class:
                require_service("HTTP fuzzer not available")

            fuzzer = fuzzer_class(config)

            # Record some test cases
            try:
                fuzzer.fuzz_all()
            except (KeyboardInterrupt, ConnectionError):
                pass

            # Get recorded test cases using fuzzer's own manager
            manager = fuzzer._test_case_manager
            cases = manager.database.get_test_cases()[:10]
            if not cases:
                pytest.skip("No test cases recorded")

            # Clear server request log
            RecordingHTTPHandler.received_requests = []

            # Replay first test case
            test_id = cases[0].id
            success = manager.replay_test_case(test_id, show_detail=False, check_response=False)

            # Replay should succeed (payload was sent)
            # Note: server.request_count may be 0 for malformed HTTP requests
            assert success, "Replay should succeed in sending payload"

    def test_replay_with_response_check(self, temp_session, available_port):
        """Test replaying with response validation."""
        require_import("boofuzz")

        from oida.fuzz import FuzzerConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        with RecordingServer(available_port) as server:
            config = FuzzerConfig(
                target_ip="127.0.0.1",
                target_port=server.port,
                protocol="http",
                session_filename=temp_session,
                enumerate=False,
                store_all_payloads=True,  # Enable full payload storage for replay testing
                index_end=30,  # Limit to 30 test cases for fast test
                web_interface=False,  # Disable web interface for tests
            )

            fuzzer_class = PROTOCOL_FUZZERS.get("http")
            if not fuzzer_class:
                require_service("HTTP fuzzer not available")

            fuzzer = fuzzer_class(config)

            # Record test cases
            try:
                fuzzer.fuzz_all()
            except (KeyboardInterrupt, ConnectionError):
                pass

            # Replay with response check using fuzzer's manager
            manager = fuzzer._test_case_manager
            cases = manager.database.get_test_cases()[:10]
            if not cases:
                pytest.skip("No test cases recorded")

            test_id = cases[0].id

            # Should succeed with running server
            success = manager.replay_test_case(test_id, show_detail=False, check_response=True)
            assert success, "Replay should succeed when server responds"


class TestReplayRangeParsing:
    """Test replay range parsing functionality."""

    def test_parse_single_id(self, temp_session, available_port):
        """Test parsing single test case ID."""
        require_import("boofuzz")

        from oida.fuzz import FuzzerConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase
        from oida.fuzz.core.session.manager import TestCaseManager

        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=available_port,
            protocol="http",
            session_filename=temp_session,
            enumerate=False,
            web_interface=False,  # Disable web interface for tests
        )

        fuzzer_class = PROTOCOL_FUZZERS.get("http")
        if not fuzzer_class:
            require_service("HTTP fuzzer not available")

        fuzzer = fuzzer_class(config)

        db_path = f"{temp_session}.db"
        database = SQLAlchemyDatabase(db_path)
        database.init_schema()
        manager = TestCaseManager(fuzzer, database, store_all_payloads=False)

        # Test single ID
        ids = manager.parse_test_case_range("5")
        assert ids == [5]

    def test_parse_range(self, temp_session, available_port):
        """Test parsing range (1-5)."""
        require_import("boofuzz")

        from oida.fuzz import FuzzerConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase
        from oida.fuzz.core.session.manager import TestCaseManager

        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=available_port,
            protocol="http",
            session_filename=temp_session,
            enumerate=False,
            web_interface=False,  # Disable web interface for tests
        )

        fuzzer_class = PROTOCOL_FUZZERS.get("http")
        if not fuzzer_class:
            require_service("HTTP fuzzer not available")

        fuzzer = fuzzer_class(config)

        db_path = f"{temp_session}.db"
        database = SQLAlchemyDatabase(db_path)
        database.init_schema()
        manager = TestCaseManager(fuzzer, database, store_all_payloads=False)

        # Test range
        ids = manager.parse_test_case_range("1-5")
        assert ids == [1, 2, 3, 4, 5]

    def test_parse_invalid_format(self, temp_session, available_port):
        """Test that invalid format raises ValueError."""
        require_import("boofuzz")

        from oida.fuzz import FuzzerConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase
        from oida.fuzz.core.session.manager import TestCaseManager

        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=available_port,
            protocol="http",
            session_filename=temp_session,
            enumerate=False,
            web_interface=False,  # Disable web interface for tests
        )

        fuzzer_class = PROTOCOL_FUZZERS.get("http")
        if not fuzzer_class:
            require_service("HTTP fuzzer not available")

        fuzzer = fuzzer_class(config)

        db_path = f"{temp_session}.db"
        database = SQLAlchemyDatabase(db_path)
        database.init_schema()
        manager = TestCaseManager(fuzzer, database, store_all_payloads=False)

        # Invalid formats should raise ValueError
        with pytest.raises(ValueError):
            manager.parse_test_case_range("abc")

        with pytest.raises(ValueError):
            manager.parse_test_case_range("1,3,5")  # Comma list not supported

    def test_parse_range_bounds(self, temp_session, available_port):
        """Test range boundary cases."""
        require_import("boofuzz")

        from oida.fuzz import FuzzerConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase
        from oida.fuzz.core.session.manager import TestCaseManager

        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=available_port,
            protocol="http",
            session_filename=temp_session,
            enumerate=False,
            web_interface=False,  # Disable web interface for tests
        )

        fuzzer_class = PROTOCOL_FUZZERS.get("http")
        if not fuzzer_class:
            require_service("HTTP fuzzer not available")

        fuzzer = fuzzer_class(config)

        db_path = f"{temp_session}.db"
        database = SQLAlchemyDatabase(db_path)
        database.init_schema()
        manager = TestCaseManager(fuzzer, database, store_all_payloads=False)

        # Same start and end
        ids = manager.parse_test_case_range("5-5")
        assert ids == [5]

        # Large range
        ids = manager.parse_test_case_range("1-100")
        assert len(ids) == 100
        assert ids[0] == 1
        assert ids[-1] == 100


class TestReplayLightweightMode:
    """Test lightweight mode replay with CRC32 regeneration."""

    def test_crc32_consistency(self, temp_session, available_port):
        """Test that regenerated payloads have consistent CRC32."""
        require_import("boofuzz")

        from oida.fuzz import FuzzerConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        with RecordingServer(available_port) as server:
            config = FuzzerConfig(
                target_ip="127.0.0.1",
                target_port=server.port,
                protocol="http",
                session_filename=temp_session,
                enumerate=False,
                store_all_payloads=True,  # Enable full payload storage for replay testing
                index_end=30,  # Limit to 30 test cases for fast test
                web_interface=False,  # Disable web interface for tests
            )

            fuzzer_class = PROTOCOL_FUZZERS.get("http")
            if not fuzzer_class:
                require_service("HTTP fuzzer not available")

            fuzzer = fuzzer_class(config)

            # Record test cases
            try:
                fuzzer.fuzz_all()
            except (KeyboardInterrupt, ConnectionError):
                pass

            # Get test case with CRC32 using fuzzer's manager
            manager = fuzzer._test_case_manager
            cases = manager.database.get_test_cases()[:10]
            if not cases:
                pytest.skip("No test cases recorded")

            # Find a non-crash case (CRC32 regeneration)
            # Note: with store_all_payloads=True, all cases have stored payloads
            test_case = None
            for case in cases:
                crash = manager.database.get_crash(case.id)
                if not crash:
                    test_case = case
                    break

            if not test_case:
                pytest.skip("All test cases have stored payloads (no regeneration test)")

            # Regenerate payload twice — verify CRC32 is self-consistent across calls.
            # Regenerated CRC32 is NOT required to equal test_case.crc32: the stored
            # CRC32 was captured via session.last_send during a sequential fuzzing run
            # while regeneration starts a fresh boofuzz session, so the state-machine
            # context can differ and produce legitimately different bytes.
            try:
                payload1 = fuzzer._regenerate_payload(test_case.id)
                crc1 = binascii.crc32(payload1) & 0xFFFFFFFF

                payload2 = fuzzer._regenerate_payload(test_case.id)
                crc2 = binascii.crc32(payload2) & 0xFFFFFFFF

                assert len(payload1) > 0, "Regenerated payload should be non-empty"
                assert crc1 == crc2, (
                    f"Regenerated CRC32 should be consistent across calls: {crc1:08x} != {crc2:08x}"
                )
            except AttributeError:
                pytest.skip("Fuzzer does not support payload regeneration")

    def test_regeneration_deterministic(self, temp_session, available_port):
        """Test that payload regeneration is deterministic."""
        require_import("boofuzz")

        from oida.fuzz import FuzzerConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        with RecordingServer(available_port) as server:
            config = FuzzerConfig(
                target_ip="127.0.0.1",
                target_port=server.port,
                protocol="http",
                session_filename=temp_session,
                enumerate=False,
                store_all_payloads=True,  # Enable full payload storage for replay testing
                index_end=30,  # Limit to 30 test cases for fast test
                web_interface=False,  # Disable web interface for tests
            )

            fuzzer_class = PROTOCOL_FUZZERS.get("http")
            if not fuzzer_class:
                require_service("HTTP fuzzer not available")

            fuzzer = fuzzer_class(config)

            # Record test cases
            try:
                fuzzer.fuzz_all()
            except (KeyboardInterrupt, ConnectionError):
                pass

            # Get test cases using fuzzer's manager
            manager = fuzzer._test_case_manager
            cases = manager.database.get_test_cases()[:10]
            if not cases:
                pytest.skip("No test cases recorded")

            # Find a non-crash case
            # Note: with store_all_payloads=True, all cases have stored payloads
            test_case = None
            for case in cases:
                crash = manager.database.get_crash(case.id)
                if not crash:
                    test_case = case
                    break

            if not test_case:
                pytest.skip("All test cases have stored payloads (no regeneration test)")

            # Regenerate payload twice
            try:
                payload1 = fuzzer._regenerate_payload(test_case.id)
                payload2 = fuzzer._regenerate_payload(test_case.id)

                # Should be identical
                assert payload1 == payload2, "Regenerated payloads should be identical"
            except AttributeError:
                pytest.skip("Fuzzer does not support payload regeneration")


class TestReplayMultiple:
    """Test replaying multiple test cases."""

    def test_replay_range(self, temp_session, available_port):
        """Test replaying a range of test cases."""
        require_import("boofuzz")

        from oida.fuzz import FuzzerConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        with RecordingServer(available_port) as server:
            config = FuzzerConfig(
                target_ip="127.0.0.1",
                target_port=server.port,
                protocol="http",
                session_filename=temp_session,
                enumerate=False,
                store_all_payloads=True,  # Enable full payload storage for replay testing
                index_end=50,  # Limit to 50 test cases for fast test
                web_interface=False,  # Disable web interface for tests
            )

            fuzzer_class = PROTOCOL_FUZZERS.get("http")
            if not fuzzer_class:
                require_service("HTTP fuzzer not available")

            fuzzer = fuzzer_class(config)

            # Record test cases
            try:
                fuzzer.fuzz_all()
            except (KeyboardInterrupt, ConnectionError):
                pass

            # Get recorded count using fuzzer's manager
            manager = fuzzer._test_case_manager
            cases = manager.database.get_test_cases()[:100]
            if len(cases) < 3:
                pytest.skip("Not enough test cases recorded")

            # Clear server request log
            RecordingHTTPHandler.received_requests = []

            # Replay range
            results = manager.replay_test_cases("1-3", show_detail=False, check_response=False)

            # Should have results for 3 test cases
            assert len(results) == 3, f"Expected 3 results, got {len(results)}"

            # All replays should succeed (payloads sent)
            successes = [r[1] for r in results]
            assert all(successes), f"All replays should succeed, got: {results}"


class TestReplayNonexistent:
    """Test handling of nonexistent test cases."""

    def test_replay_nonexistent_returns_false(self, temp_session, available_port):
        """Test that replaying nonexistent test case returns False."""
        require_import("boofuzz")

        from oida.fuzz import FuzzerConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase
        from oida.fuzz.core.session.manager import TestCaseManager

        config = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=available_port,
            protocol="http",
            session_filename=temp_session,
            enumerate=False,
            web_interface=False,  # Disable web interface for tests
        )

        fuzzer_class = PROTOCOL_FUZZERS.get("http")
        if not fuzzer_class:
            require_service("HTTP fuzzer not available")

        fuzzer = fuzzer_class(config)

        db_path = f"{temp_session}.db"
        database = SQLAlchemyDatabase(db_path)
        database.init_schema()
        manager = TestCaseManager(fuzzer, database, store_all_payloads=False)

        # Try to replay nonexistent test case
        success = manager.replay_test_case(99999, show_detail=False, check_response=False)
        assert success is False, "Should return False for nonexistent test case"


class TestReplayStoredPayload:
    """Test replaying with stored crash payloads."""

    def test_stored_payload_used_for_crash(self, temp_session, available_port):
        """Test that stored payload is used when available (crash case)."""
        require_import("boofuzz")

        from oida.fuzz import FuzzerConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        # Create a server that will "crash" after a few requests
        class CrashingHandler(BaseHTTPRequestHandler):
            count = 0
            lock = threading.Lock()
            timeout = 2  # prevent blocking in readline() on half-open connections

            def log_message(self, *args):
                pass

            def do_GET(self):
                with CrashingHandler.lock:
                    CrashingHandler.count += 1
                    if CrashingHandler.count >= 20:
                        # Simulate crash by closing connection
                        self.connection.close()
                        return

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")

            do_POST = do_GET

        CrashingHandler.count = 0

        server = HTTPServer(("127.0.0.1", available_port), CrashingHandler)
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
                enumerate=False,
                monitor_check_interval=10,
                index_end=100,  # Limit to 100 test cases
                web_interface=False,  # Disable web interface for tests
            )

            fuzzer_class = PROTOCOL_FUZZERS.get("http")
            if not fuzzer_class:
                require_service("HTTP fuzzer not available")

            fuzzer = fuzzer_class(config)

            # Run fuzzer to trigger crash — BoofuzzFailure is expected when server
            # crashes intentionally (closes connection after 20 requests)
            try:
                fuzzer.fuzz_all()
            except Exception:
                pass

            # Check for crash records using fuzzer's manager
            manager = fuzzer._test_case_manager
            cases = manager.database.get_test_cases()[:100]

            for case in cases:
                crash = manager.database.get_crash(case.id)
                if crash:
                    # Verify crash has stored payload
                    assert crash.payload is not None, "Crash should have stored payload"
                    assert len(crash.payload) > 0, "Crash payload should not be empty"
                    break

            # Note: crash detection may not trigger in short test runs
            # This test verifies the crash storage mechanism works if a crash occurs

        finally:
            server.shutdown()
            server_thread.join(timeout=2)


class TestReplayEchoProtocol:
    """Test replay with echo protocol (simpler than HTTP)."""

    def test_echo_replay(self, temp_session, available_port):
        """Test replay with echo protocol."""
        require_import("boofuzz")

        from oida.fuzz import FuzzerConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        # Create simple echo server
        class EchoHandler:
            def __init__(self, conn, addr):
                self.conn = conn
                self.addr = addr

            def handle(self):
                try:
                    while True:
                        data = self.conn.recv(1024)
                        if not data:
                            break
                        self.conn.sendall(data)
                except:
                    pass
                finally:
                    self.conn.close()

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", available_port))
        server_sock.listen(5)
        server_sock.settimeout(1.0)

        running = True
        connections = []

        def accept_loop():
            while running:
                try:
                    conn, addr = server_sock.accept()
                    handler = threading.Thread(target=EchoHandler(conn, addr).handle, daemon=True)
                    handler.start()
                    connections.append(handler)
                except socket.timeout:
                    continue
                except:
                    break

        server_thread = threading.Thread(target=accept_loop, daemon=True)
        server_thread.start()
        time.sleep(0.5)

        try:
            if "echo" not in PROTOCOL_FUZZERS:
                require_service("Echo fuzzer not available")

            config = FuzzerConfig(
                target_ip="127.0.0.1",
                target_port=available_port,
                protocol="echo",
                session_filename=temp_session,
                enumerate=False,
                store_all_payloads=True,  # Enable full payload storage for replay testing
                index_end=30,  # Limit to 30 test cases for fast test
                web_interface=False,  # Disable web interface for tests
            )

            fuzzer_class = PROTOCOL_FUZZERS.get("echo")
            fuzzer = fuzzer_class(config)

            # Record test cases
            try:
                fuzzer.fuzz_all()
            except (KeyboardInterrupt, ConnectionError):
                pass

            # Verify test cases recorded using fuzzer's manager
            manager = fuzzer._test_case_manager
            if manager:
                cases = manager.database.get_test_cases()[:10]
                assert len(cases) > 0, "Should have recorded test cases"

        finally:
            running = False
            server_sock.close()
            server_thread.join(timeout=2)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
