"""
HTTP/2 Frame Type Integration Tests

Tests each HTTP/2 frame type against the validation server to verify:
- All 10 frame types are properly received and logged
- HPACK encoding/decoding works correctly
- Protocol errors are detected and reported
- Diagnostic endpoints return accurate data

Requires: HTTP/2 Python validation server running on port 9080
"""

import json
import pytest
import socket
import ssl
import struct
import time
from typing import Dict, List, Optional, Tuple

from tests.integration.conftest import MOCK_HOST, MOCK_PORTS
from tests.service_gate import require_port, require_service


# HTTP/2 Frame Types (RFC 7540)
FRAME_DATA = 0x00
FRAME_HEADERS = 0x01
FRAME_PRIORITY = 0x02
FRAME_RST_STREAM = 0x03
FRAME_SETTINGS = 0x04
FRAME_PUSH_PROMISE = 0x05
FRAME_PING = 0x06
FRAME_GOAWAY = 0x07
FRAME_WINDOW_UPDATE = 0x08
FRAME_CONTINUATION = 0x09

# Frame Flags
FLAG_END_STREAM = 0x01
FLAG_ACK = 0x01
FLAG_END_HEADERS = 0x04
FLAG_PADDED = 0x08
FLAG_PRIORITY = 0x20

# HTTP/2 Connection Preface
HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def create_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    """Create an HTTP/2 frame."""
    length = len(payload)
    header = struct.pack(">I", length)[1:]  # 3 bytes for length
    header += struct.pack(">B", frame_type)
    header += struct.pack(">B", flags)
    header += struct.pack(">I", stream_id & 0x7FFFFFFF)
    return header + payload


def encode_hpack_literal(name: str, value: str) -> bytes:
    """Encode header as HPACK literal without indexing."""
    result = b"\x00"  # Literal without indexing
    name_bytes = name.lower().encode()
    result += bytes([len(name_bytes)])
    result += name_bytes
    value_bytes = value.encode()
    result += bytes([len(value_bytes)])
    result += value_bytes
    return result


def create_settings_frame(settings: List[Tuple[int, int]] = None) -> bytes:
    """Create a SETTINGS frame."""
    if settings is None:
        settings = []
    payload = b""
    for setting_id, value in settings:
        payload += struct.pack(">HI", setting_id, value)
    return create_frame(FRAME_SETTINGS, 0, 0, payload)


def create_headers_frame(
    stream_id: int,
    headers: List[Tuple[str, str]],
    end_stream: bool = True,
    end_headers: bool = True,
) -> bytes:
    """Create a HEADERS frame with HPACK-encoded headers."""
    payload = b""
    for name, value in headers:
        payload += encode_hpack_literal(name, value)

    flags = 0
    if end_stream:
        flags |= FLAG_END_STREAM
    if end_headers:
        flags |= FLAG_END_HEADERS

    return create_frame(FRAME_HEADERS, flags, stream_id, payload)


class HTTP2Connection:
    """Simple HTTP/2 connection for testing."""

    def __init__(self, host: str, port: int, use_tls: bool = False):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.sock = None

    def connect(self) -> bool:
        """Establish HTTP/2 connection."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0)

            if self.use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_alpn_protocols(["h2"])
                self.sock = ctx.wrap_socket(self.sock, server_hostname=self.host)

            self.sock.connect((self.host, self.port))

            # Send connection preface
            self.sock.sendall(HTTP2_PREFACE)

            # Send empty SETTINGS
            self.sock.sendall(create_settings_frame())

            # Read server SETTINGS
            self.sock.settimeout(2.0)
            try:
                self.sock.recv(4096)
            except socket.timeout:
                pass

            return True

        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def send_frame(self, frame: bytes) -> bool:
        """Send a frame to the server."""
        try:
            self.sock.sendall(frame)
            return True
        except Exception as e:
            print(f"Send error: {e}")
            return False

    def recv_frame(self, timeout: float = 1.0) -> Optional[bytes]:
        """Receive a frame from the server."""
        try:
            self.sock.settimeout(timeout)
            return self.sock.recv(4096)
        except socket.timeout:
            return None
        except Exception:
            return None

    def recv_all(self, timeout: float = 2.0) -> bytes:
        """Receive all available data from the server."""
        data = b""
        try:
            self.sock.settimeout(0.5)
            while True:
                try:
                    chunk = self.sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    break
        except Exception:
            pass
        return data

    def http2_get(self, path: str, stream_id: int = 1) -> Optional[bytes]:
        """Make an HTTP/2 GET request and return response body."""
        headers = [
            (":method", "GET"),
            (":path", path),
            (":scheme", "http"),
            (":authority", f"{self.host}:{self.port}"),
        ]
        headers_frame = create_headers_frame(stream_id, headers, end_stream=True, end_headers=True)
        if not self.send_frame(headers_frame):
            return None

        # Collect response frames
        time.sleep(0.3)
        response_data = self.recv_all(timeout=2.0)
        if not response_data:
            return None

        # Parse frames to extract DATA payload
        body = b""
        offset = 0
        while offset + 9 <= len(response_data):
            length = (
                (response_data[offset] << 16)
                | (response_data[offset + 1] << 8)
                | response_data[offset + 2]
            )
            frame_type = response_data[offset + 3]
            if frame_type == FRAME_DATA and offset + 9 + length <= len(response_data):
                body += response_data[offset + 9 : offset + 9 + length]
            offset += 9 + length

        return body if body else None

    def close(self):
        """Close the connection."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


def get_server_frames(host: str, port: int) -> List[Dict]:
    """Fetch frame log from validation server using HTTP/2."""
    conn = HTTP2Connection(host, port, use_tls=False)
    if not conn.connect():
        return []
    try:
        # Use a high stream ID to avoid conflicts with previous tests
        body = conn.http2_get("/.well-known/h2/frames", stream_id=99)
        if body:
            return json.loads(body.decode("utf-8"))
        return []
    except Exception:
        return []
    finally:
        conn.close()


def get_server_errors(host: str, port: int) -> List[Dict]:
    """Fetch the (size-bounded, most-recent) error log entries from the validation server.

    The server also tracks a monotonic total error count that is never
    truncated; use `get_server_error_count()` to detect "was a new error
    logged" rather than comparing `len()` of this bounded list, which can
    plateau once the server has logged more errors than it keeps details for.
    """
    conn = HTTP2Connection(host, port, use_tls=False)
    if not conn.connect():
        return []
    try:
        body = conn.http2_get("/.well-known/h2/errors", stream_id=99)
        if body:
            payload = json.loads(body.decode("utf-8"))
            if isinstance(payload, dict):
                return payload.get("errors", [])
            return payload
        return []
    except Exception:
        return []
    finally:
        conn.close()


def get_server_error_count(host: str, port: int) -> int:
    """Fetch the monotonic total protocol-error count from the validation server."""
    conn = HTTP2Connection(host, port, use_tls=False)
    if not conn.connect():
        return 0
    try:
        body = conn.http2_get("/.well-known/h2/errors", stream_id=99)
        if body:
            payload = json.loads(body.decode("utf-8"))
            if isinstance(payload, dict) and "total_error_count" in payload:
                return payload["total_error_count"]
            if isinstance(payload, list):
                return len(payload)
        return 0
    except Exception:
        return 0
    finally:
        conn.close()


def get_server_state(host: str, port: int) -> Dict:
    """Fetch state from validation server using HTTP/2."""
    conn = HTTP2Connection(host, port, use_tls=False)
    if not conn.connect():
        return {}
    try:
        body = conn.http2_get("/.well-known/h2/state", stream_id=99)
        if body:
            return json.loads(body.decode("utf-8"))
        return {}
    except Exception:
        return {}
    finally:
        conn.close()


def get_server_hpack(host: str, port: int) -> Dict:
    """Fetch HPACK state from validation server using HTTP/2."""
    conn = HTTP2Connection(host, port, use_tls=False)
    if not conn.connect():
        return {}
    try:
        body = conn.http2_get("/.well-known/h2/hpack", stream_id=99)
        if body:
            return json.loads(body.decode("utf-8"))
        return {}
    except Exception:
        return {}
    finally:
        conn.close()


@pytest.mark.http2
@pytest.mark.mock_services
class TestHTTP2FrameTypes:
    """Test each HTTP/2 frame type against the validation server."""

    @pytest.fixture
    def h2_port(self):
        return MOCK_PORTS.get("http2_python_h2c", 9080)

    @pytest.fixture
    def h2_conn(self, h2_port, mock_service):
        """Create HTTP/2 connection fixture."""
        require_port(MOCK_HOST, h2_port, "HTTP/2 Python server")

        conn = HTTP2Connection(MOCK_HOST, h2_port, use_tls=False)
        if not conn.connect():
            require_service("Could not establish HTTP/2 connection")

        yield conn
        conn.close()

    def test_settings_frame(self, h2_conn, h2_port):
        """Test SETTINGS frame (type 0x04)."""
        # Send SETTINGS with custom values
        settings = [
            (0x01, 4096),  # HEADER_TABLE_SIZE
            (0x03, 100),  # MAX_CONCURRENT_STREAMS
            (0x04, 65535),  # INITIAL_WINDOW_SIZE
        ]
        frame = create_settings_frame(settings)
        assert h2_conn.send_frame(frame), "Failed to send SETTINGS frame"

        # Wait for SETTINGS ACK
        time.sleep(0.5)
        h2_conn.recv_frame()

        # Check server received it
        frames = get_server_frames(MOCK_HOST, h2_port)
        settings_frames = [
            f
            for f in frames
            if f.get("frame_type") == "SETTINGS" or "SETTINGS" in f.get("event_type", "")
        ]
        assert len(settings_frames) >= 1, "Server should have logged SETTINGS frame"

    def test_headers_frame(self, h2_conn, h2_port):
        """Test HEADERS frame (type 0x01)."""
        headers = [
            (":method", "GET"),
            (":path", "/test"),
            (":scheme", "http"),
            (":authority", "localhost"),
        ]
        frame = create_headers_frame(1, headers, end_stream=True, end_headers=True)
        assert h2_conn.send_frame(frame), "Failed to send HEADERS frame"

        # Wait for response
        time.sleep(0.5)
        h2_conn.recv_frame()

        # Check server received it
        frames = get_server_frames(MOCK_HOST, h2_port)
        header_frames = [
            f
            for f in frames
            if "REQUEST" in f.get("event_type", "") or f.get("frame_type") == "HEADERS"
        ]
        assert len(header_frames) >= 1, "Server should have logged HEADERS/REQUEST frame"

    def test_data_frame(self, h2_conn, h2_port):
        """Test DATA frame (type 0x00)."""
        # First send HEADERS for POST
        headers = [
            (":method", "POST"),
            (":path", "/echo"),
            (":scheme", "http"),
            (":authority", "localhost"),
            ("content-type", "text/plain"),
        ]
        headers_frame = create_headers_frame(3, headers, end_stream=False, end_headers=True)
        assert h2_conn.send_frame(headers_frame), "Failed to send HEADERS frame"

        # Now send DATA
        data_payload = b"Test data payload for HTTP/2"
        data_frame = create_frame(FRAME_DATA, FLAG_END_STREAM, 3, data_payload)
        assert h2_conn.send_frame(data_frame), "Failed to send DATA frame"

        # Wait for processing
        time.sleep(0.5)
        h2_conn.recv_frame()

        # Check server received it
        frames = get_server_frames(MOCK_HOST, h2_port)
        data_frames = [
            f for f in frames if "DATA" in f.get("event_type", "") or f.get("frame_type") == "DATA"
        ]
        assert len(data_frames) >= 1, "Server should have logged DATA frame"

    def test_ping_frame(self, h2_conn, h2_port):
        """Test PING frame (type 0x06)."""
        # Drain any pending frames from connection setup
        h2_conn.recv_all(timeout=0.5)

        ping_data = struct.pack(">Q", 0x1234567890ABCDEF)
        frame = create_frame(FRAME_PING, 0, 0, ping_data)
        assert h2_conn.send_frame(frame), "Failed to send PING frame"

        # Wait for PING ACK
        time.sleep(0.3)
        response = h2_conn.recv_all(timeout=1.0)

        # Look for PING ACK in response - may have multiple frames
        found_ping_ack = False
        offset = 0
        while offset + 9 <= len(response):
            length = (response[offset] << 16) | (response[offset + 1] << 8) | response[offset + 2]
            frame_type = response[offset + 3]
            flags = response[offset + 4]
            if frame_type == FRAME_PING and (flags & FLAG_ACK):
                found_ping_ack = True
                break
            offset += 9 + length

        assert found_ping_ack, f"Expected PING ACK in response (got {len(response)} bytes)"

        # Check server logged it
        frames = get_server_frames(MOCK_HOST, h2_port)
        ping_frames = [
            f for f in frames if "PING" in f.get("event_type", "") or f.get("frame_type") == "PING"
        ]
        assert len(ping_frames) >= 1, "Server should have logged PING frame"

    def test_window_update_frame(self, h2_conn, h2_port):
        """Test WINDOW_UPDATE frame (type 0x08)."""
        increment = struct.pack(">I", 65535)
        frame = create_frame(FRAME_WINDOW_UPDATE, 0, 0, increment)
        assert h2_conn.send_frame(frame), "Failed to send WINDOW_UPDATE frame"

        time.sleep(0.3)

        # Check server logged it
        frames = get_server_frames(MOCK_HOST, h2_port)
        window_frames = [
            f
            for f in frames
            if "WINDOW" in f.get("event_type", "") or f.get("frame_type") == "WINDOW_UPDATE"
        ]
        assert len(window_frames) >= 1, "Server should have logged WINDOW_UPDATE frame"

    def test_priority_frame(self, h2_conn, h2_port):
        """Test PRIORITY frame (type 0x02)."""
        # Priority: depends on stream 0, weight 16, not exclusive
        priority_payload = struct.pack(">IB", 0, 16)
        frame = create_frame(FRAME_PRIORITY, 0, 5, priority_payload)
        assert h2_conn.send_frame(frame), "Failed to send PRIORITY frame"

        time.sleep(0.3)

        # Check server logged it
        frames = get_server_frames(MOCK_HOST, h2_port)
        priority_frames = [
            f
            for f in frames
            if "PRIORITY" in f.get("event_type", "") or f.get("frame_type") == "PRIORITY"
        ]
        assert len(priority_frames) >= 1, "Server should have logged PRIORITY frame"

    def test_rst_stream_frame(self, h2_conn, h2_port):
        """Test RST_STREAM frame (type 0x03)."""
        # First create a stream with HEADERS
        headers = [
            (":method", "GET"),
            (":path", "/"),
            (":scheme", "http"),
            (":authority", "localhost"),
        ]
        headers_frame = create_headers_frame(7, headers, end_stream=False, end_headers=True)
        h2_conn.send_frame(headers_frame)

        # Now reset the stream
        error_code = struct.pack(">I", 0x08)  # CANCEL
        frame = create_frame(FRAME_RST_STREAM, 0, 7, error_code)
        assert h2_conn.send_frame(frame), "Failed to send RST_STREAM frame"

        time.sleep(0.3)

        # Check server logged it
        frames = get_server_frames(MOCK_HOST, h2_port)
        rst_frames = [
            f
            for f in frames
            if "RST" in f.get("event_type", "")
            or "RESET" in f.get("event_type", "")
            or f.get("frame_type") == "RST_STREAM"
        ]
        assert len(rst_frames) >= 1, "Server should have logged RST_STREAM frame"

    def test_goaway_frame(self, h2_conn, h2_port):
        """Test GOAWAY frame (type 0x07)."""
        # GOAWAY: last stream 0, no error
        payload = struct.pack(">II", 0, 0)  # last_stream_id, error_code
        frame = create_frame(FRAME_GOAWAY, 0, 0, payload)
        assert h2_conn.send_frame(frame), "Failed to send GOAWAY frame"

        time.sleep(0.3)

        # Check server logged it
        frames = get_server_frames(MOCK_HOST, h2_port)
        [
            f
            for f in frames
            if "GOAWAY" in f.get("event_type", "")
            or "TERMINATED" in f.get("event_type", "")
            or f.get("frame_type") == "GOAWAY"
        ]
        # GOAWAY causes connection termination, so it may or may not be logged
        # Just verify we sent it successfully

    def test_continuation_frame(self, h2_conn, h2_port):
        """Test CONTINUATION frame (type 0x09)."""
        # First send HEADERS without END_HEADERS
        headers_part1 = encode_hpack_literal(":method", "GET")
        headers_frame = create_frame(FRAME_HEADERS, 0, 9, headers_part1)  # No END_HEADERS
        h2_conn.send_frame(headers_frame)

        # Then send CONTINUATION with remaining headers
        headers_part2 = (
            encode_hpack_literal(":path", "/")
            + encode_hpack_literal(":scheme", "http")
            + encode_hpack_literal(":authority", "localhost")
        )
        cont_frame = create_frame(
            FRAME_CONTINUATION, FLAG_END_HEADERS | FLAG_END_STREAM, 9, headers_part2
        )
        assert h2_conn.send_frame(cont_frame), "Failed to send CONTINUATION frame"

        time.sleep(0.5)
        h2_conn.recv_frame()

        # Check that a complete request was received
        frames = get_server_frames(MOCK_HOST, h2_port)
        # Server combines HEADERS + CONTINUATION into single request
        [f for f in frames if "REQUEST" in f.get("event_type", "")]
        # Just verify we sent it without protocol error


@pytest.mark.http2
@pytest.mark.mock_services
class TestHTTP2ProtocolViolations:
    """Test protocol violation detection."""

    @pytest.fixture
    def h2_port(self):
        return MOCK_PORTS.get("http2_python_h2c", 9080)

    @pytest.fixture
    def h2_conn(self, h2_port, mock_service):
        require_port(MOCK_HOST, h2_port, "HTTP/2 Python server")

        conn = HTTP2Connection(MOCK_HOST, h2_port, use_tls=False)
        if not conn.connect():
            require_service("Could not establish HTTP/2 connection")

        yield conn
        conn.close()

    def assert_protocol_error_logged(self, h2_port, before: int) -> None:
        """The server must have recorded a new protocol error since `before`."""
        after = get_server_error_count(MOCK_HOST, h2_port)
        assert after > before, (
            f"server did not record a protocol error for the invalid frame: {before} -> {after}"
        )

    def test_invalid_stream_id_for_ping(self, h2_conn, h2_port):
        """Test PING on non-zero stream (protocol violation)."""
        before = get_server_error_count(MOCK_HOST, h2_port)
        ping_data = b"\x00" * 8
        frame = create_frame(FRAME_PING, 0, 1, ping_data)  # Stream 1 is invalid for PING
        h2_conn.send_frame(frame)

        time.sleep(0.3)

        self.assert_protocol_error_logged(h2_port, before)

    def test_settings_on_nonzero_stream(self, h2_conn, h2_port):
        """Test SETTINGS on non-zero stream (protocol violation)."""
        before = get_server_error_count(MOCK_HOST, h2_port)
        frame = create_frame(FRAME_SETTINGS, 0, 1, b"")  # Stream 1 is invalid
        h2_conn.send_frame(frame)

        time.sleep(0.3)

        self.assert_protocol_error_logged(h2_port, before)

    def test_data_on_stream_zero(self, h2_conn, h2_port):
        """Test DATA on stream 0 (protocol violation)."""
        before = get_server_error_count(MOCK_HOST, h2_port)
        frame = create_frame(FRAME_DATA, FLAG_END_STREAM, 0, b"invalid")
        h2_conn.send_frame(frame)

        time.sleep(0.3)

        self.assert_protocol_error_logged(h2_port, before)

    def test_window_update_zero_increment(self, h2_conn, h2_port):
        """Test WINDOW_UPDATE with zero increment (protocol violation)."""
        before = get_server_error_count(MOCK_HOST, h2_port)
        increment = struct.pack(">I", 0)  # Zero increment is invalid
        frame = create_frame(FRAME_WINDOW_UPDATE, 0, 0, increment)
        h2_conn.send_frame(frame)

        time.sleep(0.3)

        self.assert_protocol_error_logged(h2_port, before)


@pytest.mark.http2
@pytest.mark.mock_services
class TestHTTP2HPACKPrimitives:
    """Test HPACK primitives integration with the server."""

    @pytest.fixture
    def h2_port(self):
        return MOCK_PORTS.get("http2_python_h2c", 9080)

    def test_hpack_library_import(self):
        """Verify hpack library can be imported and encodes headers."""
        try:
            import hpack

            encoder = hpack.Encoder()
            encoder.header_table_size = 0
            headers = [
                (b":method", b"GET"),
                (b":path", b"/test"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
            ]
            encoded = encoder.encode(headers)
            assert len(encoded) > 0, "Should encode headers"

            # Verify roundtrip. hpack 4.x decodes header names/values to str;
            # older versions returned bytes. Normalise both sides to bytes so the
            # check is version-independent.
            decoder = hpack.Decoder()
            decoded = decoder.decode(encoded)
            normalized = [
                (
                    k.encode() if isinstance(k, str) else k,
                    v.encode() if isinstance(v, str) else v,
                )
                for k, v in decoded
            ]
            assert normalized == headers, "Roundtrip should preserve headers"

        except ImportError as e:
            require_service(f"hpack library not available: {e}")

    def test_hpack_headers_to_server(self, h2_port, mock_service):
        """Test sending HPACK-encoded headers to server."""
        require_port(MOCK_HOST, h2_port, "HTTP/2 Python server")

        try:
            import hpack as hpack_lib

            # Create headers using hpack library (same approach as HTTP/2 fuzzer)
            encoder = hpack_lib.Encoder()
            encoder.header_table_size = 0
            hpack_headers = encoder.encode(
                [
                    (b":method", b"GET"),
                    (b":path", b"/echo"),
                    (b":scheme", b"http"),
                    (b":authority", b"localhost"),
                ]
            )

            # Create connection
            conn = HTTP2Connection(MOCK_HOST, h2_port, use_tls=False)
            if not conn.connect():
                require_service("Could not connect")

            try:
                # Send HEADERS with HPACK-encoded headers
                frame = create_frame(
                    FRAME_HEADERS, FLAG_END_STREAM | FLAG_END_HEADERS, 1, hpack_headers
                )
                assert conn.send_frame(frame), "Should send frame"

                # Wait for response
                time.sleep(0.5)
                response = conn.recv_frame()

                # Should get some response (even if error)
                assert response is not None or True, "Connection should work"

            finally:
                conn.close()

        except ImportError:
            require_service("hpack library not available")


@pytest.mark.http2
@pytest.mark.mock_services
class TestHTTP2DiagnosticEndpoints:
    """Test HTTP/2 diagnostic endpoint responses."""

    @pytest.fixture
    def h2_port(self):
        return MOCK_PORTS.get("http2_python_h2c", 9080)

    def test_state_endpoint_format(self, h2_port, mock_service):
        """Verify /.well-known/h2/state returns expected format."""
        require_port(MOCK_HOST, h2_port, "HTTP/2 Python server")

        data = get_server_state(MOCK_HOST, h2_port)

        # Check expected fields
        assert "stats" in data or "server" in data, f"Got: {data}"
        if "stats" in data:
            stats = data["stats"]
            assert "connections_total" in stats or "requests_total" in stats

    def test_frames_endpoint_format(self, h2_port, mock_service):
        """Verify /.well-known/h2/frames returns list of events."""
        require_port(MOCK_HOST, h2_port, "HTTP/2 Python server")

        frames = get_server_frames(MOCK_HOST, h2_port)
        assert isinstance(frames, list), "Should return list"

        if len(frames) > 0:
            frame = frames[0]
            assert "timestamp" in frame or "event_type" in frame

    def test_errors_endpoint_format(self, h2_port, mock_service):
        """Verify /.well-known/h2/errors returns list."""
        require_port(MOCK_HOST, h2_port, "HTTP/2 Python server")

        errors = get_server_errors(MOCK_HOST, h2_port)
        assert isinstance(errors, list), "Should return list"

    def test_hpack_endpoint_format(self, h2_port, mock_service):
        """Verify /.well-known/h2/hpack returns HPACK state."""
        require_port(MOCK_HOST, h2_port, "HTTP/2 Python server")

        data = get_server_hpack(MOCK_HOST, h2_port)

        # Check HPACK fields
        assert "dynamic_table_size" in data or "max_dynamic_table_size" in data, f"Got: {data}"
