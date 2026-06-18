#!/usr/bin/env python3
"""
HTTP/2 Validation Server for Fuzzing Testbed

A hyper-h2 based HTTP/2 server that provides detailed protocol compliance
feedback for fuzzing. Reports frame-level events, HPACK errors, and
protocol violations via structured JSON logging.

Features:
- Frame-by-frame event logging
- HPACK decoding error detection
- Protocol violation reporting
- Diagnostic endpoints (/.well-known/h2/*)
- Both TLS and cleartext (h2c) support

Based on RFC 7540 (HTTP/2) and RFC 7541 (HPACK).
"""

import asyncio
import json
import logging
import os
import ssl
import sys
import time
import traceback
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import h2.config
import h2.connection
import h2.events
import h2.exceptions
import h2.settings

# Configure logging
LOG_LEVEL = os.environ.get("HTTP2_LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("http2-validation")

# Configuration from environment
VALIDATE_HEADERS = os.environ.get("HTTP2_VALIDATE_HEADERS", "true").lower() == "true"
LOG_HPACK = os.environ.get("HTTP2_LOG_HPACK", "true").lower() == "true"
LOG_FRAMES = os.environ.get("HTTP2_LOG_FRAMES", "true").lower() == "true"
MAX_EVENT_HISTORY = int(os.environ.get("HTTP2_MAX_EVENT_HISTORY", "1000"))


@dataclass
class FrameEvent:
    """Represents a single HTTP/2 frame event."""

    timestamp: str
    event_type: str
    stream_id: int = 0
    frame_type: str = ""
    length: int = 0
    flags: List[str] = field(default_factory=list)
    headers: Optional[List[Tuple[str, str]]] = None
    data_length: int = 0
    error_code: Optional[int] = None
    error_message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Remove None values
        return {k: v for k, v in d.items() if v is not None}


@dataclass
class ProtocolError:
    """Represents a protocol violation or error."""

    timestamp: str
    error_type: str
    error_code: str
    message: str
    stream_id: int = 0
    frame_context: Optional[Dict[str, Any]] = None
    exception_type: Optional[str] = None
    traceback: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}


class HTTP2ValidationServer:
    """HTTP/2 server with comprehensive protocol validation and logging."""

    def __init__(self, host: str = "0.0.0.0", port: int = 9080, use_tls: bool = False):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.ssl_context = None

        # Event history (circular buffer)
        self.frame_events: deque = deque(maxlen=MAX_EVENT_HISTORY)
        self.protocol_errors: deque = deque(maxlen=MAX_EVENT_HISTORY)

        # Statistics
        self.stats = {
            "connections_total": 0,
            "connections_active": 0,
            "requests_total": 0,
            "frames_received": 0,
            "frames_sent": 0,
            "protocol_errors": 0,
            "hpack_errors": 0,
            "start_time": datetime.now(timezone.utc).isoformat(),
        }

        # HPACK state tracking
        self.hpack_state = {
            "dynamic_table_size": 4096,
            "max_dynamic_table_size": 4096,
        }

        if use_tls:
            self._setup_tls()

    def _setup_tls(self):
        """Configure TLS context."""
        cert_path = Path("/app/certs/server.crt")
        key_path = Path("/app/certs/server.key")

        if not cert_path.exists() or not key_path.exists():
            logger.warning("TLS certificates not found, generating self-signed...")
            self._generate_self_signed_cert(cert_path, key_path)

        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.load_cert_chain(str(cert_path), str(key_path))
        self.ssl_context.set_alpn_protocols(["h2"])

    def _generate_self_signed_cert(self, cert_path: Path, key_path: Path):
        """Generate self-signed certificate."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime as dt

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OIDA Mock"),
                x509.NameAttribute(NameOID.COMMON_NAME, "http2-python"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.utcnow())
            .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=365))
            .sign(key, hashes.SHA256())
        )

        cert_path.parent.mkdir(parents=True, exist_ok=True)
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    def _log_frame_event(self, event_type: str, stream_id: int = 0, **kwargs):
        """Log a frame event."""
        event = FrameEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            stream_id=stream_id,
            **kwargs,
        )
        self.frame_events.append(event)
        self.stats["frames_received"] += 1

        if LOG_FRAMES:
            logger.info(f"[FRAME] {event_type} stream={stream_id} {kwargs}")

    def _log_protocol_error(
        self,
        error_type: str,
        error_code: str,
        message: str,
        stream_id: int = 0,
        exception: Optional[Exception] = None,
        frame_context: Optional[Dict] = None,
    ):
        """Log a protocol error."""
        error = ProtocolError(
            timestamp=datetime.now(timezone.utc).isoformat(),
            error_type=error_type,
            error_code=error_code,
            message=message,
            stream_id=stream_id,
            frame_context=frame_context,
            exception_type=type(exception).__name__ if exception else None,
            traceback=traceback.format_exc() if exception else None,
        )
        self.protocol_errors.append(error)
        self.stats["protocol_errors"] += 1

        logger.warning(
            f"[PROTOCOL_ERROR] {error_type}: {message} (code={error_code}, stream={stream_id})"
        )

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a single HTTP/2 connection."""
        peername = writer.get_extra_info("peername")
        logger.info(f"New connection from {peername}")

        self.stats["connections_total"] += 1
        self.stats["connections_active"] += 1

        config = h2.config.H2Configuration(
            client_side=False,
            header_encoding="utf-8",
        )
        conn = h2.connection.H2Connection(config=config)
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        await writer.drain()

        # Track stream data for building responses
        stream_data: Dict[int, Dict] = {}

        try:
            while True:
                data = await reader.read(65535)
                if not data:
                    break

                try:
                    events = conn.receive_data(data)
                except h2.exceptions.ProtocolError as e:
                    self._log_protocol_error(
                        "PROTOCOL_ERROR",
                        str(e.error_code) if hasattr(e, "error_code") else "UNKNOWN",
                        str(e),
                        exception=e,
                    )
                    # Send GOAWAY
                    conn.close_connection(error_code=h2.exceptions.ProtocolError)
                    writer.write(conn.data_to_send())
                    await writer.drain()
                    break
                except Exception as e:
                    self._log_protocol_error(
                        "HPACK_ERROR"
                        if "hpack" in str(type(e).__module__).lower()
                        else "UNKNOWN_ERROR",
                        "COMPRESSION_ERROR"
                        if "hpack" in str(type(e).__module__).lower()
                        else "INTERNAL_ERROR",
                        str(e),
                        exception=e,
                    )
                    if "hpack" in str(type(e).__module__).lower():
                        self.stats["hpack_errors"] += 1
                    break

                for event in events:
                    await self._handle_event(conn, writer, event, stream_data)

                # Send any pending data
                outbound = conn.data_to_send()
                if outbound:
                    writer.write(outbound)
                    await writer.drain()
                    self.stats["frames_sent"] += 1

        except ConnectionResetError:
            logger.info(f"Connection reset by {peername}")
        except Exception as e:
            logger.error(f"Error handling connection from {peername}: {e}")
            self._log_protocol_error("CONNECTION_ERROR", "INTERNAL_ERROR", str(e), exception=e)
        finally:
            self.stats["connections_active"] -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.info(f"Connection closed from {peername}")

    async def _handle_event(
        self,
        conn: h2.connection.H2Connection,
        writer: asyncio.StreamWriter,
        event: h2.events.Event,
        stream_data: Dict[int, Dict],
    ):
        """Handle a single h2 event."""
        event_name = type(event).__name__

        if isinstance(event, h2.events.RequestReceived):
            self._log_frame_event(
                "REQUEST_RECEIVED",
                stream_id=event.stream_id,
                headers=[(n, v) for n, v in event.headers],
                frame_type="HEADERS",
            )
            self.stats["requests_total"] += 1

            # Validate headers
            if VALIDATE_HEADERS:
                self._validate_request_headers(event.headers, event.stream_id)

            # Store request info
            stream_data[event.stream_id] = {
                "headers": dict(event.headers),
                "data": b"",
                "request_time": time.time(),
            }

            # Check if this is a diagnostic endpoint
            path = dict(event.headers).get(":path", "/")
            if path.startswith("/.well-known/h2/"):
                await self._handle_diagnostic_request(conn, writer, event.stream_id, path)
            elif not any(
                h[0] == ":method" and h[1] in ("POST", "PUT", "PATCH") for h in event.headers
            ):
                # For GET requests without body, respond immediately
                await self._send_response(
                    conn, writer, event.stream_id, stream_data.get(event.stream_id, {})
                )

        elif isinstance(event, h2.events.DataReceived):
            self._log_frame_event(
                "DATA_RECEIVED",
                stream_id=event.stream_id,
                data_length=len(event.data),
                frame_type="DATA",
            )
            if event.stream_id in stream_data:
                stream_data[event.stream_id]["data"] += event.data
            conn.acknowledge_received_data(len(event.data), event.stream_id)

        elif isinstance(event, h2.events.StreamEnded):
            self._log_frame_event(
                "STREAM_ENDED", stream_id=event.stream_id, frame_type="END_STREAM"
            )
            # Send response for streams with data
            if event.stream_id in stream_data:
                await self._send_response(
                    conn, writer, event.stream_id, stream_data[event.stream_id]
                )
                del stream_data[event.stream_id]

        elif isinstance(event, h2.events.StreamReset):
            self._log_frame_event(
                "STREAM_RESET",
                stream_id=event.stream_id,
                error_code=event.error_code,
                frame_type="RST_STREAM",
            )
            self._log_protocol_error(
                "STREAM_RESET",
                str(event.error_code),
                f"Stream {event.stream_id} reset by peer",
                stream_id=event.stream_id,
            )

        elif isinstance(event, h2.events.ConnectionTerminated):
            self._log_frame_event(
                "CONNECTION_TERMINATED",
                error_code=event.error_code,
                frame_type="GOAWAY",
                details={
                    "additional_data": event.additional_data.hex()
                    if event.additional_data
                    else None
                },
            )
            self._log_protocol_error(
                "CONNECTION_TERMINATED",
                str(event.error_code),
                f"Connection terminated: {event.additional_data}",
            )

        elif isinstance(event, h2.events.SettingsAcknowledged):
            self._log_frame_event("SETTINGS_ACKNOWLEDGED", frame_type="SETTINGS", flags=["ACK"])

        elif isinstance(event, h2.events.RemoteSettingsChanged):
            settings = {s.name: event.changed_settings[s].new_value for s in event.changed_settings}
            self._log_frame_event(
                "REMOTE_SETTINGS_CHANGED", frame_type="SETTINGS", details=settings
            )
            # Track HPACK table size changes
            if h2.settings.SettingCodes.HEADER_TABLE_SIZE in event.changed_settings:
                self.hpack_state["max_dynamic_table_size"] = event.changed_settings[
                    h2.settings.SettingCodes.HEADER_TABLE_SIZE
                ].new_value

        elif isinstance(event, h2.events.WindowUpdated):
            self._log_frame_event(
                "WINDOW_UPDATED",
                stream_id=event.stream_id,
                frame_type="WINDOW_UPDATE",
                details={"delta": event.delta},
            )

        elif isinstance(event, h2.events.PingReceived):
            self._log_frame_event(
                "PING_RECEIVED", frame_type="PING", details={"ping_data": event.ping_data.hex()}
            )

        elif isinstance(event, h2.events.PingAckReceived):
            self._log_frame_event(
                "PING_ACK_RECEIVED",
                frame_type="PING",
                flags=["ACK"],
                details={"ping_data": event.ping_data.hex()},
            )

        elif isinstance(event, h2.events.PriorityUpdated):
            self._log_frame_event(
                "PRIORITY_UPDATED",
                stream_id=event.stream_id,
                frame_type="PRIORITY",
                details={
                    "depends_on": event.depends_on,
                    "weight": event.weight,
                    "exclusive": event.exclusive,
                },
            )

        elif isinstance(event, h2.events.PushedStreamReceived):
            self._log_frame_event(
                "PUSHED_STREAM_RECEIVED",
                stream_id=event.pushed_stream_id,
                frame_type="PUSH_PROMISE",
                headers=[(n, v) for n, v in event.headers],
                details={"parent_stream_id": event.parent_stream_id},
            )

        else:
            self._log_frame_event(event_name, details={"raw_event": str(event)})

    def _validate_request_headers(self, headers: List[Tuple[str, str]], stream_id: int):
        """Validate HTTP/2 request headers per RFC 7540."""
        header_dict = {}
        pseudo_headers_done = False
        has_method = False
        has_scheme = False
        has_path = False

        for name, value in headers:
            # Check for pseudo-header order (must come first)
            if name.startswith(":"):
                if pseudo_headers_done:
                    self._log_protocol_error(
                        "HEADER_VALIDATION",
                        "PROTOCOL_ERROR",
                        f"Pseudo-header '{name}' after regular header",
                        stream_id=stream_id,
                    )
                if name == ":method":
                    has_method = True
                elif name == ":scheme":
                    has_scheme = True
                elif name == ":path":
                    has_path = True
            else:
                pseudo_headers_done = True

            # Check for uppercase (forbidden in HTTP/2)
            if any(c.isupper() for c in name):
                self._log_protocol_error(
                    "HEADER_VALIDATION",
                    "PROTOCOL_ERROR",
                    f"Uppercase character in header name '{name}'",
                    stream_id=stream_id,
                )

            # Check for connection-specific headers (forbidden)
            if name.lower() in (
                "connection",
                "keep-alive",
                "proxy-connection",
                "transfer-encoding",
                "upgrade",
            ):
                self._log_protocol_error(
                    "HEADER_VALIDATION",
                    "PROTOCOL_ERROR",
                    f"Connection-specific header '{name}' not allowed in HTTP/2",
                    stream_id=stream_id,
                )

            # Check for duplicate pseudo-headers
            if name.startswith(":") and name in header_dict:
                self._log_protocol_error(
                    "HEADER_VALIDATION",
                    "PROTOCOL_ERROR",
                    f"Duplicate pseudo-header '{name}'",
                    stream_id=stream_id,
                )

            header_dict[name] = value

        # Check required pseudo-headers
        if not has_method:
            self._log_protocol_error(
                "HEADER_VALIDATION",
                "PROTOCOL_ERROR",
                "Missing required :method pseudo-header",
                stream_id=stream_id,
            )
        if not has_scheme:
            self._log_protocol_error(
                "HEADER_VALIDATION",
                "PROTOCOL_ERROR",
                "Missing required :scheme pseudo-header",
                stream_id=stream_id,
            )
        if not has_path:
            self._log_protocol_error(
                "HEADER_VALIDATION",
                "PROTOCOL_ERROR",
                "Missing required :path pseudo-header",
                stream_id=stream_id,
            )

    async def _handle_diagnostic_request(
        self,
        conn: h2.connection.H2Connection,
        writer: asyncio.StreamWriter,
        stream_id: int,
        path: str,
    ):
        """Handle diagnostic endpoint requests."""
        # Limit results to prevent huge responses
        max_events = 100

        if path == "/.well-known/h2/state":
            body = json.dumps(
                {
                    "server": "http2-python-validation",
                    "stats": self.stats,
                    "hpack_state": self.hpack_state,
                },
                indent=2,
            )
        elif path == "/.well-known/h2/frames":
            # Return most recent events only
            recent_events = list(self.frame_events)[-max_events:]
            body = json.dumps([e.to_dict() for e in recent_events], indent=2)
        elif path == "/.well-known/h2/errors":
            # Return most recent errors only
            recent_errors = list(self.protocol_errors)[-max_events:]
            body = json.dumps([e.to_dict() for e in recent_errors], indent=2)
        elif path == "/.well-known/h2/hpack":
            body = json.dumps(self.hpack_state, indent=2)
        else:
            body = json.dumps({"error": "Unknown diagnostic endpoint"})

        body_bytes = body.encode("utf-8")
        response_headers = [
            (":status", "200"),
            ("content-type", "application/json"),
            ("content-length", str(len(body_bytes))),
            ("server", "http2-validation-server"),
        ]

        conn.send_headers(stream_id, response_headers)

        # Chunk body to fit within max frame size (16384 bytes default)
        max_chunk_size = 16384
        offset = 0
        while offset < len(body_bytes):
            chunk = body_bytes[offset : offset + max_chunk_size]
            end_stream = offset + len(chunk) >= len(body_bytes)
            conn.send_data(stream_id, chunk, end_stream=end_stream)
            writer.write(conn.data_to_send())
            await writer.drain()
            offset += len(chunk)

    async def _send_response(
        self,
        conn: h2.connection.H2Connection,
        writer: asyncio.StreamWriter,
        stream_id: int,
        request_info: Dict,
    ):
        """Send HTTP response."""
        headers = request_info.get("headers", {})
        path = headers.get(":path", "/")
        method = headers.get(":method", "GET")

        # Echo endpoint
        if path == "/echo":
            body = json.dumps(
                {
                    "method": method,
                    "path": path,
                    "headers": headers,
                    "body": request_info.get("data", b"").decode("utf-8", errors="replace"),
                    "body_length": len(request_info.get("data", b"")),
                },
                indent=2,
            ).encode("utf-8")
            status = "200"
        # Status code endpoint
        elif path.startswith("/status/"):
            try:
                status = path.split("/status/")[1].split("/")[0]
                int(status)  # Validate it's a number
            except (ValueError, IndexError):
                status = "400"
            body = f'{{"status": {status}}}'.encode("utf-8")
        # Delay endpoint
        elif path.startswith("/delay/"):
            try:
                delay = float(path.split("/delay/")[1].split("/")[0])
                await asyncio.sleep(min(delay, 30))  # Max 30 seconds
            except (ValueError, IndexError):
                delay = 0
            body = f'{{"delayed": {delay}}}'.encode("utf-8")
            status = "200"
        # Default response
        else:
            body = json.dumps(
                {
                    "message": "HTTP/2 Validation Server",
                    "path": path,
                    "method": method,
                    "endpoints": {
                        "/echo": "Echo request back",
                        "/status/{code}": "Return specific status code",
                        "/delay/{seconds}": "Delayed response",
                        "/.well-known/h2/state": "Server state",
                        "/.well-known/h2/frames": "Recent frame events",
                        "/.well-known/h2/errors": "Protocol errors",
                        "/.well-known/h2/hpack": "HPACK table state",
                    },
                },
                indent=2,
            ).encode("utf-8")
            status = "200"

        response_headers = [
            (":status", status),
            ("content-type", "application/json"),
            ("content-length", str(len(body))),
            ("server", "http2-validation-server"),
            ("x-stream-id", str(stream_id)),
        ]

        try:
            conn.send_headers(stream_id, response_headers)
            conn.send_data(stream_id, body, end_stream=True)
            writer.write(conn.data_to_send())
            await writer.drain()
        except h2.exceptions.ProtocolError as e:
            self._log_protocol_error(
                "RESPONSE_ERROR",
                str(e.error_code) if hasattr(e, "error_code") else "UNKNOWN",
                f"Failed to send response: {e}",
                stream_id=stream_id,
                exception=e,
            )

    async def start(self):
        """Start the HTTP/2 server."""
        if self.use_tls:
            server = await asyncio.start_server(
                self.handle_connection, self.host, self.port, ssl=self.ssl_context
            )
            proto = "h2 (TLS)"
        else:
            server = await asyncio.start_server(self.handle_connection, self.host, self.port)
            proto = "h2c (cleartext)"

        addr = server.sockets[0].getsockname()
        logger.info(f"HTTP/2 Validation Server listening on {addr[0]}:{addr[1]} ({proto})")
        logger.info("Diagnostic endpoints: /.well-known/h2/{state,frames,errors,hpack}")

        async with server:
            await server.serve_forever()


async def main():
    """Main entry point."""
    # Parse configuration from environment
    h2c_port = int(os.environ.get("HTTP2_H2C_PORT", "9080"))
    tls_port = int(os.environ.get("HTTP2_TLS_PORT", "9443"))
    host = os.environ.get("HTTP2_HOST", "0.0.0.0")
    enable_tls = os.environ.get("HTTP2_ENABLE_TLS", "true").lower() == "true"
    enable_h2c = os.environ.get("HTTP2_ENABLE_H2C", "true").lower() == "true"

    servers = []

    if enable_h2c:
        h2c_server = HTTP2ValidationServer(host=host, port=h2c_port, use_tls=False)
        servers.append(h2c_server.start())

    if enable_tls:
        tls_server = HTTP2ValidationServer(host=host, port=tls_port, use_tls=True)
        servers.append(tls_server.start())

    if not servers:
        logger.error("No servers enabled! Set HTTP2_ENABLE_TLS=true or HTTP2_ENABLE_H2C=true")
        sys.exit(1)

    logger.info("Starting HTTP/2 Validation Testbed...")
    await asyncio.gather(*servers)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down...")
