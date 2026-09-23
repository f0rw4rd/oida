"""OPC UA Protocol Monitor for fuzzing.

Provides health monitoring for OPC UA servers using the Hello/Acknowledge handshake.
"""

import socket
import struct
from typing import Optional

from oida.fuzz.monitors.base import ProtocolBaseline, ProtocolMonitor


class OPCUAMonitor(ProtocolMonitor):
    """
    OPC UA Protocol Monitor using Hello/Acknowledge handshake.

    Sends OPC UA Hello messages and validates Acknowledge responses to ensure
    the OPC UA server is responsive. This is the minimal connection-level
    health check that doesn't require SecureChannel establishment.

    Protocol Details:
    - Hello request: HELF + MessageSize + ProtocolVersion + BufferSizes + EndpointUrl
    - Acknowledge response: ACKF + MessageSize + ProtocolVersion + BufferSizes
    - Error response: ERRF + MessageSize + StatusCode + Reason

    The Hello/Acknowledge exchange negotiates buffer sizes and validates that
    the endpoint URL is accepted by the server.

    Args:
        host: Target hostname or IP
        port: Target port (default: 4840)
        timeout: Connection/receive timeout in seconds (default: 2)
        check_interval: Check every N test cases (default: 10)
        retry_count: Number of retries before failure (default: 2)
        failure_threshold: Consecutive failures before reporting down (default: 2)
        endpoint_url: Optional custom endpoint URL (default: opc.tcp://host:port)

    Returns:
        True if server responds with valid Acknowledge, False otherwise
    """

    # OPC UA message types
    MSG_HELLO = b"HEL"
    MSG_ACKNOWLEDGE = b"ACK"
    MSG_ERROR = b"ERR"
    CHUNK_FINAL = b"F"

    def __init__(
        self,
        host: str,
        port: int = 4840,
        timeout: float = 2.0,
        check_interval: int = 10,
        retry_count: int = 2,
        failure_threshold: int = 2,
        endpoint_url: Optional[str] = None,
    ):
        super().__init__(
            host=host,
            port=port,
            timeout=timeout,
            check_interval=check_interval,
            retry_count=retry_count,
            failure_threshold=failure_threshold,
        )

        # OPC UA-specific configuration
        self.endpoint_url = endpoint_url or f"opc.tcp://{host}:{port}"
        self.protocol_version = 0
        self.receive_buffer_size = 65535
        self.send_buffer_size = 65535
        self.max_message_size = 0  # 0 = unlimited
        self.max_chunk_count = 0  # 0 = unlimited

        # Server parameters from ACK response
        self.server_protocol_version: Optional[int] = None
        self.server_receive_buffer: Optional[int] = None
        self.server_send_buffer: Optional[int] = None

    def _build_hello_message(self) -> bytes:
        """Build OPC UA Hello message.

        Hello message structure:
        - Header: MessageType (3 bytes) + ChunkType (1 byte) + MessageSize (4 bytes)
        - Body: ProtocolVersion (4) + ReceiveBufferSize (4) + SendBufferSize (4)
                + MaxMessageSize (4) + MaxChunkCount (4) + EndpointUrl (length-prefixed)
        """
        endpoint_bytes = self.endpoint_url.encode("utf-8")

        # Body: ProtocolVersion + BufferSizes + EndpointUrl
        body = struct.pack(
            "<IIIII",
            self.protocol_version,
            self.receive_buffer_size,
            self.send_buffer_size,
            self.max_message_size,
            self.max_chunk_count,
        )
        # EndpointUrl: length-prefixed string (Int32 length + UTF-8 bytes)
        body += struct.pack("<I", len(endpoint_bytes)) + endpoint_bytes

        # Header: "HELF" + MessageSize (includes header size of 8)
        message_size = 8 + len(body)
        header = self.MSG_HELLO + self.CHUNK_FINAL + struct.pack("<I", message_size)

        return header + body

    def _parse_acknowledge(self, response: bytes) -> bool:
        """Parse OPC UA Acknowledge response.

        Acknowledge message structure:
        - Header: MessageType (3) + ChunkType (1) + MessageSize (4)
        - Body: ProtocolVersion (4) + ReceiveBufferSize (4) + SendBufferSize (4)
                + MaxMessageSize (4) + MaxChunkCount (4)

        Returns:
            True if valid Acknowledge, False otherwise
        """
        if len(response) < 28:  # Minimum ACK size: 8 header + 20 body
            self.logger.warning(f"Response too short for ACK ({len(response)} bytes)")
            return False

        # Check message type
        msg_type = response[:3]
        chunk_type = response[3:4]

        if msg_type == self.MSG_ERROR:
            # Error response - parse status code and reason
            if len(response) >= 16:
                status_code = struct.unpack("<I", response[8:12])[0]
                reason_len = struct.unpack("<I", response[12:16])[0]
                reason = ""
                if reason_len > 0 and reason_len != 0xFFFFFFFF and len(response) >= 16 + reason_len:
                    reason = response[16 : 16 + reason_len].decode("utf-8", errors="replace")
                self.logger.warning(
                    f"OPC UA Error: StatusCode=0x{status_code:08X}, Reason={reason}"
                )
            return False

        if msg_type != self.MSG_ACKNOWLEDGE:
            self.logger.warning(f"Expected ACK, got: {msg_type}")
            return False

        if chunk_type != self.CHUNK_FINAL:
            self.logger.warning(f"Expected final chunk, got: {chunk_type}")
            return False

        # Parse body (offset 8)
        try:
            (
                self.server_protocol_version,
                self.server_receive_buffer,
                self.server_send_buffer,
                _server_max_message,
                _server_max_chunk,
            ) = struct.unpack("<IIIII", response[8:28])
            return True
        except struct.error as e:
            self.logger.warning(f"Failed to parse ACK body: {e}")
            return False

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Single attempt to send Hello and verify Acknowledge response."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            self.logger.debug(f"Connecting to OPC UA server {self.host}:{self.port}")
            sock.connect((self.host, self.port))

            # Send Hello message
            hello_msg = self._build_hello_message()
            self.logger.debug(f"Sending Hello: {hello_msg[:20].hex()}...")
            sock.send(hello_msg)

            # Receive response
            response = sock.recv(1024)
            self.logger.debug(f"Received: {response[:20].hex() if response else 'empty'}...")

            # Parse and validate response
            if not self._parse_acknowledge(response):
                if fuzz_data_logger:
                    fuzz_data_logger.log_info(
                        f"OPCUAMonitor: Invalid response: {response[:20].hex() if response else 'empty'}"
                    )
                return False

            # Store baseline on first success
            if not self.baseline_established:
                self.baseline = ProtocolBaseline(
                    raw_response=response,
                    parsed_fields={
                        "protocol_version": self.server_protocol_version,
                    },
                )
                self.baseline_response = response
                self.baseline_established = True
                self.logger.display(
                    f"OPC UA baseline established: "
                    f"ProtocolVersion={self.server_protocol_version}, "
                    f"RecvBuffer={self.server_receive_buffer}, "
                    f"SendBuffer={self.server_send_buffer}"
                )
                if fuzz_data_logger:
                    fuzz_data_logger.log_info(
                        f"OPCUAMonitor: Baseline established "
                        f"(ProtocolVersion={self.server_protocol_version})"
                    )

            # Compare against baseline (check key fields)
            if self.baseline is None:
                return True
            baseline_version = self.baseline.get_field("protocol_version")
            if baseline_version is not None and self.server_protocol_version != baseline_version:
                self.logger.warning(
                    f"Protocol version changed: {baseline_version} -> {self.server_protocol_version}"
                )
                if fuzz_data_logger:
                    fuzz_data_logger.log_info(
                        f"OPCUAMonitor: Protocol version changed: "
                        f"{baseline_version} -> {self.server_protocol_version}"
                    )
                return False

            self.logger.debug("Hello/Acknowledge successful")
            return True

        except socket.timeout:
            self.logger.warning(f"OPC UA connection timeout ({self.timeout}s)")
            if fuzz_data_logger:
                fuzz_data_logger.log_info("OPCUAMonitor: Connection timeout")
            return False
        except ConnectionRefusedError:
            self.logger.warning("OPC UA connection refused")
            if fuzz_data_logger:
                fuzz_data_logger.log_info("OPCUAMonitor: Connection refused")
            return False
        except Exception as e:
            self.logger.warning(f"OPC UA error: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"OPCUAMonitor: Error - {str(e)}")
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except (OSError, AttributeError) as e:
                    self.logger.debug(f"Socket close error: {e}")


__all__ = ["OPCUAMonitor"]
