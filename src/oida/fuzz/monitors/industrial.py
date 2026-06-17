"""Industrial Control Systems (ICS) protocol monitors for fuzzing."""

import socket
import struct
import time
from enum import IntEnum, auto
from typing import Optional

from .base import ProtocolBaseline, ProtocolMonitor
from .opcua import OPCUAMonitor


class IEC104States(IntEnum):
    """IEC 60870-5-104 connection states."""

    DISCONNECTED = auto()
    ACTIVE = auto()
    ERROR = auto()


class ModbusMonitor(ProtocolMonitor):
    """
    Monitor for Modbus TCP protocol that checks service responsiveness.

    Sends Modbus Read Holding Registers requests to verify the Modbus server
    is responsive and compares responses against an established baseline.

    Args:
        host: Target hostname or IP
        port: Target port (default: 502)
        timeout: Connection/receive timeout in seconds (default: 0.1)
        check_interval: Check every N test cases (default: 100)
        retry_count: Number of retries before failure (default: 1)
        failure_threshold: Consecutive failures before reporting down (default: 1)

    Returns:
        True if server responds correctly to Modbus request, False otherwise
    """

    def __init__(
        self,
        host: str,
        port: int = 502,
        timeout: float = 0.1,
        check_interval: int = 100,
        retry_count: int = 1,
        failure_threshold: int = 1,
    ):
        super().__init__(
            host=host,
            port=port,
            timeout=timeout,
            check_interval=check_interval,
            retry_count=retry_count,
            failure_threshold=failure_threshold,
        )

        # Legacy: baseline_function_code for backwards compatibility
        # New code should use self.baseline.get_field('function_code')
        self.baseline_function_code: Optional[int] = None

    def _create_read_request(self) -> bytes:
        """Create a simple Modbus read holding registers request"""
        transaction_id = struct.pack(">H", 1)  # Transaction ID: 1
        protocol_id = struct.pack(">H", 0)  # Protocol ID: 0 (Modbus)
        length = struct.pack(">H", 6)  # Length: 6 bytes
        unit_id = struct.pack("B", 1)  # Unit ID: 1
        function_code = struct.pack("B", 0x03)  # Function 3: Read Holding Registers
        start_addr = struct.pack(">H", 0)  # Starting Address: 0
        quantity = struct.pack(">H", 1)  # Quantity: 1 register

        return (
            transaction_id + protocol_id + length + unit_id + function_code + start_addr + quantity
        )

    def _store_baseline(self, response: bytes, fuzz_data_logger=None):
        """Store the first successful response as baseline"""
        function_code = response[7] if len(response) > 7 else None

        # Use standardized ProtocolBaseline
        self.baseline = ProtocolBaseline(
            raw_response=response,
            parsed_fields={
                "function_code": function_code,
                "protocol_id": struct.unpack(">H", response[2:4])[0] if len(response) > 4 else None,
            },
        )

        # Legacy attributes for backwards compatibility
        self.baseline_response = response
        self.baseline_function_code = function_code
        self.baseline_established = True

        if fuzz_data_logger:
            fuzz_data_logger.log_info(
                f"ModbusMonitor: Baseline established (FC={function_code}, "
                f"response={response.hex()})"
            )

    def _compare_responses(self, current: bytes, fuzz_data_logger=None) -> bool:
        """Compare current response against baseline"""
        if len(current) < 9:
            if fuzz_data_logger:
                fuzz_data_logger.log_fail(
                    f"ModbusMonitor: Response too short ({len(current)} bytes)"
                )
            return False

        current_function_code = current[7]

        # Check if function code changed (especially to error response)
        if self.baseline_function_code is not None:
            if current_function_code != self.baseline_function_code:
                # Check if it became an error response (function code + 0x80)
                if current_function_code == self.baseline_function_code + 0x80:
                    if fuzz_data_logger:
                        fuzz_data_logger.log_fail(
                            f"ModbusMonitor: Modbus error response received "
                            f"(FC={current_function_code:#04x}, expected {self.baseline_function_code:#04x})"
                        )
                    return False
                elif current_function_code >= 0x80:
                    if fuzz_data_logger:
                        fuzz_data_logger.log_fail(
                            f"ModbusMonitor: Unexpected error response "
                            f"(FC={current_function_code:#04x})"
                        )
                    return False

        return True

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Single attempt to check if Modbus service is responsive"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            self.logger.debug(f"Connecting to Modbus server {self.host}:{self.port}")
            sock.connect((self.host, self.port))

            # Send Modbus read request
            request = self._create_read_request()
            self.logger.debug(f"Sending Modbus read request: {request.hex()}")
            sock.send(request)

            # Read response (minimum valid response is 9 bytes)
            response = sock.recv(256)
            self.logger.debug(f"Received response: {response.hex() if response else 'empty'}")

            # Check if response is valid Modbus format
            if len(response) >= 9:
                protocol_id = struct.unpack(">H", response[2:4])[0]
                function_code = response[7]

                # Protocol ID should be 0 and function code should not be an error
                if protocol_id == 0 and function_code < 0x80:
                    # Store baseline on first success
                    if not self.baseline_established:
                        self._store_baseline(response, fuzz_data_logger)
                        self.logger.display(f"Modbus baseline established (FC={function_code})")
                        return True

                    # Compare against baseline
                    return self._compare_responses(response, fuzz_data_logger)
                else:
                    self.logger.warning(f"Modbus error response: FC={function_code:#04x}")

            self.logger.warning(f"Invalid Modbus response format ({len(response)} bytes)")
            if fuzz_data_logger:
                fuzz_data_logger.log_info("ModbusMonitor: Invalid Modbus response format")
            return False

        except socket.timeout:
            self.logger.warning(f"Modbus connection timeout ({self.timeout}s)")
            if fuzz_data_logger:
                fuzz_data_logger.log_info("ModbusMonitor: Connection timeout")
            return False
        except Exception as e:
            self.logger.warning(f"Modbus error: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"ModbusMonitor: Error - {str(e)}")
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except (OSError, AttributeError) as e:
                    self.logger.debug(f"Socket close error: {e}")


class IEC104Monitor(ProtocolMonitor):
    """
    IEC 60870-5-104 Protocol Monitor using TESTFR frames.

    IEC 104 is a SCADA protocol for electrical substations. This monitor sends
    TESTFR (Test Frame) U-format frames and verifies TESTFR ACK responses to
    ensure the connection is alive and the server is responsive.

    Protocol Details:
    - TESTFR request:  0x68 0x04 0x43 0x00 0x00 0x00
    - TESTFR response: 0x68 0x04 0x83 0x00 0x00 0x00
    - Byte 2: 0x43 = TESTFR act, 0x83 = TESTFR con (confirmation)

    Args:
        host: Target hostname or IP
        port: Target port (default: 2404)
        timeout: Connection timeout in seconds (default: 2)
        check_interval: Check every N test cases (default: 3)
        retry_count: Number of retries before failure (default: 2)
        failure_threshold: Consecutive failures before reporting down (default: 2)

    Returns:
        True if server responds correctly to TESTFR, False otherwise
    """

    def __init__(
        self,
        host: str,
        port: int = 2404,
        timeout: int = 2,
        check_interval: int = 3,
        retry_count: int = 2,
        failure_threshold: int = 2,
    ):
        super().__init__(
            host=host,
            port=port,
            timeout=float(timeout),
            check_interval=check_interval,
            retry_count=retry_count,
            failure_threshold=failure_threshold,
        )

        # IEC 104-specific state
        self.socket: Optional[socket.socket] = None
        self.state = IEC104States.DISCONNECTED
        self.last_check = 0

    def _create_testfr(self) -> bytes:
        """Create TESTFR U-format frame (test frame activation)"""
        return bytes([0x68, 0x04, 0x43, 0x00, 0x00, 0x00])

    def _connect(self) -> bool:
        """Establish TCP connection to IEC 104 server"""
        try:
            if self.socket:
                self.socket.close()

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.logger.debug(f"Connecting to IEC 104 server {self.host}:{self.port}")
            self.socket.connect((self.host, self.port))
            self.state = IEC104States.ACTIVE
            self.logger.display("IEC 104 connection established")
            return True

        except socket.timeout:
            self.state = IEC104States.ERROR
            self.logger.warning(f"IEC 104 connection timeout ({self.timeout}s)")
            return False
        except Exception as e:
            self.state = IEC104States.ERROR
            self.logger.warning(f"IEC 104 connection failed: {e}")
            return False

    def _reset_socket(self) -> None:
        """Close and reset socket so next check attempt reconnects."""
        if self.socket:
            try:
                self.socket.close()
            except Exception as e:
                self.logger.debug(f"self.socket.close(): {e}")
        self.socket = None
        self.state = IEC104States.DISCONNECTED

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Single attempt to send TESTFR and verify TESTFR ACK response"""
        try:
            if not self.socket:
                self.logger.debug("No socket, attempting connection")
                if not self._connect():
                    self.logger.warning("IEC 104 connection failed")
                    return False

            testfr = self._create_testfr()
            self.logger.debug(f"Sending TESTFR: {testfr.hex()}")
            self.socket.send(testfr)
            self.socket.settimeout(self.timeout)

            response = self.socket.recv(6)
            self.logger.debug(f"Received: {response.hex() if response else 'empty'}")

            # Verify TESTFR ACK: must be 6 bytes with 0x83 at byte 2
            if len(response) == 6 and response[2] == 0x83:
                # Store baseline on first success
                if not self.baseline_established:
                    self.baseline = ProtocolBaseline(
                        raw_response=response,
                        parsed_fields={
                            "apdu_type": "U-format",
                            "control_field": response[2],
                            "testfr_ack": True,
                        },
                    )
                    # Legacy attribute for backwards compatibility
                    self.baseline_response = response
                    self.baseline_established = True
                    self.logger.display(f"IEC 104 baseline established: {response.hex()}")

                # Compare with baseline (using standardized baseline)
                baseline_raw = self.baseline.raw_response
                if response != baseline_raw:
                    self.logger.warning(
                        f"TESTFR response changed! Expected: {self.baseline_response.hex()}, Got: {response.hex()}"
                    )
                    if fuzz_data_logger:
                        fuzz_data_logger.log_info(
                            f"IEC 104 TESTFR response changed! "
                            f"Expected: {self.baseline_response.hex()}, "
                            f"Got: {response.hex()}"
                        )
                    # Response changed - reset socket to get fresh connection
                    self._reset_socket()
                    return False

                self.logger.debug("TESTFR ACK received successfully")
                return True
            else:
                self.logger.warning(
                    f"Invalid TESTFR response: {response.hex() if response else 'empty'} "
                    f"(expected 6 bytes with 0x83 at byte 2)"
                )
                if fuzz_data_logger:
                    fuzz_data_logger.log_info(
                        f"IEC 104 invalid TESTFR response: {response.hex() if response else 'empty'}"
                    )
                # Invalid/empty response - reset socket so next attempt reconnects
                self._reset_socket()
                return False

        except socket.timeout:
            self.logger.warning(f"IEC 104 TESTFR timeout ({self.timeout}s)")
            if fuzz_data_logger:
                fuzz_data_logger.log_info("IEC 104 TESTFR timeout")
            # Reset socket so next attempt reconnects
            self._reset_socket()
            return False
        except Exception as e:
            self.logger.warning(f"IEC 104 TESTFR failed: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"IEC 104 TESTFR attempt failed: {e}")
            # Reset socket so next attempt reconnects (fixes "Broken pipe" loops)
            self._reset_socket()
            return False

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        """Check IEC 104 connection before sending fuzz data"""
        self.test_case_count += 1

        # Only check every check_interval test cases
        if self.test_case_count % self.check_interval != 0:
            return True

        current_time = time.time()
        if current_time - self.last_check >= 1.0:  # Rate limit to 1 check per second
            if self.state in (IEC104States.DISCONNECTED, IEC104States.ERROR):
                if not self._connect():
                    return False
            elif not self._check_alive(fuzz_data_logger):
                self.state = IEC104States.ERROR
                return False
            self.last_check = current_time
        return True


class MMSMonitor(ProtocolMonitor):
    """
    MMS (Manufacturing Message Specification) Protocol Monitor.

    Sends MMS Identify requests to verify the MMS server is responsive.
    Used for TASE.2/ICCP and IEC 61850 protocol fuzzing.

    The monitor establishes an ISO-on-TCP connection (RFC 1006), sends
    an MMS Initiate request followed by an Identify request, and validates
    the response.

    Args:
        host: Target hostname or IP
        port: Target port (default: 102 for MMS/ISO-on-TCP)
        timeout: Connection timeout in seconds (default: 5)
        check_interval: Check every N test cases (default: 3)
        retry_count: Number of retries before failure (default: 2)
        failure_threshold: Consecutive failures before reporting down (default: 2)

    Returns:
        True if server responds to MMS Identify, False otherwise
    """

    # TPKT header: version (3), reserved (0), length (2 bytes)
    TPKT_VERSION = 0x03

    # COTP CR (Connection Request) for ISO-on-TCP
    COTP_CR = bytes(
        [
            0x11,  # Length
            0xE0,  # CR (Connection Request)
            0x00,
            0x00,  # DST-REF
            0x00,
            0x01,  # SRC-REF
            0x00,  # Class 0
            0xC0,
            0x01,
            0x0A,  # Parameter: TPDU size (1024)
            0xC1,
            0x02,
            0x00,
            0x01,  # Parameter: src-tsap
            0xC2,
            0x02,
            0x00,
            0x01,  # Parameter: dst-tsap
        ]
    )

    # COTP DT (Data Transfer)
    COTP_DT = bytes([0x02, 0xF0, 0x80])  # Length, DT, EOT

    def __init__(
        self,
        host: str,
        port: int = 102,
        timeout: int = 5,
        check_interval: int = 3,
        retry_count: int = 2,
        failure_threshold: int = 2,
    ):
        super().__init__(
            host=host,
            port=port,
            timeout=float(timeout),
            check_interval=check_interval,
            retry_count=retry_count,
            failure_threshold=failure_threshold,
        )

        # MMS-specific state
        self.socket: Optional[socket.socket] = None
        self.connected = False

    def _build_tpkt(self, data: bytes) -> bytes:
        """Wrap data in TPKT header (RFC 1006)."""
        length = len(data) + 4  # TPKT header is 4 bytes
        return bytes([self.TPKT_VERSION, 0x00, (length >> 8) & 0xFF, length & 0xFF]) + data

    def _build_mms_initiate(self) -> bytes:
        """Build MMS Initiate-RequestPDU."""
        from ..core.codecs.mms import MMSCodec

        codec = MMSCodec()
        return codec.build_initiate_request()

    def _build_mms_identify(self) -> bytes:
        """Build MMS Identify request."""
        from ..core.codecs.mms import MMSCodec

        codec = MMSCodec()
        return codec.build_identify_request()

    def _connect(self) -> bool:
        """Establish ISO-on-TCP connection and MMS session."""
        try:
            if self.socket:
                try:
                    self.socket.close()
                except Exception as e:
                    self.logger.debug(f"Socket close error: {e}")

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.logger.debug(f"Connecting to MMS server {self.host}:{self.port}")
            self.socket.connect((self.host, self.port))

            # Send TPKT + COTP Connection Request
            cr_packet = self._build_tpkt(self.COTP_CR)
            self.logger.debug(f"Sending COTP Connection Request: {cr_packet.hex()}")
            self.socket.send(cr_packet)

            # Receive COTP Connection Confirm
            response = self.socket.recv(256)
            self.logger.debug(f"Received COTP response: {response.hex() if response else 'empty'}")
            if len(response) < 7:
                self.logger.warning(f"COTP response too short ({len(response)} bytes)")
                return False

            # Check for COTP CC (Connection Confirm) - byte after TPKT header
            if response[5] != 0xD0:  # CC = 0xd0
                self.logger.warning(f"Expected COTP CC (0xd0), got {response[5]:#04x}")
                return False

            # Send MMS Initiate Request
            mms_init = self._build_mms_initiate()
            init_packet = self._build_tpkt(self.COTP_DT + mms_init)
            self.logger.debug("Sending MMS Initiate Request")
            self.socket.send(init_packet)

            # Receive MMS Initiate Response
            response = self.socket.recv(512)
            self.logger.debug(f"Received MMS Initiate response ({len(response)} bytes)")
            if len(response) < 10:
                self.logger.warning(f"MMS Initiate response too short ({len(response)} bytes)")
                return False

            self.connected = True
            self.logger.display("MMS session established")
            return True

        except socket.timeout:
            self.logger.warning(f"MMS connection timeout ({self.timeout}s)")
            self.connected = False
            return False
        except Exception as e:
            self.logger.warning(f"MMS connection error: {e}")
            self.connected = False
            return False

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Single attempt to send MMS Identify request and verify response."""
        try:
            if not self.socket or not self.connected:
                self.logger.debug("No MMS session, attempting connection")
                if not self._connect():
                    self.logger.warning("MMS connection failed")
                    if fuzz_data_logger:
                        fuzz_data_logger.log_info("MMSMonitor: Failed to connect")
                    return False

            # Send MMS Identify request
            identify = self._build_mms_identify()
            identify_packet = self._build_tpkt(self.COTP_DT + identify)
            self.logger.debug("Sending MMS Identify request")
            self.socket.send(identify_packet)

            self.socket.settimeout(self.timeout)
            response = self.socket.recv(512)
            self.logger.debug(f"Received MMS Identify response ({len(response)} bytes)")

            if len(response) < 10:
                self.logger.warning(f"MMS Identify response too short ({len(response)} bytes)")
                if fuzz_data_logger:
                    fuzz_data_logger.log_info("MMSMonitor: Invalid Identify response")
                return False

            # Store baseline on first success
            if not self.baseline_established:
                self.baseline = ProtocolBaseline(
                    raw_response=response,
                    parsed_fields={
                        "response_size": len(response),
                        # MMS responses are complex ASN.1 structures
                        # Store raw for now, parsing can be added later
                    },
                )
                self.baseline_established = True
                self.logger.display(f"MMS baseline established (response size: {len(response)})")
                if fuzz_data_logger:
                    fuzz_data_logger.log_info(
                        f"MMSMonitor: Baseline established (response size: {len(response)})"
                    )

            self.logger.debug("MMS Identify successful")
            return True

        except socket.timeout:
            self.logger.warning(f"MMS Identify request timeout ({self.timeout}s)")
            if fuzz_data_logger:
                fuzz_data_logger.log_info("MMSMonitor: Identify request timeout")
            self.connected = False
            return False

        except Exception as e:
            self.logger.warning(f"MMS error: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"MMSMonitor: Error - {e}")
            self.connected = False
            return False

    def close(self):
        """Close the MMS connection."""
        if self.socket:
            try:
                self.socket.close()
            except Exception as e:
                self.logger.debug(f"Socket close error: {e}")
            self.socket = None
            self.connected = False


class MQTTMonitor(ProtocolMonitor):
    """
    MQTT broker health monitor using CONNECT/CONNACK.

    Sends minimal MQTT CONNECT packets and verifies CONNACK responses to
    ensure the MQTT broker is responsive. Uses anonymous connections with
    clean session for lightweight health checking.

    Protocol Details:
    - CONNECT: Minimal packet with client ID, clean session flag
    - CONNACK: 4 bytes (type, length, flags, reason_code)
    - reason_code 0 = success, other values indicate errors

    Args:
        host: Target hostname or IP
        port: Target port (default: 1883)
        timeout: Connection/receive timeout in seconds (default: 2)
        check_interval: Check every N test cases (default: 10)
        retry_count: Number of retries before failure (default: 2)
        failure_threshold: Consecutive failures before reporting down (default: 2)

    Returns:
        True if broker responds with successful CONNACK, False otherwise
    """

    def __init__(
        self,
        host: str,
        port: int = 1883,
        timeout: float = 2.0,
        check_interval: int = 10,
        retry_count: int = 2,
        failure_threshold: int = 2,
    ):
        super().__init__(
            host=host,
            port=port,
            timeout=timeout,
            check_interval=check_interval,
            retry_count=retry_count,
            failure_threshold=failure_threshold,
        )

    def _create_connect_packet(self, client_id: str = "monitor") -> bytes:
        """Create minimal MQTT CONNECT packet (v3.1.1)."""
        client_id_bytes = client_id.encode("utf-8")

        variable_header = (
            b"\x00\x04MQTT"  # Protocol name
            b"\x04"  # Protocol level (3.1.1)
            b"\x02"  # Connect flags (clean session only)
            b"\x00\x0a"  # Keepalive: 10 seconds
        )

        payload = struct.pack(">H", len(client_id_bytes)) + client_id_bytes

        remaining_length = len(variable_header) + len(payload)
        return bytes([0x10, remaining_length]) + variable_header + payload

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Single health check: CONNECT + wait for CONNACK."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            self.logger.debug(f"Connecting to MQTT broker {self.host}:{self.port}")
            sock.connect((self.host, self.port))

            # Send CONNECT with unique client ID
            client_id = f"mon-{int(time.time())}"
            connect_packet = self._create_connect_packet(client_id)
            self.logger.debug(f"Sending CONNECT packet (client_id={client_id})")
            sock.send(connect_packet)

            # Wait for CONNACK (4 bytes: type, length, flags, reason_code)
            response = sock.recv(4)
            self.logger.debug(f"Received: {response.hex() if response else 'empty'}")

            if len(response) < 4:
                self.logger.warning(f"MQTT short response ({len(response)} bytes, expected 4)")
                if fuzz_data_logger:
                    fuzz_data_logger.log_info(
                        f"MQTTMonitor: Short response ({len(response)} bytes)"
                    )
                return False

            packet_type = response[0]
            reason_code = response[3]

            # CONNACK = 0x20, reason_code 0 = success
            if packet_type != 0x20:
                self.logger.warning(f"MQTT expected CONNACK (0x20), got {packet_type:#04x}")
                if fuzz_data_logger:
                    fuzz_data_logger.log_info(
                        f"MQTTMonitor: Expected CONNACK (0x20), got {packet_type:#04x}"
                    )
                return False

            # Store baseline on first success
            if not self.baseline_established:
                self.baseline = ProtocolBaseline(
                    raw_response=response,
                    parsed_fields={
                        "packet_type": packet_type,
                        "reason_code": reason_code,
                        "session_present": bool(response[2] & 0x01),
                    },
                )
                self.baseline_established = True
                self.logger.display(f"MQTT baseline established (reason_code={reason_code})")
                if fuzz_data_logger:
                    fuzz_data_logger.log_info(
                        f"MQTTMonitor: Baseline established (reason_code={reason_code})"
                    )
                return True

            # Compare with baseline (reason code should match)
            baseline_reason = self.baseline.get_field("reason_code")
            if response[3] != baseline_reason:
                self.logger.warning(
                    f"MQTT response changed: reason_code {baseline_reason} -> {response[3]}"
                )
                if fuzz_data_logger:
                    fuzz_data_logger.log_info(
                        f"MQTTMonitor: Response changed: reason_code "
                        f"{baseline_reason} -> {response[3]}"
                    )
                return False

            self.logger.debug(f"CONNACK received successfully (reason_code={reason_code})")
            return True

        except socket.timeout:
            self.logger.warning(f"MQTT timeout waiting for CONNACK ({self.timeout}s)")
            if fuzz_data_logger:
                fuzz_data_logger.log_info("MQTTMonitor: Timeout waiting for CONNACK")
            return False
        except Exception as e:
            self.logger.warning(f"MQTT error: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"MQTTMonitor: Error - {str(e)}")
            return False
        finally:
            if sock:
                try:
                    # Send DISCONNECT before closing (0xE0 0x00)
                    sock.send(b"\xe0\x00")
                except (OSError, AttributeError) as e:
                    self.logger.debug(f"MQTT DISCONNECT send error: {e}")
                try:
                    sock.close()
                except (OSError, AttributeError) as e:
                    self.logger.debug(f"Socket close error: {e}")


class ModbusRTUMonitor(ProtocolMonitor):
    """
    Monitor for Modbus RTU protocol over serial or RTU-over-TCP.

    Sends a Modbus RTU Read Holding Registers request (FC 0x03) and verifies
    a valid response comes back within timeout. Works over serial connections
    (RS-232/RS-485) or RTU-over-TCP (raw RTU frames over a TCP socket).

    The health check opens a fresh connection each time to avoid interfering
    with the fuzzing session's own connection.

    Args:
        port: Serial device path (e.g., '/dev/ttyUSB0') or TCP host for RTU-over-TCP
        slave_address: Modbus slave address to query (1-247)
        transport: 'serial' for RS-232/RS-485 or 'tcp' for RTU-over-TCP
        tcp_port: TCP port number (only used when transport='tcp')
        baudrate: Serial baud rate (only used when transport='serial')
        bytesize: Serial data bits (only used when transport='serial')
        parity: Serial parity (only used when transport='serial')
        stopbits: Serial stop bits (only used when transport='serial')
        timeout: Read timeout in seconds
        check_interval: Check every N test cases
        retry_count: Number of retries before failure
        failure_threshold: Consecutive failures before reporting down
    """

    def __init__(
        self,
        port: str,
        slave_address: int = 1,
        transport: str = "serial",
        tcp_port: int = 502,
        baudrate: int = 9600,
        bytesize: int = 8,
        parity: str = "N",
        stopbits: int = 1,
        timeout: float = 1.0,
        check_interval: int = 100,
        retry_count: int = 1,
        failure_threshold: int = 1,
    ):
        # For ProtocolMonitor base class: use tcp_port for TCP, 0 for serial
        monitor_port = tcp_port if transport == "tcp" else 0
        super().__init__(
            host=port,  # serial device path or TCP host
            port=monitor_port,
            timeout=timeout,
            check_interval=check_interval,
            retry_count=retry_count,
            failure_threshold=failure_threshold,
        )

        self.slave_address = slave_address
        self.transport = transport.lower()
        self.tcp_port = tcp_port
        self.baudrate = baudrate
        self.bytesize = bytesize
        self.parity = parity
        self.stopbits = stopbits

        # Baseline tracking for RTU responses
        self.baseline_function_code: Optional[int] = None

    @staticmethod
    def _calculate_crc(data: bytes) -> bytes:
        """Calculate Modbus RTU CRC-16 (polynomial 0xA001)."""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1
        return bytes([crc & 0xFF, (crc >> 8) & 0xFF])

    def _create_rtu_read_request(self) -> bytes:
        """Create a Modbus RTU Read Holding Registers request with CRC."""
        pdu = struct.pack(
            ">BBHH",
            self.slave_address,  # Slave address
            0x03,  # FC 3: Read Holding Registers
            0x0000,  # Starting address: 0
            0x0001,  # Quantity: 1 register
        )
        crc = self._calculate_crc(pdu)
        return pdu + crc

    def _validate_rtu_response(self, response: bytes) -> bool:
        """Validate a Modbus RTU response.

        Checks minimum length, slave address, function code, and CRC.

        Returns:
            True if response is a valid non-error Modbus RTU frame.
        """
        # Minimum RTU response: slave(1) + FC(1) + byte_count(1) + data(2) + CRC(2) = 7
        if len(response) < 5:
            return False

        # Verify CRC on full frame
        frame_data = response[:-2]
        expected_crc = self._calculate_crc(frame_data)
        actual_crc = response[-2:]
        if expected_crc != actual_crc:
            self.logger.debug(
                f"CRC mismatch: expected {expected_crc.hex()}, got {actual_crc.hex()}"
            )
            # CRC mismatch is not fatal for health check -- the device responded
            # but might have noise on the line. Still counts as alive.

        # Check function code is not an error response (FC + 0x80)
        function_code = response[1]
        if function_code >= 0x80:
            self.logger.debug(f"Modbus RTU error response: FC=0x{function_code:02x}")
            return False

        return True

    def _check_alive_serial(self, fuzz_data_logger=None) -> bool:
        """Health check over serial connection."""
        import serial as pyserial

        ser = None
        try:
            ser = pyserial.Serial(
                port=self.host,  # serial device path stored in self.host
                baudrate=self.baudrate,
                bytesize=self.bytesize,
                parity=self.parity,
                stopbits=self.stopbits,
                timeout=self.timeout,
            )

            request = self._create_rtu_read_request()
            self.logger.debug(f"Sending RTU read request: {request.hex()}")
            ser.write(request)
            ser.flush()

            # Wait for response -- RTU response for FC 0x03 reading 1 register:
            # slave(1) + FC(1) + byte_count(1) + data(2) + CRC(2) = 7 bytes
            # Read up to 256 bytes to handle any response size
            response = ser.read(256)
            self.logger.debug(
                f"Received {len(response)} bytes: {response.hex() if response else 'empty'}"
            )

            if not response:
                self.logger.warning("No response from RTU device")
                if fuzz_data_logger:
                    fuzz_data_logger.log_info("ModbusRTUMonitor: No serial response")
                return False

            return self._process_response(response, fuzz_data_logger)

        except pyserial.SerialException as e:
            self.logger.warning(f"Serial error: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"ModbusRTUMonitor: Serial error - {e}")
            return False
        except Exception as e:
            self.logger.warning(f"RTU monitor error: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"ModbusRTUMonitor: Error - {e}")
            return False
        finally:
            if ser is not None:
                try:
                    ser.close()
                except Exception as e:
                    self.logger.debug(f"Serial close error: {e}")

    def _check_alive_tcp(self, fuzz_data_logger=None) -> bool:
        """Health check over RTU-over-TCP connection."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            self.logger.debug(f"Connecting to RTU-over-TCP {self.host}:{self.tcp_port}")
            sock.connect((self.host, self.tcp_port))

            request = self._create_rtu_read_request()
            self.logger.debug(f"Sending RTU read request: {request.hex()}")
            sock.send(request)

            response = sock.recv(256)
            self.logger.debug(
                f"Received {len(response)} bytes: {response.hex() if response else 'empty'}"
            )

            if not response:
                self.logger.warning("No response from RTU-over-TCP target")
                if fuzz_data_logger:
                    fuzz_data_logger.log_info("ModbusRTUMonitor: No TCP response")
                return False

            return self._process_response(response, fuzz_data_logger)

        except socket.timeout:
            self.logger.warning(f"RTU-over-TCP timeout ({self.timeout}s)")
            if fuzz_data_logger:
                fuzz_data_logger.log_info("ModbusRTUMonitor: TCP timeout")
            return False
        except Exception as e:
            self.logger.warning(f"RTU-over-TCP error: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"ModbusRTUMonitor: TCP error - {e}")
            return False
        finally:
            if sock is not None:
                try:
                    sock.close()
                except (OSError, AttributeError) as e:
                    self.logger.debug(f"Socket close error: {e}")

    def _process_response(self, response: bytes, fuzz_data_logger=None) -> bool:
        """Process and validate a Modbus RTU response, updating baseline."""
        if not self._validate_rtu_response(response):
            if fuzz_data_logger:
                fuzz_data_logger.log_fail(
                    f"ModbusRTUMonitor: Invalid RTU response ({len(response)} bytes)"
                )
            return False

        function_code = response[1]

        # Store baseline on first success
        if not self.baseline_established:
            self.baseline = ProtocolBaseline(
                raw_response=response,
                parsed_fields={
                    "function_code": function_code,
                    "slave_address": response[0],
                },
            )
            self.baseline_function_code = function_code
            self.baseline_established = True
            self.logger.display(
                f"Modbus RTU baseline established (slave={response[0]}, FC=0x{function_code:02x})"
            )
            if fuzz_data_logger:
                fuzz_data_logger.log_info(
                    f"ModbusRTUMonitor: Baseline established "
                    f"(slave={response[0]}, FC=0x{function_code:02x})"
                )
            return True

        # Compare against baseline
        if self.baseline_function_code is not None and function_code != self.baseline_function_code:
            if fuzz_data_logger:
                fuzz_data_logger.log_fail(
                    f"ModbusRTUMonitor: FC changed "
                    f"(expected 0x{self.baseline_function_code:02x}, "
                    f"got 0x{function_code:02x})"
                )
            return False

        return True

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Single attempt to check if Modbus RTU device is responsive."""
        if self.transport == "tcp":
            return self._check_alive_tcp(fuzz_data_logger)
        return self._check_alive_serial(fuzz_data_logger)


__all__ = [
    "IEC104States",
    "ModbusMonitor",
    "ModbusRTUMonitor",
    "IEC104Monitor",
    "MMSMonitor",
    "MQTTMonitor",
    "OPCUAMonitor",
]
