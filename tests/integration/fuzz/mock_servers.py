"""
Minimal in-process mock servers for fuzzer integration testing.

These servers speak just enough protocol to allow the fuzzer to:
1. Establish a connection
2. Send fuzzed payloads
3. Receive valid-enough responses for monitors to check

They are deliberately simple -- the goal is testing the fuzzer framework,
not the protocol implementation.
"""

import socket
import struct
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Optional


@dataclass
class MockServerHandle:
    """Uniform interface for in-process mock servers."""

    host: str
    port: int
    protocol: str
    _server_socket: Optional[socket.socket] = None
    _thread: Optional[threading.Thread] = None
    _stop_event: Optional[threading.Event] = None
    _request_count: int = 0
    _crash_after: Optional[int] = None

    @property
    def request_count(self) -> int:
        return self._request_count

    def stop(self):
        if self._stop_event:
            self._stop_event.set()
        if self._server_socket:
            try:
                self._server_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self._server_socket.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=3)

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def simulate_crash(self):
        """Simulate a server crash by closing the listener socket.

        After this, no new connections are accepted and existing handlers
        will return on their next iteration, making the server truly
        unreachable (connection refused).
        """
        if self._stop_event:
            self._stop_event.set()
        if self._server_socket:
            try:
                # Shutdown first to drain the listen backlog and refuse
                # any pending connection attempts immediately.
                self._server_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self._server_socket.close()
            except Exception:
                pass
        self._server_socket = None


def find_free_port() -> int:
    """Find an available TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ============================================================================
# Modbus TCP Mock Server
# ============================================================================


def _modbus_handler(conn, addr, stop_event, handle):
    """Handle a single Modbus TCP connection."""
    conn.settimeout(1.0)
    try:
        while not stop_event.is_set():
            try:
                # Read MBAP header (7 bytes)
                header = b""
                while len(header) < 7 and not stop_event.is_set():
                    try:
                        chunk = conn.recv(7 - len(header))
                        if not chunk:
                            return
                        header += chunk
                    except TimeoutError:
                        continue

                if len(header) < 7:
                    continue

                transaction_id = struct.unpack(">H", header[0:2])[0]
                protocol_id = struct.unpack(">H", header[2:4])[0]
                length = struct.unpack(">H", header[4:6])[0]
                unit_id = header[6]

                # Read PDU
                pdu = b""
                remaining = length - 1  # subtract unit_id byte
                while len(pdu) < remaining and not stop_event.is_set():
                    try:
                        chunk = conn.recv(remaining - len(pdu))
                        if not chunk:
                            return
                        pdu += chunk
                    except TimeoutError:
                        continue

                if not pdu:
                    continue

                handle._request_count += 1

                if handle._crash_after and handle._request_count >= handle._crash_after:
                    handle.simulate_crash()
                    return

                fc = pdu[0]

                # Build response based on function code
                if fc == 0x03:  # Read Holding Registers
                    reg_count = struct.unpack(">H", pdu[3:5])[0] if len(pdu) >= 5 else 1
                    byte_count = reg_count * 2
                    resp_pdu = bytes([fc, byte_count]) + b"\x00\x01" * reg_count
                elif fc == 0x01:  # Read Coils
                    resp_pdu = bytes([fc, 1, 0x01])
                elif fc == 0x02:  # Read Discrete Inputs
                    resp_pdu = bytes([fc, 1, 0x01])
                elif fc == 0x04:  # Read Input Registers
                    reg_count = struct.unpack(">H", pdu[3:5])[0] if len(pdu) >= 5 else 1
                    byte_count = reg_count * 2
                    resp_pdu = bytes([fc, byte_count]) + b"\x00\x02" * reg_count
                elif fc in (0x05, 0x06, 0x0F, 0x10):  # Write operations
                    resp_pdu = pdu[:5]  # Echo back
                elif fc == 0x2B:  # MEI (Read Device Identification)
                    resp_pdu = bytes(
                        [
                            0x2B,
                            0x0E,  # MEI type
                            0x01,  # Read device ID code
                            0x01,  # Conformity level
                            0x00,  # More follows
                            0x00,  # Next object ID
                            0x03,  # Number of objects
                            0x00,
                            0x04,
                            0x4F,
                            0x49,
                            0x44,
                            0x41,  # VendorName: OIDA
                            0x01,
                            0x04,
                            0x4D,
                            0x6F,
                            0x63,
                            0x6B,  # ProductCode: Mock
                            0x02,
                            0x05,
                            0x31,
                            0x2E,
                            0x30,
                            0x2E,
                            0x30,  # Revision: 1.0.0
                        ]
                    )
                else:
                    # Unsupported FC - return exception
                    resp_pdu = bytes([fc | 0x80, 0x01])

                # Build MBAP response
                resp_length = len(resp_pdu) + 1  # +1 for unit_id
                resp_header = struct.pack(">HHH", transaction_id, protocol_id, resp_length)
                response = resp_header + bytes([unit_id]) + resp_pdu

                conn.sendall(response)

            except TimeoutError:
                continue
            except (ConnectionResetError, BrokenPipeError, OSError):
                return
    finally:
        conn.close()


def _run_tcp_server(server_socket, stop_event, handler_func, handle):
    """Generic TCP server loop that accepts connections and spawns handler threads."""
    server_socket.settimeout(1.0)
    threads = []
    try:
        while not stop_event.is_set():
            try:
                conn, addr = server_socket.accept()
                t = threading.Thread(
                    target=handler_func,
                    args=(conn, addr, stop_event, handle),
                    daemon=True,
                )
                t.start()
                threads.append(t)
            except TimeoutError:
                continue
            except OSError:
                break
    finally:
        for t in threads:
            t.join(timeout=1)


@contextmanager
def modbus_server(port=0, crash_after=None):
    """Start a minimal Modbus TCP server."""
    if port == 0:
        port = find_free_port()

    handle = MockServerHandle(
        host="127.0.0.1",
        port=port,
        protocol="modbus",
        _crash_after=crash_after,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(5)

    handle._server_socket = sock
    handle._stop_event = threading.Event()

    handle._thread = threading.Thread(
        target=_run_tcp_server,
        args=(sock, handle._stop_event, _modbus_handler, handle),
        daemon=True,
    )
    handle._thread.start()

    # Wait for server to be ready
    time.sleep(0.1)
    try:
        yield handle
    finally:
        handle.stop()


# ============================================================================
# OPC UA Mock Server (minimal Hello/Acknowledge)
# ============================================================================


def _opcua_handler(conn, addr, stop_event, handle):
    """Handle a single OPC UA connection with minimal responses."""
    conn.settimeout(1.0)
    try:
        while not stop_event.is_set():
            try:
                # Read message header (at least 8 bytes: type[3] + 'F'[1] + size[4])
                header = b""
                while len(header) < 8 and not stop_event.is_set():
                    try:
                        chunk = conn.recv(8 - len(header))
                        if not chunk:
                            return
                        header += chunk
                    except TimeoutError:
                        continue

                if len(header) < 8:
                    continue

                msg_type = header[0:3]
                msg_size = struct.unpack("<I", header[4:8])[0]

                # Read rest of message
                remaining = msg_size - 8
                body = b""
                while len(body) < remaining and not stop_event.is_set():
                    try:
                        chunk = conn.recv(remaining - len(body))
                        if not chunk:
                            return
                        body += chunk
                    except TimeoutError:
                        continue

                handle._request_count += 1

                if handle._crash_after and handle._request_count >= handle._crash_after:
                    handle.simulate_crash()
                    return

                if msg_type == b"HEL":
                    # Send Acknowledge
                    ack = b"ACKF"
                    ack_body = struct.pack(
                        "<IIIII",
                        0,  # ProtocolVersion
                        65535,  # ReceiveBufferSize
                        65535,  # SendBufferSize
                        0,  # MaxMessageSize
                        0,  # MaxChunkCount
                    )
                    ack_size = struct.pack("<I", 8 + len(ack_body))
                    conn.sendall(ack + ack_size + ack_body)
                elif msg_type == b"OPN":
                    # OpenSecureChannel - send minimal response
                    # This is a simplified response
                    resp_type = b"OPNF"
                    resp_body = b"\x00" * 60  # Simplified secure channel response
                    resp_size = struct.pack("<I", 8 + len(resp_body))
                    conn.sendall(resp_type + resp_size + resp_body)
                elif msg_type == b"MSG":
                    # Generic message - send empty response
                    resp_type = b"MSGF"
                    resp_body = b"\x00" * 20
                    resp_size = struct.pack("<I", 8 + len(resp_body))
                    conn.sendall(resp_type + resp_size + resp_body)
                elif msg_type == b"CLO":
                    return
                else:
                    # Unknown - echo back a minimal response
                    resp = msg_type + b"F" + struct.pack("<I", 8)
                    conn.sendall(resp)

            except TimeoutError:
                continue
            except (ConnectionResetError, BrokenPipeError, OSError):
                return
    finally:
        conn.close()


@contextmanager
def opcua_server(port=0, crash_after=None):
    """Start a minimal OPC UA server (Hello/Acknowledge only)."""
    if port == 0:
        port = find_free_port()

    handle = MockServerHandle(
        host="127.0.0.1",
        port=port,
        protocol="opcua",
        _crash_after=crash_after,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(5)

    handle._server_socket = sock
    handle._stop_event = threading.Event()

    handle._thread = threading.Thread(
        target=_run_tcp_server,
        args=(sock, handle._stop_event, _opcua_handler, handle),
        daemon=True,
    )
    handle._thread.start()
    time.sleep(0.1)

    try:
        yield handle
    finally:
        handle.stop()


# ============================================================================
# IEC 104 Mock Server
# ============================================================================


def _iec104_handler(conn, addr, stop_event, handle):
    """Handle a single IEC 104 connection."""
    conn.settimeout(1.0)
    try:
        while not stop_event.is_set():
            try:
                # IEC 104 APDU starts with 0x68 + length
                start = b""
                while len(start) < 2 and not stop_event.is_set():
                    try:
                        chunk = conn.recv(2 - len(start))
                        if not chunk:
                            return
                        start += chunk
                    except TimeoutError:
                        continue

                if len(start) < 2 or start[0] != 0x68:
                    continue

                apdu_len = start[1]
                body = b""
                while len(body) < apdu_len and not stop_event.is_set():
                    try:
                        chunk = conn.recv(apdu_len - len(body))
                        if not chunk:
                            return
                        body += chunk
                    except TimeoutError:
                        continue

                if len(body) < 4:
                    continue

                handle._request_count += 1

                if handle._crash_after and handle._request_count >= handle._crash_after:
                    handle.simulate_crash()
                    return

                ctrl = body[0:4]

                # Check U-format frames
                if ctrl[0] & 0x03 == 0x03:  # U-format
                    if ctrl[0] == 0x07:  # STARTDT act
                        # Send STARTDT con
                        conn.sendall(bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00]))
                    elif ctrl[0] == 0x13:  # STOPDT act
                        # Send STOPDT con
                        conn.sendall(bytes([0x68, 0x04, 0x23, 0x00, 0x00, 0x00]))
                    elif ctrl[0] == 0x43:  # TESTFR act
                        # Send TESTFR con
                        conn.sendall(bytes([0x68, 0x04, 0x83, 0x00, 0x00, 0x00]))
                elif ctrl[0] & 0x01 == 0x00:  # I-format
                    # Send S-format acknowledgment
                    rx_seq = struct.unpack("<H", ctrl[0:2])[0] >> 1
                    new_rx = (rx_seq + 1) << 1
                    conn.sendall(bytes([0x68, 0x04, 0x01, 0x00]) + struct.pack("<H", new_rx))
                elif ctrl[0] & 0x03 == 0x01:  # S-format
                    pass  # Acknowledgment, no response needed

            except TimeoutError:
                continue
            except (ConnectionResetError, BrokenPipeError, OSError):
                return
    finally:
        conn.close()


@contextmanager
def iec104_server(port=0, crash_after=None):
    """Start a minimal IEC 104 server."""
    if port == 0:
        port = find_free_port()

    handle = MockServerHandle(
        host="127.0.0.1",
        port=port,
        protocol="iec104",
        _crash_after=crash_after,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(5)

    handle._server_socket = sock
    handle._stop_event = threading.Event()

    handle._thread = threading.Thread(
        target=_run_tcp_server,
        args=(sock, handle._stop_event, _iec104_handler, handle),
        daemon=True,
    )
    handle._thread.start()
    time.sleep(0.1)

    try:
        yield handle
    finally:
        handle.stop()


# ============================================================================
# MMS Mock Server (ISO-on-TCP + COTP + MMS Initiate)
# ============================================================================


def _mms_handler(conn, addr, stop_event, handle):
    """Handle a single MMS/ISO-on-TCP connection."""
    conn.settimeout(1.0)
    try:
        while not stop_event.is_set():
            try:
                # TPKT header: version(1) + reserved(1) + length(2)
                tpkt = b""
                while len(tpkt) < 4 and not stop_event.is_set():
                    try:
                        chunk = conn.recv(4 - len(tpkt))
                        if not chunk:
                            return
                        tpkt += chunk
                    except TimeoutError:
                        continue

                if len(tpkt) < 4 or tpkt[0] != 0x03:
                    continue

                pkt_len = struct.unpack(">H", tpkt[2:4])[0]
                remaining = pkt_len - 4
                body = b""
                while len(body) < remaining and not stop_event.is_set():
                    try:
                        chunk = conn.recv(remaining - len(body))
                        if not chunk:
                            return
                        body += chunk
                    except TimeoutError:
                        continue

                handle._request_count += 1

                if handle._crash_after and handle._request_count >= handle._crash_after:
                    handle.simulate_crash()
                    return

                if not body:
                    continue

                # Check COTP PDU type
                cotp_len = body[0]
                if len(body) > 1:
                    cotp_type = body[1]
                else:
                    continue

                if cotp_type == 0xE0:  # COTP Connection Request (CR)
                    # Send COTP Connection Confirm (CC)
                    cc = bytes(
                        [
                            0x03,
                            0x00,
                            0x00,
                            0x0B,  # TPKT
                            0x06,  # COTP length
                            0xD0,  # CC PDU type
                            0x00,
                            0x01,  # Destination reference
                            0x00,
                            0x01,  # Source reference
                            0x00,  # Class 0
                        ]
                    )
                    conn.sendall(cc)
                elif cotp_type == 0xF0:  # COTP Data (DT)
                    # Check for MMS Initiate-Request in the data
                    data_start = 1 + cotp_len
                    if data_start < len(body):
                        app_data = body[data_start:]
                        if app_data and app_data[0] == 0xA8:  # MMS Initiate-Request
                            # Send MMS Initiate-Response wrapped in TPKT/COTP
                            mms_resp = bytes(
                                [
                                    0xA9,
                                    0x1A,  # MMS Initiate-Response tag + length
                                    0x80,
                                    0x03,
                                    0x00,
                                    0xFD,
                                    0xE8,  # localDetailCalling (65000)
                                    0x81,
                                    0x01,
                                    0x05,  # proposedMaxServOutstandingCalling (5)
                                    0x82,
                                    0x01,
                                    0x05,  # proposedMaxServOutstandingCalled (5)
                                    0x83,
                                    0x01,
                                    0x01,  # proposedDataStructureNestingLevel (1)
                                    0xA4,
                                    0x09,  # initResponseDetail
                                    0x80,
                                    0x01,
                                    0x01,  # negotiatedVersionNumber (1)
                                    0x81,
                                    0x04,
                                    0x00,
                                    0x00,
                                    0x00,
                                    0x01,  # proposedParameterCBB
                                ]
                            )
                            cotp_dt = bytes([0x02, 0xF0, 0x80])
                            total_len = 4 + len(cotp_dt) + len(mms_resp)
                            tpkt_resp = bytes([0x03, 0x00]) + struct.pack(">H", total_len)
                            conn.sendall(tpkt_resp + cotp_dt + mms_resp)
                        else:
                            # Generic MMS response - send a confirmed response
                            mms_resp = bytes(
                                [
                                    0xA1,
                                    0x06,  # Confirmed-ResponsePDU tag + length
                                    0x02,
                                    0x01,
                                    0x01,  # invokeID = 1
                                    0xA5,
                                    0x01,
                                    0x00,  # Identify response (empty)
                                ]
                            )
                            cotp_dt = bytes([0x02, 0xF0, 0x80])
                            total_len = 4 + len(cotp_dt) + len(mms_resp)
                            tpkt_resp = bytes([0x03, 0x00]) + struct.pack(">H", total_len)
                            conn.sendall(tpkt_resp + cotp_dt + mms_resp)

            except TimeoutError:
                continue
            except (ConnectionResetError, BrokenPipeError, OSError):
                return
    finally:
        conn.close()


@contextmanager
def mms_server(port=0, crash_after=None):
    """Start a minimal MMS/ISO-on-TCP server."""
    if port == 0:
        port = find_free_port()

    handle = MockServerHandle(
        host="127.0.0.1",
        port=port,
        protocol="mms",
        _crash_after=crash_after,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(5)

    handle._server_socket = sock
    handle._stop_event = threading.Event()

    handle._thread = threading.Thread(
        target=_run_tcp_server,
        args=(sock, handle._stop_event, _mms_handler, handle),
        daemon=True,
    )
    handle._thread.start()
    time.sleep(0.1)

    try:
        yield handle
    finally:
        handle.stop()


# ============================================================================
# MQTT Mock Server
# ============================================================================


def _mqtt_handler(conn, addr, stop_event, handle):
    """Handle a single MQTT connection."""
    conn.settimeout(1.0)
    try:
        while not stop_event.is_set():
            try:
                # MQTT fixed header: type+flags(1) + remaining length (1-4 bytes)
                first = b""
                while len(first) < 1 and not stop_event.is_set():
                    try:
                        chunk = conn.recv(1)
                        if not chunk:
                            return
                        first += chunk
                    except TimeoutError:
                        continue

                if not first:
                    continue

                pkt_type = (first[0] >> 4) & 0x0F

                # Decode remaining length (variable-length encoding)
                remaining_length = 0
                multiplier = 1
                for _ in range(4):
                    try:
                        b = conn.recv(1)
                        if not b:
                            return
                        byte_val = b[0]
                        remaining_length += (byte_val & 0x7F) * multiplier
                        multiplier *= 128
                        if (byte_val & 0x80) == 0:
                            break
                    except TimeoutError:
                        continue

                # Read payload
                payload = b""
                while len(payload) < remaining_length and not stop_event.is_set():
                    try:
                        chunk = conn.recv(remaining_length - len(payload))
                        if not chunk:
                            return
                        payload += chunk
                    except TimeoutError:
                        continue

                handle._request_count += 1

                if handle._crash_after and handle._request_count >= handle._crash_after:
                    handle.simulate_crash()
                    return

                if pkt_type == 1:  # CONNECT
                    # Send CONNACK (session present=0, return code=0)
                    conn.sendall(bytes([0x20, 0x02, 0x00, 0x00]))
                elif pkt_type == 3:  # PUBLISH
                    # QoS 0 - no response needed
                    qos = (first[0] >> 1) & 0x03
                    if qos == 1:
                        # PUBACK - need packet identifier
                        if len(payload) >= 2:
                            # Skip topic to find packet ID
                            topic_len = struct.unpack(">H", payload[0:2])[0]
                            pkt_id_offset = 2 + topic_len
                            if len(payload) > pkt_id_offset + 1:
                                pkt_id = payload[pkt_id_offset : pkt_id_offset + 2]
                                conn.sendall(bytes([0x40, 0x02]) + pkt_id)
                elif pkt_type == 8:  # SUBSCRIBE
                    # SUBACK
                    if len(payload) >= 2:
                        pkt_id = payload[0:2]
                        conn.sendall(bytes([0x90, 0x03]) + pkt_id + bytes([0x00]))
                elif pkt_type == 12:  # PINGREQ
                    # PINGRESP
                    conn.sendall(bytes([0xD0, 0x00]))
                elif pkt_type == 14:  # DISCONNECT
                    return

            except TimeoutError:
                continue
            except (ConnectionResetError, BrokenPipeError, OSError):
                return
    finally:
        conn.close()


@contextmanager
def mqtt_server(port=0, crash_after=None):
    """Start a minimal MQTT broker."""
    if port == 0:
        port = find_free_port()

    handle = MockServerHandle(
        host="127.0.0.1",
        port=port,
        protocol="mqtt",
        _crash_after=crash_after,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(5)

    handle._server_socket = sock
    handle._stop_event = threading.Event()

    handle._thread = threading.Thread(
        target=_run_tcp_server,
        args=(sock, handle._stop_event, _mqtt_handler, handle),
        daemon=True,
    )
    handle._thread.start()
    time.sleep(0.1)

    try:
        yield handle
    finally:
        handle.stop()


# ============================================================================
# Generic TCP Echo Server (for any protocol that just needs a connection)
# ============================================================================


def _echo_handler(conn, addr, stop_event, handle):
    """Accept data and echo it back."""
    conn.settimeout(1.0)
    try:
        while not stop_event.is_set():
            try:
                data = conn.recv(4096)
                if not data:
                    return
                handle._request_count += 1
                if handle._crash_after and handle._request_count >= handle._crash_after:
                    handle.simulate_crash()
                    return
                conn.sendall(data)
            except TimeoutError:
                continue
            except (ConnectionResetError, BrokenPipeError, OSError):
                return
    finally:
        conn.close()


@contextmanager
def echo_server(port=0, crash_after=None):
    """Start a TCP echo server."""
    if port == 0:
        port = find_free_port()

    handle = MockServerHandle(
        host="127.0.0.1",
        port=port,
        protocol="echo",
        _crash_after=crash_after,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(5)

    handle._server_socket = sock
    handle._stop_event = threading.Event()

    handle._thread = threading.Thread(
        target=_run_tcp_server,
        args=(sock, handle._stop_event, _echo_handler, handle),
        daemon=True,
    )
    handle._thread.start()
    time.sleep(0.1)

    try:
        yield handle
    finally:
        handle.stop()


# ============================================================================
# Server factory by protocol name
# ============================================================================

MOCK_SERVER_FACTORIES = {
    "modbus": modbus_server,
    "opcua": opcua_server,
    "iec104": iec104_server,
    "mms": mms_server,
    "mqtt": mqtt_server,
    "echo": echo_server,
}


def get_mock_server(protocol: str, port: int = 0, crash_after: int = None):
    """Get a context manager for the appropriate mock server."""
    factory = MOCK_SERVER_FACTORIES.get(protocol)
    if factory is None:
        raise ValueError(f"No mock server for protocol: {protocol}")
    return factory(port=port, crash_after=crash_after)
