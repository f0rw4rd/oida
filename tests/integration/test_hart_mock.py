#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integration tests for HART mock server

These tests run against the HART mock server started by docker-compose.
Run: make mock-start first, then pytest tests/integration/test_hart_mock.py
"""

import pytest
import socket
import struct

from tests.service_gate import require_service

# Skip all tests if mock server is not running
pytestmark = [
    pytest.mark.integration,
    pytest.mark.hart,
]


def is_mock_running(host: str = "127.0.0.1", port: int = 5091) -> bool:
    """Check the pure-Python HART-IP mock (hart-pymock) is up and answering.

    Sends a pass-through (msg_id=3) Command 0 over TCP and expects a HART
    response PDU. The mock's HART-IP header is ``>BBHBBH`` (version, msg_type,
    msg_id[2], status, sequence[1], payload_len[2]); msg_id 3 is the
    pass-through HART command (msg_id 1 is Session Close and returns no PDU).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        if sock.connect_ex((host, port)) != 0:
            return False

        # HART PDU: short frame, address 0, Command 0, no data + XOR checksum
        pdu = bytes([0x02, 0x00, 0x00, 0x00])
        checksum = 0
        for b in pdu:
            checksum ^= b
        pdu += bytes([checksum])

        header = struct.pack(">BBHBBH", 1, 0, 3, 0, 1, len(pdu))
        sock.sendall(header + pdu)

        data = sock.recv(1024)
        # A real command response carries an 8-byte header + a HART PDU.
        return len(data) > 8
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


# Skip all tests if mock is not running
@pytest.fixture(scope="module", autouse=True)
def check_mock_running():
    if not is_mock_running():
        require_service(
            "HART mock server not responding to HART-IP protocol (run: make mock-start)"
        )


class TestHARTMockBasic:
    """Tests against basic HART mock server"""

    HOST = "127.0.0.1"
    UDP_PORT = 5090
    TCP_PORT = 5091

    def build_hart_request(self, command: int, address: int = 0, data: bytes = b"") -> bytes:
        """Build a HART-IP request frame"""
        # Build PDU
        delimiter = 0x02  # Short frame
        byte_count = len(data)

        pdu = bytes([delimiter, address, command, byte_count]) + data

        # Calculate checksum (XOR of all PDU bytes)
        checksum = 0
        for b in pdu:
            checksum ^= b
        pdu += bytes([checksum])

        # Build header
        header = struct.pack(
            ">BBHBBH",
            1,  # version
            0,  # msg_type (request)
            3,  # msg_id (3 = pass-through HART command; 1 is Session Close)
            0,  # status
            1,  # sequence
            len(pdu),  # payload_len
        )

        return header + pdu

    def parse_response(self, data: bytes) -> dict:
        """Parse HART-IP response"""
        if len(data) < 8:
            return {"error": "Response too short"}

        # Parse header
        version, msg_type, msg_id, status, sequence, payload_len = struct.unpack(
            ">BBHBBH", data[:8]
        )

        pdu = data[8:]
        if len(pdu) < 5:
            return {"error": "PDU too short"}

        delimiter = pdu[0]
        address = pdu[1]
        command = pdu[2]
        byte_count = pdu[3]

        # Response code and device status are first 2 bytes of data
        if byte_count >= 2:
            response_code = pdu[4]
            device_status = pdu[5]
            payload = pdu[6 : 4 + byte_count]
        else:
            response_code = 0
            device_status = 0
            payload = b""

        return {
            "version": version,
            "msg_type": msg_type,
            "msg_id": msg_id,
            "status": status,
            "delimiter": delimiter,
            "address": address,
            "command": command,
            "response_code": response_code,
            "device_status": device_status,
            "payload": payload,
        }

    def test_tcp_connect(self):
        """Test TCP connection to mock server"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((self.HOST, self.TCP_PORT))
            assert sock.getpeername()[0]
        finally:
            sock.close()

    def test_udp_send_receive(self):
        """Test UDP communication with mock server"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        try:
            # Send Command 0 (Read Unique ID)
            request = self.build_hart_request(0)
            sock.sendto(request, (self.HOST, self.UDP_PORT))

            data, addr = sock.recvfrom(1024)
            assert len(data) > 8

            response = self.parse_response(data)
            assert response["response_code"] == 0  # Success
            assert response["command"] == 0

        finally:
            sock.close()

    def test_command_0_read_unique_id(self):
        """Test Command 0: Read Unique Identifier"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((self.HOST, self.TCP_PORT))

            request = self.build_hart_request(0)
            sock.sendall(request)

            data = sock.recv(1024)
            response = self.parse_response(data)

            assert response["response_code"] == 0
            assert len(response["payload"]) >= 9  # At least device info

            # Check manufacturer ID is in valid range (official FieldComm Group IDs)
            if len(response["payload"]) > 1:
                manufacturer_id = response["payload"][1]
                assert manufacturer_id in [
                    0x26,
                    0x17,
                    0x37,
                    0x2A,
                ]  # FCG IDs: Emerson, Honeywell, Yokogawa, Siemens

        finally:
            sock.close()

    def test_command_1_read_pv(self):
        """Test Command 1: Read Primary Variable"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((self.HOST, self.TCP_PORT))

            request = self.build_hart_request(1)
            sock.sendall(request)

            data = sock.recv(1024)
            response = self.parse_response(data)

            assert response["response_code"] == 0
            assert len(response["payload"]) >= 5  # units + float value

            response["payload"][0]
            value = struct.unpack(">f", response["payload"][1:5])[0]

            # Value should be reasonable
            assert -1000 < value < 1000

        finally:
            sock.close()

    def test_command_3_read_dynamic_vars(self):
        """Test Command 3: Read All Dynamic Variables"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((self.HOST, self.TCP_PORT))

            request = self.build_hart_request(3)
            sock.sendall(request)

            data = sock.recv(1024)
            response = self.parse_response(data)

            assert response["response_code"] == 0
            # Should have current (4) + 4 vars * 5 bytes each = 24 bytes
            assert len(response["payload"]) >= 20

            # Parse loop current
            loop_current = struct.unpack(">f", response["payload"][0:4])[0]
            assert 0 < loop_current < 25  # mA range

        finally:
            sock.close()

    def test_command_13_read_tag(self):
        """Test Command 13: Read Tag, Descriptor, Date"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((self.HOST, self.TCP_PORT))

            request = self.build_hart_request(13)
            sock.sendall(request)

            data = sock.recv(1024)
            response = self.parse_response(data)

            assert response["response_code"] == 0
            # Tag (6) + Descriptor (12) + Date (3) = 21 bytes
            assert len(response["payload"]) >= 21

        finally:
            sock.close()

    def test_command_15_read_output(self):
        """Test Command 15: Read Output Information"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((self.HOST, self.TCP_PORT))

            request = self.build_hart_request(15)
            sock.sendall(request)

            data = sock.recv(1024)
            response = self.parse_response(data)

            assert response["response_code"] == 0
            # alarm + transfer + units + upper_range + lower_range + damping
            assert len(response["payload"]) >= 15

        finally:
            sock.close()

    def test_unknown_command_returns_error(self):
        """Test that unknown commands return appropriate error"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((self.HOST, self.TCP_PORT))

            # Command 255 is not implemented
            request = self.build_hart_request(255)
            sock.sendall(request)

            data = sock.recv(1024)
            response = self.parse_response(data)

            # Should return "command not implemented" (32)
            assert response["response_code"] == 32

        finally:
            sock.close()


class TestHARTMockMultidrop:
    """Tests against multi-drop HART mock server"""

    HOST = "127.0.0.1"
    UDP_PORT = 5092
    TCP_PORT = 5093

    def build_hart_request(self, command: int, address: int = 0, data: bytes = b"") -> bytes:
        """Build a HART-IP request frame"""
        delimiter = 0x02
        byte_count = len(data)
        pdu = bytes([delimiter, address, command, byte_count]) + data
        checksum = 0
        for b in pdu:
            checksum ^= b
        pdu += bytes([checksum])

        header = struct.pack(">BBHBBH", 1, 0, 3, 0, 1, len(pdu))
        return header + pdu

    def parse_response(self, data: bytes) -> dict:
        """Parse HART-IP response"""
        if len(data) < 8:
            return {"error": "Response too short"}

        version, msg_type, msg_id, status, sequence, payload_len = struct.unpack(
            ">BBHBBH", data[:8]
        )

        pdu = data[8:]
        if len(pdu) < 5:
            return {"error": "PDU too short"}

        response_code = pdu[4] if len(pdu) > 4 else 0
        payload = pdu[6 : 4 + pdu[3]] if len(pdu) > 6 else b""

        return {
            "response_code": response_code,
            "payload": payload,
            "command": pdu[2],
            "address": pdu[1],
        }

    @pytest.fixture
    def skip_if_multidrop_not_running(self):
        """Skip if multidrop mock is not running"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.HOST, self.TCP_PORT))
            sock.close()
            if result != 0:
                require_service("HART multi-drop mock not running")
        except Exception:
            require_service("HART multi-drop mock not running")

    def test_multiple_devices(self, skip_if_multidrop_not_running):
        """Test that multiple devices respond on different addresses"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)

        devices_found = []

        try:
            sock.connect((self.HOST, self.TCP_PORT))

            # Query addresses 0-3
            for addr in range(4):
                request = self.build_hart_request(0, address=addr)
                sock.sendall(request)

                data = sock.recv(1024)
                response = self.parse_response(data)

                if response["response_code"] == 0:
                    devices_found.append(addr)

            # Should find 4 devices
            assert len(devices_found) == 4
            assert devices_found == [0, 1, 2, 3]

        finally:
            sock.close()

    def test_different_manufacturers(self, skip_if_multidrop_not_running):
        """Test that devices have different manufacturers"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)

        manufacturers = []

        try:
            sock.connect((self.HOST, self.TCP_PORT))

            for addr in range(4):
                request = self.build_hart_request(0, address=addr)
                sock.sendall(request)

                data = sock.recv(1024)
                response = self.parse_response(data)

                if response["response_code"] == 0 and len(response["payload"]) > 1:
                    mfr_id = response["payload"][1]
                    manufacturers.append(mfr_id)

            # Should have 4 different manufacturers
            assert len(manufacturers) == 4
            # Check they're the expected FCG IDs: Emerson, Honeywell, Yokogawa, Siemens
            assert set(manufacturers) == {0x26, 0x17, 0x37, 0x2A}

        finally:
            sock.close()


# NOTE: scanner-level coverage (version probe, tag/device-info reads, variable
# reads) lives in test_hart_integration.py, which exercises the oida HART
# scanner CLI against the FieldComm C hipserver (the reference HART-IP server
# the hartip-py client is designed for). Those scanner.* class-API checks were
# removed from this file: this module covers the pure-Python mock's raw
# protocol behaviour, which doesn't implement the full HART-IP session the
# hartip-py client needs for version probing / TCP sessions.


class TestHARTScannerAdditionalStatus:
    """Test HART additional status reading against mock server"""

    HOST = "127.0.0.1"
    TCP_PORT = 5091

    def test_scanner_read_additional_status(self):
        """Test HARTScanner can read additional status from mock"""
        from oida.protocols.hart.scanner import HARTScanner

        scanner = HARTScanner(
            {
                "rhost": self.HOST,
                "rport": self.TCP_PORT,
                "protocol": "tcp",
                "timeout": 5,
            }
        )

        try:
            scanner.connect()
            status = scanner.read_additional_status()

            assert status is not None
            assert isinstance(status, dict)

        finally:
            scanner.disconnect()


# TestHARTScannerIntegration removed — its scanner.connect()/read_device_info()/
# read_all_variables() class-API checks are covered by test_hart_integration.py
# against the FieldComm C hipserver (see note above).
