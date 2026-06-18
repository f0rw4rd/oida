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

# Skip all tests if mock server is not running
pytestmark = [
    pytest.mark.integration,
    pytest.mark.hart,
]


def is_mock_running(host: str = "127.0.0.1", port: int = 5094) -> bool:
    """Check if HART mock server is running and responding to HART-IP protocol"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((host, port))
        if result != 0:
            sock.close()
            return False

        # Send a HART-IP Command 0 and check for a valid response
        # Build minimal HART-IP frame: version(1), msg_type(0=req), msg_id(2), status(1),
        # seq(2), body_len(2) + HART PDU
        delimiter = 0x02  # Short frame
        address = 0x00
        command = 0
        data_len = 0
        pdu = struct.pack("BBB", delimiter | 0x80, address, command)
        pdu += struct.pack("B", data_len)
        # Checksum
        checksum = 0
        for b in pdu:
            checksum ^= b
        pdu += struct.pack("B", checksum)

        # HART-IP header
        header = struct.pack(">BBHBHH", 1, 0, 1, 0, 0, len(pdu))
        sock.sendall(header + pdu)

        data = sock.recv(1024)
        sock.close()
        return len(data) > 8
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return False


# Skip all tests if mock is not running
@pytest.fixture(scope="module", autouse=True)
def check_mock_running():
    if not is_mock_running():
        pytest.skip("HART mock server not responding to HART-IP protocol (run: make mock-start)")


class TestHARTMockBasic:
    """Tests against basic HART mock server"""

    HOST = "127.0.0.1"
    UDP_PORT = 5094
    TCP_PORT = 5095

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
            1,  # msg_id
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
            assert True
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
    UDP_PORT = 5096
    TCP_PORT = 5097

    def build_hart_request(self, command: int, address: int = 0, data: bytes = b"") -> bytes:
        """Build a HART-IP request frame"""
        delimiter = 0x02
        byte_count = len(data)
        pdu = bytes([delimiter, address, command, byte_count]) + data
        checksum = 0
        for b in pdu:
            checksum ^= b
        pdu += bytes([checksum])

        header = struct.pack(">BBHBBH", 1, 0, 1, 0, 1, len(pdu))
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
                pytest.skip("HART multi-drop mock not running")
        except Exception:
            pytest.skip("HART multi-drop mock not running")

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


class TestHARTScannerVersionProbe:
    """Test HART-IP version probing against mock server"""

    HOST = "127.0.0.1"
    UDP_PORT = 5094

    def test_scanner_probe_version(self):
        """Test that version probe detects v1 on mock server"""
        from oida.protocols.hart.scanner import HARTScanner

        scanner = HARTScanner(
            {
                "rhost": self.HOST,
                "rport": self.UDP_PORT,
                "protocol": "udp",
                "timeout": 5,
            }
        )

        version = scanner.probe_version()
        assert version == 1  # Mock is v1-only


class TestHARTScannerAdditionalStatus:
    """Test HART additional status reading against mock server"""

    HOST = "127.0.0.1"
    TCP_PORT = 5095

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


class TestHARTScannerIntegration:
    """Test the HART scanner module against mock server"""

    def test_scanner_connect(self):
        """Test HARTScanner can connect to mock"""
        from oida.protocols.hart.scanner import HARTScanner

        scanner = HARTScanner(
            {
                "rhost": "127.0.0.1",
                "rport": 5095,
                "protocol": "tcp",
                "timeout": 5,
            }
        )

        conn = scanner.connect()
        assert conn is not None

        scanner.disconnect()

    def test_scanner_read_device_info(self):
        """Test HARTScanner can read device info from mock"""
        from oida.protocols.hart.scanner import HARTScanner

        scanner = HARTScanner(
            {
                "rhost": "127.0.0.1",
                "rport": 5095,
                "protocol": "tcp",
                "timeout": 5,
            }
        )

        try:
            scanner.connect()
            info = scanner.read_device_info()

            assert info is not None
            assert info.manufacturer_id == 0x26  # Rosemount/Emerson (FCG ID)
            assert info.tag == "PT-101"

        finally:
            scanner.disconnect()

    def test_scanner_read_variables(self):
        """Test HARTScanner can read process variables from mock"""
        from oida.protocols.hart.scanner import HARTScanner

        scanner = HARTScanner(
            {
                "rhost": "127.0.0.1",
                "rport": 5095,
                "protocol": "tcp",
                "timeout": 5,
            }
        )

        try:
            scanner.connect()
            variables = scanner.read_all_variables()

            assert len(variables) > 0
            # Should have loop current and PV at minimum
            assert any(v.name == "Loop Current" for v in variables)
            assert any(v.name == "Primary Variable" for v in variables)

        finally:
            scanner.disconnect()
