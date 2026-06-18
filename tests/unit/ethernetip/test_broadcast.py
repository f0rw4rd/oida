#!/usr/bin/env python3
"""
Unit tests for EtherNet/IP broadcast discovery and __init__ module functions.

Tests cover:
- broadcast_discovery() standalone function
- _parse_list_identity() packet parsing
- Edge cases in packet parsing (short data, bad commands, etc.)
"""

import struct
import unittest
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.core

from oida.protocols.ethernetip import broadcast_discovery
from oida.protocols.ethernetip.__init__ import _parse_list_identity
from oida.protocols.ethernetip.constants import ENIP_CMD_LIST_IDENTITY


def _build_list_identity_response(
    vendor_id=1,
    device_type=0x0E,
    product_code=65,
    major=20,
    minor=3,
    status=0,
    serial=0x12345678,
    product_name="TestPLC",
    state=3,
):
    """Build a valid ListIdentity response packet for testing."""
    # Identity item data: protocol_version(2) + sockaddr(16) + identity fields
    # sockaddr: sin_family(2) + sin_port(2) + sin_addr(4) + sin_zero(8) = 16
    protocol_version = struct.pack("<H", 1)
    sockaddr = struct.pack(">HH4s8s", 2, 44818, b"\xc0\xa8\x01\x64", b"\x00" * 8)

    name_bytes = product_name.encode("utf-8")
    identity = struct.pack(
        "<HHHBB HI B",
        vendor_id,
        device_type,
        product_code,
        major,
        minor,
        status,
        serial,
        len(name_bytes),
    )
    identity += name_bytes
    identity += struct.pack("<B", state)

    item_data = protocol_version + sockaddr + identity

    # CPF: item_count(2) + type_id(2) + item_length(2) + item_data
    cpf = struct.pack("<H HH", 1, 0x000C, len(item_data))
    cpf += item_data

    # ENIP header
    header = struct.pack(
        "<HH I I Q I",
        ENIP_CMD_LIST_IDENTITY,
        len(cpf),
        0,
        0,
        0,
        0,
    )

    return header + cpf


class TestParseListIdentity(unittest.TestCase):
    """Test _parse_list_identity packet parsing."""

    def test_valid_response(self):
        data = _build_list_identity_response()
        result = _parse_list_identity(data)
        self.assertIsNotNone(result)
        self.assertTrue(result["success"])
        self.assertEqual(result["vendor_id"], 1)
        self.assertEqual(result["device_type"], 0x0E)
        self.assertEqual(result["product_code"], 65)
        self.assertEqual(result["revision"], (20, 3))
        self.assertEqual(result["serial_number"], 0x12345678)
        self.assertEqual(result["product_name"], "TestPLC")
        self.assertEqual(result["state"], 3)
        self.assertEqual(result["state_name"], "Operational")

    def test_too_short_header(self):
        result = _parse_list_identity(b"\x01\x02")
        self.assertIsNone(result)

    def test_wrong_command(self):
        data = _build_list_identity_response()
        # Change command to something else
        data = struct.pack("<H", 0x0004) + data[2:]
        result = _parse_list_identity(data)
        self.assertIsNone(result)

    def test_length_mismatch(self):
        data = _build_list_identity_response()
        # Set length field to a huge value
        data = data[:2] + struct.pack("<H", 9999) + data[4:]
        result = _parse_list_identity(data)
        self.assertIsNone(result)

    def test_zero_item_count(self):
        header = struct.pack("<HH I I Q I", ENIP_CMD_LIST_IDENTITY, 2, 0, 0, 0, 0)
        cpf = struct.pack("<H", 0)  # item_count = 0
        data = header + cpf
        result = _parse_list_identity(data)
        self.assertIsNone(result)

    def test_wrong_item_type(self):
        header = struct.pack("<HH I I Q I", ENIP_CMD_LIST_IDENTITY, 10, 0, 0, 0, 0)
        cpf = struct.pack("<H HH", 1, 0x0099, 0)  # Wrong type_id
        data = header + cpf
        result = _parse_list_identity(data)
        self.assertIsNone(result)

    def test_item_data_too_short(self):
        header = struct.pack("<HH I I Q I", ENIP_CMD_LIST_IDENTITY, 10, 0, 0, 0, 0)
        cpf = struct.pack("<H HH", 1, 0x000C, 5)
        cpf += b"\x00" * 5  # Too short for identity parsing
        data = header + cpf
        result = _parse_list_identity(data)
        self.assertIsNone(result)

    def test_state_names(self):
        """Test various device state values."""
        for state_val, expected_name in [
            (0, "Nonexistent"),
            (1, "Device Self Testing"),
            (2, "Standby"),
            (3, "Operational"),
            (4, "Major Recoverable Fault"),
            (5, "Major Unrecoverable Fault"),
            (255, "Default"),
        ]:
            data = _build_list_identity_response(state=state_val)
            result = _parse_list_identity(data)
            self.assertIsNotNone(result)
            self.assertEqual(result["state_name"], expected_name, f"State {state_val} mismatch")

    def test_unknown_state(self):
        data = _build_list_identity_response(state=99)
        result = _parse_list_identity(data)
        self.assertIsNotNone(result)
        self.assertIn("Unknown", result["state_name"])


class TestBroadcastDiscovery(unittest.TestCase):
    """Test broadcast_discovery standalone function."""

    def test_no_lhost_returns_empty(self):
        result = broadcast_discovery(lhost="")
        self.assertEqual(result, [])

    def test_no_lhost_none_returns_empty(self):
        result = broadcast_discovery(lhost=None)
        self.assertEqual(result, [])

    @patch("socket.socket")
    def test_valid_broadcast(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        response = _build_list_identity_response()
        mock_sock.recvfrom.side_effect = [
            (response, ("192.168.1.200", 44818)),
            TimeoutError("timeout"),
            TimeoutError("timeout"),
            TimeoutError("timeout"),
            TimeoutError("timeout"),
            TimeoutError("timeout"),
            TimeoutError("timeout"),
        ]

        result = broadcast_discovery(lhost="192.168.1.1", timeout=0.1)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ip_address"], "192.168.1.200")
        self.assertTrue(result[0]["success"])

    @patch("socket.socket")
    def test_duplicate_ip_deduplication(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        response = _build_list_identity_response()
        mock_sock.recvfrom.side_effect = [
            (response, ("192.168.1.200", 44818)),
            (response, ("192.168.1.200", 44818)),  # duplicate
            TimeoutError("timeout"),
            TimeoutError("timeout"),
            TimeoutError("timeout"),
            TimeoutError("timeout"),
        ]

        result = broadcast_discovery(lhost="192.168.1.1", timeout=0.1)
        self.assertEqual(len(result), 1)

    @patch("socket.socket")
    def test_socket_error_returns_empty(self, mock_socket_class):
        mock_socket_class.side_effect = OSError("Cannot bind")
        result = broadcast_discovery(lhost="192.168.1.1", timeout=0.1)
        self.assertEqual(result, [])

    def test_subnet_broadcast(self):
        """Test that subnet parameter is accepted (does not crash)."""
        with patch("socket.socket") as mock_socket_class:
            mock_sock = MagicMock()
            mock_socket_class.return_value = mock_sock
            mock_sock.recvfrom.side_effect = TimeoutError("timeout")

            result = broadcast_discovery(
                lhost="192.168.1.1",
                subnet="192.168.1.0/24",
                timeout=0.1,
            )
            self.assertEqual(result, [])

    def test_invalid_subnet_does_not_crash(self):
        with patch("socket.socket") as mock_socket_class:
            mock_sock = MagicMock()
            mock_socket_class.return_value = mock_sock
            mock_sock.recvfrom.side_effect = TimeoutError("timeout")

            result = broadcast_discovery(
                lhost="192.168.1.1",
                subnet="not-a-subnet",
                timeout=0.1,
            )
            self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()
