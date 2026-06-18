#!/usr/bin/env python3
"""
Unit tests for EtherNet/IP DiscoveryMixin.

Tests cover:
- _list_identity: success, no response, wrong command, truncated, status flags,
  extended status, device IP, state_name mapping
- _parse_cpf_items: empty, single, multiple, truncated
- _list_services: communications service, unknown type, no response, empty
- _list_interfaces: CIP Identity, Ethernet Link, unknown type, no response
- _broadcast_discovery: no lhost, success, deduplication, socket error
- _parse_list_identity_response: delegates to parsers, failure fallback
"""

import struct
import unittest
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.core

from oida.protocols.ethernetip.constants import (
    ENIP_CMD_LIST_IDENTITY,
    ENIP_CMD_LIST_INTERFACES,
    ENIP_CMD_LIST_SERVICES,
)
from oida.protocols.ethernetip.mixins.discovery import DiscoveryMixin


def _build_enip_header(command: int, data: bytes = b"") -> bytes:
    """Build a minimal ENIP header for testing."""
    return struct.pack("<HH I I Q I", command, len(data), 0, 0, 0, 0) + data


def _build_identity_item(
    vendor_id: int = 1,
    device_type: int = 0x0E,
    product_code: int = 55,
    major: int = 20,
    minor: int = 11,
    status: int = 0,
    serial: int = 0xDEADBEEF,
    product_name: str = "TestPLC",
    state: int = 3,
    ip_bytes: bytes = b"\xc0\xa8\x01\x64",  # 192.168.1.100
) -> bytes:
    """Build a CIP Identity item payload for ListIdentity response."""
    # Protocol version (2 bytes)
    item = struct.pack("<H", 1)
    # sockaddr_in: sin_family(2) + sin_port(2) + sin_addr(4) + sin_zero(8)
    item += struct.pack(">HH", 2, 44818)  # sin_family, sin_port big endian
    item += ip_bytes  # IP address in network byte order
    item += b"\x00" * 8  # sin_zero
    # Identity fields
    item += struct.pack("<H", vendor_id)
    item += struct.pack("<H", device_type)
    item += struct.pack("<H", product_code)
    item += struct.pack("<BB", major, minor)
    item += struct.pack("<H", status)
    item += struct.pack("<I", serial)
    # Product name (length-prefixed)
    name_bytes = product_name.encode("utf-8")
    item += struct.pack("<B", len(name_bytes))
    item += name_bytes
    # State
    item += struct.pack("<B", state)
    return item


def _build_list_identity_response(**kwargs) -> bytes:
    """Build a complete ListIdentity response packet."""
    item_data = _build_identity_item(**kwargs)
    # CPF: item_count(2) + type_id(2) + item_length(2) + item_data
    cpf = struct.pack("<H", 1)  # 1 item
    cpf += struct.pack("<HH", 0x000C, len(item_data))  # Identity type
    cpf += item_data
    return _build_enip_header(ENIP_CMD_LIST_IDENTITY, cpf)


class MockDiscoveryHost(DiscoveryMixin):
    """Test host for DiscoveryMixin."""

    def __init__(self):
        self.logger = MagicMock()
        self._send_response = None
        self._parse_header_response = None
        self._build_packet_response = b"\x00" * 24

    def _send_enip_command(self, host, port, command, use_udp=False):
        return self._send_response

    def _parse_enip_header(self, data):
        if self._parse_header_response is not None:
            return self._parse_header_response
        # Default: parse for real
        if len(data) < 24:
            return None
        command, length, session, status = struct.unpack("<HH I I", data[:12])
        return {
            "command": command,
            "length": length,
            "session": session,
            "status": status,
            "data": data[24 : 24 + length],
        }

    def _build_enip_packet(self, command, data=b""):
        return _build_enip_header(command, data)

    def get_target_info(self):
        return ("192.168.1.100", 44818)


# =============================================================================
# _list_identity tests
# =============================================================================


class TestListIdentity(unittest.TestCase):
    """Test _list_identity method."""

    def setUp(self):
        self.host = MockDiscoveryHost()

    def test_success_full_identity(self):
        response = _build_list_identity_response(
            vendor_id=1,
            device_type=0x0E,
            product_code=55,
            major=20,
            minor=11,
            serial=0xDEADBEEF,
            product_name="1769-L33ER",
            state=3,
        )
        self.host._send_response = response
        result = self.host._list_identity("192.168.1.100", display=False)

        self.assertTrue(result["success"])
        self.assertEqual(result["vendor_id"], 1)
        self.assertEqual(result["device_type"], 0x0E)
        self.assertEqual(result["product_code"], 55)
        self.assertEqual(result["revision"], (20, 11))
        self.assertEqual(result["serial_number"], 0xDEADBEEF)
        self.assertEqual(result["product_name"], "1769-L33ER")
        self.assertEqual(result["state"], 3)
        self.assertEqual(result["state_name"], "Operational")

    def test_no_response(self):
        self.host._send_response = None
        result = self.host._list_identity("192.168.1.100")
        self.assertFalse(result["success"])
        self.assertEqual(result["vendor_id"], 0)

    def test_wrong_command_in_response(self):
        """Response with wrong command code returns default."""
        response = _build_enip_header(0x0004, b"\x00" * 10)
        self.host._send_response = response
        result = self.host._list_identity("192.168.1.100")
        self.assertFalse(result["success"])

    def test_truncated_cpf_data(self):
        """CPF data too short (< 2 bytes)."""
        cpf = b"\x01"
        response = _build_enip_header(ENIP_CMD_LIST_IDENTITY, cpf)
        self.host._send_response = response
        result = self.host._list_identity("192.168.1.100")
        self.assertFalse(result["success"])

    def test_zero_item_count(self):
        """Zero items in CPF."""
        cpf = struct.pack("<H", 0)
        response = _build_enip_header(ENIP_CMD_LIST_IDENTITY, cpf)
        self.host._send_response = response
        result = self.host._list_identity("192.168.1.100")
        self.assertFalse(result["success"])

    def test_wrong_item_type(self):
        """Non-identity item type (not 0x000C)."""
        cpf = struct.pack("<H", 1)  # 1 item
        cpf += struct.pack("<HH", 0x00FF, 4)  # wrong type_id
        cpf += b"\x00" * 4
        response = _build_enip_header(ENIP_CMD_LIST_IDENTITY, cpf)
        self.host._send_response = response
        result = self.host._list_identity("192.168.1.100")
        self.assertFalse(result["success"])

    def test_truncated_identity_data(self):
        """Identity item_data shorter than 33 bytes."""
        item_data = b"\x00" * 20  # too short
        cpf = struct.pack("<H", 1)
        cpf += struct.pack("<HH", 0x000C, len(item_data))
        cpf += item_data
        response = _build_enip_header(ENIP_CMD_LIST_IDENTITY, cpf)
        self.host._send_response = response
        result = self.host._list_identity("192.168.1.100")
        self.assertFalse(result["success"])

    def test_device_ip_parsing(self):
        """Device IP extracted from sockaddr structure."""
        response = _build_list_identity_response(
            ip_bytes=b"\x0a\x00\x00\x01",
        )
        self.host._send_response = response
        result = self.host._list_identity("10.0.0.1", display=False)
        self.assertTrue(result["success"])
        self.assertEqual(result["device_ip"], "10.0.0.1")

    def test_status_flags_owned_configured(self):
        """Status word with owned and configured bits set."""
        response = _build_list_identity_response(status=0x0003)
        self.host._send_response = response
        result = self.host._list_identity("192.168.1.100", display=False)
        self.assertTrue(result["success"])
        self.assertTrue(result["status_owned"])
        self.assertTrue(result["status_configured"])
        self.assertFalse(result["status_faulted"])

    def test_status_flags_faulted(self):
        """Status word with fault bits set."""
        response = _build_list_identity_response(status=0x00F1)
        self.host._send_response = response
        result = self.host._list_identity("192.168.1.100", display=False)
        self.assertTrue(result["success"])
        self.assertTrue(result["status_faulted"])
        self.assertTrue(result["status_minor_recoverable_fault"])
        self.assertTrue(result["status_minor_unrecoverable_fault"])
        self.assertTrue(result["status_major_recoverable_fault"])
        self.assertTrue(result["status_major_unrecoverable_fault"])

    def test_extended_status_firmware_update(self):
        """Extended status bits 8-11 = 1 (Firmware Update In Progress)."""
        response = _build_list_identity_response(status=0x0101)
        self.host._send_response = response
        result = self.host._list_identity("192.168.1.100", display=False)
        self.assertTrue(result["success"])
        self.assertEqual(result["extended_status"], "Firmware Update In Progress")

    def test_extended_status_unknown(self):
        """Extended status bits with unknown value."""
        response = _build_list_identity_response(status=0x0F01)
        self.host._send_response = response
        result = self.host._list_identity("192.168.1.100", display=False)
        self.assertTrue(result["success"])
        self.assertIn("Unknown", result["extended_status"])

    def test_state_name_mapping_all_known(self):
        """Test all known state values."""
        state_map = {
            0: "Non-existent",
            1: "Device Self Testing",
            2: "Standby",
            3: "Operational",
            4: "Major Recoverable Fault",
            5: "Major Unrecoverable Fault",
            6: "Default for DHCP/BOOTP",
            255: "Default (Unknown)",
        }
        for state_val, expected_name in state_map.items():
            response = _build_list_identity_response(state=state_val)
            self.host._send_response = response
            result = self.host._list_identity("192.168.1.100", display=False)
            self.assertTrue(result["success"])
            self.assertEqual(result["state_name"], expected_name, f"state={state_val}")

    def test_state_name_unknown(self):
        """Unknown state value produces fallback string."""
        response = _build_list_identity_response(state=99)
        self.host._send_response = response
        result = self.host._list_identity("192.168.1.100", display=False)
        self.assertTrue(result["success"])
        self.assertIn("99", result["state_name"])

    def test_display_true_logs_output(self):
        """When display=True, logger.display is called."""
        response = _build_list_identity_response()
        self.host._send_response = response
        self.host._list_identity("192.168.1.100", display=True)
        self.host.logger.display.assert_called()

    def test_display_false_no_display_log(self):
        """When display=False, logger.display not called for identity info."""
        response = _build_list_identity_response(status=0)
        self.host._send_response = response
        self.host.logger.reset_mock()
        self.host._list_identity("192.168.1.100", display=False)
        # display should not be called
        self.host.logger.display.assert_not_called()

    def test_faulted_device_warning(self):
        """Faulted device triggers logger.warning."""
        response = _build_list_identity_response(status=0x0010)
        self.host._send_response = response
        self.host._list_identity("192.168.1.100", display=True)
        self.host.logger.warning.assert_called()

    def test_no_status_zero_status(self):
        """Status word = 0 should not set status_owned etc."""
        response = _build_list_identity_response(status=0)
        self.host._send_response = response
        result = self.host._list_identity("192.168.1.100", display=False)
        self.assertTrue(result["success"])
        self.assertNotIn("status_owned", result)

    def test_udp_mode(self):
        """use_udp parameter propagated to _send_enip_command."""
        calls = []

        def mock_send(host, port, command, use_udp=False):
            calls.append(use_udp)
            return None

        self.host._send_enip_command = mock_send
        self.host._list_identity("192.168.1.100", use_udp=True)
        self.assertTrue(calls[0])


# =============================================================================
# _parse_cpf_items tests
# =============================================================================


class TestParseCpfItems(unittest.TestCase):
    """Test _parse_cpf_items method."""

    def setUp(self):
        self.host = MockDiscoveryHost()

    def test_empty_data(self):
        result = self.host._parse_cpf_items(b"")
        self.assertEqual(result, [])

    def test_single_byte_too_short(self):
        result = self.host._parse_cpf_items(b"\x01")
        self.assertEqual(result, [])

    def test_zero_items(self):
        data = struct.pack("<H", 0)
        result = self.host._parse_cpf_items(data)
        self.assertEqual(result, [])

    def test_single_item(self):
        item_data = b"\xaa\xbb\xcc"
        data = struct.pack("<H", 1)
        data += struct.pack("<HH", 0x000C, len(item_data))
        data += item_data
        result = self.host._parse_cpf_items(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], 0x000C)
        self.assertEqual(result[0][1], item_data)

    def test_multiple_items(self):
        data = struct.pack("<H", 2)
        # Item 1
        data += struct.pack("<HH", 0x000C, 2)
        data += b"\x01\x02"
        # Item 2
        data += struct.pack("<HH", 0x00B2, 3)
        data += b"\x03\x04\x05"
        result = self.host._parse_cpf_items(data)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], (0x000C, b"\x01\x02"))
        self.assertEqual(result[1], (0x00B2, b"\x03\x04\x05"))

    def test_truncated_item_header(self):
        """Item count says 2 but only header for first item present."""
        data = struct.pack("<H", 2)
        data += struct.pack("<HH", 0x000C, 2)
        data += b"\x01\x02"
        # No second item header
        result = self.host._parse_cpf_items(data)
        self.assertEqual(len(result), 1)

    def test_truncated_item_data(self):
        """Item header claims 10 bytes but only 3 available."""
        data = struct.pack("<H", 1)
        data += struct.pack("<HH", 0x000C, 10)
        data += b"\x01\x02\x03"
        result = self.host._parse_cpf_items(data)
        self.assertEqual(len(result), 0)

    def test_empty_item(self):
        """Item with zero-length data."""
        data = struct.pack("<H", 1)
        data += struct.pack("<HH", 0x000C, 0)
        result = self.host._parse_cpf_items(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], (0x000C, b""))


# =============================================================================
# _list_services tests
# =============================================================================


class TestListServices(unittest.TestCase):
    """Test _list_services method."""

    def setUp(self):
        self.host = MockDiscoveryHost()

    def test_no_response(self):
        self.host._send_response = None
        result = self.host._list_services("192.168.1.100")
        self.assertEqual(result, [])

    def test_wrong_command(self):
        """Response with wrong command returns empty list."""
        cpf = struct.pack("<H", 0)
        response = _build_enip_header(ENIP_CMD_LIST_IDENTITY, cpf)
        self.host._send_response = response
        result = self.host._list_services("192.168.1.100")
        self.assertEqual(result, [])

    def test_communications_service(self):
        """Parse a Communications service (type 0x0100)."""
        # Build service item: version(2) + capability_flags(2) + name(16)
        name = b"Communications\x00\x00"  # 16 bytes
        item_data = struct.pack("<HH", 1, 0x0020) + name
        cpf = struct.pack("<H", 1)
        cpf += struct.pack("<HH", 0x0100, len(item_data))
        cpf += item_data
        response = _build_enip_header(ENIP_CMD_LIST_SERVICES, cpf)
        self.host._send_response = response
        result = self.host._list_services("192.168.1.100")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "Communications")
        self.assertEqual(result[0]["type_code"], 0x0100)
        self.assertEqual(result[0]["protocol_version"], 1)
        self.assertEqual(result[0]["capability_flags"], 0x0020)
        self.assertEqual(result[0]["name"], "Communications")

    def test_unknown_service_type(self):
        """Unknown service type returns with type='Unknown'."""
        item_data = b"\x01\x02\x03\x04"
        cpf = struct.pack("<H", 1)
        cpf += struct.pack("<HH", 0x0200, len(item_data))
        cpf += item_data
        response = _build_enip_header(ENIP_CMD_LIST_SERVICES, cpf)
        self.host._send_response = response
        result = self.host._list_services("192.168.1.100")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "Unknown")
        self.assertEqual(result[0]["type_code"], 0x0200)

    def test_empty_services(self):
        """Zero items in CPF data."""
        cpf = struct.pack("<H", 0)
        response = _build_enip_header(ENIP_CMD_LIST_SERVICES, cpf)
        self.host._send_response = response
        result = self.host._list_services("192.168.1.100")
        self.assertEqual(result, [])

    def test_communications_service_short_item(self):
        """Communications service item with minimal data (< 4 bytes)."""
        item_data = b"\x01\x02"  # only 2 bytes
        cpf = struct.pack("<H", 1)
        cpf += struct.pack("<HH", 0x0100, len(item_data))
        cpf += item_data
        response = _build_enip_header(ENIP_CMD_LIST_SERVICES, cpf)
        self.host._send_response = response
        result = self.host._list_services("192.168.1.100")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "Communications")
        # No protocol_version or capability_flags should be set
        self.assertNotIn("protocol_version", result[0])

    def test_multiple_services(self):
        """Multiple services returned."""
        cpf = struct.pack("<H", 2)
        # Service 1: Communications
        name = b"Communications\x00\x00"
        item1 = struct.pack("<HH", 1, 0x0020) + name
        cpf += struct.pack("<HH", 0x0100, len(item1))
        cpf += item1
        # Service 2: Unknown
        item2 = b"\xff"
        cpf += struct.pack("<HH", 0x0200, len(item2))
        cpf += item2
        response = _build_enip_header(ENIP_CMD_LIST_SERVICES, cpf)
        self.host._send_response = response
        result = self.host._list_services("192.168.1.100")
        self.assertEqual(len(result), 2)


# =============================================================================
# _list_interfaces tests
# =============================================================================


class TestListInterfaces(unittest.TestCase):
    """Test _list_interfaces method."""

    def setUp(self):
        self.host = MockDiscoveryHost()

    def test_no_response(self):
        self.host._send_response = None
        result = self.host._list_interfaces("192.168.1.100")
        self.assertEqual(result, [])

    def test_wrong_command(self):
        cpf = struct.pack("<H", 0)
        response = _build_enip_header(ENIP_CMD_LIST_IDENTITY, cpf)
        self.host._send_response = response
        result = self.host._list_interfaces("192.168.1.100")
        self.assertEqual(result, [])

    def test_cip_identity_interface(self):
        """CIP Identity interface type 0x000C."""
        item_data = b"\x01\x02\x03\x04"
        cpf = struct.pack("<H", 1)
        cpf += struct.pack("<HH", 0x000C, len(item_data))
        cpf += item_data
        response = _build_enip_header(ENIP_CMD_LIST_INTERFACES, cpf)
        self.host._send_response = response
        result = self.host._list_interfaces("192.168.1.100")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "CIP Identity")
        self.assertEqual(result[0]["type_code"], 0x000C)
        self.assertEqual(result[0]["index"], 0)
        self.assertEqual(result[0]["data_length"], 4)
        self.assertEqual(result[0]["raw_data"], item_data.hex())

    def test_ethernet_link_interface(self):
        """Ethernet Link interface type 0x0086."""
        item_data = b"\xaa\xbb"
        cpf = struct.pack("<H", 1)
        cpf += struct.pack("<HH", 0x0086, len(item_data))
        cpf += item_data
        response = _build_enip_header(ENIP_CMD_LIST_INTERFACES, cpf)
        self.host._send_response = response
        result = self.host._list_interfaces("192.168.1.100")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "Ethernet Link")

    def test_unknown_interface_type(self):
        """Unknown interface type."""
        item_data = b"\x01"
        cpf = struct.pack("<H", 1)
        cpf += struct.pack("<HH", 0x00FF, len(item_data))
        cpf += item_data
        response = _build_enip_header(ENIP_CMD_LIST_INTERFACES, cpf)
        self.host._send_response = response
        result = self.host._list_interfaces("192.168.1.100")

        self.assertEqual(len(result), 1)
        self.assertIn("Unknown", result[0]["type"])

    def test_multiple_interfaces(self):
        """Multiple interfaces returned."""
        cpf = struct.pack("<H", 2)
        cpf += struct.pack("<HH", 0x000C, 2) + b"\x01\x02"
        cpf += struct.pack("<HH", 0x0086, 3) + b"\x03\x04\x05"
        response = _build_enip_header(ENIP_CMD_LIST_INTERFACES, cpf)
        self.host._send_response = response
        result = self.host._list_interfaces("192.168.1.100")

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["index"], 0)
        self.assertEqual(result[1]["index"], 1)

    def test_empty_item_data(self):
        """Interface with no item_data should not have raw_data."""
        cpf = struct.pack("<H", 1)
        cpf += struct.pack("<HH", 0x000C, 0)
        response = _build_enip_header(ENIP_CMD_LIST_INTERFACES, cpf)
        self.host._send_response = response
        result = self.host._list_interfaces("192.168.1.100")

        self.assertEqual(len(result), 1)
        self.assertNotIn("raw_data", result[0])

    def test_empty_interfaces_response(self):
        """Zero items in CPF."""
        cpf = struct.pack("<H", 0)
        response = _build_enip_header(ENIP_CMD_LIST_INTERFACES, cpf)
        self.host._send_response = response
        result = self.host._list_interfaces("192.168.1.100")
        self.assertEqual(result, [])


# =============================================================================
# _broadcast_discovery tests
# =============================================================================


class TestBroadcastDiscovery(unittest.TestCase):
    """Test _broadcast_discovery method."""

    def setUp(self):
        self.host = MockDiscoveryHost()

    def test_no_lhost_fails(self):
        result = self.host._broadcast_discovery(lhost="", timeout=0.1)
        self.assertEqual(result, [])
        self.host.logger.fail.assert_called()

    def test_none_lhost_fails(self):
        result = self.host._broadcast_discovery(lhost=None, timeout=0.1)
        self.assertEqual(result, [])
        self.host.logger.fail.assert_called()

    @patch("oida.protocols.ethernetip.mixins.discovery.socket.socket")
    def test_success_single_response(self, mock_socket_cls):
        """Single device responds to broadcast."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        response_packet = _build_list_identity_response(product_name="TestDevice")

        # First recvfrom returns data, second times out to stop the loop
        mock_sock.recvfrom.side_effect = [
            (response_packet, ("192.168.1.100", 44818)),
            TimeoutError("done"),
            TimeoutError("done"),
            TimeoutError("done"),
            TimeoutError("done"),
            TimeoutError("done"),
            TimeoutError("done"),
        ]

        self.host._parse_list_identity_response = MagicMock(
            return_value={
                "success": True,
                "vendor_name": "Rockwell",
                "product_name": "TestDevice",
            }
        )

        result = self.host._broadcast_discovery(lhost="192.168.1.1", timeout=0.5)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ip_address"], "192.168.1.100")

    @patch("oida.protocols.ethernetip.mixins.discovery.socket.socket")
    def test_duplicate_ip_deduplication(self, mock_socket_cls):
        """Same IP responding twice should be deduplicated."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        response_packet = _build_list_identity_response()

        mock_sock.recvfrom.side_effect = [
            (response_packet, ("192.168.1.100", 44818)),
            (response_packet, ("192.168.1.100", 44818)),  # duplicate
            TimeoutError("done"),
            TimeoutError("done"),
            TimeoutError("done"),
            TimeoutError("done"),
            TimeoutError("done"),
        ]

        self.host._parse_list_identity_response = MagicMock(
            return_value={"success": True, "vendor_name": "Test", "product_name": "PLC"}
        )

        result = self.host._broadcast_discovery(lhost="192.168.1.1", timeout=0.5)
        self.assertEqual(len(result), 1)

    @patch("oida.protocols.ethernetip.mixins.discovery.socket.socket")
    def test_socket_creation_error(self, mock_socket_cls):
        """Socket creation failure handled gracefully."""
        mock_socket_cls.side_effect = OSError("Permission denied")
        result = self.host._broadcast_discovery(lhost="192.168.1.1", timeout=0.1)
        self.assertEqual(result, [])
        self.host.logger.fail.assert_called()

    @patch("oida.protocols.ethernetip.mixins.discovery.socket.socket")
    def test_non_list_identity_response_ignored(self, mock_socket_cls):
        """Non-ListIdentity responses are ignored."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        # Build a non-ListIdentity response
        bad_response = _build_enip_header(0x0004, b"\x00\x00")

        mock_sock.recvfrom.side_effect = [
            (bad_response, ("192.168.1.200", 44818)),
            TimeoutError("done"),
            TimeoutError("done"),
            TimeoutError("done"),
            TimeoutError("done"),
        ]

        result = self.host._broadcast_discovery(lhost="192.168.1.1", timeout=0.5)
        self.assertEqual(len(result), 0)

    @patch("oida.protocols.ethernetip.mixins.discovery.socket.socket")
    def test_multiple_different_devices(self, mock_socket_cls):
        """Multiple devices on different IPs."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        pkt1 = _build_list_identity_response(product_name="PLC1")
        pkt2 = _build_list_identity_response(product_name="PLC2")

        mock_sock.recvfrom.side_effect = [
            (pkt1, ("192.168.1.100", 44818)),
            (pkt2, ("192.168.1.101", 44818)),
            TimeoutError("done"),
            TimeoutError("done"),
            TimeoutError("done"),
            TimeoutError("done"),
        ]

        self.host._parse_list_identity_response = MagicMock(
            return_value={"success": True, "vendor_name": "Test", "product_name": "PLC"}
        )

        result = self.host._broadcast_discovery(lhost="192.168.1.1", timeout=0.5)
        self.assertEqual(len(result), 2)


# =============================================================================
# _parse_list_identity_response tests
# =============================================================================


class TestParseListIdentityResponse(unittest.TestCase):
    """Test _parse_list_identity_response method."""

    def setUp(self):
        self.host = MockDiscoveryHost()

    def test_delegates_to_parsers_valid_data(self):
        """Test the method works with valid data (delegates to parsers.parse_list_identity)."""
        response = _build_list_identity_response(vendor_id=1, product_name="TestPLC", state=3)
        result = self.host._parse_list_identity_response(response)
        self.assertTrue(result["success"])
        self.assertEqual(result["product_name"], "TestPLC")

    def test_returns_empty_on_invalid_data(self):
        """Invalid data returns default empty result."""
        result = self.host._parse_list_identity_response(b"\x00\x01")
        self.assertFalse(result["success"])
        self.assertEqual(result["vendor_id"], 0)
        self.assertEqual(result["product_name"], "")

    def test_returns_empty_on_empty_bytes(self):
        result = self.host._parse_list_identity_response(b"")
        self.assertFalse(result["success"])

    def test_valid_packet_parsed(self):
        """Full valid ListIdentity packet is parsed correctly."""
        response = _build_list_identity_response(
            vendor_id=1, product_name="MyPLC", serial=0x12345678
        )
        result = self.host._parse_list_identity_response(response)
        self.assertTrue(result["success"])
        self.assertEqual(result["serial_number"], 0x12345678)


if __name__ == "__main__":
    unittest.main()
