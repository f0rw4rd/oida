"""
EtherNet/IP Encapsulation Commands Mixin

Handles ENIP packet building, parsing, and session registration:
- Build/parse ENIP encapsulation packets
- Parse CIP responses from SendRRData
- Send ENIP commands over TCP/UDP
- Register sessions for CIP communication
"""

from __future__ import annotations

import struct
from typing import Any, Dict, Optional, TYPE_CHECKING

from oida.utils.protocol_helpers import ConnectionHelper
from oida.protocols.ethernetip.constants import ENIP_CMD_REGISTER_SESSION

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class EnipCommandsMixin(_ScannerBase):
    """Mixin providing EtherNet/IP encapsulation command operations."""

    def _build_enip_packet(self, command: int, data: bytes = b"") -> bytes:
        """Build an EtherNet/IP encapsulation packet"""
        # EtherNet/IP header: command(2) + length(2) + session(4) + status(4) + context(8) + options(4) = 24 bytes
        header = struct.pack(
            "<HHIIQ I",
            command,  # Command
            len(data),  # Length
            0,  # Session handle (0 for List commands)
            0,  # Status
            0,  # Sender context
            0,  # Options
        )
        return header + data

    def _parse_enip_header(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse EtherNet/IP encapsulation header"""
        if len(data) < 24:
            return None
        try:
            # Only the first 12 bytes (command/length/session/status) are
            # consumed by callers. The old unpack read sender_context + a
            # 2-byte "options" (the real ENIP options field is 4 bytes) and no
            # caller ever read either, so drop them rather than mis-parse.
            command, length, session, status = struct.unpack("<HHII", data[:12])
            return {
                "command": command,
                "length": length,
                "session": session,
                "status": status,
                "data": data[24 : 24 + length] if len(data) >= 24 + length else b"",
            }
        except struct.error as e:
            self.logger.debug(f"parse enip header failed: {e}")
            return None

    def _parse_cip_response(self, data: bytes) -> Dict[str, Any]:
        """Parse CIP response from SendRRData reply.

        Structure after ENIP header (24 bytes):
        - Interface Handle (4 bytes)
        - Timeout (2 bytes)
        - Item Count (2 bytes)
        - Item 0: Null Address (type 0x0000, len 0)
        - Item 1: Unconnected Data (type 0x00B2, len N)
          - Reply Service (1 byte)
          - Reserved (1 byte)
          - General Status (1 byte)
          - Additional Status Size (1 byte)
        """
        result = {"general_status": 0xFF, "reply_service": 0}

        try:
            if len(data) < 24:
                return result

            # Skip ENIP header, parse CPF
            cpf_data = data[24:]
            if len(cpf_data) < 8:
                return result

            iface_handle, timeout, item_count = struct.unpack("<IHH", cpf_data[:8])
            offset = 8

            # Find Unconnected Data item (0x00B2)
            for _ in range(item_count):
                if offset + 4 > len(cpf_data):
                    break
                item_type, item_len = struct.unpack("<HH", cpf_data[offset : offset + 4])
                offset += 4

                if item_type == 0x00B2 and item_len >= 4:
                    # CIP response: reply_service, reserved, general_status, add_status_size
                    cip_data = cpf_data[offset : offset + item_len]
                    reply_service, _reserved, general_status, _add_size = struct.unpack(
                        "<BBBB", cip_data[:4]
                    )
                    result["reply_service"] = reply_service
                    result["general_status"] = general_status
                    break

                offset += item_len

        except struct.error as e:
            self.logger.debug(f"parse cip response failed: {e}")
            pass

        return result

    # TODO: Raw socket ENIP command layer - consider wrapping with cpppo's
    # client.connector or pycomm3's CIPDriver for session/connection management
    # instead of manual packet construction + bare socket send/recv.
    def _send_enip_command(
        self,
        host: str,
        port: int,
        command: int,
        data: bytes = b"",
    ) -> Optional[bytes]:
        """Send an EtherNet/IP command over TCP and receive the response."""
        packet = self._build_enip_packet(command, data)
        sock = None

        try:
            sock = ConnectionHelper.create_tcp_socket(host, port, self.timeout)
            sock.send(packet)
            response = sock.recv(4096)
            return response
        except TimeoutError:
            self.logger.debug(f"Timeout sending command 0x{command:04X} to {host}:{port}")
            return None
        except Exception as e:
            self.logger.debug(f"Error sending command 0x{command:04X}: {e}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception as e:
                    self.logger.debug(f"send enip command failed: {e}")
                    pass  # Ignore socket close errors

    def _register_session(self, host: str, port: int = 44818) -> Optional[int]:
        """
        Register an EtherNet/IP session for CIP communication.

        Returns session handle on success, None on failure.
        """
        # Register Session command (0x65)
        # Data: Protocol version (1) + Options flags (0)
        register_data = struct.pack("<HH", 1, 0)
        response = self._send_enip_command(host, port, ENIP_CMD_REGISTER_SESSION, register_data)

        if not response:
            return None

        header = self._parse_enip_header(response)
        if not header or header["status"] != 0:
            return None

        return header["session"]
