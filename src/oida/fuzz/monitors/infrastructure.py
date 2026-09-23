"""Infrastructure protocol monitors for fuzzing (DHCP, TFTP)."""

import socket
import struct
from typing import Optional

from oida.fuzz.monitors.base import ProtocolMonitor

# Module-level stdlib logger removed in §−1 cosmetic sweep; helpers
# now use self.logger (the NXC-style ICSLogger provided by ProtocolMonitor).


class DHCPDiscoverMonitor(ProtocolMonitor):
    """
    DHCP Discover Monitor that sends DHCP DISCOVER and validates OFFER responses.

    Validates that the DHCP server responds with OFFER messages.

    Args:
        host: Target hostname or IP
        port: Target port (default: 67)
        timeout: Request timeout in seconds (default: 2)
        check_interval: Check every N test cases (default: 1)
        retry_count: Number of retries before failure (default: 2)
        failure_threshold: Consecutive failures before reporting down (default: 2)
    """

    def __init__(
        self,
        host: str,
        port: int = 67,
        timeout: int = 2,
        check_interval: int = 1,
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

    def _create_dhcp_discover(self) -> bytes:
        """Create a DHCP DISCOVER packet"""
        # DHCP DISCOVER message (simplified)
        message = bytearray()

        # Message type (BOOTREQUEST)
        message.append(0x01)
        # Hardware type (Ethernet)
        message.append(0x01)
        # Hardware address length
        message.append(0x06)
        # Hops
        message.append(0x00)
        # Transaction ID (random)
        message.extend(struct.pack(">I", 0x12345678))
        # Seconds elapsed
        message.extend(struct.pack(">H", 0))
        # Flags
        message.extend(struct.pack(">H", 0x8000))  # Broadcast flag
        # Client IP (0.0.0.0)
        message.extend(b"\x00" * 4)
        # Your IP (0.0.0.0)
        message.extend(b"\x00" * 4)
        # Server IP (0.0.0.0)
        message.extend(b"\x00" * 4)
        # Gateway IP (0.0.0.0)
        message.extend(b"\x00" * 4)
        # Client hardware address (MAC)
        message.extend(b"\x00\x11\x22\x33\x44\x55")
        # Client hardware address padding
        message.extend(b"\x00" * 10)
        # Server hostname (64 bytes)
        message.extend(b"\x00" * 64)
        # Boot filename (128 bytes)
        message.extend(b"\x00" * 128)
        # Magic cookie
        message.extend(b"\x63\x82\x53\x63")

        # DHCP options
        # Option 53: DHCP Message Type (DISCOVER = 1)
        message.extend(b"\x35\x01\x01")
        # Option 255: End
        message.extend(b"\xff")

        return bytes(message)

    def _send_discover(self) -> Optional[bytes]:
        """Send DHCP DISCOVER and get response"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            # Bind to a local port to receive responses
            # Use port 0 to let OS assign an ephemeral port, or port 68 for standard DHCP client
            sock.bind(("0.0.0.0", 0))

            discover = self._create_dhcp_discover()
            sock.sendto(discover, (self.host, self.port))

            # Wait for DHCP OFFER response
            response, _ = sock.recvfrom(1024)

            return response

        except Exception as e:
            self.logger.debug(f"DHCP probe socket send/recv failed: {e}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception as e:
                    self.logger.debug(f"sock.close(): {e}")

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Single attempt to check if DHCP service is responding correctly"""
        response = self._send_discover()

        if response is None or len(response) < 240:
            if fuzz_data_logger:
                fuzz_data_logger.log_info("DHCPDiscoverMonitor: Failed to get DHCP OFFER")
            return False

        # Validate DHCP response (should be BOOTREPLY)
        if response[0] != 0x02:
            if fuzz_data_logger:
                fuzz_data_logger.log_info("DHCPDiscoverMonitor: Invalid DHCP response type")
            return False

        # Store baseline on first successful request
        if not self.baseline_established:
            self.baseline_established = True
            if fuzz_data_logger:
                fuzz_data_logger.log_info(
                    "DHCPDiscoverMonitor: Stored baseline (DHCP OFFER received)"
                )

        return True


class TFTPReadMonitor(ProtocolMonitor):
    """
    TFTP Read Monitor that sends read requests and validates responses.

    Sends RRQ (Read Request) for a test file and validates response.

    Args:
        host: Target hostname or IP
        port: Target port (default: 69)
        timeout: Request timeout in seconds (default: 2)
        check_interval: Check every N test cases (default: 1)
        retry_count: Number of retries before failure (default: 2)
        failure_threshold: Consecutive failures before reporting down (default: 2)
    """

    def __init__(
        self,
        host: str,
        port: int = 69,
        timeout: int = 2,
        check_interval: int = 1,
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

    def _create_tftp_rrq(self) -> bytes:
        """Create a TFTP Read Request (RRQ) packet"""
        # Opcode: RRQ (1)
        rrq = struct.pack(">H", 1)
        # Filename
        rrq += b"test.txt\x00"
        # Mode: octet
        rrq += b"octet\x00"

        return rrq

    def _send_rrq(self) -> Optional[bytes]:
        """Send TFTP RRQ and get response"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            rrq = self._create_tftp_rrq()
            sock.sendto(rrq, (self.host, self.port))

            # Wait for response (DATA or ERROR)
            response, _ = sock.recvfrom(516)

            return response

        except Exception as e:
            self.logger.debug(f"TFTP RRQ probe socket send/recv failed: {e}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception as e:
                    self.logger.debug(f"sock.close(): {e}")

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Single attempt to check if TFTP service is responding correctly"""
        response = self._send_rrq()

        if response is None or len(response) < 4:
            if fuzz_data_logger:
                fuzz_data_logger.log_info("TFTPReadMonitor: Failed to get TFTP response")
            return False

        # Validate TFTP response (should be DATA (3) or ERROR (5))
        opcode = struct.unpack(">H", response[:2])[0]
        if opcode not in [3, 5]:
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"TFTPReadMonitor: Invalid opcode {opcode}")
            return False

        # Store baseline on first successful request
        if not self.baseline_established:
            self.baseline_established = True
            if fuzz_data_logger:
                fuzz_data_logger.log_info(
                    "TFTPReadMonitor: Stored baseline (TFTP response received)"
                )

        return True


__all__ = ["DHCPDiscoverMonitor", "TFTPReadMonitor"]
