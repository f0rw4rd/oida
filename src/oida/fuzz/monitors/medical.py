"""Medical protocol monitors for fuzzing (HL7)."""

import socket
import time
from typing import Optional

from .base import ProtocolMonitor


class HL7Monitor(ProtocolMonitor):
    """
    HL7 MLLP Monitor that sends ACK messages and validates responses.

    Uses MLLP (Minimal Lower Layer Protocol) framing with:
    - Start: 0x0B (Vertical Tab)
    - End: 0x1C 0x0D (File Separator + Carriage Return)

    Args:
        host: Target hostname or IP
        port: Target port (default: 2575)
        timeout: Request timeout in seconds (default: 5)
        check_interval: Check every N test cases (default: 3)
        retry_count: Number of retries before failure (default: 2)
        failure_threshold: Consecutive failures before reporting down (default: 2)
    """

    # MLLP framing constants
    MLLP_START = b"\x0b"
    MLLP_END = b"\x1c\x0d"

    def __init__(
        self,
        host: str,
        port: int = 2575,
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

        # HL7-specific baseline
        self.baseline_ack_code: Optional[str] = None

    def _create_hl7_ack(self) -> bytes:
        """Create a simple HL7 ACK message wrapped in MLLP"""
        timestamp = time.strftime("%Y%m%d%H%M%S")
        msg_id = f"MONITOR{timestamp}"

        # Simple ACK message
        hl7_message = (
            f"MSH|^~\\&|MONITOR|MONITOR|TARGET|TARGET|{timestamp}||ACK|{msg_id}|P|2.5\r"
            f"MSA|AA|{msg_id}|\r"
        )

        return self.MLLP_START + hl7_message.encode("ascii") + self.MLLP_END

    def _send_message(self) -> Optional[bytes]:
        """Send HL7 message and get response"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))

            # Send ACK message
            message = self._create_hl7_ack()
            sock.send(message)

            # Read response (with MLLP framing).
            # Same OOM guard as hl7/utils.py:send_probe — a peer that
            # never sends MLLP_END can't drive us to OOM. Pin the
            # buffer at 16 MiB; fuzz targets that ignore framing
            # (the whole point of this monitor) hit this all the time.
            MAX_HL7_RESPONSE = 16 * 1024 * 1024
            response = b""
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                response += chunk
                # Check for MLLP end marker
                if self.MLLP_END in response:
                    break
                if len(response) > MAX_HL7_RESPONSE:
                    self.logger.debug(
                        f"HL7Monitor: response capped at {MAX_HL7_RESPONSE} bytes "
                        f"(target never sent MLLP_END)"
                    )
                    break

            return response

        except Exception as e:
            self.logger.debug(f"HL7 send failed: {e}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception as e:
                    self.logger.debug(f"Socket close error: {e}")

    def _parse_ack_code(self, response: bytes) -> Optional[str]:
        """Extract ACK code from MSA segment"""
        try:
            # Remove MLLP framing
            if response.startswith(self.MLLP_START):
                response = response[1:]
            if self.MLLP_END in response:
                response = response[: response.index(self.MLLP_END)]

            # Parse HL7 message
            message = response.decode("ascii", errors="ignore")
            for segment in message.split("\r"):
                if segment.startswith("MSA|"):
                    fields = segment.split("|")
                    if len(fields) >= 2:
                        return fields[1]  # AA, AE, AR, etc.
            return None
        except Exception as e:
            self.logger.debug(f"if response.startswith(self.MLLP_START):: {e}")
            return None

    def _store_baseline(self, response: bytes, fuzz_data_logger=None):
        """Store the first response as baseline"""
        self.baseline_response = response
        self.baseline_ack_code = self._parse_ack_code(response)
        self.baseline_established = True

        if fuzz_data_logger:
            fuzz_data_logger.log_info(
                f"HL7Monitor: Stored baseline response (ACK code={self.baseline_ack_code})"
            )

    def _compare_responses(self, current: bytes, fuzz_data_logger=None) -> bool:
        """Compare current response against baseline"""
        current_ack = self._parse_ack_code(current)

        # Check if we got an ACK response
        if current_ack is None:
            if fuzz_data_logger:
                fuzz_data_logger.log_fail("HL7Monitor: Invalid or missing ACK response")
            return False

        # Check if ACK code changed significantly
        if self.baseline_ack_code and current_ack != self.baseline_ack_code:
            # AA->AE or AA->AR could indicate issues
            if self.baseline_ack_code == "AA" and current_ack in ["AE", "AR", "CR"]:
                if fuzz_data_logger:
                    fuzz_data_logger.log_fail(
                        f"HL7Monitor: ACK code changed from {self.baseline_ack_code} to {current_ack}"
                    )
                return False

        return True

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Single attempt to check if HL7 service is responding correctly"""
        response = self._send_message()

        if response is None:
            if fuzz_data_logger:
                fuzz_data_logger.log_info("HL7Monitor: Failed to connect to HL7 service")
            return False

        # Check for valid MLLP framing
        if not response.startswith(self.MLLP_START):
            if fuzz_data_logger:
                fuzz_data_logger.log_info("HL7Monitor: Response missing MLLP start marker")
            return False

        # Store baseline on first successful request
        if not self.baseline_established:
            self._store_baseline(response, fuzz_data_logger)
            return True

        # Compare against baseline
        return self._compare_responses(response, fuzz_data_logger)


__all__ = ["HL7Monitor"]
