"""
ASTM Framing Mixin

Handles ENQ/ACK handshake, frame sending/receiving, and checksum calculation.
"""

from typing import Optional

from ..records import STX, ETX, EOT, ENQ, ACK, NAK, ETB, CR, LF


class FramingMixin:
    """Mixin providing ASTM framing operations."""

    def _send_enq(self) -> bool:
        """Send ENQ and wait for ACK"""
        if not self.conn:
            return False

        try:
            self.conn.sendall(ENQ)
            response = self.conn.recv(1)
            if response == ACK:
                return True
            elif response == NAK:
                self.logger.debug("Received NAK to ENQ")
                return False
            else:
                self.logger.debug(f"Unexpected response to ENQ: {response!r}")
                return False
        except TimeoutError:
            self.logger.debug("ENQ timeout")
            return False
        except Exception as e:
            self.logger.debug(f"ENQ error: {e}")
            return False

    def _send_eot(self) -> bool:
        """Send EOT (end of transmission)"""
        if not self.conn:
            return False

        try:
            self.conn.sendall(EOT)
            self.frame_number = 1  # Reset frame counter
            return True
        except Exception as e:
            self.logger.debug(f"EOT error: {e}")
            return False

    def _calculate_checksum(self, data: bytes) -> bytes:
        """Calculate modulus-256 checksum as 2-char hex.

        Delegates to ASTMRecordBuilder so the framing and builder paths can
        never drift; falls back to a local computation only if no builder is
        attached yet.
        """
        if getattr(self, "record_builder", None) is not None:
            return self.record_builder._calculate_checksum(data)
        total = sum(data) % 256
        return f"{total:02X}".encode()

    def _send_frame(self, record_data: str) -> bool:
        """Send ASTM framed data with checksum"""
        if not self.conn:
            return False

        try:
            # Frame structure: STX + frame_num + data + ETX + checksum + CR + LF
            frame_num = str(self.frame_number % 8).encode()
            data_bytes = record_data.encode("utf-8")

            # Checksum covers: frame_num + data + ETX
            checksum_data = frame_num + data_bytes + ETX
            checksum = self._calculate_checksum(checksum_data)

            # Full frame
            frame = STX + checksum_data + checksum + CR + LF
            self.conn.sendall(frame)

            # Wait for ACK/NAK
            response = self.conn.recv(1)

            if response == ACK:
                self.frame_number += 1
                return True
            elif response == NAK:
                self.logger.debug(f"Received NAK for frame {self.frame_number}")
                return False
            else:
                self.logger.debug(f"Unexpected frame response: {response!r}")
                return False

        except TimeoutError:
            self.logger.debug(f"Frame {self.frame_number} timeout")
            return False
        except Exception as e:
            self.logger.debug(f"Frame send error: {e}")
            return False

    def _receive_frame(self) -> Optional[str]:
        """Receive and validate ASTM frame"""
        if not self.conn:
            return None

        MAX_FRAME_SIZE = 64 * 1024  # 64KB per frame (ASTM frames are small)
        try:
            # Read until we get a complete frame
            data = bytearray()
            while True:
                chunk = self.conn.recv(1024)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > MAX_FRAME_SIZE:
                    return None
                if CR + LF in data:
                    break

            if not data:
                return None

            # Strip STX
            if data.startswith(STX):
                data = data[1:]

            # Find ETX or ETB
            etx_pos = data.find(ETX)
            etb_pos = data.find(ETB)

            if etx_pos == -1 and etb_pos == -1:
                self.logger.debug("No ETX/ETB found in frame")
                return None

            end_pos = etx_pos if etx_pos != -1 else etb_pos

            # Extract frame content (frame_num + record_data)
            frame_content = data[: end_pos + 1]

            # Validate checksum (2 bytes after ETX/ETB).
            # If the buffer doesn't contain the full checksum yet, that's
            # a short read — the old code silently fell through to ACK,
            # accepting truncated frames as valid. Treat short-read the
            # same as checksum mismatch: NAK and bail.
            if len(data) <= end_pos + 3:
                self.logger.debug(
                    f"Short read: frame ends at {end_pos} but buffer is only "
                    f"{len(data)} bytes — checksum truncated"
                )
                self.conn.sendall(NAK)
                return None

            received_checksum = data[end_pos + 1 : end_pos + 3]
            calculated_checksum = self._calculate_checksum(frame_content)
            if received_checksum != calculated_checksum:
                self.logger.debug(
                    f"Checksum mismatch: {received_checksum!r} vs {calculated_checksum!r}"
                )
                self.conn.sendall(NAK)
                return None

            # Send ACK
            self.conn.sendall(ACK)

            # Return record data (skip frame number)
            record_data = frame_content[1:-1].decode("utf-8", errors="ignore")
            return record_data

        except TimeoutError as e:
            self.logger.debug("receive frame failed: %s", e)
            return None
        except Exception as e:
            self.logger.debug(f"Frame receive error: {e}")
            return None
