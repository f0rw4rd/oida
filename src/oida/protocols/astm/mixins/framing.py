"""
ASTM Framing Mixin

Handles ENQ/ACK handshake, frame sending/receiving, and checksum calculation.
"""

from ..records import STX, ETX, EOT, ENQ, ACK, NAK, CR, LF


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

    def _read_application_ack(self, timeout: float = 2.0) -> bool:
        """Check for an application-level acknowledgement after a transmission.

        A frame-level ACK (the single ACK byte _send_frame waits on) only
        confirms data-link receipt + checksum per ASTM E1381 — a conformant
        receiver ACKs any well-formed frame *before* the LIS application has
        validated or persisted the record. To distinguish that link-level ACK
        from genuine application acceptance, we look for the receiver opening
        its own transmission (server-initiated ENQ followed by a data record
        such as a Comment/Manufacturer/status reply) after our EOT.

        Returns True only if the peer sends an ENQ and follows it with at least
        one STX-framed record — i.e. an application-level response. A bare
        timeout (no server transmission) returns False.
        """
        if not self.conn:
            return False

        prev_timeout = None
        try:
            try:
                prev_timeout = self.conn.gettimeout()
            except Exception:
                prev_timeout = None
            self.conn.settimeout(timeout)

            first = self.conn.recv(1)
            if first != ENQ:
                return False

            # Server wants to transmit — ACK its ENQ and read the first frame.
            self.conn.sendall(ACK)
            frame = self.conn.recv(1024)
            # An application reply carries an STX-framed record. EOT alone (the
            # server immediately ending its transmission) is not an acceptance.
            return bool(frame) and STX in frame
        except TimeoutError:
            self.logger.debug("No application-level response (timeout)")
            return False
        except Exception as e:
            self.logger.debug(f"Application ACK read error: {e}")
            return False
        finally:
            try:
                if prev_timeout is not None:
                    self.conn.settimeout(prev_timeout)
            except Exception:
                pass

    def _calculate_checksum(self, data: bytes) -> bytes:
        """Calculate modulus-256 checksum as 2-char hex.

        Delegates to ASTMRecordBuilder so the framing and builder paths can
        never drift. record_builder is always attached before framing runs.
        """
        return self.record_builder._calculate_checksum(data)

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
