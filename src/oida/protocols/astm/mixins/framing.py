"""
ASTM Framing Mixin

Handles ENQ/ACK handshake, frame sending/receiving, and checksum calculation.

Receive buffering
------------------
A single ``recv()`` call is not guaranteed to return exactly one ASTM frame:
a fast peer can coalesce several frames into one TCP segment, and a slow one
can split a single frame across several. ``_buf_recv``/``_fill_buffer`` keep
a small per-connection byte buffer so bytes read but not yet consumed by one
operation (e.g. the tail of an application-ack reply) are not discarded and
cannot be misread as the reply to a later, unrelated handshake byte.
"""

from ..records import ACK, CR, ENQ, EOT, ETB, ETX, LF, NAK, STX


class FramingMixin:
    """Mixin providing ASTM framing operations."""

    # Maximum record-text length per physical frame (ASTM E1381); longer
    # records are split across multiple ETB-terminated frames.
    _MAX_FRAME_TEXT = 240

    # ASTM E1381 allows retransmitting an unacknowledged/garbled frame up to
    # this many times before the sender gives up on it.
    _MAX_FRAME_RETRIES = 6

    # Hard cap on unconsumed buffered bytes, so a hostile/broken peer that
    # never sends a frame terminator cannot grow the buffer without bound.
    _RX_BUFFER_CAP = 64 * 1024

    # Hard cap on frames parsed out of one _read_frames_until_eot() call, so
    # a peer that never sends EOT cannot loop us forever.
    _MAX_FRAMES_PER_READ = 100

    # -- low-level buffered receive ---------------------------------------

    def _fill_buffer(self) -> None:
        """Read one chunk from the socket and append it to the receive buffer."""
        chunk = self.conn.recv(1024)
        if not chunk:
            raise ConnectionError("ASTM peer closed the connection")
        buf = getattr(self, "_rx_buffer", b"") + chunk
        if len(buf) > self._RX_BUFFER_CAP:
            raise ConnectionError(
                f"ASTM receive buffer exceeded {self._RX_BUFFER_CAP} bytes without a complete frame"
            )
        self._rx_buffer = buf

    def _buf_recv(self, n: int) -> bytes:
        """Return exactly n bytes, preferring any already-buffered leftovers.

        When the buffer is empty this issues a single ``recv(n)`` — identical
        to the historical direct call — so link-level 1-byte ENQ/ACK/NAK reads
        behave exactly as before. Only bytes left over from a previous
        buffered read (e.g. the remainder after a frame boundary) are served
        without touching the socket, which is what stops those bytes from
        leaking into the next, unrelated read.
        """
        buf = getattr(self, "_rx_buffer", b"")
        if not buf:
            chunk = self.conn.recv(n)
            if not chunk:
                raise ConnectionError("ASTM peer closed the connection")
            buf = chunk

        while len(buf) < n:
            more = self.conn.recv(1024)
            if not more:
                raise ConnectionError("ASTM peer closed the connection")
            buf += more
            if len(buf) > self._RX_BUFFER_CAP:
                raise ConnectionError(f"ASTM receive buffer exceeded {self._RX_BUFFER_CAP} bytes")

        result, self._rx_buffer = buf[:n], buf[n:]
        return result

    def _read_frames_until_eot(self, timeout: float = 2.0) -> list:
        """Read, checksum-validate, and ACK/NAK every complete frame the peer
        sends, until EOT arrives or the read times out.

        Handles frames coalesced into a single recv() (each complete frame in
        the buffer is parsed and ACKed in turn) and frames split across
        several recv() calls (partial data is buffered until a full frame is
        available). Any bytes left over after the last frame/EOT stay in the
        receive buffer for the next read instead of being discarded.

        Returns the list of checksum-valid frame payloads, in arrival order.
        Frames that fail checksum are NAKed and are not included.
        """
        frames: list = []
        if not self.conn:
            return frames

        try:
            self.conn.settimeout(timeout)
        except Exception:
            pass

        self._rx_buffer = getattr(self, "_rx_buffer", b"")

        for _ in range(self._MAX_FRAMES_PER_READ):
            frame_bytes = None
            term_idx = -1

            # Ensure the buffer holds either an EOT or one complete frame.
            while True:
                buf = self._rx_buffer
                if buf[:1] == EOT:
                    self._rx_buffer = buf[1:]
                    return frames
                if buf[:1] == STX:
                    etx_idx = buf.find(ETX, 1)
                    etb_idx = buf.find(ETB, 1)
                    if etx_idx == -1:
                        term_idx = etb_idx
                    elif etb_idx == -1:
                        term_idx = etx_idx
                    else:
                        term_idx = min(etx_idx, etb_idx)
                    if term_idx != -1:
                        frame_end = term_idx + 1 + 2 + 2  # + checksum(2) + CR LF
                        if len(buf) >= frame_end:
                            frame_bytes = bytes(buf[:frame_end])
                            self._rx_buffer = buf[frame_end:]
                            break
                elif buf:
                    self.logger.debug(f"Unexpected byte in ASTM stream: {buf[:1]!r}")
                    self._rx_buffer = buf[1:]
                    return frames
                try:
                    self._fill_buffer()
                except TimeoutError:
                    return frames
                except Exception as e:
                    self.logger.debug(f"ASTM buffered read error: {e}")
                    return frames

            checksum_data = frame_bytes[1 : term_idx + 1]
            received_checksum = frame_bytes[term_idx + 1 : term_idx + 3]
            expected_checksum = self._calculate_checksum(checksum_data)
            try:
                if received_checksum.upper() == expected_checksum.upper():
                    frames.append(frame_bytes)
                    self.conn.sendall(ACK)
                else:
                    self.logger.debug(
                        f"Checksum mismatch: expected {expected_checksum!r}, "
                        f"got {received_checksum!r}"
                    )
                    self.conn.sendall(NAK)
            except Exception as e:
                self.logger.debug(f"ASTM ACK/NAK send error: {e}")
                return frames

        return frames

    # -- handshake -----------------------------------------------------

    def _send_enq(self) -> bool:
        """Send ENQ and wait for ACK"""
        if not self.conn:
            return False

        try:
            self.conn.sendall(ENQ)
            response = self._buf_recv(1)
            if response == ACK:
                # A new transmission is beginning: frame numbering always
                # restarts at 1 here, regardless of whether the *previous*
                # transmission's EOT/reset ever ran (it may have aborted
                # mid-stream without reaching _send_eot's success path).
                self.frame_number = 1
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

        Returns True only if the peer sends an ENQ and follows it with at
        least one checksum-valid STX-framed record — i.e. an application-level
        response. A bare timeout (no server transmission) returns False. Any
        of the server's reply frames are drained and ACKed here (rather than
        left half-read) so they cannot leak into the next handshake's read.
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

            first = self._buf_recv(1)
            if first != ENQ:
                return False

            # Server wants to transmit — ACK its ENQ and read its frame(s).
            self.conn.sendall(ACK)
            frames = self._read_frames_until_eot(timeout=timeout)
            return len(frames) > 0
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

    # -- sending ---------------------------------------------------------

    def _send_single_frame(self, data_bytes: bytes, terminator: bytes) -> bool:
        """Send one physical frame (ending in ETX or ETB), retrying on
        NAK/timeout up to _MAX_FRAME_RETRIES times per ASTM E1381.

        Does not advance self.frame_number — the caller does that once the
        fragment is ACKed, so a retried frame always keeps the same number.
        """
        if not self.conn:
            return False

        frame_num = str(self.frame_number % 8).encode()
        checksum_data = frame_num + data_bytes + terminator
        checksum = self._calculate_checksum(checksum_data)
        frame = STX + checksum_data + checksum + CR + LF

        for attempt in range(1 + self._MAX_FRAME_RETRIES):
            try:
                self.conn.sendall(frame)
                response = self._buf_recv(1)

                if response == ACK:
                    return True
                elif response == NAK:
                    self.logger.debug(
                        f"Received NAK for frame {self.frame_number} "
                        f"(attempt {attempt + 1}/{1 + self._MAX_FRAME_RETRIES})"
                    )
                    continue
                else:
                    self.logger.debug(f"Unexpected frame response: {response!r}")
                    return False
            except TimeoutError:
                self.logger.debug(
                    f"Frame {self.frame_number} timeout "
                    f"(attempt {attempt + 1}/{1 + self._MAX_FRAME_RETRIES})"
                )
                continue
            except Exception as e:
                self.logger.debug(f"Frame send error: {e}")
                return False

        self.logger.debug(
            f"Frame {self.frame_number} rejected after {1 + self._MAX_FRAME_RETRIES} attempts"
        )
        return False

    def _send_frame(self, record_data: str) -> bool:
        """Send ASTM framed data with checksum.

        Frame structure: STX + frame_num + text + (ETB|ETX) + checksum + CR + LF.
        Record text longer than _MAX_FRAME_TEXT is split across multiple
        ETB-terminated intermediate frames, with the final fragment carrying
        the record-terminating CR before ETX (the CR belongs to the record
        text, so it lands wherever the text itself ends).
        """
        if not self.conn:
            return False

        try:
            text_bytes = record_data.encode("utf-8")

            if len(text_bytes) <= self._MAX_FRAME_TEXT:
                fragments = [(text_bytes + CR, ETX)]
            else:
                fragments = []
                remaining = text_bytes
                while len(remaining) > self._MAX_FRAME_TEXT:
                    fragments.append((remaining[: self._MAX_FRAME_TEXT], ETB))
                    remaining = remaining[self._MAX_FRAME_TEXT :]
                fragments.append((remaining + CR, ETX))

            for data_bytes, terminator in fragments:
                if not self._send_single_frame(data_bytes, terminator):
                    return False
                self.frame_number += 1

            return True
        except Exception as e:
            self.logger.debug(f"Frame send error: {e}")
            return False
