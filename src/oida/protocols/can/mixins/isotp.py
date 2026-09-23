"""
CAN ISO-TP (ISO 15765-2) Mixin

Receive-side ISO-TP transport helper. The scanner only ever sends
single-frame (<=7-byte) requests, so no TX segmentation is needed -- but a
spec-compliant ECU answers a multi-frame response with a First Frame and then
waits for the tester's Flow Control (0x30) before streaming Consecutive
Frames. This mixin provides:

- ``isotp_recv``: recv a single ISO-TP message for a request/response ID pair.
  On a Single Frame it returns the de-framed payload immediately (no FC, no CF
  wait). On a First Frame it sends ONE Flow Control frame (CTS, BS=0, STmin=0)
  then collects Consecutive Frames and delegates stitching to
  ``_assemble_isotp_data``.
- ``_assemble_isotp_data``: the single, shared SF/FF+CF reassembler (the only
  copy in the codebase; both the scanner and the NXC connection inherit it).

All loops are bounded by a deadline -- ``isotp_recv`` never hangs, returning a
partial payload or ``None`` on missing / out-of-order CFs.
"""

import time
from typing import Any, List, Optional, Tuple

from oida.protocols.can.constants import (
    ISOTP_CONSECUTIVE_FRAME,
    ISOTP_FC_CONTINUE,
    ISOTP_FIRST_FRAME,
    ISOTP_FLOW_CONTROL,
    ISOTP_SINGLE_FRAME,
    OBD2_REQUEST_ID,
    OBD2_RESPONSE_RANGE,
)


def _get_python_can() -> Any:
    """Resolve _python_can from scanner module (avoids circular import)."""
    from oida.protocols.can.scanner import _python_can

    return _python_can


class ISOTPMixin:
    """Mixin providing receive-side ISO-TP (ISO 15765-2) transport."""

    def _isotp_id_matches(self, msg: Any, request_id: int, response_id: int) -> bool:
        """Return True if ``msg`` is a plausible response to ``request_id``.

        Mirrors the matching used by ``_recv_uds_response``: an exact match on
        the expected ``response_id``, plus the OBD-II broadcast case where a
        request on 0x7DF may be answered by any ECU in the response range.
        """
        if msg.arbitration_id == response_id:
            return True
        if request_id == OBD2_REQUEST_ID:
            return OBD2_RESPONSE_RANGE[0] <= msg.arbitration_id <= OBD2_RESPONSE_RANGE[1]
        return False

    def isotp_recv(
        self,
        bus: Any,
        request_id: int,
        response_id: int,
        timeout: float = 0.2,
    ) -> Optional[Tuple[int, bytes]]:
        """Receive one ISO-TP message, sending Flow Control if multi-frame.

        Args:
            bus: python-can Bus instance.
            request_id: arbitration ID the request was sent on (used to send
                Flow Control and to match OBD-II broadcast responses).
            response_id: expected response arbitration ID.
            timeout: overall deadline in seconds.

        Returns:
            A ``(arbitration_id, payload)`` tuple where ``arbitration_id`` is the
            real source ID of the frame that was accepted (important for OBD-II
            broadcast probes, where any ECU in the response range may answer)
            and ``payload`` is the de-framed message (service byte first, PCI
            stripped, trimmed to the declared length). ``None`` if nothing
            usable arrived.
        """
        end_time = time.time() + timeout

        # ------------------------------------------------------------------
        # 1. Wait for the first matching frame (SF or FF).
        # ------------------------------------------------------------------
        first: Optional[bytes] = None
        source_id: Optional[int] = None
        while time.time() < end_time:
            remaining = end_time - time.time()
            if remaining <= 0:
                break
            try:
                msg = bus.recv(timeout=min(remaining, 0.05))
            except Exception:
                # udp_multicast datagrams can coalesce under load, yielding
                # msgpack decode failures; skip the corrupt packet and continue.
                continue
            if msg is None:
                continue
            if not self._isotp_id_matches(msg, request_id, response_id):
                continue
            data = bytes(msg.data)
            if not data:
                continue
            first = data
            source_id = msg.arbitration_id
            break

        if first is None or source_id is None:
            return None

        frame_type = first[0] & 0xF0

        # ------------------------------------------------------------------
        # 2. Single Frame: done, no FC / CF needed (keeps mocked-bus tests fast).
        # ------------------------------------------------------------------
        if frame_type == ISOTP_SINGLE_FRAME:
            payload = self._assemble_isotp_data([first])
            return None if payload is None else (source_id, payload)

        # ------------------------------------------------------------------
        # 3. First Frame: send Flow Control, then collect Consecutive Frames.
        # ------------------------------------------------------------------
        if frame_type == ISOTP_FIRST_FRAME:
            # The 12-bit length spans both PCI bytes, so a First Frame shorter
            # than 2 bytes has no declared length -- a hostile/truncated ECU
            # reply like b"\x10" would IndexError here. Treat it as unusable.
            if len(first) < 2:
                return None
            total_length = ((first[0] & 0x0F) << 8) | first[1]
            self._send_flow_control(bus, request_id)

            frames: List[bytes] = [first]
            collected = len(first[2:])  # data bytes carried by the FF
            # The FF is implicitly SN 0; the first CF must carry SN 1 and each
            # subsequent CF increments mod 16. On a duplicating transport (the
            # udp_multicast test bus re-sends frames) a Consecutive Frame can
            # arrive twice or interleaved with a stale copy, so a frame whose SN
            # does not match the one we expect is treated as a duplicate/stray
            # and skipped -- we keep waiting for the expected SN rather than
            # aborting (which would drop an otherwise-complete payload).
            expected_sn = 1
            while collected < total_length and time.time() < end_time:
                remaining = end_time - time.time()
                if remaining <= 0:
                    break
                try:
                    msg = bus.recv(timeout=min(remaining, 0.05))
                except Exception:
                    # udp_multicast datagrams can coalesce under load, yielding
                    # msgpack decode failures; skip the corrupt packet and continue.
                    continue
                if msg is None:
                    continue
                if not self._isotp_id_matches(msg, request_id, response_id):
                    continue
                cf = bytes(msg.data)
                if not cf or (cf[0] & 0xF0) != ISOTP_CONSECUTIVE_FRAME:
                    continue
                if (cf[0] & 0x0F) != expected_sn:
                    # Duplicate or out-of-order Consecutive Frame: ignore it and
                    # keep waiting for the SN we actually need.
                    continue
                expected_sn = (expected_sn + 1) & 0x0F
                frames.append(cf)
                collected += len(cf[1:])

            payload = self._assemble_isotp_data(frames)
            return None if payload is None else (source_id, payload)

        # Flow Control / unknown frame type as the first frame: nothing usable.
        return None

    def _send_flow_control(self, bus: Any, request_id: int) -> None:
        """Send a single ISO-TP Flow Control frame (CTS, BS=0, STmin=0)."""
        can = _get_python_can()()
        fc = bytes([ISOTP_FLOW_CONTROL | ISOTP_FC_CONTINUE, 0x00, 0x00, 0, 0, 0, 0, 0])
        try:
            msg = can.Message(arbitration_id=request_id, data=fc, is_extended_id=False)
            bus.send(msg)
        except Exception as e:  # pragma: no cover - defensive
            self.logger.debug(f"ISO-TP: Flow Control send failed: {e}")

    def _assemble_isotp_data(self, frames: List[bytes]) -> Optional[bytes]:
        """Assemble data from ISO-TP frames.

        Handles single-frame and multi-frame (first + consecutive) messages.
        This is the single shared reassembler used by both ``CANScanner`` and
        the NXC ``can`` connection.

        Args:
            frames: List of raw CAN frame data payloads.

        Returns:
            Assembled (de-framed) payload bytes or None.
        """
        if not frames:
            return None

        first = frames[0]
        if not first:
            return None

        frame_type = (first[0] >> 4) & 0x0F

        if frame_type == 0x0:
            # Single frame
            length = first[0] & 0x0F
            return first[1 : 1 + length]

        elif frame_type == 0x1:
            # First frame + consecutive frames. A 1-byte FF carries no length
            # nibble pair and cannot be reassembled (see isotp_recv).
            if len(first) < 2:
                return None
            total_length = ((first[0] & 0x0F) << 8) | first[1]
            assembled = bytearray(first[2:])

            for cf in frames[1:]:
                if not cf:
                    continue
                cf_type = (cf[0] >> 4) & 0x0F
                if cf_type == 0x2:
                    assembled.extend(cf[1:])

            return bytes(assembled[:total_length])

        return None
