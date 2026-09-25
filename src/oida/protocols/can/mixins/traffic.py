"""
CAN Traffic Mixin

Handles passive traffic sniffing and raw CAN operations:
- Traffic sniffing with statistics collection
- Traffic statistics display
- Arbitration ID classification
- Raw CAN message send/receive
- Arbitration ID filter parsing
"""

import time
from typing import Any, Dict, List, Optional, Set

from oida.utils.export_utils import export_table
from oida.protocols.can.constants import (
    CAN_EXT_ID_MAX,
    CAN_STD_ID_MAX,
    CANOPEN_HEARTBEAT_BASE,
    CANOPEN_NMT_ID,
    CANOPEN_SDO_RX_BASE,
    CANOPEN_SDO_TX_BASE,
    COMMON_UDS_PAIRS,
    OBD2_REQUEST_ID,
    OBD2_RESPONSE_RANGE,
    CANMessage,
    CANTrafficStats,
    make_traffic_key,
    split_traffic_key,
)


def _get_python_can():
    """Resolve _python_can from scanner module (avoids circular import)."""
    from oida.protocols.can.scanner import _python_can

    return _python_can


class TrafficMixin:
    """Mixin providing CAN bus traffic sniffing and raw message operations."""

    def _sniff_traffic(self, bus: Any, duration: int = 10) -> CANTrafficStats:
        """
        Passively sniff CAN bus traffic and collect statistics.

        Args:
            bus: python-can Bus instance
            duration: Sniff duration in seconds

        Returns:
            CANTrafficStats with collected data
        """
        stats = CANTrafficStats()
        start_time = time.time()
        end_time = start_time + duration

        msg_count = 0

        while time.time() < end_time:
            remaining = end_time - time.time()
            if remaining <= 0:
                break

            try:
                msg = bus.recv(timeout=min(remaining, 1.0))
            except Exception:
                # udp_multicast datagrams can coalesce under load, yielding
                # msgpack decode failures; skip the corrupt packet and continue.
                stats.error_frames += 1
                continue
            if msg is None:
                continue

            arb_id = msg.arbitration_id

            # Apply ID filter if set - restrict the capture to matching IDs.
            if self.id_filter and arb_id not in self.id_filter:
                continue

            msg_count += 1

            # Update ID counts. Key on the frame format as well as the numeric
            # ID: a standard 0x123 and an extended 0x123 are different frames on
            # the wire and must not be merged into one statistics row.
            key = make_traffic_key(arb_id, msg.is_extended_id)
            if key not in stats.id_counts:
                stats.id_counts[key] = 0
            stats.id_counts[key] += 1

            # Track extended IDs
            if msg.is_extended_id:
                stats.extended_ids.add(arb_id & CAN_EXT_ID_MAX)

            # Track error/remote frames
            if msg.is_error_frame:
                stats.error_frames += 1
            if msg.is_remote_frame:
                stats.remote_frames += 1

        actual_duration = time.time() - start_time
        stats.total_messages = msg_count
        stats.unique_ids = len(stats.id_counts)
        stats.duration_seconds = round(actual_duration, 2)
        stats.messages_per_second = (
            round(msg_count / actual_duration, 1) if actual_duration > 0 else 0
        )

        return stats

    def _print_traffic_stats(self, stats: CANTrafficStats) -> None:
        """Print traffic statistics summary."""
        self.logger.display(f"  Total messages: {stats.total_messages}")
        self.logger.display(f"  Unique IDs: {stats.unique_ids}")
        self.logger.display(f"  Duration: {stats.duration_seconds}s")
        self.logger.display(f"  Rate: {stats.messages_per_second} msg/s")

        if stats.error_frames:
            self.logger.warning(f"  Error frames: {stats.error_frames}")
        if stats.remote_frames:
            self.logger.display(f"  Remote frames: {stats.remote_frames}")
        if stats.extended_ids:
            self.logger.display(f"  Extended IDs seen: {len(stats.extended_ids)}")

        # Show top IDs
        top_ids = stats.get_top_ids(15)
        if top_ids:
            rows = []
            for key, count in top_ids:
                arb_id, is_ext = split_traffic_key(key)
                id_str = f"0x{arb_id:08X}" if is_ext else f"0x{arb_id:03X}"
                pct = (count / stats.total_messages * 100) if stats.total_messages > 0 else 0
                label = self._identify_id(arb_id, is_ext)
                rows.append([id_str, str(count), f"{pct:.1f}%", label])

            export_table(
                "can_traffic",
                ["Arb ID", "Count", "%", "Classification"],
                rows,
                title="Top Arbitration IDs",
            )

    def _classify_traffic(self, stats: CANTrafficStats) -> List[Dict[str, Any]]:
        """
        Classify observed arbitration IDs into protocol categories.

        Returns:
            List of classified device/node dictionaries
        """
        classified = []

        for key, count in sorted(stats.id_counts.items()):
            arb_id, is_ext = split_traffic_key(key)
            entry = {
                "arbitration_id": f"0x{arb_id:08X}" if is_ext else f"0x{arb_id:03X}",
                "count": count,
                "extended": is_ext,
                "classification": self._identify_id(arb_id, is_ext),
            }
            classified.append(entry)

        return classified

    def _identify_id(self, arb_id: int, is_extended: Optional[bool] = None) -> str:
        """Classify a single arbitration ID.

        ``is_extended`` says whether the frame used the 29-bit format. It matters
        because the OBD-II/UDS/CANopen ranges below are all 11-bit assignments: a
        29-bit frame that happens to carry the numeric value 0x7E8 is not an
        OBD-II response. When it is omitted the format is inferred from the
        numeric value, which is only reliable for IDs above the 11-bit range.
        """
        if is_extended is None:
            is_extended = arb_id > CAN_STD_ID_MAX

        if is_extended:
            # None of the 11-bit assignments below apply to an extended frame.
            return "Extended frame (possible J1939)"

        # OBD-II
        if arb_id == OBD2_REQUEST_ID:
            return "OBD-II Request (broadcast)"
        if OBD2_RESPONSE_RANGE[0] <= arb_id <= OBD2_RESPONSE_RANGE[1]:
            ecu_num = arb_id - OBD2_RESPONSE_RANGE[0] + 1
            return f"OBD-II Response (ECU #{ecu_num})"

        # UDS
        if arb_id in COMMON_UDS_PAIRS:
            return f"UDS Request -> 0x{COMMON_UDS_PAIRS[arb_id]:03X}"
        if arb_id in COMMON_UDS_PAIRS.values():
            return "UDS Response"

        # CANopen
        if arb_id == CANOPEN_NMT_ID:
            return "CANopen NMT"
        if arb_id == 0x080:
            return "CANopen SYNC"
        if 0x081 <= arb_id <= 0x0FF:
            node = arb_id - 0x080
            return f"CANopen Emergency (node {node})"
        if 0x181 <= arb_id <= 0x1FF:
            node = arb_id - 0x180
            return f"CANopen TPDO1 (node {node})"
        if 0x201 <= arb_id <= 0x27F:
            node = arb_id - 0x200
            return f"CANopen RPDO1 (node {node})"
        if 0x281 <= arb_id <= 0x2FF:
            node = arb_id - 0x280
            return f"CANopen TPDO2 (node {node})"
        if 0x301 <= arb_id <= 0x37F:
            node = arb_id - 0x300
            return f"CANopen RPDO2 (node {node})"
        if 0x381 <= arb_id <= 0x3FF:
            node = arb_id - 0x380
            return f"CANopen TPDO3 (node {node})"
        if 0x401 <= arb_id <= 0x47F:
            node = arb_id - 0x400
            return f"CANopen RPDO3 (node {node})"
        if 0x481 <= arb_id <= 0x4FF:
            node = arb_id - 0x480
            return f"CANopen TPDO4 (node {node})"
        if 0x501 <= arb_id <= 0x57F:
            node = arb_id - 0x500
            return f"CANopen RPDO4 (node {node})"
        if CANOPEN_SDO_TX_BASE < arb_id <= 0x5FF:
            node = arb_id - CANOPEN_SDO_TX_BASE
            return f"CANopen SDO Response (node {node})"
        if CANOPEN_SDO_RX_BASE < arb_id <= 0x67F:
            node = arb_id - CANOPEN_SDO_RX_BASE
            return f"CANopen SDO Request (node {node})"
        if CANOPEN_HEARTBEAT_BASE < arb_id <= 0x77F:
            node = arb_id - CANOPEN_HEARTBEAT_BASE
            return f"CANopen Heartbeat (node {node})"

        # J1939 detection (extended IDs)
        if arb_id > CAN_STD_ID_MAX:
            return "Extended frame (possible J1939)"

        return ""

    def send_message(
        self,
        bus: Any,
        arb_id: int,
        data: bytes,
        is_extended: bool = False,
    ) -> bool:
        """
        Send a raw CAN message.

        Args:
            bus: python-can Bus instance
            arb_id: Arbitration ID
            data: Data bytes (up to 8 for classic CAN)
            is_extended: Use extended (29-bit) arbitration ID

        Returns:
            True if message was sent successfully
        """
        can = _get_python_can()()
        try:
            msg = can.Message(
                arbitration_id=arb_id,
                data=data,
                is_extended_id=is_extended,
            )
            bus.send(msg)
            self.logger.debug(f"Sent: ID=0x{arb_id:03X} Data={' '.join(f'{b:02X}' for b in data)}")
            return True
        except Exception as e:
            self.logger.fail(f"Send failed: {e}")
            return False

    def recv_message(self, bus: Any, timeout: float = 1.0) -> Optional[CANMessage]:
        """
        Receive a single CAN message.

        Args:
            bus: python-can Bus instance
            timeout: Maximum wait time

        Returns:
            CANMessage or None if timeout
        """
        msg = bus.recv(timeout=timeout)
        if msg is None:
            return None

        return CANMessage(
            arbitration_id=msg.arbitration_id,
            data=bytes(msg.data),
            timestamp=msg.timestamp or time.time(),
            is_extended=msg.is_extended_id,
            is_remote=msg.is_remote_frame,
            is_error=msg.is_error_frame,
            dlc=msg.dlc,
            channel=str(getattr(msg, "channel", "")),
        )

    def _parse_id_filter(self, filter_str: str) -> Optional[Set[int]]:
        """Parse arbitration ID filter string into a set of IDs."""
        if not filter_str:
            return None

        ids: Set[int] = set()
        for part in filter_str.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                # Range: 0x100-0x1FF
                lo, hi = part.split("-", 1)
                try:
                    lo_int = int(lo.strip(), 0)
                    hi_int = int(hi.strip(), 0)
                    ids.update(range(lo_int, hi_int + 1))
                except ValueError:
                    self.logger.warning(f"Invalid filter range: {part}")
            else:
                try:
                    ids.add(int(part, 0))
                except ValueError:
                    self.logger.warning(f"Invalid filter ID: {part}")

        return ids if ids else None
