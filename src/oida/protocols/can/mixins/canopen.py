"""
CAN CANopen Mixin

Handles CANopen (CiA 301) protocol operations:
- Node scanning (heartbeat listening + RTR probing)
- SDO read (expedited and segmented upload)
- SDO response reception
- Device info fingerprinting
- Object Dictionary scanning
- EMCY (Emergency) message monitoring
- Heartbeat monitoring and topology mapping
- NMT state reading
- PDO discovery
- Modbus-over-CANopen gateway detection (CiA 309)
- Modbus register mapping enumeration
"""

import time
from typing import Any, Dict, List, Optional, Tuple

from ....utils.export_utils import export_table
from ..constants import (
    CANOPEN_DEVICE_PROFILES,
    CANOPEN_EMCY_CODES,
    CANOPEN_ERR_REGISTER_BITS,
    CANOPEN_FINGERPRINT_INDICES,
    CANOPEN_HEARTBEAT_BASE,
    CANOPEN_KNOWN_GATEWAY_VENDORS,
    CANOPEN_NMT_STATES,
    CANOPEN_NODE_ID_MAX,
    CANOPEN_NODE_ID_MIN,
    CANOPEN_OD_ENTRIES,
    CANOPEN_OD_RPDO1_COMM,
    CANOPEN_OD_RPDO1_MAPPING,
    CANOPEN_OD_TPDO1_COMM,
    CANOPEN_OD_TPDO1_MAPPING,
    CANOPEN_PDO_COMM_COB_ID,
    CANOPEN_PDO_COMM_TRANSMISSION,
    CANOPEN_SDO_RX_BASE,
    CANOPEN_SDO_TX_BASE,
    CIA309_PROFILE_NUMBER,
    SDO_ABORT_CODES,
    SDO_CMD_SEGMENT_UPLOAD_0,
    SDO_CMD_SEGMENT_UPLOAD_1,
    SDO_CMD_UPLOAD_INITIATE,
    SDO_EXPEDITED_BIT,
    SDO_N_BITS_MASK,
    SDO_SCS_ABORT,
    SDO_SCS_INITIATE_UPLOAD,
    SDO_SCS_SEGMENT_UPLOAD,
    SDO_SIZE_INDICATED_BIT,
    CANopenNode,
    CANopenSDOResponse,
)


def _get_python_can():
    """Resolve _python_can from scanner module (avoids circular import)."""
    from ..scanner import _python_can

    return _python_can


class CANopenMixin:
    """Mixin providing CANopen (CiA 301) protocol operations."""

    @staticmethod
    def _safe_recv(bus: Any, timeout: float) -> Any:
        """bus.recv() that tolerates transient transport decode errors.

        The udp_multicast test transport can coalesce datagrams under load,
        making python-can raise on the corrupt packet. Treat that like an
        empty read so one bad frame never aborts a CANopen scan/monitor.
        """
        try:
            return bus.recv(timeout=timeout)
        except Exception:
            return None

    @staticmethod
    def _node_from_heartbeat(node_id: int, data: bytes) -> CANopenNode:
        """Create a CANopenNode from raw heartbeat data bytes."""
        nmt_state = data[0] & 0x7F if len(data) >= 1 else 0
        return CANopenNode(
            node_id=node_id,
            nmt_state=nmt_state,
            nmt_state_name=CANOPEN_NMT_STATES.get(nmt_state, f"Unknown(0x{nmt_state:02X})"),
        )

    def _recv_heartbeats(self, bus: Any, duration: float, discovered: Dict[int, CANopenNode]):
        """Listen for heartbeat messages for *duration* seconds, populating *discovered*."""
        end_time = time.time() + duration
        while time.time() < end_time:
            remaining = end_time - time.time()
            if remaining <= 0:
                break
            msg = self._safe_recv(bus, min(remaining, 0.5))
            if msg is None:
                continue
            arb_id = msg.arbitration_id
            if CANOPEN_HEARTBEAT_BASE < arb_id <= CANOPEN_HEARTBEAT_BASE + CANOPEN_NODE_ID_MAX:
                node_id = arb_id - CANOPEN_HEARTBEAT_BASE
                if node_id not in discovered:
                    node = self._node_from_heartbeat(node_id, bytes(msg.data))
                    discovered[node_id] = node
                    self.logger.success(
                        f"  Node {node_id}: heartbeat detected (state: {node.nmt_state_name})"
                    )

    def canopen_node_scan(self, bus: Any, timeout_per_node: float = 0.05) -> List[CANopenNode]:
        """
        Discover active CANopen nodes by sending NMT node guarding RTR
        requests and listening for heartbeat responses on COB-IDs 0x701-0x77F.

        This is a passive-safe scan: it listens for heartbeat messages that
        nodes send autonomously, then probes non-responding IDs with RTR.

        Args:
            bus: python-can Bus instance
            timeout_per_node: Timeout per node probe in seconds

        Returns:
            List of discovered CANopenNode objects
        """
        can = _get_python_can()()
        discovered: Dict[int, CANopenNode] = {}

        self.logger.display(f"[CANopen] Scanning for nodes 1-{CANOPEN_NODE_ID_MAX}...")

        # Phase 1: Listen for heartbeats passively (2 seconds)
        self.logger.display("  Phase 1: Listening for heartbeat messages (2s)...")
        self._recv_heartbeats(bus, 2.0, discovered)

        # Phase 2: Send RTR (Remote Transmit Request) to nodes not yet found
        self.logger.display("  Phase 2: Probing remaining nodes with node guarding RTR...")
        for node_id in range(CANOPEN_NODE_ID_MIN, CANOPEN_NODE_ID_MAX + 1):
            if node_id in discovered:
                continue

            heartbeat_cob_id = CANOPEN_HEARTBEAT_BASE + node_id

            try:
                msg = can.Message(
                    arbitration_id=heartbeat_cob_id,
                    data=[],
                    is_extended_id=False,
                    is_remote_frame=True,
                )
                bus.send(msg)
            except Exception as e:
                self.logger.debug(f"CANopen: heartbeat RTR frame send failed: {e}")
                continue

            # Listen for response
            end_time = time.time() + timeout_per_node
            while time.time() < end_time:
                resp = self._safe_recv(bus, timeout_per_node)
                if resp is None:
                    break
                if resp.arbitration_id == heartbeat_cob_id and not resp.is_remote_frame:
                    node = self._node_from_heartbeat(node_id, bytes(resp.data))
                    discovered[node_id] = node
                    self.logger.success(
                        f"  Node {node_id}: RTR response (state: {node.nmt_state_name})"
                    )
                    break

        nodes = sorted(discovered.values(), key=lambda n: n.node_id)
        self.logger.display(f"  Found {len(nodes)} CANopen nodes")

        # Print summary table
        if nodes:
            rows = []
            for n in nodes:
                rows.append(
                    [
                        str(n.node_id),
                        f"0x{n.node_id:02X}",
                        n.nmt_state_name,
                        f"0x{n.sdo_rx_cob_id:03X}/{n.sdo_tx_cob_id:03X}",
                    ]
                )
            export_table(
                "canopen_nodes",
                ["Node", "Hex", "NMT State", "SDO RX/TX"],
                rows,
                title="CANopen Nodes",
            )

        return nodes

    def canopen_sdo_read(
        self,
        bus: Any,
        node_id: int,
        index: int,
        subindex: int = 0x00,
        timeout: float = 0.5,
    ) -> CANopenSDOResponse:
        """
        Read an Object Dictionary entry via SDO expedited/segmented upload.

        Sends an SDO upload initiate request and handles both expedited
        responses (data <= 4 bytes) and segmented transfers (data > 4 bytes).

        Args:
            bus: python-can Bus instance
            node_id: Target CANopen node ID (1-127)
            index: Object Dictionary index (e.g., 0x1000)
            subindex: Object Dictionary sub-index (default 0x00)
            timeout: Response timeout in seconds

        Returns:
            CANopenSDOResponse with read data or error info
        """
        can = _get_python_can()()
        result = CANopenSDOResponse(node_id=node_id, index=index, subindex=subindex)

        sdo_rx_id = CANOPEN_SDO_RX_BASE + node_id  # Client -> Server
        sdo_tx_id = CANOPEN_SDO_TX_BASE + node_id  # Server -> Client

        # Build SDO upload initiate request
        # byte[0] = CCS=2 (initiate upload) -> 0x40
        # byte[1..2] = index (little-endian)
        # byte[3] = sub-index
        # byte[4..7] = reserved (0x00)
        index_lo = index & 0xFF
        index_hi = (index >> 8) & 0xFF
        request = bytes(
            [
                SDO_CMD_UPLOAD_INITIATE,
                index_lo,
                index_hi,
                subindex,
                0x00,
                0x00,
                0x00,
                0x00,
            ]
        )

        try:
            msg = can.Message(
                arbitration_id=sdo_rx_id,
                data=request,
                is_extended_id=False,
            )
            bus.send(msg)
        except Exception as e:
            result.error = True
            result.abort_message = f"Failed to send SDO request: {e}"
            return result

        # Wait for SDO response on sdo_tx_id
        resp_data = self._recv_sdo_response(bus, sdo_tx_id, timeout)
        if resp_data is None:
            result.error = True
            result.abort_message = "SDO response timeout"
            return result

        # Parse response command byte
        cmd = resp_data[0]
        scs = (cmd >> 5) & 0x07

        # Check for abort (SCS=4, cmd byte = 0x80)
        if scs == SDO_SCS_ABORT:
            result.error = True
            if len(resp_data) >= 8:
                result.abort_code = (
                    resp_data[4] | (resp_data[5] << 8) | (resp_data[6] << 16) | (resp_data[7] << 24)
                )
                result.abort_message = SDO_ABORT_CODES.get(
                    result.abort_code, f"Unknown abort 0x{result.abort_code:08X}"
                )
            return result

        # Check for initiate upload response (SCS=2, cmd bits 7..5 = 010)
        if scs == SDO_SCS_INITIATE_UPLOAD:
            expedited = bool(cmd & SDO_EXPEDITED_BIT)
            size_indicated = bool(cmd & SDO_SIZE_INDICATED_BIT)

            if expedited:
                # Expedited transfer: data is in bytes 4..7
                if size_indicated:
                    # n = bits 3..2, unused bytes count
                    n = (cmd & SDO_N_BITS_MASK) >> 2
                    data_len = 4 - n
                else:
                    data_len = 4  # Full 4 bytes, no size info
                result.data = bytes(resp_data[4 : 4 + data_len])
            else:
                # Segmented transfer
                if size_indicated and len(resp_data) >= 8:
                    total_size = (
                        resp_data[4]
                        | (resp_data[5] << 8)
                        | (resp_data[6] << 16)
                        | (resp_data[7] << 24)
                    )
                else:
                    total_size = 0  # Unknown size

                # Read segments
                assembled = bytearray()
                toggle = 0
                is_last = False
                max_segments = 256  # Safety limit

                for _ in range(max_segments):
                    # Send segment upload request
                    seg_cmd = SDO_CMD_SEGMENT_UPLOAD_0 if toggle == 0 else SDO_CMD_SEGMENT_UPLOAD_1
                    seg_request = bytes([seg_cmd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

                    try:
                        seg_msg = can.Message(
                            arbitration_id=sdo_rx_id,
                            data=seg_request,
                            is_extended_id=False,
                        )
                        bus.send(seg_msg)
                    except Exception:
                        break

                    # Wait for a *valid* segment-upload response carrying the
                    # toggle bit we just sent. On a shared/lossy bus (e.g. the
                    # udp_multicast test transport) stray frames appear: a
                    # duplicated initiate-upload response (SCS=2), a heartbeat,
                    # or a duplicated segment echoing the wrong toggle. Parsing
                    # any of those as segment data silently corrupts the result,
                    # so drain until we see the expected segment (SCS=0, matching
                    # toggle), an abort, or the deadline.
                    seg_resp = None
                    seg_deadline = time.time() + timeout
                    while time.time() < seg_deadline:
                        remaining = seg_deadline - time.time()
                        candidate = self._recv_sdo_response(bus, sdo_tx_id, remaining)
                        if candidate is None:
                            break
                        cand_scs = (candidate[0] >> 5) & 0x07
                        if cand_scs == SDO_SCS_ABORT:
                            seg_resp = candidate
                            break
                        if cand_scs != SDO_SCS_SEGMENT_UPLOAD:
                            continue  # stray initiate/other frame — ignore
                        if ((candidate[0] >> 4) & 0x01) != toggle:
                            continue  # duplicate/reordered segment — ignore
                        seg_resp = candidate
                        break

                    if seg_resp is None:
                        break

                    seg_scs = (seg_resp[0] >> 5) & 0x07
                    if seg_scs == SDO_SCS_ABORT:
                        result.error = True
                        if len(seg_resp) >= 8:
                            result.abort_code = (
                                seg_resp[4]
                                | (seg_resp[5] << 8)
                                | (seg_resp[6] << 16)
                                | (seg_resp[7] << 24)
                            )
                            result.abort_message = SDO_ABORT_CODES.get(
                                result.abort_code,
                                f"Unknown abort 0x{result.abort_code:08X}",
                            )
                        return result

                    # Segment upload response: SCS=0
                    # Bits: n (3..1) = unused bytes, c (bit 0) = last segment
                    n_seg = (seg_resp[0] >> 1) & 0x07
                    is_last = bool(seg_resp[0] & 0x01)
                    seg_data_len = 7 - n_seg
                    assembled.extend(seg_resp[1 : 1 + seg_data_len])

                    if is_last:
                        break

                    toggle = 1 - toggle

                # A segmented transfer that never delivered its final segment, or
                # came up short of the indicated size, is incomplete — report it
                # as an error rather than handing back a truncated/garbled value.
                if not is_last or (total_size > 0 and len(assembled) < total_size):
                    result.error = True
                    result.abort_message = "Incomplete segmented SDO transfer"
                    return result

                if total_size > 0:
                    result.data = bytes(assembled[:total_size])
                else:
                    result.data = bytes(assembled)

        return result

    def _recv_sdo_response(self, bus: Any, sdo_tx_id: int, timeout: float = 0.5) -> Optional[bytes]:
        """
        Receive an SDO response from a specific COB-ID.

        Args:
            bus: python-can Bus instance
            sdo_tx_id: Expected SDO response COB-ID
            timeout: Max wait time

        Returns:
            8 bytes of response data or None
        """
        end_time = time.time() + timeout
        while time.time() < end_time:
            remaining = end_time - time.time()
            if remaining <= 0:
                break
            msg = self._safe_recv(bus, min(remaining, 0.05))
            if msg is None:
                continue
            if msg.arbitration_id == sdo_tx_id and not msg.is_remote_frame:
                return bytes(msg.data)
        return None

    def canopen_device_info(self, bus: Any, node_id: int) -> CANopenNode:
        """
        Read standard identity objects to fingerprint a CANopen device.

        Reads OD entries 0x1000 (device type), 0x1008 (device name),
        0x1009 (HW version), 0x100A (SW version), and 0x1018 (identity
        with vendor/product/revision/serial).

        Args:
            bus: python-can Bus instance
            node_id: Target node ID (1-127)

        Returns:
            CANopenNode with populated device information
        """
        node = CANopenNode(node_id=node_id)

        self.logger.display(f"[CANopen] Reading device info for node {node_id}...")

        for index, subindex, name in CANOPEN_FINGERPRINT_INDICES:
            resp = self.canopen_sdo_read(bus, node_id, index, subindex, timeout=0.5)
            if resp.error:
                self.logger.debug(f"  {name} (0x{index:04X}:{subindex:02X}): {resp.abort_message}")
                continue

            node.od_entries_found.append(index)

            # Parse based on index
            if index == 0x1000 and subindex == 0x00:
                val = resp.as_uint32
                if val is not None:
                    node.device_type = val
                    profile = val & 0xFFFF
                    node.device_profile = profile
                    node.device_profile_name = CANOPEN_DEVICE_PROFILES.get(
                        profile, f"Profile {profile}"
                    )
                    self.logger.display(
                        f"  Device Type: 0x{val:08X} (profile: {node.device_profile_name})"
                    )

            elif index == 0x1001 and subindex == 0x00:
                val = resp.as_uint8
                if val is not None:
                    node.error_register = val
                    bits = []
                    for bit_val, bit_name in CANOPEN_ERR_REGISTER_BITS.items():
                        if val & bit_val:
                            bits.append(bit_name)
                    bits_str = ", ".join(bits) if bits else "No errors"
                    self.logger.display(f"  Error Register: 0x{val:02X} ({bits_str})")

            elif index == 0x1008:
                val = resp.as_string
                if val:
                    node.device_name = val
                    self.logger.display(f"  Device Name: {val}")

            elif index == 0x1009:
                val = resp.as_string
                if val:
                    node.hw_version = val
                    self.logger.display(f"  HW Version: {val}")

            elif index == 0x100A:
                val = resp.as_string
                if val:
                    node.sw_version = val
                    self.logger.display(f"  SW Version: {val}")

            elif index == 0x1018 and subindex == 0x01:
                val = resp.as_uint32
                if val is not None:
                    node.vendor_id = val
                    node.vendor_name = CANOPEN_KNOWN_GATEWAY_VENDORS.get(val, f"Vendor 0x{val:08X}")
                    self.logger.display(f"  Vendor ID: 0x{val:08X} ({node.vendor_name})")

            elif index == 0x1018 and subindex == 0x02:
                val = resp.as_uint32
                if val is not None:
                    node.product_code = val
                    self.logger.display(f"  Product Code: 0x{val:08X}")

            elif index == 0x1018 and subindex == 0x03:
                val = resp.as_uint32
                if val is not None:
                    node.revision = val
                    major = (val >> 16) & 0xFFFF
                    minor = val & 0xFFFF
                    self.logger.display(f"  Revision: 0x{val:08X} (v{major}.{minor})")

            elif index == 0x1018 and subindex == 0x04:
                val = resp.as_uint32
                if val is not None:
                    node.serial_number = val
                    self.logger.display(f"  Serial Number: 0x{val:08X} ({val})")

        return node

    def canopen_od_scan(
        self,
        bus: Any,
        node_id: int,
        index_range: Optional[Tuple[int, int]] = None,
    ) -> List[Tuple[int, int, bytes]]:
        """
        Scan a range of Object Dictionary indices to discover what entries exist.

        Attempts to read each index:0x00 and checks whether the response
        is valid data (entry exists) or an SDO abort (entry missing/inaccessible).

        Args:
            bus: python-can Bus instance
            node_id: Target node ID (1-127)
            index_range: (start, end) index range.
                         Default: (0x1000, 0x1FFF) communication profile area.

        Returns:
            List of (index, subindex, data) tuples for existing entries
        """
        if index_range is None:
            start_idx, end_idx = 0x1000, 0x1029
        else:
            start_idx, end_idx = index_range

        total = end_idx - start_idx + 1
        self.logger.display(
            f"[CANopen OD] Scanning {total} indices "
            f"(0x{start_idx:04X}-0x{end_idx:04X}) on node {node_id}..."
        )

        found: List[Tuple[int, int, bytes]] = []

        for idx in range(start_idx, end_idx + 1):
            resp = self.canopen_sdo_read(bus, node_id, idx, 0x00, timeout=0.2)
            if not resp.error:
                entry_name = CANOPEN_OD_ENTRIES.get(idx, f"0x{idx:04X}")
                data_hex = " ".join(f"{b:02X}" for b in resp.data)
                self.logger.display(f"  0x{idx:04X}: {entry_name} = [{data_hex}]")
                found.append((idx, 0x00, resp.data))
            elif resp.abort_code == 0x06090011:
                # Sub-index does not exist but index might exist with other sub-indices
                self.logger.debug(f"  0x{idx:04X}: sub-index 0 not found, trying sub-index count")
            else:
                # Object does not exist (0x06020000) or other error - skip
                pass

        self.logger.display(f"  {len(found)} OD entries found")
        return found

    def canopen_emcy_monitor(self, bus: Any, duration: float = 10.0) -> List[Dict[str, Any]]:
        """
        Listen for CANopen EMCY (Emergency) messages and decode error codes.

        EMCY messages have COB-IDs 0x081-0x0FF (0x080 + node_id).
        Format: [error_code_lo, error_code_hi, error_register, mfr_data x5]

        Args:
            bus: python-can Bus instance
            duration: How long to listen in seconds

        Returns:
            List of decoded emergency message dicts
        """
        self.logger.display(f"[CANopen EMCY] Monitoring emergency messages for {duration}s...")

        messages: List[Dict[str, Any]] = []
        start_time = time.time()
        end_time = start_time + duration

        while time.time() < end_time:
            remaining = end_time - time.time()
            if remaining <= 0:
                break
            msg = self._safe_recv(bus, min(remaining, 0.5))
            if msg is None:
                continue

            arb_id = msg.arbitration_id
            # EMCY: 0x081 to 0x0FF
            if 0x081 <= arb_id <= 0x0FF:
                node_id = arb_id - 0x080
                data = bytes(msg.data)
                if len(data) >= 3:
                    error_code = data[0] | (data[1] << 8)
                    error_register = data[2]
                    mfr_data = data[3:8] if len(data) > 3 else b""

                    error_name = CANOPEN_EMCY_CODES.get(
                        error_code,
                        CANOPEN_EMCY_CODES.get(error_code & 0xFF00, f"Unknown(0x{error_code:04X})"),
                    )

                    entry = {
                        "node_id": node_id,
                        "error_code": error_code,
                        "error_name": error_name,
                        "error_register": error_register,
                        "manufacturer_data": mfr_data.hex(),
                        "timestamp": time.time() - start_time,
                    }
                    messages.append(entry)

                    self.logger.display(
                        f"  EMCY node {node_id}: 0x{error_code:04X} "
                        f"({error_name}) reg=0x{error_register:02X}"
                    )

        self.logger.display(f"  {len(messages)} emergency messages captured")
        return messages

    def canopen_heartbeat_monitor(
        self, bus: Any, duration: float = 5.0
    ) -> Dict[int, Dict[str, Any]]:
        """
        Monitor heartbeat messages to map network topology.

        Listens for heartbeat messages on COB-IDs 0x701-0x77F and
        tracks which nodes are alive, their NMT states, and heartbeat rates.

        Args:
            bus: python-can Bus instance
            duration: How long to monitor in seconds

        Returns:
            Dict mapping node_id -> {state, count, first_seen, last_seen, interval}
        """
        self.logger.display(f"[CANopen Heartbeat] Monitoring for {duration}s...")

        nodes: Dict[int, Dict[str, Any]] = {}
        start_time = time.time()
        end_time = start_time + duration

        while time.time() < end_time:
            remaining = end_time - time.time()
            if remaining <= 0:
                break
            msg = self._safe_recv(bus, min(remaining, 0.5))
            if msg is None:
                continue

            arb_id = msg.arbitration_id
            if CANOPEN_HEARTBEAT_BASE < arb_id <= CANOPEN_HEARTBEAT_BASE + CANOPEN_NODE_ID_MAX:
                node_id = arb_id - CANOPEN_HEARTBEAT_BASE
                data = bytes(msg.data)
                nmt_state = data[0] & 0x7F if len(data) >= 1 else 0
                ts = time.time() - start_time

                if node_id not in nodes:
                    nodes[node_id] = {
                        "state": nmt_state,
                        "state_name": CANOPEN_NMT_STATES.get(nmt_state, f"0x{nmt_state:02X}"),
                        "count": 0,
                        "first_seen": ts,
                        "last_seen": ts,
                        "timestamps": [],
                    }

                entry = nodes[node_id]
                entry["count"] += 1
                entry["last_seen"] = ts
                entry["state"] = nmt_state
                entry["state_name"] = CANOPEN_NMT_STATES.get(nmt_state, f"0x{nmt_state:02X}")
                entry["timestamps"].append(ts)

        # Calculate heartbeat intervals
        for node_id, entry in nodes.items():
            timestamps = entry.pop("timestamps")
            if len(timestamps) >= 2:
                intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
                entry["avg_interval_ms"] = round(sum(intervals) / len(intervals) * 1000, 1)
            else:
                entry["avg_interval_ms"] = 0

        if nodes:
            rows = []
            for nid in sorted(nodes.keys()):
                e = nodes[nid]
                rows.append(
                    [
                        str(nid),
                        e["state_name"],
                        str(e["count"]),
                        f"{e['avg_interval_ms']}ms",
                    ]
                )
            export_table(
                "canopen_heartbeat",
                ["Node", "State", "HB Count", "Avg Interval"],
                rows,
                title="CANopen Heartbeat Map",
            )
        else:
            self.logger.display("  No heartbeat messages detected")

        return nodes

    def canopen_nmt_state_read(self, bus: Any, node_id: int, timeout: float = 1.0) -> Optional[int]:
        """
        Read the current NMT state of a node via node guarding RTR.

        Args:
            bus: python-can Bus instance
            node_id: Target node ID
            timeout: Response timeout

        Returns:
            NMT state code or None if no response
        """
        can = _get_python_can()()
        heartbeat_cob_id = CANOPEN_HEARTBEAT_BASE + node_id

        try:
            msg = can.Message(
                arbitration_id=heartbeat_cob_id,
                data=[],
                is_extended_id=False,
                is_remote_frame=True,
            )
            bus.send(msg)
        except Exception as e:
            self.logger.debug(f"CANopen: single-node heartbeat RTR frame send failed: {e}")
            return None

        end_time = time.time() + timeout
        while time.time() < end_time:
            resp = self._safe_recv(bus, min(end_time - time.time(), 0.1))
            if resp is None:
                continue
            if resp.arbitration_id == heartbeat_cob_id and not resp.is_remote_frame:
                data = bytes(resp.data)
                if len(data) >= 1:
                    return data[0] & 0x7F
        return None

    def canopen_pdo_discover(self, bus: Any, node_id: int) -> Dict[str, Any]:
        """
        Read PDO mapping parameters to understand data flow.

        Reads TPDO and RPDO communication and mapping parameters from
        the Object Dictionary.

        Args:
            bus: python-can Bus instance
            node_id: Target node ID

        Returns:
            Dict with PDO configuration info
        """
        self.logger.display(f"[CANopen PDO] Discovering PDO mappings for node {node_id}...")

        pdo_info: Dict[str, Any] = {"tpdo": {}, "rpdo": {}}

        # Read TPDO1-4 and RPDO1-4 communication and mapping parameters
        pdo_configs = [
            ("TPDO1", CANOPEN_OD_TPDO1_COMM, CANOPEN_OD_TPDO1_MAPPING),
            ("TPDO2", CANOPEN_OD_TPDO1_COMM + 1, CANOPEN_OD_TPDO1_MAPPING + 1),
            ("TPDO3", CANOPEN_OD_TPDO1_COMM + 2, CANOPEN_OD_TPDO1_MAPPING + 2),
            ("TPDO4", CANOPEN_OD_TPDO1_COMM + 3, CANOPEN_OD_TPDO1_MAPPING + 3),
            ("RPDO1", CANOPEN_OD_RPDO1_COMM, CANOPEN_OD_RPDO1_MAPPING),
            ("RPDO2", CANOPEN_OD_RPDO1_COMM + 1, CANOPEN_OD_RPDO1_MAPPING + 1),
            ("RPDO3", CANOPEN_OD_RPDO1_COMM + 2, CANOPEN_OD_RPDO1_MAPPING + 2),
            ("RPDO4", CANOPEN_OD_RPDO1_COMM + 3, CANOPEN_OD_RPDO1_MAPPING + 3),
        ]

        for pdo_name, comm_idx, map_idx in pdo_configs:
            pdo_entry: Dict[str, Any] = {"enabled": False}

            # Read COB-ID (sub-index 1 of communication parameter)
            resp = self.canopen_sdo_read(bus, node_id, comm_idx, CANOPEN_PDO_COMM_COB_ID)
            if not resp.error and resp.as_uint32 is not None:
                cob_id = resp.as_uint32
                # Bit 31: PDO valid (0=valid, 1=not valid)
                enabled = not bool(cob_id & 0x80000000)
                pdo_entry["enabled"] = enabled
                pdo_entry["cob_id"] = cob_id & 0x1FFFFFFF
                pdo_entry["cob_id_hex"] = f"0x{cob_id & 0x1FFFFFFF:03X}"
            else:
                continue  # PDO not configured

            # Read transmission type (sub-index 2)
            resp = self.canopen_sdo_read(bus, node_id, comm_idx, CANOPEN_PDO_COMM_TRANSMISSION)
            if not resp.error and resp.as_uint8 is not None:
                pdo_entry["transmission_type"] = resp.as_uint8

            # Read number of mapped objects (sub-index 0 of mapping parameter)
            resp = self.canopen_sdo_read(bus, node_id, map_idx, 0x00)
            if not resp.error and resp.as_uint8 is not None:
                num_mappings = resp.as_uint8
                pdo_entry["num_mappings"] = num_mappings

                # Read each mapping entry
                mappings = []
                for sub in range(1, min(num_mappings + 1, 9)):
                    resp = self.canopen_sdo_read(bus, node_id, map_idx, sub)
                    if not resp.error and resp.as_uint32 is not None:
                        mapping_val = resp.as_uint32
                        # Mapping: [index:16][subindex:8][length_bits:8]
                        m_index = (mapping_val >> 16) & 0xFFFF
                        m_sub = (mapping_val >> 8) & 0xFF
                        m_bits = mapping_val & 0xFF
                        mappings.append(
                            {
                                "index": f"0x{m_index:04X}",
                                "subindex": m_sub,
                                "length_bits": m_bits,
                            }
                        )
                pdo_entry["mappings"] = mappings

            pdo_key = "tpdo" if pdo_name.startswith("T") else "rpdo"
            pdo_info[pdo_key][pdo_name] = pdo_entry

            if pdo_entry.get("enabled"):
                self.logger.display(
                    f"  {pdo_name}: COB-ID={pdo_entry.get('cob_id_hex', 'N/A')} "
                    f"mappings={pdo_entry.get('num_mappings', '?')}"
                )

        return pdo_info

    # -------------------------------------------------------------------
    # Modbus-over-CANopen Gateway Detection (CiA 309)
    # -------------------------------------------------------------------

    def canopen_modbus_gateway_detect(
        self,
        bus: Any,
        nodes: Optional[List[CANopenNode]] = None,
    ) -> List[CANopenNode]:
        """
        Identify Modbus gateway devices by reading device type (0x1000)
        and checking for CiA 309 profile or known gateway vendor IDs.

        A device is flagged as a gateway if:
        1. Its device profile (lower 16 bits of 0x1000) == 309 (CiA 309), OR
        2. Its vendor ID matches a known gateway manufacturer

        Args:
            bus: python-can Bus instance
            nodes: Optional pre-scanned node list. If None, scans first.

        Returns:
            List of CANopenNode objects identified as gateways
        """
        if nodes is None:
            nodes = self.canopen_node_scan(bus)

        self.logger.display(f"[CANopen Gateway] Checking {len(nodes)} nodes for Modbus gateways...")

        gateways: List[CANopenNode] = []

        for node in nodes:
            # Read device info if not already populated
            if node.device_type == 0:
                info = self.canopen_device_info(bus, node.node_id)
                node.device_type = info.device_type
                node.device_profile = info.device_profile
                node.device_profile_name = info.device_profile_name
                node.vendor_id = info.vendor_id
                node.vendor_name = info.vendor_name
                node.device_name = info.device_name
                node.product_code = info.product_code

            # Check for CiA 309 profile
            if node.device_profile == CIA309_PROFILE_NUMBER:
                node.is_gateway = True
                node.gateway_type = "CiA 309 Modbus Gateway"
                gateways.append(node)
                self.logger.success(
                    f"  Node {node.node_id}: CiA 309 Modbus gateway "
                    f"({node.device_name or 'unnamed'})"
                )
                continue

            # Check for known gateway vendor IDs
            if node.vendor_id in CANOPEN_KNOWN_GATEWAY_VENDORS:
                # Could be a gateway - check device name for keywords
                name_lower = (node.device_name or "").lower()
                gateway_keywords = [
                    "gateway",
                    "gw",
                    "modbus",
                    "converter",
                    "bridge",
                    "interface",
                    "anybus",
                    "mgate",
                ]
                if any(kw in name_lower for kw in gateway_keywords):
                    node.is_gateway = True
                    node.gateway_type = f"Suspected Modbus gateway ({node.vendor_name})"
                    gateways.append(node)
                    self.logger.success(
                        f"  Node {node.node_id}: suspected gateway "
                        f"({node.device_name}, vendor: {node.vendor_name})"
                    )

        if not gateways:
            self.logger.display("  No Modbus gateways detected")

        return gateways

    def _sdo_scan_range(
        self,
        bus: Any,
        node_id: int,
        start_idx: int,
        end_idx: int,
        mappings: Dict[int, bytes],
        timeout: float = 0.2,
    ) -> None:
        """Read OD entries in [start_idx, end_idx], appending hits to *mappings*."""
        for idx in range(start_idx, end_idx + 1):
            resp = self.canopen_sdo_read(bus, node_id, idx, 0x00, timeout=timeout)
            if not resp.error and resp.data:
                mappings[idx] = resp.data
                data_hex = " ".join(f"{b:02X}" for b in resp.data)
                self.logger.display(f"  0x{idx:04X}: [{data_hex}]")

    def canopen_modbus_register_map(
        self,
        bus: Any,
        node_id: int,
        scan_range: Optional[Tuple[int, int]] = None,
    ) -> Dict[int, bytes]:
        """
        If a gateway is detected, enumerate exposed Modbus registers
        via SDO reads of the CiA 309 mapping objects.

        For CiA 309 gateways, the OD range 0x5100-0x51FF typically
        contains Modbus register mapping configuration. We also scan
        the device profile area (0x6000-0x6FFF) for I/O data that
        may be Modbus-accessible.

        Args:
            bus: python-can Bus instance
            node_id: Gateway node ID
            scan_range: Optional (start, end) OD range to scan.
                        Default: (0x5100, 0x51FF) for CiA 309 mapping area.

        Returns:
            Dict mapping OD index -> data for discovered register mappings
        """
        if scan_range is None:
            start_idx, end_idx = 0x5100, 0x51FF
        else:
            start_idx, end_idx = scan_range

        self.logger.display(
            f"[CANopen Modbus Map] Scanning register mappings on node {node_id} "
            f"(0x{start_idx:04X}-0x{end_idx:04X})..."
        )

        mappings: Dict[int, bytes] = {}
        self._sdo_scan_range(bus, node_id, start_idx, end_idx, mappings)

        # Also scan device profile area for I/O data
        self.logger.display("  Scanning device profile area (0x6000-0x60FF)...")
        self._sdo_scan_range(bus, node_id, 0x6000, 0x60FF, mappings)

        self.logger.display(f"  {len(mappings)} register mapping entries found")
        return mappings
