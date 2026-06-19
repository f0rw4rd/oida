"""
CAN XCP/CCP Mixin

Handles XCP (ASAM MCD-1 XCP) and CCP (CCP v2.1) protocol operations:
- XCP slave discovery via CONNECT command
- XCP info gathering (GET_STATUS, GET_COMM_MODE_INFO, GET_ID)
- XCP memory read via SHORT_UPLOAD
- XCP response reception and disconnect
- CCP slave discovery via CONNECT with station addresses
- CCP info gathering (version, exchange ID, session status)
- CCP response reception and disconnect
"""

import struct
import time
from typing import Any, List, Optional, Tuple

from ..constants import (
    CAN_STD_ID_MAX,
    # CCP constants
    CCP_CONNECT_CMD,
    CCP_CRC,
    CCP_DEFAULT_CRO_ID,
    CCP_DEFAULT_DTO_ID,
    CCP_DISCONNECT_CMD,
    CCP_DISCONNECT_END_SESSION,
    CCP_DTO_COMMAND_RETURN,
    XCP_CONNECT_CMD,
    XCP_CONNECT_MODE_NORMAL,
    XCP_DISCONNECT_CMD,
    XCP_ERR,
    XCP_ERR_PID,
    XCP_GET_COMM_MODE_INFO_CMD,
    XCP_GET_ID_CMD,
    XCP_GET_STATUS_CMD,
    XCP_ID_TYPE_ASCII,
    # XCP constants
    XCP_RES_PID,
    XCP_SHORT_UPLOAD_CMD,
    CCPScanResult,
    XCPScanResult,
)


# De-facto XCP-on-CAN convention: the slave's response (DTO) arbitration ID is
# one greater than the request (CRO) arbitration ID. Used by scan_xcp to only
# accept a CONNECT response on the ID that the probed request ID would elicit,
# so delayed/foreign replies are not mis-attributed to the wrong request ID.
XCP_RESP_ID_OFFSET = 1


def _get_python_can():
    """Resolve _python_can from scanner module (avoids circular import)."""
    from ..scanner import _python_can

    return _python_can


class XCPMixin:
    """Mixin providing XCP and CCP protocol discovery and operations."""

    def scan_xcp(
        self, bus: Any, scan_range: Optional[Tuple[int, int]] = None
    ) -> List[XCPScanResult]:
        """
        Scan CAN arbitration IDs for ECUs that respond to XCP CONNECT.

        Sends XCP CONNECT (0xFF) command to each candidate arbitration ID and
        checks for positive responses (0xFF in byte 0 of response).

        Args:
            bus: python-can Bus instance
            scan_range: Optional (start, end) arb ID range to scan.
                        Defaults to common XCP range 0x000-0x7FF.

        Returns:
            List of XCPScanResult for each discovered XCP slave
        """
        can = _get_python_can()()
        results: List[XCPScanResult] = []

        if scan_range is None:
            start_id, end_id = 0x000, CAN_STD_ID_MAX
        else:
            start_id, end_id = scan_range

        total = end_id - start_id + 1
        self.logger.display(
            f"[XCP] Scanning {total} arb IDs for XCP slaves (0x{start_id:03X}-0x{end_id:03X})..."
        )

        for req_id in range(start_id, end_id + 1):
            # XCP CONNECT: [CMD=0xFF, mode=0x00 (normal)]
            # Padded to 8 bytes for CAN
            connect_data = bytes(
                [
                    XCP_CONNECT_CMD,
                    XCP_CONNECT_MODE_NORMAL,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                ]
            )
            try:
                msg = can.Message(
                    arbitration_id=req_id,
                    data=connect_data,
                    is_extended_id=False,
                )
                bus.send(msg)
            except Exception as e:
                self.logger.debug(f"XCP: CONNECT frame send failed: {e}")
                continue

            # Listen for the XCP response on the expected response (DTO) ID
            # only. The XCP response ID is implementation-specific, but the
            # de-facto convention on CAN is rx = tx + 1. Filtering by the
            # expected ID prevents a delayed reply from an EARLIER probe being
            # mis-attributed to the request ID currently under test (which on a
            # busy bus produces XCPScanResult rows pairing a request_id that
            # never elicited the response with the slave's real response_id).
            expected_resp_id = req_id + XCP_RESP_ID_OFFSET
            resp = self._recv_xcp_response(
                bus, timeout=0.05, expected_id=expected_resp_id
            )
            if resp is None:
                continue

            resp_id, resp_data = resp

            # Check for XCP positive response: byte[0] == 0xFF (RES PID)
            if len(resp_data) >= 2 and resp_data[0] == XCP_RES_PID:
                self.logger.success(
                    f"XCP slave found: request=0x{req_id:03X} response=0x{resp_id:03X}"
                )

                result = XCPScanResult(
                    request_id=req_id,
                    response_id=resp_id,
                    connected=True,
                )

                # Parse CONNECT response fields
                if len(resp_data) >= 8:
                    result.resource_protection = resp_data[1]
                    result.comm_mode_basic = resp_data[2]
                    result.max_cto = resp_data[3]
                    result.max_dto = resp_data[4] | (resp_data[5] << 8)
                    result.xcp_version = f"{resp_data[6]}.{resp_data[7]}"

                results.append(result)

                # Disconnect cleanly
                self._xcp_disconnect(bus, req_id)

            elif len(resp_data) >= 2 and resp_data[0] == XCP_ERR_PID:
                err_code = resp_data[1] if len(resp_data) >= 2 else 0
                err_name = XCP_ERR.get(err_code, f"0x{err_code:02X}")
                self.logger.debug(f"  XCP error on 0x{req_id:03X}: {err_name}")

        if not results:
            self.logger.display("  No XCP slaves found")

        return results

    def xcp_get_info(self, bus: Any, req_id: int, resp_id: int) -> XCPScanResult:
        """
        Gather identification info from an XCP slave.

        Sends GET_ID, GET_COMM_MODE_INFO, and GET_STATUS commands after
        establishing a connection.

        Args:
            bus: python-can Bus instance
            req_id: Slave request (CRO) arbitration ID
            resp_id: Slave response (DTO) arbitration ID

        Returns:
            XCPScanResult with collected information
        """
        result = XCPScanResult(request_id=req_id, response_id=resp_id)

        # Step 1: CONNECT
        connect_data = bytes(
            [
                XCP_CONNECT_CMD,
                XCP_CONNECT_MODE_NORMAL,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            ]
        )
        if not self.send_message(bus, req_id, connect_data):
            result.error = "Failed to send CONNECT"
            return result

        resp = self._recv_xcp_response(bus, timeout=0.2, expected_id=resp_id)
        if resp is None or resp[1][0] != XCP_RES_PID:
            result.error = "CONNECT failed or no response"
            return result

        resp_data = resp[1]
        result.connected = True
        if len(resp_data) >= 8:
            result.resource_protection = resp_data[1]
            result.comm_mode_basic = resp_data[2]
            result.max_cto = resp_data[3]
            result.max_dto = resp_data[4] | (resp_data[5] << 8)
            result.xcp_version = f"{resp_data[6]}.{resp_data[7]}"

        # Step 2: GET_STATUS (0xFD)
        status_data = bytes([XCP_GET_STATUS_CMD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        self.send_message(bus, req_id, status_data)
        resp = self._recv_xcp_response(bus, timeout=0.2, expected_id=resp_id)
        if resp and len(resp[1]) >= 6 and resp[1][0] == XCP_RES_PID:
            rd = resp[1]
            result.status = {
                "current_session_status": rd[1],
                "current_resource_protection": rd[2],
                "session_configuration_id": (rd[4] | (rd[5] << 8)),
            }
            self.logger.display(f"  GET_STATUS: session=0x{rd[1]:02X} protection=0x{rd[2]:02X}")

        # Step 3: GET_COMM_MODE_INFO (0xFB)
        comm_data = bytes([XCP_GET_COMM_MODE_INFO_CMD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        self.send_message(bus, req_id, comm_data)
        resp = self._recv_xcp_response(bus, timeout=0.2, expected_id=resp_id)
        if resp and len(resp[1]) >= 8 and resp[1][0] == XCP_RES_PID:
            rd = resp[1]
            result.transport_version = f"{rd[6]}.{rd[7]}"
            self.logger.display(f"  GET_COMM_MODE_INFO: transport v{result.transport_version}")

        # Step 4: GET_ID (0xFA) - request ASCII identification
        id_data = bytes([XCP_GET_ID_CMD, XCP_ID_TYPE_ASCII, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        self.send_message(bus, req_id, id_data)
        resp = self._recv_xcp_response(bus, timeout=0.2, expected_id=resp_id)
        if resp and len(resp[1]) >= 8 and resp[1][0] == XCP_RES_PID:
            rd = resp[1]
            id_length = rd[4] | (rd[5] << 8) | (rd[6] << 16) | (rd[7] << 24)
            if id_length > 0 and id_length <= 255:
                # ID data may follow in next upload or be embedded
                # For short IDs embedded in the response
                self.logger.display(f"  GET_ID: length={id_length}")

        # Disconnect
        self._xcp_disconnect(bus, req_id)

        return result

    def xcp_memory_read(
        self,
        bus: Any,
        req_id: int,
        resp_id: int,
        address: int,
        length: int,
    ) -> Optional[bytes]:
        """
        Read memory from an XCP slave using SHORT_UPLOAD.

        This is an active operation that requires --confirm.

        Args:
            bus: python-can Bus instance
            req_id: Slave request CAN ID
            resp_id: Slave response CAN ID
            address: Memory address to read from
            length: Number of bytes to read (max 6 per SHORT_UPLOAD on CAN)

        Returns:
            Read bytes or None on failure
        """
        # CONNECT first
        connect_data = bytes(
            [
                XCP_CONNECT_CMD,
                XCP_CONNECT_MODE_NORMAL,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            ]
        )
        self.send_message(bus, req_id, connect_data)
        resp = self._recv_xcp_response(bus, timeout=0.2, expected_id=resp_id)
        if resp is None or resp[1][0] != XCP_RES_PID:
            self.logger.fail("XCP CONNECT failed for memory read")
            return None

        # SHORT_UPLOAD: [CMD=0xF4, num_elements, reserved, addr_ext, addr(4 bytes)]
        # Clamp to max 6 bytes per read on CAN (8-byte CTO, minus 2 header bytes)
        read_len = min(length, 6)
        addr_bytes = struct.pack("<I", address)
        upload_data = bytes([XCP_SHORT_UPLOAD_CMD, read_len, 0x00, 0x00]) + addr_bytes
        self.send_message(bus, req_id, upload_data)

        resp = self._recv_xcp_response(bus, timeout=0.5, expected_id=resp_id)
        result = None
        if resp and len(resp[1]) >= 2 and resp[1][0] == XCP_RES_PID:
            # Data starts at byte 1 in the response
            result = bytes(resp[1][1 : 1 + read_len])
            self.logger.display(
                f"  XCP read 0x{address:08X} ({read_len} bytes): "
                f"{' '.join(f'{b:02X}' for b in result)}"
            )
        elif resp and resp[1][0] == XCP_ERR_PID:
            err_code = resp[1][1] if len(resp[1]) >= 2 else 0
            self.logger.fail(
                f"XCP SHORT_UPLOAD error: {XCP_ERR.get(err_code, f'0x{err_code:02X}')}"
            )

        # Disconnect
        self._xcp_disconnect(bus, req_id)

        return result

    def _recv_xcp_response(
        self,
        bus: Any,
        timeout: float = 0.1,
        expected_id: Optional[int] = None,
    ) -> Optional[Tuple[int, bytes]]:
        """
        Receive an XCP response from the bus.

        Args:
            bus: python-can Bus instance
            timeout: Max wait time
            expected_id: If set, only accept responses on this arb ID

        Returns:
            Tuple of (arb_id, data) or None
        """
        end_time = time.time() + timeout
        while time.time() < end_time:
            remaining = end_time - time.time()
            msg = bus.recv(timeout=min(remaining, 0.02))
            if msg is None:
                continue
            data = bytes(msg.data)
            if len(data) < 1:
                continue
            # Check for XCP response PIDs (RES=0xFF, ERR=0xFE, EV=0xFD)
            if data[0] in (XCP_RES_PID, XCP_ERR_PID):
                if expected_id is not None and msg.arbitration_id != expected_id:
                    continue
                return (msg.arbitration_id, data)
        return None

    def _xcp_disconnect(self, bus: Any, req_id: int) -> None:
        """Send XCP DISCONNECT command."""
        disconnect_data = bytes([XCP_DISCONNECT_CMD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        self.send_message(bus, req_id, disconnect_data)
        # Drain any response
        self._recv_xcp_response(bus, timeout=0.05)

    # -------------------------------------------------------------------
    # CCP Protocol Discovery (ASAM MCD-1 CCP v2.1)
    # -------------------------------------------------------------------

    def scan_ccp(
        self,
        bus: Any,
        station_range: Optional[Tuple[int, int]] = None,
        cro_id: int = CCP_DEFAULT_CRO_ID,
        dto_id: int = CCP_DEFAULT_DTO_ID,
    ) -> List[CCPScanResult]:
        """
        Scan for CCP-enabled ECUs by trying CONNECT with station addresses.

        CCP CONNECT CRO format (8 bytes):
            [CMD=0x01, CTR, station_addr_lo, station_addr_hi, 0,0,0,0]

        Args:
            bus: python-can Bus instance
            station_range: Range of station addresses to try (default 0-255)
            cro_id: CAN arb ID for CRO (master -> slave)
            dto_id: CAN arb ID for DTO (slave -> master)

        Returns:
            List of CCPScanResult for each discovered CCP slave
        """
        can = _get_python_can()()
        results: List[CCPScanResult] = []

        if station_range is None:
            start_addr, end_addr = 0, 255
        else:
            start_addr, end_addr = station_range

        total = end_addr - start_addr + 1
        self.logger.display(
            f"[CCP] Scanning {total} station addresses ({start_addr}-{end_addr}) "
            f"on CRO=0x{cro_id:03X}/DTO=0x{dto_id:03X}..."
        )

        ctr = 0  # Command counter

        for station_addr in range(start_addr, end_addr + 1):
            ctr = (ctr + 1) & 0xFF

            # CRO: [CMD, CTR, station_lo, station_hi, 0, 0, 0, 0]
            # Station address is little-endian (Intel byte order per CCP spec)
            station_lo = station_addr & 0xFF
            station_hi = (station_addr >> 8) & 0xFF
            connect_cro = bytes(
                [CCP_CONNECT_CMD, ctr, station_lo, station_hi, 0x00, 0x00, 0x00, 0x00]
            )

            try:
                msg = can.Message(
                    arbitration_id=cro_id,
                    data=connect_cro,
                    is_extended_id=False,
                )
                bus.send(msg)
            except Exception as e:
                self.logger.debug(f"CCP: CONNECT CRO frame send failed: {e}")
                continue

            # Listen for DTO response on dto_id
            resp = self._recv_ccp_response(bus, dto_id, timeout=0.05)
            if resp is None:
                continue

            resp_data = resp
            # DTO format: [PID, ERR, CTR, data...]
            # PID=0xFF means command return message
            if len(resp_data) >= 3 and resp_data[0] == CCP_DTO_COMMAND_RETURN:
                err_code = resp_data[1]

                if err_code == 0x00:  # Acknowledge / No Error
                    self.logger.success(
                        f"CCP slave found: station={station_addr} "
                        f"(CRO=0x{cro_id:03X}, DTO=0x{dto_id:03X})"
                    )
                    result = CCPScanResult(
                        cro_id=cro_id,
                        dto_id=dto_id,
                        station_address=station_addr,
                        connected=True,
                    )
                    results.append(result)

                    # Disconnect cleanly
                    self._ccp_disconnect(bus, cro_id, station_addr, dto_id=dto_id)
                else:
                    err_name = CCP_CRC.get(err_code, f"0x{err_code:02X}")
                    self.logger.debug(f"  CCP station {station_addr}: {err_name}")

        if not results:
            self.logger.display("  No CCP slaves found")

        return results

    def _recv_ccp_response(self, bus: Any, dto_id: int, timeout: float = 0.1) -> Optional[bytes]:
        """
        Receive a CCP DTO response.

        Args:
            bus: python-can Bus instance
            dto_id: Expected DTO CAN ID
            timeout: Max wait time

        Returns:
            Response data bytes or None
        """
        end_time = time.time() + timeout
        while time.time() < end_time:
            remaining = end_time - time.time()
            msg = bus.recv(timeout=min(remaining, 0.02))
            if msg is None:
                continue
            if msg.arbitration_id == dto_id:
                return bytes(msg.data)
        return None

    def _ccp_disconnect(
        self,
        bus: Any,
        cro_id: int,
        station_address: int,
        dto_id: int = CCP_DEFAULT_DTO_ID,
    ) -> None:
        """Send CCP DISCONNECT command."""
        station_lo = station_address & 0xFF
        station_hi = (station_address >> 8) & 0xFF
        # DISCONNECT: [CMD=0x07, CTR, type=0x01(end_session), 0, station_lo, station_hi, 0, 0]
        disconnect_cro = bytes(
            [
                CCP_DISCONNECT_CMD,
                0x00,
                CCP_DISCONNECT_END_SESSION,
                0x00,
                station_lo,
                station_hi,
                0x00,
                0x00,
            ]
        )
        self.send_message(bus, cro_id, disconnect_cro)
        self._recv_ccp_response(bus, dto_id, timeout=0.05)
