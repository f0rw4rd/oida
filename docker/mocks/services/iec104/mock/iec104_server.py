#!/usr/bin/env python3
"""
Mock IEC 104 Server for testing OIDA IEC 104 scanner
"""

import asyncio
import logging
import struct
import time
from typing import Dict

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


class IEC104Frame:
    """IEC 60870-5-104 frame structure"""

    # APCI (Application Protocol Control Information)
    START_BYTE = 0x68

    # ASDU Types - Standard
    M_SP_NA_1 = 1  # Single-point information
    M_DP_NA_1 = 3  # Double-point information
    M_ME_NA_1 = 9  # Measured value, normalized value
    M_ME_NB_1 = 11  # Measured value, scaled value
    M_ME_NC_1 = 13  # Measured value, short floating point
    C_IC_NA_1 = 100  # Interrogation command

    # Custom/Vendor-Specific Type IDs (128-255)
    # These are used to test custom type detection
    CUSTOM_VENDOR_1 = 200  # Vendor-specific measurement
    CUSTOM_VENDOR_2 = 201  # Vendor-specific status
    CUSTOM_VENDOR_3 = 210  # Vendor-specific control feedback
    CUSTOM_VENDOR_4 = 220  # Vendor-specific diagnostic

    @staticmethod
    def create_i_frame(asdu_data: bytes, send_seq: int, recv_seq: int) -> bytes:
        """Create I-format frame"""
        apci_len = len(asdu_data) + 4
        apci = struct.pack(
            "<BBHH",
            IEC104Frame.START_BYTE,
            apci_len,
            (send_seq << 1),  # Send sequence number
            (recv_seq << 1),
        )  # Receive sequence number
        return apci + asdu_data

    @staticmethod
    def create_s_frame(recv_seq: int) -> bytes:
        """Create S-format frame (supervisory)"""
        apci = struct.pack(
            "<BBHH",
            IEC104Frame.START_BYTE,
            4,  # Length
            0x01,  # S-frame marker
            (recv_seq << 1),
        )
        return apci

    @staticmethod
    def create_u_frame(function: int) -> bytes:
        """Create U-format frame (unnumbered)"""
        apci = struct.pack(
            "<BBHH",
            IEC104Frame.START_BYTE,
            4,  # Length
            function,  # Function code
            0,
        )
        return apci


class IEC104ASDU:
    """IEC 60870-5-104 ASDU (Application Service Data Unit)"""

    @staticmethod
    def create_asdu(type_id: int, cause: int, common_addr: int, ioa: int, data: bytes) -> bytes:
        """Create ASDU"""
        # ASDU header: TypeID, VSQ, COT, CommonAddr, IOA
        vsq = 0x01  # Single information object
        asdu_header = struct.pack("<BBHHL", type_id, vsq, cause, common_addr, ioa)
        return asdu_header + data

    @staticmethod
    def create_single_point(value: bool, quality: int = 0x00) -> bytes:
        """Create single point information"""
        spi = (quality << 1) | (1 if value else 0)
        return struct.pack("<B", spi)

    @staticmethod
    def create_measured_value_float(value: float, quality: int = 0x00) -> bytes:
        """Create measured value (short floating point)"""
        return struct.pack("<fB", value, quality)

    @staticmethod
    def create_measured_value_scaled(value: int, quality: int = 0x00) -> bytes:
        """Create measured value (scaled)"""
        return struct.pack("<hB", value, quality)


class MockIEC104Server:
    """Mock IEC 104 server implementation"""

    def __init__(self, host="0.0.0.0", port=2404):
        self.host = host
        self.port = port
        self.clients = []
        self.send_seq = 0
        self.recv_seq = 0
        self.data_points = self._create_mock_data_points()

    def _create_mock_data_points(self) -> Dict[int, Dict]:
        """Create mock industrial data points"""
        points = {}

        # Digital inputs (IOA 1-20)
        for i in range(1, 21):
            points[i] = {
                "type": "digital",
                "value": i % 2 == 0,  # Alternating pattern
                "description": f"Digital Input {i}",
            }

        # Analog measurements (IOA 21-50)
        for i in range(21, 51):
            points[i] = {
                "type": "analog",
                "value": 100.0 + i * 10.0,
                "description": f"Analog Measurement {i}",
            }

        # Status points (IOA 51-70)
        for i in range(51, 71):
            points[i] = {
                "type": "status",
                "value": i % 3,  # 0, 1, 2 states
                "description": f"Status Point {i}",
            }

        # Scaled values (IOA 71-100)
        for i in range(71, 101):
            points[i] = {"type": "scaled", "value": i * 100, "description": f"Scaled Value {i}"}

        # Custom/Vendor-Specific data points (IOA 1000-1019)
        # These use non-standard Type IDs to test custom type detection
        for i in range(1000, 1005):
            points[i] = {
                "type": "custom_vendor_1",
                "type_id": IEC104Frame.CUSTOM_VENDOR_1,  # Type 200
                "value": i * 10 + 0.5,
                "description": f"Vendor Measurement {i}",
            }

        for i in range(1005, 1010):
            points[i] = {
                "type": "custom_vendor_2",
                "type_id": IEC104Frame.CUSTOM_VENDOR_2,  # Type 201
                "value": i % 4,  # 0-3 status values
                "description": f"Vendor Status {i}",
            }

        for i in range(1010, 1015):
            points[i] = {
                "type": "custom_vendor_3",
                "type_id": IEC104Frame.CUSTOM_VENDOR_3,  # Type 210
                "value": 100 + i,
                "description": f"Vendor Control FB {i}",
            }

        for i in range(1015, 1020):
            points[i] = {
                "type": "custom_vendor_4",
                "type_id": IEC104Frame.CUSTOM_VENDOR_4,  # Type 220
                "value": bytes([0xDE, 0xAD, 0xBE, 0xEF, i & 0xFF]),
                "description": f"Vendor Diagnostic {i}",
            }

        return points

    def _simulate_data_changes(self):
        """Simulate realistic data changes"""
        import random
        import math

        current_time = time.time()

        # Update analog values with sine wave + noise
        for ioa in range(21, 51):
            base_value = 100.0 + ioa * 10.0
            sine_component = 50.0 * math.sin(current_time * 0.1 + ioa * 0.1)
            noise = random.uniform(-5.0, 5.0)
            self.data_points[ioa]["value"] = base_value + sine_component + noise

        # Randomly toggle some digital inputs
        for ioa in range(1, 21):
            if random.random() < 0.1:  # 10% chance to toggle
                self.data_points[ioa]["value"] = not self.data_points[ioa]["value"]

        # Update scaled values
        for ioa in range(71, 101):
            self.data_points[ioa]["value"] = ioa * 100 + random.randint(-50, 50)

    async def handle_client(self, reader, writer):
        """Handle individual client connection"""
        client_addr = writer.get_extra_info("peername")
        log.info(f"IEC 104 client connected from {client_addr}")

        self.clients.append(writer)
        connected = False

        try:
            while True:
                # Read frame header
                data = await reader.read(2)
                if not data:
                    break

                if len(data) < 2:
                    continue

                start_byte, length = struct.unpack("<BB", data)

                if start_byte != IEC104Frame.START_BYTE:
                    continue

                # Read rest of frame
                if length > 0:
                    remaining_data = await reader.read(length)
                    if not remaining_data:
                        break

                    frame_data = data + remaining_data
                    await self._process_frame(frame_data, writer, connected)

                    # Update connection status based on frame type
                    if length >= 4:
                        frame_type = struct.unpack("<H", remaining_data[:2])[0]
                        if frame_type & 0x03 == 0x03:  # U-frame
                            u_type = (frame_type >> 2) & 0x3F
                            if u_type == 0x01:  # STARTDT act
                                connected = True
                            elif u_type == 0x04:  # STOPDT act
                                connected = False

        except Exception as e:
            log.error(f"Error handling client {client_addr}: {e}")
        finally:
            if writer in self.clients:
                self.clients.remove(writer)
            writer.close()
            await writer.wait_closed()
            log.info(f"IEC 104 client {client_addr} disconnected")

    async def _process_frame(self, frame_data: bytes, writer, connected: bool):
        """Process received IEC 104 frame"""
        if len(frame_data) < 6:
            return

        start, length, ctrl1, ctrl2 = struct.unpack("<BBHH", frame_data[:6])

        # Determine frame type
        if ctrl1 & 0x01 == 0:  # I-frame
            if connected:
                await self._handle_i_frame(frame_data[6:], writer)
            self.recv_seq = (self.recv_seq + 1) % 32768

        elif ctrl1 & 0x03 == 0x01:  # S-frame
            # Supervisory frame - acknowledge
            pass

        elif ctrl1 & 0x03 == 0x03:  # U-frame
            await self._handle_u_frame(ctrl1, writer)

    async def _handle_u_frame(self, ctrl: int, writer):
        """Handle U-format frames (connection control)"""
        u_type = (ctrl >> 2) & 0x3F

        if u_type == 0x01:  # STARTDT act
            # Send STARTDT con
            response = IEC104Frame.create_u_frame(0x0B)  # STARTDT con
            writer.write(response)
            await writer.drain()
            log.info("IEC 104 connection activated")

        elif u_type == 0x04:  # STOPDT act
            # Send STOPDT con
            response = IEC104Frame.create_u_frame(0x23)  # STOPDT con
            writer.write(response)
            await writer.drain()
            log.info("IEC 104 connection deactivated")

        elif u_type == 0x10:  # TESTFR act
            # Send TESTFR con
            response = IEC104Frame.create_u_frame(0x83)  # TESTFR con
            writer.write(response)
            await writer.drain()

    async def _handle_i_frame(self, asdu_data: bytes, writer):
        """Handle I-format frames (data transmission)"""
        if len(asdu_data) < 9:  # Minimum ASDU header size
            return

        type_id, vsq, cause, common_addr, ioa = struct.unpack("<BBHHL", asdu_data[:9])

        log.debug(f"Received ASDU: Type={type_id}, Cause={cause}, IOA={ioa}")

        if type_id == IEC104Frame.C_IC_NA_1:  # General interrogation
            await self._send_general_interrogation_response(writer, common_addr)

        # Send S-frame acknowledgment
        s_frame = IEC104Frame.create_s_frame(self.recv_seq)
        writer.write(s_frame)
        await writer.drain()

    async def _send_general_interrogation_response(self, writer, common_addr: int):
        """Send response to general interrogation command"""
        log.info("Sending general interrogation response")

        # Simulate data changes
        self._simulate_data_changes()

        # Send all data points
        for ioa, point in self.data_points.items():
            if point["type"] == "digital":
                data = IEC104ASDU.create_single_point(point["value"])
                asdu = IEC104ASDU.create_asdu(IEC104Frame.M_SP_NA_1, 20, common_addr, ioa, data)

            elif point["type"] == "analog":
                data = IEC104ASDU.create_measured_value_float(point["value"])
                asdu = IEC104ASDU.create_asdu(IEC104Frame.M_ME_NC_1, 20, common_addr, ioa, data)

            elif point["type"] == "scaled":
                data = IEC104ASDU.create_measured_value_scaled(int(point["value"]))
                asdu = IEC104ASDU.create_asdu(IEC104Frame.M_ME_NB_1, 20, common_addr, ioa, data)

            elif point["type"].startswith("custom_vendor"):
                # Send custom/vendor-specific type
                type_id = point.get("type_id", 200)
                if isinstance(point["value"], bytes):
                    data = point["value"]
                elif isinstance(point["value"], float):
                    data = struct.pack("<fB", point["value"], 0x00)
                else:
                    data = struct.pack("<hB", int(point["value"]), 0x00)
                asdu = IEC104ASDU.create_asdu(type_id, 20, common_addr, ioa, data)

            else:
                continue

            # Send I-frame with data
            i_frame = IEC104Frame.create_i_frame(asdu, self.send_seq, self.recv_seq)
            writer.write(i_frame)
            await writer.drain()

            self.send_seq = (self.send_seq + 1) % 32768

            # Small delay to avoid overwhelming client
            await asyncio.sleep(0.01)

        # Send end of interrogation
        end_data = struct.pack("<B", 0x00)  # Qualifier of interrogation
        end_asdu = IEC104ASDU.create_asdu(IEC104Frame.C_IC_NA_1, 10, common_addr, 0, end_data)
        end_frame = IEC104Frame.create_i_frame(end_asdu, self.send_seq, self.recv_seq)
        writer.write(end_frame)
        await writer.drain()

        self.send_seq = (self.send_seq + 1) % 32768

        # Count custom types sent
        custom_count = sum(1 for p in self.data_points.values() if p["type"].startswith("custom"))
        log.info(
            f"General interrogation complete - sent {len(self.data_points)} data points ({custom_count} custom types)"
        )

    async def start_server(self):
        """Start the IEC 104 server"""
        server = await asyncio.start_server(self.handle_client, self.host, self.port)

        log.info(f"Mock IEC 104 server started on {self.host}:{self.port}")
        log.info(f"Serving {len(self.data_points)} mock data points")

        async with server:
            await server.serve_forever()


async def main():
    """Start the mock IEC 104 server"""
    server = MockIEC104Server()
    await server.start_server()


if __name__ == "__main__":
    asyncio.run(main())
