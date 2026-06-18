#!/usr/bin/env python3
"""
Mock Modbus TCP Server for testing OIDA Modbus scanner

Supports pymodbus 3.x API.

Register Map (oida-mock):
  Holding Registers (4x):
    0: system_status (u16, rw) - System status: 0=off, 1=on, 2=fault
    1: operation_mode (u16, rw) - Mode: 0=manual, 1=auto, 2=maintenance
    2: error_code (u16, r) - Current error code
    3: uptime_hours (u16, r) - System uptime in hours

    10-11: temperature_setpoint (f32, rw) - Temperature setpoint in °C
    12-13: pressure_setpoint (f32, rw) - Pressure setpoint in bar
    14-15: flow_rate_setpoint (f32, rw) - Flow rate setpoint in L/min

    20-21: current_temperature (f32, r) - Current temperature reading
    22-23: current_pressure (f32, r) - Current pressure reading
    24-25: current_flow_rate (f32, r) - Current flow rate reading

    30-31: total_runtime (u32, r) - Total runtime in seconds
    32-33: cycle_count (u32, rw) - Process cycle counter

    40: motor_speed_pct (u16, rw) - Motor speed 0-100%
    41: valve_position_pct (u16, rw) - Valve position 0-100%
    42: pump_enabled (u16, rw) - Pump enable: 0=off, 1=on

    50-51: alarm_threshold_high (f32, rw) - High alarm threshold
    52-53: alarm_threshold_low (f32, rw) - Low alarm threshold

    60-61: pid_kp (f32, rw) - PID proportional gain
    62-63: pid_ki (f32, rw) - PID integral gain
    64-65: pid_kd (f32, rw) - PID derivative gain

CANopen MEI (FC 43/13) Support:
  Mock CANopen Object Dictionary for testing CiA 309-2 gateway functionality.
  Simulates a CANopen-to-Modbus gateway with standard objects.
"""

import asyncio
import logging
import struct
from pymodbus.server import ModbusTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusServerContext

# Handle pymodbus 3.11+ API change (ModbusSlaveContext -> ModbusDeviceContext)
try:
    from pymodbus.datastore import ModbusSlaveContext
except ImportError:
    from pymodbus.datastore import ModbusDeviceContext as ModbusSlaveContext
# Handle pymodbus 3.11+ API change (device module removed)
try:
    from pymodbus.device import ModbusDeviceIdentification
except ImportError:
    from pymodbus import ModbusDeviceIdentification
from pymodbus.pdu import ModbusPDU

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


# =============================================================================
# CANopen MEI (FC 43/13) Constants and Data
# =============================================================================

# MEI Type codes
MEI_TYPE_CANOPEN = 0x0D  # CANopen (CiA 309-2)
MEI_TYPE_DEVICE_ID = 0x0E  # Device Identification

# CANopen MEI command codes
CANOPEN_CMD_GET_INFO = 0x01
CANOPEN_CMD_SDO_DOWNLOAD = 0x20  # Write
CANOPEN_CMD_SDO_UPLOAD = 0x40  # Read

# CANopen data types
CANOPEN_TYPE_BOOLEAN = 0x01
CANOPEN_TYPE_INTEGER8 = 0x02
CANOPEN_TYPE_INTEGER16 = 0x03
CANOPEN_TYPE_INTEGER32 = 0x04
CANOPEN_TYPE_UNSIGNED8 = 0x05
CANOPEN_TYPE_UNSIGNED16 = 0x06
CANOPEN_TYPE_UNSIGNED32 = 0x07
CANOPEN_TYPE_REAL32 = 0x08
CANOPEN_TYPE_VISIBLE_STRING = 0x09

# Mock CANopen Object Dictionary
# Format: (index, subindex) -> (data_type, value)
CANOPEN_OBJECT_DICTIONARY = {
    # Communication Profile Area (0x1000-0x1FFF)
    (0x1000, 0): (CANOPEN_TYPE_UNSIGNED32, 0x00000191),  # Device Type (401 = Generic I/O)
    (0x1001, 0): (CANOPEN_TYPE_UNSIGNED8, 0x00),  # Error Register
    (0x1008, 0): (CANOPEN_TYPE_VISIBLE_STRING, b"OIDA Mock CANopen"),  # Manufacturer Device Name
    (0x1009, 0): (CANOPEN_TYPE_VISIBLE_STRING, b"1.0.0"),  # Hardware Version
    (0x100A, 0): (CANOPEN_TYPE_VISIBLE_STRING, b"2.0.0"),  # Software Version
    (0x1017, 0): (CANOPEN_TYPE_UNSIGNED16, 1000),  # Producer Heartbeat Time (ms)
    (0x1018, 0): (CANOPEN_TYPE_UNSIGNED8, 4),  # Identity Object - number of entries
    (0x1018, 1): (CANOPEN_TYPE_UNSIGNED32, 0x00000001),  # Vendor ID
    (0x1018, 2): (CANOPEN_TYPE_UNSIGNED32, 0x00000001),  # Product Code
    (0x1018, 3): (CANOPEN_TYPE_UNSIGNED32, 0x00020000),  # Revision Number (2.0)
    (0x1018, 4): (CANOPEN_TYPE_UNSIGNED32, 0x12345678),  # Serial Number
    # Manufacturer Specific Area (0x2000-0x5FFF)
    (0x2000, 0): (CANOPEN_TYPE_UNSIGNED16, 100),  # Custom register
    (0x2001, 0): (CANOPEN_TYPE_REAL32, 3.14159),  # Custom float
    # Standardized Device Profile Area (0x6000-0x9FFF) - Generic I/O
    (0x6000, 0): (CANOPEN_TYPE_UNSIGNED8, 8),  # Read Input 8 Bit - number of inputs
    (0x6000, 1): (CANOPEN_TYPE_UNSIGNED8, 0b10101010),  # Input byte 1
    (0x6200, 0): (CANOPEN_TYPE_UNSIGNED8, 8),  # Write Output 8 Bit - number of outputs
    (0x6200, 1): (CANOPEN_TYPE_UNSIGNED8, 0b01010101),  # Output byte 1
}


def encode_canopen_value(data_type: int, value) -> bytes:
    """Encode a CANopen value to bytes (little-endian)."""
    if data_type == CANOPEN_TYPE_BOOLEAN:
        return bytes([1 if value else 0])
    elif data_type == CANOPEN_TYPE_INTEGER8:
        return struct.pack("<b", value)
    elif data_type == CANOPEN_TYPE_INTEGER16:
        return struct.pack("<h", value)
    elif data_type == CANOPEN_TYPE_INTEGER32:
        return struct.pack("<i", value)
    elif data_type == CANOPEN_TYPE_UNSIGNED8:
        return struct.pack("<B", value)
    elif data_type == CANOPEN_TYPE_UNSIGNED16:
        return struct.pack("<H", value)
    elif data_type == CANOPEN_TYPE_UNSIGNED32:
        return struct.pack("<I", value)
    elif data_type == CANOPEN_TYPE_REAL32:
        return struct.pack("<f", value)
    elif data_type == CANOPEN_TYPE_VISIBLE_STRING:
        if isinstance(value, str):
            value = value.encode("ascii")
        return value + b"\x00"  # Null-terminated
    else:
        return bytes([])


class CANopenMEIRequest(ModbusPDU):
    """Custom PDU for CANopen MEI (FC 43/13) requests."""

    function_code = 0x2B  # FC 43

    def __init__(self, mei_type=0, data=b"", **kwargs):
        super().__init__(**kwargs)
        self.mei_type = mei_type
        self.data = data

    def decode(self, data: bytes) -> None:
        """Decode the request."""
        if len(data) >= 1:
            self.mei_type = data[0]
            self.data = data[1:] if len(data) > 1 else b""

    def encode(self) -> bytes:
        """Encode the request."""
        return bytes([self.mei_type]) + self.data


class CANopenMEIResponse(ModbusPDU):
    """Custom PDU for CANopen MEI (FC 43/13) responses."""

    function_code = 0x2B  # FC 43

    def __init__(self, mei_type=0, data=b"", **kwargs):
        super().__init__(**kwargs)
        self.mei_type = mei_type
        self.data = data

    def encode(self) -> bytes:
        """Encode the response."""
        return bytes([self.mei_type]) + self.data

    def decode(self, data: bytes) -> None:
        """Decode the response."""
        if len(data) >= 1:
            self.mei_type = data[0]
            self.data = data[1:] if len(data) > 1 else b""


def handle_canopen_mei(request_data: bytes) -> bytes:
    """Handle CANopen MEI (FC 43/13) requests.

    Args:
        request_data: Raw request data after function code

    Returns:
        Response data to send back
    """
    if len(request_data) < 2:
        log.warning("CANopen MEI: Request too short")
        return bytes([MEI_TYPE_CANOPEN, 0x00])  # Error response

    mei_type = request_data[0]
    command = request_data[1]

    log.info(f"CANopen MEI request: MEI=0x{mei_type:02X}, CMD=0x{command:02X}")

    # Only handle CANopen MEI type
    if mei_type != MEI_TYPE_CANOPEN:
        log.warning(f"CANopen MEI: Unsupported MEI type 0x{mei_type:02X}")
        return bytes([mei_type, 0x00])

    # Handle Get Info command
    if command == CANOPEN_CMD_GET_INFO:
        log.info("CANopen MEI: Get Info")
        # Response: [MEI_type] [gateway_class] [protocol_version] [vendor_info...]
        return bytes(
            [
                MEI_TYPE_CANOPEN,
                0x01,  # Gateway class 1 (SDO client)
                0x01,  # Protocol version 1.0
                0x00,  # Additional info length
            ]
        )

    # Handle SDO Upload (Read) command
    elif command == CANOPEN_CMD_SDO_UPLOAD:
        if len(request_data) < 6:
            log.warning("CANopen MEI: SDO Upload request too short")
            return bytes([MEI_TYPE_CANOPEN, command, 0x00])

        node_id = request_data[2]
        index = request_data[3] | (request_data[4] << 8)  # Little-endian
        subindex = request_data[5]

        log.info(
            f"CANopen MEI: SDO Upload Node={node_id}, Index=0x{index:04X}, Subindex={subindex}"
        )

        # Look up in object dictionary
        obj_key = (index, subindex)
        if obj_key in CANOPEN_OBJECT_DICTIONARY:
            data_type, value = CANOPEN_OBJECT_DICTIONARY[obj_key]
            encoded_value = encode_canopen_value(data_type, value)

            log.info(f"CANopen MEI: Found object, type=0x{data_type:02X}, value={value}")

            # Response: [MEI_type] [cmd] [node_id] [data_type] [data...]
            return (
                bytes(
                    [
                        MEI_TYPE_CANOPEN,
                        command,
                        node_id,
                        data_type,
                    ]
                )
                + encoded_value
            )
        else:
            log.warning(f"CANopen MEI: Object not found 0x{index:04X}:{subindex}")
            # SDO abort response (object does not exist - 0x06020000)
            return bytes(
                [
                    MEI_TYPE_CANOPEN,
                    0x80,  # Abort
                    node_id,
                    0x00,
                    0x00,
                    0x02,
                    0x06,  # Abort code: Object does not exist
                ]
            )

    # Handle SDO Download (Write) command
    elif command == CANOPEN_CMD_SDO_DOWNLOAD:
        if len(request_data) < 6:
            log.warning("CANopen MEI: SDO Download request too short")
            return bytes([MEI_TYPE_CANOPEN, command, 0x00])

        node_id = request_data[2]
        index = request_data[3] | (request_data[4] << 8)
        subindex = request_data[5]
        write_data = request_data[6:] if len(request_data) > 6 else b""

        log.info(
            f"CANopen MEI: SDO Download Node={node_id}, Index=0x{index:04X}, Subindex={subindex}, Data={write_data.hex()}"
        )

        # For mock, just acknowledge the write
        obj_key = (index, subindex)
        if obj_key in CANOPEN_OBJECT_DICTIONARY:
            # Success response
            return bytes(
                [
                    MEI_TYPE_CANOPEN,
                    command,
                    node_id,
                ]
            )
        else:
            log.warning(f"CANopen MEI: Object not found for write 0x{index:04X}:{subindex}")
            return bytes(
                [
                    MEI_TYPE_CANOPEN,
                    0x80,  # Abort
                    node_id,
                    0x00,
                    0x00,
                    0x02,
                    0x06,  # Object does not exist
                ]
            )

    else:
        log.warning(f"CANopen MEI: Unknown command 0x{command:02X}")
        return bytes([MEI_TYPE_CANOPEN, 0x00])


def float32_to_regs(value: float, byte_order="big") -> list:
    """Convert float32 to two 16-bit registers (big-endian)"""
    packed = struct.pack(">f", value)
    return [
        (packed[0] << 8) | packed[1],
        (packed[2] << 8) | packed[3],
    ]


def uint32_to_regs(value: int) -> list:
    """Convert uint32 to two 16-bit registers (big-endian)"""
    return [(value >> 16) & 0xFFFF, value & 0xFFFF]


def create_device_identity():
    """Create device identification for MEI (FC43)"""
    identity = ModbusDeviceIdentification()
    identity[0x00] = "OIDA Mock Devices"  # VendorName
    identity[0x01] = "OIDA-MOCK-001"  # ProductCode
    identity[0x02] = "2.0.0"  # MajorMinorRevision
    identity[0x03] = "https://github.com/oida"  # VendorUrl
    identity[0x04] = "Mock Industrial PLC"  # ProductName
    identity[0x05] = "OIDA-SIM"  # ModelName
    identity[0x06] = "OIDA Fuzz Test Server"  # UserApplicationName
    return identity


def create_modbus_context():
    """Create a mock Modbus context with typed registers for fuzz testing"""

    # Initialize 100 registers with zeros
    hr_data = [0] * 100

    # Single u16 registers (0-9)
    hr_data[0] = 1  # system_status: 1=on
    hr_data[1] = 1  # operation_mode: 1=auto
    hr_data[2] = 0  # error_code: no error
    hr_data[3] = 1234  # uptime_hours

    # Float32 setpoints (10-15) - 2 registers each
    hr_data[10:12] = float32_to_regs(25.5)  # temperature_setpoint: 25.5°C
    hr_data[12:14] = float32_to_regs(3.14)  # pressure_setpoint: 3.14 bar
    hr_data[14:16] = float32_to_regs(100.0)  # flow_rate_setpoint: 100 L/min

    # Float32 readings (20-25) - read-only in practice
    hr_data[20:22] = float32_to_regs(24.8)  # current_temperature
    hr_data[22:24] = float32_to_regs(3.12)  # current_pressure
    hr_data[24:26] = float32_to_regs(98.5)  # current_flow_rate

    # Uint32 counters (30-33)
    hr_data[30:32] = uint32_to_regs(86400)  # total_runtime: 1 day in seconds
    hr_data[32:34] = uint32_to_regs(1000)  # cycle_count

    # Control registers (40-42)
    hr_data[40] = 75  # motor_speed_pct: 75%
    hr_data[41] = 50  # valve_position_pct: 50%
    hr_data[42] = 1  # pump_enabled: on

    # Alarm thresholds (50-53)
    hr_data[50:52] = float32_to_regs(30.0)  # alarm_threshold_high
    hr_data[52:54] = float32_to_regs(10.0)  # alarm_threshold_low

    # PID parameters (60-65)
    hr_data[60:62] = float32_to_regs(1.5)  # pid_kp
    hr_data[62:64] = float32_to_regs(0.1)  # pid_ki
    hr_data[64:66] = float32_to_regs(0.05)  # pid_kd

    # Create data blocks
    coils = ModbusSequentialDataBlock(0x00, [0] * 100)
    discrete_inputs = ModbusSequentialDataBlock(0x00, [1, 0, 1, 0] * 25)
    input_registers = ModbusSequentialDataBlock(0x00, [0] * 100)
    holding_registers = ModbusSequentialDataBlock(0x00, hr_data)

    # Create slave context
    slave_context = ModbusSlaveContext(
        di=discrete_inputs,
        co=coils,
        hr=holding_registers,
        ir=input_registers,
    )

    # Create server context with single slave
    # Handle pymodbus 3.11+ API change (slaves -> devices)
    try:
        context = ModbusServerContext(slaves=slave_context, single=True)
    except TypeError:
        context = ModbusServerContext(devices=slave_context, single=True)

    return context


def custom_request_handler(request):
    """Custom request handler for unsupported function codes.

    This handles FC 43 (MEI) for CANopen support.
    """
    # Check if this is FC 43 (MEI)
    fc = getattr(request, "function_code", 0)
    if fc == 0x2B:
        # Get the raw data from the request
        try:
            raw_data = request.encode() if hasattr(request, "encode") else b""
            log.info(f"FC 43 request received, data: {raw_data.hex()}")

            # Handle CANopen MEI
            response_data = handle_canopen_mei(raw_data)

            # Create response
            response = CANopenMEIResponse(
                mei_type=response_data[0] if response_data else 0,
                data=response_data[1:] if len(response_data) > 1 else b"",
            )
            return response
        except Exception as e:
            log.error(f"Error handling FC 43: {e}")
            return None
    return None


async def main():
    """Start the mock Modbus TCP server"""
    log.info("Starting Mock Modbus TCP Server on port 502")
    log.info("  - Standard Modbus registers supported")
    log.info("  - CANopen MEI (FC 43/13) supported")

    context = create_modbus_context()

    # pymodbus 3.x uses ModbusTcpServer class
    server = ModbusTcpServer(
        context=context,
        identity=create_device_identity(),
        address=("0.0.0.0", 502),
    )

    # Register custom PDU handlers for FC 43
    # Note: pymodbus 3.x custom function handling is done via decoder registration
    try:
        if hasattr(server, "decoder"):
            # Register our custom request/response classes
            server.decoder.register(CANopenMEIRequest)
            server.decoder.register(CANopenMEIResponse)
            log.info("Registered CANopen MEI (FC 43) handlers")
    except Exception as e:
        log.warning(f"Could not register custom FC handlers: {e}")
        log.info("CANopen MEI may not be fully supported")

    log.info("Server ready - waiting for connections...")
    await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
