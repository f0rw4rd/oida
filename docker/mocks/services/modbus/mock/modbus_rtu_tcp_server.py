#!/usr/bin/env python3
"""
Mock Modbus RTU-over-TCP Server for testing OIDA --rtu-over-tcp mode

Simulates a serial-to-Ethernet gateway that speaks Modbus RTU framing
over a TCP socket (common in Moxa, Digi, Lantronix gateways).

Unlike standard Modbus TCP (MBAP header), RTU-over-TCP uses:
  - Unit address byte (1 byte)
  - Function code (1 byte)
  - Data (variable)
  - CRC-16 (2 bytes, little-endian)

Multiple slave IDs respond on different unit addresses:
  Unit 1: PLC controller  (full register set)
  Unit 2: Remote I/O      (coils + discrete inputs only)
  Unit 3: Power meter     (input registers only)

Environment:
  MODBUS_RTU_TCP_PORT - Listen port (default: 5030)
"""

import asyncio
import logging
import os
import struct

from pymodbus.server import ModbusTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusServerContext

# pymodbus 3.7-3.11 uses Framer, 3.12+ uses FramerType
try:
    from pymodbus.framer import FramerType as Framer
except ImportError:
    from pymodbus.framer import Framer

try:
    from pymodbus.datastore import ModbusSlaveContext
except ImportError:
    from pymodbus.datastore import ModbusDeviceContext as ModbusSlaveContext
try:
    from pymodbus.device import ModbusDeviceIdentification
except ImportError:
    from pymodbus import ModbusDeviceIdentification

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def float32_to_regs(value: float) -> list:
    packed = struct.pack(">f", value)
    return [(packed[0] << 8) | packed[1], (packed[2] << 8) | packed[3]]


def uint32_to_regs(value: int) -> list:
    return [(value >> 16) & 0xFFFF, value & 0xFFFF]


# ---------------------------------------------------------------------------
# Slave contexts  (3 units on the same "serial bus")
# ---------------------------------------------------------------------------


def create_plc_context():
    """Unit 1: PLC controller - full register set."""
    hr_data = [0] * 100
    hr_data[0] = 1  # system_status: on
    hr_data[1] = 1  # operation_mode: auto
    hr_data[2] = 0  # error_code
    hr_data[3] = 5678  # uptime_hours
    hr_data[10:12] = float32_to_regs(22.0)
    hr_data[12:14] = float32_to_regs(4.5)
    hr_data[40] = 80  # motor_speed_pct
    hr_data[41] = 60  # valve_position_pct
    hr_data[42] = 1  # pump_enabled

    return ModbusSlaveContext(
        di=ModbusSequentialDataBlock(1, [1, 0, 1, 0] * 25),
        co=ModbusSequentialDataBlock(1, [0] * 100),
        hr=ModbusSequentialDataBlock(1, hr_data),
        ir=ModbusSequentialDataBlock(1, [0] * 100),
    )


def create_remote_io_context():
    """Unit 2: Remote I/O module - coils and discrete inputs."""
    return ModbusSlaveContext(
        di=ModbusSequentialDataBlock(1, [1, 1, 0, 0, 1, 0, 1, 1] * 8),
        co=ModbusSequentialDataBlock(1, [0, 1, 0, 1, 1, 0, 0, 1] * 8),
        hr=ModbusSequentialDataBlock(1, [0] * 10),
        ir=ModbusSequentialDataBlock(1, [0] * 10),
    )


def create_power_meter_context():
    """Unit 3: Power meter - input registers with energy data."""
    ir_data = [0] * 100

    # Voltage L1-L3 (float32, 2 regs each)
    ir_data[0:2] = float32_to_regs(230.1)  # V_L1
    ir_data[2:4] = float32_to_regs(231.4)  # V_L2
    ir_data[4:6] = float32_to_regs(229.8)  # V_L3

    # Current L1-L3 (float32)
    ir_data[10:12] = float32_to_regs(12.5)  # I_L1
    ir_data[12:14] = float32_to_regs(8.3)  # I_L2
    ir_data[14:16] = float32_to_regs(15.1)  # I_L3

    # Power (float32)
    ir_data[20:22] = float32_to_regs(2875.0)  # Active power W
    ir_data[22:24] = float32_to_regs(450.0)  # Reactive power VAR
    ir_data[24:26] = float32_to_regs(2910.0)  # Apparent power VA

    # Energy (uint32, 2 regs)
    ir_data[30:32] = uint32_to_regs(123456)  # Total kWh

    # Frequency
    ir_data[40:42] = float32_to_regs(50.02)  # Hz

    # Power factor
    ir_data[50:52] = float32_to_regs(0.987)  # cos(phi)

    return ModbusSlaveContext(
        di=ModbusSequentialDataBlock(1, [0] * 10),
        co=ModbusSequentialDataBlock(1, [0] * 10),
        hr=ModbusSequentialDataBlock(1, [0] * 10),
        ir=ModbusSequentialDataBlock(1, ir_data),
    )


def create_device_identity():
    identity = ModbusDeviceIdentification()
    identity[0x00] = "OIDA Mock Devices"
    identity[0x01] = "OIDA-RTU-GW"
    identity[0x02] = "2.0.0"
    identity[0x03] = "https://github.com/oida"
    identity[0x04] = "Mock Serial Gateway (RTU-over-TCP)"
    identity[0x05] = "OIDA-RTU"
    identity[0x06] = "OIDA Modbus RTU-over-TCP Gateway"
    return identity


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main():
    port = int(os.environ.get("MODBUS_RTU_TCP_PORT", "5030"))

    print("=" * 50)
    print("  Modbus RTU-over-TCP Gateway (pymodbus)")
    print(f"  Port: {port}")
    print("  Framing: RTU (with CRC-16)")
    print("  Slaves:")
    print("    Unit 1: PLC controller")
    print("    Unit 2: Remote I/O module")
    print("    Unit 3: Power meter")
    print("=" * 50)

    # Multi-slave context
    slaves = {
        1: create_plc_context(),
        2: create_remote_io_context(),
        3: create_power_meter_context(),
    }
    try:
        context = ModbusServerContext(slaves=slaves, single=False)
    except TypeError:
        context = ModbusServerContext(devices=slaves, single=False)

    server = ModbusTcpServer(
        context=context,
        identity=create_device_identity(),
        address=("0.0.0.0", port),
        framer=Framer.RTU,
    )

    log.info("Modbus RTU-over-TCP gateway listening on port %d", port)
    await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
