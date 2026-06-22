#!/usr/bin/env python3
"""
Enhanced Mock ADS (Automation Device Specification) Server for testing OIDA ADS scanner

Supports:
- Full symbol enumeration with proper pyads-compatible responses
- Memory area access (M-Area, I/O images, Data area)
- Multi-port support (TC3PLC1-4, NC, CNC, SPS1-4)
- State control (RUN, STOP, CONFIG, etc.)
- AMS route table
- Read/Write operations with value persistence
- Realistic PLC simulation
"""

import asyncio
import logging
import struct
import time
import math
import random
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import IntEnum

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
log = logging.getLogger(__name__)


class ADSCommand(IntEnum):
    """ADS command IDs"""

    INVALID = 0x00
    READDEVICEINFO = 0x01
    READ = 0x02
    WRITE = 0x03
    READSTATE = 0x04
    WRITECTRL = 0x05
    ADDNOTIFICATION = 0x06
    DELNOTIFICATION = 0x07
    NOTIFICATION = 0x08
    READWRITE = 0x09


class ADSState(IntEnum):
    """ADS state constants"""

    INVALID = 0
    IDLE = 1
    RESET = 2
    INIT = 3
    START = 4
    RUN = 5
    STOP = 6
    SAVECFG = 7
    LOADCFG = 8
    POWERFAILURE = 9
    POWERGOOD = 10
    ERROR = 11
    SHUTDOWN = 12
    SUSPEND = 13
    RESUME = 14
    CONFIG = 15
    RECONFIG = 16


class ADSError(IntEnum):
    """ADS error codes"""

    NOERR = 0x00000000
    INTERNAL = 0x00000001
    NORTIME = 0x00000002
    TARGETPORTNOTFOUND = 0x00000006
    TARGETMACHINENOTFOUND = 0x00000007
    UNKNOWNCMDID = 0x00000008
    INVALIDAMSNETID = 0x0000000F
    INVALIDADSPORT = 0x00000018
    SYMBOLNOTFOUND = 0x00000710
    INVALIDINDEXGROUP = 0x00000702
    INVALIDINDEXOFFSET = 0x00000703
    ACCESSDENIED = 0x00000705
    INVALIDSIZE = 0x00000706


class IndexGroup(IntEnum):
    """ADS index groups for various operations"""

    # Symbol access
    SYMTAB = 0xF000  # Symbol table
    SYMNAME = 0xF001  # Symbol name
    SYMVAL = 0xF002  # Symbol value
    SYM_HNDBYNAME = 0xF003  # Get handle by name
    SYM_VALBYNAME = 0xF004  # Value by name
    SYM_VALBYHND = 0xF005  # Value by handle
    SYM_RELEASEHND = 0xF006  # Release handle
    SYM_INFOBYNAME = 0xF007  # Info by name
    SYM_VERSION = 0xF008  # Symbol version
    SYM_INFOBYNAMEEX = 0xF009  # Extended info
    SYM_DOWNLOAD = 0xF00A  # Download symbols
    SYM_UPLOAD = 0xF00B  # Upload symbols
    SYM_UPLOADINFO = 0xF00C  # Upload info
    SYM_UPLOADINFO2 = 0xF00F  # Upload info 2

    # Memory areas
    MEMORYBYTE = 0x4020  # %MB - Memory byte
    MEMORYBIT = 0x4021  # %MX - Memory bit
    MEMORYSIZE = 0x4025  # Memory size
    DATA = 0x4040  # Data area
    RETAIN = 0x4080  # Retain data

    # I/O images
    IOIMAGE_RWIB = 0xF020  # Input image byte
    IOIMAGE_RWIX = 0xF021  # Input image bit
    IOIMAGE_RWOB = 0xF030  # Output image byte
    IOIMAGE_RWOX = 0xF031  # Output image bit

    # Device info
    DEVICE_DATA = 0xF100  # Device data


@dataclass
class Symbol:
    """PLC Symbol definition"""

    name: str
    type_name: str
    size: int
    value: Any
    index_group: int = 0
    index_offset: int = 0
    flags: int = 0x0008  # PLCF_SYMBOL (readable/writable)
    array_dim: int = 0
    comment: str = ""

    def get_bytes(self) -> bytes:
        """Get symbol value as bytes"""
        if self.type_name == "BOOL":
            return struct.pack("<B", 1 if self.value else 0)
        elif self.type_name == "BYTE":
            return struct.pack("<B", self.value & 0xFF)
        elif self.type_name == "INT":
            return struct.pack("<h", self.value)
        elif self.type_name == "UINT":
            return struct.pack("<H", self.value)
        elif self.type_name == "DINT":
            return struct.pack("<i", self.value)
        elif self.type_name == "UDINT":
            return struct.pack("<I", self.value)
        elif self.type_name == "REAL":
            return struct.pack("<f", self.value)
        elif self.type_name == "LREAL":
            return struct.pack("<d", self.value)
        elif self.type_name.startswith("STRING"):
            encoded = str(self.value).encode("utf-8")[: self.size - 1]
            return encoded + b"\x00" * (self.size - len(encoded))
        elif self.type_name.startswith("ARRAY"):
            # Handle arrays
            data = b""
            for v in self.value:
                if isinstance(v, bool):
                    data += struct.pack("<B", 1 if v else 0)
                elif isinstance(v, int):
                    data += struct.pack("<h", v)
                elif isinstance(v, float):
                    data += struct.pack("<f", v)
            return data
        else:
            return b"\x00" * self.size

    def set_from_bytes(self, data: bytes):
        """Set symbol value from bytes"""
        if len(data) < self.size:
            return

        if self.type_name == "BOOL":
            self.value = data[0] != 0
        elif self.type_name == "BYTE":
            self.value = data[0]
        elif self.type_name == "INT":
            self.value = struct.unpack("<h", data[:2])[0]
        elif self.type_name == "UINT":
            self.value = struct.unpack("<H", data[:2])[0]
        elif self.type_name == "DINT":
            self.value = struct.unpack("<i", data[:4])[0]
        elif self.type_name == "UDINT":
            self.value = struct.unpack("<I", data[:4])[0]
        elif self.type_name == "REAL":
            self.value = struct.unpack("<f", data[:4])[0]
        elif self.type_name == "LREAL":
            self.value = struct.unpack("<d", data[:8])[0]
        elif self.type_name.startswith("STRING"):
            null_idx = data.find(b"\x00")
            if null_idx >= 0:
                self.value = data[:null_idx].decode("utf-8", errors="replace")
            else:
                self.value = data.decode("utf-8", errors="replace")


@dataclass
class AMSRoute:
    """AMS Route entry"""

    name: str
    netid: bytes
    address: str
    transport: int = 1  # TCP
    flags: int = 0


@dataclass
class PortContext:
    """Context for each ADS port"""

    port_num: int
    port_name: str
    state: ADSState = ADSState.RUN
    device_name: str = "Mock TwinCAT PLC"
    version: Tuple[int, int, int] = (3, 1, 4024)
    symbols: Dict[str, Symbol] = field(default_factory=dict)
    handles: Dict[int, str] = field(default_factory=dict)  # handle -> symbol name
    next_handle: int = 1


class AMSHeader:
    """AMS (Automation Message Specification) header"""

    SIZE = 32

    def __init__(self):
        self.target_netid = b"\x00" * 6
        self.target_port = 0
        self.source_netid = b"\x00" * 6
        self.source_port = 0
        self.command_id = 0
        self.state_flags = 0x0004  # ADS command
        self.data_length = 0
        self.error_code = 0
        self.invoke_id = 0

    def pack(self) -> bytes:
        return struct.pack(
            "<6sH6sHHHIII",
            self.target_netid,
            self.target_port,
            self.source_netid,
            self.source_port,
            self.command_id,
            self.state_flags,
            self.data_length,
            self.error_code,
            self.invoke_id,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "AMSHeader":
        header = cls()
        (
            header.target_netid,
            header.target_port,
            header.source_netid,
            header.source_port,
            header.command_id,
            header.state_flags,
            header.data_length,
            header.error_code,
            header.invoke_id,
        ) = struct.unpack("<6sH6sHHHIII", data[:32])
        return header

    def create_response(self) -> "AMSHeader":
        """Create response header from request"""
        resp = AMSHeader()
        resp.target_netid = self.source_netid
        resp.target_port = self.source_port
        resp.source_netid = self.target_netid
        resp.source_port = self.target_port
        resp.command_id = self.command_id
        resp.state_flags = 0x0005  # ADS response
        resp.invoke_id = self.invoke_id
        return resp


class MockADSServer:
    """Enhanced Mock ADS server with full feature support"""

    # Port definitions
    PORTS = {
        851: ("TC3PLC1", "TwinCAT 3 PLC Runtime 1"),
        852: ("TC3PLC2", "TwinCAT 3 PLC Runtime 2"),
        853: ("TC3PLC3", "TwinCAT 3 PLC Runtime 3"),
        854: ("TC3PLC4", "TwinCAT 3 PLC Runtime 4"),
        801: ("SPS1", "TwinCAT 2 PLC Runtime 1"),
        811: ("SPS2", "TwinCAT 2 PLC Runtime 2"),
        500: ("NC", "NC/PTP NCI"),
        501: ("NCSAF", "NC/PTP SAF"),
        100: ("CNC", "CNC"),
        900: ("CUSTOMER1", "Customer Port 1"),
        901: ("CUSTOMER2", "Customer Port 2"),
    }

    def __init__(self, host="0.0.0.0", port=48898):
        self.host = host
        self.port = port
        self.netid = b"\x7f\x00\x00\x01\x01\x01"  # 127.0.0.1.1.1

        # Memory areas (shared across ports)
        self.memory_byte = bytearray(1024)  # M-Area bytes
        self.memory_bit = bytearray(128)  # M-Area bits (1024 bits)
        self.data_area = bytearray(4096)  # Data area
        self.input_image = bytearray(256)  # Input image
        self.output_image = bytearray(256)  # Output image
        self.retain_data = bytearray(1024)  # Retain data

        # Port contexts
        self.ports: Dict[int, PortContext] = {}
        self._init_ports()

        # AMS routes
        self.routes: List[AMSRoute] = self._create_routes()

        # Simulation state
        self.start_time = time.time()

    def _init_ports(self):
        """Initialize all supported ports with symbols"""
        for port_num, (port_name, desc) in self.PORTS.items():
            ctx = PortContext(
                port_num=port_num,
                port_name=port_name,
                device_name=f"Mock {desc}",
                symbols=self._create_symbols(port_num, port_name),
            )
            self.ports[port_num] = ctx

        # Initialize memory with test patterns
        for i in range(0, 256, 4):
            struct.pack_into("<I", self.memory_byte, i, i * 100)
        for i in range(64):
            self.input_image[i] = i
            self.output_image[i] = 255 - i

    def _create_symbols(self, port_num: int, port_name: str) -> Dict[str, Symbol]:
        """Create realistic symbols for a port"""
        symbols = {}
        offset = 0

        def add_symbol(name, type_name, size, value, comment=""):
            nonlocal offset
            sym = Symbol(
                name=name,
                type_name=type_name,
                size=size,
                value=value,
                index_group=IndexGroup.DATA,
                index_offset=offset,
                comment=comment,
            )
            symbols[name] = sym
            offset += size

        # System variables
        add_symbol("MAIN.bSystemReady", "BOOL", 1, True, "System ready status")
        add_symbol("MAIN.bStart", "BOOL", 1, False, "Start command")
        add_symbol("MAIN.bStop", "BOOL", 1, False, "Stop command")
        add_symbol("MAIN.bReset", "BOOL", 1, False, "Reset command")
        add_symbol("MAIN.bEmergencyStop", "BOOL", 1, False, "Emergency stop active")
        add_symbol("MAIN.bAutoMode", "BOOL", 1, True, "Automatic mode")
        add_symbol("MAIN.bManualMode", "BOOL", 1, False, "Manual mode")

        # Numeric process values
        add_symbol("MAIN.nCycleCounter", "UDINT", 4, 0, "PLC cycle counter")
        add_symbol("MAIN.nErrorCode", "UINT", 2, 0, "Current error code")
        add_symbol("MAIN.nOperationMode", "INT", 2, 1, "Operation mode (1=Auto, 2=Manual)")
        add_symbol("MAIN.nSpeed", "INT", 2, 1500, "Process speed")
        add_symbol("MAIN.nPosition", "DINT", 4, 0, "Current position")
        add_symbol("MAIN.nSetpoint", "DINT", 4, 10000, "Position setpoint")

        # Analog values
        add_symbol("MAIN.rTemperature", "REAL", 4, 25.5, "Process temperature")
        add_symbol("MAIN.rPressure", "REAL", 4, 1013.25, "Process pressure")
        add_symbol("MAIN.rFlow", "REAL", 4, 15.7, "Flow rate")
        add_symbol("MAIN.rLevel", "REAL", 4, 75.0, "Tank level %")
        add_symbol("MAIN.rVoltage", "REAL", 4, 24.0, "Supply voltage")
        add_symbol("MAIN.rCurrent", "REAL", 4, 2.5, "Current consumption")

        # Setpoints
        add_symbol("MAIN.rTempSetpoint", "REAL", 4, 25.0, "Temperature setpoint")
        add_symbol("MAIN.rPressureSetpoint", "REAL", 4, 1000.0, "Pressure setpoint")
        add_symbol("MAIN.rFlowSetpoint", "REAL", 4, 15.0, "Flow setpoint")

        # Motor control structure
        add_symbol("MAIN.Motor1.bEnable", "BOOL", 1, True, "Motor 1 enable")
        add_symbol("MAIN.Motor1.bFwd", "BOOL", 1, True, "Motor 1 forward")
        add_symbol("MAIN.Motor1.bRev", "BOOL", 1, False, "Motor 1 reverse")
        add_symbol("MAIN.Motor1.bFault", "BOOL", 1, False, "Motor 1 fault")
        add_symbol("MAIN.Motor1.bRunning", "BOOL", 1, True, "Motor 1 running")
        add_symbol("MAIN.Motor1.nSpeed", "INT", 2, 1450, "Motor 1 speed RPM")
        add_symbol("MAIN.Motor1.nSpeedSetpoint", "INT", 2, 1500, "Motor 1 speed setpoint")
        add_symbol("MAIN.Motor1.rCurrent", "REAL", 4, 12.5, "Motor 1 current A")
        add_symbol("MAIN.Motor1.rTorque", "REAL", 4, 45.2, "Motor 1 torque %")

        # Second motor
        add_symbol("MAIN.Motor2.bEnable", "BOOL", 1, False, "Motor 2 enable")
        add_symbol("MAIN.Motor2.bFwd", "BOOL", 1, False, "Motor 2 forward")
        add_symbol("MAIN.Motor2.bFault", "BOOL", 1, False, "Motor 2 fault")
        add_symbol("MAIN.Motor2.bRunning", "BOOL", 1, False, "Motor 2 running")
        add_symbol("MAIN.Motor2.nSpeed", "INT", 2, 0, "Motor 2 speed RPM")
        add_symbol("MAIN.Motor2.rCurrent", "REAL", 4, 0.0, "Motor 2 current A")

        # Pump control
        add_symbol("MAIN.Pump1.bStart", "BOOL", 1, True, "Pump 1 start")
        add_symbol("MAIN.Pump1.bRunning", "BOOL", 1, True, "Pump 1 running")
        add_symbol("MAIN.Pump1.bFault", "BOOL", 1, False, "Pump 1 fault")
        add_symbol("MAIN.Pump1.rSpeed", "REAL", 4, 85.0, "Pump 1 speed %")
        add_symbol("MAIN.Pump1.rFlow", "REAL", 4, 12.3, "Pump 1 flow")
        add_symbol("MAIN.Pump1.rPressure", "REAL", 4, 4.5, "Pump 1 pressure bar")

        # Valve control
        add_symbol("MAIN.Valve1.bOpen", "BOOL", 1, True, "Valve 1 open cmd")
        add_symbol("MAIN.Valve1.bClosed", "BOOL", 1, False, "Valve 1 closed status")
        add_symbol("MAIN.Valve1.bOpened", "BOOL", 1, True, "Valve 1 opened status")
        add_symbol("MAIN.Valve1.nPosition", "INT", 2, 100, "Valve 1 position %")
        add_symbol("MAIN.Valve1.rFlow", "REAL", 4, 15.7, "Valve 1 flow")

        add_symbol("MAIN.Valve2.bOpen", "BOOL", 1, False, "Valve 2 open cmd")
        add_symbol("MAIN.Valve2.bClosed", "BOOL", 1, True, "Valve 2 closed status")
        add_symbol("MAIN.Valve2.nPosition", "INT", 2, 0, "Valve 2 position %")

        # Alarms
        add_symbol("MAIN.Alarms.bTempHigh", "BOOL", 1, False, "High temperature alarm")
        add_symbol("MAIN.Alarms.bTempLow", "BOOL", 1, False, "Low temperature alarm")
        add_symbol("MAIN.Alarms.bPressureHigh", "BOOL", 1, False, "High pressure alarm")
        add_symbol("MAIN.Alarms.bPressureLow", "BOOL", 1, False, "Low pressure alarm")
        add_symbol("MAIN.Alarms.bLevelHigh", "BOOL", 1, False, "High level alarm")
        add_symbol("MAIN.Alarms.bLevelLow", "BOOL", 1, False, "Low level alarm")
        add_symbol("MAIN.Alarms.bMotorFault", "BOOL", 1, False, "Motor fault alarm")
        add_symbol("MAIN.Alarms.bSystemFault", "BOOL", 1, False, "System fault")
        add_symbol("MAIN.Alarms.nActiveAlarms", "INT", 2, 0, "Number of active alarms")

        # Arrays
        add_symbol("MAIN.aInputs", "ARRAY[0..15] OF BOOL", 16, [True, False] * 8, "Digital inputs")
        add_symbol("MAIN.aOutputs", "ARRAY[0..15] OF BOOL", 16, [False] * 16, "Digital outputs")
        add_symbol("MAIN.aAnalogIn", "ARRAY[0..7] OF REAL", 32, [0.0] * 8, "Analog inputs")
        add_symbol("MAIN.aAnalogOut", "ARRAY[0..3] OF REAL", 16, [0.0] * 4, "Analog outputs")
        add_symbol("MAIN.aCounters", "ARRAY[0..3] OF UDINT", 16, [0, 0, 0, 0], "Counters")

        # Strings
        add_symbol("MAIN.sDeviceName", "STRING(80)", 81, f"Mock {port_name} Device", "Device name")
        add_symbol("MAIN.sStatus", "STRING(40)", 41, "Running", "Status text")
        add_symbol("MAIN.sOperator", "STRING(30)", 31, "Operator", "Operator name")
        add_symbol("MAIN.sRecipe", "STRING(50)", 51, "Default Recipe", "Active recipe")
        add_symbol("MAIN.sLastError", "STRING(100)", 101, "", "Last error message")

        # PID controller
        add_symbol("MAIN.PID1.rSetpoint", "REAL", 4, 25.0, "PID setpoint")
        add_symbol("MAIN.PID1.rProcessValue", "REAL", 4, 25.5, "PID process value")
        add_symbol("MAIN.PID1.rOutput", "REAL", 4, 50.0, "PID output %")
        add_symbol("MAIN.PID1.rKp", "REAL", 4, 1.0, "PID proportional gain")
        add_symbol("MAIN.PID1.rKi", "REAL", 4, 0.1, "PID integral gain")
        add_symbol("MAIN.PID1.rKd", "REAL", 4, 0.01, "PID derivative gain")
        add_symbol("MAIN.PID1.bEnable", "BOOL", 1, True, "PID enable")
        add_symbol("MAIN.PID1.bManual", "BOOL", 1, False, "PID manual mode")

        # Time/date
        add_symbol("MAIN.tCycleTime", "UDINT", 4, 10000, "Cycle time us")
        add_symbol("MAIN.tLastCycle", "UDINT", 4, 8500, "Last cycle time us")
        add_symbol("MAIN.dtStartTime", "UDINT", 4, int(time.time()), "Start timestamp")
        add_symbol("MAIN.nUptime", "UDINT", 4, 0, "Uptime seconds")

        # Port-specific symbols
        if port_name.startswith("TC3PLC"):
            add_symbol("_TaskInfo[1].CycleTime", "UDINT", 4, 10000, "Task cycle time")
            add_symbol("_TaskInfo[1].CycleCount", "UDINT", 4, 0, "Task cycle count")
            add_symbol("_TaskInfo[1].LastExecTime", "UDINT", 4, 8500, "Last exec time")

        if port_name == "NC":
            add_symbol("NC.bReady", "BOOL", 1, True, "NC ready")
            add_symbol("NC.bMoving", "BOOL", 1, False, "NC axis moving")
            add_symbol("NC.rActPos", "LREAL", 8, 0.0, "NC actual position")
            add_symbol("NC.rSetPos", "LREAL", 8, 0.0, "NC set position")
            add_symbol("NC.rVelocity", "REAL", 4, 0.0, "NC velocity")

        return symbols

    def _create_routes(self) -> List[AMSRoute]:
        """Create AMS route table"""
        return [
            AMSRoute("Local", self.netid, "127.0.0.1"),
            AMSRoute("PLC1", b"\xc0\xa8\x01\x0a\x01\x01", "192.168.1.10"),
            AMSRoute("PLC2", b"\xc0\xa8\x01\x14\x01\x01", "192.168.1.20"),
            AMSRoute("Engineering", b"\xc0\xa8\x01\x64\x01\x01", "192.168.1.100"),
        ]

    def _simulate_values(self, ctx: PortContext):
        """Simulate realistic PLC value changes"""
        current_time = time.time()
        elapsed = current_time - self.start_time
        symbols = ctx.symbols

        # Cycle counter
        if "MAIN.nCycleCounter" in symbols:
            symbols["MAIN.nCycleCounter"].value = int(elapsed * 100)  # 100 cycles/sec

        if "MAIN.nUptime" in symbols:
            symbols["MAIN.nUptime"].value = int(elapsed)

        # Temperature simulation (sinusoidal with noise)
        if "MAIN.rTemperature" in symbols:
            base_temp = 25.0
            temp_variation = 3.0 * math.sin(elapsed * 0.05) + random.uniform(-0.5, 0.5)
            symbols["MAIN.rTemperature"].value = round(base_temp + temp_variation, 2)

            # Temperature alarms
            temp = symbols["MAIN.rTemperature"].value
            if "MAIN.Alarms.bTempHigh" in symbols:
                symbols["MAIN.Alarms.bTempHigh"].value = temp > 28.0
            if "MAIN.Alarms.bTempLow" in symbols:
                symbols["MAIN.Alarms.bTempLow"].value = temp < 20.0

        # Pressure simulation
        if "MAIN.rPressure" in symbols:
            base_pressure = 1013.25
            pressure_variation = 50 * math.cos(elapsed * 0.08) + random.uniform(-10, 10)
            symbols["MAIN.rPressure"].value = round(base_pressure + pressure_variation, 2)

            pressure = symbols["MAIN.rPressure"].value
            if "MAIN.Alarms.bPressureLow" in symbols:
                symbols["MAIN.Alarms.bPressureLow"].value = pressure < 960.0
            if "MAIN.Alarms.bPressureHigh" in symbols:
                symbols["MAIN.Alarms.bPressureHigh"].value = pressure > 1060.0

        # Flow rate
        if "MAIN.rFlow" in symbols:
            base_flow = 15.0
            flow_variation = 3.0 * math.sin(elapsed * 0.12) + random.uniform(-0.3, 0.3)
            symbols["MAIN.rFlow"].value = round(max(0, base_flow + flow_variation), 2)

        # Motor speed varies slightly when running
        if "MAIN.Motor1.bRunning" in symbols and symbols["MAIN.Motor1.bRunning"].value:
            if "MAIN.Motor1.nSpeed" in symbols:
                base_speed = symbols.get(
                    "MAIN.Motor1.nSpeedSetpoint", Symbol("", "", 2, 1500)
                ).value
                speed_variation = int(30 * math.sin(elapsed * 0.1) + random.uniform(-5, 5))
                symbols["MAIN.Motor1.nSpeed"].value = max(0, base_speed + speed_variation)

            if "MAIN.Motor1.rCurrent" in symbols:
                speed_ratio = symbols["MAIN.Motor1.nSpeed"].value / 1500.0
                symbols["MAIN.Motor1.rCurrent"].value = round(
                    12.5 * speed_ratio + random.uniform(-0.5, 0.5), 2
                )

        # Level changes slowly
        if "MAIN.rLevel" in symbols:
            flow_in = symbols.get("MAIN.rFlow", Symbol("", "", 4, 15.0)).value
            base_change = (flow_in - 15.0) * 0.01
            current_level = symbols["MAIN.rLevel"].value
            new_level = max(0, min(100, current_level + base_change + random.uniform(-0.1, 0.1)))
            symbols["MAIN.rLevel"].value = round(new_level, 1)

            if "MAIN.Alarms.bLevelHigh" in symbols:
                symbols["MAIN.Alarms.bLevelHigh"].value = new_level > 90.0
            if "MAIN.Alarms.bLevelLow" in symbols:
                symbols["MAIN.Alarms.bLevelLow"].value = new_level < 10.0

        # Count active alarms
        if "MAIN.Alarms.nActiveAlarms" in symbols:
            alarm_count = sum(
                1 for k, v in symbols.items() if k.startswith("MAIN.Alarms.b") and v.value
            )
            symbols["MAIN.Alarms.nActiveAlarms"].value = alarm_count

            if "MAIN.Alarms.bSystemFault" in symbols:
                symbols["MAIN.Alarms.bSystemFault"].value = alarm_count >= 3

        # Update position (simulate motion)
        if "MAIN.nPosition" in symbols:
            setpoint = symbols.get("MAIN.nSetpoint", Symbol("", "", 4, 10000)).value
            current = symbols["MAIN.nPosition"].value
            if current != setpoint:
                step = min(100, abs(setpoint - current))
                if current < setpoint:
                    symbols["MAIN.nPosition"].value = current + step
                else:
                    symbols["MAIN.nPosition"].value = current - step

        # Random input changes (5% chance)
        if "MAIN.aInputs" in symbols:
            inputs = symbols["MAIN.aInputs"].value
            for i in range(len(inputs)):
                if random.random() < 0.02:
                    inputs[i] = not inputs[i]

        # Cycle time variation
        if "_TaskInfo[1].CycleTime" in symbols:
            symbols["_TaskInfo[1].CycleTime"].value = 10000 + random.randint(-200, 200)
        if "_TaskInfo[1].LastExecTime" in symbols:
            symbols["_TaskInfo[1].LastExecTime"].value = int(
                symbols.get("_TaskInfo[1].CycleTime", Symbol("", "", 4, 10000)).value * 0.85
            )
        if "_TaskInfo[1].CycleCount" in symbols:
            symbols["_TaskInfo[1].CycleCount"].value = int(elapsed * 100)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle ADS client connection"""
        client_addr = writer.get_extra_info("peername")
        log.info(f"ADS client connected from {client_addr}")

        try:
            while True:
                # Read AMS/TCP header (6 bytes: reserved + length)
                tcp_header = await reader.read(6)
                if not tcp_header or len(tcp_header) < 6:
                    break

                reserved, length = struct.unpack("<HI", tcp_header)

                if length > 65536:  # Sanity check
                    log.warning(f"Invalid message length: {length}")
                    break

                # Read AMS header + data
                ams_data = await reader.read(length)
                if len(ams_data) < AMSHeader.SIZE:
                    break

                # Parse AMS header
                ams_header = AMSHeader.unpack(ams_data)
                ads_data = ams_data[AMSHeader.SIZE :] if len(ams_data) > AMSHeader.SIZE else b""

                # Get port context
                port_ctx = self.ports.get(ams_header.target_port)
                if port_ctx:
                    self._simulate_values(port_ctx)

                # Process request
                response = await self._process_request(ams_header, ads_data, port_ctx)

                if response:
                    tcp_response = struct.pack("<HI", 0, len(response))
                    writer.write(tcp_response + response)
                    await writer.drain()

        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.error(f"Error handling client {client_addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            log.info(f"ADS client {client_addr} disconnected")

    async def _process_request(
        self, header: AMSHeader, data: bytes, ctx: Optional[PortContext]
    ) -> bytes:
        """Process ADS request and generate response"""
        response_header = header.create_response()
        response_data = b""

        # Check if port exists
        if ctx is None:
            response_header.error_code = ADSError.TARGETPORTNOTFOUND
            response_header.data_length = 0
            return response_header.pack()

        cmd = header.command_id

        try:
            if cmd == ADSCommand.READDEVICEINFO:
                response_data = self._handle_read_device_info(ctx)

            elif cmd == ADSCommand.READSTATE:
                response_data = self._handle_read_state(ctx)

            elif cmd == ADSCommand.WRITECTRL:
                response_data = self._handle_write_control(ctx, data)

            elif cmd == ADSCommand.READ:
                response_data = self._handle_read(ctx, data)

            elif cmd == ADSCommand.WRITE:
                response_data = self._handle_write(ctx, data)

            elif cmd == ADSCommand.READWRITE:
                response_data = self._handle_read_write(ctx, data)

            else:
                log.warning(f"Unhandled ADS command: {cmd}")
                response_header.error_code = ADSError.UNKNOWNCMDID

        except Exception as e:
            log.error(f"Error processing command {cmd}: {e}")
            response_header.error_code = ADSError.INTERNAL

        response_header.data_length = len(response_data)
        return response_header.pack() + response_data

    def _handle_read_device_info(self, ctx: PortContext) -> bytes:
        """Handle ReadDeviceInfo request"""
        major, minor, build = ctx.version
        name = ctx.device_name.encode("utf-8")[:15].ljust(16, b"\x00")

        # Response: result(4) + major(1) + minor(1) + build(2) + name(16)
        return struct.pack("<IBBH16s", 0, major, minor, build, name)

    def _handle_read_state(self, ctx: PortContext) -> bytes:
        """Handle ReadState request"""
        # Response: result(4) + ads_state(2) + device_state(2)
        return struct.pack("<IHH", 0, ctx.state, ctx.state)

    def _handle_write_control(self, ctx: PortContext, data: bytes) -> bytes:
        """Handle WriteControl request (state change)"""
        if len(data) < 8:
            return struct.pack("<I", ADSError.INVALIDSIZE)

        ads_state, device_state, length = struct.unpack("<HHI", data[:8])

        log.info(f"State change request: {ads_state} (port {ctx.port_num})")

        # Validate state
        try:
            new_state = ADSState(ads_state)
            ctx.state = new_state
            log.info(f"State changed to {new_state.name}")
            return struct.pack("<I", 0)  # Success
        except ValueError:
            return struct.pack("<I", ADSError.INTERNAL)

    def _handle_read(self, ctx: PortContext, data: bytes) -> bytes:
        """Handle Read request"""
        if len(data) < 12:
            return struct.pack("<I", ADSError.INVALIDSIZE)

        index_group, index_offset, length = struct.unpack("<III", data[:12])

        log.debug(f"Read: group=0x{index_group:x} offset=0x{index_offset:x} len={length}")

        read_data = self._read_data(ctx, index_group, index_offset, length)

        if read_data is None:
            return struct.pack("<II", ADSError.INVALIDINDEXGROUP, 0)

        # Response: result(4) + length(4) + data
        return struct.pack("<II", 0, len(read_data)) + read_data

    def _handle_write(self, ctx: PortContext, data: bytes) -> bytes:
        """Handle Write request"""
        if len(data) < 12:
            return struct.pack("<I", ADSError.INVALIDSIZE)

        index_group, index_offset, length = struct.unpack("<III", data[:12])
        write_data = data[12 : 12 + length]

        log.debug(f"Write: group=0x{index_group:x} offset=0x{index_offset:x} len={length}")

        success = self._write_data(ctx, index_group, index_offset, write_data)

        return struct.pack("<I", 0 if success else ADSError.ACCESSDENIED)

    def _handle_read_write(self, ctx: PortContext, data: bytes) -> bytes:
        """Handle ReadWrite request (used for symbol operations)"""
        if len(data) < 16:
            return struct.pack("<I", ADSError.INVALIDSIZE)

        index_group, index_offset, read_len, write_len = struct.unpack("<IIII", data[:16])
        write_data = data[16 : 16 + write_len]

        log.debug(
            f"ReadWrite: group=0x{index_group:x} offset=0x{index_offset:x} read={read_len} write={write_len}"
        )

        # Handle symbol operations
        if index_group == IndexGroup.SYM_HNDBYNAME:
            return self._get_handle_by_name(ctx, write_data, read_len)

        elif index_group == IndexGroup.SYM_VALBYHND:
            return self._read_value_by_handle(ctx, index_offset, read_len)

        elif index_group == IndexGroup.SYM_VALBYNAME:
            return self._read_value_by_name(ctx, write_data, read_len)

        elif index_group == IndexGroup.SYM_INFOBYNAMEEX:
            return self._get_symbol_info(ctx, write_data, read_len)

        elif index_group == IndexGroup.SYM_UPLOADINFO2:
            return self._get_upload_info(ctx, read_len)

        elif index_group == IndexGroup.SYM_UPLOAD:
            return self._upload_symbols(ctx, read_len)

        # Default read/write
        read_data = self._read_data(ctx, index_group, index_offset, read_len)
        if read_data is None:
            return struct.pack("<II", ADSError.INVALIDINDEXGROUP, 0)

        return struct.pack("<II", 0, len(read_data)) + read_data

    def _read_data(self, ctx: PortContext, group: int, offset: int, length: int) -> Optional[bytes]:
        """Read data from appropriate memory area"""
        if group == IndexGroup.MEMORYBYTE:
            end = min(offset + length, len(self.memory_byte))
            return bytes(self.memory_byte[offset:end]).ljust(length, b"\x00")

        elif group == IndexGroup.MEMORYBIT:
            byte_offset = offset // 8
            bit_offset = offset % 8
            value = (self.memory_byte[byte_offset] >> bit_offset) & 1
            return struct.pack("<B", value)

        elif group == IndexGroup.DATA:
            # Look up symbol by offset
            for sym in ctx.symbols.values():
                if sym.index_offset == offset:
                    return sym.get_bytes()[:length]
            # Fallback to data area
            end = min(offset + length, len(self.data_area))
            return bytes(self.data_area[offset:end]).ljust(length, b"\x00")

        elif group == IndexGroup.IOIMAGE_RWIB:
            end = min(offset + length, len(self.input_image))
            return bytes(self.input_image[offset:end]).ljust(length, b"\x00")

        elif group == IndexGroup.IOIMAGE_RWOB:
            end = min(offset + length, len(self.output_image))
            return bytes(self.output_image[offset:end]).ljust(length, b"\x00")

        elif group == IndexGroup.RETAIN:
            end = min(offset + length, len(self.retain_data))
            return bytes(self.retain_data[offset:end]).ljust(length, b"\x00")

        return b"\x00" * length

    def _write_data(self, ctx: PortContext, group: int, offset: int, data: bytes) -> bool:
        """Write data to appropriate memory area"""
        if group == IndexGroup.MEMORYBYTE:
            for i, b in enumerate(data):
                if offset + i < len(self.memory_byte):
                    self.memory_byte[offset + i] = b
            return True

        elif group == IndexGroup.DATA:
            # Look up symbol by offset
            for sym in ctx.symbols.values():
                if sym.index_offset == offset:
                    sym.set_from_bytes(data)
                    return True
            # Fallback to data area
            for i, b in enumerate(data):
                if offset + i < len(self.data_area):
                    self.data_area[offset + i] = b
            return True

        elif group == IndexGroup.IOIMAGE_RWOB:
            for i, b in enumerate(data):
                if offset + i < len(self.output_image):
                    self.output_image[offset + i] = b
            return True

        elif group == IndexGroup.RETAIN:
            for i, b in enumerate(data):
                if offset + i < len(self.retain_data):
                    self.retain_data[offset + i] = b
            return True

        return False

    def _get_handle_by_name(self, ctx: PortContext, name_data: bytes, read_len: int) -> bytes:
        """Get symbol handle by name"""
        try:
            name = name_data.rstrip(b"\x00").decode("utf-8")

            if name in ctx.symbols:
                handle = ctx.next_handle
                ctx.handles[handle] = name
                ctx.next_handle += 1

                log.debug(f"Created handle {handle} for symbol '{name}'")
                return struct.pack("<III", 0, 4, handle)
            else:
                log.debug(f"Symbol not found: '{name}'")
                return struct.pack("<II", ADSError.SYMBOLNOTFOUND, 0)

        except Exception as e:
            log.error(f"Error getting handle: {e}")
            return struct.pack("<II", ADSError.INTERNAL, 0)

    def _read_value_by_handle(self, ctx: PortContext, handle: int, read_len: int) -> bytes:
        """Read symbol value by handle"""
        name = ctx.handles.get(handle)
        if not name:
            return struct.pack("<II", ADSError.SYMBOLNOTFOUND, 0)

        sym = ctx.symbols.get(name)
        if not sym:
            return struct.pack("<II", ADSError.SYMBOLNOTFOUND, 0)

        data = sym.get_bytes()[:read_len]
        return struct.pack("<II", 0, len(data)) + data

    def _read_value_by_name(self, ctx: PortContext, name_data: bytes, read_len: int) -> bytes:
        """Read symbol value by name"""
        try:
            name = name_data.rstrip(b"\x00").decode("utf-8")

            sym = ctx.symbols.get(name)
            if not sym:
                return struct.pack("<II", ADSError.SYMBOLNOTFOUND, 0)

            data = sym.get_bytes()[:read_len]
            return struct.pack("<II", 0, len(data)) + data

        except Exception:
            return struct.pack("<II", ADSError.INTERNAL, 0)

    def _get_symbol_info(self, ctx: PortContext, name_data: bytes, read_len: int) -> bytes:
        """Get extended symbol information"""
        try:
            name = name_data.rstrip(b"\x00").decode("utf-8")

            sym = ctx.symbols.get(name)
            if not sym:
                return struct.pack("<II", ADSError.SYMBOLNOTFOUND, 0)

            # Build symbol info structure
            name_bytes = name.encode("utf-8")
            type_bytes = sym.type_name.encode("utf-8")
            comment_bytes = sym.comment.encode("utf-8")

            # Info structure (simplified)
            info = struct.pack(
                "<IIIIHHHH",
                sym.index_group,  # Index group
                sym.index_offset,  # Index offset
                sym.size,  # Size
                sym.flags,  # Flags
                len(name_bytes) + 1,  # Name length
                len(type_bytes) + 1,  # Type length
                len(comment_bytes) + 1,  # Comment length
                0,  # Reserved
            )
            info += name_bytes + b"\x00"
            info += type_bytes + b"\x00"
            info += comment_bytes + b"\x00"

            return struct.pack("<II", 0, len(info)) + info

        except Exception:
            return struct.pack("<II", ADSError.INTERNAL, 0)

    def _get_upload_info(self, ctx: PortContext, read_len: int) -> bytes:
        """Get symbol upload info (count and total size)"""
        symbol_count = len(ctx.symbols)

        # Calculate total symbol data size
        total_size = 0
        for sym in ctx.symbols.values():
            name_len = len(sym.name.encode("utf-8")) + 1
            type_len = len(sym.type_name.encode("utf-8")) + 1
            comment_len = len(sym.comment.encode("utf-8")) + 1
            total_size += 30 + name_len + type_len + comment_len  # Entry header + strings

        # Response: result(4) + length(4) + nSymbols(4) + nSymSize(4)
        data = struct.pack("<II", symbol_count, total_size)
        return struct.pack("<II", 0, len(data)) + data

    def _upload_symbols(self, ctx: PortContext, read_len: int) -> bytes:
        """Upload complete symbol table"""
        data = b""

        for sym in ctx.symbols.values():
            name_bytes = sym.name.encode("utf-8")
            type_bytes = sym.type_name.encode("utf-8")
            comment_bytes = sym.comment.encode("utf-8")

            # Symbol entry structure (pyads compatible)
            entry = struct.pack(
                "<IIIIHHHHHH",
                sym.index_group,  # Index group
                sym.index_offset,  # Index offset
                sym.size,  # Size
                0,  # Data type
                sym.flags,  # Flags
                0,  # Reserved 1
                len(name_bytes) + 1,  # Name length
                len(type_bytes) + 1,  # Type length
                len(comment_bytes) + 1,  # Comment length
                0,  # Reserved 2
            )
            entry += name_bytes + b"\x00"
            entry += type_bytes + b"\x00"
            entry += comment_bytes + b"\x00"

            # Pad to 4-byte alignment
            while len(entry) % 4 != 0:
                entry += b"\x00"

            data += entry

        return struct.pack("<II", 0, len(data)) + data

    async def start_server(self):
        """Start the ADS server"""
        server = await asyncio.start_server(self.handle_client, self.host, self.port)

        log.info("=" * 60)
        log.info(f"Enhanced Mock ADS Server started on {self.host}:{self.port}")
        log.info(f"AMS Net ID: {'.'.join(str(b) for b in self.netid)}")
        log.info("=" * 60)
        log.info("Available ports:")
        for port_num, (port_name, desc) in self.PORTS.items():
            ctx = self.ports.get(port_num)
            sym_count = len(ctx.symbols) if ctx else 0
            log.info(f"  {port_num}: {port_name} ({desc}) - {sym_count} symbols")
        log.info("Memory areas: M-Area(1KB), Data(4KB), I/O(256B each), Retain(1KB)")
        log.info(f"AMS Routes: {len(self.routes)} entries")
        log.info("=" * 60)

        async with server:
            await server.serve_forever()


async def main():
    """Start the mock ADS server"""
    import argparse

    parser = argparse.ArgumentParser(description="Mock ADS Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=48898, help="TCP port")
    args = parser.parse_args()

    server = MockADSServer(args.host, args.port)
    await server.start_server()


if __name__ == "__main__":
    asyncio.run(main())
