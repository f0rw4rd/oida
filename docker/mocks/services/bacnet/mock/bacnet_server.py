#!/usr/bin/env python3
"""
BACnet Mock Server for Testing

Full-featured BACnet device simulator using bacpypes3. Provides ~100 objects
across 15+ types with dynamic simulation, custom service handlers, and
vendor-proprietary extensions.

Services supported:
- Who-Is / I-Am
- ReadProperty / ReadPropertyMultiple
- WriteProperty / WritePropertyMultiple
- COV subscriptions
- ReinitializeDevice (password: "OIDA")
- TimeSynchronization
- AtomicReadFile (stream + record access)
- DeviceCommunicationControl

Usage:
    python bacnet_server.py [--device-id DEVICE_ID] [--port PORT] [--verbose]
"""

import argparse
import asyncio
import logging
import math
import os
import random
import signal
from datetime import datetime, timedelta

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

from bacpypes3.apdu import (
    AtomicReadFileACK,
    AtomicReadFileRequest,
    ReinitializeDeviceRequest,
    SimpleAckPDU,
    TimeSynchronizationRequest,
    UTCTimeSynchronizationRequest,
)
from bacpypes3.basetypes import (
    Action,
    CalendarEntry,
    DailySchedule,
    DateTime,
    DateRange,
    DeviceObjectPropertyReference,
    DeviceObjectReference,
    DeviceStatus,
    FileAccessMethod,
    LifeSafetyMode,
    LifeSafetyOperation,
    LifeSafetyState,
    LoggingType,
    LogRecord,
    LogRecordLogDatum,
    Maintenance,
    NetworkNumberQuality,
    NetworkType,
    NodeType,
    ObjectPropertyReference,
    ProgramError,
    ProgramRequest,
    ProgramState,
    Relationship,
    SetpointReference,
    SilencedState,
    TimeValue,
)
from bacpypes3.errors import ExecutionError
from bacpypes3.ipv4.app import NormalApplication
from bacpypes3.local.analog import (
    AnalogInputObject,
    AnalogOutputObject,
    AnalogValueObject,
    AnalogValueObjectCmd,
)
from bacpypes3.local.binary import (
    BinaryInputObject,
    BinaryOutputObject,
    BinaryValueObjectCmd,
)
from bacpypes3.local.device import DeviceObject
from bacpypes3.local.multistate import MultiStateValueObject
from bacpypes3.local.object import Object as _Object
from bacpypes3.local.schedule import ScheduleObject
from bacpypes3.object import (
    CalendarObject as _CalendarObject,
    FileObject as _FileObject,
    LifeSafetyPointObject as _LifeSafetyPointObject,
    LoopObject as _LoopObject,
    ProgramObject as _ProgramObject,
    StructuredViewObject as _StructuredViewObject,
    TrendLogObject as _TrendLogObject,
)
from bacpypes3.pdu import Address
from bacpypes3.primitivedata import (
    Date,
    OctetString,
    Real,
    Time,
)


# ---------------------------------------------------------------------------
# Local object wrappers for types without bacpypes3.local implementations
# The _post_init override prevents AttributeError on object types that lack
# notificationClass (Calendar, File, StructuredView).
# ---------------------------------------------------------------------------
class _SafePostInitMixin:
    """Override _post_init to tolerate missing notificationClass."""

    async def _post_init(self):
        try:
            nc = self.notificationClass
        except AttributeError:
            return
        if nc is None:
            return
        await super()._post_init()


class LocalLoopObject(_SafePostInitMixin, _Object, _LoopObject):
    pass


class LocalProgramObject(_SafePostInitMixin, _Object, _ProgramObject):
    pass


class LocalCalendarObject(_SafePostInitMixin, _Object, _CalendarObject):
    pass


class LocalTrendLogObject(_SafePostInitMixin, _Object, _TrendLogObject):
    pass


class LocalFileObject(_SafePostInitMixin, _Object, _FileObject):
    pass


class LocalLifeSafetyPointObject(_SafePostInitMixin, _Object, _LifeSafetyPointObject):
    pass


class LocalStructuredViewObject(_SafePostInitMixin, _Object, _StructuredViewObject):
    pass


# ---------------------------------------------------------------------------
# File data for AtomicReadFile testing
# ---------------------------------------------------------------------------
CONFIG_FILE_DATA = (
    b"[system]\n"
    b"device_name = OIDA Test Device\n"
    b"device_id = 1234\n"
    b"vendor_id = 999\n"
    b"location = Test Lab Building A\n"
    b"\n"
    b"[network]\n"
    b"ip_address = 0.0.0.0\n"
    b"subnet_mask = 255.255.255.0\n"
    b"port = 47808\n"
    b"\n"
    b"[bacnet]\n"
    b"apdu_timeout = 6000\n"
    b"apdu_retries = 3\n"
    b"max_apdu_length = 1476\n"
    b"segmentation = both\n"
    b"\n"
    b"[zones]\n"
    b"zone_1_name = Main Office\n"
    b"zone_2_name = Server Room\n"
    b"zone_3_name = Conference Room\n"
    b"zone_4_name = Lobby\n"
    b"zone_5_name = Break Room\n"
    b"\n"
    b"[schedules]\n"
    b"weekday_start = 08:00\n"
    b"weekday_end = 17:00\n"
    b"weekend_mode = off\n"
    b"\n"
    b"[security]\n"
    b"reinit_password = OIDA\n"
    b"write_enabled = true\n"
    b"dcc_password = OIDA\n"
)

FIRMWARE_FILE_DATA = b"\x7fELF" + os.urandom(4092)  # fake ELF binary, 4KB


# ---------------------------------------------------------------------------
# BACnet Mock Server
# ---------------------------------------------------------------------------
class BACnetMockServer:
    """Full-featured BACnet device simulator using bacpypes3."""

    def __init__(
        self,
        device_id: int = 1234,
        device_name: str = "OIDA Test Device",
        port: int = 47808,
        ip: str = "0.0.0.0",
    ):
        self.device_id = device_id
        self.device_name = device_name
        self.port = port
        self.ip = ip
        self.app: NormalApplication | None = None
        self.running = False
        self._sim_task: asyncio.Task | None = None
        self._file_data: dict[str, bytes] = {
            "config.txt": CONFIG_FILE_DATA,
            "firmware.bin": FIRMWARE_FILE_DATA,
        }
        # Track mutable objects for simulation
        self._analog_inputs: list = []
        self._analog_outputs: list = []
        self._binary_inputs: list = []
        self._binary_outputs: list = []
        self._trend_logs: list = []
        self._loops: list = []
        self._setpoint_values: list = []

    async def start(self):
        """Start the BACnet device."""
        try:
            logger.info(f"Starting BACnet device {self.device_id} ({self.device_name})...")

            device = DeviceObject(
                objectIdentifier=("device", self.device_id),
                objectName=self.device_name,
                vendorIdentifier=999,
                vendorName="OIDA Test Vendor",
                modelName="OIDA Mock BACnet Controller",
                firmwareRevision="2.1.0",
                applicationSoftwareVersion="2.0.0",
                description="Full-featured BACnet mock for OIDA scanner testing",
                location="Test Lab Building A",
                protocolVersion=1,
                protocolRevision=22,
                systemStatus=DeviceStatus.operational,
                maxApduLengthAccepted=1476,
                segmentationSupported="segmentedBoth",
                apduTimeout=6000,
                numberOfApduRetries=3,
                databaseRevision=1,
            )

            # Resolve actual IP when 0.0.0.0 is specified - bacpypes3 needs
            # the real interface address so it can compute the broadcast address.
            bind_ip = self.ip
            netmask = 24
            if bind_ip == "0.0.0.0":
                import socket as _sock

                try:
                    s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    bind_ip = s.getsockname()[0]
                    s.close()
                except Exception:
                    # Fallback: resolve hostname
                    bind_ip = _sock.gethostbyname(_sock.gethostname())
                # Detect netmask from the resolved IP range
                if bind_ip.startswith("172."):
                    netmask = 16
                elif bind_ip.startswith("10."):
                    netmask = 8
                logger.info(f"  Resolved bind address: {bind_ip}/{netmask}")

            local_address = Address(f"{bind_ip}/{netmask}:{self.port}")
            self.app = NormalApplication(device, local_address)

            # Install custom service handlers
            self.app.do_ReinitializeDeviceRequest = self._do_reinitialize_device
            self.app.do_TimeSynchronizationRequest = self._do_time_synchronization
            self.app.do_UTCTimeSynchronizationRequest = self._do_utc_time_synchronization
            self.app.do_AtomicReadFileRequest = self._do_atomic_read_file

            # Populate all objects
            self._create_analog_inputs()
            self._create_analog_outputs()
            self._create_analog_values()
            self._create_binary_inputs()
            self._create_binary_outputs()
            self._create_binary_values()
            self._create_multistate_values()
            self._create_loop_objects()
            self._create_program_objects()
            self._create_schedule_and_calendar()
            self._create_trend_logs()
            self._create_file_objects()
            self._create_life_safety_objects()
            self._create_network_port_objects()
            self._create_structured_view()

            self.running = True
            self._sim_task = asyncio.create_task(self._simulate_values())

            obj_count = len(list(self.app.iter_objects()))
            logger.info(f"BACnet device started on {self.ip}:{self.port}")
            logger.info(f"Device ID: {self.device_id}, Objects: {obj_count}")
            return True

        except Exception as e:
            logger.error(f"Failed to start BACnet device: {e}")
            import traceback

            traceback.print_exc()
            return False

    # -------------------------------------------------------------------
    # Object creation helpers
    # -------------------------------------------------------------------
    def _create_analog_inputs(self):
        """5 AnalogInputObjects - temperature sensors with COV."""
        zones = ["Main Office", "Server Room", "Conference Room", "Lobby", "Break Room"]
        for i, zone in enumerate(zones, 1):
            obj = AnalogInputObject(
                objectIdentifier=("analogInput", i),
                objectName=f"Zone {i} Temperature",
                description=f"{zone} temperature sensor",
                presentValue=72.0 + i,
                units="degreesFahrenheit",
                covIncrement=1.0,
                statusFlags=[0, 0, 0, 0],
                eventState="normal",
                outOfService=False,
            )
            self.app.add_object(obj)
            self._analog_inputs.append(obj)
        logger.info("  Created 5 Analog Inputs (temperature sensors w/ COV)")

    def _create_analog_outputs(self):
        """3 AnalogOutputObjects - dampers, commandable with priority arrays."""
        for i in range(1, 4):
            obj = AnalogOutputObject(
                objectIdentifier=("analogOutput", i),
                objectName=f"Damper {i} Position",
                description=f"Zone {i} damper actuator",
                presentValue=50.0,
                units="percent",
                statusFlags=[0, 0, 0, 0],
                eventState="normal",
                outOfService=False,
                relinquishDefault=0.0,
                minPresValue=0.0,
                maxPresValue=100.0,
            )
            self.app.add_object(obj)
            self._analog_outputs.append(obj)
        logger.info("  Created 3 Analog Outputs (damper positions)")

    def _create_analog_values(self):
        """5 AnalogValueObjects - 3 commandable setpoints + 2 read-only."""
        for i in range(1, 4):
            obj = AnalogValueObjectCmd(
                objectIdentifier=("analogValue", i),
                objectName=f"Zone {i} Setpoint",
                description=f"Zone {i} temperature setpoint (commandable)",
                presentValue=72.0,
                units="degreesFahrenheit",
                statusFlags=[0, 0, 0, 0],
                eventState="normal",
                outOfService=False,
                relinquishDefault=72.0,
            )
            self.app.add_object(obj)
            self._setpoint_values.append(obj)

        # 2 read-only analog values
        obj = AnalogValueObject(
            objectIdentifier=("analogValue", 4),
            objectName="Outside Air Temperature",
            description="Outside air temperature (read-only)",
            presentValue=55.0,
            units="degreesFahrenheit",
            statusFlags=[0, 0, 0, 0],
            eventState="normal",
            outOfService=False,
        )
        self.app.add_object(obj)

        obj = AnalogValueObject(
            objectIdentifier=("analogValue", 5),
            objectName="Building Pressure",
            description="Building static pressure (read-only)",
            presentValue=0.05,
            units="inchesOfWater",
            statusFlags=[0, 0, 0, 0],
            eventState="normal",
            outOfService=False,
        )
        self.app.add_object(obj)
        logger.info("  Created 5 Analog Values (3 commandable setpoints + 2 read-only)")

    def _create_binary_inputs(self):
        """3 BinaryInputObjects - occupancy sensors."""
        for i in range(1, 4):
            obj = BinaryInputObject(
                objectIdentifier=("binaryInput", i),
                objectName=f"Zone {i} Occupancy",
                description=f"Zone {i} occupancy sensor",
                presentValue="active" if i % 2 == 0 else "inactive",
                statusFlags=[0, 0, 0, 0],
                eventState="normal",
                outOfService=False,
                activeText="Occupied",
                inactiveText="Unoccupied",
            )
            self.app.add_object(obj)
            self._binary_inputs.append(obj)
        logger.info("  Created 3 Binary Inputs (occupancy sensors)")

    def _create_binary_outputs(self):
        """5 BinaryOutputObjects - lights, commandable with priority arrays."""
        for i in range(1, 6):
            obj = BinaryOutputObject(
                objectIdentifier=("binaryOutput", i),
                objectName=f"Light {i}",
                description=f"Zone lighting output {i}",
                presentValue="inactive",
                statusFlags=[0, 0, 0, 0],
                eventState="normal",
                outOfService=False,
                activeText="On",
                inactiveText="Off",
                relinquishDefault="inactive",
            )
            self.app.add_object(obj)
            self._binary_outputs.append(obj)
        logger.info("  Created 5 Binary Outputs (lights)")

    def _create_binary_values(self):
        """2 BinaryValueObjects - system modes, commandable."""
        modes = [("Heating Mode", "Heat", "No Heat"), ("Fan Mode", "On", "Auto")]
        for i, (name, active, inactive) in enumerate(modes, 1):
            obj = BinaryValueObjectCmd(
                objectIdentifier=("binaryValue", i),
                objectName=name,
                description=f"System {name.lower()} control (commandable)",
                presentValue="active",
                statusFlags=[0, 0, 0, 0],
                eventState="normal",
                outOfService=False,
                activeText=active,
                inactiveText=inactive,
                relinquishDefault="inactive",
            )
            self.app.add_object(obj)
        logger.info("  Created 2 Binary Values (commandable system modes)")

    def _create_multistate_values(self):
        """1 MultiStateValueObject - HVAC mode (4 states)."""
        obj = MultiStateValueObject(
            objectIdentifier=("multiStateValue", 1),
            objectName="HVAC Mode",
            description="HVAC operating mode selector",
            presentValue=2,
            numberOfStates=4,
            stateText=["Off", "Heat", "Cool", "Auto"],
            statusFlags=[0, 0, 0, 0],
            eventState="normal",
            outOfService=False,
        )
        self.app.add_object(obj)
        logger.info("  Created 1 Multi-State Value (HVAC mode)")

    def _create_loop_objects(self):
        """2 LoopObjects - PID controllers for zone temperature control."""
        loops = [
            {
                "instance": 1,
                "name": "Zone 1 PID Controller",
                "desc": "Zone 1 temperature PID loop",
                "p": 10.0,
                "i": 0.5,
                "d": 0.1,
                "setpoint": 72.0,
                "output": 50.0,
            },
            {
                "instance": 2,
                "name": "Zone 2 PID Controller",
                "desc": "Zone 2 temperature PID loop (aggressive tuning)",
                "p": 80.0,  # High P - triggers security analysis
                "i": 2.0,
                "d": 0.0,
                "setpoint": 72.0,
                "output": 45.0,
            },
        ]
        for lp in loops:
            obj = LocalLoopObject(
                objectIdentifier=("loop", lp["instance"]),
                objectName=lp["name"],
                description=lp["desc"],
                presentValue=lp["output"],
                statusFlags=[0, 0, 0, 0],
                eventState="normal",
                outOfService=False,
                outputUnits="percent",
                manipulatedVariableReference=ObjectPropertyReference(
                    objectIdentifier=f"analogOutput:{lp['instance']}",
                    propertyIdentifier="presentValue",
                ),
                controlledVariableReference=ObjectPropertyReference(
                    objectIdentifier=f"analogInput:{lp['instance']}",
                    propertyIdentifier="presentValue",
                ),
                controlledVariableValue=72.0 + lp["instance"],
                controlledVariableUnits="degreesFahrenheit",
                setpointReference=SetpointReference(
                    setpointReference=ObjectPropertyReference(
                        objectIdentifier=f"analogValue:{lp['instance']}",
                        propertyIdentifier="presentValue",
                    ),
                ),
                setpoint=lp["setpoint"],
                action=Action.direct,
                proportionalConstant=lp["p"],
                proportionalConstantUnits="percent",
                integralConstant=lp["i"],
                integralConstantUnits="percent",
                derivativeConstant=lp["d"],
                derivativeConstantUnits="percent",
                bias=50.0,
                maximumOutput=100.0,
                minimumOutput=0.0,
                priorityForWriting=8,
                updateInterval=200,  # centiseconds (2s)
                covIncrement=0.5,
            )
            self.app.add_object(obj)
            self._loops.append(obj)
        logger.info("  Created 2 Loop Objects (PID controllers)")

    def _create_program_objects(self):
        """2 ProgramObjects - running and halted."""
        # Running program
        obj = LocalProgramObject(
            objectIdentifier=("program", 1),
            objectName="MainControl",
            description="Main HVAC control program",
            programState=ProgramState.running,
            programChange=ProgramRequest.ready,
            programLocation="/opt/hvac/main_control.bin",
            statusFlags=[0, 0, 0, 0],
            outOfService=False,
        )
        self.app.add_object(obj)

        # Halted program
        obj = LocalProgramObject(
            objectIdentifier=("program", 2),
            objectName="DiagnosticRoutine",
            description="System diagnostic and self-test routine",
            programState=ProgramState.halted,
            programChange=ProgramRequest.ready,
            reasonForHalt=ProgramError.other,
            descriptionOfHalt="Operator request - scheduled maintenance",
            programLocation="/opt/hvac/diagnostics.bin",
            statusFlags=[0, 0, 0, 0],
            outOfService=False,
        )
        self.app.add_object(obj)
        logger.info("  Created 2 Program Objects (running + halted)")

    def _create_schedule_and_calendar(self):
        """1 ScheduleObject + 1 CalendarObject."""
        # Weekly schedule: Mon-Fri 8am-5pm occupied, otherwise unoccupied
        occupied = Real(72.0)
        unoccupied = Real(65.0)

        weekday_schedule = DailySchedule(
            daySchedule=[
                TimeValue(time=Time("08:00:00.00"), value=occupied),
                TimeValue(time=Time("17:00:00.00"), value=unoccupied),
            ]
        )
        weekend_schedule = DailySchedule(
            daySchedule=[
                TimeValue(time=Time("00:00:00.00"), value=unoccupied),
            ]
        )

        sched = ScheduleObject(
            objectIdentifier=("schedule", 1),
            objectName="Weekday Occupancy Schedule",
            description="Mon-Fri 8am-5pm occupied mode",
            presentValue=occupied,
            effectivePeriod=DateRange(
                startDate=Date("2024-01-01"),
                endDate=Date("2030-12-31"),
            ),
            weeklySchedule=[
                weekday_schedule,  # Monday
                weekday_schedule,  # Tuesday
                weekday_schedule,  # Wednesday
                weekday_schedule,  # Thursday
                weekday_schedule,  # Friday
                weekend_schedule,  # Saturday
                weekend_schedule,  # Sunday
            ],
            scheduleDefault=unoccupied,
            priorityForWriting=9,
            statusFlags=[0, 0, 0, 0],
            eventState="normal",
            outOfService=False,
            reliability="noFaultDetected",
        )
        self.app.add_object(sched)
        logger.info("  Created 1 Schedule Object (weekday occupancy)")

        # Calendar with holiday entries
        cal = LocalCalendarObject(
            objectIdentifier=("calendar", 1),
            objectName="Holiday Calendar",
            description="Company holidays for schedule exceptions",
            presentValue=False,
            dateList=[
                CalendarEntry(date=Date("2025-01-01")),  # New Year
                CalendarEntry(date=Date("2025-07-04")),  # Independence Day
                CalendarEntry(
                    dateRange=DateRange(
                        startDate=Date("2025-12-24"),
                        endDate=Date("2025-12-26"),
                    )
                ),  # Christmas
            ],
        )
        self.app.add_object(cal)
        logger.info("  Created 1 Calendar Object (holidays)")

    def _create_trend_logs(self):
        """2 TrendLogObjects pre-populated with historical data."""
        now = datetime.now()
        for i in range(1, 3):
            # Generate 50 historical records
            records = []
            for j in range(50):
                ts = now - timedelta(minutes=(50 - j) * 5)
                dt = DateTime(ts)
                val = 72.0 + i + 3.0 * math.sin(j * 0.2) + random.uniform(-0.5, 0.5)
                record = LogRecord(
                    timestamp=dt,
                    logDatum=LogRecordLogDatum(realValue=val),
                )
                records.append(record)

            obj = LocalTrendLogObject(
                objectIdentifier=("trendLog", i),
                objectName=f"Zone {i} Temp Log",
                description=f"Zone {i} temperature trend log",
                enable=True,
                stopWhenFull=False,
                bufferSize=1000,
                logBuffer=records,
                recordCount=len(records),
                totalRecordCount=len(records),
                loggingType=LoggingType.polled,
                logInterval=300,  # 5 minutes in seconds
                statusFlags=[0, 0, 0, 0],
                eventState="normal",
                reliability="noFaultDetected",
                logDeviceObjectProperty=DeviceObjectPropertyReference(
                    objectIdentifier=f"analogInput:{i}",
                    propertyIdentifier="presentValue",
                ),
            )
            self.app.add_object(obj)
            self._trend_logs.append(obj)
        logger.info("  Created 2 Trend Log Objects (50 records each)")

    def _create_file_objects(self):
        """2 FileObjects - stream access config + record access firmware."""
        now = DateTime(datetime.now())

        config_file = LocalFileObject(
            objectIdentifier=("file", 1),
            objectName="config.txt",
            description="Device configuration file",
            fileType="text/plain",
            fileSize=len(CONFIG_FILE_DATA),
            modificationDate=now,
            archive=False,
            readOnly=False,
            fileAccessMethod=FileAccessMethod.streamAccess,
        )
        self.app.add_object(config_file)

        firmware_file = LocalFileObject(
            objectIdentifier=("file", 2),
            objectName="firmware.bin",
            description="Device firmware image",
            fileType="application/octet-stream",
            fileSize=len(FIRMWARE_FILE_DATA),
            modificationDate=now,
            archive=False,
            readOnly=True,
            fileAccessMethod=FileAccessMethod.recordAccess,
            recordCount=16,  # 4096 / 256 = 16 records
        )
        self.app.add_object(firmware_file)
        logger.info("  Created 2 File Objects (config + firmware)")

    def _create_life_safety_objects(self):
        """2 LifeSafetyPointObjects - smoke detector + emergency stop."""
        smoke = LocalLifeSafetyPointObject(
            objectIdentifier=("lifeSafetyPoint", 1),
            objectName="Smoke Detector Zone 1",
            description="Zone 1 smoke detection sensor",
            presentValue=LifeSafetyState.quiet,
            trackingValue=LifeSafetyState.quiet,
            statusFlags=[0, 0, 0, 0],
            eventState="normal",
            reliability="noFaultDetected",
            outOfService=False,
            mode=LifeSafetyMode.on,
            acceptedModes=[LifeSafetyMode.on, LifeSafetyMode.off, LifeSafetyMode.test],
            silenced=SilencedState.unsilenced,
            operationExpected=LifeSafetyOperation.none,
            maintenanceRequired=Maintenance.none,
            directReading=0.0,
            units="partsPerMillion",
        )
        self.app.add_object(smoke)

        estop = LocalLifeSafetyPointObject(
            objectIdentifier=("lifeSafetyPoint", 2),
            objectName="Emergency Stop",
            description="System emergency stop button",
            presentValue=LifeSafetyState.quiet,
            trackingValue=LifeSafetyState.quiet,
            statusFlags=[0, 0, 0, 0],
            eventState="normal",
            reliability="noFaultDetected",
            outOfService=False,
            mode=LifeSafetyMode.on,
            acceptedModes=[LifeSafetyMode.on, LifeSafetyMode.off],
            silenced=SilencedState.unsilenced,
            operationExpected=LifeSafetyOperation.none,
        )
        self.app.add_object(estop)
        logger.info("  Created 2 Life Safety Point Objects (smoke + e-stop)")

    def _create_network_port_objects(self):
        """2 NetworkPortObjects - BACnet/IP + MS/TP.

        We register these directly into the application dictionaries to avoid
        NormalApplication.add_object() trying to create actual link layers
        (which would fail for MS/TP and duplicate-bind for BACnet/IP).
        """
        from bacpypes3.object import NetworkPortObject as _RawNetworkPortObject

        ip_port = _RawNetworkPortObject(
            objectIdentifier=("networkPort", 1),
            objectName="BACnet/IP Port",
            description="Primary BACnet/IP network interface",
            statusFlags=[0, 0, 0, 0],
            reliability="noFaultDetected",
            outOfService=False,
            networkType=NetworkType.ipv4,
            protocolLevel="bacnet-application",
            networkNumber=1,
            networkNumberQuality=NetworkNumberQuality.configured,
            changesPending=False,
            macAddress=b"\x00\x00\x00\x00\xba\xc0",
            linkSpeed=100000000.0,
            bacnetIPMode="normal",
            ipAddress=b"\x00\x00\x00\x00",
            ipSubnetMask=b"\xff\xff\xff\x00",
            bacnetIPUDPPort=self.port,
        )
        self._register_object(ip_port)

        mstp_port = _RawNetworkPortObject(
            objectIdentifier=("networkPort", 2),
            objectName="MS/TP Port",
            description="BACnet MS/TP serial bus interface",
            statusFlags=[0, 0, 0, 0],
            reliability="noFaultDetected",
            outOfService=False,
            networkType=NetworkType.mstp,
            protocolLevel="bacnet-application",
            networkNumber=100,
            networkNumberQuality=NetworkNumberQuality.configured,
            changesPending=False,
            macAddress=b"\x01",
            linkSpeed=76800.0,
            maxMaster=127,
            maxInfoFrames=1,
        )
        self._register_object(mstp_port)
        logger.info("  Created 2 Network Port Objects (BACnet/IP + MS/TP)")

    def _register_object(self, obj):
        """Register an object directly without triggering link-layer binding."""
        self.app.objectName[obj.objectName] = obj
        self.app.objectIdentifier[obj.objectIdentifier] = obj
        obj._app = self.app

    def _create_structured_view(self):
        """1 StructuredViewObject - HVAC system hierarchy."""
        obj = LocalStructuredViewObject(
            objectIdentifier=("structuredView", 1),
            objectName="HVAC System",
            description="Top-level HVAC system view",
            nodeType=NodeType.system,
            nodeSubtype="HVAC",
            subordinateList=[
                DeviceObjectReference(objectIdentifier="analogInput:1"),
                DeviceObjectReference(objectIdentifier="analogInput:2"),
                DeviceObjectReference(objectIdentifier="analogOutput:1"),
                DeviceObjectReference(objectIdentifier="analogOutput:2"),
                DeviceObjectReference(objectIdentifier="analogValue:1"),
                DeviceObjectReference(objectIdentifier="analogValue:2"),
                DeviceObjectReference(objectIdentifier="loop:1"),
                DeviceObjectReference(objectIdentifier="loop:2"),
                DeviceObjectReference(objectIdentifier="schedule:1"),
            ],
            subordinateAnnotations=[
                "Zone 1 Temp",
                "Zone 2 Temp",
                "Zone 1 Damper",
                "Zone 2 Damper",
                "Zone 1 Setpoint",
                "Zone 2 Setpoint",
                "Zone 1 PID",
                "Zone 2 PID",
                "Occupancy Schedule",
            ],
            defaultSubordinateRelationship=Relationship.contains,
        )
        self.app.add_object(obj)
        logger.info("  Created 1 Structured View Object (HVAC hierarchy)")

    # -------------------------------------------------------------------
    # Custom service handlers
    # -------------------------------------------------------------------
    async def _do_reinitialize_device(self, apdu: ReinitializeDeviceRequest):
        """Handle ReinitializeDevice - requires password 'OIDA'."""
        logger.info(
            f"ReinitializeDevice request: state={apdu.reinitializedStateOfDevice}, "
            f"from={apdu.pduSource}"
        )
        password = getattr(apdu, "password", None)
        if password is None or str(password) != "OIDA":
            logger.warning("ReinitializeDevice rejected: wrong password")
            raise ExecutionError(errorClass="security", errorCode="passwordFailure")

        logger.info(f"ReinitializeDevice accepted: {apdu.reinitializedStateOfDevice}")
        await self.app.response(SimpleAckPDU(context=apdu))

    async def _do_time_synchronization(self, apdu: TimeSynchronizationRequest):
        """Handle TimeSynchronization (unconfirmed - no response)."""
        logger.info(f"TimeSynchronization received: {apdu.time} from {apdu.pduSource}")

    async def _do_utc_time_synchronization(self, apdu: UTCTimeSynchronizationRequest):
        """Handle UTCTimeSynchronization (unconfirmed - no response)."""
        logger.info(f"UTCTimeSynchronization received: {apdu.time} from {apdu.pduSource}")

    async def _do_atomic_read_file(self, apdu: AtomicReadFileRequest):
        """Handle AtomicReadFile for stream and record access."""
        file_obj = self.app.get_object_id(apdu.fileIdentifier)
        if file_obj is None:
            logger.warning(f"AtomicReadFile: unknown object {apdu.fileIdentifier}")
            raise ExecutionError(errorClass="object", errorCode="unknownObject")

        file_name = str(file_obj.objectName)
        file_data = self._file_data.get(file_name)
        if file_data is None:
            raise ExecutionError(errorClass="object", errorCode="unknownObject")

        access = apdu.accessMethod

        if hasattr(access, "streamAccess") and access.streamAccess is not None:
            # Stream access
            sa = access.streamAccess
            start = int(sa.fileStartPosition)
            count = int(sa.requestedOctetCount)
            chunk = file_data[start : start + count]
            eof = (start + count) >= len(file_data)

            from bacpypes3.basetypes import (
                AtomicReadFileACKAccessMethodStreamAccess,
                AtomicReadFileACKAccessMethodChoice,
            )

            ack = AtomicReadFileACK(
                context=apdu,
                endOfFile=eof,
                accessMethod=AtomicReadFileACKAccessMethodChoice(
                    streamAccess=AtomicReadFileACKAccessMethodStreamAccess(
                        fileStartPosition=start,
                        fileData=OctetString(chunk),
                    ),
                ),
            )
            logger.info(
                f"AtomicReadFile stream: {file_name} offset={start} len={len(chunk)} eof={eof}"
            )
            await self.app.response(ack)

        elif hasattr(access, "recordAccess") and access.recordAccess is not None:
            # Record access
            ra = access.recordAccess
            start_record = int(ra.fileStartRecord)
            count = int(ra.requestedRecordCount)
            record_size = 256
            records = []
            for r in range(start_record, min(start_record + count, len(file_data) // record_size)):
                offset = r * record_size
                records.append(OctetString(file_data[offset : offset + record_size]))
            eof = (start_record + count) * record_size >= len(file_data)

            from bacpypes3.basetypes import (
                AtomicReadFileACKAccessMethodRecordAccess,
                AtomicReadFileACKAccessMethodChoice,
            )

            ack = AtomicReadFileACK(
                context=apdu,
                endOfFile=eof,
                accessMethod=AtomicReadFileACKAccessMethodChoice(
                    recordAccess=AtomicReadFileACKAccessMethodRecordAccess(
                        fileStartRecord=start_record,
                        returnedRecordCount=len(records),
                        fileRecordData=records,
                    ),
                ),
            )
            logger.info(
                f"AtomicReadFile record: {file_name} start={start_record} "
                f"returned={len(records)} eof={eof}"
            )
            await self.app.response(ack)
        else:
            raise ExecutionError(errorClass="services", errorCode="invalidDataType")

    # -------------------------------------------------------------------
    # Dynamic simulation
    # -------------------------------------------------------------------
    async def _simulate_values(self):
        """Background task updating object values periodically."""
        logger.info("Dynamic simulation started (2s interval)")
        counter = 0
        try:
            while self.running:
                await asyncio.sleep(2.0)
                counter += 1
                t = counter * 2.0  # elapsed seconds

                # Temperature sensors: sinusoidal 68-78°F with noise
                for idx, ai in enumerate(self._analog_inputs):
                    base = 73.0 + idx * 0.5
                    value = base + 5.0 * math.sin(t / 60.0 + idx * 1.2) + random.uniform(-0.3, 0.3)
                    ai.presentValue = round(value, 2)

                # Damper positions: follow error from setpoint
                for idx, ao in enumerate(self._analog_outputs):
                    if idx < len(self._analog_inputs) and idx < len(self._setpoint_values):
                        temp = float(self._analog_inputs[idx].presentValue)
                        sp = float(self._setpoint_values[idx].presentValue)
                        error = temp - sp
                        current = float(ao.presentValue)
                        target = max(0.0, min(100.0, 50.0 + error * 5.0))
                        # Smooth toward target
                        new_val = current + (target - current) * 0.3
                        ao.presentValue = round(max(0.0, min(100.0, new_val)), 1)

                # Loop objects: update controlled variable and output
                for idx, loop in enumerate(self._loops):
                    if idx < len(self._analog_inputs):
                        loop.controlledVariableValue = float(self._analog_inputs[idx].presentValue)
                        # Simple P-only output simulation
                        sp = float(loop.setpoint)
                        cv = float(loop.controlledVariableValue)
                        p = float(loop.proportionalConstant)
                        error = sp - cv
                        output = float(loop.bias) + (error * p / 100.0)
                        loop.presentValue = round(max(0.0, min(100.0, output)), 2)

                # Occupancy: random toggle every ~30s
                if counter % 15 == 0:
                    for bi in self._binary_inputs:
                        if random.random() < 0.3:
                            current = bi.presentValue
                            bi.presentValue = "inactive" if str(current) == "active" else "active"

                # Trend logs: append new record
                for idx, tl in enumerate(self._trend_logs):
                    if idx < len(self._analog_inputs):
                        val = float(self._analog_inputs[idx].presentValue)
                        record = LogRecord(
                            timestamp=DateTime(datetime.now()),
                            logDatum=LogRecordLogDatum(realValue=val),
                        )
                        buf = list(tl.logBuffer)
                        buf.append(record)
                        # Keep buffer bounded
                        if len(buf) > int(tl.bufferSize):
                            buf = buf[-int(tl.bufferSize) :]
                        tl.logBuffer = buf
                        tl.recordCount = len(buf)
                        tl.totalRecordCount = int(tl.totalRecordCount) + 1

                if counter % 30 == 0:
                    logger.debug(
                        f"Sim cycle {counter}: temps={[round(float(ai.presentValue), 1) for ai in self._analog_inputs]}"
                    )

        except asyncio.CancelledError:
            logger.info("Dynamic simulation stopped")

    # -------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------
    async def run_forever(self):
        """Run the device until stopped."""
        logger.info("Device running. Press Ctrl+C to stop.")
        try:
            while self.running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass

    def stop(self):
        """Stop the device."""
        self.running = False
        if self._sim_task and not self._sim_task.done():
            self._sim_task.cancel()
        if self.app:
            try:
                self.app.close()
                logger.info("BACnet device stopped")
            except Exception as e:
                logger.error(f"Error stopping device: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="BACnet Mock Server for Testing",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--device-id", type=int, default=1234, help="BACnet device instance ID")
    parser.add_argument("--device-name", type=str, default="OIDA Test Device", help="Device name")
    parser.add_argument("--port", type=int, default=47808, help="BACnet/IP UDP port")
    parser.add_argument("--ip", type=str, default="0.0.0.0", help="Local IP address to bind to")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    device = BACnetMockServer(
        device_id=args.device_id,
        device_name=args.device_name,
        port=args.port,
        ip=args.ip,
    )

    async def run():
        if await device.start():
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, device.stop)
            await device.run_forever()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        device.stop()


if __name__ == "__main__":
    main()
