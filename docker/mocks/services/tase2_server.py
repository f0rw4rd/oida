#!/usr/bin/env python3
"""
Mock TASE.2/ICCP Server for testing OIDA TASE.2 scanner

TASE.2 (IEC 60870-6) runs on top of MMS (Manufacturing Message Specification)
using ISO 8823 session layer on port 102.

This mock server simulates:
- VCC (Virtual Control Center) and ICC (Indication Control Center) domains
- Bilateral table information
- Data points with quality indicators
- Transfer sets (Block 2 - Report-by-Exception)
- Control points (Block 5 - Device Control)
"""

import asyncio
import logging
import struct
import time
import random
import math
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from enum import IntEnum

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
log = logging.getLogger("TASE2Server")


class PointType(IntEnum):
    """TASE.2 Indication Point Types"""

    REAL = 1
    STATE = 2
    DISCRETE = 3
    REAL_Q = 4
    STATE_Q = 5
    DISCRETE_Q = 6
    REAL_Q_TIME = 7
    STATE_Q_TIME = 8
    DISCRETE_Q_TIME = 9


class Quality(IntEnum):
    """TASE.2 Quality Flags"""

    GOOD = 0
    INVALID = 1
    HELD = 2
    SUSPECT = 3


class TagValue(IntEnum):
    """TASE.2 Device Tag Values (Block 5)"""

    NO_TAG = 0
    OPEN_AND_CLOSE_INHIBIT = 1
    CLOSE_ONLY_INHIBIT = 2


class DeviceState(IntEnum):
    """TASE.2 SBO Device State"""

    IDLE = 0
    ARMED = 1


class IMStatus(IntEnum):
    """TASE.2 Information Message Status (Block 4)"""

    ACTIVE = 0
    ARCHIVED = 1
    DELETED = 2


class IMStorageStatus(IntEnum):
    """TASE.2 IM Store Status (Block 4)"""

    AVAILABLE = 0
    FULL = 1
    ERROR = 2


class MMSTag(IntEnum):
    """MMS/BER Tag Values"""

    # PDU Types
    CONFIRMED_REQUEST = 0xA0
    CONFIRMED_RESPONSE = 0xA1
    INITIATE_REQUEST = 0xA8
    INITIATE_RESPONSE = 0xA9
    CONCLUDE_REQUEST = 0x8B
    CONCLUDE_RESPONSE = 0x8C

    # Data Types
    BOOLEAN = 0x83
    INTEGER = 0x85
    UNSIGNED = 0x86
    FLOAT = 0x87
    VISIBLE_STRING = 0x8A
    STRUCTURE = 0xA2
    ARRAY = 0xA1


@dataclass
class DataPoint:
    """TASE.2 Data Point"""

    name: str
    domain: str
    point_type: PointType
    value: Any
    quality: Quality = Quality.GOOD
    writable: bool = False
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "domain": self.domain,
            "point_type": self.point_type.name,
            "value": self.value,
            "quality": self.quality.name,
            "writable": self.writable,
        }


@dataclass
class TransferSet:
    """TASE.2 Transfer Set (Block 2 - RBE)"""

    name: str
    domain: str
    data_set: str
    interval: int = 5000  # milliseconds
    rbe_enabled: bool = True
    buffer_time: int = 1000
    integrity_time: int = 60000


@dataclass
class ControlPoint:
    """TASE.2 Control Point (Block 5)"""

    name: str
    domain: str
    is_sbo: bool = True  # Select-Before-Operate (vs Direct Control)
    state: DeviceState = DeviceState.IDLE
    check_back_id: Optional[int] = None
    tag_value: TagValue = TagValue.NO_TAG
    tag_reason: str = ""
    armed_time: Optional[float] = None  # Time when armed (for timeout)


@dataclass
class InformationMessage:
    """TASE.2 Information Message (Block 4)

    Per IEC 60870-6-503, messages include info_reference and local_reference
    for bilateral table access control.
    """

    message_id: str
    content: str
    time_created: float
    originator: str = "MockServer"
    status: IMStatus = IMStatus.ACTIVE
    priority: int = 5  # 1-9 (1=highest)
    info_reference: str = ""  # Inherited from IM store, bilateral table access control
    local_reference: str = ""  # Client-assigned identifier

    @property
    def size(self) -> int:
        return len(self.content)


@dataclass
class IMTransfer:
    """TASE.2 IM Transfer Store (Block 4)

    Per IEC 60870-6-503, IM Transfer Sets include:
    - info_reference: Information Reference for bilateral table access control
    - local_reference: Local Reference for client identification
    - scope: VCC (server-wide) or ICC (bilateral-specific)
    """

    name: str
    domain: str
    max_messages: int = 100
    storage_status: IMStorageStatus = IMStorageStatus.AVAILABLE
    messages: List[InformationMessage] = field(default_factory=list)
    info_reference: str = ""  # For bilateral table access control
    local_reference: str = ""  # Client-assigned identifier
    scope: str = "ICC"  # VCC or ICC

    def __post_init__(self):
        # Default info_reference to name if not set
        if not self.info_reference:
            self.info_reference = self.name
        # Default scope based on domain
        if self.domain.upper().startswith("VCC"):
            self.scope = "VCC"

    @property
    def current_count(self) -> int:
        return len(self.messages)


@dataclass
class Domain:
    """TASE.2 Domain (VCC or ICC)"""

    name: str
    is_vcc: bool
    variables: List[str] = field(default_factory=list)
    data_sets: List[str] = field(default_factory=list)


class TASE2Server:
    """Mock TASE.2/ICCP Server"""

    def __init__(self, host: str = "0.0.0.0", port: int = 102):
        self.host = host
        self.port = port
        self.bilateral_table_id = "BLT_UTILITY_001"
        self.bilateral_table_count = 2

        # Create mock data model
        self.domains: Dict[str, Domain] = {}
        self.data_points: Dict[str, DataPoint] = {}
        self.transfer_sets: Dict[str, TransferSet] = {}
        self.control_points: Dict[str, ControlPoint] = {}
        self.dynamic_data_sets: Dict[str, List[Dict[str, str]]] = {}  # Client-created data sets
        self.im_stores: Dict[str, IMTransfer] = {}  # Block 4: IM stores
        self._im_message_counter = 0  # Counter for message IDs

        self._create_data_model()

        # TASE.2 Protocol Objects (VMD-specific)
        # Supported_Features bitmap per IEC 60870-6-503 Section 8.1.8:
        # Bit 0: Block1 (always 1, Basic)
        # Bit 1: Block2 (Report-by-Exception)
        # Bit 2: reserved
        # Bit 3: Block4 (Information Messages)
        # Bit 4: Block5 (Device Control)
        # Bits 5-9: reserved
        # Bit 10: Block11 (Historical)
        # Bit 11: Block12 (Extended Historical)
        self.supported_features = {
            "block1": True,  # Basic (always 1)
            "block2": True,  # Report-by-Exception
            "block4": True,  # Information Messages
            "block5": True,  # Device Control
            "block11": False,  # Historical (not implemented)
            "block12": False,  # Extended Historical (not implemented)
        }
        # Generate bitstring representation (for raw protocol)
        self.supported_features_bits = self._features_to_bitstring()

        # TASE.2_Version (major, minor)
        self.tase2_version = {"major": 2000, "minor": 8}

        # Supported conformance blocks (legacy)
        self.supported_blocks = [1, 2, 5]  # Basic, RBE, Control

        # Server info
        self.vendor = "OIDA Mock"
        self.model = "TASE2-SIM"
        self.revision = "1.0.0"

        # CheckBackID counter for SBO operations
        self._check_back_id_counter = 1000

        # SBO timeout (30 seconds per spec)
        self.sbo_timeout = 30.0

        # DSConditions tracking (per IEC 60870-6-503 Section 5.2.6.2)
        self.ds_conditions_detected: Dict[str, Dict[str, bool]] = {}

        # Next available transfer set counter
        self._next_ds_transfer_set_counter = 1

    def _features_to_bitstring(self) -> int:
        """Convert supported_features to bitstring value per spec."""
        bits = 0
        if self.supported_features.get("block1", False):
            bits |= 0x0001  # bit 0
        if self.supported_features.get("block2", False):
            bits |= 0x0002  # bit 1
        if self.supported_features.get("block4", False):
            bits |= 0x0008  # bit 3
        if self.supported_features.get("block5", False):
            bits |= 0x0010  # bit 4
        if self.supported_features.get("block11", False):
            bits |= 0x0400  # bit 10
        if self.supported_features.get("block12", False):
            bits |= 0x0800  # bit 11
        return bits

    def get_next_ds_transfer_set(self, domain: str) -> str:
        """Get next available DSTransferSet name."""
        name = f"TS_Dynamic_{self._next_ds_transfer_set_counter}"
        self._next_ds_transfer_set_counter += 1
        return name

    def get_ds_conditions_detected(self, domain: str) -> Dict[str, bool]:
        """Get DSConditions_Detected for a domain."""
        return self.ds_conditions_detected.get(
            domain,
            {
                "IntervalTimeOut": False,
                "ObjectChange": False,
                "OperatorRequest": False,
                "IntegrityTimeOut": False,
                "OtherExternalEvent": False,
            },
        )

    def set_ds_condition(self, domain: str, condition: str, value: bool = True):
        """Set a DSCondition flag (for simulation)."""
        if domain not in self.ds_conditions_detected:
            self.ds_conditions_detected[domain] = {
                "IntervalTimeOut": False,
                "ObjectChange": False,
                "OperatorRequest": False,
                "IntegrityTimeOut": False,
                "OtherExternalEvent": False,
            }
        if condition in self.ds_conditions_detected[domain]:
            self.ds_conditions_detected[domain][condition] = value

    def _create_data_model(self):
        """Create mock TASE.2 data model"""

        # VCC Domain - Global scope variables
        vcc = Domain(name="VCC", is_vcc=True)
        vcc.variables = [
            "System_Status",
            "Total_Generation_MW",
            "Total_Load_MW",
            "Frequency_Hz",
            "Tie_Line_Flow_MW",
        ]
        vcc.data_sets = ["DS_System", "DS_Generation"]
        self.domains["VCC"] = vcc

        # Add VCC data points
        self._add_point(
            "System_Status", "VCC", PointType.STATE, 1, desc="System operational status"
        )
        self._add_point(
            "Total_Generation_MW", "VCC", PointType.REAL_Q, 2500.5, desc="Total generation"
        )
        self._add_point("Total_Load_MW", "VCC", PointType.REAL_Q, 2450.3, desc="Total load")
        self._add_point(
            "Frequency_Hz", "VCC", PointType.REAL_Q_TIME, 50.02, desc="System frequency"
        )
        self._add_point(
            "Tie_Line_Flow_MW", "VCC", PointType.REAL_Q, 50.2, desc="Tie line power flow"
        )

        # ICC1 Domain - Substation 1
        icc1 = Domain(name="ICC1", is_vcc=False)
        icc1.variables = [
            "Bus_Voltage_kV",
            "Feeder1_MW",
            "Feeder1_MVAr",
            "Feeder2_MW",
            "Feeder2_MVAr",
            "Breaker1_Status",
            "Breaker2_Status",
            "Transformer_Tap",
            "Breaker1_Control",
            "Breaker2_Control",
            "Tap_Setpoint",
        ]
        icc1.data_sets = ["DS_Measurements", "DS_Status", "DS_Controls"]
        self.domains["ICC1"] = icc1

        # Add ICC1 data points
        self._add_point("Bus_Voltage_kV", "ICC1", PointType.REAL_Q, 132.5, desc="Bus voltage")
        self._add_point(
            "Feeder1_MW", "ICC1", PointType.REAL_Q_TIME, 45.2, desc="Feeder 1 active power"
        )
        self._add_point(
            "Feeder1_MVAr", "ICC1", PointType.REAL_Q_TIME, 12.3, desc="Feeder 1 reactive power"
        )
        self._add_point(
            "Feeder2_MW", "ICC1", PointType.REAL_Q_TIME, 38.7, desc="Feeder 2 active power"
        )
        self._add_point(
            "Feeder2_MVAr", "ICC1", PointType.REAL_Q_TIME, 8.9, desc="Feeder 2 reactive power"
        )
        self._add_point("Breaker1_Status", "ICC1", PointType.STATE_Q, 1, desc="Breaker 1 closed")
        self._add_point("Breaker2_Status", "ICC1", PointType.STATE_Q, 1, desc="Breaker 2 closed")
        self._add_point("Transformer_Tap", "ICC1", PointType.DISCRETE_Q, 5, desc="Tap position")

        # Control points (writable)
        self._add_point(
            "Breaker1_Control", "ICC1", PointType.STATE, 0, writable=True, desc="Breaker 1 control"
        )
        self._add_point(
            "Breaker2_Control", "ICC1", PointType.STATE, 0, writable=True, desc="Breaker 2 control"
        )
        self._add_point(
            "Tap_Setpoint", "ICC1", PointType.DISCRETE, 5, writable=True, desc="Tap setpoint"
        )

        # Add control points for Block 5 with various configurations
        # Breaker1 - SBO device with tag (simulates maintenance mode)
        self.control_points["ICC1/Breaker1_Control"] = ControlPoint(
            name="Breaker1_Control",
            domain="ICC1",
            is_sbo=True,
            state=DeviceState.IDLE,
            tag_value=TagValue.CLOSE_ONLY_INHIBIT,
            tag_reason="Scheduled maintenance",
        )
        # Breaker2 - SBO device without tag (normal operation)
        self.control_points["ICC1/Breaker2_Control"] = ControlPoint(
            name="Breaker2_Control",
            domain="ICC1",
            is_sbo=True,
            state=DeviceState.IDLE,
            tag_value=TagValue.NO_TAG,
        )
        # Tap_Setpoint - Direct control device (not SBO)
        self.control_points["ICC1/Tap_Setpoint"] = ControlPoint(
            name="Tap_Setpoint",
            domain="ICC1",
            is_sbo=False,
            state=DeviceState.IDLE,
            tag_value=TagValue.NO_TAG,
        )

        # ICC2 Domain - Substation 2
        icc2 = Domain(name="ICC2", is_vcc=False)
        icc2.variables = [
            "Bus_Voltage_kV",
            "Load_MW",
            "Load_MVAr",
            "Capacitor_Status",
            "Capacitor_Control",
        ]
        icc2.data_sets = ["DS_Measurements", "DS_Status"]
        self.domains["ICC2"] = icc2

        self._add_point("Bus_Voltage_kV", "ICC2", PointType.REAL_Q, 33.2, desc="Bus voltage")
        self._add_point("Load_MW", "ICC2", PointType.REAL_Q_TIME, 15.8, desc="Load active power")
        self._add_point("Load_MVAr", "ICC2", PointType.REAL_Q_TIME, 4.2, desc="Load reactive power")
        self._add_point(
            "Capacitor_Status", "ICC2", PointType.STATE_Q, 1, desc="Capacitor in service"
        )
        self._add_point(
            "Capacitor_Control", "ICC2", PointType.STATE, 0, writable=True, desc="Capacitor control"
        )

        # Capacitor - SBO device with full inhibit tag (locked out)
        self.control_points["ICC2/Capacitor_Control"] = ControlPoint(
            name="Capacitor_Control",
            domain="ICC2",
            is_sbo=True,
            state=DeviceState.IDLE,
            tag_value=TagValue.OPEN_AND_CLOSE_INHIBIT,
            tag_reason="Equipment fault - DO NOT OPERATE",
        )

        # Transfer sets for Block 2 (RBE)
        self.transfer_sets["VCC/TS_System"] = TransferSet(
            name="TS_System", domain="VCC", data_set="DS_System", interval=5000, rbe_enabled=True
        )
        self.transfer_sets["ICC1/TS_Measurements"] = TransferSet(
            name="TS_Measurements",
            domain="ICC1",
            data_set="DS_Measurements",
            interval=2000,
            rbe_enabled=True,
        )
        self.transfer_sets["ICC1/TS_Status"] = TransferSet(
            name="TS_Status",
            domain="ICC1",
            data_set="DS_Status",
            interval=0,
            rbe_enabled=True,  # Event-driven only
        )

        # Information Message stores for Block 4
        # VCC-scope operator messages
        vcc_im = IMTransfer(name="IM_OperatorMessages", domain="VCC", max_messages=100)
        vcc_im.messages = [
            InformationMessage(
                message_id="MSG001",
                content="System startup initiated",
                time_created=time.time() - 3600,
                originator="ControlCenter",
                status=IMStatus.ACTIVE,
                priority=3,
            ),
            InformationMessage(
                message_id="MSG002",
                content="All systems nominal",
                time_created=time.time() - 1800,
                originator="ControlCenter",
                status=IMStatus.ACTIVE,
                priority=5,
            ),
        ]
        self.im_stores["VCC/IM_OperatorMessages"] = vcc_im

        # ICC1 file transfer store
        icc1_im = IMTransfer(name="IM_FileTransfer", domain="ICC1", max_messages=50)
        icc1_im.messages = [
            InformationMessage(
                message_id="FILE001",
                content="Relay settings update v2.1 - Base64 data would go here",
                time_created=time.time() - 7200,
                originator="EngineeringWorkstation",
                status=IMStatus.ARCHIVED,
                priority=2,
            ),
        ]
        self.im_stores["ICC1/IM_FileTransfer"] = icc1_im

        # ICC1 alarm log store
        icc1_alarms = IMTransfer(name="IM_AlarmLog", domain="ICC1", max_messages=200)
        icc1_alarms.messages = [
            InformationMessage(
                message_id="ALM001",
                content="Overcurrent alarm on Feeder1 - 120% of rating",
                time_created=time.time() - 900,
                originator="ProtectionSystem",
                status=IMStatus.ACTIVE,
                priority=1,
            ),
            InformationMessage(
                message_id="ALM002",
                content="Undervoltage warning - 95% of nominal",
                time_created=time.time() - 600,
                originator="ProtectionSystem",
                status=IMStatus.ACTIVE,
                priority=2,
            ),
        ]
        self.im_stores["ICC1/IM_AlarmLog"] = icc1_alarms

        # Add IM store names to domain variables
        vcc.variables.append("IM_OperatorMessages")
        icc1.variables.extend(["IM_FileTransfer", "IM_AlarmLog"])

    def _add_point(
        self,
        name: str,
        domain: str,
        ptype: PointType,
        value: Any,
        writable: bool = False,
        desc: str = "",
    ):
        """Add a data point"""
        key = f"{domain}/{name}"
        self.data_points[key] = DataPoint(
            name=name,
            domain=domain,
            point_type=ptype,
            value=value,
            writable=writable,
            description=desc,
        )

    def _simulate_values(self):
        """Simulate changing values"""
        t = time.time()

        # Frequency varies around 50 Hz
        freq_point = self.data_points.get("VCC/Frequency_Hz")
        if freq_point:
            freq_point.value = round(
                50.0 + 0.05 * math.sin(t * 0.1) + random.uniform(-0.01, 0.01), 3
            )

        # Power values vary
        for key, point in self.data_points.items():
            if point.point_type in (PointType.REAL, PointType.REAL_Q, PointType.REAL_Q_TIME):
                if "MW" in point.name or "MVAr" in point.name:
                    base = point.value
                    variation = base * 0.05 * math.sin(t * 0.05 + hash(key) * 0.1)
                    noise = random.uniform(-base * 0.01, base * 0.01)
                    point.value = round(base + variation + noise, 2)
                elif "Voltage" in point.name:
                    base = point.value
                    point.value = round(base + random.uniform(-0.5, 0.5), 2)

        # Occasionally change quality (simulate telemetry issues)
        if random.random() < 0.02:  # 2% chance
            key = random.choice(list(self.data_points.keys()))
            point = self.data_points[key]
            if point.quality == Quality.GOOD:
                point.quality = random.choice([Quality.SUSPECT, Quality.HELD])
            else:
                point.quality = Quality.GOOD

        # Check for SBO timeouts
        self._check_sbo_timeouts()

    def _check_sbo_timeouts(self):
        """Check for SBO devices that have timed out"""
        current_time = time.time()
        for key, cp in self.control_points.items():
            if cp.state == DeviceState.ARMED and cp.armed_time:
                if current_time - cp.armed_time > self.sbo_timeout:
                    log.info(f"SBO timeout for {key} - returning to IDLE")
                    cp.state = DeviceState.IDLE
                    cp.check_back_id = None
                    cp.armed_time = None

    def _generate_check_back_id(self) -> int:
        """Generate unique CheckBackID for SBO operations"""
        self._check_back_id_counter += 1
        return self._check_back_id_counter

    def select_device(self, domain: str, device: str) -> Dict[str, Any]:
        """Select an SBO device (Block 5 operation)"""
        key = f"{domain}/{device}"
        cp = self.control_points.get(key)

        if not cp:
            return {"success": False, "error": "Device not found"}

        if not cp.is_sbo:
            return {"success": False, "error": "Device is Direct Control, not SBO"}

        # Check tag
        if cp.tag_value == TagValue.OPEN_AND_CLOSE_INHIBIT:
            return {"success": False, "error": f"Device tagged: {cp.tag_reason}"}

        # Generate CheckBackID and arm device
        cp.check_back_id = self._generate_check_back_id()
        cp.state = DeviceState.ARMED
        cp.armed_time = time.time()

        log.info(f"Device {key} selected, CheckBackID: {cp.check_back_id}")

        return {
            "success": True,
            "check_back_id": cp.check_back_id,
            "state": cp.state.name,
            "timeout": self.sbo_timeout,
        }

    def operate_device(
        self, domain: str, device: str, value: Any, check_back_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Operate a device (Block 5 operation)"""
        key = f"{domain}/{device}"
        cp = self.control_points.get(key)

        if not cp:
            return {"success": False, "error": "Device not found"}

        # Check tag for close operations
        if cp.tag_value == TagValue.OPEN_AND_CLOSE_INHIBIT:
            return {"success": False, "error": f"Device tagged: {cp.tag_reason}"}

        if cp.tag_value == TagValue.CLOSE_ONLY_INHIBIT and value:  # Close command
            return {"success": False, "error": "Device tagged: Close only inhibit"}

        if cp.is_sbo:
            # SBO device - verify CheckBackID
            if cp.state != DeviceState.ARMED:
                return {"success": False, "error": "Device not selected (IDLE state)"}

            if check_back_id is not None and check_back_id != cp.check_back_id:
                return {"success": False, "error": "CheckBackID mismatch"}

            # Check timeout
            if cp.armed_time and time.time() - cp.armed_time > self.sbo_timeout:
                cp.state = DeviceState.IDLE
                cp.check_back_id = None
                cp.armed_time = None
                return {"success": False, "error": "SBO timeout expired"}

        # Execute operation
        point_key = f"{domain}/{device}"
        if point_key in self.data_points:
            self.data_points[point_key].value = value
            log.info(f"Device {key} operated with value: {value}")

        # Return to IDLE
        cp.state = DeviceState.IDLE
        cp.check_back_id = None
        cp.armed_time = None

        return {"success": True, "value": value}

    def get_tag(self, domain: str, device: str) -> Dict[str, Any]:
        """Get tag value for a device (Block 5 operation)"""
        key = f"{domain}/{device}"
        cp = self.control_points.get(key)

        if not cp:
            return {"success": False, "error": "Device not found"}

        return {"success": True, "tag_value": cp.tag_value.name, "tag_reason": cp.tag_reason}

    def set_tag(self, domain: str, device: str, tag_value: str, reason: str = "") -> Dict[str, Any]:
        """Set tag value for a device (Block 5 operation)"""
        key = f"{domain}/{device}"
        cp = self.control_points.get(key)

        if not cp:
            return {"success": False, "error": "Device not found"}

        # Parse tag value
        tag_map = {
            "NO_TAG": TagValue.NO_TAG,
            "OPEN_AND_CLOSE_INHIBIT": TagValue.OPEN_AND_CLOSE_INHIBIT,
            "CLOSE_ONLY_INHIBIT": TagValue.CLOSE_ONLY_INHIBIT,
            "CLOSE_ONLY": TagValue.CLOSE_ONLY_INHIBIT,  # Alias
        }

        if tag_value.upper() not in tag_map:
            return {"success": False, "error": f"Invalid tag value: {tag_value}"}

        cp.tag_value = tag_map[tag_value.upper()]
        cp.tag_reason = reason

        log.info(f"Device {key} tag set to {cp.tag_value.name}: {reason}")

        return {"success": True, "tag_value": cp.tag_value.name, "reason": reason}

    def create_data_set(
        self, domain: str, name: str, members: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """Create a dynamic data set (Block 1 operation)"""
        key = f"{domain}/{name}"

        if key in self.dynamic_data_sets:
            return {"success": False, "error": "Data set already exists"}

        # Validate members exist
        for member in members:
            member_key = f"{member.get('domain', domain)}/{member.get('name', '')}"
            if member_key not in self.data_points:
                return {"success": False, "error": f"Variable not found: {member_key}"}

        self.dynamic_data_sets[key] = members
        log.info(f"Created data set {key} with {len(members)} members")

        return {"success": True, "name": key, "member_count": len(members)}

    def delete_data_set(self, domain: str, name: str) -> Dict[str, Any]:
        """Delete a dynamic data set (Block 1 operation)"""
        key = f"{domain}/{name}"

        if key not in self.dynamic_data_sets:
            return {"success": False, "error": "Data set not found"}

        del self.dynamic_data_sets[key]
        log.info(f"Deleted data set {key}")

        return {"success": True}

    def get_data_set_members(self, domain: str, name: str) -> Dict[str, Any]:
        """Get members of a data set (Block 1 operation)"""
        key = f"{domain}/{name}"

        # Check dynamic data sets first
        if key in self.dynamic_data_sets:
            return {"success": True, "members": self.dynamic_data_sets[key]}

        # Check predefined data sets
        domain_obj = self.domains.get(domain)
        if not domain_obj or name not in domain_obj.data_sets:
            return {"success": False, "error": "Data set not found"}

        # Return variables in the domain as members (simplified)
        members = [
            {"domain": domain, "name": var}
            for var in domain_obj.variables[:5]  # First 5 as example
        ]
        return {"success": True, "members": members}

    def get_data_value_type(self, domain: str, name: str) -> Dict[str, Any]:
        """Get type information for a data value (Block 1 operation)"""
        key = f"{domain}/{name}"
        point = self.data_points.get(key)

        if not point:
            return {"success": False, "error": "Variable not found"}

        # Map point type to type structure
        type_info = {"type_name": point.point_type.name, "deletable": False, "structure": []}

        # Build structure based on type
        if point.point_type in (PointType.REAL, PointType.REAL_Q, PointType.REAL_Q_TIME):
            type_info["structure"].append({"name": "Value", "type": "REAL"})
        elif point.point_type in (PointType.STATE, PointType.STATE_Q, PointType.STATE_Q_TIME):
            type_info["structure"].append({"name": "Value", "type": "STATE"})
        elif point.point_type in (
            PointType.DISCRETE,
            PointType.DISCRETE_Q,
            PointType.DISCRETE_Q_TIME,
        ):
            type_info["structure"].append({"name": "Value", "type": "DISCRETE"})

        # Add quality for _Q types
        if "_Q" in point.point_type.name:
            type_info["structure"].append({"name": "Quality", "type": "BITSTRING"})

        # Add timestamp for _TIME types
        if "TIME" in point.point_type.name:
            type_info["structure"].append({"name": "TimeStamp", "type": "UTC_TIME"})

        return {"success": True, **type_info}

    def _encode_ber_length(self, length: int) -> bytes:
        """Encode BER length"""
        if length < 0x80:
            return bytes([length])
        elif length < 0x100:
            return bytes([0x81, length])
        elif length < 0x10000:
            return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
        else:
            return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])

    def _encode_string(self, s: str) -> bytes:
        """Encode visible string"""
        data = s.encode("utf-8")
        return bytes([MMSTag.VISIBLE_STRING]) + self._encode_ber_length(len(data)) + data

    def _encode_integer(self, val: int) -> bytes:
        """Encode integer"""
        data = struct.pack(">i", val)
        return bytes([MMSTag.INTEGER]) + self._encode_ber_length(len(data)) + data

    def _encode_float(self, val: float) -> bytes:
        """Encode float"""
        data = struct.pack(">f", val)
        return bytes([MMSTag.FLOAT]) + self._encode_ber_length(len(data)) + data

    def _encode_boolean(self, val: bool) -> bytes:
        """Encode boolean"""
        return bytes([MMSTag.BOOLEAN, 0x01, 0xFF if val else 0x00])

    def _create_response(self, request: bytes) -> bytes:
        """Create response based on request type"""
        self._simulate_values()

        # Parse basic request structure
        if len(request) < 10:
            return self._create_initiate_response()

        # Check for different request types in the data
        req_str = request.decode("latin-1", errors="ignore").lower()

        # Domain list request
        if "getdomainnames" in req_str or len(request) < 50:
            return self._create_domain_list_response()

        # Variable list request
        if "getvariablelist" in req_str:
            return self._create_variable_list_response()

        # Read request
        if "read" in req_str:
            return self._create_read_response()

        # Default: return domain list
        return self._create_domain_list_response()

    def _create_initiate_response(self) -> bytes:
        """Create MMS initiate response"""
        # Simplified initiate response
        vendor = self._encode_string(self.vendor)
        model = self._encode_string(self.model)
        revision = self._encode_string(self.revision)

        content = vendor + model + revision

        response = (
            bytes([MMSTag.INITIATE_RESPONSE]) + self._encode_ber_length(len(content)) + content
        )
        return self._wrap_response(response)

    def _create_domain_list_response(self) -> bytes:
        """Create response with domain list"""
        content = b""

        # Bilateral table info
        blt_id = self._encode_string(self.bilateral_table_id)
        blt_count = self._encode_integer(self.bilateral_table_count)
        content += blt_id + blt_count

        # Domain names
        for domain_name, domain in self.domains.items():
            domain_data = self._encode_string(domain_name)
            is_vcc = self._encode_boolean(domain.is_vcc)
            var_count = self._encode_integer(len(domain.variables))
            ds_count = self._encode_integer(len(domain.data_sets))
            content += domain_data + is_vcc + var_count + ds_count

        response = (
            bytes([MMSTag.CONFIRMED_RESPONSE, 0x00])
            + self._encode_ber_length(len(content))
            + content
        )
        return self._wrap_response(response)

    def _create_variable_list_response(self) -> bytes:
        """Create response with variable list"""
        content = b""

        for key, point in self.data_points.items():
            name = self._encode_string(point.name)
            domain = self._encode_string(point.domain)
            ptype = self._encode_integer(point.point_type)

            # Encode value based on type
            if point.point_type in (PointType.STATE, PointType.STATE_Q, PointType.STATE_Q_TIME):
                value = self._encode_boolean(bool(point.value))
            elif point.point_type in (
                PointType.DISCRETE,
                PointType.DISCRETE_Q,
                PointType.DISCRETE_Q_TIME,
            ):
                value = self._encode_integer(int(point.value))
            else:
                value = self._encode_float(float(point.value))

            quality = self._encode_integer(point.quality)
            writable = self._encode_boolean(point.writable)

            content += name + domain + ptype + value + quality + writable

        response = (
            bytes([MMSTag.CONFIRMED_RESPONSE, 0x00])
            + self._encode_ber_length(len(content))
            + content
        )
        return self._wrap_response(response)

    def _create_read_response(self) -> bytes:
        """Create read response with data point values"""
        content = b""

        # Return first few points as example
        for key, point in list(self.data_points.items())[:10]:
            name = self._encode_string(f"{point.domain}/{point.name}")

            if point.point_type in (PointType.STATE, PointType.STATE_Q, PointType.STATE_Q_TIME):
                value = self._encode_boolean(bool(point.value))
            elif point.point_type in (
                PointType.DISCRETE,
                PointType.DISCRETE_Q,
                PointType.DISCRETE_Q_TIME,
            ):
                value = self._encode_integer(int(point.value))
            else:
                value = self._encode_float(float(point.value))

            quality = self._encode_string(point.quality.name)
            content += name + value + quality

        response = (
            bytes([MMSTag.CONFIRMED_RESPONSE, 0x00])
            + self._encode_ber_length(len(content))
            + content
        )
        return self._wrap_response(response)

    def _wrap_response(self, mms_data: bytes) -> bytes:
        """Wrap MMS data in session/presentation headers"""
        # Simplified ISO 8823 session layer
        # SPDU header (Session Protocol Data Unit)
        spdu_type = 0x0D  # DATA TRANSFER SPDU

        # Presentation layer (simplified)
        pres_header = bytes([0x61])  # Fully-encoded-data
        pres_header += self._encode_ber_length(len(mms_data))

        # Session header
        session_data = pres_header + mms_data
        session_header = bytes([spdu_type]) + self._encode_ber_length(len(session_data))

        return session_header + session_data

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle TASE.2 client connection"""
        client_addr = writer.get_extra_info("peername")
        log.info(f"TASE.2 client connected from {client_addr}")

        try:
            while True:
                # Read request
                data = await asyncio.wait_for(reader.read(4096), timeout=60.0)
                if not data:
                    break

                log.debug(f"Received {len(data)} bytes from {client_addr}")

                # Create and send response
                response = self._create_response(data)
                writer.write(response)
                await writer.drain()

                log.debug(f"Sent {len(response)} bytes to {client_addr}")

        except asyncio.TimeoutError:
            log.info(f"Client {client_addr} timed out")
        except ConnectionResetError:
            log.info(f"Client {client_addr} connection reset")
        except Exception as e:
            log.error(f"Error handling client {client_addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            log.info(f"TASE.2 client {client_addr} disconnected")

    async def start(self):
        """Start the TASE.2 server"""
        server = await asyncio.start_server(self.handle_client, self.host, self.port)

        log.info("=" * 60)
        log.info(f"Mock TASE.2/ICCP Server started on {self.host}:{self.port}")
        log.info("=" * 60)
        log.info(f"TASE.2 Version: {self.tase2_version['major']}.{self.tase2_version['minor']}")
        log.info(f"Bilateral Table ID: {self.bilateral_table_id}")
        log.info("")
        log.info("Supported Features (Conformance Blocks):")
        for block, enabled in self.supported_features.items():
            status = "ENABLED" if enabled else "disabled"
            log.info(f"  {block}: {status}")
        log.info("")
        log.info(f"Domains ({len(self.domains)}):")
        for name, domain in self.domains.items():
            dtype = "VCC" if domain.is_vcc else "ICC"
            log.info(
                f"  {dtype}: {name} ({len(domain.variables)} vars, {len(domain.data_sets)} datasets)"
            )
        log.info("")
        log.info(f"Data Points: {len(self.data_points)}")
        log.info(f"Transfer Sets: {len(self.transfer_sets)}")
        log.info(f"Control Points: {len(self.control_points)}")
        log.info("")
        log.info("Device Tags (Block 5):")
        tagged_count = 0
        for key, cp in self.control_points.items():
            if cp.tag_value != TagValue.NO_TAG:
                log.info(f"  {key}: {cp.tag_value.name} - {cp.tag_reason}")
                tagged_count += 1
        if tagged_count == 0:
            log.info("  (no tagged devices)")
        log.info("")
        log.info(f"SBO Timeout: {self.sbo_timeout}s")
        log.info("=" * 60)

        async with server:
            await server.serve_forever()


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Mock TASE.2/ICCP Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", "-p", type=int, default=102, help="Port (default: 102)")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    server = TASE2Server(host=args.host, port=args.port)

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        log.info("Server stopped")


if __name__ == "__main__":
    main()
