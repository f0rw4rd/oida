#!/usr/bin/env python3
"""
FreeTASE2 Mock Server - IEC 60870-6-503 Compliant

TASE.2/ICCP server implementation using libiec61850 Python bindings.
Implements Blocks 1, 2, and 5 per IEC 60870-6-503 specification.

Block 1: Basic data exchange (Get/Set Data Value, Data Sets)
Block 2: Report-by-Exception (Transfer Sets, InformationReport)
Block 5: Device Control (Select-Before-Operate, Direct Control, Tagging)

Usage:
    python tase2_server_spec.py --port 102 --debug

Requirements:
    - libiec61850 compiled with Python bindings
    - FreeTase2 abstractions (optional)
"""

import argparse
import logging
import signal
import sys
import time
import math
import random
import threading
from typing import Dict, Optional, Any
from dataclasses import dataclass

# Local imports
from tase2_types import (
    IndicationPointType,
    StateValue,
    DataFlags,
    Quality,
    TimeStamp,
    ControlPointType,
    CommandValue,
    TagValue,
    DeviceState,
    DeviceClass,
    DSConditions,
    TransferSetStatus,
    SupportedFeatures,
    IndicationPoint,
    ControlPoint,
    DataSetTransferSet,
    DataSet,
    MmsDataAccessError,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
log = logging.getLogger("FreeTASE2")

# Try to import libiec61850
try:
    import iec61850

    HAS_LIBIEC61850 = True
    log.info("libiec61850 Python bindings loaded")
except ImportError as e:
    HAS_LIBIEC61850 = False
    log.warning(f"libiec61850 not available: {e}")
    log.warning("Server will not start without libiec61850")


# =============================================================================
# TASE.2 Server Configuration
# =============================================================================


@dataclass
class TASE2ServerConfig:
    """Server configuration"""

    host: str = "0.0.0.0"
    port: int = 102
    vendor: str = "OIDA"
    model: str = "FreeTASE2"
    revision: str = "1.0.0"
    bilateral_table_id: str = "BLT_UTILITY_001"
    tase2_version: tuple = (2000, 8)
    supported_features: SupportedFeatures = (
        SupportedFeatures.BLOCK_1 | SupportedFeatures.BLOCK_2 | SupportedFeatures.BLOCK_5
    )
    sbo_timeout: int = 30  # seconds


# =============================================================================
# Data Model
# =============================================================================


class TASE2DataModel:
    """TASE.2 Data Model with VCC and ICC domains

    Implements the Virtual Control Center (VCC) model per IEC 60870-6-503.
    """

    def __init__(self, config: TASE2ServerConfig):
        self.config = config

        # VCC-scope variables
        self.bilateral_table_id = config.bilateral_table_id
        self.tase2_version = config.tase2_version
        self.supported_features = config.supported_features

        # ICC domains
        self.domains: Dict[str, Dict[str, Any]] = {}

        # Data points by full path (domain/name)
        self.indication_points: Dict[str, IndicationPoint] = {}
        self.control_points: Dict[str, ControlPoint] = {}

        # Data sets
        self.data_sets: Dict[str, DataSet] = {}

        # Transfer sets (Block 2)
        self.transfer_sets: Dict[str, DataSetTransferSet] = {}
        self.next_transfer_set_index = 0

        # Initialize model
        self._init_domains()
        self._init_data_points()
        self._init_control_points()
        self._init_data_sets()
        self._init_transfer_sets()

    def _init_domains(self):
        """Initialize ICC domains"""
        # VCC domain (system-wide)
        self.domains["VCC"] = {"description": "Virtual Control Center", "scope": "VMD"}

        # ICC1 - Substation 1
        self.domains["ICC1"] = {"description": "Substation North", "scope": "Domain"}

        # ICC2 - Substation 2
        self.domains["ICC2"] = {"description": "Substation South", "scope": "Domain"}

    def _init_data_points(self):
        """Initialize indication points per IEC 60870-6-802"""

        # VCC scope - System-wide data
        self._add_point(
            "VCC",
            "System_Status",
            IndicationPointType.DATA_STATE_Q,
            StateValue.ON,
            "System operational status",
        )
        self._add_point(
            "VCC",
            "Total_Generation_MW",
            IndicationPointType.DATA_REAL_Q_TIMETAG,
            2500.5,
            "Total system generation",
        )
        self._add_point(
            "VCC",
            "Total_Load_MW",
            IndicationPointType.DATA_REAL_Q_TIMETAG,
            2450.3,
            "Total system load",
        )
        self._add_point(
            "VCC",
            "System_Frequency_Hz",
            IndicationPointType.DATA_REAL_Q_TIMETAG,
            50.02,
            "System frequency",
        )
        self._add_point(
            "VCC",
            "Tie_Line_Flow_MW",
            IndicationPointType.DATA_REAL_Q,
            50.2,
            "Inter-area tie line flow",
        )
        self._add_point(
            "VCC", "ACE_MW", IndicationPointType.DATA_REAL_Q, -2.5, "Area Control Error"
        )

        # ICC1 - Substation 1 (132kV)
        self._add_point(
            "ICC1", "Bus_Voltage_kV", IndicationPointType.DATA_REAL_Q_TIMETAG, 132.5, "Bus voltage"
        )
        self._add_point(
            "ICC1",
            "Feeder1_MW",
            IndicationPointType.DATA_REAL_Q_TIMETAG,
            45.2,
            "Feeder 1 active power",
        )
        self._add_point(
            "ICC1",
            "Feeder1_MVAr",
            IndicationPointType.DATA_REAL_Q_TIMETAG,
            12.3,
            "Feeder 1 reactive power",
        )
        self._add_point(
            "ICC1",
            "Feeder2_MW",
            IndicationPointType.DATA_REAL_Q_TIMETAG,
            38.7,
            "Feeder 2 active power",
        )
        self._add_point(
            "ICC1",
            "Feeder2_MVAr",
            IndicationPointType.DATA_REAL_Q_TIMETAG,
            8.9,
            "Feeder 2 reactive power",
        )
        self._add_point(
            "ICC1",
            "Breaker1_Status",
            IndicationPointType.DATA_STATE_Q_TIMETAG,
            StateValue.ON,
            "Circuit breaker 1 status",
        )
        self._add_point(
            "ICC1",
            "Breaker2_Status",
            IndicationPointType.DATA_STATE_Q_TIMETAG,
            StateValue.ON,
            "Circuit breaker 2 status",
        )
        self._add_point(
            "ICC1",
            "Transformer_Tap",
            IndicationPointType.DATA_DISCRETE_Q,
            5,
            "Transformer tap position",
        )
        self._add_point(
            "ICC1", "Alarm_Count", IndicationPointType.DATA_DISCRETE_Q, 0, "Active alarm count"
        )

        # ICC2 - Substation 2 (33kV)
        self._add_point(
            "ICC2", "Bus_Voltage_kV", IndicationPointType.DATA_REAL_Q_TIMETAG, 33.2, "Bus voltage"
        )
        self._add_point(
            "ICC2", "Load_MW", IndicationPointType.DATA_REAL_Q_TIMETAG, 15.8, "Load active power"
        )
        self._add_point(
            "ICC2", "Load_MVAr", IndicationPointType.DATA_REAL_Q_TIMETAG, 4.2, "Load reactive power"
        )
        self._add_point(
            "ICC2", "Power_Factor", IndicationPointType.DATA_REAL_Q, 0.966, "Power factor"
        )
        self._add_point(
            "ICC2",
            "Capacitor_Status",
            IndicationPointType.DATA_STATE_Q_TIMETAG,
            StateValue.ON,
            "Capacitor bank status",
        )
        self._add_point(
            "ICC2",
            "Capacitor_MVAr",
            IndicationPointType.DATA_REAL_Q,
            5.0,
            "Capacitor reactive power",
        )

    def _add_point(
        self, domain: str, name: str, ptype: IndicationPointType, value: Any, description: str = ""
    ):
        """Add an indication point"""
        full_name = f"{domain}/{name}"
        self.indication_points[full_name] = IndicationPoint(
            name=full_name,
            point_type=ptype,
            value=value,
            quality=Quality(DataFlags.VALIDITY_GOOD | DataFlags.SOURCE_TELEMETERED),
            timestamp=TimeStamp.now()
            if ptype
            in (
                IndicationPointType.DATA_REAL_Q_TIMETAG,
                IndicationPointType.DATA_STATE_Q_TIMETAG,
                IndicationPointType.DATA_DISCRETE_Q_TIMETAG,
            )
            else None,
        )

    def _init_control_points(self):
        """Initialize control points (Block 5)"""

        # ICC1 - Circuit breaker controls (SBO)
        self.control_points["ICC1/Breaker1_Control"] = ControlPoint(
            name="ICC1/Breaker1_Control",
            control_type=ControlPointType.COMMAND,
            device_class=DeviceClass.SBO,
            tag=TagValue.CLOSE_ONLY_INHIBIT,
            tag_reason="Scheduled maintenance",
            check_back_id=0x1001,
            timeout_seconds=self.config.sbo_timeout,
        )

        self.control_points["ICC1/Breaker2_Control"] = ControlPoint(
            name="ICC1/Breaker2_Control",
            control_type=ControlPointType.COMMAND,
            device_class=DeviceClass.SBO,
            tag=TagValue.NO_TAG,
            check_back_id=0x1002,
            timeout_seconds=self.config.sbo_timeout,
        )

        # ICC1 - Tap changer (Direct control setpoint)
        self.control_points["ICC1/Tap_Setpoint"] = ControlPoint(
            name="ICC1/Tap_Setpoint",
            control_type=ControlPointType.SETPOINT_DISCRETE,
            device_class=DeviceClass.DIRECT,
            setpoint_value=5,
            tag=TagValue.NO_TAG,
        )

        # ICC2 - Capacitor bank control (SBO)
        self.control_points["ICC2/Capacitor_Control"] = ControlPoint(
            name="ICC2/Capacitor_Control",
            control_type=ControlPointType.COMMAND,
            device_class=DeviceClass.SBO,
            tag=TagValue.OPEN_AND_CLOSE_INHIBIT,
            tag_reason="Equipment fault - investigation in progress",
            check_back_id=0x2001,
            timeout_seconds=self.config.sbo_timeout,
        )

        # ICC2 - Voltage setpoint (Direct control)
        self.control_points["ICC2/Voltage_Setpoint"] = ControlPoint(
            name="ICC2/Voltage_Setpoint",
            control_type=ControlPointType.SETPOINT_REAL,
            device_class=DeviceClass.DIRECT,
            setpoint_value=33.0,
            tag=TagValue.NO_TAG,
        )

    def _init_data_sets(self):
        """Initialize data sets (Named Variable Lists)"""

        # VCC scope data sets
        self.data_sets["VCC/DS_System"] = DataSet(
            name="VCC/DS_System",
            scope="VCC",
            members=[
                "VCC/System_Status",
                "VCC/Total_Generation_MW",
                "VCC/Total_Load_MW",
                "VCC/System_Frequency_Hz",
                "VCC/ACE_MW",
            ],
            deletable=False,
        )

        # ICC1 scope data sets
        self.data_sets["ICC1/DS_Voltages"] = DataSet(
            name="ICC1/DS_Voltages",
            scope="ICC",
            members=[
                "ICC1/Bus_Voltage_kV",
            ],
            deletable=True,
        )

        self.data_sets["ICC1/DS_Feeders"] = DataSet(
            name="ICC1/DS_Feeders",
            scope="ICC",
            members=[
                "ICC1/Feeder1_MW",
                "ICC1/Feeder1_MVAr",
                "ICC1/Feeder2_MW",
                "ICC1/Feeder2_MVAr",
            ],
            deletable=True,
        )

        self.data_sets["ICC1/DS_Status"] = DataSet(
            name="ICC1/DS_Status",
            scope="ICC",
            members=[
                "ICC1/Breaker1_Status",
                "ICC1/Breaker2_Status",
                "ICC1/Transformer_Tap",
            ],
            deletable=True,
        )

        # ICC2 scope data sets
        self.data_sets["ICC2/DS_Load"] = DataSet(
            name="ICC2/DS_Load",
            scope="ICC",
            members=[
                "ICC2/Bus_Voltage_kV",
                "ICC2/Load_MW",
                "ICC2/Load_MVAr",
                "ICC2/Power_Factor",
            ],
            deletable=True,
        )

    def _init_transfer_sets(self):
        """Initialize transfer sets (Block 2)"""

        # Create pool of available transfer sets per domain
        for domain in ["VCC", "ICC1", "ICC2"]:
            for i in range(1, 6):  # 5 transfer sets per domain
                ts_name = f"{domain}/TS_{i:02d}"
                self.transfer_sets[ts_name] = DataSetTransferSet(
                    name=ts_name,
                    status=TransferSetStatus.DISABLED,
                )

    def get_next_transfer_set(self, domain: str) -> Optional[str]:
        """Get next available (disabled) transfer set name"""
        for name, ts in self.transfer_sets.items():
            if name.startswith(f"{domain}/") and ts.status == TransferSetStatus.DISABLED:
                return name
        return None

    def simulate_values(self):
        """Update simulated values"""
        t = time.time()

        for name, point in self.indication_points.items():
            # Update timestamp
            if point.has_timestamp():
                point.timestamp = TimeStamp.now()

            # Simulate based on type
            if "Frequency" in name:
                # Frequency varies around 50 Hz
                point.value = round(
                    50.0 + 0.05 * math.sin(t * 0.1) + random.uniform(-0.01, 0.01), 3
                )
            elif "MW" in name or "MVAr" in name:
                # Power varies by ~2%
                base = point.value
                variation = base * 0.02 * math.sin(t * 0.05 + hash(name) * 0.1)
                point.value = round(base + variation + random.uniform(-0.5, 0.5), 2)
            elif "Voltage" in name:
                # Voltage varies slightly
                base = point.value
                point.value = round(base + random.uniform(-0.2, 0.2), 2)
            elif "ACE" in name:
                # ACE varies around 0
                point.value = round(random.uniform(-5, 5), 2)
            elif "Power_Factor" in name:
                # PF varies slightly
                point.value = round(0.95 + random.uniform(-0.02, 0.02), 3)


# =============================================================================
# libiec61850 Server Implementation
# =============================================================================


class TASE2Server:
    """TASE.2 Server using libiec61850

    Implements IEC 60870-6-503 TASE.2 protocol over MMS.
    """

    def __init__(self, config: TASE2ServerConfig = None):
        self.config = config or TASE2ServerConfig()
        self.data_model = TASE2DataModel(self.config)

        self.server = None
        self.model = None
        self.running = False
        self.simulation_thread = None
        self.transfer_thread = None
        self.stop_event = threading.Event()

        # SBO timers
        self.sbo_timers: Dict[str, threading.Timer] = {}

    def _create_ied_model(self):
        """Create IED model for libiec61850

        Maps TASE.2 objects to MMS/IEC 61850 model:
        - VCC -> VMD (unnamed domain)
        - ICC domains -> MMS Domains
        - Data Values -> Named Variables
        - Data Sets -> Named Variable Lists
        """
        if not HAS_LIBIEC61850:
            raise RuntimeError("libiec61850 not available")

        # Create model with vendor info
        self.model = iec61850.IedModel_create(self.config.model)

        # Add VCC-scope variables (VMD-specific)
        self._add_vcc_variables()

        # Add ICC domains and their variables
        for domain_name in self.data_model.domains:
            if domain_name != "VCC":
                self._add_domain(domain_name)

        return self.model

    def _add_vcc_variables(self):
        """Add VCC-scope (VMD-specific) variables"""
        # These are special TASE.2 variables accessible without domain

        # Create a logical device for VCC scope
        ld = iec61850.LogicalDevice_create("VCC", self.model)
        ln = iec61850.LogicalNode_create("LLN0", ld)

        # Supported_Features - BitString
        # TASE.2_Version - Structure
        # Bilateral_Table_ID - VisibleString

        # Add indication points for VCC domain
        for name, point in self.data_model.indication_points.items():
            if name.startswith("VCC/"):
                var_name = name.split("/")[1]
                self._add_data_object(ln, var_name, point)

    def _add_domain(self, domain_name: str):
        """Add ICC domain with its variables"""
        ld = iec61850.LogicalDevice_create(domain_name, self.model)
        ln = iec61850.LogicalNode_create("LLN0", ld)

        # Add indication points
        for name, point in self.data_model.indication_points.items():
            if name.startswith(f"{domain_name}/"):
                var_name = name.split("/")[1]
                self._add_data_object(ln, var_name, point)

        # Add control points (Block 5)
        for name, cp in self.data_model.control_points.items():
            if name.startswith(f"{domain_name}/"):
                var_name = name.split("/")[1]
                self._add_control_object(ln, var_name, cp)

    def _add_data_object(self, ln, name: str, point: IndicationPoint):
        """Add a data object to the model"""
        # Convert LogicalNode to ModelNode* for SWIG type system
        ln_modelnode = iec61850.toModelNode(ln)
        do = iec61850.DataObject_create(name, ln_modelnode, 0)
        do_modelnode = iec61850.toModelNode(do)

        # Add value attribute based on type
        # DataAttribute_create signature: (name, parent, type, fc, triggerOptions, arrayElements, sAddr)
        if point.point_type in (
            IndicationPointType.DATA_REAL,
            IndicationPointType.DATA_REAL_Q,
            IndicationPointType.DATA_REAL_Q_TIMETAG,
        ):
            iec61850.DataAttribute_create(
                "mag", do_modelnode, iec61850.IEC61850_FLOAT32, iec61850.IEC61850_FC_MX, 0, 0, 0
            )
        elif point.point_type in (
            IndicationPointType.DATA_STATE,
            IndicationPointType.DATA_STATE_Q,
            IndicationPointType.DATA_STATE_Q_TIMETAG,
        ):
            iec61850.DataAttribute_create(
                "stVal", do_modelnode, iec61850.IEC61850_INT32, iec61850.IEC61850_FC_ST, 0, 0, 0
            )
        elif point.point_type in (
            IndicationPointType.DATA_DISCRETE,
            IndicationPointType.DATA_DISCRETE_Q,
            IndicationPointType.DATA_DISCRETE_Q_TIMETAG,
        ):
            iec61850.DataAttribute_create(
                "stVal", do_modelnode, iec61850.IEC61850_INT32, iec61850.IEC61850_FC_ST, 0, 0, 0
            )

        # Add quality if present
        if point.has_quality():
            iec61850.DataAttribute_create(
                "q", do_modelnode, iec61850.IEC61850_QUALITY, iec61850.IEC61850_FC_ST, 0, 0, 0
            )

        # Add timestamp if present
        if point.has_timestamp():
            iec61850.DataAttribute_create(
                "t", do_modelnode, iec61850.IEC61850_TIMESTAMP, iec61850.IEC61850_FC_ST, 0, 0, 0
            )

    def _add_control_object(self, ln, name: str, cp: ControlPoint):
        """Add a control object to the model (Block 5)"""
        # Convert LogicalNode to ModelNode* for SWIG type system
        ln_modelnode = iec61850.toModelNode(ln)
        do = iec61850.DataObject_create(name, ln_modelnode, 0)
        do_modelnode = iec61850.toModelNode(do)

        # DataAttribute_create signature: (name, parent, type, fc, triggerOptions, arrayElements, sAddr)
        if cp.control_type == ControlPointType.COMMAND:
            # Binary command
            iec61850.DataAttribute_create(
                "ctlVal", do_modelnode, iec61850.IEC61850_BOOLEAN, iec61850.IEC61850_FC_CO, 0, 0, 0
            )
        else:
            # Setpoint
            iec61850.DataAttribute_create(
                "setVal", do_modelnode, iec61850.IEC61850_FLOAT32, iec61850.IEC61850_FC_CO, 0, 0, 0
            )

        # SBO check-back ID
        if cp.device_class == DeviceClass.SBO:
            sbo_name = f"{name}_SBO"
            sbo_do = iec61850.DataObject_create(sbo_name, ln_modelnode, 0)
            sbo_do_modelnode = iec61850.toModelNode(sbo_do)
            iec61850.DataAttribute_create(
                "ctlVal", sbo_do_modelnode, iec61850.IEC61850_INT32, iec61850.IEC61850_FC_CO, 0, 0, 0
            )

        # Tag value
        tag_name = f"{name}_TAG"
        tag_do = iec61850.DataObject_create(tag_name, ln_modelnode, 0)
        tag_do_modelnode = iec61850.toModelNode(tag_do)
        iec61850.DataAttribute_create(
            "tagVal", tag_do_modelnode, iec61850.IEC61850_INT32, iec61850.IEC61850_FC_ST, 0, 0, 0
        )
        iec61850.DataAttribute_create(
            "tagReason", tag_do_modelnode, iec61850.IEC61850_VISIBLE_STRING_255, iec61850.IEC61850_FC_ST, 0, 0, 0
        )

    def _simulation_loop(self):
        """Background thread for value simulation"""
        while not self.stop_event.is_set():
            self.data_model.simulate_values()

            # Update server values
            if self.server:
                try:
                    iec61850.IedServer_lockDataModel(self.server)
                    # Update values in model...
                    iec61850.IedServer_unlockDataModel(self.server)
                except Exception as e:
                    log.debug(f"Value update error: {e}")

            self.stop_event.wait(1.0)

    def _transfer_loop(self):
        """Background thread for transfer set reporting (Block 2)"""
        while not self.stop_event.is_set():
            current_time = time.time()

            for name, ts in self.data_model.transfer_sets.items():
                if ts.status != TransferSetStatus.ENABLED:
                    continue

                # Check interval timeout
                if ts.transmission_pars.interval > 0:
                    last_time = ts.last_report_time.seconds if ts.last_report_time else 0
                    if current_time - last_time >= ts.transmission_pars.interval:
                        self._send_transfer_report(ts)

            self.stop_event.wait(0.5)

    def _send_transfer_report(self, ts: DataSetTransferSet):
        """Send transfer report (InformationReport) for a transfer set"""
        if not ts.data_set_name or ts.data_set_name not in self.data_model.data_sets:
            return

        ds = self.data_model.data_sets[ts.data_set_name]
        ts.last_report_time = TimeStamp.now()
        ts.conditions_detected = DSConditions.INTERVAL_TIMEOUT

        log.debug(f"Transfer Report: {ts.name} -> {ts.data_set_name}")

        # In a real implementation, this would send an MMS InformationReport
        # using iec61850.IedServer_sendInformationReport()

    def _handle_select(self, device_name: str, client_id: str) -> tuple:
        """Handle Select operation (Block 5 SBO)

        Returns (success, check_back_id or error_code)
        """
        if device_name not in self.data_model.control_points:
            return (False, MmsDataAccessError.OBJECT_NON_EXISTENT)

        cp = self.data_model.control_points[device_name]

        # Check device class
        if cp.device_class != DeviceClass.SBO:
            return (False, MmsDataAccessError.OBJECT_ACCESS_UNSUPPORTED)

        # Check tag
        if cp.tag == TagValue.OPEN_AND_CLOSE_INHIBIT:
            return (False, MmsDataAccessError.TEMPORARILY_UNAVAILABLE)

        # Check state
        if cp.state == DeviceState.ARMED:
            return (False, MmsDataAccessError.TEMPORARILY_UNAVAILABLE)

        # Select the device
        cp.state = DeviceState.ARMED
        cp.selected_by = client_id

        # Start timeout timer
        self._start_sbo_timer(device_name)

        log.info(
            f"Device {device_name} selected by {client_id}, CheckBackID=0x{cp.check_back_id:04X}"
        )

        return (True, cp.check_back_id)

    def _handle_operate(self, device_name: str, command: Any, client_id: str) -> tuple:
        """Handle Operate operation (Block 5)

        Returns (success, error_code if failed)
        """
        if device_name not in self.data_model.control_points:
            return (False, MmsDataAccessError.OBJECT_NON_EXISTENT)

        cp = self.data_model.control_points[device_name]

        # Check tag
        if cp.tag == TagValue.OPEN_AND_CLOSE_INHIBIT:
            return (False, MmsDataAccessError.TEMPORARILY_UNAVAILABLE)

        if cp.tag == TagValue.CLOSE_ONLY_INHIBIT:
            # Check if this is a close command
            if cp.control_type == ControlPointType.COMMAND and command == CommandValue.CLOSE:
                return (False, MmsDataAccessError.TEMPORARILY_UNAVAILABLE)

        # For SBO devices, check selection
        if cp.device_class == DeviceClass.SBO:
            if cp.state != DeviceState.ARMED:
                return (False, MmsDataAccessError.TEMPORARILY_UNAVAILABLE)
            if cp.selected_by != client_id:
                return (False, MmsDataAccessError.TEMPORARILY_UNAVAILABLE)

            # Cancel timeout timer
            self._cancel_sbo_timer(device_name)

        # Execute command
        log.info(f"Device {device_name} operated: {command}")

        # Reset state
        cp.state = DeviceState.IDLE
        cp.selected_by = None

        # Update corresponding indication point
        status_point = device_name.replace("_Control", "_Status")
        if status_point in self.data_model.indication_points:
            if cp.control_type == ControlPointType.COMMAND:
                new_state = StateValue.ON if command == CommandValue.CLOSE else StateValue.OFF
                self.data_model.indication_points[status_point].value = new_state
                self.data_model.indication_points[status_point].timestamp = TimeStamp.now()

        return (True, None)

    def _start_sbo_timer(self, device_name: str):
        """Start SBO timeout timer"""
        self._cancel_sbo_timer(device_name)

        cp = self.data_model.control_points[device_name]

        def timeout_callback():
            log.warning(f"SBO timeout for {device_name}")
            cp.state = DeviceState.IDLE
            cp.selected_by = None

        timer = threading.Timer(cp.timeout_seconds, timeout_callback)
        timer.daemon = True
        timer.start()
        self.sbo_timers[device_name] = timer

    def _cancel_sbo_timer(self, device_name: str):
        """Cancel SBO timeout timer"""
        if device_name in self.sbo_timers:
            self.sbo_timers[device_name].cancel()
            del self.sbo_timers[device_name]

    def start(self):
        """Start the TASE.2 server"""
        log.info("=" * 70)
        log.info("FreeTASE2 Mock Server - IEC 60870-6-503 Compliant")
        log.info("=" * 70)
        log.info(f"Vendor: {self.config.vendor}")
        log.info(f"Model: {self.config.model}")
        log.info(f"Revision: {self.config.revision}")
        log.info(f"Port: {self.config.port}")
        log.info("-" * 70)
        log.info(f"Bilateral Table ID: {self.config.bilateral_table_id}")
        log.info(f"TASE.2 Version: {self.config.tase2_version[0]}.{self.config.tase2_version[1]}")
        log.info(f"Supported Features: 0x{int(self.config.supported_features):03X}")
        log.info(
            f"  Block 1 (Basic): {'Yes' if self.config.supported_features & SupportedFeatures.BLOCK_1 else 'No'}"
        )
        log.info(
            f"  Block 2 (RBE):   {'Yes' if self.config.supported_features & SupportedFeatures.BLOCK_2 else 'No'}"
        )
        log.info(
            f"  Block 5 (Ctrl):  {'Yes' if self.config.supported_features & SupportedFeatures.BLOCK_5 else 'No'}"
        )
        log.info("-" * 70)
        log.info(f"Domains: {', '.join(self.data_model.domains.keys())}")
        log.info(f"Indication Points: {len(self.data_model.indication_points)}")
        log.info(f"Control Points: {len(self.data_model.control_points)}")
        log.info(f"Data Sets: {len(self.data_model.data_sets)}")
        log.info(f"Transfer Sets: {len(self.data_model.transfer_sets)}")
        log.info("=" * 70)

        if not HAS_LIBIEC61850:
            log.error("Cannot start: libiec61850 not available")
            log.error("Please ensure libiec61850 is compiled with Python bindings")
            sys.exit(1)

        try:
            # Create IED model
            self._create_ied_model()

            # Create and start server
            self.server = iec61850.IedServer_create(self.model)
            iec61850.IedServer_start(self.server, self.config.port)

            log.info(f"MMS/TASE.2 server listening on port {self.config.port}")

        except Exception as e:
            log.error(f"Failed to start server: {e}")
            sys.exit(1)

        # Start background threads
        self.running = True
        self.simulation_thread = threading.Thread(target=self._simulation_loop, daemon=True)
        self.simulation_thread.start()

        self.transfer_thread = threading.Thread(target=self._transfer_loop, daemon=True)
        self.transfer_thread.start()

        # Wait for shutdown
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

        self.stop()

    def stop(self):
        """Stop the server"""
        log.info("Shutting down...")
        self.running = False
        self.stop_event.set()

        # Cancel all SBO timers
        for timer in self.sbo_timers.values():
            timer.cancel()
        self.sbo_timers.clear()

        # Stop threads
        if self.simulation_thread:
            self.simulation_thread.join(timeout=2.0)
        if self.transfer_thread:
            self.transfer_thread.join(timeout=2.0)

        # Stop server
        if self.server:
            iec61850.IedServer_stop(self.server)
            iec61850.IedServer_destroy(self.server)

        log.info("Server stopped")


# =============================================================================
# Main Entry Point
# =============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="FreeTASE2 Mock Server - IEC 60870-6-503 Compliant"
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", "-p", type=int, default=102, help="Port (default: 102)")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug logging")
    parser.add_argument("--vendor", default="OIDA", help="Vendor name")
    parser.add_argument("--model", default="FreeTASE2", help="Model name")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Handle signals
    def signal_handler(sig, frame):
        log.info("Received shutdown signal")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Create config
    config = TASE2ServerConfig(
        host=args.host,
        port=args.port,
        vendor=args.vendor,
        model=args.model,
    )

    # Start server
    server = TASE2Server(config)
    server.start()


if __name__ == "__main__":
    main()
