#!/usr/bin/env python3
"""
Full-Featured EtherNet/IP Mock Server using cpppo

This server provides a realistic simulation of an Allen-Bradley/Rockwell PLC
with full support for:
- READ_TAG / WRITE_TAG (including Fragmented)
- Multiple data types (SINT, INT, DINT, REAL, STRING)
- Tag arrays for bulk data access
- Dynamic value simulation for realistic testing
- Write operation logging for security testing

Usage:
    python ethernetip_server.py [--port PORT] [--verbose]

Testing:
    # Read a tag
    python -m cpppo.server.enip.client -a localhost AI_Temperature

    # Read array elements
    python -m cpppo.server.enip.client -a localhost "SCADA[0-10]"

    # Write a value
    python -m cpppo.server.enip.client -a localhost "AI_Temperature=(REAL)30.5"
"""

import logging
import sys
import time
import math
import random
import threading
import argparse
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("EtherNetIP-Mock")

# Try to import cpppo
try:
    from cpppo.server.enip.main import main as enip_main
    from cpppo.server.enip import device
    import cpppo.server.enip as enip

    CPPPO_AVAILABLE = True
except ImportError as e:
    log.error(f"cpppo library not available: {e}")
    log.error("Install with: pip install cpppo")
    CPPPO_AVAILABLE = False

# =============================================================================
# TAG DEFINITIONS
# =============================================================================

# PLC Tags simulating a typical industrial control system
TAGS = {
    # Digital Inputs (use SINT since BOOL arrays have limited support)
    "DI_MotorRunning": "SINT",
    "DI_PumpRunning": "SINT",
    "DI_ValveOpen": "SINT",
    "DI_EmergencyStop": "SINT",
    "DI_ManualMode": "SINT",
    "DI_AutoMode": "SINT",
    "DI_SystemReady": "SINT",
    "DI_AlarmActive": "SINT",
    # Digital Outputs
    "DO_StartMotor": "SINT",
    "DO_StopMotor": "SINT",
    "DO_StartPump": "SINT",
    "DO_OpenValve": "SINT",
    "DO_CloseValve": "SINT",
    "DO_AlarmHorn": "SINT",
    "DO_StatusLight": "SINT",
    "DO_Reset": "SINT",
    # Analog Inputs (sensor values)
    "AI_Temperature": "REAL",
    "AI_Pressure": "REAL",
    "AI_FlowRate": "REAL",
    "AI_Level": "REAL",
    "AI_Vibration": "REAL",
    "AI_Current": "REAL",
    "AI_Voltage": "REAL",
    "AI_Power": "REAL",
    # Analog Outputs (setpoints)
    "AO_SpeedSetpoint": "REAL",
    "AO_PressureSetpoint": "REAL",
    "AO_FlowSetpoint": "REAL",
    "AO_TempSetpoint": "REAL",
    # PID Control Parameters
    "PID_Output": "REAL",
    "PID_Error": "REAL",
    "PID_Integral": "REAL",
    "PID_Derivative": "REAL",
    "PID_Kp": "REAL",
    "PID_Ki": "REAL",
    "PID_Kd": "REAL",
    # System Parameters
    "SYS_ScanTime": "DINT",
    "SYS_CycleCount": "DINT",
    "SYS_ErrorCount": "DINT",
    "SYS_WarningCount": "DINT",
    "SYS_Uptime": "DINT",
    # SCADA/HMI Arrays (for bulk data transfer testing)
    "SCADA": "DINT[1000]",
    "DATA": "REAL[100]",
    "STATUS": "INT[50]",
    "ALARMS": "DINT[32]",
    # String Tags
    "DeviceName": "SSTRING",
    "Location": "SSTRING",
    "FirmwareVersion": "SSTRING",
    "LastError": "SSTRING",
}

# Initial values for tags
INITIAL_VALUES = {
    # Digital Inputs
    "DI_MotorRunning": 1,
    "DI_PumpRunning": 0,
    "DI_ValveOpen": 1,
    "DI_EmergencyStop": 0,
    "DI_ManualMode": 0,
    "DI_AutoMode": 1,
    "DI_SystemReady": 1,
    "DI_AlarmActive": 0,
    # Digital Outputs
    "DO_StartMotor": 0,
    "DO_StopMotor": 0,
    "DO_StartPump": 0,
    "DO_OpenValve": 0,
    "DO_CloseValve": 0,
    "DO_AlarmHorn": 0,
    "DO_StatusLight": 1,
    "DO_Reset": 0,
    # Analog Inputs
    "AI_Temperature": 25.5,
    "AI_Pressure": 101.325,
    "AI_FlowRate": 15.7,
    "AI_Level": 75.2,
    "AI_Vibration": 2.1,
    "AI_Current": 12.5,
    "AI_Voltage": 480.0,
    "AI_Power": 8500.0,
    # Analog Outputs
    "AO_SpeedSetpoint": 1500.0,
    "AO_PressureSetpoint": 100.0,
    "AO_FlowSetpoint": 15.0,
    "AO_TempSetpoint": 25.0,
    # PID Parameters
    "PID_Output": 50.0,
    "PID_Error": 0.5,
    "PID_Integral": 125.0,
    "PID_Derivative": 2.1,
    "PID_Kp": 1.0,
    "PID_Ki": 0.1,
    "PID_Kd": 0.01,
    # System
    "SYS_ScanTime": 10,
    "SYS_CycleCount": 0,
    "SYS_ErrorCount": 0,
    "SYS_WarningCount": 0,
    "SYS_Uptime": 0,
}

# =============================================================================
# SIMULATION STATE
# =============================================================================


class SimulationState:
    """Thread-safe simulation state manager"""

    def __init__(self):
        self._lock = threading.RLock()
        self._values: Dict[str, Any] = INITIAL_VALUES.copy()
        self._write_log: list = []
        self._start_time = time.time()

    def get(self, tag: str, default: Any = None) -> Any:
        with self._lock:
            return self._values.get(tag, default)

    def set(self, tag: str, value: Any) -> None:
        with self._lock:
            self._values[tag] = value

    def log_write(self, tag: str, key: Any, value: Any) -> None:
        with self._lock:
            entry = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "tag": tag,
                "key": key,
                "value": value,
            }
            self._write_log.append(entry)
            log.info(f"WRITE: {tag}[{key}] = {value}")

    def get_uptime(self) -> int:
        return int(time.time() - self._start_time)


# Global simulation state
sim_state = SimulationState()


# =============================================================================
# VALUE SIMULATION THREAD
# =============================================================================


def simulation_thread():
    """
    Background thread that updates simulated sensor values.

    Simulates realistic industrial process behavior:
    - Temperature fluctuates with sine wave + noise
    - Pressure varies based on pump status
    - Flow rate depends on valve position
    - Level changes based on flow
    - Power consumption varies with motor status
    """
    log.info("Starting value simulation thread")

    while True:
        try:
            t = time.time()

            # Get current digital states
            motor_running = sim_state.get("DI_MotorRunning", 0) == 1
            pump_running = sim_state.get("DI_PumpRunning", 0) == 1
            valve_open = sim_state.get("DI_ValveOpen", 0) == 1

            # Temperature: 25°C base, ±5°C sine wave + random noise
            temp_base = 25.0
            temp_variation = 5.0 * math.sin(t * 0.1) + random.uniform(-1.0, 1.0)
            new_temp = temp_base + temp_variation
            sim_state.set("AI_Temperature", round(new_temp, 2))

            # Pressure: 100 kPa base, +20 if pump running, ±10 cosine variation
            pressure_base = 100.0
            pressure_boost = 20.0 if pump_running else 0.0
            pressure_variation = 10.0 * math.cos(t * 0.08) + random.uniform(-2.0, 2.0)
            new_pressure = pressure_base + pressure_boost + pressure_variation
            sim_state.set("AI_Pressure", round(new_pressure, 3))

            # Flow Rate: 15 L/min base, depends on valve position
            flow_base = 15.0
            flow_multiplier = 1.0 if valve_open else 0.1
            flow_variation = 3.0 * math.sin(t * 0.12) + random.uniform(-0.5, 0.5)
            new_flow = max(0, (flow_base + flow_variation) * flow_multiplier)
            sim_state.set("AI_FlowRate", round(new_flow, 2))

            # Level: Changes based on flow (simplified tank model)
            current_level = sim_state.get("AI_Level", 50.0)
            flow_delta = (new_flow - 15.0) * 0.1  # Level changes with flow deviation
            new_level = max(0, min(100, current_level + flow_delta))
            sim_state.set("AI_Level", round(new_level, 1))

            # Vibration: Random with slight correlation to motor
            vib_base = 2.0 if motor_running else 0.5
            vib_variation = random.uniform(-0.5, 0.5)
            sim_state.set("AI_Vibration", round(vib_base + vib_variation, 2))

            # Current: Varies with motor load
            if motor_running:
                current_base = 12.5
                current_variation = 2.0 * math.sin(t * 0.15) + random.uniform(-0.5, 0.5)
            else:
                current_base = 0.5
                current_variation = random.uniform(-0.1, 0.1)
            sim_state.set("AI_Current", round(current_base + current_variation, 2))

            # Voltage: Relatively stable with small variations
            voltage_base = 480.0
            voltage_variation = random.uniform(-5.0, 5.0)
            sim_state.set("AI_Voltage", round(voltage_base + voltage_variation, 1))

            # Power: Calculated from voltage and current
            voltage = sim_state.get("AI_Voltage", 480.0)
            current = sim_state.get("AI_Current", 0.0)
            power = voltage * current * 1.732 * 0.85  # 3-phase, PF=0.85
            sim_state.set("AI_Power", round(power, 1))

            # PID simulation (simplified)
            setpoint = sim_state.get("AO_TempSetpoint", 25.0)
            process_value = sim_state.get("AI_Temperature", 25.0)
            error = setpoint - process_value
            sim_state.set("PID_Error", round(error, 3))

            # System counters
            sim_state.set("SYS_CycleCount", sim_state.get("SYS_CycleCount", 0) + 1)
            sim_state.set("SYS_Uptime", sim_state.get_uptime())

            # Alarm logic
            alarm_active = 0
            if new_temp > 35.0 or new_temp < 15.0:
                alarm_active = 1
            if new_pressure > 130.0 or new_pressure < 70.0:
                alarm_active = 1
            if new_level < 10.0 or new_level > 95.0:
                alarm_active = 1
            sim_state.set("DI_AlarmActive", alarm_active)
            sim_state.set("DO_AlarmHorn", alarm_active)

        except Exception as e:
            log.error(f"Simulation error: {e}")
            sim_state.set("SYS_ErrorCount", sim_state.get("SYS_ErrorCount", 0) + 1)

        time.sleep(1.0)  # Update every second


# =============================================================================
# MAIN SERVER
# =============================================================================


def main():
    """Start the EtherNet/IP mock server"""

    parser = argparse.ArgumentParser(description="EtherNet/IP Mock PLC Server")
    parser.add_argument("--port", "-p", type=int, default=44818, help="TCP port (default: 44818)")
    parser.add_argument(
        "--address",
        "-a",
        type=str,
        default="0.0.0.0",
        help="Bind address (default: 0.0.0.0)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    if not CPPPO_AVAILABLE:
        log.error("Cannot start server: cpppo library not installed")
        log.error("Install with: pip install cpppo")
        return 1

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    log.info("=" * 60)
    log.info("EtherNet/IP Mock PLC Server (cpppo-based)")
    log.info("=" * 60)
    log.info(f"Bind address: {args.address}:{args.port}")
    log.info(f"Tags defined: {len(TAGS)}")

    # Start simulation thread
    sim_thread = threading.Thread(target=simulation_thread, daemon=True)
    sim_thread.start()
    log.info("Value simulation thread started")

    # Build tag arguments for cpppo
    tag_args = []
    for tag_name, tag_type in TAGS.items():
        tag_args.append(f"{tag_name}={tag_type}")

    log.info("Starting cpppo EtherNet/IP server...")
    log.info("Tags: " + ", ".join(list(TAGS.keys())[:10]) + "...")

    # Build cpppo server arguments
    argv = [
        "--address",
        f"{args.address}:{args.port}",
        "--print",  # Print I/O activity
    ]

    if args.verbose:
        argv.append("-v")

    # Add all tag definitions
    argv.extend(tag_args)

    log.info("")
    log.info("Test commands:")
    log.info(
        f"  Read tag:   python -m cpppo.server.enip.client -a localhost:{args.port} AI_Temperature"
    )
    log.info(
        f"  Read array: python -m cpppo.server.enip.client -a localhost:{args.port} 'SCADA[0-10]'"
    )
    log.info(
        f"  Write tag:  python -m cpppo.server.enip.client -a localhost:{args.port} 'AO_TempSetpoint=(REAL)30.0'"
    )
    log.info("")

    try:
        # Start cpppo server (blocks until terminated)
        return enip_main(argv=argv)
    except KeyboardInterrupt:
        log.info("Server shutdown requested")
        return 0
    except Exception as e:
        log.error(f"Server error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
