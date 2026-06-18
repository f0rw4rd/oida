#!/usr/bin/env python3
"""
Mock ADS Server using existing pyads framework
"""

import logging
import time
import threading
import random
import math

try:
    import pyads
    from pyads import constants

    HAS_PYADS = True
except ImportError:
    HAS_PYADS = False

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


class MockADSServerFramework:
    """Mock ADS server using existing pyads framework"""

    def __init__(self, host="0.0.0.0", port=48898):
        self.host = host
        self.port = port
        self.running = False
        self.plc_data = self._create_plc_variables()

    def _create_plc_variables(self):
        """Create realistic PLC variables"""
        variables = {}

        # System variables
        variables["TwinCAT_SystemInfoVarList._TaskInfo[1].CycleTime"] = {
            "type": pyads.PLCTYPE_UDINT if HAS_PYADS else "UDINT",
            "value": 10000,  # 10ms cycle time in microseconds
            "description": "PLC Cycle Time",
        }

        variables["TwinCAT_SystemInfoVarList._TaskInfo[1].LastExecTime"] = {
            "type": pyads.PLCTYPE_UDINT if HAS_PYADS else "UDINT",
            "value": 8500,
            "description": "Last Execution Time",
        }

        variables["TwinCAT_SystemInfoVarList._AppInfo.AdsState"] = {
            "type": pyads.PLCTYPE_UINT if HAS_PYADS else "UINT",
            "value": 5,  # ADSSTATE_RUN
            "description": "ADS State",
        }

        # Main program variables
        variables["MAIN.bSystemStart"] = {
            "type": pyads.PLCTYPE_BOOL if HAS_PYADS else "BOOL",
            "value": True,
            "description": "System Start Command",
        }

        variables["MAIN.bSystemStop"] = {
            "type": pyads.PLCTYPE_BOOL if HAS_PYADS else "BOOL",
            "value": False,
            "description": "System Stop Command",
        }

        variables["MAIN.bEmergencyStop"] = {
            "type": pyads.PLCTYPE_BOOL if HAS_PYADS else "BOOL",
            "value": False,
            "description": "Emergency Stop Active",
        }

        variables["MAIN.bSystemReady"] = {
            "type": pyads.PLCTYPE_BOOL if HAS_PYADS else "BOOL",
            "value": True,
            "description": "System Ready Status",
        }

        # Process values
        variables["MAIN.rTemperature"] = {
            "type": pyads.PLCTYPE_REAL if HAS_PYADS else "REAL",
            "value": 25.5,
            "description": "Process Temperature",
        }

        variables["MAIN.rPressure"] = {
            "type": pyads.PLCTYPE_REAL if HAS_PYADS else "REAL",
            "value": 1013.25,
            "description": "Process Pressure",
        }

        variables["MAIN.rFlowRate"] = {
            "type": pyads.PLCTYPE_REAL if HAS_PYADS else "REAL",
            "value": 15.7,
            "description": "Flow Rate",
        }

        variables["MAIN.rLevel"] = {
            "type": pyads.PLCTYPE_REAL if HAS_PYADS else "REAL",
            "value": 75.2,
            "description": "Tank Level",
        }

        # Setpoints
        variables["MAIN.rTemperatureSetpoint"] = {
            "type": pyads.PLCTYPE_REAL if HAS_PYADS else "REAL",
            "value": 25.0,
            "description": "Temperature Setpoint",
        }

        variables["MAIN.rPressureSetpoint"] = {
            "type": pyads.PLCTYPE_REAL if HAS_PYADS else "REAL",
            "value": 1000.0,
            "description": "Pressure Setpoint",
        }

        # Motor control
        variables["MAIN.Motor1.bEnable"] = {
            "type": pyads.PLCTYPE_BOOL if HAS_PYADS else "BOOL",
            "value": True,
            "description": "Motor 1 Enable",
        }

        variables["MAIN.Motor1.nSpeed"] = {
            "type": pyads.PLCTYPE_INT if HAS_PYADS else "INT",
            "value": 1500,
            "description": "Motor 1 Speed (RPM)",
        }

        variables["MAIN.Motor1.rCurrent"] = {
            "type": pyads.PLCTYPE_REAL if HAS_PYADS else "REAL",
            "value": 12.5,
            "description": "Motor 1 Current (A)",
        }

        variables["MAIN.Motor1.bFault"] = {
            "type": pyads.PLCTYPE_BOOL if HAS_PYADS else "BOOL",
            "value": False,
            "description": "Motor 1 Fault",
        }

        # Pump control
        variables["MAIN.Pump1.bStart"] = {
            "type": pyads.PLCTYPE_BOOL if HAS_PYADS else "BOOL",
            "value": False,
            "description": "Pump 1 Start Command",
        }

        variables["MAIN.Pump1.bRunning"] = {
            "type": pyads.PLCTYPE_BOOL if HAS_PYADS else "BOOL",
            "value": True,
            "description": "Pump 1 Running Status",
        }

        variables["MAIN.Pump1.rSpeed"] = {
            "type": pyads.PLCTYPE_REAL if HAS_PYADS else "REAL",
            "value": 85.5,
            "description": "Pump 1 Speed (%)",
        }

        # Valve control
        variables["MAIN.Valve1.bOpen"] = {
            "type": pyads.PLCTYPE_BOOL if HAS_PYADS else "BOOL",
            "value": True,
            "description": "Valve 1 Open Command",
        }

        variables["MAIN.Valve1.nPosition"] = {
            "type": pyads.PLCTYPE_INT if HAS_PYADS else "INT",
            "value": 75,
            "description": "Valve 1 Position (%)",
        }

        # Alarm system
        variables["MAIN.Alarms.bTempHigh"] = {
            "type": pyads.PLCTYPE_BOOL if HAS_PYADS else "BOOL",
            "value": False,
            "description": "High Temperature Alarm",
        }

        variables["MAIN.Alarms.bPressureLow"] = {
            "type": pyads.PLCTYPE_BOOL if HAS_PYADS else "BOOL",
            "value": False,
            "description": "Low Pressure Alarm",
        }

        variables["MAIN.Alarms.bSystemFault"] = {
            "type": pyads.PLCTYPE_BOOL if HAS_PYADS else "BOOL",
            "value": False,
            "description": "System Fault",
        }

        # Counters
        variables["MAIN.nCycleCounter"] = {
            "type": pyads.PLCTYPE_UDINT if HAS_PYADS else "UDINT",
            "value": 123456,
            "description": "PLC Cycle Counter",
        }

        variables["MAIN.nErrorCounter"] = {
            "type": pyads.PLCTYPE_UINT if HAS_PYADS else "UINT",
            "value": 5,
            "description": "Error Counter",
        }

        # String data
        variables["MAIN.sDeviceName"] = {
            "type": pyads.PLCTYPE_STRING if HAS_PYADS else "STRING",
            "value": "Mock TwinCAT PLC",
            "description": "Device Name",
        }

        variables["MAIN.sOperatorMessage"] = {
            "type": pyads.PLCTYPE_STRING if HAS_PYADS else "STRING",
            "value": "System Running Normal",
            "description": "Operator Message",
        }

        return variables

    def _simulate_plc_data(self):
        """Simulate realistic PLC data changes"""
        current_time = time.time()

        # Update process values with realistic industrial patterns
        # Temperature varies slowly
        temp_base = 25.0
        temp_variation = 3.0 * math.sin(current_time * 0.05) + random.uniform(-1.0, 1.0)
        new_temp = temp_base + temp_variation
        self.plc_data["MAIN.rTemperature"]["value"] = round(new_temp, 2)

        # Pressure varies with pump operation
        pump_running = self.plc_data["MAIN.Pump1.bRunning"]["value"]
        pressure_base = 1013.25 if pump_running else 950.0
        pressure_variation = 30.0 * math.sin(current_time * 0.08) + random.uniform(-10.0, 10.0)
        new_pressure = pressure_base + pressure_variation
        self.plc_data["MAIN.rPressure"]["value"] = round(new_pressure, 2)

        # Flow rate depends on valve position and pump
        valve_position = self.plc_data["MAIN.Valve1.nPosition"]["value"]
        pump_speed = self.plc_data["MAIN.Pump1.rSpeed"]["value"]
        flow_factor = (valve_position / 100.0) * (pump_speed / 100.0)
        flow_base = 15.0 * flow_factor
        flow_variation = 2.0 * math.sin(current_time * 0.12) + random.uniform(-0.5, 0.5)
        new_flow = max(0, flow_base + flow_variation)
        self.plc_data["MAIN.rFlowRate"]["value"] = round(new_flow, 2)

        # Level changes based on flow
        current_level = self.plc_data["MAIN.rLevel"]["value"]
        level_change = (new_flow - 12.0) * 0.1  # Net flow effect
        new_level = max(0, min(100, current_level + level_change))
        self.plc_data["MAIN.rLevel"]["value"] = round(new_level, 1)

        # Motor speed varies slightly
        motor_enabled = self.plc_data["MAIN.Motor1.bEnable"]["value"]
        if motor_enabled:
            speed_base = 1500
            speed_variation = int(50 * math.sin(current_time * 0.1) + random.uniform(-10, 10))
            self.plc_data["MAIN.Motor1.nSpeed"]["value"] = max(0, speed_base + speed_variation)

            # Current proportional to speed
            speed_ratio = self.plc_data["MAIN.Motor1.nSpeed"]["value"] / 1500.0
            current_base = 12.5 * speed_ratio
            current_variation = random.uniform(-1.0, 1.0)
            self.plc_data["MAIN.Motor1.rCurrent"]["value"] = round(
                max(0, current_base + current_variation), 2
            )
        else:
            self.plc_data["MAIN.Motor1.nSpeed"]["value"] = 0
            self.plc_data["MAIN.Motor1.rCurrent"]["value"] = 0.0

        # Pump speed control (simple simulation)
        if self.plc_data["MAIN.Pump1.bStart"]["value"]:
            self.plc_data["MAIN.Pump1.bRunning"]["value"] = True
            current_speed = self.plc_data["MAIN.Pump1.rSpeed"]["value"]
            if current_speed < 85.0:
                self.plc_data["MAIN.Pump1.rSpeed"]["value"] = min(90.0, current_speed + 0.5)
        else:
            current_speed = self.plc_data["MAIN.Pump1.rSpeed"]["value"]
            if current_speed > 0:
                self.plc_data["MAIN.Pump1.rSpeed"]["value"] = max(0, current_speed - 1.0)
            if current_speed <= 5.0:
                self.plc_data["MAIN.Pump1.bRunning"]["value"] = False

        # Alarm logic
        self.plc_data["MAIN.Alarms.bTempHigh"]["value"] = new_temp > 28.0
        self.plc_data["MAIN.Alarms.bPressureLow"]["value"] = new_pressure < 980.0

        # System fault if multiple alarms
        alarm_count = sum(
            [
                self.plc_data["MAIN.Alarms.bTempHigh"]["value"],
                self.plc_data["MAIN.Alarms.bPressureLow"]["value"],
                self.plc_data["MAIN.Motor1.bFault"]["value"],
            ]
        )
        self.plc_data["MAIN.Alarms.bSystemFault"]["value"] = alarm_count >= 2

        # Update counters
        self.plc_data["MAIN.nCycleCounter"]["value"] += 1
        if self.plc_data["MAIN.Alarms.bSystemFault"]["value"]:
            self.plc_data["MAIN.nErrorCounter"]["value"] += 1

        # Update operator message
        if self.plc_data["MAIN.Alarms.bSystemFault"]["value"]:
            self.plc_data["MAIN.sOperatorMessage"]["value"] = "SYSTEM FAULT - CHECK ALARMS"
        elif any(
            [
                self.plc_data["MAIN.Alarms.bTempHigh"]["value"],
                self.plc_data["MAIN.Alarms.bPressureLow"]["value"],
            ]
        ):
            self.plc_data["MAIN.sOperatorMessage"]["value"] = "WARNING - ALARM ACTIVE"
        else:
            self.plc_data["MAIN.sOperatorMessage"]["value"] = "System Running Normal"

        # Update cycle time (simulate slight variations)
        base_cycle = 10000  # 10ms
        cycle_variation = random.randint(-500, 500)
        self.plc_data["TwinCAT_SystemInfoVarList._TaskInfo[1].CycleTime"]["value"] = (
            base_cycle + cycle_variation
        )
        self.plc_data["TwinCAT_SystemInfoVarList._TaskInfo[1].LastExecTime"]["value"] = int(
            (base_cycle + cycle_variation) * 0.85
        )

    def start_server_pyads(self):
        """Start server using pyads framework (if available)"""
        log.info("Starting ADS server with pyads framework")
        log.warning("Note: pyads is primarily a client library, not a server")
        log.info("For full ADS server functionality, consider using TwinCAT or Beckhoff tools")

        # pyads doesn't provide server functionality, but we can simulate
        # the behavior by creating a mock that responds to our scanner
        self.start_server_fallback()

    def start_server_fallback(self):
        """Start our custom ADS server implementation"""
        log.info("Starting ADS server with custom implementation")

        # Import our custom implementation
        from ads_server import MockADSServer

        # Create server with our PLC data
        server = MockADSServer(self.host, self.port)

        # Convert our variables to the server's symbol format
        server.symbols = {}
        for var_name, var_data in self.plc_data.items():
            server.symbols[var_name] = {
                "type": str(var_data["type"]).replace("PLCTYPE_", "")
                if "PLCTYPE_" in str(var_data["type"])
                else var_data["type"],
                "value": var_data["value"],
                "size": self._get_type_size(var_data["type"]),
            }

        # Start simulation
        def simulation_loop():
            while self.running:
                self._simulate_plc_data()

                # Update server symbols
                for var_name, var_data in self.plc_data.items():
                    if var_name in server.symbols:
                        server.symbols[var_name]["value"] = var_data["value"]

                time.sleep(1)  # Update every second

        self.running = True
        sim_thread = threading.Thread(target=simulation_loop, daemon=True)
        sim_thread.start()

        log.info(f"ADS server running on {self.host}:{self.port}")
        log.info(f"Device: {self.plc_data['MAIN.sDeviceName']['value']}")
        log.info(f"Serving {len(self.plc_data)} PLC variables")
        log.info("Available variable groups:")
        log.info("  - System variables (TwinCAT_SystemInfoVarList.*)")
        log.info("  - Main program variables (MAIN.*)")
        log.info("  - Motor control (MAIN.Motor1.*)")
        log.info("  - Pump control (MAIN.Pump1.*)")
        log.info("  - Valve control (MAIN.Valve1.*)")
        log.info("  - Alarm system (MAIN.Alarms.*)")

        # Start server (this will block)
        import asyncio

        asyncio.run(server.start_server())

    def _get_type_size(self, plc_type):
        """Get size in bytes for PLC data type"""
        if HAS_PYADS:
            type_sizes = {
                pyads.PLCTYPE_BOOL: 1,
                pyads.PLCTYPE_BYTE: 1,
                pyads.PLCTYPE_INT: 2,
                pyads.PLCTYPE_UINT: 2,
                pyads.PLCTYPE_DINT: 4,
                pyads.PLCTYPE_UDINT: 4,
                pyads.PLCTYPE_REAL: 4,
                pyads.PLCTYPE_LREAL: 8,
                pyads.PLCTYPE_STRING: 81,  # Default string size
            }
            return type_sizes.get(plc_type, 4)
        else:
            # Fallback for string types
            type_sizes = {
                "BOOL": 1,
                "BYTE": 1,
                "INT": 2,
                "UINT": 2,
                "DINT": 4,
                "UDINT": 4,
                "REAL": 4,
                "LREAL": 8,
                "STRING": 81,
            }
            return type_sizes.get(str(plc_type), 4)

    def start(self):
        """Start the server using the best available framework"""
        if HAS_PYADS:
            self.start_server_pyads()
        else:
            log.warning("pyads not available, using custom implementation")
            self.start_server_fallback()


def main():
    """Start the mock ADS server"""
    server = MockADSServerFramework()
    server.start()


if __name__ == "__main__":
    main()
