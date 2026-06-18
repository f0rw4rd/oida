#!/usr/bin/env python3
"""
Mock IEC 104 Server using existing lib60870 framework
"""

import logging
import time
import threading
import random
import math

# Try to use existing IEC 104 libraries
try:
    import lib60870

    HAS_LIB60870 = True
except ImportError:
    try:
        import iec104

        HAS_IEC104 = True
        HAS_LIB60870 = False
    except ImportError:
        # Fallback to our custom implementation
        HAS_LIB60870 = False
        HAS_IEC104 = False

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


class MockIEC104ServerFramework:
    """Mock IEC 104 server using existing frameworks when available"""

    def __init__(self, host="0.0.0.0", port=2404):
        self.host = host
        self.port = port
        self.data_points = self._create_data_points()
        self.running = False

    def _create_data_points(self):
        """Create industrial data points"""
        points = {}

        # Digital inputs (Binary counters and status)
        for i in range(1, 21):
            points[i] = {
                "type": "digital",
                "value": i % 2 == 0,
                "description": f"Digital Input {i} - {'Pump' if i <= 5 else 'Valve' if i <= 10 else 'Motor' if i <= 15 else 'Alarm'} {((i - 1) % 5) + 1}",
                "quality": 0x00,  # Good quality
            }

        # Analog measurements (Temperatures, pressures, flows)
        base_values = {
            "temperature": 25.0,
            "pressure": 1013.25,
            "flow": 15.7,
            "level": 75.0,
            "voltage": 230.0,
            "current": 5.4,
            "power": 1250.0,
            "frequency": 50.0,
        }

        for i in range(21, 61):
            measurement_type = list(base_values.keys())[(i - 21) % len(base_values)]
            base_value = base_values[measurement_type]

            points[i] = {
                "type": "analog",
                "value": base_value + (i - 21) * 0.1,
                "description": f"{measurement_type.title()} Sensor {((i - 21) % 8) + 1}",
                "quality": 0x00,
                "measurement_type": measurement_type,
            }

        # Control commands (Setpoints and commands)
        for i in range(61, 81):
            points[i] = {
                "type": "command",
                "value": 0,  # 0 = not executed, 1 = executed
                "description": f"Control Command {i - 60}",
                "quality": 0x00,
            }

        # Status and counters
        for i in range(81, 101):
            points[i] = {
                "type": "counter",
                "value": i * 100,
                "description": f"Counter {i - 80}",
                "quality": 0x00,
            }

        return points

    def _simulate_data(self):
        """Simulate realistic data changes"""
        current_time = time.time()

        # Update analog values with realistic industrial patterns
        for ioa, point in self.data_points.items():
            if point["type"] == "analog":
                measurement_type = point.get("measurement_type", "generic")
                base_value = point["value"]

                if measurement_type == "temperature":
                    # Temperature varies slowly with daily cycle + noise
                    daily_cycle = 5.0 * math.sin(current_time * 0.001)  # Daily variation
                    process_variation = 2.0 * math.sin(current_time * 0.1 + ioa * 0.1)
                    noise = random.uniform(-0.5, 0.5)
                    point["value"] = round(25.0 + daily_cycle + process_variation + noise, 2)

                elif measurement_type == "pressure":
                    # Pressure varies with pump operations
                    pump_cycle = 50.0 * math.sin(current_time * 0.05 + ioa * 0.1)
                    noise = random.uniform(-5.0, 5.0)
                    point["value"] = round(1013.25 + pump_cycle + noise, 2)

                elif measurement_type == "flow":
                    # Flow rate varies with valve positions
                    flow_cycle = 5.0 * math.sin(current_time * 0.08 + ioa * 0.15)
                    noise = random.uniform(-1.0, 1.0)
                    point["value"] = round(max(0, 15.7 + flow_cycle + noise), 2)

                elif measurement_type == "voltage":
                    # Voltage is relatively stable with small variations
                    variation = 10.0 * math.sin(current_time * 0.02 + ioa * 0.1)
                    noise = random.uniform(-2.0, 2.0)
                    point["value"] = round(230.0 + variation + noise, 1)

                elif measurement_type == "current":
                    # Current varies with load
                    load_variation = 2.0 * math.sin(current_time * 0.1 + ioa * 0.1)
                    noise = random.uniform(-0.5, 0.5)
                    point["value"] = round(max(0, 5.4 + load_variation + noise), 2)

                elif measurement_type == "power":
                    # Power varies with load and operational state
                    power_variation = 300.0 * math.sin(current_time * 0.1 + ioa * 0.1)
                    noise = random.uniform(-50.0, 50.0)
                    point["value"] = round(max(0, 1250.0 + power_variation + noise), 1)

                elif measurement_type == "frequency":
                    # Grid frequency is very stable
                    variation = 0.1 * math.sin(current_time * 0.01)
                    noise = random.uniform(-0.02, 0.02)
                    point["value"] = round(50.0 + variation + noise, 3)

            elif point["type"] == "digital":
                # Randomly toggle some digital inputs (equipment state changes)
                if random.random() < 0.02:  # 2% chance per update
                    point["value"] = not point["value"]

            elif point["type"] == "counter":
                # Slowly increment counters
                if random.random() < 0.1:  # 10% chance per update
                    point["value"] += random.randint(1, 5)

    def start_server_lib60870(self):
        """Start server using lib60870 framework"""
        log.info("Starting IEC 104 server with lib60870 framework")

        def information_object_callback(parameter, asdu):
            """Handle information objects"""
            log.debug(f"Received ASDU: {asdu}")
            return True

        def connection_event_callback(parameter, connection, event):
            """Handle connection events"""
            if event == lib60870.CS104_CON_EVENT_CONNECTION_OPENED:
                log.info("IEC 104 client connected")
            elif event == lib60870.CS104_CON_EVENT_CONNECTION_CLOSED:
                log.info("IEC 104 client disconnected")
            elif event == lib60870.CS104_CON_EVENT_ACTIVATED:
                log.info("IEC 104 connection activated")
            elif event == lib60870.CS104_CON_EVENT_DEACTIVATED:
                log.info("IEC 104 connection deactivated")

        def interrogation_handler(parameter, connection, asdu, qoi):
            """Handle general interrogation"""
            log.info(f"General interrogation requested (QOI: {qoi})")

            # Send all data points
            for ioa, point in self.data_points.items():
                if point["type"] == "digital":
                    # Send single point information
                    io = lib60870.InformationObject_create(
                        None, ioa, lib60870.IEC60870_TYPE_M_SP_NA_1
                    )
                    lib60870.SinglePointInformation_create(
                        io, point["value"], lib60870.IEC60870_QUALITY_GOOD
                    )

                elif point["type"] == "analog":
                    # Send measured value (short floating point)
                    io = lib60870.InformationObject_create(
                        None, ioa, lib60870.IEC60870_TYPE_M_ME_NC_1
                    )
                    lib60870.MeasuredValueShort_create(
                        io, point["value"], lib60870.IEC60870_QUALITY_GOOD
                    )

                # Send the information object
                newAsdu = lib60870.CS101_ASDU_create(
                    lib60870.defaultAppLayerParameters,
                    False,
                    lib60870.CS101_COT_INTERROGATED_BY_STATION,
                    0,
                    1,
                    False,
                    False,
                )
                lib60870.CS101_ASDU_addInformationObject(newAsdu, io)
                lib60870.CS104_Connection_sendASDU(connection, newAsdu)
                lib60870.CS101_ASDU_destroy(newAsdu)
                lib60870.InformationObject_destroy(io)

            # Send end of interrogation
            lib60870.CS104_Connection_sendEndOfInitialization(connection, 1)
            return True

        # Create server
        server = lib60870.CS104_Slave_create(100, 100)
        lib60870.CS104_Slave_setLocalAddress(server, self.host)
        lib60870.CS104_Slave_setLocalPort(server, self.port)

        # Set callbacks
        lib60870.CS104_Slave_setConnectionEventHandler(server, connection_event_callback, None)
        lib60870.CS104_Slave_setInterrogationHandler(server, interrogation_handler, None)

        # Start server
        lib60870.CS104_Slave_start(server)

        # Start simulation
        def simulation_loop():
            while self.running:
                self._simulate_data()
                time.sleep(2)

        self.running = True
        sim_thread = threading.Thread(target=simulation_loop, daemon=True)
        sim_thread.start()

        log.info(f"IEC 104 server running on {self.host}:{self.port}")
        log.info(f"Serving {len(self.data_points)} data points")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Shutting down IEC 104 server...")
            self.running = False
            lib60870.CS104_Slave_stop(server)
            lib60870.CS104_Slave_destroy(server)

    def start_server_iec104(self):
        """Start server using iec104 framework"""
        log.info("Starting IEC 104 server with iec104 framework")

        # Create server configuration
        config = iec104.ServerConfig()
        config.host = self.host
        config.port = self.port
        config.max_connections = 10

        # Create server
        server = iec104.Server(config)

        # Add data points
        for ioa, point in self.data_points.items():
            if point["type"] == "digital":
                server.add_point(ioa, iec104.PointType.SINGLE_POINT, point["value"])
            elif point["type"] == "analog":
                server.add_point(ioa, iec104.PointType.MEASURED_VALUE_SHORT_FLOAT, point["value"])
            elif point["type"] == "counter":
                server.add_point(ioa, iec104.PointType.INTEGRATED_TOTALS, point["value"])

        # Start simulation
        def simulation_loop():
            while self.running:
                self._simulate_data()

                # Update server with new values
                for ioa, point in self.data_points.items():
                    try:
                        server.update_point(ioa, point["value"])
                    except:
                        pass

                time.sleep(2)

        self.running = True
        sim_thread = threading.Thread(target=simulation_loop, daemon=True)
        sim_thread.start()

        # Start server
        server.start()

        log.info(f"IEC 104 server running on {self.host}:{self.port}")
        log.info(f"Serving {len(self.data_points)} data points")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Shutting down IEC 104 server...")
            self.running = False
            server.stop()

    def start_server_fallback(self):
        """Fallback to our custom implementation"""
        log.info("Starting IEC 104 server with fallback implementation")

        # Import our custom implementation
        from iec104_server import MockIEC104Server

        server = MockIEC104Server(self.host, self.port)

        # Update data points
        server.data_points = self.data_points

        # Start simulation
        def simulation_loop():
            while self.running:
                self._simulate_data()
                server.data_points = self.data_points
                time.sleep(2)

        self.running = True
        sim_thread = threading.Thread(target=simulation_loop, daemon=True)
        sim_thread.start()

        # Start server (this will block)
        import asyncio

        asyncio.run(server.start_server())

    def start(self):
        """Start the server using the best available framework"""
        if HAS_LIB60870:
            self.start_server_lib60870()
        elif HAS_IEC104:
            self.start_server_iec104()
        else:
            log.warning("No IEC 104 framework available, using fallback implementation")
            self.start_server_fallback()


def main():
    """Start the mock IEC 104 server"""
    server = MockIEC104ServerFramework()
    server.start()


if __name__ == "__main__":
    main()
