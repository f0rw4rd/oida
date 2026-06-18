#!/usr/bin/env python3
"""
Mock IEC 104 Server using c104 framework
"""

import logging
import time
import threading
import random
import math

try:
    import c104

    HAS_C104 = True
except ImportError:
    HAS_C104 = False

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


class MockIEC104ServerC104:
    """Mock IEC 104 server using c104 framework"""

    def __init__(self, host="0.0.0.0", port=2404):
        self.host = host
        self.port = port
        self.running = False
        self.server = None
        self.station = None
        self.data_points = {}

    def _create_data_points(self):
        """Create industrial data points using c104"""
        if not HAS_C104:
            return

        # Create station
        self.station = c104.Station(common_address=1)

        # Digital inputs (Single Point Information)
        digital_descriptions = [
            "Pump 1 Running",
            "Pump 2 Running",
            "Valve 1 Open",
            "Valve 2 Open",
            "Motor 1 Running",
            "Motor 2 Running",
            "Emergency Stop",
            "System Ready",
            "Alarm Horn",
            "Warning Light",
            "Breaker 1 Closed",
            "Breaker 2 Closed",
            "Isolator 1 Closed",
            "Isolator 2 Closed",
            "Auto Mode",
            "Manual Mode",
            "Process Running",
            "Maintenance Mode",
            "Safety System OK",
            "Backup Power",
        ]

        for i in range(1, 21):
            point = self.station.add_point(
                io_address=i,
                type=c104.Type.M_SP_NA_1,  # Single point information
                report_ms=1000,  # Report every second
            )
            point.value = i % 2 == 0  # Alternating pattern
            point.quality = c104.Quality.GOOD

            self.data_points[i] = {
                "point": point,
                "type": "digital",
                "description": digital_descriptions[i - 1]
                if i <= len(digital_descriptions)
                else f"Digital Input {i}",
                "base_value": i % 2 == 0,
            }

        # Analog measurements (Measured Value Scaled)
        analog_descriptions = [
            "Temperature Reactor 1",
            "Temperature Reactor 2",
            "Pressure Line 1",
            "Pressure Line 2",
            "Flow Rate Feed",
            "Flow Rate Product",
            "Level Tank 1",
            "Level Tank 2",
            "Voltage Phase A",
            "Voltage Phase B",
            "Voltage Phase C",
            "Current Phase A",
            "Current Phase B",
            "Current Phase C",
            "Active Power",
            "Reactive Power",
            "Frequency",
            "Power Factor",
            "Vibration Motor 1",
            "Vibration Motor 2",
            "Conductivity",
            "pH Value",
            "Oxygen Level",
            "CO2 Level",
            "Steam Pressure",
            "Cooling Water Flow",
            "Lube Oil Pressure",
            "Fuel Flow",
            "Exhaust Temperature",
            "Ambient Temperature",
            "Humidity",
            "Wind Speed",
            "Solar Radiation",
            "Battery Voltage",
            "Generator Speed",
            "Turbine Speed",
            "Steam Flow",
            "Condensate Level",
            "Bearing Temperature",
            "Oil Temperature",
        ]

        base_values = [
            25.5,
            28.2,
            1013.25,
            950.0,  # Temperatures and pressures
            15.7,
            12.3,
            75.2,
            68.5,  # Flow rates and levels
            230.1,
            229.8,
            230.3,
            5.42,  # Electrical measurements
            5.38,
            5.45,
            1250.0,
            300.2,  # More electrical
            50.02,
            0.85,
            2.1,
            1.8,  # Frequency, PF, vibration
            850.5,
            7.2,
            21.0,
            0.03,  # Chemical measurements
            15.5,
            125.0,
            4.2,
            18.5,  # Process measurements
            285.0,
            22.5,
            65.0,
            12.5,  # Environmental
            950.0,
            12.6,
            1800.0,
            3600.0,  # Power generation
            45.2,
            85.5,
            85.0,
            95.5,  # Steam system
        ]

        for i in range(21, 61):
            point = self.station.add_point(
                io_address=i,
                type=c104.Type.M_ME_NB_1,  # Measured value scaled
                report_ms=2000,  # Report every 2 seconds
            )

            base_idx = (i - 21) % len(base_values)
            base_value = base_values[base_idx]

            point.value = int(base_value * 100)  # Scale for integer representation
            point.quality = c104.Quality.GOOD

            self.data_points[i] = {
                "point": point,
                "type": "analog",
                "description": analog_descriptions[i - 21]
                if (i - 21) < len(analog_descriptions)
                else f"Analog Measurement {i}",
                "base_value": base_value,
                "scale_factor": 100,
            }

        # Floating point measurements (Measured Value Short Floating Point)
        for i in range(61, 81):
            point = self.station.add_point(
                io_address=i,
                type=c104.Type.M_ME_NC_1,  # Measured value short floating point
                report_ms=2000,
            )

            base_idx = (i - 61) % len(base_values)
            base_value = base_values[base_idx]

            point.value = base_value
            point.quality = c104.Quality.GOOD

            self.data_points[i] = {
                "point": point,
                "type": "float",
                "description": f"Float Measurement {i - 60}",
                "base_value": base_value,
            }

        # Integrated totals (counters)
        counter_descriptions = [
            "Energy Total kWh",
            "Energy Today kWh",
            "Runtime Hours Motor 1",
            "Runtime Hours Motor 2",
            "Pump Starts Count",
            "Alarm Count",
            "Maintenance Counter",
            "Production Counter",
            "Error Count",
            "Reset Count",
            "Cycle Count",
            "Operating Hours",
            "Start Count",
            "Stop Count",
            "Emergency Count",
            "Manual Operations",
            "Auto Operations",
            "Fault Count",
            "Warning Count",
            "Service Hours",
        ]

        for i in range(81, 101):
            point = self.station.add_point(
                io_address=i,
                type=c104.Type.M_IT_NA_1,  # Integrated totals
                report_ms=5000,  # Report every 5 seconds
            )

            point.value = (i - 80) * 1000 + random.randint(0, 999)
            point.quality = c104.Quality.GOOD

            self.data_points[i] = {
                "point": point,
                "type": "counter",
                "description": counter_descriptions[i - 81]
                if (i - 81) < len(counter_descriptions)
                else f"Counter {i}",
                "base_value": (i - 80) * 1000,
            }

        log.info(f"Created {len(self.data_points)} data points:")
        log.info(
            f"  - Digital inputs (IOA 1-20): {sum(1 for p in self.data_points.values() if p['type'] == 'digital')}"
        )
        log.info(
            f"  - Analog scaled (IOA 21-60): {sum(1 for p in self.data_points.values() if p['type'] == 'analog')}"
        )
        log.info(
            f"  - Float values (IOA 61-80): {sum(1 for p in self.data_points.values() if p['type'] == 'float')}"
        )
        log.info(
            f"  - Counters (IOA 81-100): {sum(1 for p in self.data_points.values() if p['type'] == 'counter')}"
        )

    def _simulate_data(self):
        """Simulate realistic data changes using c104"""
        if not HAS_C104 or not self.station:
            return

        current_time = time.time()

        for ioa, data in self.data_points.items():
            point = data["point"]

            if data["type"] == "digital":
                # Randomly toggle some digital inputs (equipment state changes)
                if random.random() < 0.02:  # 2% chance per update
                    new_value = not point.value
                    point.value = new_value

                    # Set quality based on simulation
                    if random.random() < 0.95:
                        point.quality = c104.Quality.GOOD
                    else:
                        point.quality = c104.Quality.QUESTIONABLE

            elif data["type"] == "analog":
                # Simulate analog values with industrial patterns
                base_value = data["base_value"]
                scale_factor = data["scale_factor"]

                # Different simulation patterns based on measurement type
                if "Temperature" in data["description"]:
                    # Temperature varies slowly with process changes
                    process_variation = 5.0 * math.sin(current_time * 0.05 + ioa * 0.1)
                    noise = random.uniform(-1.0, 1.0)
                    new_value = base_value + process_variation + noise

                elif "Pressure" in data["description"]:
                    # Pressure varies with pump operations
                    pump_cycle = 50.0 * math.sin(current_time * 0.08 + ioa * 0.1)
                    noise = random.uniform(-10.0, 10.0)
                    new_value = base_value + pump_cycle + noise

                elif "Flow" in data["description"]:
                    # Flow rate varies with valve positions
                    flow_cycle = 5.0 * math.sin(current_time * 0.1 + ioa * 0.15)
                    noise = random.uniform(-2.0, 2.0)
                    new_value = max(0, base_value + flow_cycle + noise)

                elif "Voltage" in data["description"]:
                    # Voltage is relatively stable
                    variation = 10.0 * math.sin(current_time * 0.02 + ioa * 0.1)
                    noise = random.uniform(-2.0, 2.0)
                    new_value = base_value + variation + noise

                elif "Current" in data["description"]:
                    # Current varies with load
                    load_variation = 2.0 * math.sin(current_time * 0.1 + ioa * 0.1)
                    noise = random.uniform(-0.5, 0.5)
                    new_value = max(0, base_value + load_variation + noise)

                elif "Power" in data["description"]:
                    # Power varies with operational state
                    power_variation = 200.0 * math.sin(current_time * 0.1 + ioa * 0.1)
                    noise = random.uniform(-50.0, 50.0)
                    new_value = max(0, base_value + power_variation + noise)

                else:
                    # Generic variation
                    variation = base_value * 0.1 * math.sin(current_time * 0.08 + ioa * 0.1)
                    noise = random.uniform(-base_value * 0.02, base_value * 0.02)
                    new_value = base_value + variation + noise

                point.value = int(new_value * scale_factor)
                point.quality = (
                    c104.Quality.GOOD if random.random() < 0.98 else c104.Quality.QUESTIONABLE
                )

            elif data["type"] == "float":
                # Similar to analog but stored as float
                base_value = data["base_value"]
                variation = base_value * 0.1 * math.sin(current_time * 0.08 + ioa * 0.1)
                noise = random.uniform(-base_value * 0.02, base_value * 0.02)
                new_value = base_value + variation + noise

                point.value = round(new_value, 2)
                point.quality = c104.Quality.GOOD

            elif data["type"] == "counter":
                # Slowly increment counters
                if random.random() < 0.1:  # 10% chance per update
                    point.value += random.randint(1, 5)
                    point.quality = c104.Quality.GOOD

    def start_server_c104(self):
        """Start server using c104 framework"""
        log.info("Starting IEC 104 server with c104 framework")

        if not HAS_C104:
            log.error("c104 library not available!")
            return

        # Create server
        self.server = c104.Server(ip=self.host, port=self.port, tick_rate_ms=1000)

        # Add connection event handlers
        @self.server.on_receive_raw
        def on_receive_raw(data: bytes) -> None:
            log.debug(f"Received raw data: {len(data)} bytes")

        @self.server.on_send_raw
        def on_send_raw(data: bytes) -> None:
            log.debug(f"Sent raw data: {len(data)} bytes")

        @self.server.on_station_interrogation
        def on_station_interrogation(common_address: int) -> None:
            log.info(f"Station interrogation for CA {common_address}")

            # Send all current values
            if self.station and self.station.common_address == common_address:
                for ioa, data in self.data_points.items():
                    point = data["point"]
                    point.transmit(cause=c104.Cot.INTERROGATED_BY_STATION)

        # Create and add station
        self._create_data_points()
        if self.station:
            self.server.add_station(self.station)

        # Start server
        self.server.start()

        if not self.server.is_running:
            log.error("Failed to start c104 server!")
            return

        log.info(f"IEC 104 server running on {self.host}:{self.port}")
        log.info(
            f"Station Common Address: {self.station.common_address if self.station else 'N/A'}"
        )

        # Start simulation thread
        def simulation_loop():
            while self.running:
                try:
                    self._simulate_data()
                    time.sleep(2)  # Update every 2 seconds
                except Exception as e:
                    log.error(f"Simulation error: {e}")
                    time.sleep(5)

        self.running = True
        sim_thread = threading.Thread(target=simulation_loop, daemon=True)
        sim_thread.start()

        log.info("Started IEC 104 data simulation")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Shutting down IEC 104 server...")
            self.running = False
            if self.server:
                self.server.stop()

    def start_server_fallback(self):
        """Fallback to our custom implementation"""
        log.warning("c104 not available, using fallback implementation")

        # Import our custom implementation
        from iec104_server import MockIEC104Server

        server = MockIEC104Server(self.host, self.port)

        # Start simulation
        def simulation_loop():
            while self.running:
                server._simulate_data_changes()
                time.sleep(2)

        self.running = True
        sim_thread = threading.Thread(target=simulation_loop, daemon=True)
        sim_thread.start()

        # Start server (this will block)
        import asyncio

        asyncio.run(server.start_server())

    def start(self):
        """Start the server using the best available framework"""
        if HAS_C104:
            self.start_server_c104()
        else:
            self.start_server_fallback()


def main():
    """Start the mock IEC 104 server"""
    server = MockIEC104ServerC104()
    server.start()


if __name__ == "__main__":
    main()
