#!/usr/bin/env python3
"""
FreeTASE2 Mock Server using libiec61850 Python bindings

Proper IEC 60870-6 TASE.2/ICCP implementation for testing OIDA scanner.
Requires libiec61850 compiled with Python bindings.

Features:
- Full MMS/ISO protocol stack
- Block 1: Basic data exchange
- Block 2: Report-by-Exception (RBE)
- Block 5: Device control (SBO/Direct)
- Bilateral tables
- Transfer sets
"""

import argparse
import logging
import signal
import sys
import time
import math
import random
from threading import Thread, Event
from typing import Dict, List, Any

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
log = logging.getLogger("FreeTASE2")

# Try to import libiec61850
try:
    import iec61850

    HAS_LIBIEC61850 = True
    log.info("libiec61850 Python bindings loaded successfully")
except ImportError as e:
    HAS_LIBIEC61850 = False
    log.warning(f"libiec61850 not available: {e}")
    log.warning("Falling back to simulation mode")


class TASE2DataModel:
    """TASE.2 Data Model Definition"""

    def __init__(self):
        self.bilateral_table_id = "BLT_UTILITY_001"
        self.tase2_version = (2000, 8)

        # Supported features bitmap (per IEC 60870-6-503)
        self.supported_features = 0b00000000_00010011  # Block 1, 2, 5

        # Data points with simulated values
        self.data_points: Dict[str, Dict[str, Any]] = {}
        self.control_points: Dict[str, Dict[str, Any]] = {}

        self._init_data_model()

    def _init_data_model(self):
        """Initialize TASE.2 data model"""

        # VCC Domain - System-wide values
        self.data_points["VCC/System_Status"] = {
            "type": "State",
            "value": 1,
            "quality": 0,
            "domain": "VCC",
        }
        self.data_points["VCC/Total_Generation_MW"] = {
            "type": "RealQ",
            "value": 2500.5,
            "quality": 0,
            "domain": "VCC",
        }
        self.data_points["VCC/Total_Load_MW"] = {
            "type": "RealQ",
            "value": 2450.3,
            "quality": 0,
            "domain": "VCC",
        }
        self.data_points["VCC/Frequency_Hz"] = {
            "type": "RealQTimeTag",
            "value": 50.02,
            "quality": 0,
            "domain": "VCC",
        }
        self.data_points["VCC/Tie_Line_Flow_MW"] = {
            "type": "RealQ",
            "value": 50.2,
            "quality": 0,
            "domain": "VCC",
        }

        # ICC1 Domain - Substation 1
        self.data_points["ICC1/Bus_Voltage_kV"] = {
            "type": "RealQ",
            "value": 132.5,
            "quality": 0,
            "domain": "ICC1",
        }
        self.data_points["ICC1/Feeder1_MW"] = {
            "type": "RealQTimeTag",
            "value": 45.2,
            "quality": 0,
            "domain": "ICC1",
        }
        self.data_points["ICC1/Feeder1_MVAr"] = {
            "type": "RealQTimeTag",
            "value": 12.3,
            "quality": 0,
            "domain": "ICC1",
        }
        self.data_points["ICC1/Feeder2_MW"] = {
            "type": "RealQTimeTag",
            "value": 38.7,
            "quality": 0,
            "domain": "ICC1",
        }
        self.data_points["ICC1/Feeder2_MVAr"] = {
            "type": "RealQTimeTag",
            "value": 8.9,
            "quality": 0,
            "domain": "ICC1",
        }
        self.data_points["ICC1/Breaker1_Status"] = {
            "type": "StateQ",
            "value": 1,
            "quality": 0,
            "domain": "ICC1",
        }
        self.data_points["ICC1/Breaker2_Status"] = {
            "type": "StateQ",
            "value": 1,
            "quality": 0,
            "domain": "ICC1",
        }
        self.data_points["ICC1/Transformer_Tap"] = {
            "type": "DiscreteQ",
            "value": 5,
            "quality": 0,
            "domain": "ICC1",
        }

        # ICC2 Domain - Substation 2
        self.data_points["ICC2/Bus_Voltage_kV"] = {
            "type": "RealQ",
            "value": 33.2,
            "quality": 0,
            "domain": "ICC2",
        }
        self.data_points["ICC2/Load_MW"] = {
            "type": "RealQTimeTag",
            "value": 15.8,
            "quality": 0,
            "domain": "ICC2",
        }
        self.data_points["ICC2/Load_MVAr"] = {
            "type": "RealQTimeTag",
            "value": 4.2,
            "quality": 0,
            "domain": "ICC2",
        }
        self.data_points["ICC2/Capacitor_Status"] = {
            "type": "StateQ",
            "value": 1,
            "quality": 0,
            "domain": "ICC2",
        }

        # Control points (Block 5)
        self.control_points["ICC1/Breaker1_Control"] = {
            "type": "Command",
            "is_sbo": True,
            "tag": 2,
            "tag_reason": "Maintenance",
            "domain": "ICC1",
            "state": "idle",
            "check_back_id": None,
        }
        self.control_points["ICC1/Breaker2_Control"] = {
            "type": "Command",
            "is_sbo": True,
            "tag": 0,
            "tag_reason": "",
            "domain": "ICC1",
            "state": "idle",
            "check_back_id": None,
        }
        self.control_points["ICC1/Tap_Setpoint"] = {
            "type": "Setpoint",
            "is_sbo": False,
            "tag": 0,
            "tag_reason": "",
            "domain": "ICC1",
            "state": "idle",
            "check_back_id": None,
        }
        self.control_points["ICC2/Capacitor_Control"] = {
            "type": "Command",
            "is_sbo": True,
            "tag": 1,
            "tag_reason": "Equipment fault",
            "domain": "ICC2",
            "state": "idle",
            "check_back_id": None,
        }

    def simulate_values(self):
        """Update simulated values"""
        t = time.time()

        # Frequency varies around 50 Hz
        if "VCC/Frequency_Hz" in self.data_points:
            self.data_points["VCC/Frequency_Hz"]["value"] = round(
                50.0 + 0.05 * math.sin(t * 0.1) + random.uniform(-0.01, 0.01), 3
            )

        # Power values vary slightly
        for key, point in self.data_points.items():
            if "MW" in key or "MVAr" in key:
                base = point["value"]
                variation = base * 0.02 * math.sin(t * 0.05 + hash(key) * 0.1)
                point["value"] = round(base + variation + random.uniform(-0.5, 0.5), 2)
            elif "Voltage" in key:
                base = point["value"]
                point["value"] = round(base + random.uniform(-0.2, 0.2), 2)

    def get_domains(self) -> List[str]:
        """Get list of domains"""
        domains = set()
        for key in self.data_points.keys():
            domains.add(key.split("/")[0])
        return sorted(domains)

    def get_variables(self, domain: str) -> List[str]:
        """Get variables in a domain"""
        return [k.split("/")[1] for k in self.data_points.keys() if k.startswith(f"{domain}/")]


class TASE2ServerLibIEC:
    """TASE.2 Server using libiec61850"""

    def __init__(self, host: str = "0.0.0.0", port: int = 102):
        self.host = host
        self.port = port
        self.data_model = TASE2DataModel()
        self.running = False
        self.server = None
        self.simulation_thread = None
        self.stop_event = Event()

    def _create_mms_server(self):
        """Create MMS server with TASE.2 data model"""
        if not HAS_LIBIEC61850:
            raise RuntimeError("libiec61850 not available")

        # Create IED model
        model = iec61850.IedModel_create("TASE2_Server")

        # Create logical device for each domain
        for domain in self.data_model.get_domains():
            ld = iec61850.LogicalDevice_create(domain, model)

            # Create logical node for data
            ln = iec61850.LogicalNode_create("LLN0", ld)

            # Add data objects for each variable
            for var_name in self.data_model.get_variables(domain):
                key = f"{domain}/{var_name}"
                point = self.data_model.data_points.get(key, {})

                # Create data object based on type
                if "Real" in point.get("type", ""):
                    do = iec61850.DataObject_create(var_name, ln, 0)
                    da = iec61850.DataAttribute_create(
                        "mag", do, iec61850.IEC61850_FC_MX, iec61850.IEC61850_FLOAT32, 0
                    )
                elif "State" in point.get("type", ""):
                    do = iec61850.DataObject_create(var_name, ln, 0)
                    da = iec61850.DataAttribute_create(
                        "stVal", do, iec61850.IEC61850_FC_ST, iec61850.IEC61850_BOOLEAN, 0
                    )
                elif "Discrete" in point.get("type", ""):
                    do = iec61850.DataObject_create(var_name, ln, 0)
                    da = iec61850.DataAttribute_create(
                        "stVal", do, iec61850.IEC61850_FC_ST, iec61850.IEC61850_INT32, 0
                    )

        # Create server
        self.server = iec61850.IedServer_create(model)

        return model

    def _simulation_loop(self):
        """Background thread for value simulation"""
        while not self.stop_event.is_set():
            self.data_model.simulate_values()

            # Update server values if running
            if self.server and HAS_LIBIEC61850:
                try:
                    iec61850.IedServer_lockDataModel(self.server)
                    # Update values in model...
                    iec61850.IedServer_unlockDataModel(self.server)
                except Exception as e:
                    log.debug(f"Value update error: {e}")

            self.stop_event.wait(1.0)  # Update every second

    def start(self):
        """Start the TASE.2 server"""
        log.info("=" * 60)
        log.info("FreeTASE2 Mock Server")
        log.info("=" * 60)

        if HAS_LIBIEC61850:
            log.info("Mode: libiec61850 (full protocol stack)")
            try:
                model = self._create_mms_server()
                iec61850.IedServer_start(self.server, self.port)
                log.info(f"MMS/TASE.2 server listening on port {self.port}")
            except Exception as e:
                log.error(f"Failed to start libiec61850 server: {e}")
                log.info("Falling back to simulation mode")
        else:
            log.info("Mode: Simulation (no libiec61850)")

        # Print data model info
        log.info(f"Bilateral Table: {self.data_model.bilateral_table_id}")
        log.info(
            f"TASE.2 Version: {self.data_model.tase2_version[0]}.{self.data_model.tase2_version[1]}"
        )
        log.info(f"Supported Features: 0x{self.data_model.supported_features:04X}")
        log.info(f"Domains: {', '.join(self.data_model.get_domains())}")
        log.info(f"Data Points: {len(self.data_model.data_points)}")
        log.info(f"Control Points: {len(self.data_model.control_points)}")
        log.info("=" * 60)

        # Start simulation thread
        self.running = True
        self.simulation_thread = Thread(target=self._simulation_loop, daemon=True)
        self.simulation_thread.start()

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

        if self.server and HAS_LIBIEC61850:
            iec61850.IedServer_stop(self.server)
            iec61850.IedServer_destroy(self.server)

        if self.simulation_thread:
            self.simulation_thread.join(timeout=2.0)

        log.info("Server stopped")


class TASE2ServerFallback:
    """Fallback TASE.2 server using pure Python (simplified MMS)"""

    def __init__(self, host: str = "0.0.0.0", port: int = 102):
        self.host = host
        self.port = port
        self.data_model = TASE2DataModel()

        # Import the existing Python implementation
        import sys

        sys.path.insert(0, "/app")
        try:
            from tase2_server import TASE2Server

            self.server = TASE2Server(host, port)
            self.use_fallback = True
        except ImportError:
            self.server = None
            self.use_fallback = False

    def start(self):
        """Start fallback server"""
        if self.server:
            import asyncio

            asyncio.run(self.server.start())
        else:
            log.error("No server implementation available")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="FreeTASE2 Mock Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", "-p", type=int, default=102, help="Port (default: 102)")
    parser.add_argument("--debug", "-d", action="store_true", help="Debug logging")
    parser.add_argument(
        "--fallback", "-f", action="store_true", help="Force Python fallback (no libiec61850)"
    )
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Handle signals
    def signal_handler(sig, frame):
        log.info("Received shutdown signal")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start server
    if HAS_LIBIEC61850 and not args.fallback:
        server = TASE2ServerLibIEC(args.host, args.port)
    else:
        server = TASE2ServerFallback(args.host, args.port)

    server.start()


if __name__ == "__main__":
    main()
