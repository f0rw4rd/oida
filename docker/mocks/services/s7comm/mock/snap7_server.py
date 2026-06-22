#!/usr/bin/env python3
"""
Snap7 Mock Server - Simulates Siemens S7 PLC for testing

This server provides a mock S7 PLC that responds to Snap7 client requests.
Used for testing oida s7 scanner without real hardware.

Password Note:
    The python-snap7 Server class does NOT natively support session password
    enforcement.  All client operations (including get_cpu_state) succeed
    regardless of whether set_session_password() was called on the client.

    This means --default-creds and --brute tests exercise the full code path
    (load passwords, iterate, call set_session_password + get_cpu_state) and
    will report the first password as "found".  This is expected behavior for
    Category B integration tests that verify the code runs without crashing.

    SNAP7_PASSWORD is accepted as an environment variable so the mock stays
    consistent with the pattern used by other mock servers, and so the value
    can be changed if a future snap7 release adds server-side auth.

Usage:
    python snap7_server.py [--port PORT] [--cpu-type TYPE]

Environment variables:
    SNAP7_PORT      - Server port (default: 102)
    SNAP7_CPU_TYPE  - CPU type: 1200, 1500, 300, 400 (default: 1200)
    SNAP7_DB_COUNT  - Number of data blocks (default: 10)
    SNAP7_PASSWORD  - Session password (default: "1234"; not enforced by
                      python-snap7 Server but recorded for documentation)
"""

import os
import sys
import time
import signal
import logging
import ctypes
from typing import Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("snap7-server")

try:
    import snap7
    from snap7.server import Server
    from snap7 import SrvArea
except ImportError as e:
    logger.error(f"python-snap7 not installed or import error: {e}")
    logger.error("Run: pip install python-snap7")
    sys.exit(1)


class Snap7MockServer:
    """Mock Siemens S7 PLC server for testing"""

    def __init__(
        self,
        port: int = 102,
        cpu_type: str = "1200",
        db_count: int = 10,
        password: str = "1234",
    ):
        self.port = port
        self.cpu_type = cpu_type
        self.db_count = db_count
        self.password = password
        self.server: Optional[Server] = None
        self.running = False

        # Memory areas (pre-allocated)
        self.memory_size = 1024  # bytes per area
        self.db_size = 256  # bytes per data block

    def _create_data_area(self, size: int, pattern: int = 0) -> ctypes.Array:
        """Create a data area with optional pattern fill"""
        data = (ctypes.c_uint8 * size)()
        if pattern:
            for i in range(size):
                data[i] = (pattern + i) % 256
        return data

    def _setup_memory_areas(self):
        """Register all memory areas with realistic test data"""
        logger.info("Setting up memory areas...")

        # Process inputs (PE) - simulated sensor values
        pe_data = self._create_data_area(self.memory_size)
        pe_data[0] = 0xFF  # All inputs high
        pe_data[1] = 0x55  # Alternating pattern
        pe_data[2] = 0xAA
        self.server.register_area(SrvArea.PE, 0, pe_data)
        logger.info(f"  PE (Inputs): {self.memory_size} bytes")

        # Process outputs (PA) - simulated actuator states
        pa_data = self._create_data_area(self.memory_size)
        pa_data[0] = 0x0F  # Some outputs active
        self.server.register_area(SrvArea.PA, 0, pa_data)
        logger.info(f"  PA (Outputs): {self.memory_size} bytes")

        # Merkers/Flags (MK) - internal flags
        mk_data = self._create_data_area(self.memory_size)
        mk_data[0] = 0x01  # System running flag
        mk_data[1] = 0x00  # Error flags clear
        self.server.register_area(SrvArea.MK, 0, mk_data)
        logger.info(f"  MK (Flags): {self.memory_size} bytes")

        # Data blocks (DB1 - DBn)
        for db_num in range(1, self.db_count + 1):
            db_data = self._create_data_area(self.db_size, pattern=db_num)
            # Add some structured data to each DB
            db_data[0] = db_num  # DB number marker
            db_data[1] = 0x00  # Status byte
            # Simulated values at offset 2-5 (32-bit value)
            db_data[2] = 0x00
            db_data[3] = 0x00
            db_data[4] = (db_num * 100) >> 8
            db_data[5] = (db_num * 100) & 0xFF
            self.server.register_area(SrvArea.DB, db_num, db_data)

        logger.info(f"  DB1-DB{self.db_count}: {self.db_size} bytes each")

        # Counters (CT)
        ct_data = self._create_data_area(512)
        self.server.register_area(SrvArea.CT, 0, ct_data)
        logger.info("  CT (Counters): 512 bytes")

        # Timers (TM)
        tm_data = self._create_data_area(512)
        self.server.register_area(SrvArea.TM, 0, tm_data)
        logger.info("  TM (Timers): 512 bytes")

    def _event_callback(self, event):
        """Handle server events for logging"""
        # Event logging (optional, can be verbose)
        pass

    def _rw_callback(self, sender, operation, tag, data):
        """Handle read/write operations"""
        # Can be used to log or validate access
        return 0  # Allow operation

    def start(self):
        """Start the mock S7 server"""
        logger.info("=" * 60)
        logger.info("Snap7 Mock Server - Siemens S7 PLC Simulator")
        logger.info("=" * 60)
        logger.info(f"CPU Type: S7-{self.cpu_type}")
        logger.info(f"Port: {self.port}")
        logger.info(f"Data Blocks: {self.db_count}")
        logger.info(f"Password: {self.password} (not enforced by snap7 Server)")
        logger.info("=" * 60)

        try:
            self.server = Server()

            # Setup memory areas
            self._setup_memory_areas()

            # Set callbacks (optional)
            # self.server.set_events_callback(self._event_callback)

            # Start server
            logger.info(f"Starting server on port {self.port}...")
            # In python-snap7 2.x, start() takes no arguments - port is always 102
            self.server.start()
            self.running = True

            logger.info("")
            logger.info("Server is running. Press Ctrl+C to stop.")
            logger.info("")
            logger.info("Test with: oida s7 <host> --port %d", self.port)
            logger.info("")

            # Keep server running
            while self.running:
                time.sleep(1)

        except Exception as e:
            logger.error(f"Server error: {e}")
            raise
        finally:
            self.stop()

    def stop(self):
        """Stop the server gracefully"""
        if self.server and self.running:
            logger.info("Stopping server...")
            self.running = False
            try:
                self.server.stop()
                self.server.destroy()
            except Exception as e:
                logger.debug(f"Error during shutdown: {e}")
            logger.info("Server stopped.")


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Snap7 Mock S7 PLC Server")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SNAP7_PORT", 102)),
        help="Server port (default: 102)",
    )
    parser.add_argument(
        "--cpu-type",
        choices=["1200", "1500", "300", "400"],
        default=os.environ.get("SNAP7_CPU_TYPE", "1200"),
        help="CPU type (default: 1200)",
    )
    parser.add_argument(
        "--db-count",
        type=int,
        default=int(os.environ.get("SNAP7_DB_COUNT", 10)),
        help="Number of data blocks (default: 10)",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("SNAP7_PASSWORD", "1234"),
        help="Session password (default: 1234, not enforced by snap7 Server)",
    )

    args = parser.parse_args()

    # Create and start server
    server = Snap7MockServer(
        port=args.port,
        cpu_type=args.cpu_type,
        db_count=args.db_count,
        password=args.password,
    )

    # Handle signals for graceful shutdown
    def signal_handler(signum, frame):
        logger.info("Received shutdown signal...")
        server.running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start server
    server.start()


if __name__ == "__main__":
    main()
