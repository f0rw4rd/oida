"""
Serial Connection Module

Provides serial port connectivity for protocols like Modbus RTU.
"""

import serial
from typing import Optional

from ....utils.ics_logger import get_logger

# Module-level logger for standalone functions
_module_log = get_logger("SERIAL", "parse", 0)


class SerialConnection:
    """
    Serial connection wrapper compatible with boofuzz connection interface.

    Supports RS-232/RS-485 serial communication for protocols like Modbus RTU.
    """

    def __init__(
        self,
        port: str,
        baudrate: int = 9600,
        bytesize: int = 8,
        parity: str = "N",
        stopbits: int = 1,
        timeout: float = 1.0,
    ):
        """
        Initialize serial connection parameters.

        Args:
            port: Serial port device path (e.g., '/dev/ttyUSB0', 'COM3')
            baudrate: Communication speed (9600, 19200, 38400, 57600, 115200)
            bytesize: Number of data bits (5, 6, 7, 8)
            parity: Parity checking ('N'=None, 'E'=Even, 'O'=Odd, 'M'=Mark, 'S'=Space)
            stopbits: Number of stop bits (1, 1.5, 2)
            timeout: Read timeout in seconds
        """
        self.port = port
        self.baudrate = baudrate
        self.bytesize = bytesize
        self.parity = parity
        self.stopbits = stopbits
        self.timeout = timeout
        self._serial: Optional[serial.Serial] = None
        self._log = get_logger("SERIAL", port, baudrate)

        self._log.display(f"Configured: {port} @ {baudrate} baud, {bytesize}{parity}{stopbits}")

    def open(self):
        """Open the serial port connection."""
        if self._serial and self._serial.is_open:
            self._log.warning(f"Serial port {self.port} already open")
            return

        try:
            self._serial = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                bytesize=self.bytesize,
                parity=self.parity,
                stopbits=self.stopbits,
                timeout=self.timeout,
            )
            self._log.success(f"Opened serial port {self.port}")
        except serial.SerialException as e:
            self._log.fail(f"Failed to open serial port {self.port}: {e}")
            raise

    def close(self):
        """Close the serial port connection."""
        if self._serial and self._serial.is_open:
            self._serial.close()
            self._log.display(f"Closed serial port {self.port}")
        self._serial = None

    def send(self, data: bytes) -> int:
        """
        Send data over serial port.

        Args:
            data: Bytes to send

        Returns:
            Number of bytes written
        """
        if not self._serial or not self._serial.is_open:
            raise RuntimeError(f"Serial port {self.port} not open")

        bytes_written = self._serial.write(data)
        self._serial.flush()  # Ensure data is transmitted
        self._log.debug(f"Sent {bytes_written} bytes: {data.hex()}")
        return bytes_written

    def recv(self, size: int = 1024) -> bytes:
        """
        Receive data from serial port.

        Args:
            size: Maximum number of bytes to read

        Returns:
            Received bytes (may be empty if timeout)
        """
        if not self._serial or not self._serial.is_open:
            raise RuntimeError(f"Serial port {self.port} not open")

        data = self._serial.read(size)
        if data:
            self._log.debug(f"Received {len(data)} bytes: {data.hex()}")
        return data

    @property
    def info(self) -> str:
        """Get connection info string."""
        return f"{self.port} @ {self.baudrate} baud ({self.bytesize}{self.parity}{self.stopbits})"


def parse_serial_target(target: str) -> tuple:
    """
    Parse serial target string into components.

    Format: /dev/ttyUSB0:9600:8n1

    Args:
        target: Serial target string

    Returns:
        Tuple of (port, baudrate, bytesize, parity, stopbits)

    Examples:
        >>> parse_serial_target('/dev/ttyUSB0')
        ('/dev/ttyUSB0', 9600, 8, 'N', 1)

        >>> parse_serial_target('/dev/ttyUSB0:19200')
        ('/dev/ttyUSB0', 19200, 8, 'N', 1)

        >>> parse_serial_target('/dev/ttyUSB0:9600:8n1')
        ('/dev/ttyUSB0', 9600, 8, 'N', 1)

        >>> parse_serial_target('COM3:115200:8e1')
        ('COM3', 115200, 8, 'E', 1)
    """
    # Default values
    port = target
    baudrate = 9600
    bytesize = 8
    parity = "N"
    stopbits = 1

    # Split by colon
    parts = target.split(":")

    if len(parts) >= 1:
        port = parts[0]

    if len(parts) >= 2:
        try:
            baudrate = int(parts[1])
        except ValueError:
            _module_log.warning(f"Invalid baudrate '{parts[1]}', using default {baudrate}")

    if len(parts) >= 3:
        # Parse format like "8n1" or "8e1" or "7o2"
        format_str = parts[2].lower()

        if len(format_str) >= 1 and format_str[0].isdigit():
            bytesize = int(format_str[0])

        if len(format_str) >= 2:
            parity = format_str[1].upper()

        if len(format_str) >= 3 and format_str[2].isdigit():
            stopbits = int(format_str[2])

    return (port, baudrate, bytesize, parity, stopbits)
