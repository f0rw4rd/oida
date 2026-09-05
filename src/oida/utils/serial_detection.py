"""
Serial port auto-detection utilities.

Provides automatic detection of serial port parameters including baud rate,
parity, stop bits, and byte size.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple
import string
import time

from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)

try:
    import serial
    import serial.tools.list_ports

    PYSERIAL_AVAILABLE = True
except ImportError:
    PYSERIAL_AVAILABLE = False


class DetectionMethod(Enum):
    """Detection method for serial parameter auto-detection."""

    PASSIVE = "passive"  # Listen for incoming data
    ACTIVE = "active"  # Send probe strings


@dataclass
class SerialConfig:
    """Detected serial port configuration."""

    port: str
    baudrate: int
    parity: str = "N"  # N, E, O
    stopbits: int = 1  # 1, 2
    bytesize: int = 8  # 7, 8
    confidence: float = 0.0  # 0.0 - 1.0

    def __str__(self) -> str:
        parity_map = {"N": "None", "E": "Even", "O": "Odd"}
        return (
            f"Port:     {self.port}\n"
            f"Baudrate: {self.baudrate}\n"
            f"Parity:   {parity_map.get(self.parity, self.parity)}\n"
            f"Stopbits: {self.stopbits}\n"
            f"Bytesize: {self.bytesize}\n"
            f"Confidence: {self.confidence:.0%}"
        )

    def as_dict(self) -> dict:
        """Return configuration as dictionary."""
        return {
            "port": self.port,
            "baudrate": self.baudrate,
            "parity": self.parity,
            "stopbits": self.stopbits,
            "bytesize": self.bytesize,
            "confidence": self.confidence,
        }


@dataclass
class PortInfo:
    """Information about an available serial port."""

    device: str  # /dev/ttyUSB0
    description: str  # USB Serial
    hwid: str  # USB VID:PID
    manufacturer: Optional[str] = None

    def __str__(self) -> str:
        parts = [self.device]
        if self.description:
            parts.append(f"- {self.description}")
        if self.hwid:
            parts.append(f"({self.hwid})")
        return "  ".join(parts)


class SerialDetector:
    """
    Auto-detect serial port parameters.

    Supports two detection methods:
    - Passive: Listen for incoming data and analyze character patterns
    - Active: Send probe strings and analyze responses

    Example usage:
        detector = SerialDetector()

        # List available ports
        ports = detector.list_ports()

        # Detect parameters using passive listening
        config = detector.detect('/dev/ttyUSB0', DetectionMethod.PASSIVE)

        # Detect with full parameter sweep
        config = detector.detect('/dev/ttyUSB0', DetectionMethod.ACTIVE, full_sweep=True)
    """

    # Standard baud rates to test (ordered by commonality)
    STANDARD_BAUDS = [115200, 57600, 38400, 19200, 9600, 4800, 2400, 1200]

    # Extended baud rates for comprehensive testing
    EXTENDED_BAUDS = [
        921600,
        460800,
        230400,
        115200,
        57600,
        38400,
        19200,
        9600,
        4800,
        2400,
        1200,
        600,
        300,
    ]

    # Serial parameter options
    PARITY_OPTIONS = ["N", "E", "O"]
    STOPBITS_OPTIONS = [1, 2]
    BYTESIZE_OPTIONS = [8, 7]

    # Probe strings for active detection
    PROBE_STRINGS = [
        b"\r\n",  # Universal newline
        b"AT\r\n",  # AT modem command
        b"\x00",  # Null byte
    ]

    # Character sets for scoring
    VOWELS = set("aeiouAEIOU")
    PUNCTUATION = set(".,;:!?")
    WHITESPACE = set(" \t\n\r")

    def __init__(self, verbose: bool = False):
        """
        Initialize serial detector.

        Args:
            verbose: Enable verbose output during detection
        """
        self.verbose = verbose
        self._check_dependencies()

    def _check_dependencies(self) -> None:
        """Check if pyserial is available."""
        if not PYSERIAL_AVAILABLE:
            raise ImportError(
                "pyserial is required for serial detection. Install with: pip install oida-ics[serial]"
            )

    def _log(self, message: str) -> None:
        """Log message if verbose mode is enabled."""
        if self.verbose:
            logger.info(message)

    @staticmethod
    def list_ports() -> List[PortInfo]:
        """
        Enumerate available serial ports.

        Returns:
            List of PortInfo objects for each available port
        """
        if not PYSERIAL_AVAILABLE:
            return []

        ports = []
        for port in serial.tools.list_ports.comports():
            ports.append(
                PortInfo(
                    device=port.device,
                    description=port.description or "",
                    hwid=port.hwid or "",
                    manufacturer=port.manufacturer,
                )
            )
        return sorted(ports, key=lambda p: p.device)

    def detect(
        self,
        port: str,
        method: DetectionMethod,
        full_sweep: bool = False,
        timeout: float = 5.0,
        extended_bauds: bool = False,
    ) -> Optional[SerialConfig]:
        """
        Detect serial port parameters.

        Args:
            port: Serial port device path (e.g., /dev/ttyUSB0)
            method: Detection method (PASSIVE or ACTIVE)
            full_sweep: Test all parity/stopbit combinations
            timeout: Timeout in seconds for each test
            extended_bauds: Use extended baud rate list

        Returns:
            SerialConfig with detected parameters, or None if detection failed
        """
        bauds = self.EXTENDED_BAUDS if extended_bauds else self.STANDARD_BAUDS

        if full_sweep:
            # Generate all parameter combinations
            params = [
                (p, s, b)
                for p in self.PARITY_OPTIONS
                for s in self.STOPBITS_OPTIONS
                for b in self.BYTESIZE_OPTIONS
            ]
        else:
            # Default to 8N1
            params = [("N", 1, 8)]

        self._log(f"Starting {method.value} detection on {port}")
        self._log(f"Testing {len(bauds)} baud rates × {len(params)} param combinations")

        if method == DetectionMethod.PASSIVE:
            return self._passive_detect(port, bauds, params, timeout)
        elif method == DetectionMethod.ACTIVE:
            return self._active_detect(port, bauds, params, timeout)
        else:
            raise ValueError(f"Unknown detection method: {method}")

    def _passive_detect(
        self, port: str, bauds: List[int], params: List[Tuple[str, int, int]], timeout: float
    ) -> Optional[SerialConfig]:
        """
        Detect parameters by passively listening for incoming data.

        Reads data at each baud rate and scores it based on the ratio
        of printable ASCII characters.

        Args:
            port: Serial port device path
            bauds: List of baud rates to test
            params: List of (parity, stopbits, bytesize) tuples
            timeout: Read timeout in seconds

        Returns:
            Best matching SerialConfig or None
        """
        best_config = None
        best_score = 0.0

        for baud in bauds:
            for parity, stopbits, bytesize in params:
                config_str = f"{baud} {bytesize}{parity}{stopbits}"
                self._log(f"Testing {config_str}...")

                try:
                    score, data_len = self._test_passive(
                        port, baud, parity, stopbits, bytesize, timeout
                    )

                    if data_len == 0:
                        self._log(f"  {config_str}: no data")
                    else:
                        self._log(f"  {config_str}: {data_len} bytes, score: {score:.2f}")

                    if score > best_score:
                        best_score = score
                        best_config = SerialConfig(
                            port=port,
                            baudrate=baud,
                            parity=parity,
                            stopbits=stopbits,
                            bytesize=bytesize,
                            confidence=score,
                        )

                        # Early exit if we found a very good match
                        if score >= 0.9:
                            self._log(f"Found excellent match: {config_str}")
                            return best_config

                except serial.SerialException as e:
                    self._log(f"  {config_str}: error - {e}")
                    continue

        # Return best match if confidence is above threshold
        if best_config and best_config.confidence >= 0.5:
            return best_config

        return None

    def _test_passive(
        self, port: str, baud: int, parity: str, stopbits: int, bytesize: int, timeout: float
    ) -> Tuple[float, int]:
        """
        Test a specific configuration by reading data.

        Args:
            port: Serial port device path
            baud: Baud rate
            parity: Parity setting
            stopbits: Stop bits
            bytesize: Byte size
            timeout: Read timeout

        Returns:
            Tuple of (score, bytes_received)
        """
        parity_map = {"N": serial.PARITY_NONE, "E": serial.PARITY_EVEN, "O": serial.PARITY_ODD}
        stopbits_map = {1: serial.STOPBITS_ONE, 2: serial.STOPBITS_TWO}

        with serial.Serial(
            port=port,
            baudrate=baud,
            parity=parity_map[parity],
            stopbits=stopbits_map[stopbits],
            bytesize=bytesize,
            timeout=timeout,
        ) as ser:
            # Clear any buffered data
            ser.reset_input_buffer()

            # Wait and read
            time.sleep(0.1)  # Small delay to allow data to arrive
            data = ser.read(1024)  # Read up to 1KB

            if not data:
                return 0.0, 0

            return self._score_data(data), len(data)

    def _active_detect(
        self, port: str, bauds: List[int], params: List[Tuple[str, int, int]], timeout: float
    ) -> Optional[SerialConfig]:
        """
        Detect parameters by actively probing the device.

        Sends probe strings and analyzes responses.

        Args:
            port: Serial port device path
            bauds: List of baud rates to test
            params: List of (parity, stopbits, bytesize) tuples
            timeout: Response timeout in seconds

        Returns:
            First valid SerialConfig or None
        """
        best_config = None
        best_score = 0.0

        for baud in bauds:
            for parity, stopbits, bytesize in params:
                config_str = f"{baud} {bytesize}{parity}{stopbits}"
                self._log(f"Testing {config_str}...")

                try:
                    score = self._test_active(port, baud, parity, stopbits, bytesize, timeout)

                    if score > 0:
                        self._log(f"  {config_str}: response received, score: {score:.2f}")
                    else:
                        self._log(f"  {config_str}: no valid response")

                    if score > best_score:
                        best_score = score
                        best_config = SerialConfig(
                            port=port,
                            baudrate=baud,
                            parity=parity,
                            stopbits=stopbits,
                            bytesize=bytesize,
                            confidence=score,
                        )

                        # Early exit on good response
                        if score >= 0.7:
                            self._log(f"Found good match: {config_str}")
                            return best_config

                except serial.SerialException as e:
                    self._log(f"  {config_str}: error - {e}")
                    continue

        if best_config and best_config.confidence >= 0.3:
            return best_config

        return None

    def _test_active(
        self, port: str, baud: int, parity: str, stopbits: int, bytesize: int, timeout: float
    ) -> float:
        """
        Test a configuration by sending probes.

        Args:
            port: Serial port device path
            baud: Baud rate
            parity: Parity setting
            stopbits: Stop bits
            bytesize: Byte size
            timeout: Response timeout

        Returns:
            Score (0.0 - 1.0) based on response quality
        """
        parity_map = {"N": serial.PARITY_NONE, "E": serial.PARITY_EVEN, "O": serial.PARITY_ODD}
        stopbits_map = {1: serial.STOPBITS_ONE, 2: serial.STOPBITS_TWO}

        best_score = 0.0

        with serial.Serial(
            port=port,
            baudrate=baud,
            parity=parity_map[parity],
            stopbits=stopbits_map[stopbits],
            bytesize=bytesize,
            timeout=timeout,
            write_timeout=timeout,
        ) as ser:
            for probe in self.PROBE_STRINGS:
                # Clear buffers
                ser.reset_input_buffer()
                ser.reset_output_buffer()

                # Send probe
                try:
                    ser.write(probe)
                    ser.flush()
                except serial.SerialException as e:
                    logger.debug(f"ser.write(probe): {e}")
                    continue

                # Wait for response
                time.sleep(0.2)
                response = ser.read(256)

                if response:
                    score = self._score_data(response)
                    if score > best_score:
                        best_score = score

        return best_score

    def _score_data(self, data: bytes) -> float:
        """
        Score data quality based on character classification.

        Uses a multi-factor scoring system:
        - Base score: ratio of printable ASCII characters
        - Bonus: presence of vowels (indicates real text)
        - Bonus: presence of punctuation
        - Bonus: presence of whitespace

        Args:
            data: Raw bytes to score

        Returns:
            Score from 0.0 to 1.0
        """
        if not data:
            return 0.0

        total = len(data)
        printable_set = set(string.printable.encode("ascii"))

        # Count character types
        printable = 0
        vowels = 0
        punctuation = 0
        whitespace = 0

        for byte in data:
            if byte in printable_set:
                printable += 1
                char = chr(byte)
                if char in self.VOWELS:
                    vowels += 1
                if char in self.PUNCTUATION:
                    punctuation += 1
                if char in self.WHITESPACE:
                    whitespace += 1

        # Base score: printable ratio
        base_score = printable / total

        # Bonus multipliers (up to 1.5x)
        multiplier = 1.0
        if vowels > 0:
            multiplier += 0.15
        if punctuation > 0:
            multiplier += 0.15
        if whitespace > 0:
            multiplier += 0.2

        # Final score capped at 1.0
        return min(1.0, base_score * multiplier)


def check_serial_available() -> bool:
    """Check if pyserial is available."""
    return PYSERIAL_AVAILABLE
