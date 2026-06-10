"""
OIDA Fuzzer Configuration Module

Core configuration classes and utilities for the OIDA fuzzing framework.
"""

from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum


@dataclass
class MonitorSpec:
    """Single monitor specification."""

    name: str
    interval: Optional[int] = None  # None = use default from registry


@dataclass
class MonitorConfig:
    """Monitor configuration for fuzzing sessions.

    Supports parsing CLI specifications like:
    - 'ping,socket'           -> use defaults
    - 'ping:50,modbus:10'     -> custom intervals
    - 'none'                  -> disable all monitors
    """

    monitors: List[MonitorSpec]
    logic: str = "and"  # "and" or "or"

    @classmethod
    def parse(cls, monitors_str: str, logic: str = "and") -> "MonitorConfig":
        """Parse CLI string like 'ping:50,socket,modbus:10'.

        Args:
            monitors_str: Comma-separated monitor specs with optional intervals
            logic: Combination logic ('and' or 'or')

        Returns:
            MonitorConfig instance

        Examples:
            >>> MonitorConfig.parse('ping,socket')
            MonitorConfig(monitors=[MonitorSpec('ping'), MonitorSpec('socket')], logic='and')
            >>> MonitorConfig.parse('ping:50,modbus:10', 'or')
            MonitorConfig(monitors=[MonitorSpec('ping', 50), MonitorSpec('modbus', 10)], logic='or')
            >>> MonitorConfig.parse('none')
            MonitorConfig(monitors=[], logic='and')
        """
        # Normalize logic
        logic = logic.lower()
        if logic not in ("and", "or"):
            logic = "and"

        # Handle 'none' - disable all monitors
        if monitors_str.lower().strip() == "none":
            return cls(monitors=[], logic=logic)

        specs = []
        for part in monitors_str.split(","):
            part = part.strip()
            if not part:
                continue

            if ":" in part:
                name, interval_str = part.split(":", 1)
                try:
                    interval = int(interval_str.strip())
                except ValueError:
                    interval = None
                specs.append(MonitorSpec(name=name.strip().lower(), interval=interval))
            else:
                specs.append(MonitorSpec(name=part.strip().lower(), interval=None))

        return cls(monitors=specs, logic=logic)

    def is_empty(self) -> bool:
        """Check if no monitors are configured."""
        return len(self.monitors) == 0

    def get_monitor_names(self) -> List[str]:
        """Get list of monitor names."""
        return [spec.name for spec in self.monitors]

    def format_display(self) -> str:
        """Format for display in startup output.

        Returns:
            String like 'ping:100, modbus:10 (logic=AND)'
        """
        if self.is_empty():
            return "none"

        parts = []
        for spec in self.monitors:
            if spec.interval is not None:
                parts.append(f"{spec.name}:{spec.interval}")
            else:
                parts.append(spec.name)

        logic_str = self.logic.upper()
        return f"{', '.join(parts)} (logic={logic_str})"


class ProtocolType(Enum):
    TCP = "tcp"
    SSL = "ssl"
    UDP = "udp"
    RAW = "raw"
    SERIAL = "serial"
    BLE = "ble"
    IEC104 = "iec104"  # IEC 60870-5-104 with automatic STARTDT handshake
    ICMP = "icmp"  # ICMP raw sockets (kernel handles IP header and checksum)
    ICMPV6 = "icmpv6"  # ICMPv6 raw sockets (kernel handles IPv6 header and checksum)


@dataclass
class FuzzerConfig:
    target_ip: str
    target_port: int
    protocol: str = "unknown"  # Protocol name (modbus, opcua, etc.) for test case tracking
    session_filename: str = "fuzzer_session"
    crash_threshold: int = 5
    restart_timeout: int = 5
    web_port: int = 26000
    process_monitor_port: Optional[int] = None
    log_session: bool = True
    skip_pre_send_checks: bool = True
    monitor_check_interval: int = 100
    protocol_type: ProtocolType = ProtocolType.TCP
    protocol_options: Dict[str, Any] = None
    console_output: bool = False  # Disable verbose console output by default
    web_interface: bool = True  # Enable web interface by default
    seed: Optional[int] = None  # Random seed for protocol-level randomization
    index_start: int = 1  # Start test case index (for replaying specific ranges)
    index_end: Optional[int] = None  # End test case index (None = fuzz all)
    store_all_payloads: bool = (
        False  # Store all payloads (old behavior, larger DB). Default: lightweight mode
    )
    distribution_total: Optional[int] = None  # Total number of machines for distributed fuzzing
    distribution_id: Optional[int] = None  # This machine's ID (1-indexed) in distributed setup
    enabled_requests: Optional[List[str]] = None  # Whitelist: only run these requests
    disabled_requests: Optional[List[str]] = None  # Blacklist: skip these requests
    monitor_config: Optional[MonitorConfig] = (
        None  # Monitor configuration (None = use protocol defaults)
    )
    monitor_logic: str = "and"  # Default combination logic for monitors ("and" or "or")
    boofuzz_db: bool = False  # Enable boofuzz-results database (disabled by default)
    reuse_target_connection: bool = (
        True  # Reuse TCP connection between test cases (faster, disable for crash detection)
    )
    receive_data_after_fuzz: bool = True  # Wait for response after fuzz payload
    receive_data_after_each_request: bool = True  # Wait for response after setup/prereq requests
    sleep_time: float = 0.0  # Delay between test cases in seconds (0.0 = no delay)
    monitor_retry_delay: float = (
        0.1  # Delay between monitor retry attempts in seconds (default=0.1)
    )
    # Socket timeouts / reconnection (None = use connection/protocol default)
    recv_timeout: Optional[float] = None  # Data-socket receive timeout (default 5.0)
    send_timeout: Optional[float] = None  # Data-socket send timeout (default 5.0)
    reconnect_delay: Optional[float] = None  # ResilientTCPConnection retry delay (default 0.5)
    max_reconnect_attempts: Optional[int] = None  # Reconnect attempts on RST (default 3)
    # TLS configuration
    tls_enabled: bool = False  # Enable TLS/SSL for connection (no verification)
    # Capability enumeration
    enumerate: bool = True  # Probe target capabilities before fuzzing (default=True)
    # Crash handling
    pause_on_crash: bool = False  # Pause fuzzing when crash is detected (wait for user input)
    graceful_degradation: bool = (
        False  # Disable failed monitors instead of stopping (continue with remaining)
    )
    # Timeout auto-calibration (measures latency before fuzzing, sets timeouts from it)
    calibrate: bool = True  # Run startup calibration (skipped for any user-set timeout)
    calibration_probes: int = 50  # Probes to send during calibration (min 30 clean)
    adaptive_timeout: bool = False  # Adapt monitor timeout online (Jacobson/Karels EWMA)
    detect_drift: bool = False  # Recalibrate on sustained latency drift (implies adaptive)

    def __post_init__(self):
        """Initialize protocol_options if not provided"""
        if self.protocol_options is None:
            self.protocol_options = {}

    def get_option(self, key: str, default: Any = None) -> Any:
        """Get a protocol-specific option with a default value"""
        return self.protocol_options.get(key, default)

    def set_option(self, key: str, value: Any) -> None:
        """Set a protocol-specific option"""
        if self.protocol_options is None:
            self.protocol_options = {}
        self.protocol_options[key] = value


def hexdump(data, bytes_per_line=16):
    """Create a hexdump representation of binary data."""
    result = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i : i + bytes_per_line]
        # Hex values
        hex_values = " ".join(f"{b:02x}" for b in chunk)
        # ASCII representation (printable characters or dot)
        ascii_values = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        # Add line with offset, hex values, and ASCII
        result.append(f"{i:08x}:  {hex_values:<{bytes_per_line * 3}}  |{ascii_values}|")
    return "\n".join(result)
