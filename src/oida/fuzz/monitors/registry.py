"""Monitor registry for fuzzing framework.

Provides a registry of available monitors with metadata for CLI integration
and dynamic monitor instantiation.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Type, Any

from boofuzz.monitors import BaseMonitor

import logging

logger = logging.getLogger(__name__)


@dataclass
class MonitorInfo:
    """Monitor metadata for registry."""

    name: str  # Short name (e.g., "ping")
    cls: Type[BaseMonitor]  # Monitor class
    default_interval: int  # Default check interval
    description: str  # Help text
    default_port: Optional[int] = None  # Default port if applicable


# Global registry
MONITOR_REGISTRY: Dict[str, MonitorInfo] = {}


def register_monitor(
    name: str,
    cls: Type[BaseMonitor],
    default_interval: int = 100,
    description: str = "",
    default_port: Optional[int] = None,
) -> None:
    """Register a monitor type.

    Args:
        name: Short name for CLI usage (e.g., "ping", "modbus")
        cls: Monitor class that inherits from BaseMonitor
        default_interval: Default check interval (test cases between checks)
        description: Human-readable description for help text
        default_port: Default port if the monitor requires one
    """
    MONITOR_REGISTRY[name.lower()] = MonitorInfo(
        name=name.lower(),
        cls=cls,
        default_interval=default_interval,
        description=description,
        default_port=default_port,
    )


def get_monitor(name: str) -> Optional[MonitorInfo]:
    """Get monitor info by name.

    Args:
        name: Monitor name (case-insensitive)

    Returns:
        MonitorInfo if found, None otherwise
    """
    return MONITOR_REGISTRY.get(name.lower())


def get_available_monitors() -> Dict[str, MonitorInfo]:
    """Get all available monitors.

    Returns:
        Dictionary of monitor name -> MonitorInfo
    """
    return MONITOR_REGISTRY.copy()


def create_monitor(
    name: str, host: str, port: Optional[int] = None, interval: Optional[int] = None, **kwargs: Any
) -> Optional[BaseMonitor]:
    """Create a monitor instance by name.

    Args:
        name: Monitor name (case-insensitive)
        host: Target host
        port: Target port (uses default if not specified)
        interval: Check interval (uses default if not specified)
        **kwargs: Additional arguments passed to monitor constructor

    Returns:
        Monitor instance if found and created, None otherwise
    """
    info = get_monitor(name)
    if info is None:
        return None

    # Determine port to use
    actual_port = port if port is not None else info.default_port

    # Determine interval to use
    actual_interval = interval if interval is not None else info.default_interval

    # Build constructor arguments based on monitor type
    # Different monitors have different constructor signatures
    try:
        # PingMonitor doesn't take port
        if name.lower() == "ping":
            return info.cls(host=host, **kwargs)

        # SocketHealthMonitor and most others take host and port
        if name.lower() == "socket":
            if actual_port is None:
                return None  # Socket monitor requires port
            return info.cls(host=host, port=actual_port, **kwargs)

        # Protocol-specific monitors with check_interval
        if name.lower() in (
            "modbus",
            "iec104",
            "mms",
            "mqtt",
            "opcua",
            "hl7",
            "http",
            "ftp",
            "smtp",
            "dns",
            "dhcp",
            "tftp",
        ):
            monitor_kwargs = {"host": host, "check_interval": actual_interval}
            if actual_port is not None:
                monitor_kwargs["port"] = actual_port
            monitor_kwargs.update(kwargs)
            return info.cls(**monitor_kwargs)

        # Fallback: try with host and port
        monitor_kwargs = {"host": host}
        if actual_port is not None:
            monitor_kwargs["port"] = actual_port
        monitor_kwargs.update(kwargs)
        return info.cls(**monitor_kwargs)

    except Exception as e:
        # registry.py is a module-level factory with no self context, so
        # the stdlib logger stays here — but with a descriptive message
        # so it's useful in debug output instead of just "Operation failed".
        logger.debug(f"Monitor registry: failed to instantiate {info.cls.__name__}: {e}")
        return None


def _init_registry() -> None:
    """Initialize the monitor registry with all available monitors."""
    # Import monitors - use lazy imports to avoid circular dependencies
    from .network import PingMonitor, SocketHealthMonitor
    from .industrial import ModbusMonitor, IEC104Monitor, MMSMonitor, MQTTMonitor, OPCUAMonitor
    from .application import HTTPGetMonitor, FTPCommandMonitor, SMTPCommandMonitor, DNSQueryMonitor
    from .infrastructure import DHCPDiscoverMonitor, TFTPReadMonitor
    from .medical import HL7Monitor

    # Network monitors
    register_monitor("ping", PingMonitor, 100, "ICMP ping check")
    register_monitor("socket", SocketHealthMonitor, 100, "TCP port check")

    # Industrial protocol monitors
    register_monitor("modbus", ModbusMonitor, 10, "Modbus read check", default_port=502)
    register_monitor("iec104", IEC104Monitor, 10, "IEC104 TESTFR check", default_port=2404)
    register_monitor("mms", MMSMonitor, 10, "MMS identify check", default_port=102)
    register_monitor("mqtt", MQTTMonitor, 10, "MQTT CONNECT/CONNACK check", default_port=1883)
    register_monitor("opcua", OPCUAMonitor, 10, "OPC UA Hello/Acknowledge check", default_port=4840)

    # Application protocol monitors
    register_monitor("http", HTTPGetMonitor, 50, "HTTP GET check", default_port=80)
    register_monitor("ftp", FTPCommandMonitor, 50, "FTP PWD check", default_port=21)
    register_monitor("smtp", SMTPCommandMonitor, 50, "SMTP EHLO check", default_port=25)
    register_monitor("dns", DNSQueryMonitor, 50, "DNS query check", default_port=53)

    # Infrastructure protocol monitors
    register_monitor("dhcp", DHCPDiscoverMonitor, 50, "DHCP discover check", default_port=67)
    register_monitor("tftp", TFTPReadMonitor, 50, "TFTP read check", default_port=69)

    # Medical protocol monitors
    register_monitor("hl7", HL7Monitor, 20, "HL7 ACK check", default_port=2575)


# Initialize registry on module import
_init_registry()


__all__ = [
    "MonitorInfo",
    "MONITOR_REGISTRY",
    "register_monitor",
    "get_monitor",
    "get_available_monitors",
    "create_monitor",
]
