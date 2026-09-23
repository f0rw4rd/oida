"""Connection layer for protocol fuzzing.

This module provides transport-level connections for fuzzing:
- TCP, SSL, UDP socket connections
- Serial connections for Modbus RTU
- Raw socket connections for low-level fuzzing
- Scapy-based connections for custom packet crafting
- Stateful connections with handshake support

All imports are lazy to avoid pulling in boofuzz at CLI startup time.
"""

# Cache for loaded modules/classes
_cache = {}


def __getattr__(name):
    """Lazy imports for all connection classes (requires boofuzz)."""
    if name in _cache:
        return _cache[name]

    _boofuzz_attrs = {"TCPSocketConnection", "SSLSocketConnection", "UDPSocketConnection"}
    _base_attrs = {"BaseConnection", "ConnectionFactory", "MockConnection", "MockConnectionFactory"}
    _tcp_attrs = {"RealConnectionFactory", "IEC104SocketConnection", "ResilientTCPConnection"}
    _udp_attrs = {"CountingUDPConnection"}
    _raw_attrs = {"RawSocketConnection"}
    _serial_attrs = {"SerialConnection", "parse_serial_target"}
    _scapy_attrs = {"ScapyRawConnection"}
    _stateful_attrs = {"StatefulConnection", "TLSHandler", "TLSUpgradeMixin", "BannerConnection"}

    if name in _boofuzz_attrs:
        from boofuzz import TCPSocketConnection, SSLSocketConnection, UDPSocketConnection

        _cache.update(
            {
                "TCPSocketConnection": TCPSocketConnection,
                "SSLSocketConnection": SSLSocketConnection,
                "UDPSocketConnection": UDPSocketConnection,
            }
        )
        return _cache[name]

    if name in _base_attrs:
        from oida.fuzz.core.connections.base import (
            BaseConnection,
            ConnectionFactory,
            MockConnection,
            MockConnectionFactory,
        )

        _cache.update(
            {
                "BaseConnection": BaseConnection,
                "ConnectionFactory": ConnectionFactory,
                "MockConnection": MockConnection,
                "MockConnectionFactory": MockConnectionFactory,
            }
        )
        return _cache[name]

    if name in _tcp_attrs:
        from oida.fuzz.core.connections.tcp import (
            RealConnectionFactory,
            IEC104SocketConnection,
            ResilientTCPConnection,
        )

        _cache.update(
            {
                "RealConnectionFactory": RealConnectionFactory,
                "IEC104SocketConnection": IEC104SocketConnection,
                "ResilientTCPConnection": ResilientTCPConnection,
            }
        )
        return _cache[name]

    if name in _udp_attrs:
        from oida.fuzz.core.connections.udp import CountingUDPConnection

        _cache["CountingUDPConnection"] = CountingUDPConnection
        return CountingUDPConnection

    if name in _raw_attrs:
        from oida.fuzz.core.connections.raw_socket import RawSocketConnection

        _cache.update({"RawSocketConnection": RawSocketConnection})
        return _cache[name]

    if name in _serial_attrs:
        from oida.fuzz.core.connections.serial import SerialConnection, parse_serial_target

        _cache.update(
            {"SerialConnection": SerialConnection, "parse_serial_target": parse_serial_target}
        )
        return _cache[name]

    if name in _scapy_attrs:
        from oida.fuzz.core.connections.scapy import ScapyRawConnection

        _cache["ScapyRawConnection"] = ScapyRawConnection
        return ScapyRawConnection

    if name in _stateful_attrs:
        from oida.fuzz.core.connections.stateful import (
            StatefulConnection,
            TLSHandler,
            TLSUpgradeMixin,
            BannerConnection,
        )

        _cache.update(
            {
                "StatefulConnection": StatefulConnection,
                "TLSHandler": TLSHandler,
                "TLSUpgradeMixin": TLSUpgradeMixin,
                "BannerConnection": BannerConnection,
            }
        )
        return _cache[name]

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Boofuzz re-exports
    "TCPSocketConnection",
    "SSLSocketConnection",
    "UDPSocketConnection",
    # Base classes
    "BaseConnection",
    "ConnectionFactory",
    "MockConnection",
    "MockConnectionFactory",
    # TCP/SSL connections
    "RealConnectionFactory",
    "IEC104SocketConnection",
    "ResilientTCPConnection",
    # UDP connections
    "CountingUDPConnection",
    # Raw socket
    "RawSocketConnection",
    # Serial
    "SerialConnection",
    "parse_serial_target",
    # Scapy
    "ScapyRawConnection",
    # Stateful connections
    "StatefulConnection",
    "TLSHandler",
    "TLSUpgradeMixin",  # Deprecated: use TLSHandler composition instead
    "BannerConnection",
]
