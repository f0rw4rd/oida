#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Custom exception hierarchy for ICS protocol scanners.
Provides specific error types for better error handling and debugging.

Exception naming uses ICS prefix to avoid shadowing Python builtins:
- ICSConnectionError (not ConnectionError)
- ICSTimeoutError (not TimeoutError)
- ICSPermissionError (not PermissionError)

Note: Legacy aliases (ConnectionError, TimeoutError, PermissionError) were
removed to prevent accidental builtin shadowing on star-import.
"""

__all__ = [
    # Base exceptions
    "ICSProtocolError",
    "ICSConnectionError",
    "AuthenticationError",
    "ProtocolError",
    "DependencyError",
    "ConfigurationError",
    "ICSTimeoutError",
    "ICSPermissionError",
    "SecurityError",
    # Protocol-specific exceptions
    "ModbusError",
    "OPCUAError",
    "EtherCATError",
    "ADSError",
]


class ICSProtocolError(Exception):
    """Base exception for all ICS protocol scanner errors"""

    def __init__(self, message: str, protocol: str = "", error_code: str = ""):
        super().__init__(message)
        self.protocol = protocol
        self.error_code = error_code
        self.message = message

    def __str__(self) -> str:
        if self.protocol:
            return f"[{self.protocol}] {self.message}"
        return self.message


class ICSConnectionError(ICSProtocolError):
    """Raised when connection to target fails"""

    def __init__(self, message: str, protocol: str = "", error_code: str = ""):
        """Initialize connection error"""
        super().__init__(message, protocol, error_code)


class AuthenticationError(ICSProtocolError):
    """Raised when authentication fails"""

    def __init__(self, message: str, protocol: str = "", error_code: str = ""):
        """Initialize authentication error"""
        super().__init__(message, protocol, error_code)


class ProtocolError(ICSProtocolError):
    """Raised when protocol-specific errors occur"""

    def __init__(self, message: str, protocol: str = "", error_code: str = ""):
        """Initialize protocol error"""
        super().__init__(message, protocol, error_code)


class DependencyError(ICSProtocolError):
    """Raised when required dependencies are missing"""

    def __init__(self, message: str, protocol: str = "", error_code: str = ""):
        """Initialize dependency error"""
        super().__init__(message, protocol, error_code)


class ConfigurationError(ICSProtocolError):
    """Raised when configuration is invalid"""

    def __init__(self, message: str, protocol: str = "", error_code: str = ""):
        """Initialize configuration error"""
        super().__init__(message, protocol, error_code)


class ICSTimeoutError(ICSProtocolError):
    """Raised when operations timeout"""

    def __init__(self, message: str, protocol: str = "", error_code: str = ""):
        """Initialize timeout error"""
        super().__init__(message, protocol, error_code)


class ICSPermissionError(ICSProtocolError):
    """Raised when insufficient permissions are detected"""

    def __init__(self, message: str, protocol: str = "", error_code: str = ""):
        """Initialize permission error"""
        super().__init__(message, protocol, error_code)


class SecurityError(ICSProtocolError):
    """Raised when security violations are detected"""

    def __init__(self, message: str, protocol: str = "", error_code: str = ""):
        """Initialize security error"""
        super().__init__(message, protocol, error_code)


# Protocol-specific exceptions


class ModbusError(ProtocolError):
    """Modbus protocol specific errors"""

    def __init__(self, message: str, function_code: int = 0, exception_code: int = 0):
        super().__init__(message, protocol="Modbus")
        self.function_code = function_code
        self.exception_code = exception_code


class OPCUAError(ProtocolError):
    """OPC UA protocol specific errors"""

    def __init__(self, message: str, status_code: str = ""):
        super().__init__(message, protocol="OPC UA")
        self.status_code = status_code


class EtherCATError(ProtocolError):
    """EtherCAT protocol specific errors"""

    def __init__(self, message: str, al_status: int = 0):
        super().__init__(message, protocol="EtherCAT")
        self.al_status = al_status


class ADSError(ProtocolError):
    """Beckhoff ADS protocol specific errors"""

    def __init__(self, message: str, ads_error: int = 0):
        super().__init__(message, protocol="ADS")
        self.ads_error = ads_error
