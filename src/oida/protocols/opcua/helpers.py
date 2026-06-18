#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OPC UA Helper Functions and Lazy Import Utilities

This module provides utility functions for OPC UA URL handling,
lazy imports, and helper classes.
"""

import threading
from typing import TYPE_CHECKING

from ...utils.lazy_import import lazy_import

# Type hints only - no runtime import
if TYPE_CHECKING:
    pass

# Lazy import for asyncua - only loads when actually used
_asyncua = lazy_import("asyncua", "OPC UA")

# Supported OPC UA URL scheme
OPCUA_SCHEME = "opc.tcp://"

# Keywords indicating potentially dangerous operations
DANGEROUS_KEYWORDS = ["start", "stop", "reset", "write", "execute", "delete", "format", "emergency"]


class _AsyncuaCache:
    """Thread-safe singleton cache for asyncua module.

    Avoids global keyword usage while providing test compatibility
    via module-level 'asyncua' attribute export.
    """

    _lock = threading.Lock()
    _module = None

    @classmethod
    def get(cls):
        """Get asyncua module, raising DependencyError if not available."""
        if cls._module is not None:
            return cls._module
        with cls._lock:
            if cls._module is None:
                cls._module = _asyncua()
        return cls._module


class _SecurityPoliciesCache:
    """Thread-safe singleton cache for security policies."""

    _lock = threading.Lock()
    _policies = None

    @classmethod
    def get(cls):
        """Get cached security policies."""
        if cls._policies is not None:
            return cls._policies
        with cls._lock:
            if cls._policies is None:
                cls._policies = _get_security_policies()
        return cls._policies


# Module-level export for test compatibility (tests patch oida.protocols.opcua.asyncua)
# This is populated lazily when _get_asyncua() is first called
asyncua = None


def _get_asyncua():
    """Get asyncua module, raising DependencyError if not available.

    Thread-safe: uses singleton cache pattern.
    """
    # Use module-level asyncua for backwards compatibility with tests
    import sys

    result = _AsyncuaCache.get()
    # Update module-level export for test compatibility
    current_module = sys.modules[__name__]
    current_module.asyncua = result
    return result


def _get_security_policies():
    """Get OPC UA security policies lazily.

    Includes backward compatibility for older asyncua versions that may not
    have the newer AES-based security policies (added in asyncua >= 0.9.90).
    """
    _get_asyncua()
    from asyncua.crypto import security_policies

    policies = {
        "none": None,  # No security - use None, not a security policy class
        "basic128rsa15": security_policies.SecurityPolicyBasic128Rsa15,
        "basic256": security_policies.SecurityPolicyBasic256,
        "basic256sha256": security_policies.SecurityPolicyBasic256Sha256,
    }

    # Newer policies added in asyncua >= 0.9.90 - graceful fallback for older versions
    aes128 = getattr(security_policies, "SecurityPolicyAes128Sha256RsaOaep", None)
    if aes128 is not None:
        policies["aes128_sha256_rsaoaep"] = aes128

    aes256 = getattr(security_policies, "SecurityPolicyAes256Sha256RsaPss", None)
    if aes256 is not None:
        policies["aes256_sha256_rsapss"] = aes256

    return policies


def _get_security_policies_cached():
    """Get cached security policies.

    Thread-safe: uses singleton cache pattern.
    """
    return _SecurityPoliciesCache.get()


def _normalize_opcua_url(target: str, default_port: int = 4840) -> str:
    """
    Normalize OPC UA target to a proper URL.

    Accepts:
        - opc.tcp://host:port/path
        - host:port/path
        - host:port
        - host (uses default port)

    Returns:
        Properly formatted OPC UA URL with opc.tcp:// scheme
    """
    target = target.strip()

    # Already has scheme
    if target.lower().startswith(OPCUA_SCHEME):
        return target

    # No scheme - add opc.tcp://
    if ":" in target and not target.startswith("["):
        # Has port: host:port or host:port/path
        return f"{OPCUA_SCHEME}{target}"
    else:
        # Just host, add default port
        return f"{OPCUA_SCHEME}{target}:{default_port}"


def _parse_opcua_url(url: str) -> tuple:
    """
    Parse OPC UA URL into components.

    Returns:
        (host, port, path)
    """
    url = _normalize_opcua_url(url)

    # Remove scheme
    remainder = url[len(OPCUA_SCHEME) :]

    # Split path
    if "/" in remainder:
        host_port, path = remainder.split("/", 1)
        path = "/" + path
    else:
        host_port = remainder
        path = ""

    # Split host:port
    if ":" in host_port:
        host, port_str = host_port.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            port = 4840
    else:
        host = host_port
        port = 4840

    return host, port, path


def _get_client_class():
    """Get OPC UA Client class lazily."""
    _get_asyncua()
    from asyncua.client.client import Client

    return Client


def _get_ua_module():
    """Get asyncua.ua module lazily."""
    asyncua = _get_asyncua()
    return asyncua.ua


def _get_bad_user_access_denied():
    """Get BadUserAccessDenied exception class lazily."""
    _get_asyncua()
    from asyncua.ua.uaerrors import BadUserAccessDenied

    return BadUserAccessDenied


class _LazyUaModule:
    """
    Lazy proxy for the asyncua.ua module.

    Forwards all attribute access to the lazily-loaded ua module.
    This allows code to use `ua.AttributeIds`, `ua.NodeClass` etc.
    without requiring asyncua to be imported at module load time.
    """

    def __getattr__(self, name):
        ua_module = _get_ua_module()
        return getattr(ua_module, name)


# Module-level lazy proxy for ua module - can be used like the original ua import
ua = _LazyUaModule()
