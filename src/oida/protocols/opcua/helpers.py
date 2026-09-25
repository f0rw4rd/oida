#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OPC UA Helper Functions and Lazy Import Utilities

This module provides utility functions for OPC UA URL handling,
lazy imports, and helper classes.
"""

from oida.utils.lazy_import import lazy_import

# Lazy import for asyncua - only loads when actually used
_asyncua = lazy_import("asyncua", "OPC UA")

# Supported OPC UA URL scheme
OPCUA_SCHEME = "opc.tcp://"

# Keywords indicating potentially dangerous operations
DANGEROUS_KEYWORDS = ["start", "stop", "reset", "write", "execute", "delete", "format", "emergency"]


# Patch target for tests, which patch oida.protocols.opcua.asyncua. Kept as a
# module-level name so the attribute exists for mock.patch; no production code
# reads it (callers go through _get_asyncua()).
asyncua = None


def _get_asyncua():
    """Get asyncua module, raising DependencyError if not available.

    The underlying ``_asyncua`` LazyModule already lock-guards and caches the
    loaded module, so no extra caching layer is needed here.
    """
    return _asyncua()


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
    # Bracketed IPv6 needs special handling: `[::1]:4840` already has a
    # port, `[::1]` does not. The old check `target.startswith("[")`
    # treated EVERY bracketed form as "no port" and appended :4840 even
    # when one was already there, producing `[::1]:4840:4840`.
    if target.startswith("["):
        # Bracketed IPv6 - port iff a ':' appears AFTER the closing ']'
        close = target.find("]")
        has_port = close != -1 and ":" in target[close + 1 :].split("/", 1)[0]
        if has_port:
            return f"{OPCUA_SCHEME}{target}"
        return f"{OPCUA_SCHEME}{target}:{default_port}"
    if ":" in target:
        # Has port: host:port or host:port/path
        return f"{OPCUA_SCHEME}{target}"
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

    # Bracketed IPv6 - split path AFTER the closing ']' so the colons
    # inside the address don't break path or port detection.
    if remainder.startswith("["):
        close = remainder.find("]")
        if close == -1:
            # Malformed - return what we can.
            return remainder, 4840, ""
        ipv6_host = remainder[: close + 1]
        tail = remainder[close + 1 :]
        if "/" in tail:
            port_part, path = tail.split("/", 1)
            path = "/" + path
        else:
            port_part = tail
            path = ""
        port = 4840
        if port_part.startswith(":"):
            try:
                port = int(port_part[1:])
            except ValueError:
                port = 4840
        return ipv6_host, port, path

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
        return getattr(_get_asyncua().ua, name)


# Module-level lazy proxy for ua module - can be used like the original ua import
ua = _LazyUaModule()
