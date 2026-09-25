#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Permission checking utilities for raw socket access.
"""

import os
import sys
import socket
from typing import Tuple, Optional

import logging

logger = logging.getLogger(__name__)


def check_raw_socket_capability() -> Tuple[bool, Optional[str]]:
    """
    Check if the current process has raw socket capabilities.

    Returns a tuple of (has_capability, error_message).
    This checks for:
    1. Root privileges (uid 0)
    2. CAP_NET_RAW capability (via attempting to create a raw socket)

    Returns:
        Tuple[bool, Optional[str]]: (True, None) if capable, (False, error_msg) if not
    """
    # First check if we're root/admin
    if hasattr(os, "geteuid"):
        if os.geteuid() == 0:
            return True, None
    elif sys.platform == "win32":
        try:
            import ctypes

            if ctypes.windll.shell32.IsUserAnAdmin():
                return True, None
        except Exception as e:
            logger.debug(f"Optional import ctypes not available: {e}")

    # Try to create a raw socket to test capabilities
    try:
        # Attempt to create a raw socket
        if hasattr(socket, "AF_PACKET"):
            test_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            test_socket.close()
        else:
            # Windows/macOS have no AF_PACKET, so Layer-2 raw capture via this
            # path is unavailable. (Previously this imported a non-existent
            # platform_compat.check_l2_available, raising ImportError here.)
            return False, "l2_not_available"
        return True, None
    except PermissionError as e:
        logger.debug(f"raw socket creation denied (need root/CAP_NET_RAW): {e}")
        return False, "permission_error"
    except Exception as e:
        # Fallback for other errors (e.g., AF_PACKET not available on non-Linux)
        error_msg = f"Unable to create raw socket: {e}"
        return False, error_msg


def raw_socket_help_lines() -> list:
    """Actionable "how to grant raw-socket access" lines for the current runtime.

    Correct for BOTH a normal Python install and a frozen PyInstaller standalone
    binary. The previous hardcoded ``setcap ... $(which python3)`` is wrong for a
    frozen build (there is no python3 to setcap) and dangerous for a normal one
    (it grants CAP_NET_RAW to the shared interpreter). Here the setcap target is
    always the *actual* executable of this process (``sys.executable``): the oida
    binary when frozen, the interpreter otherwise.
    """
    invocation = os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else "oida"
    lines = [f"Run with sudo:  sudo {invocation} ..."]

    if sys.platform == "win32":
        lines.append("Or run the terminal / oida as Administrator.")
        return lines

    target = os.path.realpath(sys.executable) if sys.executable else "<executable>"
    lines.append(f"Or grant the capability:  sudo setcap cap_net_raw+eip {target}")
    if getattr(sys, "frozen", False):
        # onedir: setcap on the binary works. onefile: the bootloader re-execs an
        # extracted temp copy, so the capability may not carry over - say so.
        lines.append(
            "  (single-file build? setcap may not persist through extraction - "
            "prefer sudo, or use the directory build)"
        )
    return lines
