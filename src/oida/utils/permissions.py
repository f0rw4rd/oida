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
