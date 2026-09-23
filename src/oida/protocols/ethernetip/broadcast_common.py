"""
Shared UDP broadcast-response collection for EtherNet/IP ListIdentity discovery.

Used by both the standalone `broadcast_discovery()` function (for callers that
don't want to instantiate a full scanner) and `DiscoveryMixin._broadcast_discovery`
(the NXC-style scan path), which differ only in socket setup/logging around this
shared receive loop.
"""

import socket
import time
from typing import Any, Callable, Dict, List, Optional

from oida.protocols.ethernetip.parsers import parse_list_identity


def collect_list_identity_responses(
    sock: socket.socket,
    timeout: float,
    on_device: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None,
) -> List[Dict[str, Any]]:
    """
    Poll a bound, broadcast-enabled UDP socket for ListIdentity responses.

    Callers own socket creation/binding and sending the initial broadcast
    packet; this only handles the receive/parse/dedupe loop.

    Args:
        sock: UDP socket already bound and configured with a short recv timeout
        timeout: Total time (seconds) to keep polling for responses
        on_device: Optional callback invoked as on_device(ip_addr, device) for
            each newly discovered device
        on_error: Optional callback invoked with the exception for any
            non-timeout error while receiving/parsing a response

    Returns:
        List of parsed device identity dicts (with "ip_address" set)
    """
    devices: List[Dict[str, Any]] = []
    seen_ips = set()
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            data, addr = sock.recvfrom(4096)
            ip_addr = addr[0]

            if ip_addr in seen_ips:
                continue
            seen_ips.add(ip_addr)

            device = parse_list_identity(data)
            if device:
                device["ip_address"] = ip_addr
                devices.append(device)
                if on_device:
                    on_device(ip_addr, device)

        except TimeoutError:
            # Normal: poll window elapsed with no more responses.
            continue
        except Exception as e:
            if on_error:
                on_error(e)

    return devices
