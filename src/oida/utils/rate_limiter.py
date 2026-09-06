"""
Thread-safe rate limiter for active network scanning.

Provides global rate limiting for packet sending across all active scanners
to prevent network saturation and ensure OT safety.
"""

import socket
import threading
import time
from typing import Optional, Tuple

__all__ = [
    "RateLimiter",
    "set_rate_limit",
    "rate_limit",
    "get_rate_limiter",
    "send_packet",
    "sendto",
    "scapy_sendp",
    "scapy_srp",
]


class RateLimiter:
    """Thread-safe rate limiter for packet sending.

    Ensures that packets are sent no faster than the configured rate.
    All active scanners can share a single instance for global rate limiting.

    Example:
        limiter = RateLimiter(packets_per_second=10.0)

        # In scanner code:
        for target in targets:
            limiter.wait()  # Blocks until next send is allowed
            socket.sendto(packet, target)
    """

    def __init__(self, packets_per_second: float = 10.0):
        """Initialize rate limiter.

        Args:
            packets_per_second: Maximum packets per second (0 = unlimited)
        """
        self.packets_per_second = packets_per_second
        self.interval = 1.0 / packets_per_second if packets_per_second > 0 else 0
        self.last_send = 0.0
        self._lock = threading.Lock()
        self._packet_count = 0

    def wait(self) -> None:
        """Block until the next packet can be sent.

        Thread-safe - multiple scanners can call this concurrently.
        """
        if self.interval <= 0:
            return

        with self._lock:
            now = time.time()
            elapsed = now - self.last_send
            if elapsed < self.interval:
                sleep_time = self.interval - elapsed
                time.sleep(sleep_time)
            self.last_send = time.time()
            self._packet_count += 1

    def reset(self) -> None:
        """Reset the rate limiter state."""
        with self._lock:
            self.last_send = 0.0
            self._packet_count = 0

    @property
    def packet_count(self) -> int:
        """Return the number of packets sent through this limiter."""
        return self._packet_count

    def __repr__(self) -> str:
        return f"RateLimiter(pps={self.packets_per_second}, sent={self._packet_count})"


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None
_rate_limiter_lock = threading.Lock()


def set_rate_limit(packets_per_second: float) -> Optional[RateLimiter]:
    """Set the global rate limit for active scanning.

    Args:
        packets_per_second: Maximum packets per second (0 or negative = unlimited)

    Returns:
        The RateLimiter instance if rate limiting is enabled, None otherwise.
    """
    global _rate_limiter
    with _rate_limiter_lock:
        if packets_per_second > 0:
            _rate_limiter = RateLimiter(packets_per_second)
        else:
            _rate_limiter = None
        return _rate_limiter


def get_rate_limiter() -> Optional[RateLimiter]:
    """Get the current global rate limiter.

    Returns:
        The RateLimiter instance if rate limiting is enabled, None otherwise.
    """
    return _rate_limiter


def rate_limit() -> None:
    """Apply rate limiting if enabled.

    Call this before sending each packet in active scanners.
    If no rate limiter is configured, returns immediately.

    Example:
        from oida.utils.rate_limiter import rate_limit

        # In scanner code:
        for target in targets:
            rate_limit()  # Blocks if rate limit would be exceeded
            socket.sendto(packet, target)
    """
    if _rate_limiter:
        _rate_limiter.wait()


def sendto(
    sock: socket.socket,
    data: bytes,
    address: Tuple[str, int],
) -> int:
    """Rate-limited socket.sendto() wrapper.

    Drop-in replacement for sock.sendto() that applies global rate limiting.

    Args:
        sock: Socket to send on
        data: Data to send
        address: Destination (host, port) tuple

    Returns:
        Number of bytes sent

    Example:
        from oida.utils.rate_limiter import sendto

        # Instead of: sock.sendto(packet, (host, port))
        sendto(sock, packet, (host, port))
    """
    rate_limit()
    return sock.sendto(data, address)


def send_packet(
    sock: socket.socket,
    data: bytes,
    address: Optional[Tuple[str, int]] = None,
) -> int:
    """Rate-limited packet send with optional address.

    Wrapper that handles both connected and unconnected sockets.

    Args:
        sock: Socket to send on
        data: Data to send
        address: Optional destination for unconnected sockets

    Returns:
        Number of bytes sent
    """
    rate_limit()
    if address:
        return sock.sendto(data, address)
    else:
        return sock.send(data)


def scapy_sendp(pkt, iface: Optional[str] = None, verbose: int = 0, **kwargs):
    """Rate-limited Scapy sendp() wrapper.

    Drop-in replacement for scapy.sendp() that applies global rate limiting.

    Args:
        pkt: Scapy packet to send
        iface: Interface to send on
        verbose: Verbosity level (default 0)
        **kwargs: Additional arguments passed to sendp()

    Returns:
        Result from sendp()
    """
    from scapy.all import sendp

    rate_limit()
    return sendp(pkt, iface=iface, verbose=verbose, **kwargs)


def scapy_srp(pkt, iface: Optional[str] = None, timeout: float = 2, verbose: int = 0, **kwargs):
    """Rate-limited Scapy srp() wrapper.

    Drop-in replacement for scapy.srp() that applies global rate limiting.
    Note: srp sends all packets at once by default. For per-packet rate limiting,
    use the `inter` parameter to set delay between packets.

    Args:
        pkt: Scapy packet(s) to send
        iface: Interface to send on
        timeout: Receive timeout in seconds
        verbose: Verbosity level (default 0)
        **kwargs: Additional arguments passed to srp()

    Returns:
        Tuple of (answered, unanswered) packets
    """
    from scapy.all import srp

    # If rate limiting is enabled, use inter parameter for per-packet delay
    if _rate_limiter and _rate_limiter.interval > 0:
        # Override inter if not already set
        if "inter" not in kwargs:
            kwargs["inter"] = _rate_limiter.interval

    rate_limit()  # Initial rate limit before batch
    return srp(pkt, iface=iface, timeout=timeout, verbose=verbose, **kwargs)
