"""
Cross-platform compatibility utilities for OIDA.

Provides platform-aware implementations for:
- OS detection
- Raw socket capability checking
- Function timeout handling
- Temporary directory paths
- Network interface binding
"""

import os
import re
import subprocess
import sys
import socket
import tempfile
import threading
from pathlib import Path
from typing import Tuple, Optional, Callable, Any, Dict, List

from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)

# Platform detection
IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")

# PyInstaller frozen detection
IS_FROZEN = getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")


def _pkg_root() -> Path:
    """Return the oida package root directory.

    When running from a PyInstaller bundle, ``sys._MEIPASS`` points to the
    temporary extraction directory.  Data files are placed under
    ``<_MEIPASS>/oida/`` to mirror the source layout.

    When running from source, the package root is simply the ``oida/``
    directory that contains ``__init__.py``.
    """
    if IS_FROZEN:
        return Path(sys._MEIPASS) / "oida"
    return Path(__file__).parent.parent


IS_MACOS = sys.platform == "darwin"
IS_POSIX = os.name == "posix"


# =============================================================================
# Function Timeout
# =============================================================================


def timeout_wrapper(func: Callable, timeout: int, *args, **kwargs) -> Any:
    """
    Execute a function with a timeout.

    Cross-platform implementation using threading instead of Unix signals.

    Args:
        func: Function to execute
        timeout: Timeout in seconds
        *args: Positional arguments for func
        **kwargs: Keyword arguments for func

    Returns:
        Function result

    Raises:
        TimeoutError: If function doesn't complete within timeout
    """
    result = [None]
    exception = [None]
    completed = threading.Event()

    def target():
        try:
            result[0] = func(*args, **kwargs)
        except Exception as e:
            exception[0] = e
        finally:
            completed.set()

    thread = threading.Thread(target=target, daemon=True)
    thread.start()

    if not completed.wait(timeout):
        raise TimeoutError(f"Function timed out after {timeout} seconds")

    if exception[0] is not None:
        raise exception[0]

    return result[0]


# =============================================================================
# Temporary Directories
# =============================================================================


def get_temp_dir(subdir: str = None) -> str:
    """
    Get platform-appropriate temporary directory.

    Args:
        subdir: Optional subdirectory name to create

    Returns:
        Path to temporary directory
    """
    base = tempfile.gettempdir()
    if subdir:
        path = os.path.join(base, subdir)
        os.makedirs(path, exist_ok=True)
        return path
    return base


def get_cert_save_dir() -> str:
    """Get directory for saving certificates."""
    return get_temp_dir("oida_certs")


# =============================================================================
# Network Interface Binding
# =============================================================================

# Linux-specific socket option
SO_BINDTODEVICE = 25 if IS_LINUX else None


def bind_socket_to_interface(sock: socket.socket, interface: str) -> bool:
    """
    Bind a socket to a specific network interface.

    On Linux, uses SO_BINDTODEVICE. On other platforms, attempts IP-based binding.

    Args:
        sock: Socket to bind
        interface: Interface name (e.g., "eth0", "Ethernet")

    Returns:
        True if successfully bound to interface, False otherwise
    """
    if IS_LINUX and SO_BINDTODEVICE is not None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, interface.encode())
            logger.debug(f"Bound socket to {interface} via SO_BINDTODEVICE")
            return True
        except (OSError, AttributeError) as e:
            logger.debug(f"SO_BINDTODEVICE failed for {interface}: {e}")

    # Fallback: try to bind to interface IP (works on all platforms)
    try:
        from oida.protocols.discovery.core import get_interface_ip

        ip = get_interface_ip(interface)
        if ip:
            # Note: This only binds outgoing packets, not a full interface bind
            sock.bind((ip, 0))
            logger.debug(f"Bound socket to {interface} via IP binding ({ip})")
            return True
    except Exception as e:
        logger.debug(f"IP-based binding failed for {interface}: {e}")

    return False


def get_config_search_paths(subdir: str) -> List[Path]:
    """Get ordered list of paths to search for config/data files.

    Args:
        subdir: Subdirectory path relative to oida root (e.g. "mqtt/wordlists")

    Returns:
        List of paths to check, in priority order.
    """
    paths = [
        # Package data location (always first)
        _pkg_root() / "data" / subdir,
        # User config location
        Path.home() / ".oida" / subdir,
    ]

    # System config location (platform-aware)
    if IS_WINDOWS:
        program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        paths.append(Path(program_data) / "oida" / subdir)
    else:
        paths.append(Path("/etc/oida") / subdir)

    return paths


# =============================================================================
# Cross-Platform ARP Cache
# =============================================================================


def get_arp_cache() -> List[Tuple[str, str, str]]:
    """Read the system ARP cache in a cross-platform way.

    Returns:
        List of (ip_address, mac_address, interface) tuples.
        MAC addresses are normalized to lowercase colon-separated format.
    """
    if IS_LINUX:
        return _get_arp_cache_linux()
    elif IS_WINDOWS:
        return _get_arp_cache_windows()
    elif IS_MACOS:
        return _get_arp_cache_macos()
    return []


def _get_arp_cache_linux() -> List[Tuple[str, str, str]]:
    """Read ARP cache from /proc/net/arp on Linux."""
    entries = []
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f:
                if line.startswith("IP"):
                    continue  # Skip header
                parts = line.split()
                if len(parts) >= 6:
                    ip = parts[0]
                    mac = parts[3].lower()
                    iface = parts[5]
                    if mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                        entries.append((ip, mac, iface))
    except Exception as e:
        logger.debug(f"Could not read /proc/net/arp: {e}")
    return entries


def _get_arp_cache_windows() -> List[Tuple[str, str, str]]:
    """Parse 'arp -a' output on Windows."""
    entries = []
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return entries

        current_iface = ""
        for line in result.stdout.splitlines():
            line = line.strip()
            # Interface header: "Interface: 192.168.1.5 --- 0x4"
            if line.startswith("Interface:"):
                current_iface = line.split()[1] if len(line.split()) > 1 else ""
                continue
            # Entry: "  192.168.1.1     aa-bb-cc-dd-ee-ff     dynamic"
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                mac_raw = parts[1]
                # Validate IP format (skip header lines)
                try:
                    socket.inet_aton(ip)
                except OSError as e:
                    logger.debug(f"socket.inet_aton(ip): {e}")
                    continue
                # Normalize Windows MAC format (aa-bb-cc-dd-ee-ff -> aa:bb:cc:dd:ee:ff)
                mac = mac_raw.replace("-", ":").lower()
                if mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                    entries.append((ip, mac, current_iface))
    except Exception as e:
        logger.debug(f"Could not parse arp -a output: {e}")
    return entries


def _get_arp_cache_macos() -> List[Tuple[str, str, str]]:
    """Parse 'arp -an' output on macOS."""
    entries = []
    try:
        result = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return entries

        # Format: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
        for line in result.stdout.splitlines():
            match = re.match(r"\?\s+\(([^)]+)\)\s+at\s+([0-9a-fA-F:]+)\s+on\s+(\S+)", line)
            if match:
                ip, mac, iface = match.group(1), match.group(2).lower(), match.group(3)
                if mac not in (
                    "00:00:00:00:00:00",
                    "ff:ff:ff:ff:ff:ff",
                    "(incomplete)",
                ):
                    entries.append((ip, mac, iface))
    except Exception as e:
        logger.debug(f"Could not parse arp -an output: {e}")
    return entries


def get_arp_cache_as_ip_to_mac() -> Dict[str, str]:
    """Convenience: get ARP cache as {ip: mac} dict."""
    return {ip: mac for ip, mac, _iface in get_arp_cache()}


def get_arp_cache_as_mac_to_ips() -> Dict[str, List[str]]:
    """Convenience: get ARP cache as {mac: [ip, ...]} dict."""
    result: Dict[str, List[str]] = {}
    for ip, mac, _iface in get_arp_cache():
        if mac not in result:
            result[mac] = []
        if ip not in result[mac]:
            result[mac].append(ip)
    return result


# =============================================================================
# Cross-Platform Interface State
# =============================================================================


def get_interface_state(interface: str) -> Optional[str]:
    """Check if a network interface is up, cross-platform.

    Returns:
        "up", "down", or None if state cannot be determined.
    """
    if IS_LINUX:
        return _get_interface_state_linux(interface)
    else:
        return _get_interface_state_portable(interface)


def _get_interface_state_linux(interface: str) -> Optional[str]:
    """Check interface state via /sys/class/net on Linux."""
    operstate_path = f"/sys/class/net/{interface}/operstate"
    try:
        if os.path.exists(operstate_path):
            with open(operstate_path) as f:
                state = f.read().strip()
                # "unknown" is common for virtual interfaces and means "up"
                return "up" if state in ("up", "unknown") else "down"
    except (OSError, IOError) as e:
        logger.debug(f"if os.path.exists(operstate_path):: {e}")
    # Fall through to portable check
    return _get_interface_state_portable(interface)


def _get_interface_state_portable(interface: str) -> Optional[str]:
    """Check interface state using psutil or netifaces (all platforms)."""
    try:
        import psutil

        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        if interface in stats:
            return "up" if stats[interface].isup else "down"
        if interface in addrs:
            return "up"  # Has addresses, assume up
    except ImportError as e:
        logger.debug(f"Optional import psutil not available: {e}")

    try:
        import netifaces

        if interface in netifaces.interfaces():
            return "up"  # netifaces can't check state, but interface exists
    except ImportError as e:
        logger.debug(f"Optional import netifaces not available: {e}")

    return None


def check_interface_exists(interface: str) -> bool:
    """Check if a network interface exists on this system, cross-platform.

    Returns:
        True if interface exists, False if definitely not found.
        Returns True on errors (fail-open) to avoid blocking legitimate use.
    """
    if IS_LINUX:
        if os.path.exists(f"/sys/class/net/{interface}"):
            return True

    # Portable check via psutil
    try:
        import psutil

        return interface in psutil.net_if_addrs()
    except ImportError as e:
        logger.debug(f"Optional import psutil not available: {e}")

    # Portable check via netifaces
    try:
        import netifaces

        return interface in netifaces.interfaces()
    except ImportError as e:
        logger.debug(f"Optional import netifaces not available: {e}")

    # Can't verify - fail open
    logger.debug(f"Cannot verify interface {interface} (no psutil/netifaces)")
    return True


# =============================================================================
# Cross-Platform Ping
# =============================================================================


def ping_host(host: str, count: int = 1, timeout: int = 1, ipv6: bool = False) -> bool:
    """Ping a host using platform-appropriate flags.

    Args:
        host: IP address or hostname to ping
        count: Number of ping packets
        timeout: Timeout in seconds
        ipv6: Use IPv6 ping

    Returns:
        True if host responded, False otherwise.
    """
    cmd = _build_ping_command(host, count, timeout, ipv6)
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.debug(f"Failed to get result: {e}")
        return False


def build_ping_command(
    host: str, count: int = 1, timeout: int = 1, ipv6: bool = False
) -> List[str]:
    """Build a platform-appropriate ping command.

    Public interface for callers that need the command list
    (e.g., to parse output themselves).
    """
    return _build_ping_command(host, count, timeout, ipv6)


def _build_ping_command(
    host: str, count: int = 1, timeout: int = 1, ipv6: bool = False
) -> List[str]:
    """Build platform-appropriate ping command list."""
    if IS_WINDOWS:
        # Windows: ping -n <count> -w <timeout_ms> host
        ping_cmd = "ping"
        if ipv6:
            ping_cmd = "ping"  # Windows uses -6 flag
        cmd = [ping_cmd, "-n", str(count), "-w", str(timeout * 1000), host]
        if ipv6:
            cmd.insert(1, "-6")
    else:
        # Unix/macOS: ping -c <count> -W <timeout> host
        if ipv6:
            ping_cmd = "ping6" if IS_MACOS else "ping"
            cmd = [ping_cmd, "-c", str(count), "-W", str(timeout), host]
            if not IS_MACOS:
                cmd.insert(1, "-6")
        else:
            cmd = ["ping", "-c", str(count), "-W", str(timeout), host]
    return cmd


# =============================================================================
# Cross-Platform IPv6 Neighbor Discovery
# =============================================================================


def get_ipv6_neighbors(interface: str) -> List[Tuple[str, str]]:
    """Read IPv6 NDP neighbor cache, cross-platform.

    Args:
        interface: Network interface name

    Returns:
        List of (ipv6_address, mac_address) tuples.
    """
    if IS_LINUX:
        return _get_ipv6_neighbors_linux(interface)
    elif IS_WINDOWS:
        return _get_ipv6_neighbors_windows(interface)
    elif IS_MACOS:
        return _get_ipv6_neighbors_macos(interface)
    return []


def _get_ipv6_neighbors_linux(interface: str) -> List[Tuple[str, str]]:
    """Parse 'ip -6 neigh show dev <iface>' on Linux."""
    entries = []
    try:
        result = subprocess.run(
            ["ip", "-6", "neigh", "show", "dev", interface],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return entries

        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 4:
                ipv6_addr = parts[0]
                mac = ""
                for i, part in enumerate(parts):
                    if part == "lladdr" and i + 1 < len(parts):
                        mac = parts[i + 1].lower()
                if ipv6_addr and not ipv6_addr.startswith("ff"):
                    entries.append((ipv6_addr, mac))
    except Exception as e:
        logger.debug(f"Linux IPv6 neighbor query error: {e}")
    return entries


def _get_ipv6_neighbors_windows(interface: str) -> List[Tuple[str, str]]:
    """Parse 'netsh interface ipv6 show neighbors' on Windows."""
    entries = []
    try:
        result = subprocess.run(
            [
                "netsh",
                "interface",
                "ipv6",
                "show",
                "neighbors",
                f"interface={interface}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return entries

        # Format: "IPv6 Address                    Physical Address   Type"
        # Skip header lines, parse entries
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                ipv6_addr = parts[0]
                # Validate it looks like IPv6
                if ":" in ipv6_addr and not ipv6_addr.startswith("---"):
                    mac_raw = parts[1] if len(parts) > 1 else ""
                    mac = mac_raw.replace("-", ":").lower()
                    if not ipv6_addr.startswith("ff"):
                        entries.append((ipv6_addr, mac))
    except Exception as e:
        logger.debug(f"Windows IPv6 neighbor query error: {e}")
    return entries


def _get_ipv6_neighbors_macos(interface: str) -> List[Tuple[str, str]]:
    """Parse 'ndp -an' output on macOS."""
    entries = []
    try:
        result = subprocess.run(
            ["ndp", "-an"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return entries

        # Format: "Neighbor                    Linklayer Address  Netif ..."
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                ipv6_addr = parts[0]
                mac = parts[1].lower()
                iface = parts[2]
                if ":" in ipv6_addr and iface == interface and not ipv6_addr.startswith("ff"):
                    entries.append((ipv6_addr, mac))
    except Exception as e:
        logger.debug(f"macOS NDP query error: {e}")
    return entries
