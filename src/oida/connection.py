"""
Base connection class for all ICS protocols (NXC-style architecture)

This module provides the abstract base class that all protocol scanners inherit from.
It follows the NXC (NetExec) pattern where protocol classes are callable and trigger
the entire scanning workflow upon instantiation.
"""

from abc import ABC, abstractmethod
import copy
import socket
from typing import Any, Dict, Optional


class connection(ABC):
    """
    Base connection class for all protocols (NXC-style)

    All protocol scanners must inherit from this class and implement the required
    abstract methods. Upon instantiation, the protocol flow is automatically triggered.

    Architecture:
        1. Child class calls super().__init__(args, db, host)
        2. Base class resolves hostname and stores connection parameters
        3. Base class calls proto_flow() to start scanning workflow
        4. Child implements proto_flow() with protocol-specific logic

    Example:
        class modbus(connection):
            def __init__(self, args, db, host):
                self.protocol_name = "modbus"
                self.default_port = 502
                super().__init__(args, db, host)

            def proto_flow(self):
                self.proto_logger()
                self.create_conn_obj()
                self.enum_host_info()
                self.print_host_info()
                self.login()
                self.scan_registers()
    """

    def __init__(self, args: Any, db: Optional[Any], host: str):
        """
        Initialize connection and trigger protocol flow

        Args:
            args: Parsed command-line arguments (argparse.Namespace)
            db: Database instance for storing results (optional)
            host: Target host (IP address or hostname)
        """
        from oida.utils.ics_logger import get_logger, update_logger_host, print_startup_banner

        print_startup_banner()

        self.args = args
        self.db = db
        self.host = host
        self.hostname = host
        self.conn = None

        # Get protocol and port for logger
        protocol_name = getattr(self, "protocol_name", "unknown")
        port = getattr(self.args, "port", None) or getattr(self, "default_port", 0) or 0

        # Get logger from factory - available immediately for _resolve_host()
        self.logger = get_logger(
            protocol=protocol_name,
            host=host,
            port=port,
            verbose=self._detect_verbose(),
        )

        # Resolve hostname to IP
        self.ip = self._resolve_host(host)

        # If hostname resolved to different IP, update logger cache key
        if self.ip != host:
            update_logger_host(protocol_name, host, port, self.ip, hostname=host)
            # Update logger's host to use resolved IP for display
            self.logger.extra["host"] = self.ip
            if host != self.ip:
                self.logger.extra["hostname"] = host[:16]

        # Store connection results (success=None means "not yet determined")
        self.results = {
            "host": host,
            "ip": self.ip,
            "protocol": protocol_name,
            "port": getattr(self.args, "port", None) or getattr(self, "default_port", None),
            "success": None,
            "data": {},
        }

        # Run proto_logger() to apply the resolved IP / port to the logger
        # before proto_flow starts. Subclasses do not need to call this
        # themselves; the call is idempotent so legacy calls in subclass
        # proto_flow() implementations are harmless.
        self.proto_logger()

        # Trigger protocol execution flow
        # Error handling and cleanup are centralized here so proto_flow()
        # implementations only need the happy-path logic.
        try:
            self.proto_flow()
            # Only set success if proto_flow didn't explicitly set it
            if self.results.get("success") is None:
                self.results["success"] = True
        except KeyboardInterrupt:
            if self.logger:
                self.logger.display("Scan interrupted by user")
            self.results["data"]["interrupted"] = True
            # Interrupted scans are not failures
            if self.results.get("success") is None:
                self.results["success"] = True
        except Exception as e:
            self.results["success"] = False
            self.results["error"] = str(e)
            if self.logger:
                self.logger.fail(
                    f"{getattr(self, 'protocol_name', 'unknown').upper()} "
                    f"scan failed for {self.host}: {e}"
                )
        finally:
            # Always cleanup connection resources
            try:
                self.cleanup()
            except Exception as e:
                self.logger.debug(f"cleanup failed: {e}")
            # Attach security findings to results for export
            if self.logger:
                findings = self.logger.to_list()
                if findings:
                    self.results["data"].setdefault("security_findings", []).extend(findings)

    def _detect_verbose(self) -> bool:
        """Determine verbose mode from args (debug flag or verbose >= 1)."""
        if not self.args:
            return False
        try:
            return bool(getattr(self.args, "debug", False)) or (
                int(getattr(self.args, "verbose", 0) or 0) >= 1
            )
        except (TypeError, ValueError):
            # Logger not yet initialized when called from __init__
            return False

    def _resolve_host(self, host: str) -> str:
        """
        Resolve hostname to IP address (IPv4 or IPv6).

        Args:
            host: Hostname or IP address

        Returns:
            str: IP address (returns original if resolution fails)
        """
        try:
            # gethostbyname is IPv4-only. Use getaddrinfo so IPv6
            # hostnames (and AAAA-only records) resolve correctly.
            # Prefer the first result, whatever family it is — the
            # caller's downstream socket code is now also IPv6-aware
            # (see test_connection above).
            results = socket.getaddrinfo(host, None)
            if results:
                return results[0][4][0]
            return host
        except socket.gaierror as e:
            # If resolution fails, return original (might be IP already)
            self.logger.debug(f"resolve host failed: {e}")
            return host

    def get_host_fqdn(self) -> str:
        """
        Get fully qualified domain name for target

        Returns:
            str: FQDN or IP if FQDN unavailable
        """
        try:
            return socket.getfqdn(self.ip)
        except Exception as e:
            self.logger.debug(f"get host fqdn failed: {e}")
            return self.ip

    @abstractmethod
    def proto_flow(self):
        """
        Main protocol execution flow (happy-path only).

        Error handling, cleanup, and success/failure bookkeeping are handled
        by ``connection.__init__``.  Implementations should simply raise on
        fatal errors — the base class will log, set results, and call
        ``cleanup()``.

        Typical implementation:
        1. create_conn_obj() - Establish connection
        2. enum_host_info() - Gather device information
        3. print_host_info() - Display discovered info
        4. Protocol-specific scanning actions

        Logger setup (``proto_logger()``) is called automatically by
        ``connection.__init__`` before ``proto_flow()`` runs — child classes
        do not need to call it.

        Must be implemented by child class.
        """

    def proto_logger(self):
        """
        Apply the resolved IP / hostname / port to the logger.

        Called automatically by ``connection.__init__`` after host resolution
        and before ``proto_flow()``. Idempotent: calling it again from a
        subclass ``proto_flow()`` is harmless but unnecessary.

        Can be overridden by a child class to add protocol-specific logger
        context (e.g. extra fields).
        """
        if self.logger is None:
            # Shouldn't happen, but handle gracefully
            from oida.utils.ics_logger import get_logger

            protocol_name = getattr(self, "protocol_name", "unknown")
            port = self.results.get("port") or getattr(self, "default_port", 0) or 0
            self.logger = get_logger(
                protocol=protocol_name,
                host=self.ip,
                port=port,
                verbose=self._detect_verbose(),
            )
            return

        # Update logger to use resolved IP for display
        self.logger.extra["host"] = self.ip

        # Set hostname if original host was different from IP
        if hasattr(self, "host") and self.host != self.ip:
            self.logger.extra["hostname"] = self.host[:16]

        # Update port if it changed
        port = self.results.get("port") or getattr(self, "default_port", 0) or 0
        if port:
            self.logger.extra["port"] = port

    @abstractmethod
    def create_conn_obj(self):
        """
        Create protocol-specific connection object

        Should establish the actual protocol connection and store
        it in self.conn. Should handle connection errors appropriately.

        Must be implemented by child class.
        """

    @abstractmethod
    def enum_host_info(self):
        """
        Enumerate host/device information

        Should gather device identification, version info, capabilities,
        etc. Store results in self.results['data'].

        Must be implemented by child class.
        """

    @abstractmethod
    def print_host_info(self):
        """
        Print discovered host information

        Should display the information gathered by enum_host_info()
        in a user-friendly format. Respect verbosity flags.

        Must be implemented by child class.
        """

    def login(self):
        """
        Authenticate to target (if applicable)

        Default implementation is a no-op. Override if protocol
        requires authentication.

        Returns:
            bool: True if authentication successful, False otherwise
        """
        return True

    def cleanup(self):
        """
        Cleanup connection and resources

        Should close self.conn and cleanup any other resources.
        Override for protocol-specific cleanup logic.
        """
        if self.conn:
            try:
                if hasattr(self.conn, "close"):
                    self.conn.close()
                elif hasattr(self.conn, "disconnect"):
                    self.conn.disconnect()
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Error during cleanup: {e}")

    def get_results(self) -> Dict[str, Any]:
        """
        Get scan results

        Returns:
            dict: Results dictionary with host info and scan data
        """
        return self.results

    def _convert_args_to_dict(self) -> Dict[str, Any]:
        """
        Convert argparse.Namespace to dict format expected by scanners.

        Auto-converts underscore keys to hyphenated (unit_id -> unit-id).
        """
        result = {"rhost": self.ip}
        for key, value in vars(self.args).items():
            if value is None:
                continue
            # Map special keys
            if key == "port":
                result["rport"] = value
            else:
                # Store both forms: underscore (argparse native) and
                # hyphenated (legacy scanner convention)
                result[key] = value
                hyphenated = key.replace("_", "-")
                if hyphenated != key:
                    result[hyphenated] = value
        return result


class NetworkConnection(connection):
    """
    Base class for network-based protocols (TCP/UDP)

    Extends connection with network-specific utilities like
    port handling and timeout management.
    """

    def __init__(self, args: Any, db: Optional[Any], host: str):
        """Initialize network connection.

        The default-port resolution is done on a *copy* of args so the caller's
        namespace is not mutated. Cross-protocol invocations from the dispatcher
        share a single argparse Namespace; writing to ``args.port`` here would
        leak the previous protocol's port to the next.
        """
        # Always copy when we touch args. The old code only copied when
        # port was unset, so a user-supplied -p value persisted on the
        # shared Namespace and bled into every subsequent protocol
        # invocation in the same process (CLI uses a process-wide
        # Namespace). Copying unconditionally is cheap (Namespace is
        # shallow) and prevents that leak entirely.
        args = copy.copy(args)
        if hasattr(self, "default_port") and not getattr(args, "port", None):
            args.port = self.default_port

        super().__init__(args, db, host)

    def test_connection(self) -> bool:
        """
        Test basic TCP connectivity to target

        Returns:
            bool: True if port is reachable
        """
        sock = None
        try:
            # Use getaddrinfo so we honor both IPv4 and IPv6 — the old
            # AF_INET-only socket() refused every IPv6 target despite
            # the framework documenting IPv6 support. Try each result
            # in order; first reachable wins.
            timeout = getattr(self.args, "timeout", 2)
            try:
                addrinfo = socket.getaddrinfo(self.ip, self.args.port, type=socket.SOCK_STREAM)
            except socket.gaierror as e:
                self.logger.debug(f"test connection: getaddrinfo failed: {e}")
                return False
            for family, socktype, proto, _, sockaddr in addrinfo:
                try:
                    sock = socket.socket(family, socktype, proto)
                    sock.settimeout(timeout)
                    if sock.connect_ex(sockaddr) == 0:
                        return True
                except OSError:
                    continue
                finally:
                    if sock is not None:
                        try:
                            sock.close()
                        except OSError:
                            pass
                        sock = None
            return False
        except Exception as e:
            self.logger.debug(f"test connection failed: {e}")
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    self.logger.debug(f"sock.close(): {e}")


class SerialConnection(connection):
    """
    Base class for serial/layer-2 protocols

    Extends connection with serial-specific utilities like
    interface handling and packet capture.
    """

    def __init__(self, args: Any, db: Optional[Any], host: str):
        """Initialize serial connection"""
        # For serial protocols, "host" might be an interface name
        self.interface = getattr(args, "interface", None) or host
        super().__init__(args, db, host)

    def get_interface_info(self) -> Dict[str, Any]:
        """
        Get information about the network interface

        Returns:
            dict: Interface info (MAC, MTU, etc.)
        """
        import netifaces

        try:
            addrs = netifaces.ifaddresses(self.interface)
            return {
                "interface": self.interface,
                "mac": addrs.get(netifaces.AF_LINK, [{}])[0].get("addr"),
                "ipv4": addrs.get(netifaces.AF_INET, [{}])[0].get("addr"),
            }
        except Exception as e:
            self.logger.debug(f"get interface info failed: {e}")
            return {"interface": self.interface}
