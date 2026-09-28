"""
Base connection class for all ICS protocols (NXC-style architecture)

This module provides the abstract base class that all protocol scanners inherit from.
It follows the NXC (NetExec) pattern where protocol classes are callable and trigger
the entire scanning workflow upon instantiation.
"""

from abc import ABC, abstractmethod
import copy
import os
import socket
from typing import Any, Dict, Optional, cast

from oida.utils import crash_report
from oida.utils.args_dict import ArgsDict
from oida.utils.confirm_gate import ConfirmGateMixin
from oida.utils.result_types import ScanResult


class connection(ConfirmGateMixin, ABC):
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
                self.scan_registers()
    """

    def __init__(self, args: Any, db: Optional[Any], host: str, *, autostart: bool = True):
        """
        Initialize connection and (by default) trigger the protocol flow.

        Args:
            args: Parsed command-line arguments (argparse.Namespace)
            db: Database instance for storing results (optional)
            host: Target host (IP address or hostname)
            autostart: When True (default, preserving CLI behavior), the scan
                runs during construction via ``run()``. Pass ``autostart=False``
                to build the object without scanning - the caller then invokes
                ``run()`` explicitly. This splits construction from execution so
                the object is constructible (and testable) without side effects.
        """
        from oida.utils.ics_logger import get_logger, update_logger_host, print_startup_banner

        print_startup_banner()

        self.args = args
        self.db = db
        self.host = host
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
            self.logger.extra["hostname"] = host[:16]

        # Store connection results (success=None means "not yet determined").
        # Kept as a mutable Dict[str, Any] because the value union is
        # heterogeneous (str, None, nested dict) and subclasses freely
        # index/mutate results["data"][...]; an inferred narrow value type would
        # make every such access an error. The documented *envelope* shape is
        # oida.utils.result_types.ScanResult, applied at the get_results()
        # boundary via cast - this dict is the flexible backing store.
        self.results: Dict[str, Any] = {
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

        # Trigger protocol execution flow unless the caller opted out.
        # autostart=True (default) preserves the CLI/library contract where
        # constructing the object runs the scan; autostart=False lets callers
        # (notably tests) build the object and invoke run() themselves.
        if autostart:
            self.run()

    def run(self) -> "ScanResult":
        """
        Execute the protocol scan flow and return the result envelope.

        Called automatically from ``__init__`` unless ``autostart=False``.
        Error handling, cleanup, and success/failure bookkeeping are centralized
        here so ``proto_flow()`` implementations only need the happy-path logic.
        """
        try:
            self.proto_flow()
            # Only set success if proto_flow didn't explicitly set it
            if self.results.get("success") is None:
                self.results["success"] = True
        except KeyboardInterrupt:
            self.logger.display("Scan interrupted by user")
            self.results["data"]["interrupted"] = True
            # Interrupted scans are not failures
            if self.results.get("success") is None:
                self.results["success"] = True
        except Exception as e:
            self.results["success"] = False
            self.results["error"] = str(e)
            self.logger.fail(
                f"{getattr(self, 'protocol_name', 'unknown').upper()} "
                f"scan failed for {self.host}: {e}"
            )
            crash_report.record(
                e,
                protocol=getattr(self, "protocol_name", "unknown"),
                args=self.args,
                context=f"host={self.host}",
            )
        finally:
            # Always cleanup connection resources
            try:
                self.cleanup()
            except Exception as e:
                self.logger.debug(f"cleanup failed: {e}")
            # Attach security findings to results for export. (A one-line
            # console tally used to print here; suppressed for now - findings
            # still print inline as they're discovered, and ride along in the
            # exported results.)
            findings = self.logger.to_list()
            if findings:
                self.results["data"].setdefault("security_findings", []).extend(findings)
            # Surface arg-key typo suspects: keys the scanner read that were
            # neither present nor a declared flag (recorded by ArgsDict). Debug
            # only - this is the consumer that makes the tracking observable.
            args_dict = getattr(self, "_args_dict", None)
            if isinstance(args_dict, ArgsDict):
                undeclared = args_dict.undeclared_reads
                if undeclared:
                    keys = ", ".join(sorted(undeclared))
                    self.logger.debug(f"arg keys read but never declared (possible typo): {keys}")
        return self.get_results()

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
            # Prefer the first result, whatever family it is - the
            # caller's downstream socket code is now also IPv6-aware.
            results = socket.getaddrinfo(host, None)
            if results:
                return results[0][4][0]
            return host
        except (socket.gaierror, UnicodeError) as e:
            # If resolution fails, return original (might be IP already).
            # UnicodeError (UnicodeEncodeError) escapes getaddrinfo for
            # hostnames IDNA encoding rejects - e.g. a 300-char label, or
            # a stray Unicode byte on a target-file line. It is NOT a
            # gaierror subclass, and this method runs BEFORE the
            # centralized proto_flow() error handling in __init__, so
            # letting it escape crashed the whole connection constructor
            # instead of degrading to a logged failure.
            self.logger.debug(f"resolve host failed: {e}")
            return host

    @abstractmethod
    def proto_flow(self):
        """
        Main protocol execution flow (happy-path only).

        Error handling, cleanup, and success/failure bookkeeping are handled
        by ``connection.__init__``.  Implementations should simply raise on
        fatal errors - the base class will log, set results, and call
        ``cleanup()``.

        Typical implementation:
        1. create_conn_obj() - Establish connection
        2. enum_host_info() - Gather device information
        3. print_host_info() - Display discovered info
        4. Protocol-specific scanning actions

        Logger setup (``proto_logger()``) is called automatically by
        ``connection.__init__`` before ``proto_flow()`` runs - child classes
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
        # Update logger to use resolved IP for display
        self.logger.extra["host"] = self.ip

        # Set hostname if original host was different from IP
        if hasattr(self, "host") and self.host != self.ip:
            self.logger.extra["hostname"] = self.host[:16]

        # Update port if it changed
        port = self.results.get("port") or getattr(self, "default_port", 0) or 0
        if port:
            self.logger.extra["port"] = port

    def record_connect_failure(
        self,
        cause: str,
        exc: BaseException | None = None,
        detail: str = "",
    ) -> None:
        """Record a connect failure uniformly across protocols (GH issue #59).

        Prints the single canonical failure line and stamps
        ``results["success"]``/``results["error"]`` so the JSON contract
        holds (error always present on connect failure, same vocabulary).
        Protocol runners should call this exactly once per failed connect
        instead of hand-rolling their own logger.fail + results stanzas.

        Args:
            cause: one of the classify_connection_failure() vocabulary:
                refused / timeout / unreachable / tls / auth / unknown.
            exc: the underlying exception, when available (message folded
                into the error string).
            detail: extra protocol-level context (e.g. the transport).
        """
        # "unknown" tells the operator nothing. When classification dead-ended
        # (a library that swallows exceptions), one cheap raw TCP probe recovers
        # the real cause - same fallback the modbus/iec104 runners already do.
        if cause == "unknown":
            from oida.utils.protocol_helpers import probe_connect_failure_cause

            try:
                timeout = float(getattr(self.args, "timeout", 2) or 2)
            except (TypeError, ValueError):
                timeout = 2.0
            probed = probe_connect_failure_cause(
                self.ip,
                self.results.get("port") or getattr(self, "default_port", 0),
                timeout=timeout,
            )
            if probed:
                cause = probed

        target = f"{self.host}:{self.results.get('port') or getattr(self, 'default_port', 0)}"
        suffix = f" ({detail})" if detail else ""
        if exc is not None and str(exc) and str(exc) != cause:
            error = f"connect {cause}: {exc}{suffix}"
        else:
            error = f"connect {cause}{suffix}"
        self.logger.fail(f"Connect failed: {cause} ({target})")
        self.results["success"] = False
        self.results["error"] = error

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

    def print_host_info(self):
        """
        Print discovered host information.

        Optional override: display the info gathered by enum_host_info() in a
        user-friendly format, respecting verbosity flags. The uniform security-
        findings tally is printed for every protocol by the teardown in
        proto_flow(), so protocols with no extra banner (e.g. SNMP) can rely on
        this no-op default.
        """

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
                self.logger.debug(f"Error during cleanup: {e}")

    def get_results(self) -> ScanResult:
        """
        Get scan results.

        Returns:
            ScanResult: the typed envelope (``host``/``ip``/``protocol``/
            ``port``/``success``/``error``/``data``) for this target. The
            internal container is a mutable ``Dict[str, Any]`` so subclasses can
            index/mutate ``results["data"][...]`` freely; ``cast`` applies the
            documented envelope shape at this boundary. See
            ``oida.utils.result_types.ScanResult``.
        """
        return cast(ScanResult, self.results)

    def _convert_args_to_dict(self) -> Dict[str, Any]:
        """
        Convert argparse.Namespace to the dict format expected by scanners.

        Returns an :class:`~oida.utils.args_dict.ArgsDict` - a normalizing dict
        where the hyphenated CLI spelling and the underscore argparse spelling
        of a key resolve to the same slot. Each key is therefore stored **once**
        (underscore form); scanners that read ``args.get("unit-id")`` still hit
        it. This replaces the old dual-write that stored every key twice.

        ``known_keys`` is the complete declared arg surface - argparse
        materializes every flag as a Namespace attribute (``None`` when unset),
        so ``vars(self.args)`` names every valid key even after the ``None``
        values are dropped below. That lets the ArgsDict distinguish a genuine
        typo'd read from a legitimately-absent optional. Strict raising is
        opt-in via ``OIDA_STRICT_ARGS`` and behavior-preserving by default.

        .. warning::
           ``OIDA_STRICT_ARGS`` is **experimental - do not enable it in CI yet.**
           ``known_keys`` here is only the argparse dest surface; protocols that
           *synthesize* dict keys (e.g. dnp3's ``cli_runner``: ``read-class``,
           ``master-address``, ``control``) would trip false positives until
           those keys are folded in. See ``ArgsDict`` for details.
        """
        declared = {"rhost", "rport", *vars(self.args).keys()}
        result = ArgsDict(
            rhost=self.ip,
            known_keys=declared,
            strict=os.environ.get("OIDA_STRICT_ARGS", "").lower() in ("1", "true", "yes"),
        )
        for key, value in vars(self.args).items():
            if value is None:
                continue
            # Map special keys
            if key == "port":
                result["rport"] = value
            else:
                result[key] = value
        # Cache the produced mapping so run() can surface any typo'd arg-key
        # reads (see undeclared_reads). Overrides mutate this object in place and
        # return it, so the reference stays the one the scanner reads from.
        self._args_dict = result
        return result


class NetworkConnection(connection):
    """
    Base class for network-based protocols (TCP/UDP)

    Extends connection with network-specific utilities like
    port handling and timeout management.
    """

    def __init__(self, args: Any, db: Optional[Any], host: str, *, autostart: bool = True):
        """Initialize network connection.

        The default-port resolution is done on a *copy* of args so the caller's
        namespace is not mutated. Cross-protocol invocations from the dispatcher
        share a single argparse Namespace; writing to ``args.port`` here would
        leak the previous protocol's port to the next.

        ``autostart`` is forwarded to the base ``connection`` (see its docstring):
        True runs the scan on construct, False builds without scanning.
        """
        # Always copy when we touch args. The old code only copied when
        # port was unset, so a user-supplied -p value persisted on the
        # shared Namespace and bled into every subsequent protocol
        # invocation in the same process (CLI uses a process-wide
        # Namespace). Deep-copy so that mutable attributes (lists/dicts/sets,
        # e.g. scan_range) are not aliased across the two Layer-2 protocols a
        # single process may run - a shallow copy left those shared and an
        # in-place mutation bled into the next invocation.
        args = copy.deepcopy(args)
        if hasattr(self, "default_port") and not getattr(args, "port", None):
            args.port = self.default_port

        super().__init__(args, db, host, autostart=autostart)


class SerialConnection(connection):
    """
    Base class for serial/layer-2 protocols

    Extends connection with serial-specific utilities like
    interface handling and packet capture.
    """

    def __init__(self, args: Any, db: Optional[Any], host: str, *, autostart: bool = True):
        """Initialize serial connection.

        ``autostart`` is forwarded to the base ``connection`` (see its docstring):
        True runs the scan on construct, False builds without scanning.
        """
        # For serial protocols, "host" might be an interface name
        self.interface = getattr(args, "interface", None) or host
        # Same isolation contract as NetworkConnection (see its comment): the
        # CLI reuses one argparse Namespace across protocol dispatches, and
        # serial scanners mutate list/dict attributes (e.g. scan_range) in
        # place. Without a deep copy those writes bleed into the caller's
        # Namespace and the next protocol invocation in this process.
        args = copy.deepcopy(args)
        super().__init__(args, db, host, autostart=autostart)
