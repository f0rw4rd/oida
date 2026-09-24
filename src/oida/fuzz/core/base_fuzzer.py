from oida.fuzz.core.config import FuzzerConfig, MonitorConfig
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Set, Union, TYPE_CHECKING
from dataclasses import dataclass
from enum import Enum
from oida.fuzz.monitors import BaseMonitor, CombinedMonitor
from oida.fuzz.monitors.registry import create_monitor
from oida.fuzz.core.connections import ConnectionFactory, RealConnectionFactory
from oida.fuzz.core.mutation import (
    MutationStrategy,
    enable_radamsa,
    disable_radamsa,
    set_mutation_seed,
)
from oida.fuzz.core.session.state_machine import StateMachine, StateTransitionError
from oida.utils.ics_logger import get_logger, ICSLogger, set_progress_active
import logging

logger = logging.getLogger(__name__)
import os
import sys
import random
import threading
import time
from boofuzz import Session, Target
from boofuzz.connections import TCPSocketConnection


class CommonState(Enum):
    """Pre-defined states common to most protocols.

    Protocols can use these directly or define custom states via StateMachine.
    These states represent typical phases in protocol communication.

    Usage:
        from oida.fuzz.core.base_fuzzer import CommonState, RequestInfo

        # Use in RequestInfo
        RequestInfo("Auth_Fuzz", "...", requires_state=CommonState.PRE_AUTH)
        RequestInfo("Post_Auth", "...", requires_state=CommonState.AUTHENTICATED)

        # Multiple acceptable states (OR logic)
        RequestInfo("Flexible", "...", requires_state=[CommonState.AUTHENTICATED, "CUSTOM_STATE"])
    """

    # Connection states
    DISCONNECTED = "DISCONNECTED"
    CONNECTED = "CONNECTED"

    # Authentication states
    PRE_AUTH = "PRE_AUTH"  # Before any authentication
    AUTHENTICATING = "AUTHENTICATING"  # During auth handshake
    AUTHENTICATED = "AUTHENTICATED"  # After successful auth
    AUTH_FAILED = "AUTH_FAILED"

    # Session states
    IDLE = "IDLE"  # Ready for commands
    BUSY = "BUSY"  # Processing a request

    # Data transfer states (FTP, etc.)
    DATA_CHANNEL_SETUP = "DATA_CHANNEL_SETUP"
    DATA_TRANSFER_ACTIVE = "DATA_TRANSFER_ACTIVE"

    # Special states
    ANY = "ANY"  # Request can run in any state
    ERROR = "ERROR"


if TYPE_CHECKING:
    from oida.fuzz.core.database import DatabaseInterface
    from oida.fuzz.core.session.manager import TestCaseManager


@dataclass
class RequestInfo:
    """Information about a fuzzer request (test case group).

    Attributes:
        name: Request name (must match the boofuzz Request name)
        description: Human-readable description
        category: Category for grouping (e.g., "baseline", "auth", "critical")
        slow: Mark as slow/expensive request
        requires_state: State(s) required to run this request

    State Requirements:
        - None: Use fuzzer's DEFAULT_REQUEST_STATE (typically AUTHENTICATED)
        - CommonState.PRE_AUTH: Run without authentication
        - CommonState.AUTHENTICATED: Run after authentication (explicit)
        - CommonState.ANY: Can run in any state
        - "CUSTOM_STATE": Protocol-specific state from StateMachine
        - ["STATE_A", "STATE_B"]: Multiple acceptable states (OR logic)

    Examples:
        # FTP USER/PASS fuzzing - must run before auth
        RequestInfo("FTP_Auth_Fuzz", "...", requires_state=CommonState.PRE_AUTH)

        # FTP CWD - must run after auth
        RequestInfo("FTP_Critical_Path", "...", requires_state=CommonState.AUTHENTICATED)

        # FTP STOR - requires passive or active mode established
        RequestInfo("FTP_FileTransfer", "...", requires_state=["FTP_PASSIVE_MODE", "FTP_ACTIVE_MODE"])

        # MQTT publish - requires subscription or auth
        RequestInfo("MQTT_Publish", "...", requires_state=["MQTT_SUBSCRIBED", "AUTHENTICATED"])
    """

    name: str
    description: str
    category: str = "general"
    slow: bool = False  # Mark slow/expensive requests
    requires_state: Optional[Union[str, CommonState, List[Union[str, CommonState]]]] = None
    # Whether mutated sends on this request normally produce a server reply.
    # False enables the no-reply fast path: the post-send recv skips the full
    # timeout wait (polls briefly instead). Only mark requests whose packets
    # are answered only on success — the fast path still surfaces RSTs.
    expects_response: bool = True


class BaseFuzzer(ABC):
    # Global protocol options - available to all fuzzers
    PROTOCOL_OPTIONS = {
        "use_radamsa": {
            "type": bool,
            "default": False,
            "description": "Use Radamsa mutations instead of boofuzz defaults",
        },
        "radamsa_mutation_count": {
            "type": int,
            "default": 200,
            "description": "Number of Radamsa mutations per field",
        },
    }

    # Default monitors for this protocol (override in subclasses)
    # Format: "monitor[:interval],monitor[:interval],..."
    # Examples: "socket" or "modbus:10"
    DEFAULT_MONITORS = "socket"

    # Stateful protocols must consume each reply to advance their state machine, so they
    # get a more generous calibrated recv timeout. Override to True in such fuzzers.
    STATEFUL = False

    def __init__(
        self,
        config: FuzzerConfig,
        connection_factory: Optional[ConnectionFactory] = None,
        mutation_strategy: Optional[MutationStrategy] = None,
    ):
        self.config = config
        self.connection_factory = connection_factory or RealConnectionFactory()

        # Create ICSLogger for consistent formatted output
        protocol = getattr(config, "protocol", "FUZZ").upper()
        verbose = getattr(config, "console_output", False)
        self.log = get_logger(
            f"FUZZ-{protocol}", config.target_ip, config.target_port, verbose=verbose
        )

        # Per-instance RNG. Seeding the process-global `random` module would be a
        # global side effect: it makes runs non-reproducible as soon as any other
        # code draws from `random`, and concurrent fuzzers would fight over the
        # same stream. Route all fuzzer-owned draws through self.rng instead.
        self.rng = random.Random(config.seed)
        if config.seed is not None:
            set_mutation_seed(config.seed)
            self.log.debug(f"Set random seed to {config.seed}")

        # Configure console output FIRST (before any boofuzz operations)
        self._configure_console_output()

        # Configure mutation strategy (instance-level, not global)
        # Priority: explicit parameter > config options > defaults
        if mutation_strategy is not None:
            self.mutation_strategy = mutation_strategy
        else:
            self.mutation_strategy = MutationStrategy.from_config(config)

        self._configure_mutation_mode()

        # Run capability enumeration before protocol definition if enabled
        # Subclasses override _enumerate_capabilities() for protocol-specific discovery
        self.capabilities: Dict[str, Any] = {}
        if config.enumerate:
            self.capabilities = self._enumerate_capabilities() or {}

        # Populated by _setup_monitor() with the CLI-requested extras
        # (--script-monitor / --valid-case / --agent-monitor) so they can be
        # re-applied below if a subclass replaces the monitor set.
        self._extra_monitors = []
        self.monitor = self._setup_monitor()
        # Only use protocol-specific custom monitors if user didn't explicitly specify monitors
        # (config.monitor_config is set when user provides -M/--monitors)
        if self.config.monitor_config is None:
            # Only override the default monitors from _setup_monitor() when a
            # subclass actually supplies custom ones. The base hook returns [],
            # and set_monitors() only guards against None -- passing the empty
            # list would wipe the configured crash monitors and silently disable
            # crash detection for every fuzzer that doesn't override the hook.
            custom_monitors = self.setup_custom_monitors()
            if custom_monitors:
                # Merge rather than replace. set_monitors() overwrites the list,
                # so a protocol supplying its own monitors would otherwise evict
                # the extras _setup_monitor() just built -- leaving
                # --agent-monitor to print its banner while the agent is never
                # queried, and crash detection silently downgraded to the
                # socket-level signal.
                seen = {id(m) for m in custom_monitors}
                custom_monitors = custom_monitors + [
                    m for m in self._extra_monitors if id(m) not in seen
                ]
                self.monitor.set_monitors(custom_monitors)

        # Log monitor configuration
        self._log_monitor_config()

        # Log capability enumeration results (subclasses override _log_capabilities)
        self._log_capabilities()

        self._session = None  # Lazy initialization
        self.state_machine: Optional[StateMachine] = (
            None  # Optional state machine for stateful protocols
        )

        # Test case manager for recording test results (lazy initialization)
        self._test_case_manager: Optional[TestCaseManager] = None
        self._database: Optional["DatabaseInterface"] = None

        # Request registry for selective fuzzing
        self._available_requests: Dict[str, RequestInfo] = {}
        self._enabled_requests: Optional[Set[str]] = None  # None = all enabled
        self._disabled_requests: Set[str] = set()

        # Populate _available_requests from get_request_definitions()
        # This ensures RequestInfo objects are available for state tracking
        for request_info in self.get_request_definitions():
            self._available_requests[request_info.name] = request_info

        # Apply request filters from config
        if config.enabled_requests:
            self._enabled_requests = set(config.enabled_requests)
        if config.disabled_requests:
            self._disabled_requests = set(config.disabled_requests)

        # Warn about --enable/--disable names that don't match any registered
        # request, so a typo (e.g. "HTTP_Baselin") is visible instead of silently
        # putting the fuzzer in whitelist mode that matches nothing and fuzzes nothing.
        self._validate_request_filters()

        # Progress monitoring
        self._progress_stop_flag = False
        self._progress_interval = 5  # seconds

    def _configure_console_output(self):
        """Configure console output verbosity

        The filters below are deliberately scoped to records emitted by
        boofuzz's own loggers (``boofuzz.*`` / root-logger ``fuzzing:`` debug
        spam).  Earlier versions matched purely on message text/level and were
        attached to *every* root-logger handler without ever being removed —
        which silently swallowed unrelated records (e.g. pytest's per-test
        LogCaptureHandler) for the rest of the process lifetime.
        """

        # Filter that blocks boofuzz's internal "fuzzing:" messages.
        # These use logging.debug() on root logger and don't follow ICSLogger format.
        class BoofuzzFilter(logging.Filter):
            def filter(self, record):
                # Only ever drop records that originate from boofuzz itself;
                # anything from other loggers must pass through untouched.
                if not (record.name == "root" or record.name.startswith("boofuzz")):
                    return True
                msg = record.getMessage()
                # Block boofuzz's "fuzzing: XXX" messages
                if msg.startswith("fuzzing:"):
                    return False
                # Block other boofuzz internal messages that clutter output
                if "Connection opened" in msg or "Connection closed" in msg:
                    return False
                return True

        # Apply boofuzz filter to root logger (always, regardless of verbose mode)
        root_logger = logging.getLogger()
        self._boofuzz_filter = BoofuzzFilter()
        for handler in root_logger.handlers:
            if self._boofuzz_filter not in handler.filters:
                handler.addFilter(self._boofuzz_filter)

        if not self.config.console_output:
            # Filter that only allows WARNING and above -- but, like
            # BoofuzzFilter, only for boofuzz-originated records, so quiet
            # mode cannot mute other subsystems sharing a handler.
            class QuietFilter(logging.Filter):
                def filter(self, record):
                    if not (record.name == "root" or record.name.startswith("boofuzz")):
                        return True
                    # Only show WARNING, ERROR, and CRITICAL
                    return record.levelno >= logging.WARNING

            # Apply filter to all existing handlers
            quiet = QuietFilter()
            for handler in root_logger.handlers:
                if quiet not in handler.filters:
                    handler.addFilter(quiet)

            # Also store filter so we can apply it to handlers created later by boofuzz
            self._quiet_filter = quiet
        else:
            self._quiet_filter = None

    def _configure_mutation_mode(self):
        """Configure mutation mode based on instance-level strategy.

        Uses self.mutation_strategy (instance-level) instead of global state.
        This allows multiple fuzzers with different mutation strategies to
        run concurrently without interference.

        Note: Global enable_radamsa()/disable_radamsa() are still called for
        backwards compatibility with code that checks is_radamsa_enabled().
        """
        if self.mutation_strategy.use_radamsa:
            try:
                # Update global state for backwards compatibility
                enable_radamsa(mutation_count=self.mutation_strategy.mutation_count)
                self.log.display(
                    f"Radamsa mutations enabled ({self.mutation_strategy.mutation_count} per field)"
                )
            except RuntimeError as e:
                self.log.fail(f"Failed to enable Radamsa: {e}")
                self.log.display("Falling back to boofuzz mutations")
                self.mutation_strategy = MutationStrategy(use_radamsa=False)
                disable_radamsa()
        else:
            # Only disable global if we're not using it
            # (don't interfere with other fuzzers that might be using it)
            self.log.debug("Using boofuzz default mutations")

    @property
    def session(self) -> Session:
        """Lazy session creation to avoid immediate network connections"""
        if self._session is None:
            self._session = self._create_session()
            self._define_protocol()

            # Setup test case manager for recording test results
            if self.config.log_session:
                self._setup_test_case_manager()

            # Setup state machine if protocol defines one
            # This happens after protocol definition so state machine
            # can use the session connection for authentication
            if hasattr(self, "_define_state_machine"):
                try:
                    self._define_state_machine()
                    if self.state_machine:
                        self.log.display(
                            f"State machine initialized: {self.state_machine.get_current_state_name()}"
                        )
                except StateTransitionError as e:
                    self.log.fail(f"Failed to initialize state machine: {e}")
                    raise
                except Exception as e:
                    self.log.fail(f"Unexpected error during state machine setup: {e}")
                    raise
        return self._session

    def _setup_test_case_manager(self) -> None:
        """Initialize TestCaseManager for recording test results with target tracking"""
        # Import here to avoid circular imports
        # (session_manager -> protocols -> fuzzers -> base_fuzzer)
        from oida.fuzz.core.database.orm import SQLAlchemyDatabase
        from oida.fuzz.core.session.manager import TestCaseManager

        try:
            # Create database
            db_path = f"{self.config.session_filename}.db"
            self._database = SQLAlchemyDatabase(db_path)

            # Create test case manager
            self._test_case_manager = TestCaseManager(
                fuzzer=self,
                database=self._database,
                store_all_payloads=getattr(self.config, "store_all_payloads", False),
            )

            # Register callbacks to record test cases automatically
            self._test_case_manager.register_callbacks()

            self.log.debug(f"TestCaseManager initialized: {db_path}")
            self.log.debug(
                f"Recording test cases for protocol={getattr(self.config, 'protocol', 'unknown')} "
                f"target={self.config.target_ip}:{self.config.target_port}"
            )

        except Exception as e:
            self.log.fail(f"Failed to setup TestCaseManager: {e}")
            # Don't fail the fuzzer if test case recording fails
            self._test_case_manager = None

    @classmethod
    def get_default_monitors(cls) -> str:
        """Get default monitor string for this protocol.

        Override DEFAULT_MONITORS in subclasses for protocol-specific defaults.

        Returns:
            Monitor specification string (e.g., "ping,socket" or "ping:100,modbus:10")
        """
        return cls.DEFAULT_MONITORS

    def _setup_monitor(self) -> CombinedMonitor:
        """Set up monitors based on configuration.

        Priority:
        1. config.monitor_config (explicit CLI --monitors)
        2. Protocol's DEFAULT_MONITORS (class attribute)
        3. Fallback: ping + socket monitors
        """
        # Determine monitor configuration
        monitor_config = self.config.monitor_config

        if monitor_config is None:
            # Use protocol defaults
            default_monitors = self.get_default_monitors()
            monitor_config = MonitorConfig.parse(default_monitors, logic=self.config.monitor_logic)

        # Determine logic
        logic = monitor_config.logic if monitor_config else self.config.monitor_logic

        # Handle "none" case - no monitors (but still honour explicit script/valid-case
        # monitors and auto-restart if the user asked for them).
        if monitor_config.is_empty():
            extra = self._create_extra_monitors()
            self._extra_monitors = list(extra)
            self._apply_restart_config(extra)
            return CombinedMonitor(
                host=self.config.target_ip,
                port=self.config.target_port,
                monitors=extra or [],
                skip_pre_send=self.config.skip_pre_send_checks,
                check_interval=self.config.monitor_check_interval,
                logic=logic,
                session_filename=self.config.session_filename,
                graceful_degradation=self.config.graceful_degradation,
            )

        # Create monitor instances from configuration
        monitors = self._create_monitors_from_config(monitor_config)

        # Append the platform-feature monitors (script / valid-case) when configured,
        # and arm auto-restart on every monitor.
        extra = self._create_extra_monitors()
        self._extra_monitors = list(extra)
        monitors.extend(extra)
        self._apply_restart_config(monitors)

        # Determine check_interval: use the maximum from monitor specs if specified,
        # otherwise fall back to config default
        check_interval = self.config.monitor_check_interval
        if monitor_config.monitors:
            # Get max interval from specs (if any have explicit intervals)
            explicit_intervals = [
                spec.interval for spec in monitor_config.monitors if spec.interval
            ]
            if explicit_intervals:
                check_interval = max(explicit_intervals)

        return CombinedMonitor(
            host=self.config.target_ip,
            port=self.config.target_port,
            monitors=monitors if monitors else None,
            skip_pre_send=self.config.skip_pre_send_checks,
            check_interval=check_interval,
            logic=logic,
            session_filename=self.config.session_filename,
            graceful_degradation=self.config.graceful_degradation,
        )

    def _create_monitors_from_config(self, monitor_config: MonitorConfig) -> List[BaseMonitor]:
        """Create monitor instances from MonitorConfig.

        Args:
            monitor_config: Monitor configuration with specs and logic

        Returns:
            List of monitor instances
        """
        monitors = []

        for spec in monitor_config.monitors:
            monitor = create_monitor(
                name=spec.name,
                host=self.config.target_ip,
                port=self.config.target_port,
                interval=spec.interval,
            )

            if monitor is not None:
                monitors.append(monitor)
            else:
                self.log.warning(f"Unknown or failed monitor: {spec.name}")

        return monitors

    def _create_extra_monitors(self) -> List[BaseMonitor]:
        """Build the script / valid-case monitors that need richer args than the
        ``name:interval`` registry path can carry."""
        extra: List[BaseMonitor] = []

        if self.config.script_monitor_command:
            from oida.fuzz.monitors.script import ScriptMonitor

            extra.append(
                ScriptMonitor(
                    host=self.config.target_ip,
                    port=self.config.target_port,
                    command=self.config.script_monitor_command,
                    check_interval=self.config.monitor_check_interval,
                )
            )
            self.log.display(f"Script monitor: {' '.join(self.config.script_monitor_command)}")

        if self.config.valid_case_probe:
            from oida.fuzz.monitors.network import ValidCaseMonitor

            extra.append(
                ValidCaseMonitor(
                    host=self.config.target_ip,
                    port=self.config.target_port,
                    probe=self.config.valid_case_probe,
                    expect=self.config.valid_case_expect,
                    check_interval=self.config.monitor_check_interval,
                )
            )
            self.log.display(f"Valid-case probe: {len(self.config.valid_case_probe)} bytes")

        if self.config.agent_monitor_host:
            from oida.fuzz.monitors.agent import AgentMonitor

            extra.append(
                AgentMonitor(
                    host=self.config.agent_monitor_host,
                    port=self.config.agent_monitor_port,
                    token=self.config.agent_monitor_token,
                    check_interval=self.config.monitor_check_interval,
                )
            )
            self.log.display(
                f"Agent monitor: {self.config.agent_monitor_host}:{self.config.agent_monitor_port}"
            )

        return extra

    def _apply_restart_config(self, monitors: List[BaseMonitor]) -> None:
        """Arm auto-restart-and-resume on every monitor that supports it.

        The restart command is deduped at run time via the shared CrashTracker, so
        arming all monitors is safe — exactly one restart fires per crash episode.
        """
        if not self.config.restart_command:
            return
        for m in monitors:
            if hasattr(m, "restart_command"):
                m.restart_command = list(self.config.restart_command)
                m.restart_delay = self.config.restart_delay
                if getattr(m, "command_runner", None) is None:
                    from oida.fuzz.core.session.commands import RealCommandRunner

                    m.command_runner = RealCommandRunner()
        self.log.display(
            f"Auto-restart armed: {' '.join(self.config.restart_command)} "
            f"(delay {self.config.restart_delay}s)"
        )

    def _log_monitor_config(self) -> None:
        """Log monitor configuration for debugging and visibility."""
        monitor_names = []
        if hasattr(self.monitor, "monitors") and self.monitor.monitors:
            for m in self.monitor.monitors:
                monitor_names.append(type(m).__name__)

        logic = getattr(self.monitor, "logic", "and").upper()
        # Use actual check_interval from CombinedMonitor (may differ from config default)
        actual_interval = getattr(
            self.monitor, "check_interval", self.config.monitor_check_interval
        )

        monitors_str = ", ".join(monitor_names) if monitor_names else "none"
        # Show monitor config at display level so user can see what's being used
        default_source = "(protocol default)" if self.config.monitor_config is None else "(custom)"
        mode_str = "graceful" if self.config.graceful_degradation else "strict"
        self.log.display(
            f"Monitor: {monitors_str} (logic={logic}, mode={mode_str}) {default_source}"
        )
        self.log.display(f"Check interval: {actual_interval} test cases")
        self.log.debug(f"Monitor type: {type(self.monitor).__name__}")
        # Log connection settings
        if self.config.reuse_target_connection:
            self.log.debug("Connection reuse: ENABLED")
        if not self.config.receive_data_after_fuzz and self.config.receive_data_after_each_request:
            self.log.debug("Fire-forget fuzz: ENABLED (setup responses kept)")
        elif not self.config.receive_data_after_fuzz:
            self.log.debug("Receive data: DISABLED (all requests)")
        if self.config.sleep_time > 0:
            self.log.debug(f"Sleep time: {self.config.sleep_time}s")
        if self.config.recv_timeout is not None:
            self.log.debug(f"Recv timeout: {self.config.recv_timeout}s (override)")
        if self.config.send_timeout is not None:
            self.log.debug(f"Send timeout: {self.config.send_timeout}s (override)")
        if self.config.reconnect_delay is not None:
            self.log.debug(f"Reconnect delay: {self.config.reconnect_delay}s (override)")
        if self.config.max_reconnect_attempts is not None:
            self.log.debug(
                f"Max reconnect attempts: {self.config.max_reconnect_attempts} (override)"
            )

    def setup_custom_monitors(self) -> List[BaseMonitor]:
        return []

    def _log_capabilities(self) -> None:
        """Log probed server capabilities.

        Override in subclasses to display enumeration results.
        Called after _log_monitor_config() during initialization.

        Example output:
            [*] Server: nginx/1.18.0
            [*] Supported methods: GET, HEAD, POST, OPTIONS
            [*] WebDAV: not detected
        """

    def _enumerate_capabilities(self) -> Optional[Dict[str, Any]]:
        """Probe target capabilities before fuzzing.

        Override in subclasses to implement protocol-specific discovery.
        Called when config.enumerate=True, before _define_protocol().

        This method should:
        1. Connect to the target and probe for supported features
        2. Log results using _get_fuzz_logger() for formatted output
        3. Return a dict with protocol-specific capability info

        Returns:
            Dict with protocol-specific capability info, or None

        Example (HTTP):
            def _enumerate_capabilities(self) -> Dict[str, Any]:
                capabilities = {'methods': set(), 'webdav': False}
                # ... probe server ...
                fuzz_log = self._get_fuzz_logger()
                fuzz_log.display(f"Methods: {', '.join(capabilities['methods'])}")
                return capabilities

        Example (Modbus):
            def _enumerate_capabilities(self) -> Dict[str, Any]:
                capabilities = {'supported_fcs': set(), 'vendor': None}
                # ... probe function codes ...
                return capabilities
        """
        return None

    def _get_fuzz_logger(self) -> ICSLogger:
        """Get ICSLogger instance for formatted enumeration output.

        Returns the fuzzer's ICSLogger for consistent [*] formatted output.

        Returns:
            ICSLogger instance

        Example:
            fuzz_log = self._get_fuzz_logger()
            fuzz_log.display("Server: nginx/1.18.0")
            fuzz_log.display("Methods: GET, HEAD, POST")
        """
        return self.log

    @classmethod
    def get_protocol_options(cls) -> Dict[str, Dict[str, Any]]:
        """Get protocol-specific options for this fuzzer

        Returns a dictionary where keys are option names and values are dicts with:
        - type: The expected type (str, int, bool)
        - default: Default value
        - description: Human-readable description
        - choices: Optional list of valid choices
        - example: Optional example value

        Merges base class options with subclass-specific options.
        """
        # Start with base class options
        options = {}

        # Walk through the MRO (Method Resolution Order) in reverse
        # This ensures base options come first, then get overridden by subclass options
        for base_class in reversed(cls.__mro__):
            if hasattr(base_class, "PROTOCOL_OPTIONS") and base_class is not object:
                options.update(base_class.PROTOCOL_OPTIONS)

        return options

    @classmethod
    def format_options_help(cls) -> str:
        """Format help text for protocol options"""
        options = cls.get_protocol_options()
        if not options:
            return "No protocol-specific options available for this fuzzer."

        lines = []
        lines.append("\nProtocol-Specific Options:")
        lines.append("-" * 60)

        for name, info in options.items():
            lines.append(f"\n  --option {name}=<value>")
            lines.append(f"      {info.get('description', 'No description')}")
            lines.append(f"      Type: {info.get('type', 'str').__name__}")
            lines.append(f"      Default: {info.get('default', 'None')}")

            if "choices" in info:
                lines.append(f"      Choices: {', '.join(str(c) for c in info['choices'])}")

            if "example" in info:
                lines.append(f"      Example: --option {name}={info['example']}")

        return "\n".join(lines)

    # ==================== REQUEST REGISTRY METHODS ====================

    def register_request(
        self, name: str, description: str, category: str = "general", slow: bool = False
    ) -> None:
        """
        Register a request definition for selective fuzzing.

        Call this at the start of _define_protocol() to register all available requests
        before creating and connecting them.

        Args:
            name: Request name (must match the Request() name)
            description: Human-readable description
            category: Category for grouping (e.g., "baseline", "methods", "edge_cases")
            slow: Mark as slow/expensive request

        Example:
            def _define_protocol(self):
                self.register_request("HTTP_Baseline", "Simple GET / baseline test", "baseline")
                self.register_request("WebDAV_Methods", "WebDAV operations", "webdav", slow=True)
                ...
        """
        self._available_requests[name] = RequestInfo(
            name=name, description=description, category=category, slow=slow
        )

    def is_request_enabled(self, name: str) -> bool:
        """
        Check if a request is enabled for fuzzing.

        Args:
            name: Request name to check

        Returns:
            True if the request should be included in fuzzing

        Example:
            if self.is_request_enabled("WebDAV_Methods"):
                self.session.connect(webdav_request)
        """
        # If whitelist mode (--enable), only those in the list are enabled
        if self._enabled_requests is not None:
            return name in self._enabled_requests

        # Otherwise, check blacklist (--disable)
        return name not in self._disabled_requests

    def _validate_request_filters(self) -> None:
        """Warn about --enable/--disable names not present in the request registry.

        ``_available_requests`` is populated from ``get_request_definitions()`` (the
        same source that powers ``--list-requests``). Any enable/disable name that is
        not a known request is almost certainly a typo: in whitelist (--enable) mode an
        unknown name silently matches nothing, so the fuzzer connects zero requests and
        exits 'successfully' without sending anything. Surfacing a WARNING makes the
        mistake visible instead of masquerading as a clean run.
        """
        known = set(self._available_requests.keys())
        if not known:
            # No static registry (e.g. protocols that register lazily in
            # _define_protocol); nothing to validate against here.
            return

        for label, names in (
            ("--enable", self._enabled_requests),
            ("--disable", self._disabled_requests),
        ):
            if not names:
                continue
            unknown = sorted(set(names) - known)
            if unknown:
                self.log.warning(
                    f"{label} request(s) not found in registry (typo? will match nothing): "
                    f"{', '.join(unknown)}"
                )

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """
        Class method to get request definitions without instantiating the fuzzer.

        Override this in subclasses to provide static request definitions.

        Returns:
            List of RequestInfo objects
        """
        return []

    @classmethod
    def format_requests_help(cls) -> str:
        """Format help text for available requests"""
        requests = cls.get_request_definitions()
        if not requests:
            return "No request definitions available for this fuzzer."

        lines = []
        lines.append("\nAvailable Requests:")
        lines.append("-" * 70)

        # Group by category
        categories: Dict[str, List[RequestInfo]] = {}
        for req in requests:
            if req.category not in categories:
                categories[req.category] = []
            categories[req.category].append(req)

        for category, reqs in sorted(categories.items()):
            lines.append(f"\n  [{category}]")
            for req in reqs:
                slow_marker = " [SLOW]" if req.slow else ""
                # Format state requirement
                state_marker = ""
                if req.requires_state is not None:
                    if isinstance(req.requires_state, CommonState):
                        state_marker = f" [{req.requires_state.value}]"
                    elif isinstance(req.requires_state, list):
                        states = [
                            s.value if isinstance(s, CommonState) else s for s in req.requires_state
                        ]
                        state_marker = f" [{'/'.join(states)}]"
                    else:
                        state_marker = f" [{req.requires_state}]"
                lines.append(f"    {req.name:<30} - {req.description}{slow_marker}{state_marker}")

        lines.append("")
        lines.append("Use --enable or --disable to select specific requests:")
        lines.append("  --enable HTTP_Baseline,JSON_Request    # Only run these")
        lines.append("  --disable WebDAV_Methods               # Skip these")
        lines.append("")
        lines.append(
            "State markers: [PRE_AUTH]=before login, [AUTHENTICATED]=after login, [ANY]=any state"
        )

        return "\n".join(lines)

    def _create_socket(self) -> TCPSocketConnection:
        """Create appropriate socket connection using the injected factory"""
        return self.connection_factory.create_connection(self.config)

    def _timeout_overrides(self, recv_default: float = 5.0, send_default: float = 5.0) -> dict:
        """Socket timeout kwargs for protocols that build their own connection.

        Prefers the CLI overrides (--recv-timeout / --send-timeout, surfaced as
        config.recv_timeout / config.send_timeout) and falls back to the protocol's
        own default when unset. boofuzz TCP/UDP/SSL connections all accept both kwargs.
        """
        recv = self.config.recv_timeout if self.config.recv_timeout is not None else recv_default
        send = self.config.send_timeout if self.config.send_timeout is not None else send_default
        return {"send_timeout": send, "recv_timeout": recv}

    def _create_session(self) -> Session:
        """Create and configure fuzzing session"""

        # Determine web port (None disables web interface)
        web_port = self.config.web_port if self.config.web_interface else None

        # Configure fuzz loggers:
        # - Empty list [] = disable boofuzz console output
        # - None = use boofuzz defaults (console output)
        # By default, we disable boofuzz's console output
        fuzz_loggers = None if self.config.boofuzz_db else []

        # Configure database:
        # - None = boofuzz creates db in boofuzz-results/ (default boofuzz behavior)
        # - ":memory:" = use in-memory SQLite database (no files created)
        # By default, we use in-memory to avoid cluttering boofuzz-results/
        db_filename = None if self.config.boofuzz_db else ":memory:"

        # Create restart callback for crash recovery
        def restart_target():
            """Restart callback invoked when monitor detects a crash.

            Logs the crash and waits for target to potentially restart.
            Connection will be re-established by boofuzz on next test case.
            """
            self.log.fail("TARGET CRASH DETECTED - Monitor reported failure")
            self.log.display(f"Waiting {self.config.restart_timeout}s for target recovery...")
            time.sleep(self.config.restart_timeout)
            self.log.display("Continuing fuzzing (connection will reconnect)")

        # Note: We use our own lightweight logging through TestCaseManager.
        # boofuzz's db is either in-memory (default) or on disk (--boofuzz-db flag).
        # The two branches previously built byte-for-byte identical Sessions and
        # differed only by the warning, so build once and warn conditionally.
        if not self.config.log_session:
            self.log.warning("Session logging is disabled!")
        session = Session(
            target=Target(connection=self._create_socket(), monitors=[self.monitor]),
            crash_threshold_request=self.config.crash_threshold,
            restart_timeout=self.config.restart_timeout,
            restart_callbacks=[restart_target],
            web_port=web_port,
            # boofuzz blocks on input() ("Press ENTER to close webinterface") after the
            # run when keep_web_open is True and a web port is set. Under a non-interactive
            # stdin (CI, pytest, piped invocation) that read hits EOF and surfaces as a
            # spurious traceback. Only keep the UI waiting when someone is actually at a TTY.
            keep_web_open=bool(getattr(sys.stdin, "isatty", lambda: False)()),
            check_data_received_each_request=False,
            receive_data_after_each_request=self.config.receive_data_after_each_request,
            receive_data_after_fuzz=self.config.receive_data_after_fuzz,
            fuzz_loggers=fuzz_loggers,
            db_filename=db_filename,
            index_start=self.config.index_start,
            index_end=self.config.index_end,
            sleep_time=self.config.sleep_time,
            reuse_target_connection=self.config.reuse_target_connection,
            # Cap boofuzz's own results DB so a long campaign doesn't grow it without
            # bound. 0 (boofuzz's default) keeps every passing case forever -- against
            # a real protocol (opcua ~288k cases) that is a steady RAM leak. Failing
            # cases are always retained regardless of this cap, and OIDA records full
            # crash context to its own on-disk session DB, so a rolling window here is
            # enough for the web UI.
            fuzz_db_keep_only_n_pass_cases=self.config.fuzz_db_keep_pass_cases,
        )

        # Apply filters to any new handlers created by Session
        root_logger = logging.getLogger()
        for handler in root_logger.handlers:
            # Always apply boofuzz filter to block "fuzzing:" messages
            if hasattr(self, "_boofuzz_filter") and self._boofuzz_filter:
                if self._boofuzz_filter not in handler.filters:
                    handler.addFilter(self._boofuzz_filter)
            # Apply quiet filter if console_output is disabled
            if hasattr(self, "_quiet_filter") and self._quiet_filter:
                if self._quiet_filter not in handler.filters:
                    handler.addFilter(self._quiet_filter)

        # Display session information
        self._display_session_info(session)

        return session

    def _display_session_info(self, session: Session):
        """Display session information during initialization"""
        # Session file info
        if self.config.log_session:
            db_file = f"{self.config.session_filename}.db"
            session_file = f"{self.config.session_filename}.session"

            # Check if resuming existing session
            db_exists = os.path.exists(db_file)
            session_exists = os.path.exists(session_file)

            if db_exists or session_exists:
                if db_exists:
                    db_size = os.path.getsize(db_file)

                    # Try to get test case count from database
                    try:
                        from oida.fuzz.core.database.orm import SQLAlchemyDatabase

                        db = SQLAlchemyDatabase(db_file)
                        db.init_schema()
                        stats = db.get_target_stats(self.config.target_ip, self.config.target_port)
                        last_case = stats["last_id"]
                        crash_count = stats["crash_count"]

                        if last_case:
                            self.log.highlight(
                                f"RESUMING SESSION: {last_case:,} tests, {crash_count} crashes ({db_size / 1024 / 1024:.2f} MB)"
                            )
                            # Display resume point
                            if self.config.index_start > 1:
                                self.log.display(
                                    f"Continuing from test case {self.config.index_start}"
                                )
                            else:
                                self.log.display(f"Continuing from test case {last_case + 1}")
                        else:
                            # No data for this target in the DB
                            self.log.display(f"New target in existing session: {db_file}")
                            if self.config.index_start > 1:
                                self.log.display(
                                    f"Starting from test case: {self.config.index_start}"
                                )

                    except Exception as e:
                        self.log.debug(f"Could not read session database: {e}")

            else:
                self.log.display(f"New session: {db_file}")
                if self.config.index_start > 1:
                    self.log.display(f"Starting from test case: {self.config.index_start}")

        else:
            self.log.warning("Session logging disabled - no persistence")

    @abstractmethod
    def _define_protocol(self) -> None:
        """Define the protocol-specific fuzzing structure"""

    def _define_state_machine(self) -> None:
        """
        Optional: Define state machine for stateful protocols

        Override this method to set up authentication or multi-stage handshakes.

        Example:
            def _define_state_machine(self):
                from oida.fuzz.core.state_machine import ProtocolState, StateMachine

                connected = ProtocolState(name="CONNECTED")
                authenticated = ProtocolState(
                    name="AUTHENTICATED",
                    setup=self._perform_login,
                    validation=self._validate_auth,
                    requires=["CONNECTED"]
                )

                self.state_machine = StateMachine(
                    initial_state=connected,
                    states=[connected, authenticated]
                )

                # Transition to authenticated state
                self.state_machine.transition_to("AUTHENTICATED")
        """

    def _regenerate_payload(self, test_case_id: int) -> bytes:
        """
        Regenerate payload for specific test case using boofuzz determinism.

        This method creates a temporary session with index_start/index_end set to
        regenerate a single test case payload deterministically. Boofuzz mutations
        are deterministic by index, so test_case_id=100 always generates the same
        payload if the protocol definition hasn't changed.

        Args:
            test_case_id: Test case index to regenerate

        Returns:
            bytes: Regenerated payload

        Raises:
            ValueError: If payload cannot be regenerated

        Example:
            >>> fuzzer = HTTPFuzzer(config)
            >>> payload = fuzzer._regenerate_payload(12345)
            >>> len(payload)
            512
        """
        temp_target = None
        original_session = self._session
        try:
            # Create temporary target for regeneration (no monitors)
            temp_target = Target(connection=self._create_socket())

            # Create temporary session for single test case regeneration
            temp_session = Session(
                target=temp_target,
                index_start=test_case_id,
                index_end=test_case_id + 1,
                sleep_time=0,
                web_port=None,  # No web interface
                fuzz_loggers=[],  # No console output
                check_data_received_each_request=False,
                reuse_target_connection=self.config.reuse_target_connection,
            )

            # Temporarily use regeneration session
            self._session = temp_session

            # Define protocol (same as original fuzzing)
            self._define_protocol()

            # Capture payload during test case generation
            captured_payloads = []

            def capture_callback(target, fuzz_data_logger, session, *args, **kwargs):
                """Capture payload sent during regeneration"""
                # Get payload from session.last_send
                payload = (
                    session.last_send
                    if hasattr(session, "last_send") and session.last_send
                    else b""
                )
                if not isinstance(payload, bytes):
                    try:
                        payload = bytes(payload)
                    except (TypeError, ValueError) as e:
                        self.log.debug(f"Failed to convert payload to bytes: {e}")
                        payload = b""
                if payload:
                    captured_payloads.append(payload)

            # Register callback to capture payload using boofuzz API
            temp_session.register_post_test_case_callback(capture_callback)

            # Run single test case (regenerate payload)
            temp_session.fuzz()

            # Return captured payload
            if captured_payloads:
                return captured_payloads[0]
            else:
                raise ValueError(f"Failed to capture payload for test case {test_case_id}")

        except ValueError:
            raise
        except Exception as e:
            self.log.fail(f"Failed to regenerate payload for test case {test_case_id}: {e}")
            raise ValueError(f"Payload regeneration failed: {e}")
        finally:
            # Always restore original session
            self._session = original_session

            # Always close temporary target/connection if it was created
            if temp_target is not None:
                try:
                    temp_target.close()
                except (OSError, AttributeError) as e:
                    self.log.debug(f"Error closing temporary target: {e}")

    def fuzz_node(self, node_path: str) -> None:
        """Fuzz specific node in the protocol"""
        # Pre-flight connectivity check
        ok, err = self._preflight_check()
        if not ok:
            raise ConnectionError(f"Target unreachable ({err})")

        # Log successful preflight check
        fuzz_log = self._get_fuzz_logger()
        fuzz_log.success("Preflight check passed")

        try:
            self.session.fuzz(node_path)
        except Exception as e:
            raise ValueError(f"Failed to fuzz node {node_path}: {str(e)}")

    def _preflight_check(self) -> tuple:
        """Run pre-flight connectivity check using the configured monitor.

        Uses _check_alive_once (not _check_alive) to get actual connectivity
        status without failure tolerance thresholds.

        Returns:
            Tuple of (success: bool, error_msg: str or None)
        """
        if not self.monitor:
            self.log.debug("No monitor configured, skipping preflight check")
            return True, None

        self.log.display("Running preflight connectivity check...")

        try:
            # For CombinedMonitor: check each sub-monitor directly
            if hasattr(self.monitor, "monitors") and self.monitor.monitors:
                monitor_count = len(self.monitor.monitors)
                self.log.debug(f"Checking {monitor_count} monitor(s)")

                for i, monitor in enumerate(self.monitor.monitors, 1):
                    monitor_name = type(monitor).__name__
                    target_info = ""
                    if hasattr(monitor, "host") and hasattr(monitor, "port"):
                        target_info = f" ({monitor.host}:{monitor.port})"

                    self.log.debug(f"[{i}/{monitor_count}] Checking {monitor_name}{target_info}...")

                    if hasattr(monitor, "_check_alive_once"):
                        result = monitor._check_alive_once(None)
                        if not result:
                            self.log.fail(f"{monitor_name} check failed{target_info}")
                            return False, f"{monitor_name} failed"
                        self.log.debug(f"{monitor_name} check passed")
                    elif hasattr(monitor, "_check_alive"):
                        result = monitor._check_alive(None)
                        if not result:
                            self.log.fail(f"{monitor_name} check failed{target_info}")
                            return False, f"{monitor_name} failed"
                        self.log.debug(f"{monitor_name} check passed")
                    else:
                        self.log.debug(f"{monitor_name} has no check method, skipping")

                return True, None

            # Single monitor: call _check_alive_once directly
            elif hasattr(self.monitor, "_check_alive_once"):
                monitor_name = type(self.monitor).__name__
                target_info = ""
                if hasattr(self.monitor, "host") and hasattr(self.monitor, "port"):
                    target_info = f" ({self.monitor.host}:{self.monitor.port})"

                self.log.debug(f"Checking {monitor_name}{target_info}...")

                if self.monitor._check_alive_once(None):
                    self.log.debug(f"{monitor_name} check passed")
                    return True, None

                self.log.fail(f"{monitor_name} check failed{target_info}")
                return False, f"{type(self.monitor).__name__} failed"

            self.log.debug("Monitor has no check method")
            return True, None

        except Exception as e:
            self.log.fail(f"Preflight check error: {e}")
            return False, str(e)

    def _monitors_to_calibrate(self) -> list:
        """Live monitors exposing a probe we can time (flattens CombinedMonitor)."""
        if not self.monitor:
            return []
        if hasattr(self.monitor, "get_active_monitors"):
            candidates = self.monitor.get_active_monitors()
        elif getattr(self.monitor, "monitors", None):
            candidates = list(self.monitor.monitors)
        else:
            candidates = [self.monitor]
        return [m for m in candidates if hasattr(m, "_check_alive_once")]

    @staticmethod
    def _select_probe_monitor(monitors: list):
        """Prefer a data-plane monitor over connect-only ones (which understate latency)."""
        connect_only = {"SocketHealthMonitor", "PingMonitor"}
        for monitor in monitors:
            if type(monitor).__name__ not in connect_only:
                return monitor
        return monitors[0] if monitors else None

    def _pre_fuzz_hook(self) -> None:
        """Called after timeout calibration, immediately before the fuzz loop.

        Base implementation pushes the calibrated timeouts onto an
        already-built data connection (a session opened during preflight --
        e.g. by a protocol baseline -- froze boofuzz's 5.0s defaults into the
        socket, defeating the lazy post-calibration build) and attaches the
        reply-expectation policy (if the subclass defines one). Subclasses
        may extend (calling super()).
        """
        self._resync_connection_timeouts()
        self._attach_reply_policy()

    def _data_connection(self):
        """The session's first target connection, or None.

        Uses the lazy ``session`` property (not the raw ``_session``
        attribute): callers run at points where nothing may have built the
        session yet (e.g. _pre_fuzz_hook on a plain non-stateful fuzzer),
        and reading the raw attribute would silently no-op policy attach /
        timeout resync -- the session built by the subsequent fuzz() would
        then run without either.
        """
        targets = getattr(self.session, "targets", None)
        target = targets[0] if targets else None
        if target is None:
            return None
        # boofuzz's Target stores the connection as _target_connection in
        # current versions; older versions exposed it as .connection.
        return getattr(target, "_target_connection", None) or getattr(target, "connection", None)

    def _resync_connection_timeouts(self) -> None:
        """Push calibrated config timeouts into the live data connection.

        Only applies when the config carries explicit values (calibration
        result or --recv-timeout override): the factory already used them
        when building connections post-calibration, so this is a no-op for
        those; the target is the pre-calibration-built connection whose
        sockopts still carry boofuzz's 5.0s defaults.
        """
        conn = self._data_connection()
        if conn is None:
            return
        recv = getattr(self.config, "recv_timeout", None)
        send = getattr(self.config, "send_timeout", None)
        if recv is not None and hasattr(conn, "_recv_timeout"):
            conn._recv_timeout = recv
        if send is not None and hasattr(conn, "_send_timeout"):
            conn._send_timeout = send
        if hasattr(conn, "resync_timeouts"):
            conn.resync_timeouts()

    # Callable(bytes) -> bool: does a request with these bytes normally get a
    # reply? None (default) keeps the classic always-wait behavior. Set by
    # protocol fuzzers whose request types are decodable from the payload
    # (e.g. MQTT packet type in byte 0).
    reply_policy = None

    # Optional cap (seconds) on the post-send recv wait even when a reply IS
    # expected. Servers that drop (rather than answer) malformed requests make
    # the full recv_timeout pure dead time; the cap bounds it. None keeps the
    # full wait. Only meaningful together with reply_policy.
    reply_wait_cap = None

    def _attach_reply_policy(self) -> None:
        """Wire self.reply_policy onto the session's data connection."""
        policy = self.reply_policy
        if policy is None:
            return
        sock = self._data_connection()
        if sock is None:
            self.log.debug("No target to attach reply policy to")
            return
        if sock is not None and hasattr(sock, "reply_expected"):
            sock.reply_expected = policy
            if self.reply_wait_cap is not None:
                sock.reply_wait_cap = self.reply_wait_cap
            self.log.debug(
                "Reply-expectation policy attached to data connection"
                + (
                    f" (recv wait capped at {self.reply_wait_cap:.3f}s)"
                    if self.reply_wait_cap
                    else ""
                )
            )
        else:
            self.log.warning(
                f"reply_policy set but data connection is {type(sock).__name__} "
                "(no reply_expected hook); no-reply fast path inactive"
            )

    def _calibrate_timeouts(self, fuzz_log) -> None:
        """Measure latency via the monitor probe and set recv/monitor timeouts from it.

        Transparent (logs what it measured and set) and override-safe: a user-set
        --recv-timeout is never touched. Falls back to defaults on too few clean probes.
        """
        if not getattr(self.config, "calibrate", True):
            fuzz_log.display("Timeout calibration disabled (--no-calibrate)")
            return

        monitors = self._monitors_to_calibrate()
        probe = self._select_probe_monitor(monitors)
        if probe is None:
            self.log.debug("No probe-capable monitor; skipping calibration")
            return

        from oida.fuzz.core.calibration import DriftDetector, RtoEstimator, TimeoutCalibrator

        stateful = bool(getattr(self, "STATEFUL", False))
        probe_name = type(probe).__name__
        n = max(1, getattr(self.config, "calibration_probes", 50))
        fuzz_log.display(f"Calibrating timeouts ({n} probes against {probe_name})...")

        result = TimeoutCalibrator(probe, probes=n, stateful=stateful).run()
        if result is None:
            fuzz_log.warning(
                f"Calibration: too few clean probes against {probe_name}; keeping defaults"
            )
            return

        s = result.stats
        fuzz_log.display(
            f"  Latency: median={s.median * 1000:.1f}ms p95={s.p95 * 1000:.1f}ms "
            f"p99={s.p99 * 1000:.1f}ms max={s.max * 1000:.1f}ms "
            f"(n={result.clean_count}/{result.probe_count} clean)"
        )

        # Data channel: only when the user did NOT hard-set --recv-timeout.
        if self.config.recv_timeout is None:
            self.config.recv_timeout = result.recv_timeout
            basis = "p99x2" if stateful else "p95x1.5"
            fuzz_log.success(f"  recv_timeout: set to {result.recv_timeout:.2f}s ({basis})")
        else:
            fuzz_log.display(
                f"  recv_timeout: kept user value {self.config.recv_timeout:.2f}s "
                "(hard-set, calibration skipped)"
            )

        # Reply-wait cap (the answer-everything baseline for post-send waits
        # on protocols whose servers drop malformed requests instead of
        # answering them): a generous multiple of the measured p99. A real
        # reply to a parseable request lands far under this; silence beyond
        # it is a dropped request, not a slow one. A protocol that sets its
        # own reply_wait_cap (e.g. MQTT's 0.15s) keeps it; users can disable
        # with --no-calibrate or override by subclassing. The cap only takes
        # effect when a reply-expectation policy is also attached (it bounds
        # reply-EXPECTED waits), so plain always-wait protocols are unchanged
        # unless they opt in via reply_policy.
        if self.reply_wait_cap is None and self.reply_policy is not None:
            derived = min(max(s.p99 * 20.0, 0.05), 2.0)
            self.reply_wait_cap = derived
            fuzz_log.display(
                f"  reply_wait_cap: set to {derived:.2f}s (p99 x20, clamped [0.05, 2])"
            )

        # Monitor channel (the crash oracle): no CLI hard-set exists, so always applied.
        for monitor in monitors:
            if hasattr(monitor, "timeout"):
                monitor.timeout = result.monitor_timeout
        fuzz_log.success(
            f"  monitor timeout: set to {result.monitor_timeout:.2f}s (max(p99x2, median+6*MAD))"
        )

        # Phase 2/3: arm online adaptation / drift detection on each monitor.
        if getattr(self.config, "adaptive_timeout", False):
            detect_drift = bool(getattr(self.config, "detect_drift", False))
            for monitor in monitors:
                if not hasattr(monitor, "timeout"):
                    continue
                monitor.rto_estimator = RtoEstimator.from_stats(s)
                monitor.drift_detector = (
                    DriftDetector(s.median, s.mad_scaled) if detect_drift else None
                )
            modes = "adaptive monitor timeout" + (" + drift detection" if detect_drift else "")
            fuzz_log.display(f"  online: {modes} enabled")

    def fuzz_all(self) -> None:
        """Fuzz entire protocol"""
        # Pre-flight connectivity check
        ok, err = self._preflight_check()
        if not ok:
            raise ConnectionError(f"Target unreachable ({err})")

        # Log successful preflight check
        fuzz_log = self._get_fuzz_logger()
        fuzz_log.success("Preflight check passed")

        # Measure response latency and set timeouts from it (before the data socket is
        # built lazily on first self.session access below). Honors user-set timeouts.
        self._calibrate_timeouts(fuzz_log)

        # Apply multi-machine distribution filtering if configured
        if self.config.distribution_total and self.config.distribution_id:
            self._apply_distribution_filtering()

        # Start progress monitor if logging is enabled
        progress_thread = None
        if self.config.log_session:
            progress_thread = self._start_progress_monitor()

        try:
            # Hook for subclasses to touch self.session AFTER calibration but
            # before the fuzz loop, so the lazily-built data socket captures the
            # calibrated recv_timeout (not the pre-calibration default).
            self._pre_fuzz_hook()
            only_d = getattr(self.config, "only_depth", None)
            max_d = getattr(self.config, "max_depth", None)
            if only_d is not None:
                self._fuzz_only_depth(only_d)
            elif max_d is not None:
                # Public boofuzz cap: fuzz depths 1..N then stop.
                self.session.fuzz(max_depth=max_d)
            else:
                self.session.fuzz()
        finally:
            # Stop progress monitor
            if progress_thread:
                self._stop_progress_monitor(progress_thread)

            # Save session progress to database (for resume)
            if self._test_case_manager:
                # Reconcile the manager's de-bounced episode count with the monitor's
                # view. This is only a FLOOR, never a sum: the manager already counts
                # one crash EVENT per distinct outage episode (de-bounced, commit
                # 9299535). The monitor's signal is binary evidence ("did the target go
                # down at all?"), so we bump the count to at least 1 if the monitor saw
                # a crash the manager somehow missed (e.g. a crash detected right at
                # session end). It must NOT be seeded from CombinedMonitor.total_failures
                # -- that increments once per failed CHECK for the whole duration of an
                # outage, so a single episode lasting N monitor intervals would inflate
                # the count to N and undo the de-bounce at the reporting layer.
                if self.monitor:
                    self._reconcile_crash_count(self._test_case_manager, self.monitor)
                self._test_case_manager.save_session_progress(final=True)

            # Log distribution statistics if enabled
            if self.config.distribution_total and hasattr(self, "distribution_stats"):
                self._log_distribution_stats()

            # Warn if no sends happened - likely connection failures
            if self._test_case_manager:
                progress = self._test_case_manager.get_progress()
                actual_sends = progress.get("actual_sends", 0)
                if actual_sends == 0:
                    fuzz_log = self._get_fuzz_logger()
                    fuzz_log.warning("No data sent - TCP connection may have failed")
                    fuzz_log.warning(
                        "Check target is reachable and listening on the specified port"
                    )

    @classmethod
    def _reconcile_crash_count(cls, manager, monitor) -> None:
        """Floor the manager's de-bounced crash count with the monitor's binary view.

        A FLOOR, never a sum: ``manager._crash_count`` already counts one crash EVENT
        per distinct outage episode (de-bounced, commit 9299535). If the monitor saw a
        crash the manager somehow missed (e.g. detected right at session end), bump the
        count to at least 1. Never seed from ``CombinedMonitor.total_failures`` -- that
        counts failed CHECKS, so a single episode spanning N intervals would inflate the
        count to N and undo the de-bounce at the reporting layer.
        """
        if cls._monitor_observed_crash(monitor):
            manager._crash_count = max(manager._crash_count, 1)

    @staticmethod
    def _monitor_observed_crash(monitor) -> bool:
        """Binary: did the monitor see the target crash at least once this run?

        Deliberately NOT a count. A ``CombinedMonitor`` exposes ``total_failures``
        (incremented once per failed check, i.e. once per ``check_interval`` for the
        whole span of a single outage) and per-child ``crashed`` flags. Any of those
        being set is evidence of >=1 crash; how many EPISODES occurred is the
        manager's de-bounced ``_crash_count``, which this only floors, never replaces.
        """
        if getattr(monitor, "crashed", False):
            return True
        if getattr(monitor, "total_failures", 0):
            return True
        if getattr(monitor, "consecutive_failures", 0):
            return True
        for child in getattr(monitor, "monitors", None) or []:
            if getattr(child, "crashed", False) or getattr(child, "total_failures", 0):
                return True
        return False

    def _fuzz_only_depth(self, depth: int) -> None:
        """Fuzz ONLY combinatorial depth ``depth``, skipping all lower depths.

        boofuzz's public ``fuzz()`` always walks depth 1, then 2, then 3, ... in
        order, so reaching depth N normally means grinding through (and, on a
        big ``index_start``, generating-then-discarding) the whole lower-depth
        prefix — which scales ~O(depth1**2) and can cost minutes to hours for a
        real protocol. Driving ``_generate_n_mutations(depth=N)`` directly yields
        only depth-N cases, so the first packet goes out immediately with no seek.

        This composes with the rest of the loop: distribution filtering wraps
        ``_fuzz_current_case`` (downstream), and ``index_start`` / ``index_end``
        are still honored by ``_main_fuzz_loop`` — reinterpreted as a position
        *within* the chosen depth.
        """
        session = self.session
        if not (hasattr(session, "_main_fuzz_loop") and hasattr(session, "_generate_n_mutations")):
            raise RuntimeError(
                "--only-depth needs a boofuzz build exposing _generate_n_mutations / "
                "_main_fuzz_loop; upgrade boofuzz or drop the flag"
            )

        # Replicate fuzz()'s preconditions (total_mutant_index / total_num_mutations).
        # A finite total exists only for depth 1 (num_mutations returns None above it).
        session.total_mutant_index = 0
        session.total_num_mutations = session.num_mutations(max_depth=1) if depth == 1 else None

        self.log.display(f"Fuzzing only depth {depth} (skipping lower depths)")
        session._main_fuzz_loop(session._generate_n_mutations(depth=depth, path=None))

    def _apply_distribution_filtering(self) -> None:
        """
        Apply modulo-based filtering for multi-machine distribution.

        Wraps the session's _fuzz_current_case method to skip test cases
        that don't belong to this machine based on modulo arithmetic:
        - Machine receives cases where (case_index % total) == (id - 1)

        Example:
            Machine 2 of 3 (target_modulo = machine_id - 1 = 1), 1-based case
            indices: tests cases 1, 4, 7, 10, 13, ... (case_index % 3 == 1).
        """
        total = self.config.distribution_total
        machine_id = self.config.distribution_id
        target_modulo = machine_id - 1  # Convert to 0-indexed

        # Store original method
        original_fuzz_case = self.session._fuzz_current_case

        # Track statistics
        self.distribution_stats = {
            "total_cases": 0,
            "tested_cases": 0,
            "skipped_cases": 0,
        }

        def filtered_fuzz_case(test_case_context):
            """Wrapper that applies modulo filtering"""
            self.distribution_stats["total_cases"] += 1
            case_index = self.session.total_mutant_index

            # Check if this case belongs to this machine
            if case_index % total == target_modulo:
                self.distribution_stats["tested_cases"] += 1
                return original_fuzz_case(test_case_context)
            else:
                # Skip this case
                self.distribution_stats["skipped_cases"] += 1
                return

        # Replace the method
        self.session._fuzz_current_case = filtered_fuzz_case

        self.log.display(
            f"Distribution: Machine {machine_id}/{total} "
            f"(testing cases where index % {total} == {target_modulo})"
        )

    def _log_distribution_stats(self) -> None:
        """Log distribution statistics at the end of fuzzing"""
        stats = self.distribution_stats
        total = self.config.distribution_total
        machine_id = self.config.distribution_id

        self.log.highlight("Multi-Machine Distribution Statistics")
        self.log.display(f"Machine: {machine_id} of {total}")
        self.log.display(f"Total cases processed: {stats['total_cases']}")
        self.log.display(f"Cases tested by this machine: {stats['tested_cases']}")
        self.log.display(f"Cases skipped (for other machines): {stats['skipped_cases']}")

        if stats["total_cases"] > 0:
            tested_pct = (stats["tested_cases"] / stats["total_cases"]) * 100
            expected_pct = (1 / total) * 100
            self.log.display(
                f"Tested percentage: {tested_pct:.2f}% (expected: {expected_pct:.2f}%)"
            )

    def _start_progress_monitor(self):
        """Start background thread for progress updates.

        Reads progress from rolling buffer (in-memory) when available,
        falls back to database queries for legacy sessions.
        Progress is printed directly to stdout (not via logging) to ensure visibility.
        """

        def progress_worker():
            start_time = time.time()
            last_case = 0
            last_time = start_time

            # Signal that progress line is active (for log line coordination)
            set_progress_active(True)

            try:
                while not self._progress_stop_flag:
                    time.sleep(self._progress_interval)

                    if self._progress_stop_flag:
                        break

                    # Skip progress during recovery (don't clutter recovery output)
                    if self.monitor:
                        # Check CombinedMonitor's children
                        if any(m.crashed for m in self.monitor.monitors):
                            continue

                    try:
                        current_case = 0
                        crash_count = 0

                        # Get progress from rolling buffer (fast, no DB access)
                        if not self._test_case_manager:
                            continue

                        progress = self._test_case_manager.get_progress()
                        current_case = progress["current_case"]
                        actual_sends = progress["actual_sends"]
                        crash_count = progress["crash_count"]

                        # Calculate elapsed time
                        elapsed = time.time() - start_time
                        hours = int(elapsed // 3600)
                        minutes = int((elapsed % 3600) // 60)
                        seconds = int(elapsed % 60)
                        elapsed_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

                        # Calculate rate (tests per second)
                        now = time.time()
                        interval = now - last_time
                        cases_done = current_case - last_case
                        rate = cases_done / interval if interval > 0 else 0
                        last_case = current_case
                        last_time = now

                        # Check for crashes from multiple sources:
                        # 1. Database crash_count (boofuzz's internal crash detection via callbacks)
                        # 2. Monitor's crashed attribute (protocol-level health check failures)
                        # 3. CombinedMonitor's total_failures
                        any_crashed = False
                        crash_info = None
                        crash_source = None

                        # Source 1: Database crash count (boofuzz-detected crashes from callbacks)
                        # This catches connection failures, timeouts, etc. detected by boofuzz
                        if crash_count > 0:
                            any_crashed = True
                            crash_source = "boofuzz"

                        if self.monitor:
                            # Source 2: CombinedMonitor's total_failures
                            monitor_failures = getattr(self.monitor, "total_failures", 0)
                            if monitor_failures > 0:
                                any_crashed = True
                                if not crash_source:
                                    crash_source = "monitor"

                            # Source 3: Check child monitors for crashed state (ProtocolMonitor pattern)
                            if hasattr(self.monitor, "monitors") and self.monitor.monitors:
                                for child in self.monitor.monitors:
                                    child_crashed = getattr(child, "crashed", False)

                                    if child_crashed:
                                        any_crashed = True
                                        crash_info = getattr(child, "crash_info", None)
                                        if not crash_source:
                                            crash_source = type(child).__name__
                                        break

                            # Proactive crash detection: if rate is 0, check the monitor directly
                            # This catches cases where boofuzz is stuck and not completing test cases
                            if rate == 0 and not any_crashed:
                                try:
                                    if hasattr(self.monitor, "_check_monitors"):
                                        check_result = self.monitor._check_monitors(
                                            None, None, None, "progress-check"
                                        )
                                        if not check_result:
                                            any_crashed = True
                                            crash_source = "proactive-check"
                                except Exception as e:
                                    logger.debug(
                                        f"if hasattr(self.monitor, _check_monit...: {e}"
                                    )  # Ignore proactive check failures

                        # Format crash indicator (show CRASHED with count if any crashes detected)
                        if any_crashed:
                            crash_str = f"\033[91mCRASHED ({crash_count})\033[0m"

                            # Handle pause_on_crash option
                            if self.config.pause_on_crash and not getattr(
                                self, "_crash_paused", False
                            ):
                                self._crash_paused = True
                                print()  # New line before pause message
                                print("\033[91m" + "=" * 60 + "\033[0m")
                                print("\033[91mCRASH DETECTED - Fuzzing paused\033[0m")
                                if crash_info:
                                    print(f"  Timestamp: {crash_info.get('timestamp', 'unknown')}")
                                    print(f"  Test case: {crash_info.get('test_case', 'unknown')}")
                                    print(f"  Target: {crash_info.get('target', 'unknown')}")
                                print("\033[91m" + "=" * 60 + "\033[0m")
                                print("Press Enter to continue fuzzing, or Ctrl+C to exit...")
                                try:
                                    import sys

                                    sys.stdin.readline()
                                    self._crash_paused = False  # Reset for next crash
                                except (EOFError, KeyboardInterrupt):
                                    self._progress_stop_flag = True
                                    break
                        else:
                            crash_str = f"{crash_count}"

                        # Get current fuzz target info from boofuzz session
                        # current_test_case_name format varies: "Request:[Request.Field:N]" or "Request.Field"
                        fuzz_target = ""
                        if self._session:
                            # Use current_test_case_name (boofuzz's actual attribute)
                            if (
                                hasattr(self._session, "current_test_case_name")
                                and self._session.current_test_case_name
                            ):
                                fuzz_target = self._session.current_test_case_name
                                # Clean up boofuzz format: "Request:[Request.Field:N]" -> "Request.Field:N"
                                if ":[" in fuzz_target and fuzz_target.endswith("]"):
                                    # Extract content between [ and ]
                                    fuzz_target = fuzz_target.split(":[")[1].rstrip("]")
                            elif hasattr(self._session, "fuzz_node") and self._session.fuzz_node:
                                fuzz_target = self._session.fuzz_node.name or ""

                        # Get monitor check count (actual checks, not test cases)
                        monitor_checks = (
                            getattr(self.monitor, "actual_check_count", 0) if self.monitor else 0
                        )

                        # boofuzz position = resume_base + sent + skipped.
                        #   sent        = cases transmitted this run (num_cases_actually_fuzzed)
                        #   total       = boofuzz mutation-space position (matches its UI "Total")
                        #   resume_base = cases already fuzzed in earlier sessions (resume offset)
                        #   skipped     = within-run jumps (crash-threshold fast-forward)
                        sent = actual_sends
                        total = actual_sends
                        resume_base = max(0, getattr(self.config, "index_start", 1) - 1)
                        if self._session is not None:
                            sent = getattr(self._session, "num_cases_actually_fuzzed", actual_sends)
                            total = getattr(self._session, "total_mutant_index", sent)
                        skipped = max(0, total - sent - resume_base)

                        # Calculate actual send rate (real network activity)
                        send_rate = sent / elapsed if elapsed > 0 else 0

                        # Print progress directly to stdout (always visible).
                        # Show the resume offset only when actually resuming, so a fresh run
                        # stays terse and a resumed run explains its large Total.
                        resume_str = f" | Resumed: {resume_base:,}" if resume_base else ""
                        target_str = f" | \033[93m{fuzz_target}\033[0m" if fuzz_target else ""
                        print(
                            f"\r\033[K[\033[94m*\033[0m] Progress: {elapsed_str} | "
                            f"Sent: {sent:,} ({send_rate:.0f}/s) | "
                            f"Skipped: {skipped:,}{resume_str} | Total: {total:,} | "
                            f"Crashes: {crash_str} | "
                            f"Checks: {monitor_checks}{target_str}",
                            end="",
                            flush=True,
                        )

                    except Exception as e:
                        logger.debug(f"Operation failed: {e}")  # Ignore progress monitor errors

            finally:
                # Signal that progress line is no longer active
                set_progress_active(False)
                # Print newline to move past progress line
                print()

        thread = threading.Thread(target=progress_worker, daemon=True)
        thread.start()
        return thread

    def _stop_progress_monitor(self, thread):
        """Stop progress monitoring thread"""
        self._progress_stop_flag = True
        if thread:
            thread.join(timeout=1)
