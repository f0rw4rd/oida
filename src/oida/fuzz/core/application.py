import traceback
from typing import Optional, Callable
from .config import FuzzerConfig
from .base_fuzzer import BaseFuzzer
from ...utils.ics_logger import get_logger

# Module-level logger for application startup/shutdown
_log = get_logger("FUZZ", "app", 0)


class FuzzerApplication:
    """Testable application class that encapsulates main function logic"""

    def __init__(
        self,
        fuzzer_factory: Optional[Callable] = None,
    ):
        from .session.manager import (
            TestCaseManager,
            create_fuzzer,
        )  # Import here to avoid circular imports

        self.fuzzer_factory = fuzzer_factory or create_fuzzer
        self.TestCaseManager = TestCaseManager

    @staticmethod
    def _split_command(value):
        """Split a CLI command string into argv (shell-style, not run via a shell)."""
        if not value:
            return None
        import shlex

        return shlex.split(value)

    @staticmethod
    def _split_hostport(value, default_port):
        """Split ``HOST:PORT`` (port optional) for --agent-monitor. Returns
        ``(host, port)`` or ``(None, default_port)`` when value is empty."""
        if not value:
            return None, default_port
        if ":" in value:
            host, _, port = value.rpartition(":")
            try:
                return host, int(port)
            except ValueError:
                raise ValueError(f"Invalid port in --agent-monitor: {value!r}")
        return value, default_port

    @staticmethod
    def _parse_hex(value, label):
        """Parse a hex string (spaces tolerated) into bytes, with a clear error."""
        if not value:
            return None
        try:
            return bytes.fromhex(value.replace(" ", ""))
        except ValueError as e:
            raise ValueError(f"Invalid hex for {label}: {value!r} ({e})")

    def run_command(self, args) -> int:
        """Execute the fuzzer command with given arguments"""
        try:
            agent_monitor_host, agent_monitor_port = self._split_hostport(
                getattr(args, "agent_monitor", None), 5555
            )
            config = FuzzerConfig(
                target_ip=args.ip,
                target_port=args.port,
                protocol=args.protocol,  # Track protocol name for test case attribution
                session_filename=args.session,
                log_session=not args.nolog,
                skip_pre_send_checks=args.skip_pre_send,
                monitor_check_interval=args.check_interval,
                protocol_options=getattr(args, "protocol_options", {}),
                console_output=getattr(args, "console_output", False),
                web_interface=getattr(args, "web_interface", True),
                web_port=getattr(args, "web_port", 26000),
                seed=getattr(args, "seed", None),
                store_all_payloads=getattr(args, "store_all_payloads", False),
                boofuzz_db=getattr(args, "boofuzz_db", False),
                fuzz_db_keep_pass_cases=getattr(args, "fuzz_db_keep_pass_cases", 500),
                distribution_total=getattr(args, "distribution_total", None),
                distribution_id=getattr(args, "distribution_id", None),
                enabled_requests=getattr(args, "enabled_requests", None),
                disabled_requests=getattr(args, "disabled_requests", None),
                index_start=getattr(args, "index_start", 1),  # Resume from this test case
                index_end=getattr(args, "index_end", None),
                max_depth=getattr(args, "max_depth", None),
                only_depth=getattr(args, "only_depth", None),
                monitor_config=getattr(args, "monitor_config", None),
                monitor_logic=getattr(args, "monitor_logic", "and"),
                reuse_target_connection=getattr(args, "reuse_connection", False),
                receive_data_after_fuzz=getattr(args, "receive_data_after_fuzz", True),
                receive_data_after_each_request=getattr(
                    args, "receive_data_after_each_request", True
                ),
                sleep_time=getattr(args, "sleep_time", 0.0),
                # Socket timeouts / reconnection (None = connection/protocol default)
                recv_timeout=getattr(args, "recv_timeout", None),
                send_timeout=getattr(args, "send_timeout", None),
                reconnect_delay=getattr(args, "reconnect_delay", None),
                max_reconnect_attempts=getattr(args, "max_reconnect_attempts", None),
                # TLS configuration
                tls_enabled=getattr(args, "tls_enabled", False),
                # Capability enumeration
                enumerate=getattr(args, "enumerate", True),
                # Crash handling
                pause_on_crash=getattr(args, "pause_on_crash", False),
                # Timeout calibration
                calibrate=getattr(args, "calibrate", True),
                calibration_probes=getattr(args, "calibration_probes", 50),
                adaptive_timeout=getattr(args, "adaptive_timeout", False),
                detect_drift=getattr(args, "detect_drift", False),
                # Platform-feature monitors + auto-restart
                script_monitor_command=self._split_command(getattr(args, "script_monitor", None)),
                valid_case_probe=self._parse_hex(getattr(args, "valid_case", None), "--valid-case"),
                valid_case_expect=self._parse_hex(
                    getattr(args, "valid_case_expect", None), "--valid-case-expect"
                ),
                restart_command=self._split_command(getattr(args, "restart_command", None)),
                restart_delay=getattr(args, "restart_delay", 2.0),
                agent_monitor_host=agent_monitor_host,
                agent_monitor_port=agent_monitor_port,
                agent_monitor_token=getattr(args, "agent_token", None),
            )

            # Depth controls must be >= 1 (depth 1 = single fields).
            for name, val in (
                ("--max-depth", config.max_depth),
                ("--only-depth", config.only_depth),
            ):
                if val is not None and val < 1:
                    _log.fail(f"{name} must be >= 1 (got {val})")
                    return 2

            # Note: BaseFuzzer now handles TestCaseManager creation and callback registration
            # automatically when config.log_session is True
            fuzzer = self.fuzzer_factory(args.protocol, config)

            return self._execute_command(args, fuzzer)

        except KeyboardInterrupt:
            # Progress is saved in fuzz_all()'s finally block before this is reached
            _log.display("Fuzzing session terminated by user")
            return 0  # Clean exit on Ctrl+C
        except ConnectionError:
            # Re-raise for fuzz_cli to handle with proper formatting
            raise
        except Exception as e:
            # Check if this is a BoofuzzFailure (expected when target crashes)
            from boofuzz.exception import BoofuzzFailure

            if isinstance(e, BoofuzzFailure):
                # Clean exit - crash was already logged by monitor
                _log.display("Fuzzing stopped: target unresponsive")
                return 0
            _log.fail(f"Error: {e}")
            traceback.print_exc()
            return 1

    def _execute_command(self, args, fuzzer: BaseFuzzer) -> int:
        """Execute the specific command requested"""
        from .database.orm import SQLAlchemyDatabase

        if args.command == "list":
            # List doesn't need a fuzzer session, just read from DB
            db_path = f"{fuzzer.config.session_filename}.db"
            database = SQLAlchemyDatabase(db_path)
            database.init_schema()
            manager = self.TestCaseManager(
                fuzzer, database, store_all_payloads=False, read_only=True
            )
            manager.list_test_cases()

        elif args.command == "detail":
            # Detail doesn't need a fuzzer session, just read from DB
            db_path = f"{fuzzer.config.session_filename}.db"
            database = SQLAlchemyDatabase(db_path)
            database.init_schema()
            manager = self.TestCaseManager(
                fuzzer, database, store_all_payloads=False, read_only=True
            )
            manager.get_test_case_details(args.case_id)

        elif args.command == "replay":
            # Replay needs the fuzzer for payload regeneration
            db_path = f"{fuzzer.config.session_filename}.db"
            database = SQLAlchemyDatabase(db_path)
            database.init_schema()
            manager = self.TestCaseManager(
                fuzzer, database, store_all_payloads=False, read_only=True
            )
            check_response = getattr(args, "check_response", False)
            manager.replay_test_cases(args.range, args.detail, check_response)

        elif args.command == "fuzz":
            monitor_names = (
                [type(m).__name__ for m in fuzzer.monitor.monitors]
                if fuzzer.monitor.monitors
                else []
            )
            logic = getattr(fuzzer.monitor, "logic", "and").upper()
            fuzzer.log.display(f"Active monitors: {monitor_names} (logic={logic})")

            # TestCaseManager callbacks are registered automatically by BaseFuzzer
            # when the session property is first accessed

            # Show start message (after enumeration during fuzzer creation)
            fuzzer.log.highlight("Starting fuzzer... (Ctrl+C to stop)")

            if args.node:
                fuzzer.log.display(f"Fuzzing specific node: {args.node}")
                fuzzer.fuzz_node(args.node)
            else:
                fuzzer.fuzz_all()

        return 0
