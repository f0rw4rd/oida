"""External-script health-check monitor.

Borrowed from Defensics' external/agent instrumentation: instead of inferring
target health only from the network connection, run an arbitrary user command
between test cases and treat its exit code as the verdict (exit 0 == healthy).

This unlocks health signals the fuzzer otherwise cannot see over the wire:
  - watch an AddressSanitizer log for leak/overflow reports,
  - grep the target's syslog for error strings,
  - poll an out-of-band management API, a GPIO line, or `docker inspect` health,
  - run any project-specific liveness check.

Example::

    oida fuzz modbus 10.0.0.5 \\
        --script-monitor "ssh plc 'pidof runtime >/dev/null'"
"""

import shlex
from typing import List, Optional, Union

from .base import ProtocolMonitor
from ..core.session.commands import CommandRunner, RealCommandRunner


class ScriptMonitor(ProtocolMonitor):
    """Health monitor that shells out to an external command.

    The target is considered healthy iff the command exits with
    ``expect_returncode`` (default 0). Any exception while launching the command
    counts as unhealthy. Inherits retry / failure-threshold / crash-recovery
    behaviour from :class:`ProtocolMonitor`.

    Args:
        host: Target host (used only for logging / restart context).
        command: Command to run, as an argv list or a shell-style string
                 (split with :func:`shlex.split`; it is NOT run through a shell).
        port: Optional target port (informational; default 0).
        check_interval: Run the command every N test cases (default 10).
        timeout: Per-invocation timeout in seconds (default 5.0).
        expect_returncode: Exit code that means "healthy" (default 0).
        command_runner: Injectable command runner (default RealCommandRunner).
    """

    def __init__(
        self,
        host: str,
        command: Union[str, List[str]],
        port: int = 0,
        check_interval: int = 10,
        timeout: float = 5.0,
        expect_returncode: int = 0,
        command_runner: Optional[CommandRunner] = None,
        retry_count: int = 2,
        failure_threshold: int = 2,
        **kwargs,
    ):
        if isinstance(command, str):
            command = shlex.split(command)
        if not command:
            raise ValueError("ScriptMonitor requires a non-empty command")

        super().__init__(
            host=host,
            port=port,
            timeout=timeout,
            check_interval=check_interval,
            retry_count=retry_count,
            failure_threshold=failure_threshold,
            **kwargs,
        )
        self.command = list(command)
        self.expect_returncode = expect_returncode
        # ScriptMonitor's own command_runner is used both for the health check and
        # (inherited) for any restart command, so honour an injected one.
        if command_runner is not None:
            self.command_runner = command_runner
        elif self.command_runner is None:
            self.command_runner = RealCommandRunner()

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        try:
            self.logger.debug(f"Running health command: {' '.join(self.command)}")
            result = self.command_runner.run(
                self.command, capture_output=True, timeout=self.timeout
            )
            rc = getattr(result, "returncode", None)
            if rc == self.expect_returncode:
                return True
            self.logger.warning(f"Health command exit {rc} (expected {self.expect_returncode})")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(
                    f"ScriptMonitor: command exit {rc} != {self.expect_returncode}"
                )
            return False
        except Exception as e:
            self.logger.warning(f"Health command error: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"ScriptMonitor: command error - {e}")
            return False


__all__ = ["ScriptMonitor"]
