"""
CLI Runner helper for OIDA integration tests

Provides subprocess execution of oida CLI commands with result parsing.
Supports optional structured JSON log capture via --json-log.
"""

import os
import signal
import subprocess
import sys
import tempfile
import time
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# Subprocess budget for one CLI invocation. 30s was enough for the scan work
# itself (1-2s serially) but not for interpreter startup + imports under the
# -n 8 integration lane: under CPU contention 8 workers routinely pushed past
# 30s and produced "Command timed out after 30s" on a different protocol's
# test each run. 45s is the pytest budget's ceiling minus a 15s reporting
# margin (timeout = 60, timeout_func_only = true) - a subprocess can never
# outlive the test that started it.
DEFAULT_CLI_TIMEOUT = 45


@dataclass
class CLIResult:
    """Result from CLI command execution"""

    returncode: int
    stdout: str
    stderr: str
    json_output: Optional[Dict[str, Any]] = None
    execution_time: float = 0.0
    command: List[str] = field(default_factory=list)
    scan_log: Optional[Any] = None  # ScanLog instance when json_log=True

    @property
    def success(self) -> bool:
        return self.returncode == 0

    @property
    def combined_output(self) -> str:
        return f"{self.stdout}\n{self.stderr}"

    def __repr__(self) -> str:
        log_info = f", scan_log={len(self.scan_log)} events" if self.scan_log else ""
        return (
            f"CLIResult(returncode={self.returncode}, "
            f"success={self.success}, "
            f"time={self.execution_time:.2f}s{log_info})"
        )


class CLIRunner:
    """Helper class for running oida CLI commands"""

    def __init__(self, timeout: int = DEFAULT_CLI_TIMEOUT):
        self.default_timeout = timeout
        self.python_executable = sys.executable

    # Global arguments that must come before protocol
    GLOBAL_ARGS = {
        "format",
        "output",
        "timeout",
        "threads",
        "verbose",
        "debug",
        "quiet",
        "json-log",
        "full-width",
    }

    def run(
        self,
        protocol: str,
        target: str,
        *args: str,
        timeout: Optional[int] = None,
        expect_json: bool = True,
        json_log: bool = False,
        use_sudo: bool = False,
        **kwargs: Any,
    ) -> CLIResult:
        """
        Run oida CLI command

        Args:
            protocol: Protocol name (modbus, opcua, etc.)
            target: Target host/address
            *args: Additional CLI arguments
            timeout: Command timeout in seconds
            expect_json: If True, attempt to parse JSON from output
            json_log: If True, capture structured JSON log via --json-log
            use_sudo: If True, prefix command with sudo (for raw socket protocols)
            **kwargs: Named arguments converted to --key value

        Returns:
            CLIResult with stdout, stderr, parsed JSON, and optional scan_log
        """
        # Create temp file for JSON log if requested
        json_log_path = None
        json_log_fd = None
        if json_log:
            json_log_fd, json_log_path = tempfile.mkstemp(suffix=".jsonl", prefix="oida_log_")
            os.close(json_log_fd)
            kwargs["json_log"] = json_log_path

        # Separate global args from protocol-specific args
        global_args = []
        protocol_args = []

        for key, value in kwargs.items():
            key_clean = key.replace("_", "-")
            key_formatted = f"--{key_clean}"
            if key_clean in self.GLOBAL_ARGS or key in self.GLOBAL_ARGS:
                if isinstance(value, bool):
                    if value:
                        global_args.append(key_formatted)
                elif value is not None:
                    global_args.extend([key_formatted, str(value)])
            else:
                if isinstance(value, bool):
                    if value:
                        protocol_args.append(key_formatted)
                elif value is not None:
                    protocol_args.extend([key_formatted, str(value)])

        # Build command: [sudo] python -m oida.cli [global_args] protocol target [protocol_args]
        cmd = []
        if use_sudo:
            cmd.append("sudo")
        cmd.extend(
            [
                self.python_executable,
                "-m",
                "oida.cli",
            ]
        )
        cmd.extend(global_args)
        cmd.append(protocol)
        cmd.append(target)
        cmd.extend(args)
        cmd.extend(protocol_args)

        # Execute command
        start_time = time.time()
        scan_log = None
        effective_timeout = timeout or self.default_timeout
        proc = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,  # own process group so we can kill the whole tree
            )
            try:
                stdout, stderr = proc.communicate(timeout=effective_timeout)
            except subprocess.TimeoutExpired:
                # Kill the entire process group (handles grandchildren / asyncio fds)
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    proc.kill()
                try:
                    stdout, stderr = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout, stderr = "", ""
                execution_time = time.time() - start_time
                if json_log_path and os.path.exists(json_log_path):
                    try:
                        from tests.integration.json_log_reader import ScanLog

                        scan_log = ScanLog(json_log_path)
                    except Exception:
                        pass
                return CLIResult(
                    returncode=-1,
                    stdout=stdout or "",
                    stderr=f"Command timed out after {effective_timeout}s",
                    execution_time=execution_time,
                    command=cmd,
                    scan_log=scan_log,
                )

            result_returncode = proc.returncode
            execution_time = time.time() - start_time

            # Parse JSON if requested
            json_output = None
            if expect_json:
                json_output = self._try_parse_json(stdout)

            # Parse structured JSON log if captured
            if json_log_path and os.path.exists(json_log_path):
                try:
                    from tests.integration.json_log_reader import ScanLog

                    scan_log = ScanLog(json_log_path)
                except Exception:
                    pass  # Don't fail if log parsing fails

            return CLIResult(
                returncode=result_returncode,
                stdout=stdout,
                stderr=stderr,
                json_output=json_output,
                execution_time=execution_time,
                command=cmd,
                scan_log=scan_log,
            )

        except subprocess.TimeoutExpired:
            # Fallback - should not reach here with Popen-based flow above
            if json_log_path and os.path.exists(json_log_path):
                try:
                    from tests.integration.json_log_reader import ScanLog

                    scan_log = ScanLog(json_log_path)
                except Exception:
                    pass

            return CLIResult(
                returncode=-1,
                stdout="",
                stderr=f"Command timed out after {effective_timeout}s",
                execution_time=effective_timeout,
                command=cmd,
                scan_log=scan_log,
            )

        finally:
            # Kill leftover process if pytest-timeout or another exception interrupted us
            if proc is not None and proc.poll() is None:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    proc.kill()
                try:
                    proc.communicate(timeout=3)
                except Exception:
                    pass
            # Clean up temp file
            if json_log_path:
                try:
                    os.unlink(json_log_path)
                except OSError:
                    pass

    def assert_confirm_refused(self, result: CLIResult, *flags: str) -> None:
        """Assert the --confirm preflight refused this run before connecting.

        The CLI's _confirm_preflight (issue #51) exits 1 with the refusal on
        stderr before any connection opens, so the contract to assert is:
        rc == 1, the refusal line naming the flags, and -- when a json log was
        requested -- zero events (nothing ran, nothing touched the target).
        """
        assert result.returncode == 1, (
            f"Expected rc=1 (pre-connect refusal), got {result.returncode}: "
            f"{result.combined_output[:400]}"
        )
        output = result.combined_output.lower()
        assert "requires --confirm" in output, (
            f"Expected 'requires --confirm' refusal, got: {result.combined_output[:400]}"
        )
        assert "no traffic was sent to the target" in output, (
            f"Expected 'No traffic was sent' in refusal, got: {result.combined_output[:400]}"
        )
        assert "traceback" not in output, result.combined_output[:400]
        if flags:
            for flag in flags:
                assert flag.lower() in output, (
                    f"Expected {flag} in refusal, got: {result.combined_output[:400]}"
                )
        if result.scan_log is not None:
            assert len(result.scan_log) == 0, (
                f"Preflight refusal must not log scan events, got "
                f"{len(result.scan_log)}: {result.scan_log.events[:3]}"
            )

    def run_help(self, protocol: Optional[str] = None) -> CLIResult:
        """Run help command for main CLI or specific protocol"""
        if protocol:
            return self.run(protocol, "--help", expect_json=False)
        else:
            cmd = [self.python_executable, "-m", "oida.cli", "--help"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return CLIResult(
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                command=cmd,
            )

    def _try_parse_json(self, output: str) -> Optional[Dict[str, Any]]:
        """Attempt to parse JSON from output"""
        if not output:
            return None

        # Try parsing the whole output
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            pass

        # Try to find JSON object in output (may have prefix text)
        for start_char, end_char in [("{", "}"), ("[", "]")]:
            start = output.find(start_char)
            if start != -1:
                # Find matching end
                depth = 0
                for i, char in enumerate(output[start:], start):
                    if char == start_char:
                        depth += 1
                    elif char == end_char:
                        depth -= 1
                        if depth == 0:
                            try:
                                return json.loads(output[start : i + 1])
                            except json.JSONDecodeError:
                                break

        return None
