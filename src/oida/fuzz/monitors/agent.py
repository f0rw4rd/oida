"""Client monitor for the on-target ``oida-fuzzing-agent`` (separate repo:
github.com/f0rw4rd/oida-fuzzing-agent).

Where the other monitors probe the target directly over the wire, this one talks
to a small C agent running *on the target host* that owns the target process. The
agent sees the real exit signal/code, distinguishes a crash from a clean exit,
detects hangs, correlates a crash to the current test case, and restarts the
target — none of which a black-box network probe can do.

Protocol (newline-delimited text; see the oida-fuzzing-agent repo README):
    HELLO 1 <token>   -> OK version=1 instance=<n> state=<state>
    STATUS            -> OK state=up|down|crash|hung pid=.. test=.. signal=..
    CRASH             -> OK kind=.. signal=.. test=.. dump=.. stderr_tail=..

`_check_alive_once` returns True only when the agent reports ``state=up``. On a
crash/hang it reads ``CRASH`` (which also acknowledges the agent's latch), logs
the correlated detail, and returns False so the framework records the failure and
drives recovery; the agent's own auto-restart then brings the target back.
"""

import socket
from typing import Dict, Optional

from .base import ProtocolMonitor

AGENT_PROTOCOL_VERSION = 1


class AgentMonitor(ProtocolMonitor):
    """Health monitor that queries an on-target oida-fuzzing-agent over TCP.

    Args:
        host: Host where the oida-fuzzing-agent listens (the target host).
        port: oida-fuzzing-agent control port (default 5555).
        token: Shared secret for the agent handshake (None if the agent has none).
        timeout: Socket timeout in seconds.
        check_interval: Query every N test cases.
    """

    def __init__(
        self,
        host: str,
        port: int = 5555,
        token: Optional[str] = None,
        timeout: float = 3.0,
        check_interval: int = 10,
        retry_count: int = 2,
        failure_threshold: int = 2,
        **kwargs,
    ):
        super().__init__(
            host=host,
            port=int(port),
            timeout=float(timeout),
            check_interval=check_interval,
            retry_count=retry_count,
            failure_threshold=failure_threshold,
            **kwargs,
        )
        self.token = token

    @staticmethod
    def _parse_kv(line: str) -> Dict[str, str]:
        """Parse an ``OK k=v k=v`` agent response into a dict (verb under ``_verb``)."""
        parts = line.strip().split()
        out: Dict[str, str] = {}
        if parts:
            out["_verb"] = parts[0]
        for tok in parts[1:]:
            if "=" in tok:
                k, v = tok.split("=", 1)
                out[k] = v
        return out

    def _session(self, *commands: str):
        """Open a connection, handshake, run commands; yield parsed responses.

        Returns a list of dicts, one per command (handshake excluded). Raises
        OSError if the agent is unreachable, or RuntimeError on a failed handshake.
        """
        # create_connection resolves the host and connects over IPv4 or IPv6.
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        sock.settimeout(self.timeout)
        results = []
        try:
            fp = sock.makefile("rwb", buffering=0)

            fp.write(f"HELLO {AGENT_PROTOCOL_VERSION} {self.token or ''}\n".encode())
            hello = fp.readline().decode(errors="replace").strip()
            if not hello.startswith("OK"):
                raise RuntimeError(f"agent handshake failed: {hello}")

            for cmd in commands:
                fp.write((cmd + "\n").encode())
                line = fp.readline().decode(errors="replace")
                if not line:
                    raise RuntimeError("agent closed connection mid-session")
                results.append(self._parse_kv(line))
        finally:
            try:
                sock.close()
            except OSError:
                pass
        return results

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        try:
            (status,) = self._session("STATUS")
        except (OSError, RuntimeError, ValueError) as e:
            self.logger.warning(f"Agent unreachable: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"AgentMonitor: {e}")
            return False

        state = status.get("state", "down")
        if state == "up":
            return True

        # crash / hung / down: pull + acknowledge the crash detail for the log.
        if state in ("crash", "hung"):
            detail = {}
            try:
                (detail,) = self._session("CRASH")
            except (OSError, RuntimeError, ValueError):
                pass
            msg = (
                f"Agent reports {state}: kind={detail.get('kind', state)} "
                f"signal={detail.get('signal', status.get('signal', '?'))} "
                f"exit={detail.get('exit', status.get('exit', '?'))} "
                f"test={detail.get('test', status.get('test', '?'))} "
                f"dump={detail.get('dump', '-')}"
            )
            self.logger.fail(msg)
            stderr_tail = detail.get("stderr_tail")
            if stderr_tail and stderr_tail != "-":
                self.logger.fail(f"  target stderr: {stderr_tail}")
            if fuzz_data_logger:
                fuzz_data_logger.log_fail(f"AgentMonitor: {msg}")
        else:
            self.logger.warning(f"Agent reports target state={state}")
        return False


__all__ = ["AgentMonitor"]
