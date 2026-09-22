"""Integration tests for the C oida-fuzzing-agent (separate repo).

Compiles the agent with the system C compiler (skips if unavailable / non-POSIX),
launches it supervising a dummy target, and drives the real TCP protocol to verify
crash detection + test correlation, auto-restart, process-tree teardown, cwd/env
handling, and the DIAG host inspection.
"""

import os
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path

import pytest

from tests.service_gate import require_service

pytestmark = pytest.mark.integration


SRC_FILES = ["fuzzing_agent.c", "config.c", "platform_posix.c", "platform_win.c"]


# The C agent lives in its own repo (https://github.com/f0rw4rd/oida-fuzzing-agent).
# Find its source via $OIDA_FUZZING_AGENT_SRC or a sibling checkout next to oida.
def _agent_src() -> Path:
    env = os.environ.get("OIDA_FUZZING_AGENT_SRC")
    if env:
        return Path(env)

    here = Path(__file__).resolve()
    candidates: list[Path] = []

    # When running from a git worktree the checkout lives at
    # <repo>/.claude/worktrees/<name>/..., so parents[4] points at the
    # worktrees dir rather than the repo's parent. Detect that segment and
    # anchor to the *real* repo root's parent so the sibling checkout is found
    # from both the main checkout and any worktree.
    parts = here.parts
    if ".claude" in parts:
        idx = parts.index(".claude")
        if idx >= 1 and parts[idx : idx + 2] == (".claude", "worktrees"):
            repo_root = Path(*parts[:idx])
            candidates.append(repo_root.parent / "oida-fuzzing-agent")

    # Sibling next to the current checkout root (main checkout: .../pro/oida ->
    # .../pro/oida-fuzzing-agent). If that parent isn't writable, the agent is
    # commonly cloned INSIDE the oida repo (.../pro/oida/oida-fuzzing-agent)
    # -- accepted there too (gitignored).
    candidates.append(here.parents[4] / "oida-fuzzing-agent")
    # In-repo gitignored clone (e.g. .../pro/oida/oida-fuzzing-agent) — same
    # layout the comment above describes for read-only parents, found from
    # the test file itself: parents[0]=fuzz, [1]=integration, [2]=tests,
    # [3]=repo root.
    candidates.append(here.parents[3] / "oida-fuzzing-agent")
    if ".claude" in parts:
        idx = parts.index(".claude")
        if idx >= 1 and parts[idx : idx + 2] == (".claude", "worktrees"):
            candidates.append(Path(*parts[:idx]) / "oida-fuzzing-agent")
    else:
        candidates.append(here.parents[2] / "oida-fuzzing-agent")

    for cand in candidates:
        if all((cand / f).exists() for f in SRC_FILES):
            return cand
    # Nothing found; return the last candidate so the fixture's error message
    # reports a sensible path.
    return candidates[-1]


AGENT_SRC = _agent_src()


# On a bare checkout the agent source / C compiler are absent and these tests
# gate (fail by default; set OIDA_SKIP_MISSING_SERVICES=1 to skip instead) --
# the Docker/CI gate (docker/agent-test/) exists precisely to guarantee they
# run against the real binary.
def _skip_or_fail(reason: str):
    require_service(reason)


if os.name != "posix":
    pytest.skip("oida-fuzzing-agent integration test is POSIX-only", allow_module_level=True)


@pytest.fixture(scope="module")
def agent_bin(tmp_path_factory):
    if not all((AGENT_SRC / f).exists() for f in SRC_FILES):
        _skip_or_fail(
            f"oida-fuzzing-agent source not found at {AGENT_SRC} "
            "(set OIDA_FUZZING_AGENT_SRC or check out f0rw4rd/oida-fuzzing-agent beside oida)"
        )
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        _skip_or_fail("no C compiler available to build oida-fuzzing-agent")
    out = tmp_path_factory.mktemp("agent") / "oida-fuzzing-agent"
    cmd = [cc, "-std=c11", "-D_GNU_SOURCE", "-O2", "-o", str(out)]
    cmd += [str(AGENT_SRC / f) for f in SRC_FILES]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        _skip_or_fail(f"oida-fuzzing-agent failed to compile:\n{proc.stderr}")
    return out


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Client:
    """Tiny synchronous protocol client for one agent connection."""

    def __init__(self, port, token="t", timeout=3.0):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.fp = self.sock.makefile("rwb", buffering=0)
        assert self.cmd(f"HELLO 1 {token}").startswith("OK")

    def cmd(self, line):
        self.fp.write((line + "\n").encode())
        return self.fp.readline().decode().strip()

    def kv(self, line):
        d = {}
        for tok in self.cmd(line).split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                d[k] = v
        return d

    def close(self):
        for closer in (self.fp.close, self.sock.close):
            try:
                closer()
            except OSError:
                pass


class Agent:
    """Launch the agent supervising a target; wait until the port is live."""

    def __init__(self, agent_bin, target_argv, token="t", extra=None, cwd=None, env=None):
        self.port = _free_port()
        cmd = [str(agent_bin), "--port", str(self.port), "--token", token]
        if cwd:
            cmd += ["--cwd", cwd]
        for kv in env or []:
            cmd += ["--env", kv]
        cmd += extra or []
        cmd += ["--"] + target_argv
        self.proc = subprocess.Popen(cmd, stderr=subprocess.PIPE)
        self._wait_port()

    def _wait_port(self, deadline=5.0):
        end = time.time() + deadline
        while time.time() < end:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.3).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("agent did not start listening")

    def stop(self):
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def _wait_state(client, want, timeout=4.0):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        last = client.kv("STATUS").get("state")
        if last == want:
            return True
        time.sleep(0.1)
    raise AssertionError(f"state never became {want!r} (last={last!r})")


def test_status_up_and_diag(agent_bin):
    ag = Agent(agent_bin, ["/bin/sleep", "300"], extra=["--restart", "never"])
    try:
        c = Client(ag.port)
        assert c.kv("STATUS")["state"] == "up"
        # DIAG must report a coredumps verdict for the host
        diag = c.kv("DIAG")
        assert diag.get("coredumps") in {"ok", "disabled", "piped"}
        c.close()
    finally:
        ag.stop()


def test_crash_detection_and_test_correlation(agent_bin):
    ag = Agent(agent_bin, ["/bin/sleep", "300"], extra=["--restart", "on-crash"])
    try:
        c = Client(ag.port)
        c.cmd("SETTEST 42")
        pid = int(c.kv("STATUS")["pid"])
        os.kill(pid, signal.SIGSEGV)
        _wait_state(c, "crash")
        crash = c.kv("CRASH")
        assert crash["kind"] == "crash"
        assert crash["signal"] == str(int(signal.SIGSEGV))
        assert crash["test"] == "42"  # correlated to the in-flight test
        # auto-restarted: latch cleared after CRASH ack, new instance
        _wait_state(c, "up")
        assert int(c.kv("STATUS")["instance"]) >= 2
        c.close()
    finally:
        ag.stop()


def test_restart_command_relaunches(agent_bin):
    ag = Agent(agent_bin, ["/bin/sleep", "300"], extra=["--restart", "never"])
    try:
        c = Client(ag.port)
        inst1 = int(c.kv("STATUS")["instance"])
        assert c.cmd("RESTART").startswith("OK")
        st = c.kv("STATUS")
        assert st["state"] == "up"
        assert int(st["instance"]) > inst1
        c.close()
    finally:
        ag.stop()


def test_tree_kill_on_crash(agent_bin, tmp_path):
    gc_pid_file = tmp_path / "gc.pid"
    target = [
        "/bin/sh",
        "-c",
        f"sleep 300 & echo $! > {gc_pid_file}; exec sleep 300",
    ]
    ag = Agent(agent_bin, target, extra=["--restart", "on-crash"])
    try:
        c = Client(ag.port)
        # wait for the grandchild pid to be recorded
        end = time.time() + 3
        while not gc_pid_file.exists() and time.time() < end:
            time.sleep(0.05)
        gc_pid = int(gc_pid_file.read_text().strip())
        pid = int(c.kv("STATUS")["pid"])
        os.kill(pid, signal.SIGSEGV)
        _wait_state(c, "crash")
        time.sleep(0.5)
        # the orphaned grandchild must have been swept on crash
        assert not Path(f"/proc/{gc_pid}").exists(), "grandchild leaked after crash"
        c.close()
    finally:
        ag.stop()


def test_cwd_and_env_applied(agent_bin, tmp_path):
    workdir = tmp_path / "work"
    workdir.mkdir()
    marker = "OIDA_MARKER_VALUE_123"
    target = ["/bin/sh", "-c", 'printf "%s" "$OIDA_MARKER" > marker.txt; sleep 300']
    ag = Agent(
        agent_bin,
        target,
        cwd=str(workdir),
        env=[f"OIDA_MARKER={marker}"],
        extra=["--restart", "never"],
    )
    try:
        Client(ag.port).close()  # ensure it started
        end = time.time() + 3
        out = workdir / "marker.txt"
        while not out.exists() and time.time() < end:
            time.sleep(0.05)
        assert out.exists(), "target did not run in the configured cwd"
        assert out.read_text() == marker, "configured env var not visible to target"
    finally:
        ag.stop()


def test_python_agent_monitor_against_live_agent(agent_bin):
    """The AgentMonitor client drives the real binary end to end."""
    from oida.fuzz.monitors.agent import AgentMonitor

    ag = Agent(agent_bin, ["/bin/sleep", "300"], extra=["--restart", "never"])
    try:
        # The agent serves one client at a time, so control + monitor must not overlap.
        mon = AgentMonitor(host="127.0.0.1", port=ag.port, token="t", timeout=2.0, retry_count=1)
        assert mon._check_alive_once(None) is True

        ctrl = Client(ag.port)
        pid = int(ctrl.kv("STATUS")["pid"])
        os.kill(pid, signal.SIGSEGV)
        _wait_state(ctrl, "crash")  # confirm the agent saw the crash
        ctrl.close()
        time.sleep(0.3)  # let the agent free the client slot

        assert mon._check_alive_once(None) is False
    finally:
        ag.stop()
