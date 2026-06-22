"""Unit tests for AgentMonitor (the on-target monitor-agent client).

Drives the client against a fake in-process TCP agent so no compiled binary is
needed; the live C agent is exercised in tests/integration/fuzz/test_monitor_agent.py.
"""

import socket
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from oida.fuzz.monitors.agent import AgentMonitor


class FakeAgent:
    """Minimal monitor-agent: handshake + STATUS/CRASH, one client at a time."""

    def __init__(
        self, state="up", token=None, crash=None, drop_after_hello=False, drop_on_crash=False
    ):
        self.state = state
        self.token = token
        self.crash = crash or {}
        self.drop_after_hello = drop_after_hello
        self.drop_on_crash = drop_on_crash
        self._running = True
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.srv.settimeout(0.3)
        self.port = self.srv.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while self._running:
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(1.0)
                fp = conn.makefile("rwb", buffering=0)
                authed = False
                while self._running:
                    line = fp.readline()
                    if not line:
                        break
                    parts = line.decode().split()
                    if not parts:
                        continue
                    cmd = parts[0]
                    if cmd == "HELLO":
                        tok = parts[2] if len(parts) > 2 else ""
                        if self.token and tok != self.token:
                            fp.write(b"ERR auth\n")
                            break
                        authed = True
                        fp.write(f"OK version=1 instance=1 state={self.state}\n".encode())
                        if self.drop_after_hello:
                            break  # close without answering the next command
                    elif not authed:
                        fp.write(b"ERR not-authenticated\n")
                    elif cmd == "STATUS":
                        fp.write(
                            f"OK state={self.state} pid=123 uptime=5 test=7 "
                            f"exit=0 signal=11 restarts=0 instance=1\n".encode()
                        )
                    elif cmd == "CRASH":
                        if self.drop_on_crash:
                            break  # drop the connection instead of answering CRASH
                        kv = " ".join(f"{k}={v}" for k, v in self.crash.items())
                        fp.write(f"OK {kv}\n".encode())
                    else:
                        fp.write(b"OK\n")

    def close(self):
        self._running = False
        try:
            self.srv.close()
        except OSError:
            pass


@pytest.fixture
def agent_factory():
    agents = []

    def make(**kw):
        a = FakeAgent(**kw)
        agents.append(a)
        return a

    yield make
    for a in agents:
        a.close()


class TestAgentMonitorLiveness:
    def test_up_is_alive(self, agent_factory):
        a = agent_factory(state="up")
        mon = AgentMonitor(host="127.0.0.1", port=a.port, retry_count=1)
        assert mon._check_alive_once(None) is True

    def test_crashed_is_dead(self, agent_factory):
        a = agent_factory(
            state="crash",
            crash={"kind": "crash", "signal": "11", "exit": "0", "test": "7", "dump": "-"},
        )
        mon = AgentMonitor(host="127.0.0.1", port=a.port, retry_count=1)
        assert mon._check_alive_once(None) is False

    def test_hung_is_dead(self, agent_factory):
        a = agent_factory(state="hung", crash={"kind": "hung", "test": "7"})
        mon = AgentMonitor(host="127.0.0.1", port=a.port, retry_count=1)
        assert mon._check_alive_once(None) is False

    def test_down_is_dead(self, agent_factory):
        a = agent_factory(state="down")
        mon = AgentMonitor(host="127.0.0.1", port=a.port, retry_count=1)
        assert mon._check_alive_once(None) is False

    def test_unreachable_is_dead(self):
        # nothing listening on this port
        mon = AgentMonitor(host="127.0.0.1", port=1, timeout=0.3, retry_count=1)
        assert mon._check_alive_once(None) is False


class TestAgentMonitorAuth:
    def test_correct_token_authenticates(self, agent_factory):
        a = agent_factory(state="up", token="sek")
        mon = AgentMonitor(host="127.0.0.1", port=a.port, token="sek", retry_count=1)
        assert mon._check_alive_once(None) is True

    def test_wrong_token_is_dead(self, agent_factory):
        a = agent_factory(state="up", token="sek")
        mon = AgentMonitor(host="127.0.0.1", port=a.port, token="nope", retry_count=1)
        assert mon._check_alive_once(None) is False


class TestAgentMonitorParsing:
    def test_parse_kv(self):
        d = AgentMonitor._parse_kv("OK state=up pid=42 test=7")
        assert d["_verb"] == "OK"
        assert d["state"] == "up"
        assert d["pid"] == "42"
        assert d["test"] == "7"


class TestApplicationHostportParser:
    def test_split_hostport(self):
        from oida.fuzz.core.application import FuzzerApplication

        assert FuzzerApplication._split_hostport(None, 5555) == (None, 5555)
        assert FuzzerApplication._split_hostport("10.0.0.5:6000", 5555) == ("10.0.0.5", 6000)
        assert FuzzerApplication._split_hostport("10.0.0.5", 5555) == ("10.0.0.5", 5555)

    def test_split_hostport_bad_port(self):
        from oida.fuzz.core.application import FuzzerApplication

        with pytest.raises(ValueError):
            FuzzerApplication._split_hostport("10.0.0.5:abc", 5555)


class TestAgentMonitorWiring:
    def test_extra_monitor_created_when_configured(self):
        from oida.fuzz.core.base_fuzzer import BaseFuzzer
        from oida.fuzz.core.config import FuzzerConfig
        from oida.fuzz.monitors.agent import AgentMonitor as AM

        cfg = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=502,
            agent_monitor_host="10.0.0.5",
            agent_monitor_port=5555,
            agent_monitor_token="t",
        )
        fake = SimpleNamespace(config=cfg, log=Mock())
        extra = BaseFuzzer._create_extra_monitors(fake)
        ams = [m for m in extra if isinstance(m, AM)]
        assert len(ams) == 1
        assert ams[0].host == "10.0.0.5"
        assert ams[0].port == 5555
        assert ams[0].token == "t"

    def test_no_agent_monitor_by_default(self):
        from oida.fuzz.core.base_fuzzer import BaseFuzzer
        from oida.fuzz.core.config import FuzzerConfig
        from oida.fuzz.monitors.agent import AgentMonitor as AM

        cfg = FuzzerConfig(target_ip="127.0.0.1", target_port=502)
        fake = SimpleNamespace(config=cfg, log=Mock())
        extra = BaseFuzzer._create_extra_monitors(fake)
        assert not [m for m in extra if isinstance(m, AM)]

    def test_registered_in_registry(self):
        from oida.fuzz.monitors.registry import get_monitor

        assert get_monitor("agent") is not None


class TestAgentMonitorLoggingAndEdges:
    def test_unreachable_logs_to_fuzz_logger(self):
        mon = AgentMonitor(host="127.0.0.1", port=1, timeout=0.3, retry_count=1)
        fdl = Mock()
        assert mon._check_alive_once(fdl) is False
        fdl.log_info.assert_called()

    def test_crash_logs_stderr_tail_and_fuzz_logger(self, agent_factory):
        a = agent_factory(
            state="crash",
            crash={"kind": "crash", "signal": "11", "test": "7", "stderr_tail": "boom-trace"},
        )
        mon = AgentMonitor(host="127.0.0.1", port=a.port, retry_count=1)
        fdl = Mock()
        assert mon._check_alive_once(fdl) is False
        fdl.log_fail.assert_called()

    def test_mid_session_disconnect_is_dead(self, agent_factory):
        # agent answers HELLO then drops, so the STATUS read sees EOF
        a = agent_factory(state="up", drop_after_hello=True)
        mon = AgentMonitor(host="127.0.0.1", port=a.port, timeout=1.0, retry_count=1)
        assert mon._check_alive_once(None) is False

    def test_crash_detail_fetch_failure_is_swallowed(self, agent_factory):
        # STATUS reports crash, but the follow-up CRASH fetch drops; still returns False
        a = agent_factory(state="crash", drop_on_crash=True)
        mon = AgentMonitor(host="127.0.0.1", port=a.port, timeout=1.0, retry_count=1)
        assert mon._check_alive_once(None) is False
