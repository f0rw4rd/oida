"""Tests for the three platform-feature monitors borrowed from commercial ICS fuzzers:

1. ValidCaseMonitor   - protocol-agnostic "does the target still answer a known-good
                        request correctly" probe (Defensics valid-case instrumentation).
2. ScriptMonitor      - external health-check command hook (Defensics external/agent
                        instrumentation): exit 0 == healthy.
4. Restart-and-resume - ProtocolMonitor runs a user restart command on the first recovery
                        attempt of a crash, so a long fuzz run survives a DoS unattended
                        (beSTORM auto-restart-and-resume). Deduped across monitors that
                        share a CrashTracker.
"""

import socket
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import pytest

from oida.fuzz.core.session.commands import CommandRunner, MockCommandRunner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class _Target:
    """A toggleable stand-in for a fuzz target's liveness."""

    def __init__(self, alive=True):
        self.alive = alive


class _RestartingRunner(CommandRunner):
    """Command runner whose restart command brings a downed target back up."""

    def __init__(self, target):
        self.target = target
        self.calls = []

    def run(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        self.target.alive = True
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")


# ===========================================================================
# 2. ScriptMonitor
# ===========================================================================
class TestScriptMonitor:
    def test_exit_zero_is_healthy(self):
        from oida.fuzz.monitors.script import ScriptMonitor

        runner = MockCommandRunner()
        runner.set_responses(return_codes=[0])
        mon = ScriptMonitor(
            host="127.0.0.1", command=["true"], command_runner=runner, retry_count=1
        )
        assert mon._check_alive_once(None) is True
        assert runner.get_last_call()["cmd"] == ["true"]

    def test_nonzero_exit_is_unhealthy(self):
        from oida.fuzz.monitors.script import ScriptMonitor

        runner = MockCommandRunner()
        runner.set_responses(return_codes=[1])
        mon = ScriptMonitor(
            host="127.0.0.1", command=["false"], command_runner=runner, retry_count=1
        )
        assert mon._check_alive_once(None) is False

    def test_custom_expected_returncode(self):
        from oida.fuzz.monitors.script import ScriptMonitor

        runner = MockCommandRunner()
        runner.set_responses(return_codes=[3])
        mon = ScriptMonitor(
            host="127.0.0.1",
            command=["check"],
            expect_returncode=3,
            command_runner=runner,
            retry_count=1,
        )
        assert mon._check_alive_once(None) is True

    def test_string_command_is_split(self):
        from oida.fuzz.monitors.script import ScriptMonitor

        runner = MockCommandRunner()
        runner.set_responses(return_codes=[0])
        mon = ScriptMonitor(
            host="127.0.0.1",
            command="curl -sf http://host/health",
            command_runner=runner,
            retry_count=1,
        )
        mon._check_alive_once(None)
        assert runner.get_last_call()["cmd"] == ["curl", "-sf", "http://host/health"]

    def test_exception_is_unhealthy(self):
        from oida.fuzz.monitors.script import ScriptMonitor

        class _Boom(CommandRunner):
            def run(self, cmd, **kwargs):
                raise OSError("boom")

        mon = ScriptMonitor(host="127.0.0.1", command=["x"], command_runner=_Boom(), retry_count=1)
        assert mon._check_alive_once(None) is False

    def test_empty_command_rejected(self):
        from oida.fuzz.monitors.script import ScriptMonitor

        with pytest.raises(ValueError):
            ScriptMonitor(host="127.0.0.1", command=[])

    def test_registered_in_registry(self):
        from oida.fuzz.monitors.registry import get_monitor

        assert get_monitor("script") is not None


# ===========================================================================
# 1. ValidCaseMonitor
# ===========================================================================
class TestValidCaseMonitor:
    def _patched_socket(self, recv_bytes, connect_exc=None):
        mock_sock = MagicMock()
        if connect_exc is not None:
            mock_sock.connect.side_effect = connect_exc
        mock_sock.recv.return_value = recv_bytes
        return mock_sock

    def test_known_good_response_is_alive_and_sets_baseline(self):
        from oida.fuzz.monitors.network import ValidCaseMonitor

        mon = ValidCaseMonitor(host="127.0.0.1", port=502, probe=b"\x01\x02", retry_count=1)
        with patch("socket.socket") as sk:
            sk.return_value = self._patched_socket(b"OK-RESPONSE")
            assert mon._check_alive_once(None) is True
        assert mon.baseline_established is True
        # the probe was actually sent
        sk.return_value.sendall.assert_called_with(b"\x01\x02")

    def test_no_response_is_dead(self):
        from oida.fuzz.monitors.network import ValidCaseMonitor

        mon = ValidCaseMonitor(host="127.0.0.1", port=502, probe=b"\x01", retry_count=1)
        with patch("socket.socket") as sk:
            sk.return_value = self._patched_socket(b"")
            assert mon._check_alive_once(None) is False

    def test_connection_refused_is_dead(self):
        from oida.fuzz.monitors.network import ValidCaseMonitor

        mon = ValidCaseMonitor(host="127.0.0.1", port=502, probe=b"\x01", retry_count=1)
        with patch("socket.socket") as sk:
            sk.return_value = self._patched_socket(b"", connect_exc=socket.error("refused"))
            assert mon._check_alive_once(None) is False

    def test_changed_response_is_dead(self):
        """Strict mode: a response that differs from the established baseline = corruption."""
        from oida.fuzz.monitors.network import ValidCaseMonitor

        mon = ValidCaseMonitor(host="127.0.0.1", port=502, probe=b"\x01", retry_count=1)
        with patch("socket.socket") as sk:
            sk.return_value = self._patched_socket(b"GOOD")
            assert mon._check_alive_once(None) is True  # baseline = GOOD
            sk.return_value.recv.return_value = b"CORRUPT"
            assert mon._check_alive_once(None) is False

    def test_expect_substring_tolerates_varying_response(self):
        from oida.fuzz.monitors.network import ValidCaseMonitor

        mon = ValidCaseMonitor(
            host="127.0.0.1", port=502, probe=b"\x01", expect=b"ALIVE", retry_count=1
        )
        with patch("socket.socket") as sk:
            sk.return_value = self._patched_socket(b"ts=1 ALIVE")
            assert mon._check_alive_once(None) is True
            sk.return_value.recv.return_value = b"ts=2 ALIVE"  # different bytes, same marker
            assert mon._check_alive_once(None) is True
            sk.return_value.recv.return_value = b"ts=3 DEAD"
            assert mon._check_alive_once(None) is False


# ===========================================================================
# 4. Restart-and-resume
# ===========================================================================
class _FakeMonitor:
    """Minimal ProtocolMonitor subclass driven by a _Target flag."""

    def __new__(cls, *a, **k):
        from oida.fuzz.monitors.base import ProtocolMonitor

        # Build the subclass lazily so the import stays inside the test module.
        if not hasattr(cls, "_impl"):

            class _Impl(ProtocolMonitor):
                def __init__(self, target, **kw):
                    super().__init__(host="127.0.0.1", port=0, **kw)
                    self._target = target

                def _check_alive_once(self, fuzz_data_logger=None):
                    return self._target.alive

            cls._impl = _Impl
        return cls._impl(*a, **k)


class TestCrashTrackerRestartClaim:
    def test_claim_restart_once_per_crash(self):
        from oida.fuzz.monitors.base import CrashTracker

        t = CrashTracker(target="h:1")
        # no crash yet -> cannot claim
        assert t.claim_restart() is False
        t.record_crash(test_case_id=5)
        assert t.claim_restart() is True
        assert t.claim_restart() is False  # already claimed for this crash
        t.record_recovery(test_case_id=6)
        t.record_crash(test_case_id=9)
        assert t.claim_restart() is True  # fresh crash -> claimable again


class TestMonitorRestart:
    def test_restart_command_fires_and_target_resumes(self):
        target = _Target(alive=False)
        runner = _RestartingRunner(target)
        mon = _FakeMonitor(
            target,
            retry_count=1,
            failure_threshold=1,
            max_recovery_attempts=3,
            restart_command=["restart-target.sh"],
            restart_delay=0,
            command_runner=runner,
        )
        # First health check: target down -> crash detected -> restart -> recover.
        result = mon._check_alive(None)
        assert result is True
        assert runner.calls == [["restart-target.sh"]]
        assert mon.crashed is False

    def test_no_restart_command_means_no_subprocess(self):
        target = _Target(alive=False)
        runner = _RestartingRunner(target)
        mon = _FakeMonitor(
            target,
            retry_count=1,
            failure_threshold=1,
            max_recovery_attempts=1,
            command_runner=runner,  # provided, but no restart_command set
        )
        from oida.fuzz.monitors.base import BoofuzzFailure

        with pytest.raises(BoofuzzFailure):
            mon._check_alive(None)
        assert runner.calls == []  # never invoked without a restart_command

    def test_restart_fires_only_once_across_shared_tracker(self):
        from oida.fuzz.monitors.base import CrashTracker

        target = _Target(alive=False)
        runner = _RestartingRunner(target)
        tracker = CrashTracker(target="127.0.0.1:0")
        mon = _FakeMonitor(
            target,
            retry_count=1,
            failure_threshold=1,
            max_recovery_attempts=3,
            restart_command=["restart.sh"],
            restart_delay=0,
            command_runner=runner,
            crash_tracker=tracker,
        )
        mon._check_alive(None)
        # Even though recovery may probe several times, the restart is claimed once.
        assert runner.calls == [["restart.sh"]]


# ===========================================================================
# CLI -> config -> monitor wiring
# ===========================================================================
class TestApplicationParsers:
    def test_split_command(self):
        from oida.fuzz.core.application import FuzzerApplication

        assert FuzzerApplication._split_command(None) is None
        assert FuzzerApplication._split_command("docker restart plc") == [
            "docker",
            "restart",
            "plc",
        ]

    def test_parse_hex_ok_and_spaces(self):
        from oida.fuzz.core.application import FuzzerApplication

        assert FuzzerApplication._parse_hex(None, "x") is None
        assert FuzzerApplication._parse_hex("00 01 ab", "x") == b"\x00\x01\xab"

    def test_parse_hex_invalid_raises(self):
        from oida.fuzz.core.application import FuzzerApplication

        with pytest.raises(ValueError):
            FuzzerApplication._parse_hex("zz", "--valid-case")


class TestBaseFuzzerMonitorWiring:
    """Exercise the monitor-building helpers without standing up a full fuzzer."""

    def _fake_self(self, **config_kwargs):
        from oida.fuzz.core.base_fuzzer import BaseFuzzer
        from oida.fuzz.core.config import FuzzerConfig

        cfg = FuzzerConfig(target_ip="127.0.0.1", target_port=502, **config_kwargs)
        fake = SimpleNamespace(config=cfg, log=Mock())
        return BaseFuzzer, fake

    def test_extra_monitors_created(self):
        BaseFuzzer, fake = self._fake_self(
            script_monitor_command=["health.sh"],
            valid_case_probe=b"\x01\x02",
            valid_case_expect=b"OK",
        )
        from oida.fuzz.monitors.script import ScriptMonitor
        from oida.fuzz.monitors.network import ValidCaseMonitor

        extra = BaseFuzzer._create_extra_monitors(fake)
        types = {type(m) for m in extra}
        assert ScriptMonitor in types
        assert ValidCaseMonitor in types
        vc = next(m for m in extra if isinstance(m, ValidCaseMonitor))
        assert vc.probe == b"\x01\x02"
        assert vc.expect == b"OK"

    def test_no_extra_monitors_by_default(self):
        BaseFuzzer, fake = self._fake_self()
        assert BaseFuzzer._create_extra_monitors(fake) == []

    def test_apply_restart_arms_all_monitors(self):
        from oida.fuzz.monitors.network import SocketHealthMonitor

        BaseFuzzer, fake = self._fake_self(
            restart_command=["docker", "restart", "plc"], restart_delay=0.5
        )
        monitors = [SocketHealthMonitor("127.0.0.1", 502)]
        BaseFuzzer._apply_restart_config(fake, monitors)
        m = monitors[0]
        assert m.restart_command == ["docker", "restart", "plc"]
        assert m.restart_delay == 0.5
        assert m.command_runner is not None

    def test_apply_restart_noop_without_command(self):
        from oida.fuzz.monitors.network import SocketHealthMonitor

        BaseFuzzer, fake = self._fake_self()
        monitors = [SocketHealthMonitor("127.0.0.1", 502)]
        BaseFuzzer._apply_restart_config(fake, monitors)
        assert monitors[0].restart_command is None


# ===========================================================================
# Error / logging branch coverage
# ===========================================================================
class TestScriptMonitorLogging:
    def test_nonzero_exit_logs_to_fuzz_logger(self):
        from oida.fuzz.monitors.script import ScriptMonitor

        runner = MockCommandRunner()
        runner.set_responses(return_codes=[1])
        mon = ScriptMonitor(host="127.0.0.1", command=["x"], command_runner=runner, retry_count=1)
        fdl = Mock()
        assert mon._check_alive_once(fdl) is False
        fdl.log_info.assert_called_once()

    def test_exception_logs_to_fuzz_logger(self):
        from oida.fuzz.monitors.script import ScriptMonitor

        class _Boom(CommandRunner):
            def run(self, cmd, **kwargs):
                raise OSError("boom")

        mon = ScriptMonitor(host="127.0.0.1", command=["x"], command_runner=_Boom(), retry_count=1)
        fdl = Mock()
        assert mon._check_alive_once(fdl) is False
        fdl.log_info.assert_called_once()


class TestValidCaseMonitorEdges:
    def test_empty_probe_rejected(self):
        from oida.fuzz.monitors.network import ValidCaseMonitor

        with pytest.raises(ValueError):
            ValidCaseMonitor(host="127.0.0.1", port=502, probe=b"")

    def _mock_sock(self, recv=b"", connect_exc=None):
        m = MagicMock()
        if connect_exc is not None:
            m.connect.side_effect = connect_exc
        m.recv.return_value = recv
        return m

    def test_probe_failure_logs_to_fuzz_logger(self):
        from oida.fuzz.monitors.network import ValidCaseMonitor

        mon = ValidCaseMonitor(host="127.0.0.1", port=502, probe=b"\x01", retry_count=1)
        fdl = Mock()
        with patch("socket.socket") as sk:
            sk.return_value = self._mock_sock(connect_exc=socket.error("refused"))
            assert mon._check_alive_once(fdl) is False
        fdl.log_info.assert_called()

    def test_empty_response_logs_to_fuzz_logger(self):
        from oida.fuzz.monitors.network import ValidCaseMonitor

        mon = ValidCaseMonitor(host="127.0.0.1", port=502, probe=b"\x01", retry_count=1)
        fdl = Mock()
        with patch("socket.socket") as sk:
            sk.return_value = self._mock_sock(recv=b"")
            assert mon._check_alive_once(fdl) is False
        fdl.log_info.assert_called()

    def test_expect_missing_logs_to_fuzz_logger(self):
        from oida.fuzz.monitors.network import ValidCaseMonitor

        mon = ValidCaseMonitor(
            host="127.0.0.1", port=502, probe=b"\x01", expect=b"OK", retry_count=1
        )
        fdl = Mock()
        with patch("socket.socket") as sk:
            sk.return_value = self._mock_sock(recv=b"NOPE")
            assert mon._check_alive_once(fdl) is False
        fdl.log_info.assert_called()

    def test_changed_baseline_logs_to_fuzz_logger(self):
        from oida.fuzz.monitors.network import ValidCaseMonitor

        mon = ValidCaseMonitor(host="127.0.0.1", port=502, probe=b"\x01", retry_count=1)
        fdl = Mock()
        with patch("socket.socket") as sk:
            sock = self._mock_sock(recv=b"GOOD")
            sk.return_value = sock
            assert mon._check_alive_once(fdl) is True  # baseline = GOOD
            sock.recv.return_value = b"CORRUPT"
            assert mon._check_alive_once(fdl) is False
        fdl.log_info.assert_called()


class _ThrowingRunner(CommandRunner):
    """Restart runner that brings the target up but reports failure (raises)."""

    def __init__(self, target):
        self.target = target
        self.calls = []

    def run(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        self.target.alive = True
        raise OSError("restart reported failure")


class TestMonitorRestartBranches:
    def test_restart_delay_is_honored(self):
        target = _Target(alive=False)
        runner = _RestartingRunner(target)
        mon = _FakeMonitor(
            target,
            retry_count=1,
            failure_threshold=1,
            max_recovery_attempts=3,
            restart_command=["r.sh"],
            restart_delay=0.5,
            command_runner=runner,
        )
        with patch("oida.fuzz.monitors.base.time.sleep") as slp:
            assert mon._check_alive(None) is True
        slp.assert_any_call(0.5)

    def test_restart_logs_to_fuzz_logger(self):
        target = _Target(alive=False)
        runner = _RestartingRunner(target)
        mon = _FakeMonitor(
            target,
            retry_count=1,
            failure_threshold=1,
            max_recovery_attempts=3,
            restart_command=["r.sh"],
            restart_delay=0,
            command_runner=runner,
        )
        fdl = Mock()
        assert mon._check_alive(fdl) is True
        assert any("restart" in str(c).lower() for c in fdl.log_info.call_args_list)

    def test_restart_command_failure_is_caught(self):
        target = _Target(alive=False)
        runner = _ThrowingRunner(target)
        mon = _FakeMonitor(
            target,
            retry_count=1,
            failure_threshold=1,
            max_recovery_attempts=3,
            restart_command=["r.sh"],
            restart_delay=0,
            command_runner=runner,
        )
        # the restart command raises, but it's caught; the target came up, so
        # recovery still succeeds rather than the exception propagating.
        fdl = Mock()
        assert mon._check_alive(fdl) is True
        assert runner.calls == [["r.sh"]]
        assert mon.crashed is False
        assert any("failed" in str(c).lower() for c in fdl.log_info.call_args_list)

    def test_restart_nonzero_exit_warns(self):
        target = _Target(alive=False)

        class _NonzeroRunner(CommandRunner):
            def __init__(self, t):
                self.t = t

            def run(self, cmd, **kwargs):
                self.t.alive = True
                return SimpleNamespace(returncode=1, stdout=b"", stderr=b"")

        mon = _FakeMonitor(
            target,
            retry_count=1,
            failure_threshold=1,
            max_recovery_attempts=3,
            restart_command=["r.sh"],
            restart_delay=0,
            command_runner=_NonzeroRunner(target),
        )
        # restart command reports a non-zero exit but the target came up -> recovered
        assert mon._check_alive(None) is True
        assert mon.crashed is False
