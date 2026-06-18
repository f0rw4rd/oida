"""
Tests for session command runners.

Tests cover:
- CommandRunner: abstract interface
- RealCommandRunner: delegates to subprocess.run
- MockCommandRunner: configurable responses, call tracking
"""

import pytest
from unittest.mock import patch, Mock


# =============================================================================
# Test CommandRunner Abstract Interface
# =============================================================================


class TestCommandRunnerInterface:
    """Tests for CommandRunner abstract class."""

    def test_cannot_instantiate_directly(self):
        """CommandRunner cannot be instantiated directly."""
        from src.oida.fuzz.core.session.commands import CommandRunner

        with pytest.raises(TypeError):
            CommandRunner()


# =============================================================================
# Test RealCommandRunner
# =============================================================================


class TestRealCommandRunner:
    """Tests for RealCommandRunner."""

    def test_runs_subprocess(self):
        """RealCommandRunner delegates to subprocess.run."""
        from src.oida.fuzz.core.session.commands import RealCommandRunner

        runner = RealCommandRunner()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)
            result = runner.run(["echo", "test"], capture_output=True)
            mock_run.assert_called_once_with(["echo", "test"], capture_output=True)
            assert result.returncode == 0


# =============================================================================
# Test MockCommandRunner
# =============================================================================


class TestMockCommandRunner:
    """Tests for MockCommandRunner."""

    def test_default_response(self):
        """MockCommandRunner returns success by default."""
        from src.oida.fuzz.core.session.commands import MockCommandRunner

        runner = MockCommandRunner()
        result = runner.run(["test"])
        assert result.returncode == 0
        assert result.stdout == b""
        assert result.stderr == b""

    def test_tracks_calls(self):
        """MockCommandRunner tracks all calls."""
        from src.oida.fuzz.core.session.commands import MockCommandRunner

        runner = MockCommandRunner()
        runner.run(["cmd1", "arg1"])
        runner.run(["cmd2", "arg2"])
        assert len(runner.calls) == 2
        assert runner.calls[0]["cmd"] == ["cmd1", "arg1"]
        assert runner.calls[1]["cmd"] == ["cmd2", "arg2"]

    def test_set_responses(self):
        """Configure multiple responses."""
        from src.oida.fuzz.core.session.commands import MockCommandRunner

        runner = MockCommandRunner()
        runner.set_responses(
            return_codes=[0, 1, 0], outputs=[b"ok", b"fail", b"ok"], errors=[b"", b"error", b""]
        )

        r1 = runner.run(["cmd1"])
        assert r1.returncode == 0
        assert r1.stdout == b"ok"

        r2 = runner.run(["cmd2"])
        assert r2.returncode == 1
        assert r2.stderr == b"error"

        r3 = runner.run(["cmd3"])
        assert r3.returncode == 0

    def test_get_last_call(self):
        """get_last_call returns most recent call."""
        from src.oida.fuzz.core.session.commands import MockCommandRunner

        runner = MockCommandRunner()
        runner.run(["first"])
        runner.run(["second"])
        last = runner.get_last_call()
        assert last["cmd"] == ["second"]

    def test_get_last_call_empty(self):
        """get_last_call returns None when no calls made."""
        from src.oida.fuzz.core.session.commands import MockCommandRunner

        runner = MockCommandRunner()
        assert runner.get_last_call() is None

    def test_get_all_calls(self):
        """get_all_calls returns copy of all calls."""
        from src.oida.fuzz.core.session.commands import MockCommandRunner

        runner = MockCommandRunner()
        runner.run(["cmd1"])
        runner.run(["cmd2"])
        all_calls = runner.get_all_calls()
        assert len(all_calls) == 2
        # Verify it's a copy
        all_calls.clear()
        assert len(runner.calls) == 2

    def test_tracks_kwargs(self):
        """MockCommandRunner tracks kwargs."""
        from src.oida.fuzz.core.session.commands import MockCommandRunner

        runner = MockCommandRunner()
        runner.run(["cmd"], capture_output=True, timeout=5)
        call = runner.get_last_call()
        assert call["kwargs"]["capture_output"] is True
        assert call["kwargs"]["timeout"] == 5

    def test_exhausted_return_codes_defaults_to_zero(self):
        """When return codes exhausted, defaults to 0."""
        from src.oida.fuzz.core.session.commands import MockCommandRunner

        runner = MockCommandRunner()
        runner.set_responses(return_codes=[1])  # Only one code

        r1 = runner.run(["cmd1"])
        assert r1.returncode == 1

        r2 = runner.run(["cmd2"])
        assert r2.returncode == 0  # Default
