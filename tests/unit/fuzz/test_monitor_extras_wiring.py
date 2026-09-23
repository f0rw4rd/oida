"""Monitor extras (--agent-monitor / --script-monitor / --valid-case) must survive
a protocol's custom monitors.

BaseFuzzer.__init__ builds the monitor set in two steps:

    self.monitor = self._setup_monitor()            # protocol defaults + CLI extras
    if self.config.monitor_config is None:
        custom = self.setup_custom_monitors()       # e.g. ModbusFuzzer -> [ModbusMonitor]
        if custom:
            self.monitor.set_monitors(custom)       # replaces, does not merge

set_monitors() *replaces* the list, so any protocol that supplies custom monitors
silently discards the extras that _create_extra_monitors() just built. The
`--agent-monitor` flag then prints its banner but the AgentMonitor is never
queried -- crashes fall back to the weaker socket-level signal, and the agent
records every crash with test=-1 because no client ever sends TESTCASE.

The pre-existing TestAgentMonitorWiring cases assert _create_extra_monitors()
returns an AgentMonitor, which it does; they stop one layer short of the
replacement, which is why this went unnoticed.
"""

from typing import List

import pytest

from oida.fuzz.core.base_fuzzer import BaseFuzzer
from oida.fuzz.core.config import FuzzerConfig
from oida.fuzz.monitors.agent import AgentMonitor

AGENT_HOST = "127.0.0.1"
AGENT_PORT = 5599


class _StubProtocolMonitor:
    """Stand-in for a protocol monitor (ModbusMonitor, OpcuaMonitor, ...).

    Deliberately not a BaseMonitor subclass: this test only cares about list
    membership, and a real monitor would try to touch the network.
    """

    def __init__(self) -> None:
        self.session_filename = None
        self.crash_tracker = None


def _make_config(**overrides) -> FuzzerConfig:
    """Config with the agent monitor requested, as `--agent-monitor` would set it.

    monitor_config stays None -- that is the default when the user does not pass
    -M/--monitors, and it is the branch that triggers the replacement.
    """
    params = dict(
        target_ip="127.0.0.1",
        target_port=15502,
        protocol="stub",
        agent_monitor_host=AGENT_HOST,
        agent_monitor_port=AGENT_PORT,
        agent_monitor_token="demotoken",
        # Keep construction silent and side-effect free.
        web_interface=False,
        log_session=False,
        console_output=False,
    )
    params.update(overrides)
    return FuzzerConfig(**params)


class _FuzzerNoCustomMonitors(BaseFuzzer):
    """Protocol that adds no monitors of its own (the control case)."""

    def _define_protocol(self) -> None:
        pass


class _FuzzerWithCustomMonitors(BaseFuzzer):
    """Protocol that supplies custom monitors, like ModbusFuzzer does."""

    def _define_protocol(self) -> None:
        pass

    def setup_custom_monitors(self) -> List[object]:
        return [_StubProtocolMonitor()]


def _active_monitors(fuzzer: BaseFuzzer) -> List[object]:
    return list(fuzzer.monitor.monitors or [])


def _agent_monitors(fuzzer: BaseFuzzer) -> List[AgentMonitor]:
    return [m for m in _active_monitors(fuzzer) if isinstance(m, AgentMonitor)]


@pytest.fixture
def no_custom_fuzzer() -> BaseFuzzer:
    return _FuzzerNoCustomMonitors(_make_config())


@pytest.fixture
def custom_fuzzer() -> BaseFuzzer:
    return _FuzzerWithCustomMonitors(_make_config())


class TestMonitorExtrasSurviveCustomMonitors:
    def test_control_agent_monitor_present_without_custom_monitors(self, no_custom_fuzzer):
        """Control: with no custom monitors the agent survives.

        Pins the harness itself. If this fails, the test setup is wrong rather
        than the code under test, and the assertions below mean nothing.
        """
        agents = _agent_monitors(no_custom_fuzzer)
        assert len(agents) == 1, (
            f"expected exactly one AgentMonitor, got "
            f"{[type(m).__name__ for m in _active_monitors(no_custom_fuzzer)]}"
        )
        assert agents[0].host == AGENT_HOST
        assert agents[0].port == AGENT_PORT

    def test_agent_monitor_survives_protocol_custom_monitors(self, custom_fuzzer):
        """A protocol's custom monitors must not evict the --agent-monitor extra."""
        assert _agent_monitors(custom_fuzzer), (
            "AgentMonitor was dropped when the protocol supplied custom monitors; "
            f"active monitors are {[type(m).__name__ for m in _active_monitors(custom_fuzzer)]}. "
            "--agent-monitor prints its banner but the agent is never queried."
        )

    def test_custom_monitors_are_kept_too(self, custom_fuzzer):
        """The fix must merge, not swap: the protocol monitor stays as well."""
        kinds = [type(m).__name__ for m in _active_monitors(custom_fuzzer)]
        assert "_StubProtocolMonitor" in kinds, (
            f"protocol's own monitor was lost; active monitors are {kinds}"
        )

    def test_agent_monitor_not_duplicated(self, custom_fuzzer):
        """Merging must not append a second AgentMonitor."""
        agents = _agent_monitors(custom_fuzzer)
        assert len(agents) <= 1, f"AgentMonitor added {len(agents)} times"

    def test_no_agent_flag_means_no_agent_monitor(self):
        """Negative control: without the flag no AgentMonitor is wired in."""
        fuzzer = _FuzzerWithCustomMonitors(_make_config(agent_monitor_host=None))
        assert not _agent_monitors(fuzzer)
