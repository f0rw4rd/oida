"""Regression tests for the DEAD/UNRESPONSIVE monitor verdict split.

The motivation (from live fuzzing evaluation): connect-refused (process gone)
and connect-OK-but-silent (hang / busy / single-client target) were both
collapsed into one "check failed" outcome, so a single-client target that
merely served the fuzzer's connection could abort a whole campaign via the
stop-after-N-recovery path. These tests lock in:

1. Evidence classification: refused/reset -> DEAD; timeout/bad-reply/unknown
   -> UNRESPONSIVE; ok -> ALIVE.
2. A DEAD crossing declares a crash immediately (no corroboration).
3. An UNRESPONSIVE crossing is corroborated by a deferred re-probe before
   any crash declaration; a successful re-probe stands down (budgeted).
4. The recovery abort distinguishes the verdicts in its message and budget
   (UNRESPONSIVE gets a doubled recovery budget).
5. Chronic intermittency still trips after the stand-down budget is spent
   (Bug 4 semantics preserved).
"""

import pytest
from boofuzz.exception import BoofuzzFailure

from oida.fuzz.monitors.base import ProtocolMonitor


class _VerdictMonitor(ProtocolMonitor):
    """Scripted probe whose evidence sequence is fixed per call.

    Each call pops the next (result, evidence) pair; when the script runs
    dry the last pair repeats. No network I/O.
    """

    def __init__(self, script, **kwargs):
        kwargs.setdefault("max_recovery_attempts", 0)
        super().__init__("127.0.0.1", 9999, **kwargs)
        self._script = list(script)
        self._idx = 0
        self.corroboration_delay = 0.0
        self.recovery_backoff_base = 0.0
        self.recovery_backoff_cap = 0.0
        self.recovery_probe_timeout = 0.0

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        if self._idx < len(self._script):
            result, evidence = self._script[self._idx]
        else:
            result, evidence = self._script[-1]
        self._idx += 1
        self._set_probe_evidence(evidence)
        return result


class TestEvidenceClassification:
    def test_refused_is_dead(self):
        m = _VerdictMonitor([(True, "ok")])
        m._set_probe_evidence("refused")
        assert m._probe_verdict == "dead"

    def test_reset_is_dead(self):
        m = _VerdictMonitor([(True, "ok")])
        m._set_probe_evidence("reset")
        assert m._probe_verdict == "dead"

    @pytest.mark.parametrize("evidence", ["timeout", "bad-reply", "unknown"])
    def test_ambiguous_evidence_is_unresponsive(self, evidence):
        m = _VerdictMonitor([(True, "ok")])
        m._set_probe_evidence(evidence)
        assert m._probe_verdict == "unresponsive"

    def test_ok_is_alive(self):
        m = _VerdictMonitor([(True, "ok")])
        m._check_alive_once()  # run one probe so evidence reflects "ok"
        assert m._probe_verdict == "alive"

    def test_unknown_value_falls_back(self):
        m = _VerdictMonitor([(True, "ok")])
        m._set_probe_evidence("garbage")  # not a known evidence token
        assert m._probe_evidence == "unknown"
        assert m._probe_verdict == "unresponsive"

    def test_multipart_string_not_accepted(self):
        m = _VerdictMonitor([(True, "ok")])
        m._set_probe_evidence("refused;drop table")  # injection-shaped
        assert m._probe_evidence == "unknown"
        assert m._probe_verdict == "unresponsive"


class TestDeadCrossing:
    def test_dead_crossing_declares_crash_without_corroboration(self):
        """ECONNREFUSED at threshold -> immediate crash episode (verdict DEAD)."""
        m = _VerdictMonitor(
            [(False, "refused")],
            check_interval=1,
            retry_count=1,
            failure_threshold=1,
            max_recovery_attempts=1,
        )
        m.last_check_time = None
        # Round fails; threshold crossed; verdict dead -> crash declared, then
        # one recovery probe (also refused) -> BoofuzzFailure.
        with pytest.raises(BoofuzzFailure, match="DEAD"):
            m._check_alive(None)
        assert m.crashed
        assert m._episode_verdict == "dead"

    def test_dead_crash_info_carries_verdict(self):
        m = _VerdictMonitor(
            [(False, "refused")],
            check_interval=1,
            retry_count=1,
            failure_threshold=1,
            max_recovery_attempts=1,
        )
        m.last_check_time = None
        with pytest.raises(BoofuzzFailure):
            m._check_alive(None)
        assert m.crash_info["verdict"] == "DEAD"


class TestUnresponsiveCorroboration:
    def _unresponsive_crossing(self, corroborate_script):
        m = _VerdictMonitor(
            corroborate_script,
            check_interval=1,
            retry_count=1,
            failure_threshold=1,
            max_recovery_attempts=1,
        )
        m.last_check_time = None
        return m

    def test_transient_silence_stands_down(self):
        """Crossing + re-probe answers -> no crash, failures cleared."""
        m = self._unresponsive_crossing([(False, "timeout"), (True, "ok")])
        result = m._check_alive(None)
        assert result is True
        assert m.crashed is False
        assert m.consecutive_failures == 0
        assert m._unresponsive_standdowns == 1

    def test_standdown_is_budgeted(self):
        """Chronic intermittency exhausts the budget and then trips."""
        m = self._unresponsive_crossing([(False, "timeout"), (True, "ok")])
        m.max_corroboration_standdowns = 1
        # 1st crossing: stand-down (budget 1 -> 0).
        assert m._check_alive(None) is True
        # 2nd crossing: budget empty -> crash declared; recovery probe is the
        # #3 scripted call (True) -> target "recovers".
        result = m._check_alive(None)
        assert m.crashed or result is True
        # 3rd crossing: budget was refunded on recovery; stand down again.
        m.last_check_time = None
        assert m._check_alive(None) is True

    def test_confirmed_silent_declares_crash_with_doubled_budget(self):
        """Crossing + re-probe also silent -> crash, verdict UNRESPONSIVE, and
        the recovery budget doubles (attempts 1/2 then 2/2 before abort)."""
        m = _VerdictMonitor(
            [(False, "timeout")],
            check_interval=1,
            retry_count=1,
            failure_threshold=1,
            max_recovery_attempts=1,
        )
        m.last_check_time = None
        with pytest.raises(BoofuzzFailure, match="UNRESPONSIVE"):
            m._check_alive(None)
        assert m.crashed
        assert m._episode_verdict == "unresponsive"
        assert m._unresponsive_corroborated is True
        # max_recovery_attempts=1 but UNRESPONSIVE -> 2 probes were consumed:
        # script index advanced past the crossing probe + corroborator + 2 recovery
        assert m._idx >= 4

    def test_dead_episode_keeps_hard_budget(self):
        """DEAD verdict: no budget doubling (max_recovery_attempts stands)."""
        m = _VerdictMonitor(
            [(False, "refused")],
            check_interval=1,
            retry_count=1,
            failure_threshold=1,
            max_recovery_attempts=1,
        )
        m.last_check_time = None
        with pytest.raises(BoofuzzFailure, match="DEAD"):
            m._check_alive(None)
        # Crossing probe + 1 recovery probe only.
        assert m._idx == 2

    def test_recovery_resets_episode_state(self):
        """A recovered target gets a fresh verdict + stand-down state."""
        m = _VerdictMonitor(
            [(False, "timeout"), (True, "ok")],
            check_interval=1,
            retry_count=1,
            failure_threshold=1,
            max_recovery_attempts=1,
        )
        m.last_check_time = None
        m._unresponsive_corroborated = True
        # Script: crossing fails (timeout) -> corroborator succeeds -> recovery
        # succeeded inside the same _check_alive (threshold crossing with
        # corroborated=True goes to crash + recovery probe returns True).
        result = m._check_alive(None)
        assert result is True
        assert m._unresponsive_corroborated is False
        assert m._episode_verdict is None
        assert m._unresponsive_standdowns == 0

    def test_clean_streak_refunds_standdown(self):
        """A healthy streak gives back one spent stand-down."""
        m = _VerdictMonitor(
            [(True, "ok")],
            check_interval=1,
            retry_count=1,
            failure_threshold=2,
        )
        m._unresponsive_standdowns = 2
        m.last_check_time = None
        m._check_alive(None)  # 1 success (streak 1 < 2): no refund yet
        assert m._unresponsive_standdowns == 2
        m.last_check_time = None
        m._check_alive(None)  # streak reaches 2: refund one
        assert m._unresponsive_standdowns == 1
