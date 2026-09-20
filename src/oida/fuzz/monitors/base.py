"""Base classes and common utilities for fuzzing monitors."""

import threading
import time
from abc import abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import urllib3
from boofuzz.exception import BoofuzzFailure
from boofuzz.monitors import BaseMonitor

from ..core.session.commands import RealCommandRunner
from ..core.calibration import DriftDetector, RtoEstimator, TimeoutCalibrator
from ...utils.ics_logger import get_logger

# Disable SSL warnings for fuzzing contexts
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class ProtocolBaseline:
    """Standardized baseline storage for protocol monitors.

    All monitors should use this class to store their baseline state,
    ensuring consistent behavior across different protocol implementations.

    Attributes:
        raw_response: The original bytes received from the target
        parsed_fields: Protocol-specific parsed data (function codes, status codes, etc.)
        timestamp: Unix timestamp when baseline was established
        response_length: Length of the baseline response
    """

    raw_response: bytes
    parsed_fields: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    @property
    def response_length(self) -> int:
        """Length of the baseline response."""
        return len(self.raw_response) if self.raw_response else 0

    def get_field(self, name: str, default: Any = None) -> Any:
        """Get a parsed field value."""
        return self.parsed_fields.get(name, default)


@dataclass
class CrashEvent:
    """Record of a single crash event."""

    timestamp: float
    test_case_id: int
    test_case_name: str
    target: str
    monitor_name: str
    reason: str
    recovered: bool = False


class CrashTracker:
    """Unified crash state tracking - single source of truth.

    Centralizes crash detection, recording, and recovery tracking across
    all monitors and the fuzzing session. Prevents inconsistent crash
    counts between boofuzz, CombinedMonitor, and individual monitors.

    Thread-safe: all state mutations and reads are protected by a lock
    to prevent TOCTOU races when multiple monitors report concurrently.

    Usage:
        tracker = CrashTracker()
        tracker.record_crash(test_case_id=100, monitor_name="ModbusMonitor", ...)
        tracker.record_recovery(test_case_id=105)

        # Query crash state
        if tracker.is_crashed:
            print("Target is currently crashed")
        print(f"Total crashes: {tracker.crash_count}")
    """

    def __init__(self, target: str = ""):
        self.target = target
        self._lock = threading.Lock()
        self._crashes: List[CrashEvent] = []
        self._is_crashed = False
        self._last_crash: Optional[CrashEvent] = None
        # Set once per crash episode by the first monitor that runs the restart
        # command, so monitors sharing a tracker don't each restart the target.
        self._restart_claimed = False

    @property
    def is_crashed(self) -> bool:
        """Whether target is currently in crashed state (not recovered)."""
        with self._lock:
            return self._is_crashed

    @property
    def crash_count(self) -> int:
        """Total number of crashes detected."""
        with self._lock:
            return len(self._crashes)

    def record_crash(
        self,
        test_case_id: int,
        test_case_name: str = "",
        monitor_name: str = "",
        reason: str = "",
    ) -> CrashEvent:
        """Record a new crash event.

        Args:
            test_case_id: Test case ID when crash was detected
            test_case_name: Name of the test case/request
            monitor_name: Name of the monitor that detected the crash
            reason: Description of why crash was detected

        Returns:
            The created CrashEvent
        """
        event = CrashEvent(
            timestamp=time.time(),
            test_case_id=test_case_id,
            test_case_name=test_case_name,
            target=self.target,
            monitor_name=monitor_name,
            reason=reason,
        )
        with self._lock:
            self._crashes.append(event)
            self._is_crashed = True
            self._last_crash = event
        return event

    def record_recovery(self, test_case_id: Optional[int] = None) -> bool:
        """Record recovery from crashed state.

        Args:
            test_case_id: Optional test case ID when recovery was detected

        Returns:
            True if there was a crash to recover from, False otherwise
        """
        with self._lock:
            if not self._is_crashed or not self._last_crash:
                return False

            self._last_crash.recovered = True
            self._is_crashed = False
            self._restart_claimed = False
            return True

    def claim_restart(self) -> bool:
        """Atomically claim the right to restart the target for the current crash.

        Returns True for exactly one caller per crash episode (and only while the
        target is in a crashed state); subsequent callers get False until the next
        recovery resets the claim. This lets several monitors share a tracker without
        each firing the restart command.
        """
        with self._lock:
            if self._is_crashed and not self._restart_claimed:
                self._restart_claimed = True
                return True
            return False

    def get_crash_summary(self) -> Dict[str, Any]:
        """Get summary of crash statistics."""
        with self._lock:
            return {
                "total_crashes": len(self._crashes),
                "is_crashed": self._is_crashed,
                "recovered_count": len([c for c in self._crashes if c.recovered]),
                "unrecovered_count": len([c for c in self._crashes if not c.recovered]),
                "last_crash_test_case": (
                    self._last_crash.test_case_id if self._last_crash else None
                ),
                "monitors_with_crashes": list(set(c.monitor_name for c in self._crashes)),
            }


class ProtocolMonitor(BaseMonitor):
    """Base class for protocol-specific health monitors with unified crash detection.

    This class provides:
    - Retry logic with configurable retry_count
    - Failure threshold before reporting crash
    - Binary crash state (crashed: bool) instead of crash_count
    - Detailed crash info logging (timestamp, test case, target)
    - Recovery attempt tracking with max_recovery_attempts limit
    - Rate-limited health checks
    - DEAD/UNRESPONSIVE verdict split: probes that observe ECONNREFUSED or an
      RST classify the target DEAD (process gone); probes where the connection
      succeeds but no protocol answer arrives classify it UNRESPONSIVE (hang,
      busy queue, connection-table limit). An UNRESPONSIVE threshold crossing
      is corroborated by a deferred re-probe before any crash is declared, and
      only a DEAD verdict may trigger the stop-after-N-recovery abort -- an
      UNRESPONSIVE target instead gets a doubled recovery budget.

    Subclasses must implement:
    - _check_alive_once(fuzz_data_logger) -> bool: Single protocol-specific health check
      Subclasses are encouraged (not required) to set self._set_probe_evidence(...)
      with the failure mode they observed; unknown evidence is treated as
      UNRESPONSIVE (the conservative path: no hard abort on ambiguity).

    Args:
        host: Target hostname or IP
        port: Target port
        timeout: Connection/receive timeout in seconds
        check_interval: Check every N test cases
        retry_count: Number of retries before counting as failure
        failure_threshold: Consecutive failures before reporting crash
        max_recovery_attempts: Max attempts to recover from crash before giving up
    """

    def __init__(
        self,
        host: str,
        port: int,
        timeout: float = 2.0,
        check_interval: int = 10,
        retry_count: int = 2,
        failure_threshold: int = 2,
        max_recovery_attempts: int = 5,
        session_filename: Optional[str] = None,
        crash_tracker: Optional[CrashTracker] = None,
        restart_command: Optional[List[str]] = None,
        restart_delay: float = 2.0,
        command_runner: Optional[Any] = None,
    ):
        # Connection parameters
        self.host = host
        self.port = port
        self.timeout = timeout

        # Auto-restart-and-resume: run restart_command once per crash episode before
        # re-probing, so a long run survives a DoS without manual intervention.
        self.restart_command = list(restart_command) if restart_command else None
        self.restart_delay = restart_delay
        if command_runner is None and self.restart_command:
            command_runner = RealCommandRunner()
        self.command_runner: Any = command_runner

        # Check settings
        self.check_interval = check_interval
        self.retry_count = retry_count
        self.failure_threshold = failure_threshold
        self.max_recovery_attempts = max_recovery_attempts

        # Recovery-burst pacing (see _try_recovery). The recovery loop probes
        # max_recovery_attempts+1 times; without spacing it drains in a tight loop
        # (~0.6s) and a target that is merely busy for a second or two is declared
        # dead. Escalating backoff spreads the probes over a few seconds and a
        # widened probe timeout tolerates the slow first reply of a recovering
        # target, while a genuinely dead target still exhausts the budget and halts.
        self.recovery_backoff_base = 0.3  # seconds * attempt number
        self.recovery_backoff_cap = 1.5  # per-attempt sleep ceiling
        self.recovery_probe_timeout = 2.0  # min probe timeout used during recovery

        # Session filename for crash persistence
        self.session_filename = session_filename

        # State tracking
        self.test_case_count = 0
        self.test_case_name: Optional[str] = None  # Current test case name (set by CombinedMonitor)
        self.consecutive_failures = 0
        # Clean-check streak. A single success no longer wipes failure history;
        # failure_threshold consecutive successes are required to clear it, so a
        # half-responsive target still trips the crash threshold over time.
        self.consecutive_successes = 0
        self.last_check_time: Optional[float] = None
        # Per-case failure marker for the rate-limiter path. Set when a probe
        # round fully failed during the CURRENT case; cleared at the start of
        # each case. The rate limiter reports this instead of the lingering
        # consecutive_failures counter (which round-2 deliberately made sticky
        # across cases to catch intermittent targets, and which would
        # otherwise poison every later case's verdict).
        self._failed_this_case: bool = False

        # Online timeout adaptation (armed by the calibration phase when enabled).
        # Stay None for the static default behavior.
        self.rto_estimator: Optional[RtoEstimator] = None
        self.drift_detector: Optional[DriftDetector] = None

        # Crash state (binary)
        self.crashed = False
        self.crash_info: Optional[Dict[str, Any]] = None
        self.recovery_attempts = 0

        # Probe evidence for the DEAD/UNRESPONSIVE split. _check_alive_once
        # implementations report the failure mode they observed via
        # _set_probe_evidence(); the base class maps it to a verdict when the
        # failure threshold is crossed. Defaults keep the legacy behavior for
        # monitors that never report evidence (see _probe_verdict).
        self._probe_evidence: str = "unknown"
        # Set when an UNRESPONSIVE verdict was corroborated by a later probe
        # that still failed (crash declaration is then allowed to proceed).
        self._unresponsive_corroborated: bool = False
        # Deferred re-probe delay for corroborating UNRESPONSIVE (seconds).
        self.corroboration_delay: float = 1.0
        # Benefit-of-the-doubt budget: an unresponsive crossing that the
        # deferred re-probe answers stands down instead of declaring a crash.
        # A persistently intermittent target burns one per crossing; once the
        # budget is empty, further crossings are corroborated by definition
        # (the target is effectively broken for fuzzing even if it still
        # answers occasionally). Cleared when a clean streak re-establishes
        # health or the target recovers.
        self.max_corroboration_standdowns: int = 3
        self._unresponsive_standdowns: int = 0
        # Verdict snapshot taken when a crash episode is declared (the live
        # _probe_evidence keeps moving as later probes run).
        self._episode_verdict: Optional[str] = None

        # Baseline tracking using standardized ProtocolBaseline
        self.baseline_established = False
        self.baseline: Optional[ProtocolBaseline] = None
        # Legacy: baseline_response for backwards compatibility
        self.baseline_response: Optional[Any] = None

        # Unified crash tracking (single source of truth)
        self.crash_tracker = crash_tracker

        # ICSLogger for consistent formatted output
        # Protocol name derived from class name (e.g., "MQTTMonitor" -> "FUZZ-MQTT")
        protocol_name = self.__class__.__name__.replace("Monitor", "").upper()
        self.logger = get_logger(f"FUZZ-{protocol_name}", host, port)

    def __repr__(self) -> str:
        last_check = (
            "never"
            if self.last_check_time is None
            else f"{time.time() - self.last_check_time:.1f}s ago"
        )
        baseline_status = "established" if self.baseline_established else "not set"
        crashed_status = "CRASHED" if self.crashed else "healthy"
        return (
            f"{self.__class__.__name__}(host={self.host}, port={self.port}, "
            f"timeout={self.timeout}, check_interval={self.check_interval}, "
            f"retry_count={self.retry_count}, failure_threshold={self.failure_threshold}, "
            f"consecutive_failures={self.consecutive_failures}, "
            f"baseline={baseline_status}, status={crashed_status}, last_check={last_check})"
        )

    def __str__(self) -> str:
        if self.crashed:
            status = "CRASHED"
        elif self.consecutive_failures > 0:
            status = f"{self.consecutive_failures} failures"
        else:
            status = "healthy"
        return f"{self.__class__.__name__} for {self.host}:{self.port} ({status})"

    @abstractmethod
    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Protocol-specific single health check. Subclasses must implement.

        Args:
            fuzz_data_logger: Optional boofuzz logger for detailed logging

        Returns:
            True if target responds correctly, False otherwise
        """
        pass

    # ==================== DEAD / UNRESPONSIVE VERDICT SPLIT ====================

    # Evidence values map to verdicts below. "refused"/"reset" are strong
    # evidence the process is gone (OS refuses or RSTs the connection);
    # "timeout"/"bad-reply"/"unknown" mean the endpoint is reachable but not
    # answering correctly -- ambiguous between a hang, a busy target, and a
    # single-client target that only serves the fuzzer's own connection.
    _DEAD_EVIDENCE = frozenset({"refused", "reset"})
    _UNRESPONSIVE_EVIDENCE = frozenset({"timeout", "bad-reply", "unknown"})

    def _set_probe_evidence(self, evidence: str) -> None:
        """Report what the last probe actually observed (subclass API).

        Call from _check_alive_once with one of:
        - "ok": a valid protocol answer arrived
        - "refused": connect() got ECONNREFUSED (port closed -> process gone)
        - "reset": connect or read got an RST mid-conversation
        - "timeout": connection established, no answer within the timeout
        - "bad-reply": an answer arrived but did not parse / match baseline

        Unknown values fall back to "unknown" (treated as UNRESPONSIVE).
        """
        if evidence in ("ok", "refused", "reset", "timeout", "bad-reply"):
            self._probe_evidence = evidence
        else:
            self._probe_evidence = "unknown"

    @property
    def _probe_verdict(self) -> str:
        """Classify the last probe: "alive", "dead", or "unresponsive"."""
        if self._probe_evidence == "ok":
            return "alive"
        if self._probe_evidence in self._DEAD_EVIDENCE:
            return "dead"
        return "unresponsive"

    def _is_dead_episode(self) -> bool:
        """Whether the current crash episode was declared on DEAD evidence."""
        return self._episode_verdict == "dead"

    def _effective_recovery_limit(self) -> int:
        """Recovery-attempt budget for the current episode.

        DEAD episodes (ECONNREFUSED/RST at declaration time) keep the hard
        limit: the process is observably gone and further probing is cheap.
        UNRESPONSIVE episodes (reachable but silent) get a doubled budget:
        halting a long campaign on that weaker evidence risks false aborts
        on busy or single-client targets.
        """
        if self._is_dead_episode():
            return self.max_recovery_attempts
        return self.max_recovery_attempts * 2

    def _corroborate_unresponsive(self, fuzz_data_logger=None) -> bool:
        """Deferred re-probe an UNRESPONSIVE threshold crossing.

        Connect-succeeds-but-silent is weak crash evidence: a busy queue, a
        reboot in progress, or a single-client server that only serves the
        fuzzer's own data connection all look identical to a hang from the
        probe socket's point of view. Before declaring a crash (and arming
        the recovery abort) on that evidence alone, wait corroboration_delay
        and probe once more. A success here clears the failure streak (the
        target was merely transiently silent); a failure of any kind
        confirms the episode.

        Returns:
            True when the episode is corroborated (declare crash),
            False when the re-probe succeeded (transient -- stand down).
        """
        if self.corroboration_delay > 0:
            time.sleep(self.corroboration_delay)
        verdict_ok = self._check_alive_once(fuzz_data_logger)
        if verdict_ok:
            self.logger.display(
                "Unresponsive episode not corroborated (target answered re-probe); standing down"
            )
            self.consecutive_failures = 0
            self.consecutive_successes = 0
            # The re-probe disproved this case's failure: don't leave the
            # per-case marker armed, or a rate-limited post_send for the same
            # case would still report it.
            self._failed_this_case = False
            self.last_check_time = time.time()
            return False
        self._unresponsive_corroborated = True
        self.logger.warning("Unresponsive episode corroborated by deferred re-probe")
        return True

    def _check_alive(self, fuzz_data_logger=None) -> bool:
        """Check if target is responsive with retry logic and crash detection.

        This method:
        1. If crashed, attempts recovery with limit
        2. Rate-limits checks (min 0.2s between checks)
        3. Retries on failure up to retry_count times
        4. Tracks consecutive failures
        5. Triggers crash detection when failure_threshold exceeded

        Args:
            fuzz_data_logger: Optional boofuzz logger for detailed logging

        Returns:
            True if target is alive, False if crashed
        """
        # If already crashed, try recovery with limit
        if self.crashed:
            self.logger.debug("Already crashed, trying recovery")
            return self._try_recovery(fuzz_data_logger)

        # Rate limit: minimum 0.2s between checks. When rate-limited we skip the
        # probe; report this case's verdict only. A fully-failed probe round in
        # the CURRENT case (_failed_this_case, set below / by pre_send) fails
        # this check, so the failure is not masked by the post-send probe being
        # skipped. The lingering consecutive_failures counter is deliberately
        # NOT consulted: boofuzz treats a False return from post_send as
        # "crash detected on this case" (log_fail -> failed_test_cases ->
        # recorded crash + crashing_primitives accrual), and round-2 made that
        # counter sticky across cases (a clean streak clears it), so reporting
        # it here would poison every rate-limited post-send after a single
        # transient blip on a fast target.
        if self.last_check_time and (time.time() - self.last_check_time < 0.2):
            return not self._failed_this_case

        self.logger.debug(f"Checking target (test_case={self.test_case_count})")

        # Retry loop
        for attempt in range(self.retry_count):
            probe_start = time.perf_counter()
            result = self._check_alive_once(fuzz_data_logger)

            if result:
                if attempt > 0:
                    self.logger.display(
                        f"Check succeeded on attempt {attempt + 1}/{self.retry_count}"
                    )
                # Do NOT hard-reset the failure counter on a single success: a
                # half-crashed target that answers only intermittently would then
                # never trip the threshold (every lucky probe wipes the history).
                # Require a short run of clean checks (failure_threshold successes)
                # before clearing accumulated failures, so an alternating target
                # still accrues toward a crash.
                self.consecutive_successes += 1
                if self.consecutive_successes >= self.failure_threshold:
                    self.consecutive_failures = 0
                    # Health re-established by a clean streak: refund one
                    # stand-down (a rare blip on an otherwise healthy target
                    # stays free; chronic intermittency still exhausts).
                    if self._unresponsive_standdowns > 0:
                        self._unresponsive_standdowns -= 1
                self.last_check_time = time.time()
                self._record_rtt(time.perf_counter() - probe_start)
                return True

            # Log retry attempt
            if attempt < self.retry_count - 1:
                self.logger.warning(f"Check failed, retrying ({attempt + 1}/{self.retry_count})...")
            time.sleep(0.1)

        # All retries failed - a fully-failed round is NOT healthy.
        self.consecutive_successes = 0
        self.consecutive_failures += 1
        self.last_check_time = time.time()
        self._failed_this_case = True
        self._on_probe_timeout()

        if self.consecutive_failures >= self.failure_threshold:
            # DEAD/UNRESPONSIVE split: an uncorroborated UNRESPONSIVE crossing
            # (connect OK, no answer) gets one deferred corroborating probe
            # before a crash is declared; a DEAD crossing (ECONNREFUSED/RST)
            # or an already-corroborated episode proceeds immediately. The
            # stand-down is budgeted: a target that only intermittently
            # answers must still trip eventually (Bug 4 semantics).
            if (
                self._probe_verdict == "unresponsive"
                and not self._unresponsive_corroborated
                and self._unresponsive_standdowns < self.max_corroboration_standdowns
            ):
                if not self._corroborate_unresponsive(fuzz_data_logger):
                    # Transient silence: episode stood down, target answered.
                    self._unresponsive_standdowns += 1
                    self.logger.display(
                        f"Unresponsive stand-downs used: "
                        f"{self._unresponsive_standdowns}/{self.max_corroboration_standdowns}"
                    )
                    return True
            self._on_crash_detected(fuzz_data_logger)
            # Immediately try all recovery attempts - don't wait for next check
            # This loop will either recover (return True) or raise BoofuzzFailure.
            # Bound the burst by the verdict-aware effective limit so an
            # UNRESPONSIVE episode actually receives its doubled budget and
            # aborts with the verdict message (not the generic one).
            for _ in range(self._effective_recovery_limit() + 1):
                result = self._try_recovery(fuzz_data_logger)
                if result:
                    return True
            raise BoofuzzFailure("Recovery failed after all attempts")

        # Below the crash threshold but every probe this round failed: report the
        # failure to boofuzz (return False) instead of the old "warn but return
        # True", which reported a fully-unresponsive round as healthy and let the
        # case pass with zero successful probes. This does not abort the run --
        # only crossing failure_threshold raises BoofuzzFailure.
        self.logger.warning(f"Check failed ({self.consecutive_failures}/{self.failure_threshold})")
        return False

    def _record_rtt(self, rtt: float) -> None:
        """Store a clean probe RTT and, if armed, adapt the timeout / watch for drift."""
        if self.rto_estimator is not None:
            self.timeout = self.rto_estimator.update(rtt)
        if self.drift_detector is not None and self.drift_detector.add(rtt):
            self._recalibrate_after_drift()

    def _on_probe_timeout(self) -> None:
        """A probe failed: back the adaptive timeout off (Karn's rule — don't learn)."""
        if self.rto_estimator is not None:
            self.timeout = self.rto_estimator.on_timeout()

    def _recalibrate_after_drift(self) -> None:
        """Sustained latency drift detected: re-probe and re-seed the estimators."""
        self.logger.warning("Latency drift detected; recalibrating monitor timeout")
        result = TimeoutCalibrator(self, probes=30, warmup=1).run()
        if result is None:
            self.logger.warning("Drift recalibration: too few clean probes; keeping timeout")
            return
        self.timeout = result.monitor_timeout
        self.rto_estimator = RtoEstimator.from_stats(result.stats)
        if self.drift_detector is not None:
            self.drift_detector.recenter(result.stats.median, result.stats.mad_scaled)
        self.logger.success(f"Recalibrated monitor timeout to {self.timeout:.2f}s")

    def _on_crash_detected(self, fuzz_data_logger=None) -> None:
        """Log detailed crash information when target becomes unresponsive.

        Called when consecutive_failures >= failure_threshold.
        Sets crashed=True and populates crash_info dict.
        Reports to unified CrashTracker if available.

        Args:
            fuzz_data_logger: Optional boofuzz logger for detailed logging
        """
        self.crashed = True
        # Snapshot the verdict this episode was declared on: it decides the
        # recovery abort policy (see _try_recovery) and survives later probes.
        self._episode_verdict = (
            self._probe_verdict if self._probe_verdict != "alive" else "unresponsive"
        )
        self.crash_info = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "test_case": self.test_case_count,
            "test_case_name": self.test_case_name or "unknown",
            "target": f"{self.host}:{self.port}",
            "verdict": self._episode_verdict.upper(),
            "consecutive_failures": self.consecutive_failures,
        }

        # Report to unified crash tracker (single source of truth)
        if self.crash_tracker:
            self.crash_tracker.record_crash(
                test_case_id=self.test_case_count,
                test_case_name=self.test_case_name or "unknown",
                monitor_name=self.__class__.__name__,
                reason=f"{self.consecutive_failures} consecutive failures",
            )

        # Log crash with ICSLogger - prominent multi-line output
        self.logger.fail("=" * 50)
        self.logger.fail("POTENTIAL CRASH DETECTED!")
        self.logger.fail(f"  Timestamp:     {self.crash_info['timestamp']}")
        self.logger.fail(
            f"  Test case:     {self.crash_info['test_case']} ({self.crash_info['test_case_name']})"
        )
        self.logger.fail(f"  Target:        {self.crash_info['target']}")
        self.logger.fail(f"  Verdict:       {self.crash_info['verdict']}")
        self.logger.fail(f"  Failures:      {self.crash_info['consecutive_failures']} consecutive")
        self.logger.fail(f"  Retry count:   {self.retry_count}")
        self.logger.fail(f"  Threshold:     {self.failure_threshold}")
        self.logger.fail("=" * 50)
        self.logger.display(f"Will attempt up to {self.max_recovery_attempts} recovery attempts")

        if fuzz_data_logger:
            crash_msg = (
                f"POTENTIAL CRASH DETECTED\n"
                f"  Timestamp: {self.crash_info['timestamp']}\n"
                f"  Test case: {self.crash_info['test_case']} ({self.crash_info['test_case_name']})\n"
                f"  Target: {self.crash_info['target']}\n"
                f"  Consecutive failures: {self.crash_info['consecutive_failures']}"
            )
            fuzz_data_logger.log_fail(crash_msg)

    def _should_restart(self) -> bool:
        """Whether this monitor should fire the restart command now.

        Deduped via the shared CrashTracker when present (one restart per crash
        across all monitors); falls back to "first recovery attempt" when the
        monitor runs standalone without a tracker.
        """
        if not self.restart_command or self.command_runner is None:
            return False
        if self.crash_tracker is not None:
            return self.crash_tracker.claim_restart()
        return self.recovery_attempts == 1

    def _maybe_restart_target(self, fuzz_data_logger=None) -> None:
        """Run the configured restart command once per crash, then wait restart_delay."""
        if not self._should_restart():
            return

        cmd_str = " ".join(self.restart_command)
        self.logger.display(f"Restarting target: {cmd_str}")
        if fuzz_data_logger:
            fuzz_data_logger.log_info(f"Running restart command: {cmd_str}")
        try:
            result = self.command_runner.run(self.restart_command, capture_output=True, timeout=30)
            rc = getattr(result, "returncode", None)
            if rc not in (None, 0):
                self.logger.warning(f"Restart command exited with code {rc}")
        except Exception as e:
            self.logger.warning(f"Restart command failed: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"Restart command failed: {e}")

        if self.restart_delay > 0:
            time.sleep(self.restart_delay)

    def _try_recovery(self, fuzz_data_logger=None) -> bool:
        """Attempt to recover from crash state with limit.

        Called when self.crashed=True. Checks limit first, then increments
        recovery_attempts and gives up after max_recovery_attempts.

        Args:
            fuzz_data_logger: Optional boofuzz logger for detailed logging

        Returns:
            True if recovered, False if still crashed

        Raises:
            BoofuzzFailure: When max recovery attempts exceeded
        """
        # Check limit BEFORE incrementing to prevent "6/5" scenario
        # This also handles re-entry after BoofuzzFailure was already raised
        # DEAD/UNRESPONSIVE split: the hard stop is reserved for DEAD verdicts
        # (ECONNREFUSED/RST -- the process is observably gone). An UNRESPONSIVE
        # episode (reachable, silent) is weaker evidence: halting a long
        # campaign over it risks a false abort on a busy or single-client
        # target, so it gets a doubled budget and a clearer message instead.
        effective_limit = self._effective_recovery_limit()
        if self.recovery_attempts >= effective_limit:
            # Already at/past limit - re-raise without logging (was already logged)
            tc = f"{self.crash_info['test_case']:,}" if self.crash_info else "?"
            verdict = (
                "DEAD (connection refused/reset)" if self._is_dead_episode() else "UNRESPONSIVE"
            )
            raise BoofuzzFailure(
                f"Target {self.host}:{self.port} {verdict} after {self.recovery_attempts} "
                f"recovery attempts (crashed at test case {tc})"
            )

        self.recovery_attempts += 1

        tc = f"{self.crash_info['test_case']:,}" if self.crash_info else "?"
        self.logger.display(
            f"Recovery attempt {self.recovery_attempts}/{effective_limit} "
            f"(crashed at test case {tc})"
        )

        # Escalating backoff between recovery probes. Without it the whole recovery
        # burst fires in a tight loop (~0.6s total), so a target that is merely
        # busy/rebooting for a second or two -- a transient blip, not a crash --
        # gets its entire recovery budget exhausted before it can answer, halting
        # the run on a false positive. The backoff spreads the probes over a few
        # seconds; a genuinely dead target still exhausts all attempts and halts,
        # only later. Total added wait is bounded (~sum over attempts, capped).
        backoff = min(
            self.recovery_attempts * self.recovery_backoff_base, self.recovery_backoff_cap
        )
        if backoff > 0:
            time.sleep(backoff)

        # Auto-restart the target once per crash episode before re-probing.
        self._maybe_restart_target(fuzz_data_logger)

        # Widen the probe timeout during recovery: a recovering target often answers
        # slowly at first, and the steady-state (deliberately tight) monitor timeout
        # would reject that slow-but-alive reply and keep it counted as down.
        saved_timeout = self.timeout
        self.timeout = max(self.timeout, self.recovery_probe_timeout)
        try:
            recovered = self._check_alive_once(fuzz_data_logger)
        finally:
            self.timeout = saved_timeout

        # Try single check
        if recovered:
            # Recovered!
            down_since = self.crash_info["timestamp"] if self.crash_info else "unknown"
            test_case = f"{self.crash_info['test_case']:,}" if self.crash_info else "?"

            # Log recovery with prominent banner (like crash detection)
            self.logger.success("=" * 50)
            self.logger.success("TARGET RECOVERED!")
            self.logger.success(f"  Recovery attempts: {self.recovery_attempts}")
            self.logger.success(f"  Down since:        {down_since}")
            self.logger.success(f"  Crashed at:        test case {test_case}")
            self.logger.success("=" * 50)

            if fuzz_data_logger:
                fuzz_data_logger.log_info(
                    f"Target recovered after {self.recovery_attempts} attempts "
                    f"(down since {down_since}, crashed at test case {test_case})"
                )

            # Report recovery to unified crash tracker
            if self.crash_tracker:
                self.crash_tracker.record_recovery(test_case_id=self.test_case_count)

            # Reset crash state
            self.crashed = False
            self.crash_info = None
            self.consecutive_failures = 0
            self.consecutive_successes = 0
            self.recovery_attempts = 0
            self._unresponsive_corroborated = False
            self._episode_verdict = None
            # A recovered target gets a fresh stand-down budget: the episode
            # that just ended is over, and chronically refusing to ever stand
            # down again would re-introduce false aborts after one blip.
            self._unresponsive_standdowns = 0
            return True

        # Check if we've now hit the limit (verdict-aware, same policy as the
        # entry check: UNRESPONSIVE episodes get a doubled budget).
        effective_limit = self._effective_recovery_limit()
        if self.recovery_attempts >= effective_limit:
            self.logger.fail(
                f"Max recovery attempts ({self.recovery_attempts}/{effective_limit} "
                f"for {self._episode_verdict or 'unknown'} episode) reached - STOPPING FUZZER"
            )
            if fuzz_data_logger:
                fuzz_data_logger.log_fail(
                    f"{self.__class__.__name__}: Max recovery attempts "
                    f"({self.max_recovery_attempts}) reached, stopping fuzzer"
                )
            # Record crashed test case to DB for resume
            if self.session_filename and self.crash_info:
                try:
                    from ..core.database.orm import SQLAlchemyDatabase
                    from ..core.database.interface import TestCase as TestCaseDTO

                    db = SQLAlchemyDatabase(f"{self.session_filename}.db")
                    db.init_schema()
                    db.store_test_case(
                        TestCaseDTO(
                            id=self.crash_info["test_case"],
                            name=self.crash_info.get("test_case_name", "crash"),
                            timestamp=self.crash_info["timestamp"],
                            result="crash",
                            crc32=0,
                            target_ip=self.host,
                            target_port=self.port,
                        )
                    )
                except Exception as e:
                    self.logger.warning(f"Failed to persist crash data to session DB: {e}")
            tc = f"{self.crash_info['test_case']:,}" if self.crash_info else "?"
            verdict = (
                "DEAD (connection refused/reset)" if self._is_dead_episode() else "UNRESPONSIVE"
            )
            raise BoofuzzFailure(
                f"Target {self.host}:{self.port} {verdict} after {self.recovery_attempts} "
                f"recovery attempts (crashed at test case {tc})"
            )

        return False

    def pre_send(self, target=None, fuzz_data_logger=None, session=None) -> bool:
        """Check target health before sending fuzz data.

        Args:
            target: Boofuzz target (unused)
            fuzz_data_logger: Optional boofuzz logger
            session: Boofuzz session (unused)

        Returns:
            True if target is alive, False if crashed
        """
        self.test_case_count += 1

        # Only check every check_interval test cases. Guard the modulus: a 0 (or
        # negative) check_interval would raise ZeroDivisionError here; treat a
        # non-positive interval as "check every case" (effectively 1).
        interval = self.check_interval if self.check_interval > 0 else 1
        # New case: any per-case failure marker from the previous case is
        # stale. Clear it on EVERY pre_send (probing or interval-skipped) so a
        # rate-limited post_send never reports a previous case's failure.
        self._failed_this_case = False
        if self.test_case_count % interval != 0:
            return True

        self.logger.display(f"Pre-send health check at test case {self.test_case_count}")
        return self._check_alive(fuzz_data_logger)

    def post_send(self, target=None, fuzz_data_logger=None, session=None) -> bool:
        """Verify target health after sending fuzz data.

        Args:
            target: Boofuzz target (unused)
            fuzz_data_logger: Optional boofuzz logger
            session: Boofuzz session (unused)

        Returns:
            True if target is alive, False if crashed
        """
        # Only check every check_interval test cases. Guard the modulus (see
        # pre_send): a non-positive interval is treated as "check every case".
        interval = self.check_interval if self.check_interval > 0 else 1
        if self.test_case_count % interval != 0:
            return True

        self.logger.display(f"Post-send health check at test case {self.test_case_count}")
        return self._check_alive(fuzz_data_logger)


__all__ = [
    "BaseMonitor",
    "BoofuzzFailure",
    "CrashEvent",
    "CrashTracker",
    "RealCommandRunner",
    "ProtocolBaseline",
    "ProtocolMonitor",
]
