"""Base classes and common utilities for fuzzing monitors."""

import threading
import time
from abc import abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Any, Dict, List, Optional

import urllib3
from boofuzz.exception import BoofuzzFailure
from boofuzz.monitors import BaseMonitor

from ..core.session.commands import CommandRunner, RealCommandRunner
from ..core.config import FuzzerConfig
from ..core.calibration import DriftDetector, RtoEstimator, TimeoutCalibrator
from ...utils.ics_logger import get_logger, ICSLogger

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
        rtt: Most recent measured round-trip time of a health probe, in seconds
    """

    raw_response: bytes
    parsed_fields: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    response_length: int = field(default=0)
    rtt: Optional[float] = None

    def __post_init__(self):
        """Set response_length from raw_response if not provided."""
        if self.response_length == 0 and self.raw_response:
            self.response_length = len(self.raw_response)

    def matches(self, current_response: bytes, fields_to_check: Optional[List[str]] = None) -> bool:
        """Check if a current response matches this baseline.

        Args:
            current_response: The response to compare
            fields_to_check: Optional list of parsed_fields keys to check.
                           If None, compares raw_response bytes.

        Returns:
            True if responses match, False otherwise
        """
        if fields_to_check is None:
            return current_response == self.raw_response
        # Field-based comparison would be done by subclasses
        return True

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
    recovery_time: Optional[float] = None


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
            print(f"Crashed at test case {tracker.last_crash.test_case_id}")
        print(f"Total crashes: {tracker.crash_count}")
    """

    def __init__(self, target: str = ""):
        self.target = target
        self._lock = threading.Lock()
        self._crashes: List[CrashEvent] = []
        self._is_crashed = False
        self._last_crash: Optional[CrashEvent] = None

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

    @property
    def last_crash(self) -> Optional[CrashEvent]:
        """Most recent crash event."""
        with self._lock:
            return self._last_crash

    @property
    def unrecovered_crashes(self) -> List[CrashEvent]:
        """Crashes that haven't been recovered from."""
        with self._lock:
            return [c for c in self._crashes if not c.recovered]

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
            self._last_crash.recovery_time = time.time()
            self._is_crashed = False
            return True

    def get_crashes(self) -> List[CrashEvent]:
        """Get all recorded crash events."""
        with self._lock:
            return self._crashes.copy()

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

    def reset(self):
        """Reset all crash state (use with caution)."""
        with self._lock:
            self._crashes = []
            self._is_crashed = False
            self._last_crash = None


class IEC104States(IntEnum):
    """IEC 60870-5-104 connection states."""

    DISCONNECTED = auto()
    ACTIVE = auto()
    ERROR = auto()


class ProtocolMonitor(BaseMonitor):
    """Base class for protocol-specific health monitors with unified crash detection.

    This class provides:
    - Retry logic with configurable retry_count
    - Failure threshold before reporting crash
    - Binary crash state (crashed: bool) instead of crash_count
    - Detailed crash info logging (timestamp, test case, target)
    - Recovery attempt tracking with max_recovery_attempts limit
    - Rate-limited health checks

    Subclasses must implement:
    - _check_alive_once(fuzz_data_logger) -> bool: Single protocol-specific health check

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
    ):
        # Connection parameters
        self.host = host
        self.port = port
        self.timeout = timeout

        # Check settings
        self.check_interval = check_interval
        self.retry_count = retry_count
        self.failure_threshold = failure_threshold
        self.max_recovery_attempts = max_recovery_attempts

        # Session filename for crash persistence
        self.session_filename = session_filename

        # State tracking
        self.test_case_count = 0
        self.test_case_name: Optional[str] = None  # Current test case name (set by CombinedMonitor)
        self.consecutive_failures = 0
        self.last_check_time: Optional[float] = None

        # Online timeout adaptation (armed by the calibration phase when enabled).
        # Stay None for the static default behavior.
        self.last_rtt: Optional[float] = None
        self.rto_estimator: Optional[RtoEstimator] = None
        self.drift_detector: Optional[DriftDetector] = None

        # Crash state (binary)
        self.crashed = False
        self.crash_info: Optional[Dict[str, Any]] = None
        self.recovery_attempts = 0

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

        # Rate limit: minimum 0.2s between checks
        if self.last_check_time and (time.time() - self.last_check_time < 0.2):
            return True

        self.logger.debug(f"Checking target (test_case={self.test_case_count})")

        # Retry loop
        for attempt in range(self.retry_count):
            probe_start = time.perf_counter()
            result = self._check_alive_once(fuzz_data_logger)

            if result:
                # Success - reset failure counter
                if attempt > 0:
                    self.logger.display(
                        f"Check succeeded on attempt {attempt + 1}/{self.retry_count}"
                    )
                self.consecutive_failures = 0
                self.last_check_time = time.time()
                self._record_rtt(time.perf_counter() - probe_start)
                return True

            # Log retry attempt
            if attempt < self.retry_count - 1:
                self.logger.warning(f"Check failed, retrying ({attempt + 1}/{self.retry_count})...")
            time.sleep(0.1)

        # All retries failed - increment and check threshold
        self.consecutive_failures += 1
        self.last_check_time = time.time()
        self._on_probe_timeout()

        if self.consecutive_failures >= self.failure_threshold:
            self._on_crash_detected(fuzz_data_logger)
            # Immediately try all recovery attempts - don't wait for next check
            # This loop will either recover (return True) or raise BoofuzzFailure
            for _ in range(self.max_recovery_attempts + 1):
                result = self._try_recovery(fuzz_data_logger)
                if result:
                    return True
            raise BoofuzzFailure("Recovery failed after all attempts")

        # Not yet at threshold - report failure but continue fuzzing
        self.logger.warning(f"Check failed ({self.consecutive_failures}/{self.failure_threshold})")
        return True

    def _record_rtt(self, rtt: float) -> None:
        """Store a clean probe RTT and, if armed, adapt the timeout / watch for drift."""
        self.last_rtt = rtt
        if self.baseline is not None:
            self.baseline.rtt = rtt
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
        self.crash_info = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "test_case": self.test_case_count,
            "test_case_name": self.test_case_name or "unknown",
            "target": f"{self.host}:{self.port}",
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
        if self.recovery_attempts >= self.max_recovery_attempts:
            # Already at/past limit - re-raise without logging (was already logged)
            tc = f"{self.crash_info['test_case']:,}" if self.crash_info else "?"
            raise BoofuzzFailure(
                f"Target {self.host}:{self.port} unresponsive after {self.max_recovery_attempts} "
                f"recovery attempts (crashed at test case {tc})"
            )

        self.recovery_attempts += 1

        tc = f"{self.crash_info['test_case']:,}" if self.crash_info else "?"
        self.logger.display(
            f"Recovery attempt {self.recovery_attempts}/{self.max_recovery_attempts} "
            f"(crashed at test case {tc})"
        )

        # Try single check
        if self._check_alive_once(fuzz_data_logger):
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
            self.recovery_attempts = 0
            return True

        # Check if we've now hit the limit
        if self.recovery_attempts >= self.max_recovery_attempts:
            self.logger.fail(
                f"Max recovery attempts ({self.max_recovery_attempts}) reached - STOPPING FUZZER"
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
            raise BoofuzzFailure(
                f"Target {self.host}:{self.port} unresponsive after {self.max_recovery_attempts} "
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

        # Only check every check_interval test cases
        if self.test_case_count % self.check_interval != 0:
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
        # Only check every check_interval test cases
        if self.test_case_count % self.check_interval != 0:
            return True

        self.logger.display(f"Post-send health check at test case {self.test_case_count}")
        return self._check_alive(fuzz_data_logger)


__all__ = [
    "BaseMonitor",
    "BoofuzzFailure",
    "CommandRunner",
    "CrashEvent",
    "CrashTracker",
    "RealCommandRunner",
    "FuzzerConfig",
    "IEC104States",
    "ICSLogger",
    "ProtocolBaseline",
    "ProtocolMonitor",
]
