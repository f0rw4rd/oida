"""Timeout auto-calibration for the over-the-wire fuzzer.

The fuzzer has two independent timing channels with different jobs:

- the **data channel** receive timeout (``--recv-timeout``), which is purely a
  throughput bound: how long to wait for a fuzz case's reply before moving on; and
- each **monitor** timeout, which is the crash oracle. A too-tight monitor timeout
  produces false crash verdicts on a slow-but-alive device, so this is where a
  conservative, heavy-tail-robust value matters.

Calibration measures real response latency by timing the configured health-monitor
probe (which already sends a valid benign request) before fuzzing starts, then derives
timeouts from robust statistics: the monitor channel gets ``max(p99*2, median + 6*MAD)``;
the data channel gets the cheaper ``p95*1.5``. :class:`RtoEstimator` (Jacobson/Karels)
and :class:`DriftDetector` (CUSUM) refine the monitor timeout online during a campaign.

This module is pure: it talks to a monitor only through a ``_check_alive_once()`` duck
type, so the statistics are unit-testable without a network or a fuzzer instance.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, List, Optional

# Clamp bounds for any derived timeout, in seconds.
TIMEOUT_MIN = 0.5
TIMEOUT_MAX = 10.0

# Scale factor making the median absolute deviation a consistent estimator of the
# standard deviation under a normal distribution (1 / Phi^-1(0.75)).
MAD_TO_SIGMA = 1.4826


def clamp(value: float, lo: float = TIMEOUT_MIN, hi: float = TIMEOUT_MAX) -> float:
    """Clamp ``value`` into the inclusive ``[lo, hi]`` timeout range."""
    return max(lo, min(hi, value))


def _median_sorted(sorted_samples: List[float]) -> float:
    """Median of an already-sorted, non-empty list."""
    n = len(sorted_samples)
    mid = n // 2
    if n % 2:
        return sorted_samples[mid]
    return (sorted_samples[mid - 1] + sorted_samples[mid]) / 2.0


def _percentile_sorted(sorted_samples: List[float], q: float) -> float:
    """Linear-interpolated percentile (``q`` in ``[0, 1]``) of a sorted list."""
    if len(sorted_samples) == 1:
        return sorted_samples[0]
    rank = q * (len(sorted_samples) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(sorted_samples) - 1)
    frac = rank - lo
    return sorted_samples[lo] + (sorted_samples[hi] - sorted_samples[lo]) * frac


@dataclass
class RobustStats:
    """Outlier-resistant summary of a batch of latency samples (seconds)."""

    n: int
    median: float
    mad: float
    mad_scaled: float
    p95: float
    p99: float
    max: float
    mean: float

    @classmethod
    def from_samples(cls, samples: List[float]) -> "RobustStats":
        if not samples:
            raise ValueError("cannot compute statistics from an empty sample")
        ordered = sorted(samples)
        median = _median_sorted(ordered)
        deviations = sorted(abs(x - median) for x in ordered)
        mad = _median_sorted(deviations)
        return cls(
            n=len(ordered),
            median=median,
            mad=mad,
            mad_scaled=mad * MAD_TO_SIGMA,
            p95=_percentile_sorted(ordered, 0.95),
            p99=_percentile_sorted(ordered, 0.99),
            max=ordered[-1],
            mean=sum(ordered) / len(ordered),
        )


def recv_timeout_from(stats: RobustStats, stateful: bool = False) -> float:
    """Data-channel receive timeout: tuned for throughput, not crash detection.

    Stateful protocols (those that must consume the reply to advance) get a more
    generous ``p99 * 2``; for blind/stateless fuzzing ``p95 * 1.5`` is enough.
    """
    if stateful:
        return clamp(stats.p99 * 2.0)
    return clamp(stats.p95 * 1.5)


def monitor_timeout_from(stats: RobustStats) -> float:
    """Crash-oracle timeout: conservative, so a slow reply is not read as a crash."""
    return clamp(max(stats.p99 * 2.0, stats.median + 6.0 * stats.mad_scaled))


@dataclass
class CalibrationResult:
    """Outcome of a calibration run, kept for transparent logging."""

    stats: RobustStats
    recv_timeout: float
    monitor_timeout: float
    probe_count: int
    clean_count: int


class TimeoutCalibrator:
    """Probe a monitor N times, measure latency, and derive robust timeouts.

    The probe target only needs a ``_check_alive_once(fuzz_data_logger=None) -> bool``
    method (every :class:`ProtocolMonitor` has one). A probe that returns ``False`` or
    raises is excluded from the statistics — the calibration-time equivalent of Karn's
    rule: never learn latency from a failed exchange.
    """

    def __init__(
        self,
        probe,
        *,
        probes: int = 50,
        min_probes: int = 30,
        warmup: int = 2,
        stateful: bool = False,
        inter_probe_delay: float = 0.05,
        probe_timeout: float = TIMEOUT_MAX,
        time_budget: float = 30.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.perf_counter,
    ):
        self.probe = probe
        self.probes = max(1, probes)
        # Never require more clean samples than we attempt.
        self.min_probes = min(min_probes, self.probes)
        self.warmup = warmup
        self.stateful = stateful
        self.inter_probe_delay = inter_probe_delay
        # Widen the probe's own timeout while measuring, so a slow-but-alive reply is
        # observed as latency rather than counted as a failure (the modbus monitor's
        # default is only 0.1s). Bounded by an overall wall-clock budget.
        self.probe_timeout = probe_timeout
        self.time_budget = time_budget
        self._sleep = sleep
        self._clock = clock

    def probe_once(self) -> Optional[float]:
        """One timed probe; ``None`` if it failed (excluded from stats)."""
        start = self._clock()
        try:
            alive = self.probe._check_alive_once(None)
        except Exception:
            return None
        if not alive:
            return None
        return self._clock() - start

    def collect(self) -> List[float]:
        """Run ``warmup + probes`` probes, discarding warmup, keeping clean RTTs.

        Stops early if the overall wall-clock budget is exceeded, so a slow or flaky
        target cannot stall startup.
        """
        clean: List[float] = []
        total = self.warmup + self.probes
        start = self._clock()
        for i in range(total):
            rtt = self.probe_once()
            if i >= self.warmup and rtt is not None:
                clean.append(rtt)
            if self.time_budget and (self._clock() - start) > self.time_budget:
                break
            if self.inter_probe_delay and i < total - 1:
                self._sleep(self.inter_probe_delay)
        return clean

    def run(self) -> Optional[CalibrationResult]:
        """Calibrate, or return ``None`` if too few clean probes (keep defaults)."""
        original_timeout = getattr(self.probe, "timeout", None)
        if original_timeout is not None:
            self.probe.timeout = self.probe_timeout
        try:
            clean = self.collect()
        finally:
            if original_timeout is not None:
                self.probe.timeout = original_timeout
        if len(clean) < self.min_probes:
            return None
        stats = RobustStats.from_samples(clean)
        return CalibrationResult(
            stats=stats,
            recv_timeout=recv_timeout_from(stats, self.stateful),
            monitor_timeout=monitor_timeout_from(stats),
            probe_count=self.probes,
            clean_count=len(clean),
        )


class RtoEstimator:
    """Online monitor-timeout estimator following TCP's RTO (RFC 6298 / Jacobson-Karels).

    ``timeout = clamp(RTO * safety * backoff)`` where ``RTO = SRTT + 4 * RTTVAR``.
    Clean samples update the smoothed mean/variance and reset the backoff; a timed-out
    probe (Karn's rule) does not update the estimators and instead doubles the backoff
    until a clean sample arrives.
    """

    ALPHA = 1.0 / 8.0
    BETA = 1.0 / 4.0
    K = 4.0

    def __init__(
        self,
        srtt: float,
        rttvar: float,
        *,
        floor: float = TIMEOUT_MIN,
        ceil: float = TIMEOUT_MAX,
        safety: float = 1.3,
    ):
        self.srtt = srtt
        self.rttvar = max(rttvar, 1e-6)
        self.floor = floor
        self.ceil = ceil
        self.safety = safety
        self._backoff = 1

    @classmethod
    def from_stats(cls, stats: RobustStats, **kwargs) -> "RtoEstimator":
        return cls(srtt=stats.median, rttvar=stats.mad_scaled / 2.0, **kwargs)

    @property
    def rto(self) -> float:
        return self.srtt + self.K * self.rttvar

    def timeout(self) -> float:
        return clamp(self.rto * self.safety * self._backoff, self.floor, self.ceil)

    def update(self, rtt: float) -> float:
        """Feed a clean RTT sample. RTTVAR is updated before SRTT, per RFC 6298."""
        self.rttvar = (1 - self.BETA) * self.rttvar + self.BETA * abs(self.srtt - rtt)
        self.srtt = (1 - self.ALPHA) * self.srtt + self.ALPHA * rtt
        self._backoff = 1
        return self.timeout()

    def on_timeout(self) -> float:
        """A probe timed out: Karn's rule — don't learn, back off (cap at 64x)."""
        self._backoff = min(self._backoff * 2, 64)
        return self.timeout()


class DriftDetector:
    """Two-sided CUSUM that flags a sustained latency shift, not a single spike.

    Per-sample deviations are winsorized to ``+/- winsor * std`` so one heavy-tail
    outlier cannot trip the alarm, while a sustained regime change accumulates and does.
    """

    def __init__(
        self,
        mean: float,
        std: float,
        *,
        k_sigma: float = 0.5,
        h_sigma: float = 5.0,
        winsor: float = 4.0,
    ):
        self._configure(mean, std, k_sigma, h_sigma, winsor)

    def _configure(self, mean, std, k_sigma, h_sigma, winsor):
        self.mean = mean
        self.std = max(std, 1e-6)
        self.k_sigma = k_sigma
        self.h_sigma = h_sigma
        self.winsor = winsor
        self.k = k_sigma * self.std
        self.h = h_sigma * self.std
        self.cap = winsor * self.std
        self.reset()

    def reset(self) -> None:
        self.s_hi = 0.0
        self.s_lo = 0.0

    def recenter(self, mean: float, std: float) -> None:
        """Re-seed the baseline after a recalibration."""
        self._configure(mean, std, self.k_sigma, self.h_sigma, self.winsor)

    def add(self, rtt: float) -> bool:
        """Add a sample; return ``True`` once on a detected sustained shift."""
        dev = rtt - self.mean
        dev = max(-self.cap, min(self.cap, dev))
        self.s_hi = max(0.0, self.s_hi + dev - self.k)
        self.s_lo = min(0.0, self.s_lo + dev + self.k)
        if self.s_hi > self.h or self.s_lo < -self.h:
            self.reset()
            return True
        return False
