"""Tests for timeout auto-calibration (statistics, calibrator, RTO, drift).

Covers:
- RobustStats: median / MAD / percentiles on known inputs
- timeout formulas + clamping, stateful vs stateless recv basis
- TimeoutCalibrator: clean collection, warmup discard, failed-probe exclusion,
  insufficient-sample fallback, probe-timeout widening + restore
- RtoEstimator: Jacobson/Karels convergence, Karn backoff + reset
- DriftDetector: fires on a sustained step, NOT on a single outlier
- override gating on the BaseFuzzer hook (recv_timeout hard-set wins)
"""

from src.oida.fuzz.core.calibration import (
    DriftDetector,
    RobustStats,
    RtoEstimator,
    TimeoutCalibrator,
    clamp,
    monitor_timeout_from,
    recv_timeout_from,
)


class _Clock:
    """Deterministic, parity-independent perf_counter stand-in.

    Time only advances when the probe runs (inside _check_alive_once), so the extra
    clock reads the calibrator makes (collect-start, time-budget check) don't matter.
    """

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class _ScriptedProbe:
    """Monitor stand-in: scripted alive/dead results with scripted per-probe latency."""

    def __init__(self, results, rtt=0.02, rtts=None, clock=None):
        self.results = list(results)
        self.rtt = rtt
        self.rtts = list(rtts) if rtts is not None else None
        self.clock = clock
        self.timeout = 0.1  # tight default, like the modbus monitor
        self.timeout_during_probe = []
        self._i = 0

    def _check_alive_once(self, fuzz_data_logger=None):
        alive = self.results[self._i] if self._i < len(self.results) else False
        self.timeout_during_probe.append(self.timeout)
        if self.clock is not None:
            self.clock.now += self.rtts[self._i] if self.rtts else self.rtt
        self._i += 1
        return alive


class TestRobustStats:
    def test_known_values(self):
        s = RobustStats.from_samples([1.0, 2.0, 3.0, 4.0, 5.0])
        assert s.n == 5
        assert s.median == 3.0
        assert s.mean == 3.0
        # deviations from median: [2,1,0,1,2] -> median 1.0
        assert s.mad == 1.0
        assert abs(s.mad_scaled - 1.4826) < 1e-9
        assert s.max == 5.0

    def test_percentiles_interpolated(self):
        s = RobustStats.from_samples([float(i) for i in range(1, 101)])  # 1..100
        assert abs(s.p95 - 95.05) < 1e-6
        assert abs(s.p99 - 99.01) < 1e-6

    def test_outlier_does_not_move_median(self):
        base = [0.01] * 50
        s_clean = RobustStats.from_samples(base)
        s_spike = RobustStats.from_samples(base + [10.0])
        assert s_spike.median == s_clean.median  # median unmoved by one outlier
        assert s_spike.mean > s_clean.mean  # mean is

    def test_empty_raises(self):
        try:
            RobustStats.from_samples([])
            assert False, "expected ValueError"
        except ValueError:
            pass


class TestFormulas:
    def test_clamp_bounds(self):
        assert clamp(0.001) == 0.5
        assert clamp(999.0) == 10.0
        assert clamp(3.0) == 3.0

    def test_recv_stateful_vs_stateless(self):
        s = RobustStats.from_samples([2.0] * 40)  # median=p95=p99=2.0
        assert recv_timeout_from(s, stateful=False) == clamp(2.0 * 1.5)  # 3.0
        assert recv_timeout_from(s, stateful=True) == clamp(2.0 * 2.0)  # 4.0

    def test_monitor_uses_max_of_two_terms(self):
        s = RobustStats.from_samples([2.0] * 40)  # p99=2.0, mad_scaled=0
        # max(p99*2=4.0, median+6*0=2.0) -> 4.0
        assert monitor_timeout_from(s) == 4.0


class TestTimeoutCalibrator:
    def test_clean_collection_and_warmup(self):
        clk = _Clock()
        probe = _ScriptedProbe(results=[True] * 12, rtt=0.05, clock=clk)
        cal = TimeoutCalibrator(
            probe,
            probes=10,
            min_probes=5,
            warmup=2,
            inter_probe_delay=0,
            sleep=lambda _: None,
            clock=clk,
        )
        result = cal.run()
        assert result is not None
        assert result.clean_count == 10  # warmup excluded
        assert abs(result.stats.median - 0.05) < 1e-9

    def test_failed_probes_excluded(self):
        clk = _Clock()
        # 2 warmup + 10 attempts, 4 of which fail -> 6 clean
        results = [True, True] + [True, False, True, False, True, False, True, False, True, True]
        probe = _ScriptedProbe(results=results, rtt=0.02, clock=clk)
        cal = TimeoutCalibrator(
            probe,
            probes=10,
            min_probes=5,
            warmup=2,
            inter_probe_delay=0,
            sleep=lambda _: None,
            clock=clk,
        )
        result = cal.run()
        assert result is not None
        assert result.clean_count == 6

    def test_insufficient_samples_returns_none(self):
        clk = _Clock()
        results = [True, True] + [True] * 3 + [False] * 7  # only 3 clean of 10
        probe = _ScriptedProbe(results=results, rtt=0.02, clock=clk)
        cal = TimeoutCalibrator(
            probe,
            probes=10,
            min_probes=8,
            warmup=2,
            inter_probe_delay=0,
            sleep=lambda _: None,
            clock=clk,
        )
        assert cal.run() is None

    def test_probe_timeout_widened_then_restored(self):
        clk = _Clock()
        probe = _ScriptedProbe(results=[True] * 7, rtt=0.02, clock=clk)
        cal = TimeoutCalibrator(
            probe,
            probes=5,
            min_probes=1,
            warmup=2,
            probe_timeout=9.0,
            inter_probe_delay=0,
            sleep=lambda _: None,
            clock=clk,
        )
        cal.run()
        # While probing, the tight 0.1s default was widened to 9.0s...
        assert all(t == 9.0 for t in probe.timeout_during_probe)
        # ...and the original value was restored afterward.
        assert probe.timeout == 0.1

    def test_time_budget_stops_early(self):
        clk = _Clock()
        # Each probe "takes" 5s of wall clock; a 6s budget should stop after ~2 probes.
        probe = _ScriptedProbe(results=[True] * 20, rtt=5.0, clock=clk)
        cal = TimeoutCalibrator(
            probe,
            probes=18,
            min_probes=1,
            warmup=0,
            time_budget=6.0,
            inter_probe_delay=0,
            sleep=lambda _: None,
            clock=clk,
        )
        result = cal.run()
        assert result is not None
        assert result.clean_count <= 3


class TestRtoEstimator:
    def test_converges_toward_samples(self):
        est = RtoEstimator(srtt=0.1, rttvar=0.05)
        for _ in range(200):
            est.update(0.02)
        assert abs(est.srtt - 0.02) < 1e-3
        assert est.rttvar < 1e-2

    def test_karn_backoff_and_reset(self):
        est = RtoEstimator(srtt=0.1, rttvar=0.05, floor=0.001, ceil=100.0)
        base = est.timeout()
        t1 = est.on_timeout()
        t2 = est.on_timeout()
        assert t2 > t1 >= base  # doubles each timeout
        # a clean sample resets the backoff
        est.update(0.1)
        assert est.timeout() < t2

    def test_from_stats_seeding(self):
        s = RobustStats.from_samples([0.05] * 40)
        est = RtoEstimator.from_stats(s)
        assert est.srtt == s.median


class TestDriftDetector:
    def test_single_outlier_does_not_fire(self):
        d = DriftDetector(mean=0.01, std=0.002)
        fired = any(d.add(x) for x in [0.011, 0.009, 0.5, 0.010, 0.011, 0.009])
        assert not fired

    def test_sustained_shift_fires(self):
        d = DriftDetector(mean=0.01, std=0.002)
        fired = False
        for _ in range(50):
            if d.add(0.03):  # sustained +10 sigma regime
                fired = True
                break
        assert fired

    def test_recenter_resets(self):
        d = DriftDetector(mean=0.01, std=0.002)
        for _ in range(5):
            d.add(0.03)
        d.recenter(0.03, 0.002)
        assert d.s_hi == 0.0 and d.s_lo == 0.0


class _FakeLog:
    def display(self, *a, **k):
        pass

    success = warning = debug = fail = display


class _FakeMonitor:
    def __init__(self):
        self.timeout = 0.1

    def _check_alive_once(self, _=None):
        return True


class TestOverrideGating:
    """The BaseFuzzer hook must honor a hard-set --recv-timeout but still set the oracle."""

    def _make_fuzzer(self, recv_timeout):
        from src.oida.fuzz.core.base_fuzzer import BaseFuzzer
        from src.oida.fuzz.core.config import FuzzerConfig

        class _ConcreteFuzzer(BaseFuzzer):
            def _define_protocol(self):  # satisfy the ABC
                pass

        f = _ConcreteFuzzer.__new__(_ConcreteFuzzer)  # skip __init__; wire what the hook needs
        f.config = FuzzerConfig(target_ip="x", target_port=1, calibration_probes=5)
        f.config.recv_timeout = recv_timeout
        f.monitor = _FakeMonitor()
        f.log = _FakeLog()
        return f

    def test_hard_set_recv_timeout_preserved(self):
        from src.oida.fuzz.core.base_fuzzer import BaseFuzzer

        f = self._make_fuzzer(recv_timeout=3.0)
        BaseFuzzer._calibrate_timeouts(f, f.log)
        assert f.config.recv_timeout == 3.0  # user value untouched
        assert f.monitor.timeout != 0.1  # monitor oracle still calibrated

    def test_unset_recv_timeout_is_calibrated(self):
        from src.oida.fuzz.core.base_fuzzer import BaseFuzzer

        f = self._make_fuzzer(recv_timeout=None)
        BaseFuzzer._calibrate_timeouts(f, f.log)
        assert f.config.recv_timeout is not None  # filled in by calibration

    def test_no_calibrate_is_a_noop(self):
        from src.oida.fuzz.core.base_fuzzer import BaseFuzzer

        f = self._make_fuzzer(recv_timeout=None)
        f.config.calibrate = False
        BaseFuzzer._calibrate_timeouts(f, f.log)
        assert f.config.recv_timeout is None  # disabled -> nothing changed
        assert f.monitor.timeout == 0.1
