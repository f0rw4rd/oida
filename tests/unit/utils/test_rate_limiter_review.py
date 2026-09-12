#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression tests for the RateLimiter clock source.

Bug (core bug hunt): ``RateLimiter.wait()`` measured elapsed time with
``time.time()`` - the WALL clock.  Any backward clock adjustment during a scan
(NTP correction, manual ``date`` set, VM resume) makes ``elapsed`` negative, so::

    sleep_time = self.interval - elapsed

becomes roughly the size of the whole jump.  A one-hour step back turned a 0.1s
throttle into a 3600s sleep, hanging the scan.  A forward jump conversely stops
the throttle from being enforced at all - and this throttle is the OT-safety
mechanism that keeps active scans from saturating an industrial network.

The clock source must be ``time.monotonic()``, which cannot go backwards.
"""

import time
import unittest

from oida.utils.rate_limiter import RateLimiter


class _FakeClocks:
    """Drive the wall clock and the monotonic clock independently."""

    def __init__(self, start=1_000_000.0):
        self.wall = start
        self.mono = start
        self.sleeps = []

    def advance(self, seconds):
        """Advance both clocks, as real time passing would."""
        self.wall += seconds
        self.mono += seconds

    def step_wall(self, seconds):
        """Step ONLY the wall clock - an NTP correction. Monotonic is unaffected."""
        self.wall += seconds


class TestRateLimiterClockSource(unittest.TestCase):
    def setUp(self):
        self.clocks = _FakeClocks()
        self._real = (time.time, time.monotonic, time.sleep)
        time.time = lambda: self.clocks.wall
        time.monotonic = lambda: self.clocks.mono
        # Record requested sleeps instead of actually sleeping, and let the
        # monotonic clock advance by the slept amount as it would in reality.
        def fake_sleep(seconds):
            self.clocks.sleeps.append(seconds)
            self.clocks.advance(seconds)

        time.sleep = fake_sleep

    def tearDown(self):
        time.time, time.monotonic, time.sleep = self._real

    def test_normal_throttling_still_works(self):
        lim = RateLimiter(packets_per_second=10.0)  # interval 0.1s
        lim.wait()
        self.clocks.advance(0.01)
        lim.wait()
        self.assertAlmostEqual(self.clocks.sleeps[-1], 0.09, places=4)

    def test_backward_wall_clock_step_does_not_cause_a_huge_sleep(self):
        """An NTP step back one hour must NOT turn into a 3600s sleep."""
        lim = RateLimiter(packets_per_second=10.0)
        lim.wait()
        self.clocks.step_wall(-3600.0)  # wall clock jumps back; monotonic does not
        lim.wait()
        for slept in self.clocks.sleeps:
            self.assertLessEqual(
                slept,
                lim.interval,
                f"wait() requested a {slept:.1f}s sleep - clock source is not monotonic",
            )

    def test_forward_wall_clock_step_still_enforces_the_rate(self):
        """A forward NTP step must not silently disable the OT-safety throttle."""
        lim = RateLimiter(packets_per_second=10.0)
        lim.wait()
        self.clocks.step_wall(7200.0)  # wall clock jumps forward 2h
        lim.wait()  # no real time passed, so this MUST still throttle
        self.assertTrue(
            self.clocks.sleeps, "rate limit was not enforced after a forward clock step"
        )
        self.assertAlmostEqual(self.clocks.sleeps[-1], lim.interval, places=4)

    def test_unlimited_rate_never_sleeps(self):
        lim = RateLimiter(packets_per_second=0)
        self.assertEqual(lim.interval, 0)
        lim.wait()
        lim.wait()
        self.assertEqual(self.clocks.sleeps, [])

    def test_packet_count_is_tracked(self):
        lim = RateLimiter(packets_per_second=1000.0)
        for _ in range(5):
            self.clocks.advance(1.0)
            lim.wait()
        self.assertEqual(lim.packet_count, 5)
        lim.reset()
        self.assertEqual(lim.packet_count, 0)


if __name__ == "__main__":
    unittest.main()
