#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression tests for target-parsing bounds (F5) and mixed-spec handling (F6).

F5 (core bug hunt): the range size cap checked ``end - start > max``, admitting
a range of exactly ``max + 1`` addresses while the error message itself counts
inclusively (``end - start + 1 addresses. Maximum: 65536``).
``parse_ip_range("10.0.0.0-10.1.0.0")`` returned 65537 addresses - one MORE than
a /16's usable host count, i.e. precisely the overflow the cap exists to stop.
The IPv6 range cap (parse_ipv6_range) has the identical shape.

F6: a mixed spec such as ``192.168.1.1-scan`` passed ``is_ip_range`` (which only
validates the first half) and then blew up with an uncaught ValueError out of
``parse_targets``. It is a hostname-looking token, not a crash-worthy input.
"""

import unittest

from oida.targets import (
    parse_cidr,
    parse_ip_range,
    parse_ipv6_range,
    parse_targets,
)

MAX = 65536


class TestRangeSizeCap(unittest.TestCase):
    def test_ipv4_range_at_exactly_max_is_allowed(self):
        """65536 addresses == the documented maximum, must pass."""
        res = parse_ip_range("10.0.0.0-10.0.255.255")
        self.assertEqual(len(res), MAX)

    def test_ipv4_range_one_over_max_is_rejected(self):
        """65537 addresses must be rejected, not silently accepted."""
        with self.assertRaises(ValueError):
            parse_ip_range("10.0.0.0-10.1.0.0")

    def test_ipv6_range_one_over_max_is_rejected(self):
        """The IPv6 cap must match the IPv4 semantics (end - start > max is off by one)."""
        start = int.from_bytes(bytes(16), "big")
        with self.assertRaises(ValueError):
            parse_ipv6_range(
                f"[{_v6(start)}]-[{_v6(start + MAX + 1)}]"
            )

    def test_cidr_cap_is_consistent(self):
        """A /15 (131070 hosts) must stay rejected - anchor for the cap's intent."""
        with self.assertRaises(ValueError):
            parse_cidr("10.0.0.0/15")


def _v6(n: int) -> str:
    import ipaddress

    return str(ipaddress.IPv6Address(n))


class TestMixedSpecHandling(unittest.TestCase):
    def test_ip_dash_hostname_degrades_to_single_target(self):
        """`192.168.1.1-scan` is not a valid range - must not raise out of parse_targets."""
        res = parse_targets("192.168.1.1-scan")
        self.assertEqual(res, ["192.168.1.1-scan"])

    def test_ip_dash_empty_degrades_to_single_target(self):
        res = parse_targets("192.168.1.1-")
        self.assertEqual(res, ["192.168.1.1-"])

    def test_valid_range_still_expands(self):
        res = parse_targets("192.168.1.1-5")
        self.assertEqual(res, ["192.168.1.1", "192.168.1.2", "192.168.1.3",
                               "192.168.1.4", "192.168.1.5"])

    def test_reversed_range_still_raises(self):
        """A *well-formed* but reversed range is operator error - keep the error."""
        with self.assertRaises(ValueError):
            parse_targets("192.168.1.5-1")

    def test_host_port_numeric_path_does_not_raise(self):
        """`host:8080/2` heuristic must degrade, not fall into parse_cidr and raise."""
        res = parse_targets("10.0.0.1:8080/2")
        self.assertEqual(res, ["10.0.0.1:8080/2"])


if __name__ == "__main__":
    unittest.main()
