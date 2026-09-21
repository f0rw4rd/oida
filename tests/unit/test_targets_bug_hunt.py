#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression tests for repo-wide bug-hunt finds in ``oida.targets``.

D1 -- empty targets scanned localhost. An empty or whitespace-only spec (a
     stray comma in a list, a host-less ``:502``, ``[]``) expanded to one
     EMPTY target string, and ``socket.connect(("", port))`` resolves to
     127.0.0.1. A scanner silently probing the operator's own machine instead
     of the host they typed is a wrong-target hazard, not a cosmetic one.
     Empty specs now expand to nothing; the CLI already reports an empty
     expansion as "No valid targets found".

D2 -- the target-file cycle guard was bypassed. ``parse_target_file`` tracks
     visited realpaths, but only passed that set down when a *whole line* was
     itself a file path. A comma-separated line (``/tmp/a.txt,1.2.3.4``) goes
     through ``parse_targets``, which called ``parse_target_file`` with a fresh
     set -- so a self-referencing file recursed until RecursionError, after
     queueing hundreds of duplicate scans of the same host (98 under a
     lowered recursion limit, ~330 at the default).

D3 -- ``[a]-[b]:port`` was mangled. The module contract is that every target
     form may carry a ``:port`` suffix, but for a bracketed IPv6 range the port
     sits after the range's closing bracket, which ``split_host_port`` (a
     single-host parser) cannot see. The spec fell through every branch and
     landed in the single-target tail, which stripped the leading "[" and
     produced one unusable target.
"""

import os
import sys
import unittest

from oida.targets import parse_target_file, parse_targets


class TestEmptyTargetsDoNotBecomeLocalhost(unittest.TestCase):
    def test_empty_spec_expands_to_nothing(self):
        self.assertEqual(parse_targets(""), [])
        self.assertEqual(parse_targets("   "), [])

    def test_stray_comma_does_not_add_an_empty_target(self):
        self.assertEqual(parse_targets("1.2.3.4,,5.6.7.8"), ["1.2.3.4", "5.6.7.8"])
        self.assertEqual(parse_targets("1.2.3.4, ,5.6.7.8"), ["1.2.3.4", "5.6.7.8"])

    def test_hostless_port_is_not_a_target(self):
        """ ":502" must not become a scan of 127.0.0.1:502."""
        self.assertEqual(parse_targets(":502"), [])
        self.assertEqual(parse_targets("[]:502"), [])
        self.assertEqual(parse_targets("[]"), [])

    def test_empty_host_would_have_meant_localhost(self):
        """Pin the premise: connecting to "" really is connecting to 127.0.0.1."""
        import socket

        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            # socket.connect (unlike create_connection/getaddrinfo) maps the
            # empty host to INADDR_ANY, which the stack routes to loopback.
            client = socket.socket()
            client.settimeout(2)
            try:
                client.connect(("", port))
                self.assertEqual(client.getpeername()[0], "127.0.0.1")
            finally:
                client.close()
        finally:
            server.close()

    def test_surrounding_whitespace_is_trimmed(self):
        self.assertEqual(parse_targets("  10.0.0.1  "), ["10.0.0.1"])


class TestTargetFileCycleGuard(unittest.TestCase):
    def _write(self, tmpdir, name, content):
        path = os.path.join(tmpdir, name)
        with open(path, "w") as fh:
            fh.write(content)
        return path

    def test_self_reference_on_a_comma_line_terminates(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.txt")
            self._write(tmp, "a.txt", f"{path},1.2.3.4\n")

            limit = sys.getrecursionlimit()
            sys.setrecursionlimit(300)  # fail fast if the guard regresses
            try:
                targets = parse_target_file(path)
            finally:
                sys.setrecursionlimit(limit)

        # Exactly one expansion of the file, not one per recursion level.
        self.assertEqual(targets, ["1.2.3.4"])

    def test_mutual_reference_between_two_files_terminates(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            a = os.path.join(tmp, "a.txt")
            b = os.path.join(tmp, "b.txt")
            self._write(tmp, "a.txt", f"{b},10.0.0.1\n")
            self._write(tmp, "b.txt", f"{a},10.0.0.2\n")

            limit = sys.getrecursionlimit()
            sys.setrecursionlimit(300)
            try:
                targets = parse_target_file(a)
            finally:
                sys.setrecursionlimit(limit)

        self.assertEqual(sorted(targets), ["10.0.0.1", "10.0.0.2"])

    def test_direct_self_reference_still_guarded(self):
        """The pre-existing whole-line case must keep working."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.txt")
            self._write(tmp, "a.txt", f"{path}\n9.9.9.9\n")
            self.assertEqual(parse_target_file(path), ["9.9.9.9"])


class TestIPv6RangeWithPort(unittest.TestCase):
    def test_range_port_is_attached_to_every_expanded_target(self):
        self.assertEqual(
            parse_targets("[2001:db8::1]-[2001:db8::3]:5020"),
            ["[2001:db8::1]:5020", "[2001:db8::2]:5020", "[2001:db8::3]:5020"],
        )

    def test_portless_range_is_unchanged(self):
        self.assertEqual(
            parse_targets("[2001:db8::1]-[2001:db8::3]"),
            ["2001:db8::1", "2001:db8::2", "2001:db8::3"],
        )

    def test_attached_port_round_trips_through_split_host_port(self):
        from oida.targets import split_host_port

        targets = parse_targets("[2001:db8::1]-[2001:db8::2]:5020")
        self.assertEqual(
            [split_host_port(t) for t in targets],
            [("2001:db8::1", 5020), ("2001:db8::2", 5020)],
        )


if __name__ == "__main__":
    unittest.main()
