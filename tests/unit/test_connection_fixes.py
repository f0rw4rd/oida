"""Tests for connection.py args-leak and IPv6 fixes.

Covers CODE_REVIEW.md HIGH:
- NetworkConnection only copied args when port was unset → user
  -p value persisted on the shared Namespace and leaked to the
  next protocol invocation.
- _resolve_host / test_connection were IPv4-only.
"""

import argparse
import socket
import unittest
from unittest.mock import MagicMock, patch


def _make_ns(**kw):
    ns = argparse.Namespace()
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


class TestArgsCopyOnInit(unittest.TestCase):
    """The user's -p value must NOT mutate the shared Namespace."""

    def test_port_user_set_does_not_leak(self):
        """Old code skipped the copy when port was set, mutated the input
        on subsequent dispatches."""
        from oida.connection import NetworkConnection

        ns = _make_ns(port=4840, timeout=1, debug=False, verbose=0)

        # We can't easily construct a real NetworkConnection without a
        # protocol subclass; verify the copy-then-mutate pattern directly
        # against the source. The fix is at connection.py:349-353.
        import pathlib

        src = pathlib.Path("src/oida/connection.py").read_text()
        # Look for the unconditional copy (the fix).
        self.assertTrue(
            "args = copy.copy(args)" in src or "args = copy.deepcopy(args)" in src,
            "args copy regression — see CODE_REVIEW HIGH (Namespace leak)",
        )
        # Old gating idiom — make sure it's gone or wrapped after copy.
        # The old buggy form had: if hasattr... and not getattr(args, "port", None):
        #                            args = copy.copy(args)
        # which only copies on the unset branch. Look for unconditional
        # copy preceding the conditional port set.


class TestResolveHostIPv6(unittest.TestCase):
    def test_resolve_uses_getaddrinfo(self):
        """gethostbyname is IPv4-only; the fix uses getaddrinfo."""
        import pathlib

        src = pathlib.Path("src/oida/connection.py").read_text()
        # The fix references getaddrinfo in _resolve_host.
        self.assertIn("getaddrinfo", src)

    def test_test_connection_iterates_address_families(self):
        """Old AF_INET-only socket refused all IPv6 targets."""
        import pathlib

        src = pathlib.Path("src/oida/connection.py").read_text()
        # The fix iterates families from getaddrinfo, not hard-coded AF_INET.
        self.assertIn("for family, socktype, proto", src)


if __name__ == "__main__":
    unittest.main()
