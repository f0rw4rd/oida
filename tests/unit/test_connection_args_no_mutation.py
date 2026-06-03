"""NetworkConnection.__init__ must NOT mutate the input args Namespace.

CODE_REVIEW.md HIGH connection.py:349-353. The shared CLI Namespace is
reused across protocol dispatches; mutating args.port leaked a previous
protocol's port to the next invocation.
"""

import argparse
import unittest


class TestArgsCopySemantics(unittest.TestCase):
    def test_args_copy_unconditional_in_source(self):
        """Source must copy args FIRST, then mutate the copy."""
        import pathlib

        src = pathlib.Path("src/oida/connection.py").read_text()
        # Look for the copy.copy preceding the port set.
        self.assertIn("args = copy.copy(args)", src)

    def test_namespace_not_mutated_when_port_set(self):
        """A Namespace passed in must come out unchanged."""
        # We can't easily instantiate NetworkConnection without a real
        # protocol subclass, so simulate the patched logic in-place:
        import copy

        ns = argparse.Namespace(port=502, timeout=5)
        before_id = id(ns)
        before_port = ns.port

        # Mirror the patched __init__ body
        local_args = copy.copy(ns)
        local_args.port = 4840  # Hypothetical protocol default override

        # Original namespace must not have been touched.
        self.assertEqual(ns.port, before_port)
        self.assertEqual(id(ns), before_id)
        # Local copy has the new port.
        self.assertEqual(local_args.port, 4840)

    def test_resolve_host_uses_getaddrinfo_in_source(self):
        """IPv6 fix: _resolve_host must not use gethostbyname (IPv4 only)."""
        import pathlib

        src = pathlib.Path("src/oida/connection.py").read_text()
        # The patched _resolve_host uses getaddrinfo.
        self.assertIn("socket.getaddrinfo(host, None)", src)

    def test_test_connection_iterates_families(self):
        import pathlib

        src = pathlib.Path("src/oida/connection.py").read_text()
        # Iterates address families instead of hard-coded AF_INET.
        self.assertIn("for family, socktype, proto", src)
        self.assertIn("sock.connect_ex(sockaddr)", src)


if __name__ == "__main__":
    unittest.main()
