#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""SerialConnection must NOT mutate the caller's args Namespace.

Bug (core bug hunt): ``NetworkConnection.__init__`` deep-copies ``args`` before
touching it, with a comment documenting why - the shared CLI Namespace is reused
across protocol dispatches, and mutable attributes (lists/dicts/sets such as
``scan_range``) alias across the two Layer-2 stacks a single process may run.
``SerialConnection.__init__`` had no such copy, so a serial protocol mutating
``self.args.scan_range`` in place (or setting ``self.args.port``) wrote straight
through into the caller's Namespace and bled into the next protocol invocation.

Reproduced before the fix:
    SERIAL   before=([1, 2, 3], None)  after=([1, 2, 3], 999)  CALLER MUTATED=True
    NETWORK  before=([1, 2, 3], None)  after=([1, 2, 3], None) CALLER MUTATED=False
"""

import argparse
import unittest

from oida.connection import NetworkConnection, SerialConnection


def _concrete(base, **extra):
    """Build a minimal concrete subclass whose proto_flow mutates args in place."""
    body = {
        "create_conn_obj": lambda self: True,
        "enum_host_info": lambda self: None,
        "print_host_info": lambda self: None,
        # What a real serial scanner does: append to a list attr + set a port.
        "proto_flow": lambda self: (
            self.args.scan_range.append(999),
            setattr(self.args, "port", 4711),
        ),
    }
    body.update(extra)
    return type("Fake" + base.__name__, (base,), body)


def _namespace():
    return argparse.Namespace(
        interface=None,
        port=None,
        scan_range=[1, 2, 3],
        verbose=0,
        debug=False,
        timeout=5,
    )


class TestSerialConnectionArgsIsolation(unittest.TestCase):
    def test_serial_does_not_mutate_caller_namespace(self):
        """SerialConnection must isolate the caller's Namespace like Network does."""
        cls = _concrete(SerialConnection)
        ns = _namespace()
        before = (list(ns.scan_range), ns.port)
        cls(ns, None, "eth0")
        after = (list(ns.scan_range), ns.port)
        self.assertEqual(
            after,
            before,
            "SerialConnection leaked mutations into the caller's shared Namespace",
        )

    def test_network_does_not_mutate_caller_namespace(self):
        """The NetworkConnection guard (regression anchor for the same class of bug)."""
        cls = _concrete(NetworkConnection, default_port=502)
        ns = _namespace()
        before = (list(ns.scan_range), ns.port)
        cls(ns, None, "10.0.0.1")
        after = (list(ns.scan_range), ns.port)
        self.assertEqual(after, before)

    def test_serial_instance_sees_its_own_mutation(self):
        """Isolation must not break the scanner itself - it still sees its writes."""
        holder = {}

        def flow(self):
            self.args.scan_range.append(999)
            holder["instance_args"] = self.args

        cls = _concrete(SerialConnection, proto_flow=flow)
        ns = _namespace()
        inst = cls(ns, None, "eth0")
        self.assertIn(999, inst.args.scan_range)
        self.assertIsNot(inst.args, ns, "scanner should operate on its own copy")


if __name__ == "__main__":
    unittest.main()
