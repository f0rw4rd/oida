"""Behavioral tests for NetworkConnection/SerialConnection args isolation.

The CLI dispatcher reuses a single argparse Namespace across protocol
invocations in the same process. connection.py:384-432 (NetworkConnection
and SerialConnection __init__) deep-copies that Namespace before writing
args.port, so that (a) the caller's original Namespace is never mutated
with a protocol's default port, and (b) mutable attributes on args (lists,
dicts, sets such as scan_range) are not aliased across two invocations
that share the same underlying Namespace object. A shallow copy or no
copy at all would leak state from one protocol scan into the next.

These tests construct real NetworkConnection/SerialConnection subclasses
(autostart=False, so no actual scan runs) and assert the deep-copy
contract directly, plus the _resolve_host() guard against inputs that
getaddrinfo rejects outright (UnicodeError/gaierror).
"""

import argparse
import unittest

from oida.connection import NetworkConnection, SerialConnection


class _NoopNetwork(NetworkConnection):
    default_port = 1234

    def proto_flow(self):
        pass

    def create_conn_obj(self):
        pass

    def enum_host_info(self):
        pass


class _NoopSerial(SerialConnection):
    default_port = 5678

    def proto_flow(self):
        pass

    def create_conn_obj(self):
        pass

    def enum_host_info(self):
        pass


def _make_args(**overrides):
    ns = argparse.Namespace(port=None, verbose=0, scan_range=[1, 2])
    for k, v in overrides.items():
        setattr(ns, k, v)
    return ns


class TestNetworkConnectionArgsNotMutated(unittest.TestCase):
    def test_caller_namespace_port_not_mutated(self):
        args = _make_args()
        _NoopNetwork(args, None, "127.0.0.1", autostart=False)
        self.assertIsNone(args.port)

    def test_instance_args_port_set_to_default(self):
        args = _make_args()
        conn = _NoopNetwork(args, None, "127.0.0.1", autostart=False)
        self.assertEqual(conn.args.port, 1234)

    def test_mutable_attr_on_instance_args_not_aliased_to_caller(self):
        args = _make_args()
        conn = _NoopNetwork(args, None, "127.0.0.1", autostart=False)
        conn.args.scan_range.append(999)
        self.assertEqual(args.scan_range, [1, 2])


class TestSerialConnectionArgsNotMutated(unittest.TestCase):
    def test_caller_namespace_not_mutated(self):
        args = _make_args(interface="eth0")
        _NoopSerial(args, None, "eth0", autostart=False)
        self.assertEqual(args.scan_range, [1, 2])

    def test_mutable_attr_on_instance_args_not_aliased_to_caller(self):
        args = _make_args(interface="eth0")
        conn = _NoopSerial(args, None, "eth0", autostart=False)
        conn.args.scan_range.append(999)
        self.assertEqual(args.scan_range, [1, 2])


class TestResolveHostRejectsUnresolvableInput(unittest.TestCase):
    def test_overlong_label_returns_input_unchanged_without_raising(self):
        args = _make_args()
        conn = _NoopNetwork(args, None, "127.0.0.1", autostart=False)
        bad_host = "a" * 70 + ".example"
        result = conn._resolve_host(bad_host)
        self.assertEqual(result, bad_host)


if __name__ == "__main__":
    unittest.main()
