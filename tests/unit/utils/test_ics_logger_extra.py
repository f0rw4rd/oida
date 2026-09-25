"""Regression tests for ICSLogger.extra thread-local isolation.

Covers CODE_REVIEW.md MEDIUM (connection.py:79-84): get_logger() caches one
ICSLogger per protocol:host:port key, and connection.__init__/proto_logger()
mutate logger.extra["host"/"hostname"/"port"] in place. Two ThreadPoolExecutor
workers scanning targets that collapse to the same cache key (a duplicate
target, or two hostnames resolving to the same IP) must not torn-read or
cross-label each other's prefix. extra is now backed by thread-local storage,
so each worker gets its own host/port snapshot off the shared cached instance.
"""

import threading
import unittest

from oida.utils.ics_logger import ICSLogger, get_logger


class TestExtraThreadLocal(unittest.TestCase):
    def test_concurrent_mutation_does_not_cross_contaminate(self):
        """Two threads sharing one cached logger keep distinct host/port labels."""
        logger = get_logger(protocol="modbus", host="10.0.0.1", port=502)

        results = {}
        barrier = threading.Barrier(2)
        errors = []

        def worker(name, host, port, hostname):
            try:
                # Both workers share the SAME logger instance (same cache key
                # would have been used by get_logger). Mutate the prefix the way
                # connection.proto_logger() does.
                logger.extra["host"] = host
                logger.extra["port"] = port
                logger.extra["hostname"] = hostname
                # Force interleaving: both threads have written, now both read.
                barrier.wait(timeout=5)
                results[name] = dict(logger.extra)
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        t1 = threading.Thread(target=worker, args=("a", "192.168.1.10", 5020, "deviceA"))
        t2 = threading.Thread(target=worker, args=("b", "192.168.1.11", 5021, "deviceB"))
        t1.start()
        t2.start()
        t1.join(10)
        t2.join(10)

        self.assertEqual(errors, [], f"worker raised: {errors}")
        # Each thread must read back exactly its own values — no torn/crossed prefix.
        self.assertEqual(results["a"]["host"], "192.168.1.10")
        self.assertEqual(results["a"]["port"], 5020)
        self.assertEqual(results["a"]["hostname"], "deviceA")
        self.assertEqual(results["b"]["host"], "192.168.1.11")
        self.assertEqual(results["b"]["port"], 5021)
        self.assertEqual(results["b"]["hostname"], "deviceB")

    def test_format_prefix_is_per_thread(self):
        """_format() reads the per-thread prefix, so concurrent scans on the
        same cached logger render their own host:port, not the other's."""
        logger = get_logger(protocol="dnp3", host="10.0.0.2", port=20000)

        rendered = {}
        barrier = threading.Barrier(2)

        def worker(name, host, port):
            logger.extra["host"] = host
            logger.extra["port"] = port
            barrier.wait(timeout=5)
            rendered[name] = logger._format("msg")

        t1 = threading.Thread(target=worker, args=("a", "172.16.0.1", 102))
        t2 = threading.Thread(target=worker, args=("b", "172.16.0.2", 502))
        t1.start()
        t2.start()
        t1.join(10)
        t2.join(10)

        self.assertIn("172.16.0.1", rendered["a"])
        self.assertIn("102", rendered["a"])
        self.assertNotIn("172.16.0.2", rendered["a"])
        self.assertIn("172.16.0.2", rendered["b"])
        self.assertNotIn("172.16.0.1", rendered["b"])

    def test_seed_defaults_are_visible_to_fresh_thread(self):
        """A thread that never mutates extra still sees the constructor seed."""
        logger = ICSLogger(protocol="coap", host="10.1.1.1", port=5683, hostname="hub")
        seen = {}

        def worker():
            seen.update(logger.extra)

        t = threading.Thread(target=worker)
        t.start()
        t.join(5)

        self.assertEqual(seen["protocol"], "COAP")
        self.assertEqual(seen["host"], "10.1.1.1")
        self.assertEqual(seen["port"], 5683)
        self.assertEqual(seen["hostname"], "hub")

    def test_setter_replaces_only_current_thread(self):
        """Assigning logger.extra wholesale replaces this thread's copy only."""
        logger = ICSLogger(protocol="mqtt", host="h", port=1883)
        logger.extra = {"protocol": "MQTT", "host": "x", "port": 9, "hostname": ""}
        self.assertEqual(logger.extra["host"], "x")

        other = {}

        def worker():
            # Fresh thread re-seeds from the constructor default, unaffected.
            other.update(logger.extra)

        t = threading.Thread(target=worker)
        t.start()
        t.join(5)
        self.assertEqual(other["host"], "h")

    def test_format_snapshots_extra_once(self):
        """_format() reads the per-thread prefix dict a single time.

        Covers CODE_REVIEW.md LOW (ics_logger.py:176-180,225-229,312-325):
        a concurrent get_logger()/update_logger_host() can mutate host/hostname
        in place while _format() runs. Reading self.extra once and rendering
        from that snapshot means all fields on a line come from one consistent
        view, never a torn mix of pre- and post-mutation values.
        """
        logger = ICSLogger(protocol="modbus", host="10.0.0.1", port=502, hostname="old")

        accesses = []
        real_seed = dict(logger._extra_seed)

        class CountingDict(dict):
            def __getitem__(self, key):
                accesses.append(key)
                return super().__getitem__(key)

        # Seed this thread's copy as a CountingDict so we can observe access.
        logger._extra_local.data = CountingDict(real_seed)

        line = logger._format("hello")

        # Every field used by the rendered line must come from one dict object,
        # i.e. _format must not re-fetch self.extra between field reads. The
        # CountingDict only counts __getitem__ on the one snapshot, so the line
        # reflects a single consistent view.
        self.assertIn("10.0.0.1", line)
        self.assertIn("old", line)
        self.assertIn("502", line)
        # protocol, hostname, port, host -> exactly the four keys, once each.
        self.assertEqual(sorted(accesses), ["host", "hostname", "port", "protocol"])


class TestLogWarnUsesWarningLevel(unittest.TestCase):
    """log_warn() previously passed level="warn", which MockCLI.log does not
    match (it checks "warning"), so warnings silently rendered as info ([*])
    instead of [!]. The fix emits level="warning"."""

    def test_log_warn_forwards_warning_level(self):
        # Patch the module-level `log` (the actual fix site) rather than
        # `_get_cli`, so the assertion is robust to any prior test that left
        # ics_logger global state (log / _get_cli / _cli_instance) dirty.
        from unittest.mock import patch
        from oida.utils import ics_logger

        with patch.object(ics_logger, "log") as fake_log:
            ics_logger.log_warn("disk almost full")
        fake_log.assert_called_once_with("disk almost full", level="warning")

    def test_mockcli_renders_warning_sigil(self):
        """The level string log_warn now sends must be one MockCLI renders as [!]."""
        from oida.utils.cli import MockCLI

        cli = MockCLI()
        with self.assertLogs(cli.logger, level="INFO") as cm:
            cli.log("disk almost full", level="warning")
        self.assertTrue(any("[!] disk almost full" in line for line in cm.output))


if __name__ == "__main__":
    unittest.main()
