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


if __name__ == "__main__":
    unittest.main()
