"""LazyModule._load() must be thread-safe.

Old bug: thread A could flip _loaded=True before _module was set;
thread B saw _loaded=True with _module=None and raised DependencyError
even though the install was fine. CODE_REVIEW.md HIGH.
"""

import threading
import unittest


class TestLazyModuleConcurrency(unittest.TestCase):
    def test_concurrent_load_yields_module_consistently(self):
        from oida.utils.lazy_import import LazyModule

        # Use a real lightweight stdlib module.
        lm = LazyModule(
            "json",
            protocol="TEST",
            install_hint="(no install needed)",
        )

        results = []
        errors = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            try:
                results.append(lm())
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
            self.assertFalse(t.is_alive(), "thread hung waiting for load lock")

        self.assertEqual(errors, [], f"unexpected errors: {errors}")
        self.assertEqual(len(results), 8)
        # All threads must get the SAME module object.
        first = results[0]
        for r in results[1:]:
            self.assertIs(r, first, "concurrent threads got different module instances")

    def test_lock_attribute_present(self):
        """Belt-and-braces: snapshot the threading.Lock import."""
        import pathlib

        src = pathlib.Path("src/oida/utils/lazy_import.py").read_text()
        self.assertIn("import threading", src)
        self.assertIn("threading.Lock()", src)
        self.assertIn("with self._load_lock:", src)


if __name__ == "__main__":
    unittest.main()
