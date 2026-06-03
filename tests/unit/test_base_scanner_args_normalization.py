"""BaseScanner.__init__ must use the normalized self.args, not raw args.

CODE_REVIEW.md HIGH base_scanner.py:89-93. Raw argparse.Namespace lacks
.get(), so any code path that hits BaseScanner with a Namespace (not a
dict) raised AttributeError on the .get('debug', False) lookups.
"""

import argparse
import pathlib
import unittest


class TestBaseScannerArgsNormalization(unittest.TestCase):
    def test_source_uses_self_args_get(self):
        """The fix replaced raw args.get(...) with self.args.get(...)."""
        src = pathlib.Path("src/oida/utils/base_scanner.py").read_text()
        # Before fix: parse_bool(args.get("debug", False))
        # After fix: parse_bool(self.args.get("debug", False))
        # Look at the specific snippet
        self.assertIn(
            'parse_bool(self.args.get("debug", False))',
            src,
            "args lookup regression - must use self.args",
        )
        self.assertIn(
            'parse_bool(self.args.get("read-only", True))',
            src,
        )
        self.assertIn('int(self.args.get("timeout", 2))', src)

    def test_normalize_returns_dict_passthrough(self):
        """Dict input must pass through unchanged (no wrapping cost)."""
        from oida.utils.base_scanner import _normalize_args

        d = {"a": 1, "b": 2}
        out = _normalize_args(d)
        self.assertIs(out, d)

    def test_normalize_wraps_namespace(self):
        """argparse.Namespace gets a .get() method via the bridge."""
        from oida.utils.base_scanner import _normalize_args

        ns = argparse.Namespace(host="127.0.0.1", port=502, timeout=5)
        bridge = _normalize_args(ns)
        # Both attribute and dict-style access work.
        self.assertEqual(bridge.host, "127.0.0.1")
        self.assertEqual(bridge.get("port"), 502)
        self.assertEqual(bridge.get("missing", "default"), "default")
        self.assertIn("host", bridge)


if __name__ == "__main__":
    unittest.main()
