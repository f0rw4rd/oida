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

    def test_normalize_wraps_plain_dict_for_key_normalization(self):
        """A plain dict is wrapped in ArgsDict so hyphen/underscore key spellings
        agree — the Layer-1 dict path used to skip this, unlike the Namespace
        bridge, so a dashed read silently missed. Values are preserved; the
        result is still a dict."""
        from oida.utils.args_dict import ArgsDict
        from oida.utils.base_scanner import _normalize_args

        d = {"unit-id": 1, "b": 2}
        out = _normalize_args(d)
        self.assertIsInstance(out, ArgsDict)
        self.assertIsInstance(out, dict)
        self.assertEqual(out["unit_id"], 1)  # dashed input, underscore read
        self.assertEqual(out["unit-id"], 1)
        self.assertEqual(out["b"], 2)

    def test_normalize_passes_argsdict_through_unchanged(self):
        """An already-normalizing ArgsDict is returned as-is (idempotent, no
        double-wrap)."""
        from oida.utils.args_dict import ArgsDict
        from oida.utils.base_scanner import _normalize_args

        d = ArgsDict({"a": 1})
        self.assertIs(_normalize_args(d), d)

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
