"""OPC UA --fuzz / --duration / --policy / URL parsing fixes.

CODE_REVIEW.md HIGH:
- mixins/fuzz.py:26 - --fuzz bool-vs-str disabled all fuzz modes
- mixins/subscriptions.py:18 - --duration ignored (wrong dest name)
- nxc_connection.py:196 - --policy None silent upgrade to Basic256Sha256
"""

import pathlib
import unittest


def _read(rel):
    return pathlib.Path(rel).read_text()


class TestFuzzBoolFix(unittest.TestCase):
    def test_fuzz_falls_through_to_nodes_mode(self):
        src = _read("src/oida/protocols/opcua/mixins/fuzz.py")
        # The fix introduces a 'fuzz_mode = "nodes"' fallback when
        # args.fuzz is bool True.
        self.assertIn('fuzz_mode = getattr(self.args, "fuzz_mode", "nodes")', src)
        self.assertIn('or "nodes"', src)


class TestDurationArgNameFix(unittest.TestCase):
    def test_subscription_reads_duration_attr(self):
        src = _read("src/oida/protocols/opcua/mixins/subscriptions.py")
        # Reads args.duration (the argparse dest) rather than the
        # never-existing subscribe_duration dest.
        # Whitespace-tolerant check — ruff format may flow this differently.
        self.assertIn(
            'getattr(self.args, "duration", None)',
            src.replace("\n", " ").replace("  ", " ").replace("  ", " ").replace("  ", " "),
        )
        self.assertNotIn("subscribe_duration", src)


class TestPolicyNoneUpgradeWarning(unittest.TestCase):
    def test_mode_sign_with_policy_none_warns_and_upgrades(self):
        src = _read("src/oida/protocols/opcua/nxc_connection.py")
        # The fix emits a warning when --mode Sign|SignAndEncrypt is
        # paired with --policy None, then sets requested_policy.
        self.assertIn(
            'if needs_secure_channel and requested_policy == "None":',
            src,
        )
        self.assertIn(
            "Upgrading to Basic256Sha256",
            src,
        )
        self.assertIn('requested_policy = "Basic256Sha256"', src)


class TestNormalizeUrlSourceNoDoubling(unittest.TestCase):
    def test_ipv6_with_port_branch(self):
        src = _read("src/oida/protocols/opcua/helpers.py")
        # The fix detects bracketed IPv6, looks for ':' after closing ']'.
        self.assertIn('if target.startswith("[")', src)
        self.assertIn("target[close + 1 :]", src)


if __name__ == "__main__":
    unittest.main()
