"""Garbled exception-log messages from earlier refactor are descriptive.

CODE_REVIEW.md HIGH discovery (21 sites). Earlier the refactor produced
'Failed to get <local_var>' messages that lost operation context.
"""

import pathlib
import re
import unittest


class TestNoGarbledFailedToGetMessages(unittest.TestCase):
    def test_no_failed_to_get_ts_str(self):
        for f in pathlib.Path("src/oida/protocols/discovery").glob("*.py"):
            src = f.read_text()
            # Pattern: f"Failed to get <local_var>: {e}" — vague
            matches = re.findall(r'"Failed to get [a-z_]+: \{e\}"', src)
            self.assertFalse(matches, f"{f.name} still has garbled logs: {matches}")

    def test_descriptive_replacements_present(self):
        # Spot-check a few that should be there now.
        stats = pathlib.Path("src/oida/protocols/discovery/stats.py").read_text()
        self.assertIn("stats: packet timestamp parse failed", stats)
        self.assertIn("stats: TCP src/dst port parse failed", stats)
        self.assertIn("stats: TCP flags hex parse failed", stats)

        enrich = pathlib.Path("src/oida/protocols/discovery/enrich.py").read_text()
        self.assertIn("enrich: ping latency probe failed", enrich)
        self.assertIn("enrich: reverse-DNS lookup failed", enrich)


if __name__ == "__main__":
    unittest.main()
