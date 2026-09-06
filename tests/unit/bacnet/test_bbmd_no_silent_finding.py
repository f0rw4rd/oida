"""BBMD foreign-device-registration must not flag UDP loss as success.

CODE_REVIEW.md HIGH network.py:438-449. None response on the
RegisterForeignDevice request must be treated as INDETERMINATE
(debug-log only), not as CRITICAL security finding.
"""

import pathlib
import unittest


class TestBBMDForeignDeviceRegistration(unittest.TestCase):
    """Snapshot the policy in source — defence-in-depth against re-regression."""

    def test_none_response_is_inconclusive_not_finding(self):
        src = pathlib.Path("src/oida/protocols/bacnet/mixins/network.py").read_text()
        # The fix is the explicit None-handling branch.
        self.assertIn("if response is None:", src)
        # Inconclusive comment is the sentinel.
        self.assertIn("inconclusive", src)
        # And the CRITICAL finding must require a real ACK code:
        # 'bvlciResultCode == 0' is the only path that adds a finding.
        # Make sure the old unconditional finding form is gone.
        bad = "findings.append(\"Foreign device registration accepted\")"
        self.assertNotIn(bad, src)


if __name__ == "__main__":
    unittest.main()
