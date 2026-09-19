"""DCC brute-force / test-dcc / test-reinit must NOT treat timeout as success.

CODE_REVIEW.md HIGH bacnet/mixins/security.py:63-68. Earlier the
`_is_success_response` predicate returned True when response was None,
so any UDP packet loss was reported as 'weak password found'.
"""

import unittest
from unittest.mock import MagicMock


def _stub_types():
    """Mirror the dict structure _is_success_response expects."""

    class _Marker:
        pass

    return {
        "ErrorPDU": type("ErrorPDU", (_Marker,), {}),
        "ErrorRejectAbortNack": type("ErrorRejectAbortNack", (BaseException,), {}),
        "Error": type("Error", (_Marker,), {}),
        "AbortPDU": type("AbortPDU", (_Marker,), {}),
        "RejectPDU": type("RejectPDU", (_Marker,), {}),
    }


class TestIsSuccessResponseSemantics(unittest.TestCase):
    """Three-state truth table for _is_success_response."""

    def setUp(self):
        # Avoid touching __init__ side effects.
        from oida.protocols.bacnet.mixins.security import SecurityMixin

        self.mixin = SecurityMixin.__new__(SecurityMixin)
        self.mixin.logger = MagicMock()

    def test_none_response_is_not_success(self):
        """The bug fix: None means 'no reply' — INCONCLUSIVE, not success."""
        types = _stub_types()
        self.assertFalse(self.mixin._is_success_response(None, types))

    def test_error_pdu_is_not_success(self):
        types = _stub_types()
        self.assertFalse(self.mixin._is_success_response(types["ErrorPDU"](), types))

    def test_abort_pdu_is_not_success(self):
        types = _stub_types()
        self.assertFalse(self.mixin._is_success_response(types["AbortPDU"](), types))

    def test_reject_pdu_is_not_success(self):
        types = _stub_types()
        self.assertFalse(self.mixin._is_success_response(types["RejectPDU"](), types))

    def test_arbitrary_object_is_success(self):
        """A non-error response payload is the success case."""
        types = _stub_types()

        class _AckPDU:
            pass

        self.assertTrue(self.mixin._is_success_response(_AckPDU(), types))


if __name__ == "__main__":
    unittest.main()
