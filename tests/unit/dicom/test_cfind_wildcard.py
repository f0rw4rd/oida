"""--find with no --patient-name must use wildcard '*'.

Old bug: argparse declares --patient-name with no default=, so
args.patient_name is None when omitted. getattr's '*' fallback never
fired (attribute exists, equals None), and the query went out with
PatientName=None. CODE_REVIEW.md HIGH.
"""

import unittest
from unittest.mock import MagicMock


class TestPatientNameWildcard(unittest.TestCase):
    def test_none_coerced_to_wildcard(self):
        """The 'or '*'' coercion is the fix; verify the operator pattern."""
        args = MagicMock()
        args.patient_name = None

        # This mirrors the patched line in cfind.py:
        patient_name = getattr(args, "patient_name", "*") or "*"
        self.assertEqual(patient_name, "*")

    def test_user_supplied_value_passes_through(self):
        args = MagicMock()
        args.patient_name = "SMITH^JOHN"
        patient_name = getattr(args, "patient_name", "*") or "*"
        self.assertEqual(patient_name, "SMITH^JOHN")

    def test_source_uses_or_coercion(self):
        """Belt-and-braces: snapshot the fix is in the source."""
        import pathlib

        src = pathlib.Path("src/oida/protocols/dicom/mixins/cfind.py").read_text()
        self.assertIn(
            'getattr(self.args, "patient_name", "*") or "*"',
            src,
            "CODE_REVIEW HIGH fix regressed: --find no longer coerces None→*",
        )


if __name__ == "__main__":
    unittest.main()
