#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regression test: a non-UTF-8 byte in a custom AET wordlist must not abort the
whole AET brute-force scan.

Bug: `_aet_brute_force` opened the wordlist with the platform default text
encoding (`open(wordlist_file, "r")`, no `errors=`). A single non-UTF-8 byte
(e.g. a Windows/cp1252-authored wordlist) raised UnicodeDecodeError while
iterating the file object; the broad `except Exception` around the load
caught it, logged "Failed to load wordlist", and `return`ed immediately --
discarding every AET already read and skipping the whole scan. This mirrors
the wordlist-encoding bug already fixed for credential/password wordlists in
commits ad06ea4 / dec74e6 (see `oida.utils.login_scanner._load_file_lines`).
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from tests.service_gate import require_import

require_import(
    "pynetdicom", reason="pynetdicom not installed; install via `pip install -e .[dicom]`"
)

from tests.unit.dicom.test_mixins_enum_ops import BruteAE, _args  # noqa: E402
from tests.unit.dicom.test_scanner import _make_dicom_instance  # noqa: E402


class TestAetWordlistNonUtf8Byte(unittest.TestCase):
    def test_invalid_utf8_line_does_not_abort_scan(self):
        import oida.protocols.dicom as pkg

        with tempfile.TemporaryDirectory() as tmp:
            wl = Path(tmp) / "aets.txt"
            # A valid AET, then a line with a raw non-UTF-8 byte, then another
            # valid AET. A naive text-mode `open(..., "r")` raises
            # UnicodeDecodeError partway through iteration on the bad line.
            wl.write_bytes(b"FIRSTAE\n\xff\xfeBADLINE\nSECONDAE\n")

            verdicts = {"FIRSTAE": "ok", "SECONDAE": "ok"}
            fake_ae = BruteAE(verdicts)
            scanner = _make_dicom_instance(
                _args(confirm=True, aet_brute=str(wl), ae_wordlist=str(wl), common_ae=False)
            )
            scanner.logger = Mock()
            scanner.called_aet = "ANY"

            orig = pkg.AE
            pkg.AE = fake_ae
            try:
                scanner._aet_brute_force()
            finally:
                pkg.AE = orig

            # Before the fix: the load raised mid-iteration, the except block
            # logged "Failed to load wordlist" and returned early, so
            # results["data"] never gained an "aet_brute" key at all.
            self.assertIn(
                "aet_brute",
                scanner.results["data"],
                "wordlist load aborted the scan instead of tolerating the bad byte",
            )
            res = scanner.results["data"]["aet_brute"]
            self.assertIn("FIRSTAE", res["valid"])
            self.assertIn("SECONDAE", res["valid"])

            fail_text = " ".join(
                str(c.args[0]) for c in scanner.logger.fail.call_args_list if c.args
            )
            self.assertNotIn("Failed to load wordlist", fail_text)


if __name__ == "__main__":
    unittest.main()
