#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression tests for ``--format`` dispatch in export_utils.

Bug (core bug hunt): ``export_table()`` only had branches for ``csv``/``json``/
``xml``.  Every other value that ``oida --format`` accepts fell straight through
the dispatch loop, so **no file was written and the function still returned
True**.  That silently broke the two documented invocations:

    oida modbus HOST -o results --format all   # wrote nothing
    oida modbus HOST -o results                # default fmt "console", wrote nothing

A typo (``--format jsonn`` via the library API) was equally silent.
"""

import os
import tempfile
import unittest

from oida.utils.export_utils import _config, configure, export_table

HEADERS = ["col_a", "col_b"]
ROWS = [[1, 2], [3, 4]]


class TestExportTableFormatDispatch(unittest.TestCase):
    def setUp(self):
        self._saved = dict(_config)
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        _config.update(self._saved)

    def _export(self, fmt):
        """Configure *fmt*, export a fixed table, return (retval, sorted files)."""
        outdir = tempfile.mkdtemp(dir=self.tmpdir)
        configure(output_dir=outdir, fmt=fmt)
        ret = export_table("demo", HEADERS, ROWS)
        return ret, sorted(os.listdir(outdir))

    def test_format_all_writes_every_format(self):
        """`--format all` must write csv + json + xml, not silently nothing."""
        ret, files = self._export("all")
        self.assertTrue(ret)
        self.assertEqual(files, ["demo.csv", "demo.json", "demo.xml"])

    def test_format_all_is_case_and_space_insensitive(self):
        ret, files = self._export("  ALL  ")
        self.assertTrue(ret)
        self.assertEqual(files, ["demo.csv", "demo.json", "demo.xml"])

    def test_format_console_writes_no_files_but_succeeds(self):
        """`console` is a legitimate no-file selection - must not be an error."""
        ret, files = self._export("console")
        self.assertTrue(ret)
        self.assertEqual(files, [])

    def test_unknown_format_reports_failure(self):
        """An unrecognised format must NOT report success after writing nothing."""
        ret, files = self._export("jsonn")
        self.assertFalse(ret)
        self.assertEqual(files, [])

    def test_known_formats_still_work(self):
        self.assertEqual(self._export("csv")[1], ["demo.csv"])
        self.assertEqual(self._export("json")[1], ["demo.json"])
        self.assertEqual(self._export("xml")[1], ["demo.xml"])
        self.assertEqual(self._export("csv,json")[1], ["demo.csv", "demo.json"])

    def test_console_mixed_with_real_format_still_writes(self):
        """`console,json` must still produce the json file."""
        ret, files = self._export("console,json")
        self.assertTrue(ret)
        self.assertEqual(files, ["demo.json"])


if __name__ == "__main__":
    unittest.main()
