#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression tests for harvest-table export in ``oida.cli._export_tables``.

Bug (core bug hunt): ``_export_tables()`` only understood ``csv`` and ``json``::

    want_csv = "csv" in formats
    want_json = "json" in formats
    if not (want_csv or want_json):
        return

Any unsupported ``--format`` choice silently discarded **every** harvest table
(the pcap credential/device tables) with no warning.
"""

import os
import tempfile
import unittest

from oida.cli import export_results

RESULTS = [
    {
        "host": "10.0.0.1",
        "ip": "10.0.0.1",
        "protocol": "pcap",
        "port": 0,
        "success": True,
        "error": "",
        "data": {
            "packets": 5,
            "tables": [
                {
                    "title": "Credentials",
                    "headers": ["user", "password"],
                    "rows": [["admin", "hunter2"]],
                }
            ],
        },
    }
]


class TestHarvestTableExportFormats(unittest.TestCase):
    def _export(self, fmt):
        outdir = tempfile.mkdtemp()
        export_results(RESULTS, outdir, fmt, protocol_name="pcap")
        return outdir, sorted(os.listdir(outdir))

    def test_csv_and_json_formats_unchanged(self):
        self.assertEqual(self._export("csv")[1], ["credentials.csv", "pcap.csv"])
        self.assertEqual(self._export("json")[1], ["credentials.json", "pcap.json"])

    def test_all_format_writes_every_table_format(self):
        _, files = self._export("all")
        self.assertEqual(
            files,
            [
                "credentials.csv",
                "credentials.json",
                "pcap.csv",
                "pcap.json",
            ],
        )

    def test_console_format_writes_no_table_files(self):
        """`console` selects no file format - tables stay unwritten, no crash."""
        _, files = self._export("console")
        self.assertEqual(files, [])


if __name__ == "__main__":
    unittest.main()
