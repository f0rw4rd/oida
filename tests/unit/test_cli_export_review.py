#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression tests for harvest-table export in ``oida.cli._export_tables``.

Bug (core bug hunt): ``_export_tables()`` only understood ``csv`` and ``json``::

    want_csv = "csv" in formats
    want_json = "json" in formats
    if not (want_csv or want_json):
        return

``--format xml`` is an accepted ``--format`` choice, so that early ``return``
silently discarded **every** harvest table (the pcap credential/device tables)
with no warning - the user got only the flat ``<protocol>.xml`` summary and
never learned the tables existed.
"""

import os
import tempfile
import unittest
from xml.etree import ElementTree as ET

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

    def test_xml_format_still_writes_harvest_tables(self):
        """`--format xml` must not silently drop the harvest tables."""
        outdir, files = self._export("xml")
        self.assertIn("credentials.xml", files)
        self.assertIn("pcap.xml", files)

    def test_xml_harvest_table_content_is_complete(self):
        outdir, _ = self._export("xml")
        root = ET.parse(os.path.join(outdir, "credentials.xml")).getroot()
        records = root.findall("record")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].findtext("user"), "admin")
        self.assertEqual(records[0].findtext("password"), "hunter2")

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
                "credentials.xml",
                "pcap.csv",
                "pcap.json",
                "pcap.xml",
            ],
        )

    def test_console_format_writes_no_table_files(self):
        """`console` selects no file format - tables stay unwritten, no crash."""
        _, files = self._export("console")
        self.assertEqual(files, [])


if __name__ == "__main__":
    unittest.main()
