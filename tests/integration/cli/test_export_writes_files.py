"""When `-o out/` is set, the framework MUST write a file.

Deferred item: 5+ protocols silently produced zero files when the
operator passed `-o out/` without
`-f json|csv`. The root cause was format defaulting to "console"
which writes nothing to disk.

The actual file-writing contract lives at the framework layer in
`oida.cli.export_results` - every protocol's results flow through that
single function. This test pins the contract there:

  - export_results(format="json", -o dir) writes <protocol>.json
  - export_results(format="csv", -o dir) writes <protocol>.csv
  - export_results(format="all", -o dir) writes both
  - export_results(format="console", -o dir) writes NOTHING (the trap)

Then a CLI-wiring snapshot verifies cli.py still calls export_results
from its main dispatch loop.
"""

import json
import os
import shutil
import tempfile
import unittest

import pytest

from oida.cli import export_results


def _sample_results(protocol="modbus"):
    return [
        {
            "host": "10.0.0.1",
            "ip": "10.0.0.1",
            "protocol": protocol,
            "port": 502,
            "success": True,
            "data": {"identified": True, "vendor": "Test"},
        },
        {
            "host": "10.0.0.2",
            "ip": "10.0.0.2",
            "protocol": protocol,
            "port": 502,
            "success": False,
            "error": "timeout",
            "data": {},
        },
    ]


class TestExportResultsContract(unittest.TestCase):
    """Framework-level: export_results writes files for non-console formats."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="oida-export-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _files(self):
        return sorted(os.listdir(self.tmp))

    def test_json_writes_one_file(self):
        export_results(_sample_results(), self.tmp, "json", "modbus")
        self.assertEqual(self._files(), ["modbus.json"])
        # Sanity: round-trip
        with open(os.path.join(self.tmp, "modbus.json")) as f:
            payload = json.load(f)
        self.assertEqual(len(payload), 2)

    def test_csv_writes_one_file(self):
        export_results(_sample_results(), self.tmp, "csv", "modbus")
        self.assertEqual(self._files(), ["modbus.csv"])
        # Sanity: header present
        with open(os.path.join(self.tmp, "modbus.csv")) as f:
            header = f.readline()
        self.assertIn("host", header)
        self.assertIn("protocol", header)

    def test_all_writes_json_and_csv(self):
        export_results(_sample_results(), self.tmp, "all", "modbus")
        self.assertEqual(self._files(), sorted(["modbus.csv", "modbus.json"]))

    def test_console_writes_no_files(self):
        """The bug class: -o out/ alone (default format=console) writes
        NOTHING. Documented here so a future fix that auto-promotes
        format=console to json when output_dir is set can compare
        against this snapshot."""
        export_results(_sample_results(), self.tmp, "console", "modbus")
        self.assertEqual(self._files(), [])

    def test_empty_results_writes_nothing(self):
        """Empty results list correctly produces no file (logs warning)."""
        export_results([], self.tmp, "json", "modbus")
        self.assertEqual(self._files(), [])

    def test_creates_output_dir_if_missing(self):
        """-o out/ where 'out' doesn't exist: must be created."""
        new_dir = os.path.join(self.tmp, "subdir-that-doesnt-exist")
        export_results(_sample_results(), new_dir, "json", "modbus")
        self.assertTrue(os.path.exists(new_dir))
        self.assertEqual(os.listdir(new_dir), ["modbus.json"])

    def test_protocol_name_appears_in_filename(self):
        for proto in ("opcua", "snap7", "iec104", "modbus_rtu"):
            export_results(_sample_results(proto), self.tmp, "json", proto)
            self.assertIn(f"{proto}.json", self._files())


# CLI dispatcher wiring snapshot: cli.py main loop must invoke
# export_results so every protocol that returns results flows through
# the file-write contract above.
@pytest.fixture(scope="module")
def cli_src():
    import pathlib

    return pathlib.Path("src/oida/cli.py").read_text()


def test_cli_dispatcher_calls_export_results(cli_src):
    """cli.py main loop must invoke export_results for any -o flow."""
    assert "export_results(" in cli_src, (
        "cli.py no longer calls export_results - silent-no-files class of bugs would silently recur"
    )


def test_export_results_handles_output_dir(cli_src):
    """The call site must pass the -o flag through to export_results."""
    # Common shape: export_results(results, args.output, args.format, ...)
    assert "args.output" in cli_src or "output_dir" in cli_src, (
        "cli.py doesn't appear to thread the -o flag value through to export_results"
    )


if __name__ == "__main__":
    unittest.main()
