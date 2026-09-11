#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tests for centralized export utilities.
"""

import csv
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from oida.utils.export_utils import (
    configure,
    export_table,
    get_export_path,
    get_config,
    _config,
    _write_csv,
    _write_json,
    _write_xml,
    print_table,
    export_data,
    configure_from_args,
)


def _add_output_format_args(parser):
    """Local helper: add the -o/--output and -f/--format args that
    configure_from_args() reads (replaces the removed add_export_args)."""
    parser.add_argument("-o", "--output", metavar="DIR")
    parser.add_argument("-f", "--format", metavar="FMT", default="csv,json")


class TestConfigure(unittest.TestCase):
    """Test configure() function"""

    def setUp(self):
        """Reset config before each test"""
        _config["output_dir"] = None
        _config["format"] = "csv,json"
        _config["logger"] = None

    def tearDown(self):
        """Reset config after each test"""
        _config["output_dir"] = None
        _config["format"] = "csv,json"
        _config["logger"] = None

    def test_configure_with_output_dir(self):
        """Test configure with output directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            configure(output_dir=tmpdir, fmt="csv")

            config = get_config()
            self.assertEqual(config["output_dir"], Path(tmpdir))
            self.assertEqual(config["format"], "csv")

    def test_configure_creates_directory(self):
        """Test configure creates output directory if it doesn't exist"""
        with tempfile.TemporaryDirectory() as tmpdir:
            new_dir = os.path.join(tmpdir, "new_subdir")
            self.assertFalse(os.path.exists(new_dir))

            configure(output_dir=new_dir, fmt="json")

            self.assertTrue(os.path.exists(new_dir))

    def test_configure_without_output_dir(self):
        """Test configure without output directory"""
        configure(output_dir=None, fmt="csv,json")

        config = get_config()
        self.assertIsNone(config["output_dir"])

    def test_configure_with_logger(self):
        """Test configure with logger"""
        mock_logger = MagicMock()
        configure(output_dir=None, fmt="csv", logger=mock_logger)

        config = get_config()
        self.assertEqual(config["logger"], mock_logger)

    def test_configure_multiple_formats(self):
        """Test configure with multiple formats"""
        configure(fmt="csv,json,xml")

        config = get_config()
        self.assertEqual(config["format"], "csv,json,xml")

    def test_configure_with_path_object(self):
        """Test configure accepts Path object"""
        with tempfile.TemporaryDirectory() as tmpdir:
            configure(output_dir=Path(tmpdir), fmt="json")

            config = get_config()
            self.assertEqual(config["output_dir"], Path(tmpdir))


class TestExportTable(unittest.TestCase):
    """Test export_table() function"""

    def setUp(self):
        """Reset config before each test"""
        _config["output_dir"] = None
        _config["format"] = "csv,json"
        _config["logger"] = None

    def tearDown(self):
        """Reset config after each test"""
        _config["output_dir"] = None
        _config["format"] = "csv,json"
        _config["logger"] = None

    def test_export_table_no_output_dir(self):
        """Test export_table without output directory (console only)"""
        headers = ["Name", "Value"]
        rows = [["test1", "100"], ["test2", "200"]]

        # Should not raise, just print to console
        result = export_table("test_data", headers, rows)
        self.assertTrue(result)

    def test_export_table_empty_data(self):
        """Test export_table with empty data"""
        result = export_table("empty", [], [])
        self.assertFalse(result)

    def test_export_table_empty_rows(self):
        """Test export_table with headers but no rows"""
        result = export_table("empty", ["Col1", "Col2"], [])
        self.assertFalse(result)

    def test_export_table_csv(self):
        """Test export_table creates CSV file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            configure(output_dir=tmpdir, fmt="csv")

            headers = ["Name", "Type", "Value"]
            rows = [
                ["sensor1", "temp", "25.5"],
                ["sensor2", "pressure", "101.3"],
            ]

            result = export_table("sensors", headers, rows)
            self.assertTrue(result)

            csv_path = Path(tmpdir) / "sensors.csv"
            self.assertTrue(csv_path.exists())

            with open(csv_path, "r") as f:
                reader = csv.reader(f)
                lines = list(reader)

            self.assertEqual(lines[0], headers)
            self.assertEqual(lines[1], rows[0])
            self.assertEqual(lines[2], rows[1])

    def test_export_table_json(self):
        """Test export_table creates JSON file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            configure(output_dir=tmpdir, fmt="json")

            headers = ["Name", "Value"]
            rows = [["tag1", 100], ["tag2", 200]]

            result = export_table("tags", headers, rows)
            self.assertTrue(result)

            json_path = Path(tmpdir) / "tags.json"
            self.assertTrue(json_path.exists())

            with open(json_path, "r") as f:
                data = json.load(f)

            self.assertEqual(len(data), 2)
            self.assertEqual(data[0]["Name"], "tag1")
            self.assertEqual(data[0]["Value"], 100)
            self.assertEqual(data[1]["Name"], "tag2")
            self.assertEqual(data[1]["Value"], 200)

    def test_export_table_multiple_formats(self):
        """Test export_table creates both CSV and JSON"""
        with tempfile.TemporaryDirectory() as tmpdir:
            configure(output_dir=tmpdir, fmt="csv,json")

            headers = ["ID", "Status"]
            rows = [["1", "OK"], ["2", "FAIL"]]

            result = export_table("status", headers, rows)
            self.assertTrue(result)

            self.assertTrue((Path(tmpdir) / "status.csv").exists())
            self.assertTrue((Path(tmpdir) / "status.json").exists())

    def test_export_table_xml(self):
        """Test export_table creates XML file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            configure(output_dir=tmpdir, fmt="xml")

            headers = ["Device", "IP"]
            rows = [["plc1", "192.168.1.10"], ["plc2", "192.168.1.11"]]

            result = export_table("devices", headers, rows)
            self.assertTrue(result)

            xml_path = Path(tmpdir) / "devices.xml"
            self.assertTrue(xml_path.exists())

            content = xml_path.read_text()
            self.assertIn("<devices>", content)
            self.assertIn("<record>", content)
            self.assertIn("<Device>plc1</Device>", content)
            self.assertIn("<IP>192.168.1.10</IP>", content)

    def test_export_table_with_title(self):
        """Test export_table with title parameter"""
        headers = ["Col1"]
        rows = [["val1"]]

        # Should not raise
        result = export_table("test", headers, rows, title="Test Title")
        self.assertTrue(result)

    def test_export_table_special_characters(self):
        """Test export_table handles special characters"""
        with tempfile.TemporaryDirectory() as tmpdir:
            configure(output_dir=tmpdir, fmt="csv,json")

            headers = ["Name", "Description"]
            rows = [
                ["test,comma", 'value with "quotes"'],
                ["test\nnewline", "value with 'apostrophe'"],
            ]

            result = export_table("special", headers, rows)
            self.assertTrue(result)

            # Verify CSV handles escaping
            csv_path = Path(tmpdir) / "special.csv"
            with open(csv_path, "r") as f:
                reader = csv.reader(f)
                lines = list(reader)
            self.assertEqual(len(lines), 3)  # header + 2 rows


class TestGetExportPath(unittest.TestCase):
    """Test get_export_path() function"""

    def setUp(self):
        """Reset config before each test"""
        _config["output_dir"] = None
        _config["format"] = "csv,json"
        _config["logger"] = None

    def tearDown(self):
        """Reset config after each test"""
        _config["output_dir"] = None
        _config["format"] = "csv,json"
        _config["logger"] = None

    def test_get_export_path_no_output_dir(self):
        """Test get_export_path returns None when no output_dir configured"""
        result = get_export_path("eeprom", "bin")
        self.assertIsNone(result)

    def test_get_export_path_with_output_dir(self):
        """Test get_export_path returns path when output_dir configured"""
        with tempfile.TemporaryDirectory() as tmpdir:
            configure(output_dir=tmpdir)

            result = get_export_path("eeprom", "bin")

            self.assertIsNotNone(result)
            self.assertEqual(result, Path(tmpdir) / "eeprom.bin")

    def test_get_export_path_default_extension(self):
        """Test get_export_path uses default .bin extension"""
        with tempfile.TemporaryDirectory() as tmpdir:
            configure(output_dir=tmpdir)

            result = get_export_path("data")

            self.assertEqual(result.suffix, ".bin")

    def test_get_export_path_custom_extension(self):
        """Test get_export_path with custom extension"""
        with tempfile.TemporaryDirectory() as tmpdir:
            configure(output_dir=tmpdir)

            result = get_export_path("config", "xml")
            self.assertEqual(result.suffix, ".xml")

            result = get_export_path("dump", "hex")
            self.assertEqual(result.suffix, ".hex")

    def test_get_export_path_write_binary(self):
        """Test writing binary data to export path"""
        with tempfile.TemporaryDirectory() as tmpdir:
            configure(output_dir=tmpdir)

            path = get_export_path("eeprom", "bin")
            self.assertIsNotNone(path)

            # Write binary data
            test_data = bytes([0x00, 0x01, 0x02, 0xFF, 0xFE])
            path.write_bytes(test_data)

            # Verify
            self.assertTrue(path.exists())
            self.assertEqual(path.read_bytes(), test_data)


class TestConfigureFromArgs(unittest.TestCase):
    """Test configure_from_args() function"""

    def setUp(self):
        """Reset config before each test"""
        _config["output_dir"] = None
        _config["format"] = "csv,json"
        _config["logger"] = None

    def tearDown(self):
        """Reset config after each test"""
        _config["output_dir"] = None
        _config["format"] = "csv,json"
        _config["logger"] = None

    def test_configure_from_args_basic(self):
        """Test configure_from_args with parsed args"""
        import argparse

        parser = argparse.ArgumentParser()
        _add_output_format_args(parser)

        with tempfile.TemporaryDirectory() as tmpdir:
            args = parser.parse_args(["-o", tmpdir, "-f", "json"])
            configure_from_args(args)

            config = get_config()
            self.assertEqual(config["output_dir"], Path(tmpdir))
            self.assertEqual(config["format"], "json")

    def test_configure_from_args_with_logger(self):
        """Test configure_from_args passes logger"""
        import argparse

        parser = argparse.ArgumentParser()
        _add_output_format_args(parser)

        args = parser.parse_args([])
        mock_logger = MagicMock()
        configure_from_args(args, logger=mock_logger)

        config = get_config()
        self.assertEqual(config["logger"], mock_logger)

    def test_configure_from_args_no_output(self):
        """Test configure_from_args without output dir"""
        import argparse

        parser = argparse.ArgumentParser()
        _add_output_format_args(parser)

        args = parser.parse_args([])
        configure_from_args(args)

        config = get_config()
        self.assertIsNone(config["output_dir"])

    def test_configure_from_args_missing_attrs(self):
        """Test configure_from_args handles missing attributes gracefully"""
        import argparse

        # Args without output/format attributes
        args = argparse.Namespace(other_arg="value")
        configure_from_args(args)

        config = get_config()
        self.assertIsNone(config["output_dir"])
        self.assertEqual(config["format"], "csv,json")


class TestWriteHelpers(unittest.TestCase):
    """Test internal write helper functions"""

    def test_write_csv(self):
        """Test _write_csv helper"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.csv"
            headers = ["A", "B", "C"]
            rows = [["1", "2", "3"], ["4", "5", "6"]]

            result = _write_csv(path, headers, rows)
            self.assertTrue(result)
            self.assertTrue(path.exists())

    def test_write_json(self):
        """Test _write_json helper"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.json"
            headers = ["key", "value"]
            rows = [["a", 1], ["b", 2]]

            result = _write_json(path, headers, rows)
            self.assertTrue(result)

            data = json.loads(path.read_text())
            self.assertEqual(len(data), 2)
            self.assertEqual(data[0]["key"], "a")

    def test_write_json_non_serializable(self):
        """Test _write_json handles non-serializable types"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.json"
            headers = ["obj"]
            rows = [[{"nested": "dict"}]]

            result = _write_json(path, headers, rows)
            self.assertTrue(result)

    def test_write_xml(self):
        """Test _write_xml helper"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.xml"
            headers = ["Name", "Value"]
            rows = [["item1", "100"]]

            result = _write_xml(path, headers, rows, "root")
            self.assertTrue(result)

            content = path.read_text()
            self.assertIn("<root>", content)
            self.assertIn("<Name>item1</Name>", content)

    def test_write_xml_sanitizes_headers(self):
        """Test _write_xml sanitizes header names for XML tags"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.xml"
            headers = ["Column With Spaces", "123numeric", "special!@#"]
            rows = [["val1", "val2", "val3"]]

            result = _write_xml(path, headers, rows, "data")
            self.assertTrue(result)

            content = path.read_text()
            # Spaces should be replaced with underscores
            self.assertIn("<Column_With_Spaces>", content)
            # Leading numbers should be prefixed
            self.assertIn("<_123numeric>", content)

    def test_write_creates_parent_dirs(self):
        """Test write helpers create parent directories"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "subdir" / "nested" / "test.csv"

            result = _write_csv(path, ["A"], [["1"]])
            self.assertTrue(result)
            self.assertTrue(path.exists())


class TestLegacyAPI(unittest.TestCase):
    """Test backward compatibility with legacy export_data API"""

    def test_export_data_console(self):
        """Test legacy export_data with console output"""
        headers = ["Col1", "Col2"]
        rows = [["a", "b"], ["c", "d"]]

        # Should not raise
        result = export_data(rows, headers, output_format="console")
        self.assertTrue(result)

    def test_export_data_with_output_dir(self):
        """Test legacy export_data with file output"""
        with tempfile.TemporaryDirectory() as tmpdir:
            headers = ["Name", "Value"]
            rows = [["x", "1"], ["y", "2"]]

            result = export_data(
                rows, headers, output_format="csv", output_dir=tmpdir, filename_prefix="legacy_test"
            )
            self.assertTrue(result)

            csv_path = Path(tmpdir) / "legacy_test.csv"
            self.assertTrue(csv_path.exists())

    def test_export_data_all_formats(self):
        """Test legacy export_data with 'all' format"""
        with tempfile.TemporaryDirectory() as tmpdir:
            headers = ["A"]
            rows = [["1"]]

            result = export_data(
                rows, headers, output_format="all", output_dir=tmpdir, filename_prefix="all_test"
            )
            self.assertTrue(result)

            self.assertTrue((Path(tmpdir) / "all_test.csv").exists())
            self.assertTrue((Path(tmpdir) / "all_test.json").exists())
            self.assertTrue((Path(tmpdir) / "all_test.xml").exists())


class TestPrintTable(unittest.TestCase):
    """Test print_table function"""

    def test_print_table_basic(self):
        """Test print_table with basic data"""
        headers = ["Name", "Value"]
        rows = [["test", "123"]]

        # Should not raise
        result = print_table(rows, headers)
        self.assertTrue(result)

    def test_print_table_with_title(self):
        """Test print_table with title"""
        headers = ["Col"]
        rows = [["data"]]

        result = print_table(rows, headers, title="Test Table")
        self.assertTrue(result)

    def test_print_table_with_logger(self):
        """Test print_table uses logger if provided"""
        mock_logger = MagicMock()
        mock_logger.display = MagicMock()

        headers = ["A", "B"]
        rows = [["1", "2"]]

        result = print_table(rows, headers, logger=mock_logger)
        self.assertTrue(result)
        self.assertTrue(mock_logger.display.called)

    def test_print_table_empty_data(self):
        """Test print_table with empty data"""
        # Empty rows with headers should still work
        result = print_table([], ["A", "B"])
        self.assertTrue(result)

    @staticmethod
    def _capture(rows, headers, **kwargs):
        """Run print_table and return the joined console output."""
        logger = MagicMock()
        lines = []
        logger.display = MagicMock(side_effect=lines.append)
        logger.prefix_width = 0
        print_table(rows, headers, logger=logger, **kwargs)
        return "\n".join(lines)

    def test_print_table_keeps_rows_differing_in_first_column(self):
        """Regression: rows differing only in the first (non-index) column must
        NOT be collapsed as identical. The first column here is real data
        (Username), not a throwaway '#' index."""
        headers = [
            "Username",
            "Security Level",
            "Auth Protocol",
            "Auth Password",
            "Priv Protocol",
            "Priv Password",
        ]
        rows = [
            ["admin", "authRequired", "", "", "", ""],
            ["operator", "authRequired", "", "", "", ""],
            ["engineer", "authRequired", "", "", "", ""],
            ["monitor", "authRequired", "", "", "", ""],
        ]
        out = self._capture(rows, headers)
        self.assertNotIn("identical row", out)
        for name in ("admin", "operator", "engineer", "monitor"):
            self.assertIn(name, out)

    def test_print_table_compresses_long_identical_run(self):
        """A genuine '#' index + 'Details' table collapses rows that are
        identical in their structural columns -- but only once the run exceeds
        the collapse threshold (10). The first row prints, the rest summarize."""
        headers = ["#", "Type", "Value", "Details"]
        rows = [[str(i), "foo", "bar", f"detail-{i}"] for i in range(13)]
        out = self._capture(rows, headers)
        self.assertIn("identical row", out)
        self.assertIn("detail-0", out)
        self.assertNotIn("detail-12", out)

    def test_print_table_keeps_short_identical_run(self):
        """A short run of structurally-identical rows (<= threshold) is printed
        in full instead of being collapsed, so a handful of repeats stay
        visible with their individual index/detail columns."""
        headers = ["#", "Type", "Value", "Details"]
        rows = [
            ["1", "foo", "bar", "detail-a"],
            ["2", "foo", "bar", "detail-b"],
            ["3", "foo", "bar", "detail-c"],
        ]
        out = self._capture(rows, headers)
        self.assertNotIn("identical row", out)
        self.assertIn("detail-a", out)
        self.assertIn("detail-b", out)
        self.assertIn("detail-c", out)

    def test_print_table_full_width_disables_compression(self):
        """--full-width / full_width config shows every row verbatim."""
        headers = ["#", "Type", "Value", "Details"]
        rows = [
            ["1", "foo", "bar", "detail-a"],
            ["2", "foo", "bar", "detail-b"],
        ]
        _config["full_width"] = True
        try:
            out = self._capture(rows, headers)
        finally:
            _config["full_width"] = False
        self.assertNotIn("identical row", out)
        self.assertIn("detail-a", out)
        self.assertIn("detail-b", out)


class TestIntegration(unittest.TestCase):
    """Integration tests for export workflow"""

    def setUp(self):
        """Reset config before each test"""
        _config["output_dir"] = None
        _config["format"] = "csv,json"
        _config["logger"] = None

    def tearDown(self):
        """Reset config after each test"""
        _config["output_dir"] = None
        _config["format"] = "csv,json"
        _config["logger"] = None

    def test_full_workflow(self):
        """Test complete export workflow"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Configure at startup
            mock_logger = MagicMock()
            mock_logger.success = MagicMock()
            mock_logger.display = MagicMock()

            configure(output_dir=tmpdir, fmt="csv,json", logger=mock_logger)

            # 2. Export table data
            headers = ["Device", "IP", "Status"]
            rows = [
                ["PLC-1", "192.168.1.10", "Online"],
                ["PLC-2", "192.168.1.11", "Offline"],
                ["HMI-1", "192.168.1.20", "Online"],
            ]

            result = export_table("devices", headers, rows, "Device Scan Results")
            self.assertTrue(result)

            # 3. Verify files created
            self.assertTrue((Path(tmpdir) / "devices.csv").exists())
            self.assertTrue((Path(tmpdir) / "devices.json").exists())

            # 4. Verify CSV content
            with open(Path(tmpdir) / "devices.csv", "r") as f:
                reader = csv.DictReader(f)
                rows_read = list(reader)

            self.assertEqual(len(rows_read), 3)
            self.assertEqual(rows_read[0]["Device"], "PLC-1")
            self.assertEqual(rows_read[1]["Status"], "Offline")

            # 5. Verify JSON content
            with open(Path(tmpdir) / "devices.json", "r") as f:
                data = json.load(f)

            self.assertEqual(len(data), 3)
            self.assertEqual(data[2]["Device"], "HMI-1")

    def test_binary_export_workflow(self):
        """Test binary data export workflow"""
        with tempfile.TemporaryDirectory() as tmpdir:
            configure(output_dir=tmpdir)

            # Get path for binary data
            path = get_export_path("eeprom_dump", "bin")
            self.assertIsNotNone(path)

            # Write binary data (simulating EEPROM dump)
            eeprom_data = bytes(range(256))
            path.write_bytes(eeprom_data)

            # Verify
            self.assertTrue(path.exists())
            self.assertEqual(path.read_bytes(), eeprom_data)

    def test_no_export_dir_workflow(self):
        """Test workflow when no export directory configured"""
        # Don't configure output_dir
        configure(output_dir=None)

        # Table export should still work (console only)
        result = export_table("test", ["A"], [["1"]])
        self.assertTrue(result)

        # Binary path should return None
        path = get_export_path("data", "bin")
        self.assertIsNone(path)


if __name__ == "__main__":
    unittest.main()
