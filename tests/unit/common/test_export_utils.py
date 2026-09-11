#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tests for centralized export utilities.
"""

import argparse
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
    configure_from_args,
)
from oida.utils.proto_args_factory import add_output_options


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


class TestExportTable(unittest.TestCase):
    """Test export_table() function"""

    def setUp(self):
        _config["output_dir"] = None
        _config["format"] = "csv,json"
        _config["logger"] = None

    def tearDown(self):
        _config["output_dir"] = None
        _config["format"] = "csv,json"
        _config["logger"] = None

    def test_export_table_no_output_dir(self):
        """Test export_table without output directory (console only)"""
        headers = ["Name", "Value"]
        rows = [["test1", "100"], ["test2", "200"]]

        result = export_table("test_data", headers, rows)
        self.assertTrue(result)

    def test_export_table_empty_data(self):
        """Test export_table with empty data"""
        result = export_table("empty", [], [])
        self.assertFalse(result)

    def test_export_table_csv(self):
        """Test export_table creates CSV file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            configure(output_dir=tmpdir, fmt="csv")

            headers = ["Name", "Type", "Value"]
            rows = [["sensor1", "temp", "25.5"], ["sensor2", "pressure", "101.3"]]

            result = export_table("sensors", headers, rows)
            self.assertTrue(result)

            csv_path = Path(tmpdir) / "sensors.csv"
            self.assertTrue(csv_path.exists())

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


class TestGetExportPath(unittest.TestCase):
    """Test get_export_path() function"""

    def setUp(self):
        _config["output_dir"] = None
        _config["format"] = "csv,json"
        _config["logger"] = None

    def tearDown(self):
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

    def test_get_export_path_write_binary(self):
        """Test writing binary data to export path"""
        with tempfile.TemporaryDirectory() as tmpdir:
            configure(output_dir=tmpdir)

            path = get_export_path("eeprom", "bin")
            self.assertIsNotNone(path)

            test_data = bytes([0x00, 0x01, 0x02, 0xFF, 0xFE])
            path.write_bytes(test_data)

            self.assertTrue(path.exists())
            self.assertEqual(path.read_bytes(), test_data)


class TestAddOutputOptions(unittest.TestCase):
    """Test add_output_options() from proto_args_factory"""

    def test_add_output_options_all(self):
        """Test add_output_options adds all expected arguments"""
        parser = argparse.ArgumentParser()
        add_output_options(parser)

        args = parser.parse_args(["-o", "/tmp", "-f", "json", "-v", "-d"])
        self.assertEqual(args.output, "/tmp")
        self.assertEqual(args.format, "json")
        self.assertTrue(args.verbose)
        self.assertTrue(args.debug)

    def test_add_output_options_defaults(self):
        """Test add_output_options has correct defaults"""
        parser = argparse.ArgumentParser()
        add_output_options(parser)

        args = parser.parse_args([])
        self.assertIsNone(args.output)
        self.assertEqual(args.format, "csv,json")
        self.assertFalse(args.verbose)
        self.assertFalse(args.debug)

    def test_add_output_options_no_verbose(self):
        """Test add_output_options without verbose/debug"""
        parser = argparse.ArgumentParser()
        add_output_options(parser, include_verbose=False)

        args = parser.parse_args(["-o", "/tmp"])
        self.assertEqual(args.output, "/tmp")
        self.assertFalse(hasattr(args, "verbose"))
        self.assertFalse(hasattr(args, "debug"))


class TestConfigureFromArgs(unittest.TestCase):
    """Test configure_from_args() function"""

    def setUp(self):
        _config["output_dir"] = None
        _config["format"] = "csv,json"
        _config["logger"] = None

    def tearDown(self):
        _config["output_dir"] = None
        _config["format"] = "csv,json"
        _config["logger"] = None

    def test_configure_from_args_basic(self):
        """Test configure_from_args with parsed args"""
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
        parser = argparse.ArgumentParser()
        _add_output_format_args(parser)

        args = parser.parse_args([])
        mock_logger = MagicMock()
        configure_from_args(args, logger=mock_logger)

        config = get_config()
        self.assertEqual(config["logger"], mock_logger)

    def test_configure_from_args_missing_attrs(self):
        """Test configure_from_args handles missing attributes gracefully"""
        args = argparse.Namespace(other_arg="value")
        configure_from_args(args)

        config = get_config()
        self.assertIsNone(config["output_dir"])
        self.assertEqual(config["format"], "csv,json")


class TestIntegration(unittest.TestCase):
    """Integration tests for export workflow"""

    def setUp(self):
        _config["output_dir"] = None
        _config["format"] = "csv,json"
        _config["logger"] = None

    def tearDown(self):
        _config["output_dir"] = None
        _config["format"] = "csv,json"
        _config["logger"] = None

    def test_full_workflow(self):
        """Test complete export workflow"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Configure at startup
            configure(output_dir=tmpdir, fmt="csv,json")

            # 2. Export table data
            headers = ["Device", "IP", "Status"]
            rows = [
                ["PLC-1", "192.168.1.10", "Online"],
                ["PLC-2", "192.168.1.11", "Offline"],
            ]

            result = export_table("devices", headers, rows)
            self.assertTrue(result)

            # 3. Verify files created
            self.assertTrue((Path(tmpdir) / "devices.csv").exists())
            self.assertTrue((Path(tmpdir) / "devices.json").exists())

    def test_binary_export_workflow(self):
        """Test binary data export workflow"""
        with tempfile.TemporaryDirectory() as tmpdir:
            configure(output_dir=tmpdir)

            path = get_export_path("eeprom_dump", "bin")
            self.assertIsNotNone(path)

            eeprom_data = bytes(range(256))
            path.write_bytes(eeprom_data)

            self.assertTrue(path.exists())
            self.assertEqual(path.read_bytes(), eeprom_data)


if __name__ == "__main__":
    unittest.main()
