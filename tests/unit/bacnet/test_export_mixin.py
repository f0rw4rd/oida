"""
Unit tests for BACnet ExportMixin.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from oida.protocols.bacnet import bacnet
from tests.unit.bacnet.conftest import create_mock_args, create_mock_logger


def _create_instance(**kwargs):
    """Create bacnet instance bypassing __init__."""
    instance = object.__new__(bacnet)
    instance.args = create_mock_args(**kwargs)
    instance.logger = create_mock_logger()
    instance.results = {"data": {}}
    instance.host = "192.168.1.100"
    instance.devices = {}
    instance.objects = {}
    instance.bacnet = None
    return instance


class TestParseObjectId(unittest.TestCase):
    """Test _parse_object_id helper."""

    def test_parse_tuple(self):
        scanner = _create_instance()
        result = scanner._parse_object_id((2, 100))
        self.assertEqual(result, (2, 100))

    def test_parse_colon_string(self):
        scanner = _create_instance()
        result = scanner._parse_object_id("analogInput:5")
        self.assertEqual(result, (0, 5))  # analogInput maps to 0

    def test_parse_comma_string(self):
        scanner = _create_instance()
        result = scanner._parse_object_id("analogInput,5")
        self.assertEqual(result, (0, 5))

    def test_parse_invalid_string(self):
        scanner = _create_instance()
        result = scanner._parse_object_id("invalid")
        self.assertEqual(result, (0, 0))

    def test_parse_object_with_attributes(self):
        obj = Mock()
        obj.objectType = 2
        obj.objectIdentifier = ("analogValue", 10)
        scanner = _create_instance()
        result = scanner._parse_object_id(obj)
        self.assertEqual(result, (2, 10))


class TestExportResults(unittest.TestCase):
    """Test _export_results."""

    def test_no_output_path_skips(self):
        scanner = _create_instance(output=None)
        scanner._export_results()
        # Should not crash

    def test_json_export(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = str(Path(tmpdir) / "results")
            scanner = _create_instance(output=output_path, format="json")
            scanner.devices = {1001: {"device_id": 1001, "address": "192.168.1.100"}}
            scanner.objects = {1001: {"analogInput": [1, 2, 3]}}

            with patch("oida.utils.export_utils.configure_from_args"):
                scanner._export_results()

            result_file = Path(output_path).with_suffix(".json")
            self.assertTrue(result_file.exists())
            data = json.loads(result_file.read_text())
            self.assertIn("timestamp", data)
            self.assertIn("devices", data)


if __name__ == "__main__":
    unittest.main()
