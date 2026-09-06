"""
Unit tests for BACnet StateMixin.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from oida.protocols.bacnet import bacnet
from tests.unit.bacnet.conftest import create_mock_args, create_mock_logger


def _create_instance(**kwargs):
    """Create bacnet instance bypassing __init__."""
    instance = object.__new__(bacnet)
    instance.args = create_mock_args(**kwargs)
    instance.logger = create_mock_logger()
    instance.results = {"data": {}}
    instance.host = "192.168.1.100"
    instance.devices = {
        1001: {"device_id": 1001, "address": "192.168.1.100"},
    }
    instance.objects = {
        1001: {
            "analogInput": [1, 2, 3],
            "binaryOutput": [1],
        },
    }
    instance.bacnet = Mock()
    return instance


class TestHandleDump(unittest.TestCase):
    """Test _handle_dump method."""

    def test_dump_no_output_prints_summary(self):
        scanner = _create_instance(output=None)
        scanner.bacnet.read = Mock(return_value="test_value")
        scanner._handle_dump()
        scanner.logger.display.assert_called()

    def test_dump_with_output_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = str(Path(tmpdir) / "dump")
            scanner = _create_instance(output=output_path, format="json")
            scanner.bacnet.read = Mock(return_value="test_value")
            scanner._handle_dump()

            dump_file = Path(output_path).with_suffix(".json")
            self.assertTrue(dump_file.exists())
            data = json.loads(dump_file.read_text())
            self.assertIn("timestamp", data)
            self.assertIn("devices", data)

    def test_dump_object_type_filter(self):
        scanner = _create_instance(output=None, object_types="analogInput")
        scanner.bacnet.read = Mock(return_value="test_value")
        scanner._handle_dump()
        scanner.logger.display.assert_called()

    def test_dump_control_points_only(self):
        scanner = _create_instance(output=None, control_points=True)
        scanner.bacnet.read = Mock(return_value="test_value")
        scanner._handle_dump()
        scanner.logger.display.assert_called()

    def test_dump_values_only(self):
        scanner = _create_instance(output=None, values_only=True)
        scanner.bacnet.read = Mock(return_value=42.5)
        scanner._handle_dump()
        scanner.logger.display.assert_called()


class TestHandleDiff(unittest.TestCase):
    """Test _handle_diff method."""

    def test_diff_missing_baseline_file(self):
        scanner = _create_instance()
        scanner.args.diff = "/nonexistent/file.json"
        scanner._handle_diff()
        scanner.logger.fail.assert_called()

    def test_diff_with_no_changes(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            baseline = {
                "devices": {
                    "1001": {
                        "objects": {
                            "analogInput": [
                                {"instance": 1},
                                {"instance": 2},
                                {"instance": 3},
                            ]
                        }
                    }
                }
            }
            json.dump(baseline, f)
            f.flush()

            scanner = _create_instance()
            scanner.args.diff = f.name
            scanner._handle_diff()
            # Should report no significant changes
            scanner.logger.display.assert_called()

    def test_diff_detects_new_device(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            baseline = {"devices": {}}
            json.dump(baseline, f)
            f.flush()

            scanner = _create_instance()
            scanner.args.diff = f.name
            scanner._handle_diff()
            scanner.logger.success.assert_called()


if __name__ == "__main__":
    unittest.main()
