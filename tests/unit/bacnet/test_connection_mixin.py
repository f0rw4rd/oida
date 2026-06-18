"""
Unit tests for BACnet ConnectionMixin.
"""

import unittest
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
    instance.devices = {}
    instance.objects = {}
    instance.bacnet = None
    instance.host_info = {}
    return instance


class TestDisconnect(unittest.TestCase):
    """Test _disconnect."""

    def test_disconnect_with_no_connection(self):
        scanner = _create_instance()
        scanner.bacnet = None
        scanner._disconnect()
        # Should not crash

    def test_disconnect_with_active_connection(self):
        scanner = _create_instance()
        mock_bacnet = Mock()
        scanner.bacnet = mock_bacnet
        scanner._disconnect()
        mock_bacnet.disconnect.assert_called_once()

    def test_disconnect_handles_exception(self):
        scanner = _create_instance()
        mock_bacnet = Mock()
        mock_bacnet.disconnect.side_effect = Exception("disconnect error")
        scanner.bacnet = mock_bacnet
        scanner._disconnect()
        scanner.logger.debug.assert_called()


if __name__ == "__main__":
    unittest.main()
