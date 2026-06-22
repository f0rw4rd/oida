"""TimeSynchronization is an UNCONFIRMED service: absence of an ACK must NOT
be reported as a finding.

CODE_REVIEW.md MEDIUM bacnet/mixins/security.py:880. Previously
`_bacpypes3_test_time_sync` treated `response is None` (and the asyncio
timeout branch) as "device accepted unauthenticated TimeSynchronization",
so the check fired on essentially every target regardless of behaviour.
The fix verifies out-of-band by reading localDate/localTime before and
after, and only records a finding when the clock actually moved.
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

from oida.protocols.bacnet import bacnet
from tests.unit.bacnet.conftest import create_mock_args, create_mock_logger


def _create_instance():
    instance = object.__new__(bacnet)
    instance.args = create_mock_args()
    instance.logger = create_mock_logger()
    instance.logger.security_finding = Mock()
    instance.host = "192.168.1.100"
    instance.devices = {1001: {"device_id": 1001, "address": "192.168.1.100"}}
    instance.objects = {1001: {}}
    instance.bacnet = Mock()
    return instance


def _get_mock_types():
    AbortPDU = type("AbortPDU", (), {})
    ErrorPDU = type("ErrorPDU", (), {})
    RejectPDU = type("RejectPDU", (), {})
    Error = type("Error", (), {})
    return {
        "TimeSynchronizationRequest": Mock(return_value=Mock()),
        "ReadPropertyRequest": Mock(return_value=Mock()),
        "ObjectIdentifier": Mock(return_value=Mock()),
        "PropertyIdentifier": Mock(return_value=Mock()),
        "DateTime": Mock(return_value=Mock()),
        "Date": Mock(return_value=Mock()),
        "Time": Mock(return_value=Mock()),
        "AbortPDU": AbortPDU,
        "ErrorPDU": ErrorPDU,
        "RejectPDU": RejectPDU,
        "Error": Error,
    }


def _read_resp(value):
    """A successful ReadProperty response whose propertyValue str()s to `value`."""
    resp = Mock()
    resp.propertyValue = value
    return resp


class TestTimeSyncNoFalsePositive(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_no_reply_with_unchanged_clock_is_not_a_finding(self, mock_load):
        """The core regression: TimeSync sent, no ACK, clock unchanged -> no finding."""
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        app = AsyncMock()
        # before: localDate, localTime ; sync: None ; after: same localDate, localTime
        app.request = AsyncMock(
            side_effect=[
                _read_resp("date-X"),
                _read_resp("time-X"),
                None,  # unconfirmed TimeSync -> no app reply
                _read_resp("date-X"),
                _read_resp("time-X"),
            ]
        )

        asyncio.run(scanner._bacpypes3_test_time_sync(app, Mock(), 1001, 5.0))

        scanner.logger.security_finding.assert_not_called()

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_timeout_on_sync_is_not_a_finding(self, mock_load):
        """A timeout on the unconfirmed send must not be treated as success."""
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(
            side_effect=[
                _read_resp("date-X"),
                _read_resp("time-X"),
                asyncio.TimeoutError(),
                _read_resp("date-X"),
                _read_resp("time-X"),
            ]
        )

        asyncio.run(scanner._bacpypes3_test_time_sync(app, Mock(), 1001, 5.0))

        scanner.logger.security_finding.assert_not_called()

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_clock_actually_changed_is_a_finding(self, mock_load):
        """When the verified clock moves, that IS the real finding."""
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(
            side_effect=[
                _read_resp("date-X"),
                _read_resp("time-10:00"),
                None,  # unconfirmed
                _read_resp("date-X"),
                _read_resp("time-10:05"),  # clock advanced -> write applied
            ]
        )

        asyncio.run(scanner._bacpypes3_test_time_sync(app, Mock(), 1001, 5.0))

        scanner.logger.security_finding.assert_called_once()

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_unverifiable_clock_is_indeterminate_not_a_finding(self, mock_load):
        """If localDate/localTime can't be read, report indeterminate, no finding."""
        mock_load.return_value = _get_mock_types()
        scanner = _create_instance()
        app = AsyncMock()
        # before read fails (None) -> cannot verify
        app.request = AsyncMock(side_effect=[None, None])

        asyncio.run(scanner._bacpypes3_test_time_sync(app, Mock(), 1001, 5.0))

        scanner.logger.security_finding.assert_not_called()


if __name__ == "__main__":
    unittest.main()
