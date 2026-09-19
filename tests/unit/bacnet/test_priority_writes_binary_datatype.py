"""Priority-write test must encode the write value with the object's actual
datatype.

CODE_REVIEW.md MEDIUM bacnet/mixins/security.py:783. Previously the write
was always built as AnyAtomic(Real(current_value)) regardless of object
type. For binaryOutput/binaryValue the presentValue is a BinaryPV
enumeration, so writing a Real is rejected by a spec-compliant device with
a datatype error, reporting writable priorities as 'rejected' and masking a
real weakness. The fix drives encoding off obj_type: Real for analog*,
BinaryPV for binary*.
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

from oida.protocols.bacnet import bacnet
from tests.unit.bacnet.conftest import create_mock_args, create_mock_logger


def _create_instance(objects):
    instance = object.__new__(bacnet)
    instance.args = create_mock_args()
    instance.logger = create_mock_logger()
    instance.host = "192.168.1.100"
    instance.devices = {1001: {"device_id": 1001, "address": "192.168.1.100"}}
    instance.objects = {1001: objects}
    instance.bacnet = Mock()
    return instance


def _make_types(real_marker, binary_marker, captured):
    """Build mock types where Real/BinaryPV record their invocations."""
    AbortPDU = type("AbortPDU", (), {})
    ErrorPDU = type("ErrorPDU", (), {})
    ErrorRejectAbortNack = type("ErrorRejectAbortNack", (BaseException,), {})
    RejectPDU = type("RejectPDU", (), {})
    Error = type("Error", (), {})

    def real_ctor(v):
        captured.append(("Real", v))
        return real_marker

    def binary_ctor(v):
        captured.append(("BinaryPV", v))
        return binary_marker

    # propertyValue.cast_out returns 1 for any requested cast type.
    pv = Mock()
    pv.cast_out = Mock(return_value=1)
    read_response = Mock()
    read_response.propertyValue = pv

    return {
        "WritePropertyRequest": Mock(return_value=Mock()),
        "ReadPropertyRequest": Mock(return_value=Mock()),
        "ObjectIdentifier": Mock(return_value=Mock()),
        "PropertyIdentifier": Mock(return_value=Mock()),
        "Real": real_ctor,
        "Unsigned": Mock(return_value=Mock()),
        "BinaryPV": binary_ctor,
        "AbortPDU": AbortPDU,
        "ErrorPDU": ErrorPDU,
        "ErrorRejectAbortNack": ErrorRejectAbortNack,
        "RejectPDU": RejectPDU,
        "Error": Error,
        "AnyAtomic": Mock(return_value=Mock()),
    }, read_response


class TestPriorityWriteDatatype(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_binary_object_uses_binarypv_not_real(self, mock_load):
        """Regression: a binaryOutput write must be encoded via BinaryPV."""
        captured = []
        real_marker = object()
        binary_marker = object()
        types, read_response = _make_types(real_marker, binary_marker, captured)
        mock_load.return_value = types

        scanner = _create_instance({"binaryOutput": [1]})
        app = AsyncMock()
        error_response = types["ErrorPDU"]()
        app.request = AsyncMock(side_effect=[read_response] + [error_response] * 16)

        asyncio.run(scanner._bacpypes3_test_priority_writes(app, Mock(), 1001, 5.0))

        used = {name for name, _ in captured}
        self.assertIn("BinaryPV", used, "binary object must be encoded with BinaryPV")
        self.assertNotIn("Real", used, "binary object must NOT be encoded as Real")

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_analog_object_still_uses_real(self, mock_load):
        """Analog objects keep the Real encoding."""
        captured = []
        real_marker = object()
        binary_marker = object()
        types, read_response = _make_types(real_marker, binary_marker, captured)
        mock_load.return_value = types

        scanner = _create_instance({"analogOutput": [1]})
        app = AsyncMock()
        error_response = types["ErrorPDU"]()
        app.request = AsyncMock(side_effect=[read_response] + [error_response] * 16)

        asyncio.run(scanner._bacpypes3_test_priority_writes(app, Mock(), 1001, 5.0))

        used = {name for name, _ in captured}
        self.assertIn("Real", used, "analog object must be encoded with Real")
        self.assertNotIn("BinaryPV", used, "analog object must NOT be encoded as BinaryPV")


if __name__ == "__main__":
    unittest.main()
