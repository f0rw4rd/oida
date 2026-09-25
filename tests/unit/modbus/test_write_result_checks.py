"""_write_register_safe must treat pymodbus isError()=True as failure.

The helper (scanner_mixins/write_ops.py) derives result["success"] from
`not write_result.isError()`. A response object without an exception raised
is not success by itself; only isError() False means success.
"""

import unittest
from unittest.mock import MagicMock

from oida.protocols.modbus.scanner_mixins.write_ops import ScannerWriteOpsMixin


def _make_mixin():
    obj = ScannerWriteOpsMixin.__new__(ScannerWriteOpsMixin)
    obj.unit_id = 1
    obj.logger = MagicMock()
    return obj


def _response(is_error, registers=None, bits=None):
    resp = MagicMock()
    resp.isError.return_value = is_error
    if registers is not None:
        resp.registers = registers
    if bits is not None:
        resp.bits = bits
    return resp


class TestWriteRegisterSafeIsErrorCheck(unittest.TestCase):
    def test_holding_register_write_error_response_is_failure(self):
        obj = _make_mixin()
        client = MagicMock()
        client.read_holding_registers.return_value = _response(False, registers=[7])
        client.write_register.return_value = _response(True)

        result = obj._write_register_safe(client, address=10, value=99, register_type="holding")

        self.assertFalse(result["success"], "isError()=True on write must not be success")
        self.assertEqual(result["original_value"], 7)

    def test_holding_register_write_ok_response_is_success(self):
        obj = _make_mixin()
        client = MagicMock()
        client.read_holding_registers.return_value = _response(False, registers=[7])
        client.write_register.return_value = _response(False)
        client.write_register.side_effect = None

        result = obj._write_register_safe(
            client, address=10, value=99, register_type="holding", restore_on_exit=False
        )

        self.assertTrue(result["success"], "isError()=False on write must be success")


if __name__ == "__main__":
    unittest.main()
