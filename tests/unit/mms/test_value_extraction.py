#!/usr/bin/env python3
"""Deep unit tests for MMSScanner value/type handling and write helpers.

The pyiec61850-ng native binding is not importable in CI, so we patch the
class-level _Lib.iec61850 namespace with a fake that carries the MMS_*
type constants and MmsValue_* accessor functions the scanner calls. Each
test asserts the *converted Python value*, not the mock.
"""

from unittest.mock import MagicMock, patch

from oida.protocols.mms import MMSScanner, _Lib


# Distinct integer "type tags" mirroring the SWIG MMS_* enum constants.
TYPE_TAGS = {
    "MMS_DATA_ACCESS_ERROR": 0,
    "MMS_BOOLEAN": 1,
    "MMS_INTEGER": 2,
    "MMS_UNSIGNED": 3,
    "MMS_FLOAT": 4,
    "MMS_VISIBLE_STRING": 5,
    "MMS_STRING": 6,
    "MMS_BIT_STRING": 7,
    "MMS_STRUCTURE": 8,
    "MMS_ARRAY": 9,
}


def _fake_lib():
    """A MagicMock standing in for _Lib.iec61850 with MMS_* constants set."""
    lib = MagicMock()
    for name, tag in TYPE_TAGS.items():
        setattr(lib, name, tag)
    return lib


def _scanner():
    return MMSScanner({"rhost": "127.0.0.1", "rport": 102, "timeout": 5})


class TestExtractMmsValue:
    def setup_method(self):
        self.scanner = _scanner()

    def test_none_returns_none(self):
        assert self.scanner._extract_mms_value(None) is None

    def test_access_error_returns_none(self):
        lib = _fake_lib()
        lib.MmsValue_getType.return_value = TYPE_TAGS["MMS_DATA_ACCESS_ERROR"]
        with patch.object(_Lib, "iec61850", lib):
            assert self.scanner._extract_mms_value(MagicMock()) is None

    def test_boolean(self):
        lib = _fake_lib()
        lib.MmsValue_getType.return_value = TYPE_TAGS["MMS_BOOLEAN"]
        lib.MmsValue_getBoolean.return_value = True
        with patch.object(_Lib, "iec61850", lib):
            assert self.scanner._extract_mms_value(MagicMock()) is True

    def test_signed_integer_uses_toInt32(self):
        # The signed/unsigned fix: MMS_INTEGER must use toInt32 so negative
        # values come back negative, not as a huge unsigned number.
        lib = _fake_lib()
        lib.MmsValue_getType.return_value = TYPE_TAGS["MMS_INTEGER"]
        lib.MmsValue_toInt32.return_value = -42
        lib.MmsValue_toUint32.return_value = 4294967254  # would-be unsigned reading
        with patch.object(_Lib, "iec61850", lib):
            val = self.scanner._extract_mms_value(MagicMock())
        assert val == -42
        lib.MmsValue_toInt32.assert_called_once()
        lib.MmsValue_toUint32.assert_not_called()

    def test_unsigned_integer_uses_toUint32(self):
        lib = _fake_lib()
        lib.MmsValue_getType.return_value = TYPE_TAGS["MMS_UNSIGNED"]
        lib.MmsValue_toUint32.return_value = 4000000000
        lib.MmsValue_toInt32.return_value = -294967296
        with patch.object(_Lib, "iec61850", lib):
            val = self.scanner._extract_mms_value(MagicMock())
        assert val == 4000000000
        lib.MmsValue_toUint32.assert_called_once()
        lib.MmsValue_toInt32.assert_not_called()

    def test_float(self):
        lib = _fake_lib()
        lib.MmsValue_getType.return_value = TYPE_TAGS["MMS_FLOAT"]
        lib.MmsValue_toFloat.return_value = 3.14
        with patch.object(_Lib, "iec61850", lib):
            assert self.scanner._extract_mms_value(MagicMock()) == 3.14

    def test_visible_string_goes_through_safe_to_char_p(self):
        lib = _fake_lib()
        lib.MmsValue_getType.return_value = TYPE_TAGS["MMS_VISIBLE_STRING"]
        lib.MmsValue_toString.return_value = "raw_ptr"
        with (
            patch.object(_Lib, "iec61850", lib),
            patch.object(_Lib, "safe_to_char_p", return_value="HELLO") as char_p,
        ):
            assert self.scanner._extract_mms_value(MagicMock()) == "HELLO"
        char_p.assert_called_once_with("raw_ptr")

    def test_bit_string_as_integer(self):
        lib = _fake_lib()
        lib.MmsValue_getType.return_value = TYPE_TAGS["MMS_BIT_STRING"]
        lib.MmsValue_getBitStringAsInteger.return_value = 0b1011
        with patch.object(_Lib, "iec61850", lib):
            assert self.scanner._extract_mms_value(MagicMock()) == 11

    def test_structure_and_array_placeholders(self):
        lib = _fake_lib()
        with patch.object(_Lib, "iec61850", lib):
            lib.MmsValue_getType.return_value = TYPE_TAGS["MMS_STRUCTURE"]
            assert self.scanner._extract_mms_value(MagicMock()) == "<structure>"
            lib.MmsValue_getType.return_value = TYPE_TAGS["MMS_ARRAY"]
            assert self.scanner._extract_mms_value(MagicMock()) == "<array>"

    def test_unknown_type_returns_none(self):
        lib = _fake_lib()
        lib.MmsValue_getType.return_value = 999
        with patch.object(_Lib, "iec61850", lib):
            assert self.scanner._extract_mms_value(MagicMock()) is None

    def test_exception_during_get_type_returns_none(self):
        lib = _fake_lib()
        lib.MmsValue_getType.side_effect = RuntimeError("boom")
        with patch.object(_Lib, "iec61850", lib):
            assert self.scanner._extract_mms_value(MagicMock()) is None


class TestGetMmsTypeName:
    def setup_method(self):
        self.scanner = _scanner()

    def test_none_value(self):
        assert self.scanner._get_mms_type_name(None) == "unknown"

    def test_known_type_names(self):
        lib = _fake_lib()
        with patch.object(_Lib, "iec61850", lib):
            for tag, expected in [
                ("MMS_BOOLEAN", "boolean"),
                ("MMS_INTEGER", "integer"),
                ("MMS_UNSIGNED", "unsigned"),
                ("MMS_FLOAT", "float"),
                ("MMS_VISIBLE_STRING", "visible_string"),
                ("MMS_BIT_STRING", "bit_string"),
                ("MMS_STRUCTURE", "structure"),
                ("MMS_ARRAY", "array"),
            ]:
                lib.MmsValue_getType.return_value = TYPE_TAGS[tag]
                assert self.scanner._get_mms_type_name(MagicMock()) == expected

    def test_unknown_type_falls_back_to_type_n(self):
        lib = _fake_lib()
        lib.MmsValue_getType.return_value = 77
        with patch.object(_Lib, "iec61850", lib):
            assert self.scanner._get_mms_type_name(MagicMock()) == "type_77"

    def test_exception_returns_unknown(self):
        lib = _fake_lib()
        lib.MmsValue_getType.side_effect = RuntimeError("x")
        with patch.object(_Lib, "iec61850", lib):
            assert self.scanner._get_mms_type_name(MagicMock()) == "unknown"


class TestCreateMmsValue:
    def setup_method(self):
        self.scanner = _scanner()

    def test_bool_routes_to_newBoolean(self):
        lib = _fake_lib()
        lib.MmsValue_newBoolean.return_value = "BOOLOBJ"
        with patch.object(_Lib, "iec61850", lib):
            assert self.scanner._create_mms_value(True) == "BOOLOBJ"
        lib.MmsValue_newBoolean.assert_called_once_with(True)

    def test_int_routes_to_newInteger(self):
        lib = _fake_lib()
        lib.MmsValue_newInteger.return_value = "INTOBJ"
        with patch.object(_Lib, "iec61850", lib):
            assert self.scanner._create_mms_value(7) == "INTOBJ"
        lib.MmsValue_newInteger.assert_called_once_with(7)

    def test_float_routes_to_newFloat(self):
        lib = _fake_lib()
        lib.MmsValue_newFloat.return_value = "FLTOBJ"
        with patch.object(_Lib, "iec61850", lib):
            assert self.scanner._create_mms_value(1.5) == "FLTOBJ"
        lib.MmsValue_newFloat.assert_called_once_with(1.5)

    def test_str_routes_to_newVisibleString(self):
        lib = _fake_lib()
        lib.MmsValue_newVisibleString.return_value = "STROBJ"
        with patch.object(_Lib, "iec61850", lib):
            assert self.scanner._create_mms_value("hi") == "STROBJ"
        lib.MmsValue_newVisibleString.assert_called_once_with("hi")

    def test_other_type_coerced_to_integer(self):
        lib = _fake_lib()
        lib.MmsValue_newInteger.return_value = "INTOBJ"
        with patch.object(_Lib, "iec61850", lib):
            # A non-bool/int/float/str object that int()-coerces hits the
            # else branch -> newInteger(int(value)). Decimal qualifies.
            from decimal import Decimal

            assert self.scanner._create_mms_value(Decimal("123")) == "INTOBJ"
        lib.MmsValue_newInteger.assert_called_once_with(123)

    def test_creation_exception_returns_none(self):
        lib = _fake_lib()
        lib.MmsValue_newInteger.side_effect = RuntimeError("nope")
        with patch.object(_Lib, "iec61850", lib):
            assert self.scanner._create_mms_value(5) is None


class TestErrorCodeHelpers:
    def setup_method(self):
        self.scanner = _scanner()

    def test_extract_error_code_from_tuple(self):
        # SWIG returns (None, error_code); pick the int.
        assert MMSScanner._extract_error_code((None, 5)) == 5

    def test_extract_error_code_plain_int(self):
        assert MMSScanner._extract_error_code(3) == 3

    def test_extract_error_code_tuple_without_int(self):
        assert MMSScanner._extract_error_code((None, None)) == -1

    def test_extract_error_code_unknown_type(self):
        assert MMSScanner._extract_error_code("weird") == -1

    def test_get_error_name_known(self):
        lib = _fake_lib()
        lib.IED_ERROR_OK = 0
        lib.IED_ERROR_TIMEOUT = 6
        with patch.object(_Lib, "iec61850", lib):
            assert self.scanner._get_error_name(6) == "Timeout"

    def test_get_error_name_unknown_code(self):
        lib = _fake_lib()
        # set distinct values so the dict has no entry matching 123
        for i, attr in enumerate(
            [
                "IED_ERROR_OK",
                "IED_ERROR_NOT_CONNECTED",
                "IED_ERROR_ALREADY_CONNECTED",
                "IED_ERROR_CONNECTION_LOST",
                "IED_ERROR_SERVICE_NOT_SUPPORTED",
                "IED_ERROR_CONNECTION_REJECTED",
                "IED_ERROR_TIMEOUT",
            ]
        ):
            setattr(lib, attr, i)
        with patch.object(_Lib, "iec61850", lib):
            assert self.scanner._get_error_name(123) == "Error code 123"
