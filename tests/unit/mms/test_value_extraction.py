#!/usr/bin/env python3
"""Deep unit tests for MMSScanner value/type handling and the write adapter.

The scanner runs on pyiec61850-ng's high-level ``MMSClient`` (>= 1.6.1.4), which
already converts MmsValues to native Python types and exposes FC-aware writes
and a working ``get_server_identity``. The old SWIG-level extractors
(``_extract_mms_value`` / ``_get_mms_type_name`` / ``_create_mms_value`` /
``_extract_error_code`` / ``_get_error_name``) are gone; their behaviour is now
split between:

* ``MMSScanner._python_type_name`` (pure, labels a converted Python value),
* ``MMSScanner._normalize_read`` (maps read_value()'s lossy "<MmsValue type=N>"
  placeholder back to None / "<structure>" / "<array>"), and
* the module-level ``_write_under_fc`` adapter (bool wrapper over
  ``MMSClient.write_value(ref, val, fc=fc)``).

(Server identity now goes straight through ``MMSClient.get_server_identity()``;
its use is covered in test_scanner_internals' ``_get_server_info`` tests.)

These tests mock only at the documented boundaries: the high-level enums
(``_Lib.MmsType`` / ``_Lib.FC``), ``_Lib.WriteError``, and the client's own
``write_value`` method.
"""

from enum import IntEnum
from unittest.mock import MagicMock, patch

from oida.protocols.mms import MMSScanner, _Lib, _write_under_fc


class _WriteError(Exception):
    """Stand-in for pyiec61850.mms.WriteError."""


class _MmsType(IntEnum):
    """Stand-in for pyiec61850.mms.MmsType (only the tags _normalize_read uses)."""

    ARRAY = 0
    STRUCTURE = 1
    DATA_ACCESS_ERROR = 15


class _FC(IntEnum):
    """Stand-in for pyiec61850.mms.FC (the constraints the write shim issues)."""

    ST = 0
    MX = 1
    SP = 2
    DC = 5
    CO = 12


def _scanner():
    return MMSScanner({"rhost": "127.0.0.1", "rport": 102, "timeout": 5})


# --------------------------------------------------------------------------- #
# _python_type_name  (pure, no mocks)
# --------------------------------------------------------------------------- #
class TestPythonTypeName:
    def test_bool_before_int(self):
        # bool is a subclass of int, so the bool branch must win.
        assert MMSScanner._python_type_name(True) == "boolean"
        assert MMSScanner._python_type_name(False) == "boolean"

    def test_integer(self):
        assert MMSScanner._python_type_name(42) == "integer"
        assert MMSScanner._python_type_name(-7) == "integer"

    def test_float(self):
        assert MMSScanner._python_type_name(3.14) == "float"

    def test_structure_placeholder(self):
        assert MMSScanner._python_type_name("<structure>") == "structure"

    def test_array_placeholder(self):
        assert MMSScanner._python_type_name("<array>") == "array"

    def test_plain_string(self):
        assert MMSScanner._python_type_name("SIEMENS") == "string"

    def test_list_and_tuple_are_array(self):
        assert MMSScanner._python_type_name([1, 2]) == "array"
        assert MMSScanner._python_type_name((1, 2)) == "array"

    def test_dict_is_structure(self):
        assert MMSScanner._python_type_name({"a": 1}) == "structure"

    def test_other_falls_back_to_type_name(self):
        assert MMSScanner._python_type_name(b"raw") == "bytes"


# --------------------------------------------------------------------------- #
# _normalize_read  (needs _Lib.MmsType)
# --------------------------------------------------------------------------- #
class TestNormalizeRead:
    def setup_method(self):
        self.scanner = _scanner()

    def test_scalar_passes_through_unchanged(self):
        # Scalars never look like a placeholder, so MmsType is never consulted.
        assert self.scanner._normalize_read(42) == 42
        assert self.scanner._normalize_read(-1) == -1
        assert self.scanner._normalize_read(3.14) == 3.14
        assert self.scanner._normalize_read(True) is True

    def test_ordinary_string_passes_through(self):
        with patch.object(_Lib, "MmsType", _MmsType):
            assert self.scanner._normalize_read("SIEMENS") == "SIEMENS"

    def test_data_access_error_maps_to_none(self):
        with patch.object(_Lib, "MmsType", _MmsType):
            assert self.scanner._normalize_read("<MmsValue type=15>") is None

    def test_structure_placeholder_label(self):
        with patch.object(_Lib, "MmsType", _MmsType):
            assert self.scanner._normalize_read("<MmsValue type=1>") == "<structure>"

    def test_array_placeholder_label(self):
        with patch.object(_Lib, "MmsType", _MmsType):
            assert self.scanner._normalize_read("<MmsValue type=0>") == "<array>"

    def test_unknown_type_tag_passes_placeholder_through(self):
        # A tag that isn't error/structure/array stays as the raw placeholder.
        with patch.object(_Lib, "MmsType", _MmsType):
            assert self.scanner._normalize_read("<MmsValue type=7>") == "<MmsValue type=7>"

    def test_non_numeric_tag_is_not_a_placeholder(self):
        # Malformed tag: not int()-parseable -> returned verbatim, no crash.
        with patch.object(_Lib, "MmsType", _MmsType):
            assert self.scanner._normalize_read("<MmsValue type=xx>") == "<MmsValue type=xx>"

    def test_none_passes_through(self):
        assert self.scanner._normalize_read(None) is None


# --------------------------------------------------------------------------- #
# _write_under_fc  (bool adapter over MMSClient.write_value)
# --------------------------------------------------------------------------- #
class TestWriteUnderFC:
    def test_successful_write_passes_fc_and_returns_true(self):
        client = MagicMock()
        client.write_value.return_value = True

        with patch.object(_Lib, "WriteError", _WriteError):
            ok = _write_under_fc(client, "LD0/A.SP", 5, _FC.SP)

        assert ok is True
        client.write_value.assert_called_once_with("LD0/A.SP", 5, fc=_FC.SP)

    def test_write_value_falsy_returns_false(self):
        client = MagicMock()
        client.write_value.return_value = False

        with patch.object(_Lib, "WriteError", _WriteError):
            assert _write_under_fc(client, "LD0/A", 5, _FC.MX) is False

    def test_write_error_is_swallowed_to_false(self):
        # A rejected FC raises WriteError; the probe loop wants a bool so the
        # adapter swallows it and lets the caller try the next constraint.
        client = MagicMock()
        client.write_value.side_effect = _WriteError("object-does-not-exist")

        with patch.object(_Lib, "WriteError", _WriteError):
            assert _write_under_fc(client, "LD0/A", 5, _FC.CO) is False

    def test_other_exception_returns_false(self):
        client = MagicMock()
        client.write_value.side_effect = RuntimeError("link down")

        with patch.object(_Lib, "WriteError", _WriteError):
            assert _write_under_fc(client, "LD0/A", 5, _FC.SP) is False
