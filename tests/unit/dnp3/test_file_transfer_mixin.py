#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Behavioral tests for ``oida.protocols.dnp3.mixins.file_transfer.FileTransferMixin``.

Drives the real Group-70 file-transfer logic (directory listing, file read with
on-disk save, file write with @file payload resolution, file info, delete,
authentication, octet-string reads) with realistic result objects. Only the
opendnp3 library boundary is faked: ``_sync_callback`` (which calls IMaster
file methods and returns a FileOperationResult-like object) and ``_sync_scan``
(octet reads) are replaced. FilePermissions / FileStatus / FileType / FileMode
enums are the real opendnp3 ones so the formatting/serialization runs for real.
"""

from typing import Any, Dict, List

import pytest

from tests.service_gate import require_import

opendnp3 = require_import("opendnp3", reason="yadnp3 (opendnp3) not installed")

from oida.protocols.dnp3.scanner import DNP3Scanner


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _FakeFileInfo:
    """Stand-in for opendnp3 FileInfo (read by _file_info_to_dict)."""

    def __init__(self, name, size, ftype, created=None, permissions=None):
        self.fileName = name
        self.size = size
        self.type = ftype
        self.timeOfCreation = created
        self.permissions = permissions


class _DirEntry(_FakeFileInfo):
    """A directory entry also carries .type used for the DIR/FILE label."""


class _DirResult:
    def __init__(self, status, entries=None, summary=None):
        self.statusCode = status
        self.entries = entries or []
        self.summary = summary


class _ReadResult:
    def __init__(self, status, data=b"", summary=None):
        self.statusCode = status
        self.data = data
        self.summary = summary


class _WriteResult:
    def __init__(self, status, summary=None):
        self.statusCode = status
        self.summary = summary


class _InfoResult:
    def __init__(self, status, info=None, summary=None):
        self.statusCode = status
        self.info = info
        self.summary = summary


class _AuthResult:
    def __init__(self, status, auth_key=0, summary=None):
        self.statusCode = status
        self.authKey = auth_key
        self.summary = summary


class _OctetItem:
    class _Val:
        def __init__(self, raw):
            self._raw = raw

        def ToBytes(self):
            return self._raw

    def __init__(self, index, raw):
        self.index = index
        self.value = self._Val(raw)


class _OctetHandler:
    def __init__(self):
        self.octet_strings: List[Any] = []
        self.cleared = 0

    def clear(self):
        self.cleared += 1


def _make_scanner(**overrides) -> DNP3Scanner:
    args = {"rhost": "127.0.0.1", "rport": 20000}
    args.update(overrides)
    scanner = DNP3Scanner(args)
    scanner._connected = True
    scanner._master = object()
    return scanner


def _arm_callback(scanner, result, capture=None):
    """Replace _sync_callback to run the build lambda then return ``result``."""

    class _FakeMaster:
        def ReadDirectory(self, path, cb, config):
            if capture is not None:
                capture["path"] = path

        def ReadFile(self, filename, cb, config):
            if capture is not None:
                capture["read"] = filename

        def ReadFileWithAuth(self, filename, auth_key, cb, config):
            if capture is not None:
                capture["read_auth"] = (filename, auth_key)

        def WriteFile(self, filename, data, perms, cb, config):
            if capture is not None:
                capture["write"] = (filename, data, perms)

        def WriteFileWithAuth(self, filename, data, perms, mode, auth_key, cb, config):
            if capture is not None:
                capture["write_auth"] = (filename, data, auth_key)

        def GetFileInfo(self, filename, cb, config):
            if capture is not None:
                capture["info"] = filename

        def DeleteFile(self, filename, cb, config):
            if capture is not None:
                capture["delete"] = filename

        def AuthenticateFile(self, username, password, cb, config):
            if capture is not None:
                capture["auth"] = (username, password)

    def fake(method_fn, timeout=None):
        method_fn(_FakeMaster(), lambda r: None, object())
        return result

    scanner._sync_callback = fake


_PERMS_644 = opendnp3.FilePermissions.FromRaw(0o644)


# ---------------------------------------------------------------------------
# _format_permissions / _file_info_to_dict (pure helpers)
# ---------------------------------------------------------------------------


class TestFormatHelpers:
    def test_format_permissions_644(self):
        scanner = _make_scanner()
        s = scanner._format_permissions(_PERMS_644)
        # 0o644 -> owner rw-, group r--, world r--
        assert s == "rw-r--r--"

    def test_format_permissions_missing_role(self):
        scanner = _make_scanner()

        class _Perms:
            owner = None
            group = None
            world = None

        assert scanner._format_permissions(_Perms()) == "---------"

    def test_file_info_to_dict_full(self):
        scanner = _make_scanner()
        info = _FakeFileInfo(
            "config.xml", 1234, opendnp3.FileType.SIMPLE_FILE, created=999, permissions=_PERMS_644
        )
        d = scanner._file_info_to_dict(info)
        assert d["name"] == "config.xml"
        assert d["size"] == 1234
        assert d["type"] == "SIMPLE_FILE"
        assert d["created"] == 999
        assert d["permissions"] == "rw-r--r--"
        assert d["permissions_raw"] == 0o644


# ---------------------------------------------------------------------------
# _list_directory
# ---------------------------------------------------------------------------


class TestListDirectory:
    def test_success_lists_entries(self):
        scanner = _make_scanner(**{"list-dir": "/"})
        entries = [
            _DirEntry("etc", 0, opendnp3.FileType.DIRECTORY, permissions=_PERMS_644),
            _DirEntry("boot.cfg", 512, opendnp3.FileType.SIMPLE_FILE, permissions=_PERMS_644),
        ]
        capture: Dict[str, Any] = {}
        _arm_callback(scanner, _DirResult(opendnp3.FileStatus.SUCCESS, entries), capture)
        results = {"operations": {}}
        scanner._list_directory(results)

        op = results["operations"]["list_dir"]
        assert op["success"] is True
        assert op["path"] == "/"
        assert op["count"] == 2
        names = [e["name"] for e in op["entries"]]
        assert "etc" in names and "boot.cfg" in names
        assert capture["path"] == "/"

    def test_timeout_returns_none(self):
        scanner = _make_scanner(**{"list-dir": "/x"})
        _arm_callback(scanner, None)
        results = {"operations": {}}
        scanner._list_directory(results)
        op = results["operations"]["list_dir"]
        assert op["success"] is False
        assert "Timeout" in op["error"]

    def test_failure_status_recorded(self):
        scanner = _make_scanner(**{"list-dir": "/secret"})
        _arm_callback(scanner, _DirResult(opendnp3.FileStatus.PERMISSION_DENIED))
        results = {"operations": {}}
        scanner._list_directory(results)
        op = results["operations"]["list_dir"]
        assert op["success"] is False
        assert "PERMISSION_DENIED" in op["error"]

    def test_exception_recorded(self):
        scanner = _make_scanner(**{"list-dir": "/"})
        scanner._sync_callback = lambda fn, timeout=None: (_ for _ in ()).throw(
            RuntimeError("nope")
        )
        results = {"operations": {}}
        scanner._list_directory(results)
        assert results["operations"]["list_dir"]["success"] is False
        assert "nope" in results["operations"]["list_dir"]["error"]


# ---------------------------------------------------------------------------
# _read_file
# ---------------------------------------------------------------------------


class TestReadFile:
    def test_success_text_preview(self):
        scanner = _make_scanner(**{"read-file": "/etc/banner"})
        capture: Dict[str, Any] = {}
        _arm_callback(scanner, _ReadResult(opendnp3.FileStatus.SUCCESS, b"line1\nline2\n"), capture)
        results = {"operations": {}}
        scanner._read_file(results)

        op = results["operations"]["read_file"]
        assert op["success"] is True
        assert op["size"] == 12
        assert op["data_hex"] == b"line1\nline2\n".hex()
        assert capture["read"] == "/etc/banner"

    def test_success_saves_to_disk(self, tmp_path):
        out = tmp_path / "sub" / "saved.bin"
        scanner = _make_scanner(**{"read-file": "/f", "save-file": str(out)})
        scanner.save_file = str(out)
        payload = b"\x00\x01\x02\xff"
        _arm_callback(scanner, _ReadResult(opendnp3.FileStatus.SUCCESS, payload))
        results = {"operations": {}}
        scanner._read_file(results)

        op = results["operations"]["read_file"]
        assert op["saved_to"] == str(out)
        assert out.read_bytes() == payload

    def test_large_binary_file_no_inline_hex(self):
        scanner = _make_scanner(**{"read-file": "/big"})
        # > 65536 bytes -> data_hex is omitted; > 4096 takes the large-binary
        # preview branch (first 64 bytes shown).
        payload = bytes(range(256)) * 300  # 76800 bytes
        _arm_callback(scanner, _ReadResult(opendnp3.FileStatus.SUCCESS, payload))
        results = {"operations": {}}
        scanner._read_file(results)
        op = results["operations"]["read_file"]
        assert op["success"] is True
        assert op["size"] == len(payload)
        assert op["data_hex"] is None

    def test_save_error_recorded(self, tmp_path):
        # Point save-file at a path whose parent is a file, so mkdir/write fails.
        blocker = tmp_path / "afile"
        blocker.write_text("x")
        bad = blocker / "nested" / "out.bin"
        scanner = _make_scanner(**{"read-file": "/f", "save-file": str(bad)})
        scanner.save_file = str(bad)
        _arm_callback(scanner, _ReadResult(opendnp3.FileStatus.SUCCESS, b"data"))
        results = {"operations": {}}
        scanner._read_file(results)
        op = results["operations"]["read_file"]
        assert op["success"] is True
        assert "save_error" in op

    def test_read_with_auth_key(self):
        scanner = _make_scanner(**{"read-file": "/f"})
        scanner._file_auth_key = 0xABCD
        capture: Dict[str, Any] = {}
        _arm_callback(scanner, _ReadResult(opendnp3.FileStatus.SUCCESS, b"ok"), capture)
        results = {"operations": {}}
        scanner._read_file(results)
        assert capture["read_auth"] == ("/f", 0xABCD)
        assert results["operations"]["read_file"]["success"] is True

    def test_timeout(self):
        scanner = _make_scanner(**{"read-file": "/f"})
        _arm_callback(scanner, None)
        results = {"operations": {}}
        scanner._read_file(results)
        assert results["operations"]["read_file"]["success"] is False
        assert "Timeout" in results["operations"]["read_file"]["error"]

    def test_failure_status(self):
        scanner = _make_scanner(**{"read-file": "/f"})
        _arm_callback(scanner, _ReadResult(opendnp3.FileStatus.FILE_NOT_FOUND))
        results = {"operations": {}}
        scanner._read_file(results)
        op = results["operations"]["read_file"]
        assert op["success"] is False
        assert "FILE_NOT_FOUND" in op["error"]


# ---------------------------------------------------------------------------
# _write_file
# ---------------------------------------------------------------------------


class TestWriteFile:
    def test_inline_data_write(self):
        scanner = _make_scanner(**{"write-file": "/tmp/x", "write-data": "hello"})
        capture: Dict[str, Any] = {}
        _arm_callback(scanner, _WriteResult(opendnp3.FileStatus.SUCCESS), capture)
        results = {"operations": {}}
        scanner._write_file(results)

        op = results["operations"]["write_file"]
        assert op["success"] is True
        assert op["size"] == 5
        # Bytes handed to WriteFile are the utf-8 encoding of the inline string.
        fname, data, perms = capture["write"]
        assert fname == "/tmp/x"
        assert data == b"hello"

    def test_at_file_payload_resolution(self, tmp_path):
        src = tmp_path / "payload.bin"
        src.write_bytes(b"\xde\xad\xbe\xef")
        scanner = _make_scanner(**{"write-file": "/dst", "write-data": f"@{src}"})
        capture: Dict[str, Any] = {}
        _arm_callback(scanner, _WriteResult(opendnp3.FileStatus.SUCCESS), capture)
        results = {"operations": {}}
        scanner._write_file(results)

        op = results["operations"]["write_file"]
        assert op["success"] is True
        assert op["size"] == 4
        assert capture["write"][1] == b"\xde\xad\xbe\xef"

    def test_missing_write_data(self):
        scanner = _make_scanner(**{"write-file": "/dst", "write-data": None})
        results = {"operations": {}}
        scanner._write_file(results)
        op = results["operations"]["write_file"]
        assert op["success"] is False
        assert "write-data" in op["error"]

    def test_missing_local_file(self, tmp_path):
        scanner = _make_scanner(
            **{"write-file": "/dst", "write-data": f"@{tmp_path}/does_not_exist"}
        )
        results = {"operations": {}}
        scanner._write_file(results)
        op = results["operations"]["write_file"]
        assert op["success"] is False
        assert "Cannot read local file" in op["error"]

    def test_write_with_auth(self):
        scanner = _make_scanner(**{"write-file": "/dst", "write-data": "x"})
        scanner._file_auth_key = 0x1234
        capture: Dict[str, Any] = {}
        _arm_callback(scanner, _WriteResult(opendnp3.FileStatus.SUCCESS), capture)
        results = {"operations": {}}
        scanner._write_file(results)
        assert capture["write_auth"][0] == "/dst"
        assert capture["write_auth"][2] == 0x1234

    def test_failure_status(self):
        scanner = _make_scanner(**{"write-file": "/dst", "write-data": "x"})
        _arm_callback(scanner, _WriteResult(opendnp3.FileStatus.PERMISSION_DENIED))
        results = {"operations": {}}
        scanner._write_file(results)
        op = results["operations"]["write_file"]
        assert op["success"] is False
        assert "PERMISSION_DENIED" in op["error"]


# ---------------------------------------------------------------------------
# _authenticate_file
# ---------------------------------------------------------------------------


class TestAuthenticateFile:
    def test_auth_success_stores_key(self):
        scanner = _make_scanner(**{"file-auth": "admin:secret"})
        capture: Dict[str, Any] = {}
        _arm_callback(scanner, _AuthResult(opendnp3.FileStatus.SUCCESS, auth_key=777), capture)
        results = {"operations": {}}
        scanner._authenticate_file(results)

        op = results["operations"]["file_auth"]
        assert op["success"] is True
        assert op["username"] == "admin"
        assert op["auth_key"] == 777
        # Key is stored for subsequent read/write-with-auth.
        assert scanner._file_auth_key == 777
        assert capture["auth"] == ("admin", "secret")

    def test_auth_username_only(self):
        scanner = _make_scanner(**{"file-auth": "operator"})
        capture: Dict[str, Any] = {}
        _arm_callback(scanner, _AuthResult(opendnp3.FileStatus.SUCCESS, auth_key=1), capture)
        results = {"operations": {}}
        scanner._authenticate_file(results)
        assert capture["auth"] == ("operator", "")

    def test_auth_failure(self):
        scanner = _make_scanner(**{"file-auth": "admin:wrong"})
        _arm_callback(scanner, _AuthResult(opendnp3.FileStatus.PERMISSION_DENIED))
        results = {"operations": {}}
        scanner._authenticate_file(results)
        assert results["operations"]["file_auth"]["success"] is False

    def test_auth_empty_is_noop(self):
        scanner = _make_scanner(**{"file-auth": None})
        results = {"operations": {}}
        scanner._authenticate_file(results)
        assert "file_auth" not in results["operations"]


# ---------------------------------------------------------------------------
# _get_file_info
# ---------------------------------------------------------------------------


class TestGetFileInfo:
    def test_success(self):
        scanner = _make_scanner(**{"file-info": "/etc/cfg"})
        info = _FakeFileInfo(
            "/etc/cfg", 4096, opendnp3.FileType.SIMPLE_FILE, created=123, permissions=_PERMS_644
        )
        _arm_callback(scanner, _InfoResult(opendnp3.FileStatus.SUCCESS, info))
        results = {"operations": {}}
        scanner._get_file_info(results)

        op = results["operations"]["file_info"]
        assert op["success"] is True
        assert op["size"] == 4096
        assert op["type"] == "SIMPLE_FILE"
        assert op["permissions"] == "rw-r--r--"

    def test_timeout(self):
        scanner = _make_scanner(**{"file-info": "/x"})
        _arm_callback(scanner, None)
        results = {"operations": {}}
        scanner._get_file_info(results)
        assert results["operations"]["file_info"]["success"] is False

    def test_failure_status(self):
        scanner = _make_scanner(**{"file-info": "/x"})
        _arm_callback(scanner, _InfoResult(opendnp3.FileStatus.FILE_NOT_FOUND))
        results = {"operations": {}}
        scanner._get_file_info(results)
        assert "FILE_NOT_FOUND" in results["operations"]["file_info"]["error"]


# ---------------------------------------------------------------------------
# _delete_remote_file
# ---------------------------------------------------------------------------


class TestDeleteFile:
    def test_delete_success(self):
        scanner = _make_scanner(**{"delete-file": "/tmp/old"})
        capture: Dict[str, Any] = {}
        _arm_callback(scanner, _WriteResult(opendnp3.FileStatus.SUCCESS), capture)
        results = {"operations": {}}
        scanner._delete_remote_file(results)
        op = results["operations"]["delete_file"]
        assert op["success"] is True
        assert op["filename"] == "/tmp/old"
        assert capture["delete"] == "/tmp/old"

    def test_delete_timeout(self):
        scanner = _make_scanner(**{"delete-file": "/tmp/old"})
        _arm_callback(scanner, None)
        results = {"operations": {}}
        scanner._delete_remote_file(results)
        assert results["operations"]["delete_file"]["success"] is False

    def test_delete_failure(self):
        scanner = _make_scanner(**{"delete-file": "/tmp/old"})
        _arm_callback(scanner, _WriteResult(opendnp3.FileStatus.PERMISSION_DENIED))
        results = {"operations": {}}
        scanner._delete_remote_file(results)
        op = results["operations"]["delete_file"]
        assert op["success"] is False
        assert "PERMISSION_DENIED" in op["error"]


# ---------------------------------------------------------------------------
# _read_octet_string
# ---------------------------------------------------------------------------


def _arm_octet_scan(scanner, *, succeed=True, items=None):
    handler = _OctetHandler()
    handler.octet_strings = items or []
    scanner._handler = handler
    scanner._scan_handler = handler

    def fake(scan_fn, timeout=None):
        if succeed:
            scanner._last_task_info = type("_T", (), {"result": opendnp3.TaskCompletion.SUCCESS})()
            return True
        scanner._last_task_info = type(
            "_T", (), {"result": opendnp3.TaskCompletion.FAILURE_NO_COMMS}
        )()
        return False

    scanner._sync_scan = fake


class TestReadOctetString:
    def test_success_filters_to_range(self):
        scanner = _make_scanner(**{"read-octet": "110:0-1"})
        items = [
            _OctetItem(0, b"\xaa\xbb"),
            _OctetItem(1, b"\xcc"),
            _OctetItem(5, b"\xff"),  # out of range, must be filtered out
        ]
        _arm_octet_scan(scanner, succeed=True, items=items)
        results = {"operations": {}}
        scanner._read_octet_string(results)

        op = results["operations"]["read_octet"]
        assert op["success"] is True
        assert op["group"] == 110
        assert op["count"] == 2  # index 5 filtered out
        idxs = [d["index"] for d in op["data"]]
        assert idxs == [0, 1]
        assert op["data"][0]["value"] == "aabb"
        assert op["data"][0]["length"] == 2

    def test_single_index(self):
        scanner = _make_scanner(**{"read-octet": "111:3"})
        _arm_octet_scan(scanner, succeed=True, items=[_OctetItem(3, b"\x01")])
        results = {"operations": {}}
        scanner._read_octet_string(results)
        op = results["operations"]["read_octet"]
        assert op["start"] == 3 and op["end"] == 3
        assert op["count"] == 1

    def test_invalid_group(self):
        scanner = _make_scanner(**{"read-octet": "99:0-1"})
        results = {"operations": {}}
        scanner._read_octet_string(results)
        op = results["operations"]["read_octet"]
        assert op["success"] is False
        assert "110" in op["error"]

    def test_bad_format(self):
        scanner = _make_scanner(**{"read-octet": "110"})
        results = {"operations": {}}
        scanner._read_octet_string(results)
        op = results["operations"]["read_octet"]
        assert op["success"] is False
        assert "GROUP" in op["error"]

    def test_scan_failure(self):
        scanner = _make_scanner(**{"read-octet": "110:0"})
        _arm_octet_scan(scanner, succeed=False)
        results = {"operations": {}}
        scanner._read_octet_string(results)
        op = results["operations"]["read_octet"]
        assert op["success"] is False
        assert "no communications" in op["error"]

    def test_non_numeric_range_value_error(self):
        # Group is parsed, but the index part is non-numeric -> ValueError path.
        scanner = _make_scanner(**{"read-octet": "110:abc"})
        results = {"operations": {}}
        scanner._read_octet_string(results)
        op = results["operations"]["read_octet"]
        assert op["success"] is False

    def test_octet_value_not_bytes(self):
        scanner = _make_scanner(**{"read-octet": "110:0"})

        class _StrVal:
            def ToBytes(self):
                return "plain-string"

        item = type("_I", (), {"index": 0, "value": _StrVal()})()
        _arm_octet_scan(scanner, succeed=True, items=[item])
        results = {"operations": {}}
        scanner._read_octet_string(results)
        op = results["operations"]["read_octet"]
        assert op["success"] is True
        assert op["data"][0]["value"] == "plain-string"

    def test_empty_octet_is_noop(self):
        scanner = _make_scanner(**{"read-octet": None})
        results = {"operations": {}}
        scanner._read_octet_string(results)
        assert "read_octet" not in results["operations"]


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
