#!/usr/bin/env python3
"""Behavioural tests for the OPC UA FilesMixin.

Covers ``_dump_files`` (FileType discovery + writable warning), ``_write_file``
(confirm gate, writable check, chunked write, error paths) and the display /
output branches of ``_read_file`` not already covered by
``test_files_read_cap.py``. Only the asyncua client/node boundary is mocked.
"""

import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from oida.protocols.opcua.helpers import _asyncua, ua
from oida.protocols.opcua.mixins.files import FilesMixin


def _skip_if_no_asyncua():
    if not _asyncua.is_available:
        raise unittest.SkipTest("asyncua not available")


class _BrowseName:
    def __init__(self, name):
        self.Name = name


class _NodeId:
    def __init__(self, s):
        self._s = s

    def to_string(self):
        return self._s


class _Prop:
    """A simple property node returning a fixed read_value()."""

    def __init__(self, value):
        self._value = value

    async def read_value(self):
        return self._value


class FileNode:
    """A FileType-like object node.

    ``children`` maps browse-name -> child node. ``type_def_identifier`` set to
    ua.ObjectIds.FileType marks it as a standard FileType. ``size`` / ``writable``
    expose 0:Size and 0:Writable child properties.
    """

    def __init__(
        self,
        node_id,
        name,
        *,
        node_class=ua.NodeClass.Object,
        type_def_identifier=None,
        children=None,
        size=None,
        writable=None,
    ):
        self.nodeid = _NodeId(node_id)
        self._name = name
        self._node_class = node_class
        self._type_def_identifier = type_def_identifier
        self._children = children or []
        self._size = size
        self._writable = writable

    async def read_browse_name(self):
        return _BrowseName(self._name)

    async def read_node_class(self):
        return self._node_class

    async def read_type_definition(self):
        if self._type_def_identifier is None:
            raise RuntimeError("no type definition")
        return SimpleNamespace(Identifier=self._type_def_identifier)

    async def get_children(self):
        return list(self._children)

    async def get_child(self, rel):
        if rel == "0:Size" and self._size is not None:
            return _Prop(self._size)
        if rel == "0:Writable" and self._writable is not None:
            return _Prop(self._writable)
        raise RuntimeError(f"no child {rel}")


class _ObjectsClient:
    def __init__(self, objects_node):
        self._objects = objects_node

    def get_objects_node(self):
        return self._objects

    def get_node(self, node_id):  # pragma: no cover - overridden per test
        raise RuntimeError("get_node not configured")


class _FilesHost(FilesMixin):
    def __init__(self, objects_node=None, args=None):
        self.args = args or SimpleNamespace(max_depth=4, max_nodes=500)
        self.logger = MagicMock()
        self.results = {"data": {}}
        self.host = "10.0.0.5"
        self._client = _ObjectsClient(objects_node) if objects_node else MagicMock()


class TestDumpFiles(unittest.IsolatedAsyncioTestCase):
    async def test_standard_filetype_discovered(self):
        _skip_if_no_asyncua()
        cfg = FileNode(
            "ns=2;s=config.xml",
            "config.xml",
            type_def_identifier=ua.ObjectIds.FileType,
            size=2048,
            writable=False,
        )
        objects = FileNode("i=85", "Objects", children=[cfg])
        host = _FilesHost(objects)

        await host._dump_files()

        file_nodes = host.results["data"]["file_nodes"]
        self.assertEqual(len(file_nodes), 1)
        fn = file_nodes[0]
        self.assertEqual(fn["name"], "config.xml")
        self.assertEqual(fn["size"], 2048)
        self.assertFalse(fn["writable"])
        host.logger.success.assert_called()

    async def test_writable_file_triggers_warning(self):
        _skip_if_no_asyncua()
        firmware = FileNode(
            "ns=2;s=firmware.bin",
            "firmware.bin",
            type_def_identifier=ua.ObjectIds.FileType,
            size=4096,
            writable=True,
        )
        objects = FileNode("i=85", "Objects", children=[firmware])
        host = _FilesHost(objects)

        await host._dump_files()

        file_nodes = host.results["data"]["file_nodes"]
        self.assertEqual(len(file_nodes), 1)
        self.assertTrue(file_nodes[0]["writable"])
        # Writable files raise a highlighted attack-vector warning.
        host.logger.highlight.assert_called()
        msg = host.logger.highlight.call_args[0][0]
        self.assertIn("writable", msg)

    async def test_file_like_object_by_extension_and_children(self):
        _skip_if_no_asyncua()
        # No standard FileType type-def, but name has an extension AND a Size
        # child -> classified as file-like via is_file_like().
        size_child = FileNode("ns=2;s=log.txt.Size", "Size")
        loglike = FileNode(
            "ns=2;s=log.txt",
            "log.txt",
            children=[size_child],
            size=512,
            writable=None,
        )
        objects = FileNode("i=85", "Objects", children=[loglike])
        host = _FilesHost(objects)

        await host._dump_files()
        file_nodes = host.results["data"]["file_nodes"]
        self.assertEqual([f["name"] for f in file_nodes], ["log.txt"])

    async def test_no_files_found_warns(self):
        _skip_if_no_asyncua()
        plain = FileNode("ns=2;s=Folder", "Folder")  # no extension, not a FileType
        objects = FileNode("i=85", "Objects", children=[plain])
        host = _FilesHost(objects)

        await host._dump_files()
        self.assertNotIn("file_nodes", host.results["data"])
        host.logger.warning.assert_called()

    async def test_size_and_writable_via_child_iteration_fallback(self):
        _skip_if_no_asyncua()
        # get_child("0:Size"/"0:Writable") fails (size/writable kept None), but
        # the FileType node exposes child nodes literally named Size / Writable,
        # forcing the namespace-2 iteration fallback path.
        size_child = FileNode("ns=2;s=fw.Size", "Size", size=8192)

        class _ValProp(FileNode):
            async def read_value(self):
                return self._reported

        size_node = _ValProp("ns=2;s=fw.Size", "Size")
        size_node._reported = 8192
        writable_node = _ValProp("ns=2;s=fw.Writable", "Writable")
        writable_node._reported = True

        fw = FileNode(
            "ns=2;s=fw.bin",
            "fw.bin",
            type_def_identifier=ua.ObjectIds.FileType,
            children=[size_node, writable_node],
            size=None,  # 0:Size get_child raises -> fallback iterates children
            writable=None,
        )
        _ = size_child
        objects = FileNode("i=85", "Objects", children=[fw])
        host = _FilesHost(objects)

        await host._dump_files()
        file_nodes = host.results["data"]["file_nodes"]
        self.assertEqual(len(file_nodes), 1)
        self.assertEqual(file_nodes[0]["size"], 8192)
        self.assertTrue(file_nodes[0]["writable"])


def _make_file_node_with_methods(name="data.bin", writable=True):
    """Build a file node exposing 0:Open / 0:Write / 0:Close (and Writable)."""
    open_m, write_m, close_m, read_m = object(), object(), object(), object()
    served = {"handle": None, "written": bytearray(), "closed": False}

    node = MagicMock()
    node.nodeid = _NodeId("ns=2;s=" + name)
    node.read_browse_name = AsyncMock(return_value=_BrowseName(name))

    async def _get_child(rel):
        mapping = {
            "0:Open": open_m,
            "0:Write": write_m,
            "0:Close": close_m,
            "0:Read": read_m,
        }
        if rel in mapping:
            return mapping[rel]
        if rel == "0:Writable":
            return _Prop(writable)
        raise RuntimeError(f"no child {rel}")

    async def _call_method(method, *cargs):
        if method is open_m:
            served["handle"] = 1
            return 1
        if method is write_m:
            served["written"].extend(bytes(cargs[1]))
            return None
        if method is close_m:
            served["closed"] = True
            return None
        raise RuntimeError("unexpected method")

    node.get_child = AsyncMock(side_effect=_get_child)
    node.call_method = AsyncMock(side_effect=_call_method)
    return node, served


def _write_args(**kw):
    base = dict(write_file="ns=2;s=data.bin", confirm=True, file_data="hello world")
    base.update(kw)
    return SimpleNamespace(**base)


class TestWriteFile(unittest.IsolatedAsyncioTestCase):
    def _host(self, node, args):
        host = _FilesHost(args=args)
        host._client = MagicMock()
        host._client.get_node = MagicMock(return_value=node)
        return host

    async def test_requires_confirm(self):
        _skip_if_no_asyncua()
        node, _ = _make_file_node_with_methods()
        host = self._host(node, _write_args(confirm=False))
        await host._write_file()
        host.logger.fail.assert_called()
        self.assertNotIn("file_write", host.results["data"])

    async def test_requires_file_data(self):
        _skip_if_no_asyncua()
        node, _ = _make_file_node_with_methods()
        host = self._host(node, _write_args(file_data=None))
        await host._write_file()
        host.logger.fail.assert_called()
        self.assertNotIn("file_write", host.results["data"])

    async def test_inline_data_written_in_chunks(self):
        _skip_if_no_asyncua()
        node, served = _make_file_node_with_methods()
        host = self._host(node, _write_args(file_data="hello world"))
        await host._write_file()

        fw = host.results["data"]["file_write"]
        self.assertTrue(fw["success"])
        self.assertEqual(fw["bytes_written"], len("hello world"))
        self.assertEqual(bytes(served["written"]), b"hello world")
        self.assertTrue(served["closed"])

    async def test_file_path_uploaded(self):
        _skip_if_no_asyncua()
        node, served = _make_file_node_with_methods()
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"X" * 5000)  # spans more than one 4096 chunk
            path = tf.name
        try:
            host = self._host(node, _write_args(file_data=path))
            await host._write_file()
        finally:
            os.unlink(path)

        fw = host.results["data"]["file_write"]
        self.assertEqual(fw["bytes_written"], 5000)
        self.assertEqual(len(served["written"]), 5000)

    async def test_not_writable_aborts(self):
        _skip_if_no_asyncua()
        node, served = _make_file_node_with_methods(writable=False)
        host = self._host(node, _write_args())
        await host._write_file()
        host.logger.fail.assert_called()
        self.assertNotIn("file_write", host.results["data"])
        # No write method should have run.
        self.assertEqual(len(served["written"]), 0)

    async def test_open_for_write_status_error(self):
        _skip_if_no_asyncua()
        node, _ = _make_file_node_with_methods()

        async def _call_method(method, *cargs):
            raise ua.UaStatusCodeError("BadNotWritable")

        node.call_method = AsyncMock(side_effect=_call_method)
        host = self._host(node, _write_args())
        await host._write_file()
        host.logger.fail.assert_called()
        self.assertNotIn("file_write", host.results["data"])


class TestReadFileOutputPaths(unittest.IsolatedAsyncioTestCase):
    def _read_node(self, *, content, name="readme.txt"):
        open_m, read_m, close_m = object(), object(), object()
        state = {"served": 0, "closed": False}

        node = MagicMock()
        node.nodeid = _NodeId("ns=2;s=" + name)
        node.read_browse_name = AsyncMock(return_value=_BrowseName(name))

        async def _get_child(rel):
            mapping = {"0:Open": open_m, "0:Read": read_m, "0:Close": close_m}
            if rel == "0:Size":
                return _Prop(len(content))
            if rel in mapping:
                return mapping[rel]
            raise RuntimeError(f"no child {rel}")

        async def _call_method(method, *cargs):
            if method is open_m:
                return 1
            if method is close_m:
                state["closed"] = True
                return None
            if method is read_m:
                chunk_size = cargs[1]
                remaining = len(content) - state["served"]
                n = min(chunk_size, remaining)
                start = state["served"]
                state["served"] += n
                return content[start : start + n]
            raise RuntimeError("unexpected method")

        node.get_child = AsyncMock(side_effect=_get_child)
        node.call_method = AsyncMock(side_effect=_call_method)
        return node, state

    def _host(self, node, args):
        host = _FilesHost(args=args)
        host._client = MagicMock()
        host._client.get_node = MagicMock(return_value=node)
        return host

    async def test_text_content_displayed(self):
        _skip_if_no_asyncua()
        node, state = self._read_node(content=b"line1\nline2\nline3\n")
        host = self._host(node, SimpleNamespace(read_file="ns=2;s=readme.txt", file_output=None))
        await host._read_file()
        fr = host.results["data"]["file_read"]
        self.assertEqual(fr["size"], len(b"line1\nline2\nline3\n"))
        self.assertTrue(state["closed"])

    async def test_binary_content_hex_preview(self):
        _skip_if_no_asyncua()
        blob = bytes([0x00, 0xFF, 0x10, 0x80]) * 20
        node, _ = self._read_node(content=blob, name="dump.bin")
        host = self._host(node, SimpleNamespace(read_file="ns=2;s=dump.bin", file_output=None))
        await host._read_file()
        fr = host.results["data"]["file_read"]
        self.assertEqual(fr["size"], len(blob))
        self.assertEqual(fr["content_preview"], blob[:256].hex())

    async def test_output_written_to_file(self):
        _skip_if_no_asyncua()
        content = b"saved-output-data"
        node, _ = self._read_node(content=content, name="out.dat")
        # safe_file_path() confines output to the CWD, so write inside it.
        out_dir = tempfile.mkdtemp(dir=os.getcwd())
        out_path = os.path.join(out_dir, "downloaded.dat")
        host = self._host(
            node,
            SimpleNamespace(read_file="ns=2;s=out.dat", file_output=out_path),
        )
        try:
            await host._read_file()
            self.assertTrue(os.path.exists(out_path))
            with open(out_path, "rb") as f:
                self.assertEqual(f.read(), content)
        finally:
            if os.path.exists(out_path):
                os.unlink(out_path)
            os.rmdir(out_dir)

    async def test_open_read_status_error(self):
        _skip_if_no_asyncua()
        node, _ = self._read_node(content=b"data")

        async def _call_method(method, *cargs):
            raise ua.UaStatusCodeError("BadNotReadable")

        node.call_method = AsyncMock(side_effect=_call_method)
        host = self._host(node, SimpleNamespace(read_file="ns=2;s=readme.txt", file_output=None))
        await host._read_file()
        host.logger.fail.assert_called()
        self.assertNotIn("file_read", host.results["data"])

    async def test_no_read_file_arg_is_noop(self):
        _skip_if_no_asyncua()
        host = _FilesHost(args=SimpleNamespace(read_file=None, file_output=None))
        await host._read_file()
        self.assertNotIn("file_read", host.results["data"])


if __name__ == "__main__":
    unittest.main()
