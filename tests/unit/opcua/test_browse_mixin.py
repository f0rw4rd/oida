#!/usr/bin/env python3
"""Behavioural tests for the OPC UA BrowseMixin.

Drives the real ``_dump_address_space`` / ``_read_node`` coroutines against
realistic asyncua-shaped node objects. Only the asyncua client/node boundary is
mocked -- the BFS traversal, filtering, access-level decoding, value reads,
writable-finding emission and export call are all exercised for real.
"""

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from asyncua import ua

from oida.protocols.opcua.helpers import _asyncua
from oida.protocols.opcua.mixins.browse import BrowseMixin
from oida.utils.common_types import Category


def _skip_if_no_asyncua():
    if not _asyncua.is_available:
        raise unittest.SkipTest("asyncua not available")


class _BrowseName:
    def __init__(self, name):
        self.Name = name


class _DisplayName:
    def __init__(self, text):
        self.Text = text


class _NodeId:
    def __init__(self, identifier, ns=0):
        self.Identifier = identifier
        self.NamespaceIndex = ns

    def to_string(self):
        if self.NamespaceIndex == 0:
            return f"i={self.Identifier}"
        return f"ns={self.NamespaceIndex};i={self.Identifier}"


class _AttrResult:
    """Mimics a DataValue: ``.Value.Value`` holds the scalar."""

    def __init__(self, value):
        self.Value = SimpleNamespace(Value=value)


class FakeNode:
    """A realistic asyncua-style node.

    ``node_class`` should be a string ("Variable"/"Method"/"Object"). The
    real ``read_node_class`` returns an enum whose ``.name`` is the class, so
    we mimic that.
    """

    def __init__(
        self,
        identifier,
        name,
        node_class="Object",
        ns=0,
        children=None,
        access=None,
        data_type_name=None,
        value=None,
        executable=None,
        user_executable=None,
    ):
        self.nodeid = _NodeId(identifier, ns)
        self._name = name
        self._node_class = node_class
        self._children = children or []
        self._access = access or set()
        self._data_type_name = data_type_name
        self._value = value
        self._executable = executable
        self._user_executable = user_executable

    async def read_browse_name(self):
        return _BrowseName(self._name)

    async def read_display_name(self):
        return _DisplayName(self._name)

    async def read_node_class(self):
        return SimpleNamespace(name=self._node_class)

    async def get_children(self):
        return list(self._children)

    async def read_value(self):
        return self._value

    async def get_access_level(self):
        return self._access

    async def read_data_type(self):
        # Returns a NodeId-like object that the client resolves to a node.
        return _NodeId(99)

    async def read_attribute(self, attr_id):
        if attr_id == ua.AttributeIds.Executable:
            return _AttrResult(self._executable)
        if attr_id == ua.AttributeIds.UserExecutable:
            return _AttrResult(self._user_executable)
        return _AttrResult(None)


class _Client:
    """Fake asyncua client; resolves a fixed root and data-type nodes."""

    def __init__(self, root, data_type_name="Double"):
        self._root = root
        self._data_type_name = data_type_name

    def get_root_node(self):
        return self._root

    def get_node(self, node_id):
        # Used for resolving DataType node and for start_node / read_node.
        dt = FakeNode(99, self._data_type_name, node_class="DataType")
        return dt


class _BrowseHost(BrowseMixin):
    def __init__(self, root, args, data_type_name="Double"):
        self.args = args
        self.logger = MagicMock()
        self.results = {"data": {}}
        self.host = "10.0.0.5"
        self._client = _Client(root, data_type_name=data_type_name)


def _args(**kw):
    base = dict(max_depth=3, max_nodes=1000, format="console", output=None)
    base.update(kw)
    return SimpleNamespace(**base)


def _build_tree():
    """Two devices: one read-only var, one writable var, one method."""
    temp = FakeNode(
        2001, "Temperature", "Variable", ns=2, access={ua.AccessLevel.CurrentRead}, value=21.5
    )
    setpoint = FakeNode(
        2002,
        "Setpoint",
        "Variable",
        ns=2,
        access={ua.AccessLevel.CurrentRead, ua.AccessLevel.CurrentWrite},
        value=42.0,
    )
    start = FakeNode(3001, "Start", "Method", ns=2, executable=True, user_executable=True)
    dev = FakeNode(1001, "Device1", "Object", ns=2, children=[temp, setpoint, start])
    objects = FakeNode(85, "Objects", "Object", children=[dev])
    root = FakeNode(84, "Root", "Object", children=[objects])
    return root


def _run(host, coro_factory):
    import asyncio

    return asyncio.run(coro_factory(host))


class TestDumpFastMode(unittest.IsolatedAsyncioTestCase):
    async def test_fast_mode_collects_all_nodes(self):
        _skip_if_no_asyncua()
        host = _BrowseHost(_build_tree(), _args(max_depth=4))
        await host._dump_address_space(mode="fast")

        nodes = host.results["data"]["nodes"]
        names = {n["name"] for n in nodes}
        # Root + Objects + Device1 + the three leaves are all reachable at depth 4.
        self.assertIn("Root", names)
        self.assertIn("Setpoint", names)
        self.assertIn("Temperature", names)
        self.assertIn("Start", names)
        # Fast mode does not populate data_type / access columns.
        sp = next(n for n in nodes if n["name"] == "Setpoint")
        self.assertEqual(sp["data_type"], "")
        self.assertEqual(sp["access"], "")
        # Node IDs carry the explicit ns= prefix.
        self.assertTrue(sp["node_id"].startswith("ns=2;i=2002"))

    async def test_max_depth_prunes_traversal(self):
        _skip_if_no_asyncua()
        # depth=2 -> Root(0), Objects(1); children of Objects sit at depth 2 == max
        # and are excluded by `depth >= max_depth`.
        host = _BrowseHost(_build_tree(), _args(max_depth=2))
        await host._dump_address_space(mode="fast")
        names = {n["name"] for n in host.results["data"]["nodes"]}
        self.assertIn("Root", names)
        self.assertIn("Objects", names)
        self.assertNotIn("Device1", names)

    async def test_max_nodes_caps_results(self):
        _skip_if_no_asyncua()
        host = _BrowseHost(_build_tree(), _args(max_depth=5, max_nodes=2))
        await host._dump_address_space(mode="fast")
        self.assertLessEqual(len(host.results["data"]["nodes"]), 2)


class TestDumpFullMode(unittest.IsolatedAsyncioTestCase):
    async def test_full_mode_decodes_access_and_datatype(self):
        _skip_if_no_asyncua()
        host = _BrowseHost(_build_tree(), _args(max_depth=4), data_type_name="Double")
        await host._dump_address_space(mode="full")
        nodes = host.results["data"]["nodes"]

        setpoint = next(n for n in nodes if n["name"] == "Setpoint")
        # CurrentRead + CurrentWrite -> "RW", writable flagged.
        self.assertEqual(setpoint["access"], "RW")
        self.assertTrue(setpoint["writable"])
        self.assertEqual(setpoint["data_type"], "Double")

        temp = next(n for n in nodes if n["name"] == "Temperature")
        self.assertEqual(temp["access"], "R")
        self.assertFalse(temp["writable"])

    async def test_full_mode_with_values(self):
        _skip_if_no_asyncua()
        host = _BrowseHost(_build_tree(), _args(max_depth=4, dump_values=True))
        await host._dump_address_space(mode="full")
        setpoint = next(n for n in host.results["data"]["nodes"] if n["name"] == "Setpoint")
        self.assertEqual(setpoint["value"], "42.0")

    async def test_writable_finding_emitted(self):
        _skip_if_no_asyncua()
        # Use a real logger so we can assert the finding was collected with the
        # current ACCESS_CONTROL category.
        from oida.utils.ics_logger import ICSLogger

        host = _BrowseHost(_build_tree(), _args(max_depth=4))
        host.logger = ICSLogger("opcua", "10.0.0.5", 4840)
        host.logger.clear_findings()
        await host._dump_address_space(mode="full")

        findings = host.logger.to_list()
        titles = {f["title"] for f in findings}
        self.assertIn("Writable access", titles)
        wf = next(f for f in findings if f["title"] == "Writable access")
        self.assertEqual(wf["category"], str(Category.ACCESS_CONTROL))
        self.assertIn("writable", wf["detail"])


class TestDumpFilters(unittest.IsolatedAsyncioTestCase):
    async def test_methods_mode_keeps_only_methods(self):
        _skip_if_no_asyncua()
        host = _BrowseHost(_build_tree(), _args(max_depth=4))
        # _get_method_details / _format_method_args are pulled from the methods
        # mixin in production; provide a faithful stand-in so methods-mode runs.
        host._get_method_details = AsyncMock(
            return_value={
                "description": "",
                "input_args": [],
                "output_args": [],
                "executable": True,
                "user_executable": True,
            }
        )
        host._format_method_args = lambda a: "()"
        await host._dump_address_space(mode="methods")
        nodes = host.results["data"]["nodes"]
        self.assertTrue(nodes)
        self.assertTrue(all(n["class"] == "Method" for n in nodes))
        self.assertEqual(nodes[0]["name"], "Start")

    async def test_write_mode_keeps_only_writable(self):
        _skip_if_no_asyncua()
        host = _BrowseHost(_build_tree(), _args(max_depth=4))
        await host._dump_address_space(mode="write")
        nodes = host.results["data"]["nodes"]
        self.assertTrue(nodes)
        self.assertTrue(all(n["writable"] for n in nodes))
        self.assertEqual({n["name"] for n in nodes}, {"Setpoint"})

    async def test_namespace_filter(self):
        _skip_if_no_asyncua()
        # Only ns=2 nodes should survive (Root/Objects are ns=0).
        host = _BrowseHost(_build_tree(), _args(max_depth=4, ns="2"))
        await host._dump_address_space(mode="fast")
        nodes = host.results["data"]["nodes"]
        self.assertTrue(nodes)
        self.assertTrue(all(n["namespace"] == 2 for n in nodes))

    async def test_invalid_namespace_filter_aborts(self):
        _skip_if_no_asyncua()
        host = _BrowseHost(_build_tree(), _args(ns="not-a-number"))
        await host._dump_address_space(mode="fast")
        # Should bail before populating nodes.
        self.assertNotIn("nodes", host.results["data"])
        host.logger.fail.assert_called()


class TestDumpStartNode(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_start_node_aborts(self):
        _skip_if_no_asyncua()
        host = _BrowseHost(_build_tree(), _args(start_node="ns=2;s=missing"))

        # get_node raises when resolving start node browse name.
        bad = MagicMock()
        bad.read_browse_name = AsyncMock(side_effect=RuntimeError("no such node"))
        host._client.get_node = MagicMock(return_value=bad)

        await host._dump_address_space(mode="fast")
        self.assertNotIn("nodes", host.results["data"])
        host.logger.fail.assert_called()


class TestReadNode(unittest.IsolatedAsyncioTestCase):
    async def test_read_node_value_only(self):
        _skip_if_no_asyncua()
        host = _BrowseHost(_build_tree(), _args(node_id="ns=2;i=2002"))
        target = FakeNode(2002, "Setpoint", "Variable", ns=2, value=42.0)
        host._client.get_node = MagicMock(return_value=target)

        await host._read_node()
        nr = host.results["data"]["node_read"]
        self.assertEqual(nr["node_id"], "ns=2;i=2002")
        self.assertEqual(nr["value"], "42.0")

    async def test_read_node_with_attributes(self):
        _skip_if_no_asyncua()
        host = _BrowseHost(_build_tree(), _args(node_id="ns=2;i=2002", read_attributes=True))

        target = FakeNode(2002, "Setpoint", "Variable", ns=2, value=42.0)

        async def _dtype():
            return SimpleNamespace(name="Double")

        async def _access():
            return {ua.AccessLevel.CurrentRead, ua.AccessLevel.CurrentWrite}

        target.read_data_type_as_variant_type = _dtype
        target.get_access_level = _access
        host._client.get_node = MagicMock(return_value=target)

        await host._read_node()
        self.assertEqual(host.results["data"]["node_read"]["value"], "42.0")
        # Several display lines (browse/display/class) must have been emitted.
        self.assertGreaterEqual(host.logger.display.call_count, 4)

    async def test_read_node_missing_id_fails(self):
        _skip_if_no_asyncua()
        host = _BrowseHost(_build_tree(), _args(node_id=None))
        await host._read_node()
        host.logger.fail.assert_called()
        self.assertNotIn("node_read", host.results["data"])

    async def test_read_node_handles_error(self):
        _skip_if_no_asyncua()
        host = _BrowseHost(_build_tree(), _args(node_id="ns=2;i=999"))
        bad = MagicMock()
        bad.read_value = AsyncMock(side_effect=RuntimeError("BadNodeIdUnknown"))
        host._client.get_node = MagicMock(return_value=bad)
        await host._read_node()
        host.logger.fail.assert_called()


class TestDumpExportBoundary(unittest.TestCase):
    """Confirm dump routes results through export_data with mode-correct headers."""

    def test_full_mode_headers(self):
        _skip_if_no_asyncua()
        import asyncio

        captured = {}

        def _capture(data, headers, **kw):
            captured["headers"] = headers
            captured["rows"] = data

        # _dump_address_space imports export_data lazily from this module, so
        # patch it at the source.
        with patch("oida.utils.export_utils.export_data", _capture):
            host = _BrowseHost(_build_tree(), _args(max_depth=4))
            asyncio.run(host._dump_address_space(mode="full"))

        self.assertIn("DataType", captured["headers"])
        self.assertIn("Access", captured["headers"])
        self.assertTrue(captured["rows"])


if __name__ == "__main__":
    unittest.main()
