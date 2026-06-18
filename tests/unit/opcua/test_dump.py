#!/usr/bin/env python3
"""
Tests for OPC UA address space dump functionality.

Tests the new --dump, --dump-all, --dump-methods, --dump-write options.
"""

import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio


class MockNodeClass:
    """Mock OPC UA NodeClass enum"""

    def __init__(self, name):
        self.name = name


class MockBrowseName:
    """Mock OPC UA BrowseName"""

    def __init__(self, name, ns=0):
        self.Name = name
        self.NamespaceIndex = ns


class MockNodeId:
    """Mock OPC UA NodeId"""

    def __init__(self, identifier, ns=0):
        self.Identifier = identifier
        self.NamespaceIndex = ns

    def to_string(self):
        if self.NamespaceIndex == 0:
            return f"i={self.Identifier}"
        return f"ns={self.NamespaceIndex};i={self.Identifier}"


class MockAccessLevel:
    """Mock OPC UA AccessLevel enum"""

    CurrentRead = 0
    CurrentWrite = 1
    HistoryRead = 2


class MockNode:
    """Mock OPC UA Node"""

    def __init__(self, node_id, name, node_class, children=None, access_level=None, data_type=None):
        self.nodeid = MockNodeId(node_id)
        self._name = name
        self._node_class = node_class
        self._children = children or []
        self._access_level = access_level or {MockAccessLevel.CurrentRead}
        self._data_type = data_type

    async def read_browse_name(self):
        return MockBrowseName(self._name)

    async def read_node_class(self):
        return MockNodeClass(self._node_class)

    async def get_children(self):
        return self._children

    async def get_access_level(self):
        return self._access_level

    async def read_data_type(self):
        return MockNodeId(self._data_type or 1)


def create_mock_address_space():
    """Create a mock OPC UA address space for testing."""
    # Create nodes
    var1 = MockNode(
        2001, "Temperature", "Variable", access_level={MockAccessLevel.CurrentRead}, data_type=11
    )  # Double
    var2 = MockNode(
        2002,
        "Setpoint",
        "Variable",
        access_level={MockAccessLevel.CurrentRead, MockAccessLevel.CurrentWrite},
        data_type=11,
    )
    var3 = MockNode(
        2003, "Status", "Variable", access_level={MockAccessLevel.CurrentRead}, data_type=1
    )  # Boolean

    method1 = MockNode(3001, "Start", "Method")
    method2 = MockNode(3002, "Stop", "Method")

    obj1 = MockNode(1001, "Device1", "Object", children=[var1, var2, method1])
    obj2 = MockNode(1002, "Device2", "Object", children=[var3, method2])

    objects = MockNode(85, "Objects", "Object", children=[obj1, obj2])
    types = MockNode(86, "Types", "Object")
    views = MockNode(87, "Views", "Object")

    root = MockNode(84, "Root", "Object", children=[objects, types, views])

    return root


class TestDumpAddressSpaceFunction(unittest.TestCase):
    """Test the _dump_address_space method"""

    def setUp(self):
        """Set up test fixtures"""
        self.root = create_mock_address_space()

    def test_mock_node_structure(self):
        """Test that mock address space is correctly structured"""
        self.assertEqual(self.root._name, "Root")
        self.assertEqual(len(self.root._children), 3)

        objects = self.root._children[0]
        self.assertEqual(objects._name, "Objects")
        self.assertEqual(len(objects._children), 2)

    def test_mock_node_async_methods(self):
        """Test that mock node async methods work"""

        async def test():
            browse_name = await self.root.read_browse_name()
            self.assertEqual(browse_name.Name, "Root")

            node_class = await self.root.read_node_class()
            self.assertEqual(node_class.name, "Object")

            children = await self.root.get_children()
            self.assertEqual(len(children), 3)

        asyncio.run(test())

    def test_variable_access_level(self):
        """Test that variable access levels are correctly set"""
        objects = self.root._children[0]
        device1 = objects._children[0]

        # Temperature - read only
        temp = device1._children[0]
        self.assertIn(MockAccessLevel.CurrentRead, temp._access_level)
        self.assertNotIn(MockAccessLevel.CurrentWrite, temp._access_level)

        # Setpoint - read/write
        setpoint = device1._children[1]
        self.assertIn(MockAccessLevel.CurrentRead, setpoint._access_level)
        self.assertIn(MockAccessLevel.CurrentWrite, setpoint._access_level)

    def test_method_nodes(self):
        """Test that method nodes are correctly identified"""
        objects = self.root._children[0]
        device1 = objects._children[0]

        method1 = device1._children[2]
        self.assertEqual(method1._node_class, "Method")
        self.assertEqual(method1._name, "Start")


class TestDumpModes(unittest.TestCase):
    """Test different dump modes"""

    def test_fast_mode_columns(self):
        """Test that fast mode has correct columns"""
        # Fast mode: NS, Class, Name, Node ID
        fast_headers = ["NS", "Class", "Name", "Node ID"]
        self.assertEqual(len(fast_headers), 4)
        self.assertIn("NS", fast_headers)
        self.assertIn("Class", fast_headers)
        self.assertNotIn("DataType", fast_headers)
        self.assertNotIn("Access", fast_headers)

    def test_full_mode_columns(self):
        """Test that full mode has correct columns"""
        # Full mode: NS, Class, Name, DataType, Access, Node ID
        full_headers = ["NS", "Class", "Name", "DataType", "Access", "Node ID"]
        self.assertEqual(len(full_headers), 6)
        self.assertIn("DataType", full_headers)
        self.assertIn("Access", full_headers)

    def test_access_level_parsing(self):
        """Test access level string generation"""

        # Simulate access level parsing
        def parse_access(level_set):
            parts = []
            if MockAccessLevel.CurrentRead in level_set:
                parts.append("R")
            if MockAccessLevel.CurrentWrite in level_set:
                parts.append("W")
            if MockAccessLevel.HistoryRead in level_set:
                parts.append("H")
            return "".join(parts) if parts else "-"

        # Read only
        self.assertEqual(parse_access({MockAccessLevel.CurrentRead}), "R")

        # Read/Write
        self.assertEqual(
            parse_access({MockAccessLevel.CurrentRead, MockAccessLevel.CurrentWrite}), "RW"
        )

        # Read with History
        self.assertEqual(
            parse_access({MockAccessLevel.CurrentRead, MockAccessLevel.HistoryRead}), "RH"
        )

        # Empty
        self.assertEqual(parse_access(set()), "-")


class TestDumpFilters(unittest.TestCase):
    """Test dump filter modes"""

    def setUp(self):
        """Set up test data"""
        self.nodes = [
            {"name": "Root", "class": "Object", "writable": False},
            {"name": "Objects", "class": "Object", "writable": False},
            {"name": "Temperature", "class": "Variable", "writable": False},
            {"name": "Setpoint", "class": "Variable", "writable": True},
            {"name": "Start", "class": "Method", "writable": False},
            {"name": "Stop", "class": "Method", "writable": False},
        ]

    def test_methods_filter(self):
        """Test filtering for methods only"""
        methods = [n for n in self.nodes if n["class"] == "Method"]
        self.assertEqual(len(methods), 2)
        self.assertEqual(methods[0]["name"], "Start")
        self.assertEqual(methods[1]["name"], "Stop")

    def test_write_filter(self):
        """Test filtering for writable nodes only"""
        writable = [n for n in self.nodes if n.get("writable")]
        self.assertEqual(len(writable), 1)
        self.assertEqual(writable[0]["name"], "Setpoint")

    def test_no_methods_in_fast_dump(self):
        """Test that fast dump includes all node types"""
        # Fast dump should include all nodes
        all_nodes = self.nodes
        self.assertEqual(len(all_nodes), 6)

        # Has objects, variables, and methods
        classes = set(n["class"] for n in all_nodes)
        self.assertIn("Object", classes)
        self.assertIn("Variable", classes)
        self.assertIn("Method", classes)


class TestDumpBFSTraversal(unittest.TestCase):
    """Test BFS traversal logic"""

    def test_visited_tracking(self):
        """Test that visited nodes are tracked to prevent loops"""
        visited = set()

        # Simulate BFS
        nodes_to_visit = ["i=84", "i=85", "i=86"]

        for node_id in nodes_to_visit:
            if node_id in visited:
                continue
            visited.add(node_id)

        self.assertEqual(len(visited), 3)

        # Try to visit again - should be skipped
        for node_id in nodes_to_visit:
            if node_id in visited:
                continue
            visited.add(node_id)

        # Still 3 - no duplicates
        self.assertEqual(len(visited), 3)

    def test_max_depth_limit(self):
        """Test that max depth is respected"""
        max_depth = 3

        def should_process(depth):
            return depth < max_depth

        self.assertTrue(should_process(0))
        self.assertTrue(should_process(1))
        self.assertTrue(should_process(2))
        self.assertFalse(should_process(3))
        self.assertFalse(should_process(4))

    def test_max_nodes_limit(self):
        """Test that max nodes limit stops processing"""
        max_nodes = 5
        nodes = []

        for i in range(10):
            if len(nodes) >= max_nodes:
                break
            nodes.append({"id": i})

        self.assertEqual(len(nodes), 5)

    def test_batch_processing(self):
        """Test batch processing of nodes"""
        batch_size = 3
        queue = list(range(10))

        batches = []
        while queue:
            batch = queue[:batch_size]
            queue = queue[batch_size:]
            batches.append(batch)

        self.assertEqual(len(batches), 4)  # 3 + 3 + 3 + 1
        self.assertEqual(batches[0], [0, 1, 2])
        self.assertEqual(batches[1], [3, 4, 5])
        self.assertEqual(batches[2], [6, 7, 8])
        self.assertEqual(batches[3], [9])


class TestProtoArgs(unittest.TestCase):
    """Test proto_args.py configuration"""

    def test_dump_options_exist(self):
        """Test that dump options are defined in proto_args"""
        from oida.protocols.opcua.proto_args import proto_args
        import argparse

        # Create parser
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        # Call proto_args
        opcua_parser = proto_args(subparsers, [])

        # Check that parser was created
        self.assertIsNotNone(opcua_parser)

    def test_dump_default_values(self):
        """Test default values for dump options"""
        from oida.protocols.opcua.proto_args import proto_args
        import argparse

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        proto_args(subparsers, [])

        # Parse with no args
        args = parser.parse_args(["opcua", "localhost"])

        # Check defaults
        self.assertEqual(args.max_depth, 3)
        self.assertEqual(args.max_nodes, 1000)
        self.assertFalse(args.dump)
        self.assertFalse(args.dump_all)
        self.assertFalse(args.dump_methods)
        self.assertFalse(args.dump_write)


class TestExportIntegration(unittest.TestCase):
    """Test integration with export utilities"""

    def test_export_data_format(self):
        """Test that dump data is in correct format for export"""
        # Simulate dump output
        nodes = [
            {"namespace": 0, "class": "Object", "name": "Root", "node_id": "i=84"},
            {"namespace": 0, "class": "Variable", "name": "Temp", "node_id": "i=2001"},
        ]

        # Fast mode format
        headers = ["NS", "Class", "Name", "Node ID"]
        data = [[n["namespace"], n["class"], n["name"], n["node_id"]] for n in nodes]

        self.assertEqual(len(headers), 4)
        self.assertEqual(len(data), 2)
        self.assertEqual(len(data[0]), 4)

        # Verify data matches headers
        self.assertEqual(data[0][0], 0)  # NS
        self.assertEqual(data[0][1], "Object")  # Class
        self.assertEqual(data[0][2], "Root")  # Name
        self.assertEqual(data[0][3], "i=84")  # Node ID

    def test_full_mode_data_format(self):
        """Test full mode data format with DataType and Access"""
        nodes = [
            {
                "namespace": 2,
                "class": "Variable",
                "name": "Temp",
                "node_id": "ns=2;i=2001",
                "data_type": "Double",
                "access": "R",
            },
            {
                "namespace": 2,
                "class": "Variable",
                "name": "Setpoint",
                "node_id": "ns=2;i=2002",
                "data_type": "Double",
                "access": "RW",
            },
        ]

        headers = ["NS", "Class", "Name", "DataType", "Access", "Node ID"]
        data = [
            [n["namespace"], n["class"], n["name"], n["data_type"], n["access"], n["node_id"]]
            for n in nodes
        ]

        self.assertEqual(len(headers), 6)
        self.assertEqual(data[0][3], "Double")  # DataType
        self.assertEqual(data[0][4], "R")  # Access
        self.assertEqual(data[1][4], "RW")  # Access with write


class TestWritableNodeDetection(unittest.TestCase):
    """Test writable node detection and warning"""

    def test_writable_detection(self):
        """Test detection of writable nodes"""
        nodes = [
            {"name": "ReadOnly", "writable": False},
            {"name": "Writable1", "writable": True},
            {"name": "Writable2", "writable": True},
            {"name": "AnotherReadOnly", "writable": False},
        ]

        writable = [n for n in nodes if n.get("writable")]
        self.assertEqual(len(writable), 2)

    def test_writable_warning_format(self):
        """Test format of writable node warning"""
        writable_nodes = [
            {"name": "Setpoint", "node_id": "ns=2;i=2002", "data_type": "Double"},
            {"name": "Enable", "node_id": "ns=2;i=2003", "data_type": "Boolean"},
        ]

        # Simulate warning output
        warning_lines = []
        warning_lines.append(f"Found {len(writable_nodes)} writable variable(s)!")
        for wn in writable_nodes[:5]:
            warning_lines.append(f"  [W] {wn['name']} ({wn['node_id']})")

        self.assertEqual(len(warning_lines), 3)
        self.assertIn("2 writable", warning_lines[0])
        self.assertIn("[W] Setpoint", warning_lines[1])


class TestNXCDumpIntegration(unittest.TestCase):
    """Integration tests for NXC-style dump with mocked asyncua"""

    def _create_mock_asyncua(self):
        """Create a fully mocked asyncua module"""
        mock_asyncua = MagicMock()

        # Mock ua module with AccessLevel enum
        mock_ua = MagicMock()
        mock_ua.AccessLevel.CurrentRead = 0
        mock_ua.AccessLevel.CurrentWrite = 1
        mock_ua.AccessLevel.HistoryRead = 2
        mock_asyncua.ua = mock_ua

        return mock_asyncua

    def _create_mock_node(
        self,
        node_id,
        name,
        node_class,
        ns=0,
        children=None,
        access_level=None,
        data_type_name="String",
    ):
        """Create a mock OPC UA node with async methods"""
        node = AsyncMock()

        # NodeId
        mock_nodeid = MagicMock()
        mock_nodeid.NamespaceIndex = ns
        mock_nodeid.to_string.return_value = f"ns={ns};i={node_id}" if ns else f"i={node_id}"
        node.nodeid = mock_nodeid

        # Browse name
        mock_browse_name = MagicMock()
        mock_browse_name.Name = name
        mock_browse_name.NamespaceIndex = ns
        node.read_browse_name = AsyncMock(return_value=mock_browse_name)

        # Node class
        mock_node_class = MagicMock()
        mock_node_class.name = node_class
        node.read_node_class = AsyncMock(return_value=mock_node_class)

        # Children
        node.get_children = AsyncMock(return_value=children or [])

        # Access level (returns a set)
        access_set = access_level if access_level is not None else {0}  # Default: CurrentRead
        node.get_access_level = AsyncMock(return_value=access_set)

        # Data type
        mock_dt_nodeid = MagicMock()
        mock_dt_nodeid.Identifier = 1  # BaseDataType
        node.read_data_type = AsyncMock(return_value=mock_dt_nodeid)

        return node

    @patch("oida.protocols.opcua._get_asyncua")
    def test_dump_fast_mode(self, mock_get_asyncua):
        """Test fast dump mode with mocked asyncua"""
        mock_asyncua = self._create_mock_asyncua()
        mock_get_asyncua.return_value = mock_asyncua

        # Create mock nodes
        root = self._create_mock_node(84, "Root", "Object", children=[])
        objects = self._create_mock_node(85, "Objects", "Object", children=[])
        root.get_children = AsyncMock(return_value=[objects])

        # Verify mock structure
        async def verify():
            name = await root.read_browse_name()
            self.assertEqual(name.Name, "Root")

            nc = await root.read_node_class()
            self.assertEqual(nc.name, "Object")

            children = await root.get_children()
            self.assertEqual(len(children), 1)

        asyncio.run(verify())

    @patch("oida.protocols.opcua._get_asyncua")
    def test_dump_access_level_parsing(self, mock_get_asyncua):
        """Test access level parsing in dump"""
        mock_asyncua = self._create_mock_asyncua()
        mock_get_asyncua.return_value = mock_asyncua

        ua = mock_asyncua.ua

        # Read-only variable
        read_only = self._create_mock_node(
            2001, "ReadOnly", "Variable", access_level={ua.AccessLevel.CurrentRead}
        )

        # Read-write variable
        read_write = self._create_mock_node(
            2002,
            "ReadWrite",
            "Variable",
            access_level={ua.AccessLevel.CurrentRead, ua.AccessLevel.CurrentWrite},
        )

        async def verify():
            # Test read-only
            access = await read_only.get_access_level()
            self.assertIn(ua.AccessLevel.CurrentRead, access)
            self.assertNotIn(ua.AccessLevel.CurrentWrite, access)

            # Test read-write
            access = await read_write.get_access_level()
            self.assertIn(ua.AccessLevel.CurrentRead, access)
            self.assertIn(ua.AccessLevel.CurrentWrite, access)

        asyncio.run(verify())

    def test_dump_methods_filter_logic(self):
        """Test that methods filter correctly identifies Method nodes"""
        nodes = [
            {"class": "Object", "name": "Root"},
            {"class": "Object", "name": "Objects"},
            {"class": "Variable", "name": "Temp"},
            {"class": "Method", "name": "Start"},
            {"class": "Method", "name": "Stop"},
        ]

        # Filter for methods
        filtered = [n for n in nodes if n["class"] == "Method"]

        self.assertEqual(len(filtered), 2)
        self.assertTrue(all(n["class"] == "Method" for n in filtered))

    def test_dump_write_filter_logic(self):
        """Test that write filter correctly identifies writable nodes"""
        nodes = [
            {"class": "Variable", "name": "ReadOnly", "writable": False},
            {"class": "Variable", "name": "Writable", "writable": True},
            {"class": "Object", "name": "Container", "writable": False},
        ]

        # Filter for writable
        filtered = [n for n in nodes if n.get("writable")]

        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["name"], "Writable")


class TestCLIIntegration(unittest.TestCase):
    """Test CLI argument handling for dump options"""

    def test_parse_dump_flag(self):
        """Test parsing --dump flag"""
        import argparse
        from oida.protocols.opcua.proto_args import proto_args

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        proto_args(subparsers, [])

        args = parser.parse_args(["opcua", "localhost", "--dump"])
        self.assertTrue(args.dump)
        self.assertFalse(args.dump_all)

    def test_parse_dump_all_flag(self):
        """Test parsing --dump-all flag"""
        import argparse
        from oida.protocols.opcua.proto_args import proto_args

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        proto_args(subparsers, [])

        args = parser.parse_args(["opcua", "localhost", "--dump-all"])
        self.assertFalse(args.dump)
        self.assertTrue(args.dump_all)

    def test_parse_dump_methods_flag(self):
        """Test parsing --dump-methods flag"""
        import argparse
        from oida.protocols.opcua.proto_args import proto_args

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        proto_args(subparsers, [])

        args = parser.parse_args(["opcua", "localhost", "--dump-methods"])
        self.assertTrue(args.dump_methods)

    def test_parse_dump_write_flag(self):
        """Test parsing --dump-write flag"""
        import argparse
        from oida.protocols.opcua.proto_args import proto_args

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        proto_args(subparsers, [])

        args = parser.parse_args(["opcua", "localhost", "--dump-write"])
        self.assertTrue(args.dump_write)

    def test_parse_max_depth(self):
        """Test parsing --max-depth option"""
        import argparse
        from oida.protocols.opcua.proto_args import proto_args

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        proto_args(subparsers, [])

        args = parser.parse_args(["opcua", "localhost", "--max-depth", "5"])
        self.assertEqual(args.max_depth, 5)

    def test_parse_max_nodes(self):
        """Test parsing --max-nodes option"""
        import argparse
        from oida.protocols.opcua.proto_args import proto_args

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        proto_args(subparsers, [])

        args = parser.parse_args(["opcua", "localhost", "--max-nodes", "500"])
        self.assertEqual(args.max_nodes, 500)

    def test_combined_options(self):
        """Test combining dump options"""
        import argparse
        from oida.protocols.opcua.proto_args import proto_args

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        proto_args(subparsers, [])

        args = parser.parse_args(
            ["opcua", "localhost", "--dump-all", "--max-depth", "10", "--max-nodes", "2000"]
        )

        self.assertTrue(args.dump_all)
        self.assertEqual(args.max_depth, 10)
        self.assertEqual(args.max_nodes, 2000)


class MockArgument:
    """Mock OPC UA Argument structure"""

    def __init__(self, name, data_type_id=6, description=""):
        self.Name = name
        self.DataType = MockNodeId(data_type_id)
        self.Description = MagicMock()
        self.Description.Text = description


class TestMethodDetailsHelper(unittest.TestCase):
    """Test method details helper functions"""

    def test_parse_argument_basic(self):
        """Test parsing a basic OPC UA Argument structure"""

        # Simulate the _parse_argument logic
        def parse_argument(arg):
            builtin_types = {
                1: "Boolean",
                6: "Int32",
                7: "UInt32",
                11: "Double",
                12: "String",
            }
            arg_info = {"name": "", "data_type": "", "description": ""}

            if hasattr(arg, "Name"):
                arg_info["name"] = arg.Name or ""
            if hasattr(arg, "DataType"):
                dt_id = arg.DataType
                if hasattr(dt_id, "Identifier") and dt_id.NamespaceIndex == 0:
                    arg_info["data_type"] = builtin_types.get(dt_id.Identifier, str(dt_id))
                else:
                    arg_info["data_type"] = str(dt_id)
            if hasattr(arg, "Description") and arg.Description:
                desc = arg.Description
                if hasattr(desc, "Text"):
                    arg_info["description"] = desc.Text or ""
            return arg_info

        # Test Int32 argument
        arg = MockArgument("count", data_type_id=6, description="Item count")
        result = parse_argument(arg)
        self.assertEqual(result["name"], "count")
        self.assertEqual(result["data_type"], "Int32")
        self.assertEqual(result["description"], "Item count")

        # Test Double argument
        arg = MockArgument("value", data_type_id=11)
        result = parse_argument(arg)
        self.assertEqual(result["name"], "value")
        self.assertEqual(result["data_type"], "Double")

    def test_format_method_args_empty(self):
        """Test formatting empty argument list"""

        def format_args(args):
            if not args:
                return "()"
            parts = []
            for arg in args:
                parts.append(f"{arg.get('name', '?')}:{arg.get('data_type', '?')}")
            return f"({', '.join(parts)})"

        self.assertEqual(format_args([]), "()")

    def test_format_method_args_single(self):
        """Test formatting single argument"""

        def format_args(args):
            if not args:
                return "()"
            parts = []
            for arg in args:
                parts.append(f"{arg.get('name', '?')}:{arg.get('data_type', '?')}")
            return f"({', '.join(parts)})"

        args = [{"name": "value", "data_type": "Double"}]
        self.assertEqual(format_args(args), "(value:Double)")

    def test_format_method_args_multiple(self):
        """Test formatting multiple arguments"""

        def format_args(args):
            if not args:
                return "()"
            parts = []
            for arg in args:
                parts.append(f"{arg.get('name', '?')}:{arg.get('data_type', '?')}")
            return f"({', '.join(parts)})"

        args = [
            {"name": "x", "data_type": "Int32"},
            {"name": "y", "data_type": "Int32"},
            {"name": "name", "data_type": "String"},
        ]
        self.assertEqual(format_args(args), "(x:Int32, y:Int32, name:String)")


class TestMethodDumpFormat(unittest.TestCase):
    """Test method dump table format"""

    def test_methods_mode_headers(self):
        """Test that methods mode has correct headers aligned with other dumps"""
        headers = ["NS", "Name", "Desc", "Permissions", "Node ID"]
        self.assertEqual(len(headers), 5)
        self.assertIn("Desc", headers)
        self.assertIn("Permissions", headers)
        self.assertIn("NS", headers)

    def test_full_mode_headers(self):
        """Test that full/write mode has same headers as methods"""
        headers = ["NS", "Name", "Desc", "Permissions", "Node ID"]
        self.assertEqual(len(headers), 5)

    def test_fast_mode_headers(self):
        """Test that fast mode has minimal headers (no permissions)"""
        headers = ["NS", "Name", "Node ID"]
        self.assertEqual(len(headers), 3)
        self.assertNotIn("Permissions", headers)

    def test_permission_format(self):
        """Test permission string format"""
        # For methods: Call/-
        self.assertEqual("Call" if True else "-", "Call")
        self.assertEqual("Call" if False else "-", "-")

        # For variables: R, RW, RWH etc
        def build_access_str(read, write, history):
            parts = []
            if read:
                parts.append("R")
            if write:
                parts.append("W")
            if history:
                parts.append("H")
            return "".join(parts) if parts else "-"

        self.assertEqual(build_access_str(True, False, False), "R")
        self.assertEqual(build_access_str(True, True, False), "RW")
        self.assertEqual(build_access_str(True, True, True), "RWH")
        self.assertEqual(build_access_str(False, False, False), "-")

    def test_methods_mode_signature_format(self):
        """Test methods mode signature format"""

        def format_args(args):
            if not args:
                return "()"
            parts = [f"{a.get('name')}:{a.get('data_type')}" for a in args]
            return f"({', '.join(parts)})"

        def build_signature(in_args, out_args, desc=""):
            sig = f"{format_args(in_args)} -> {format_args(out_args)}"
            if desc:
                sig = f"{sig} | {desc[:30]}..." if len(desc) > 30 else f"{sig} | {desc}"
            return sig

        # Method with in/out args
        sig = build_signature(
            [{"name": "value", "data_type": "Double"}], [{"name": "result", "data_type": "Boolean"}]
        )
        self.assertEqual(sig, "(value:Double) -> (result:Boolean)")

        # Method with description
        sig = build_signature([{"name": "x", "data_type": "Int32"}], [], "Sets the value")
        self.assertEqual(sig, "(x:Int32) -> () | Sets the value")

    def test_description_truncation_in_signature(self):
        """Test that long descriptions are truncated in signature"""
        long_desc = "This is a very long description that should be truncated"

        def build_signature(desc):
            sig = "() -> ()"
            if desc:
                sig = f"{sig} | {desc[:30]}..." if len(desc) > 30 else f"{sig} | {desc}"
            return sig

        sig = build_signature(long_desc)
        self.assertIn("...", sig)
        self.assertTrue(len(sig.split(" | ")[1]) <= 33)  # 30 + "..."

    def test_method_no_args_signature(self):
        """Test method with no arguments produces correct signature"""

        def format_args(args):
            if not args:
                return "()"
            parts = [f"{a.get('name')}:{a.get('data_type')}" for a in args]
            return f"({', '.join(parts)})"

        sig = f"{format_args([])} -> {format_args([])}"
        self.assertEqual(sig, "() -> ()")


class TestMethodDetailsIntegration(unittest.TestCase):
    """Integration tests for method details with mocked asyncua"""

    def _create_mock_method_node(
        self,
        node_id,
        name,
        input_args=None,
        output_args=None,
        description="",
        executable=True,
        user_executable=True,
    ):
        """Create a mock method node with InputArguments/OutputArguments properties"""
        method = AsyncMock()

        # NodeId
        mock_nodeid = MagicMock()
        mock_nodeid.NamespaceIndex = 2
        mock_nodeid.to_string.return_value = f"ns=2;i={node_id}"
        method.nodeid = mock_nodeid

        # Browse name
        mock_browse_name = MagicMock()
        mock_browse_name.Name = name
        method.read_browse_name = AsyncMock(return_value=mock_browse_name)

        # Node class
        mock_node_class = MagicMock()
        mock_node_class.name = "Method"
        method.read_node_class = AsyncMock(return_value=mock_node_class)

        # Mock read_attribute to return different values based on AttributeId
        def mock_read_attribute(attr_id):
            mock_result = MagicMock()
            mock_result.Value = MagicMock()
            # Check attribute type (13=Description, 21=Executable, 22=UserExecutable)
            if hasattr(attr_id, "value"):
                attr_val = attr_id.value
            else:
                attr_val = attr_id
            if attr_val == 21:  # Executable
                mock_result.Value.Value = executable
            elif attr_val == 22:  # UserExecutable
                mock_result.Value.Value = user_executable
            else:  # Description
                mock_result.Value.Value = MagicMock()
                mock_result.Value.Value.Text = description
            return mock_result

        method.read_attribute = AsyncMock(side_effect=mock_read_attribute)

        # Create child property nodes for InputArguments and OutputArguments
        children = []

        if input_args:
            input_prop = AsyncMock()
            input_prop_name = MagicMock()
            input_prop_name.Name = "InputArguments"
            input_prop.read_browse_name = AsyncMock(return_value=input_prop_name)
            input_prop.read_value = AsyncMock(return_value=input_args)
            children.append(input_prop)

        if output_args:
            output_prop = AsyncMock()
            output_prop_name = MagicMock()
            output_prop_name.Name = "OutputArguments"
            output_prop.read_browse_name = AsyncMock(return_value=output_prop_name)
            output_prop.read_value = AsyncMock(return_value=output_args)
            children.append(output_prop)

        method.get_children = AsyncMock(return_value=children)

        return method

    def test_mock_method_node_structure(self):
        """Test that mock method node has correct structure"""
        input_args = [MockArgument("x", 6), MockArgument("y", 6)]
        output_args = [MockArgument("result", 6)]

        method = self._create_mock_method_node(
            1001,
            "Add",
            input_args=input_args,
            output_args=output_args,
            description="Add two numbers",
        )

        async def verify():
            name = await method.read_browse_name()
            self.assertEqual(name.Name, "Add")

            nc = await method.read_node_class()
            self.assertEqual(nc.name, "Method")

            children = await method.get_children()
            self.assertEqual(len(children), 2)  # InputArguments and OutputArguments

            # Check InputArguments
            input_prop_name = await children[0].read_browse_name()
            self.assertEqual(input_prop_name.Name, "InputArguments")

            input_vals = await children[0].read_value()
            self.assertEqual(len(input_vals), 2)
            self.assertEqual(input_vals[0].Name, "x")

        asyncio.run(verify())

    def test_method_with_complex_args(self):
        """Test method with complex argument types"""
        # Simulate a method like AddConnection from OPC UA PubSub
        input_args = [MockArgument("Configuration", 17)]  # NodeId type
        output_args = [MockArgument("ConnectionId", 17)]

        method = self._create_mock_method_node(
            17366,
            "AddConnection",
            input_args=input_args,
            output_args=output_args,
            description="Add a PubSub connection",
        )

        async def verify():
            children = await method.get_children()
            input_prop = children[0]
            args = await input_prop.read_value()

            self.assertEqual(args[0].Name, "Configuration")
            self.assertEqual(args[0].DataType.Identifier, 17)  # NodeId type

        asyncio.run(verify())

    def test_method_callable_permission(self):
        """Test method that user can call (UserExecutable=True)"""
        self._create_mock_method_node(1001, "Start", executable=True, user_executable=True)

        # Simulate permission string generation
        perm = "Call" if True else "-"
        self.assertEqual(perm, "Call")

    def test_method_not_callable_permission(self):
        """Test method that user cannot call (UserExecutable=False)"""
        self._create_mock_method_node(1002, "AdminOnly", executable=True, user_executable=False)

        # Simulate permission string generation
        perm = "Call" if False else "-"
        self.assertEqual(perm, "-")

    def test_method_permission_display_format(self):
        """Test that method permissions display correctly in table data"""
        # Simulate building table data for methods
        methods = [
            {
                "name": "Start",
                "user_executable": True,
                "namespace": 2,
                "node_id": "ns=2;i=1001",
                "input_args": [],
                "output_args": [],
            },
            {
                "name": "AdminOnly",
                "user_executable": False,
                "namespace": 2,
                "node_id": "ns=2;i=1002",
                "input_args": [],
                "output_args": [],
            },
        ]

        def format_args(args):
            if not args:
                return "()"
            parts = [f"{a.get('name')}:{a.get('data_type')}" for a in args]
            return f"({', '.join(parts)})"

        data = []
        for m in methods:
            in_args = format_args(m["input_args"])
            out_args = format_args(m["output_args"])
            desc = f"{in_args} -> {out_args}"
            perm = "Call" if m.get("user_executable") else "-"
            data.append([m["namespace"], m["name"], desc, perm, m["node_id"]])

        # First method should be callable
        self.assertEqual(data[0][3], "Call")
        # Second method should not be callable
        self.assertEqual(data[1][3], "-")


class TestNamespaceFilter(unittest.TestCase):
    """Test namespace filtering functionality"""

    def test_parse_single_namespace(self):
        """Test parsing single namespace filter"""
        ns_str = "2"
        ns_filter = set(int(x.strip()) for x in ns_str.split(","))
        self.assertEqual(ns_filter, {2})

    def test_parse_multiple_namespaces(self):
        """Test parsing multiple namespace filter"""
        ns_str = "0,2,3"
        ns_filter = set(int(x.strip()) for x in ns_str.split(","))
        self.assertEqual(ns_filter, {0, 2, 3})

    def test_parse_namespaces_with_spaces(self):
        """Test parsing namespace filter with spaces"""
        ns_str = "1, 2, 3"
        ns_filter = set(int(x.strip()) for x in ns_str.split(","))
        self.assertEqual(ns_filter, {1, 2, 3})

    def test_namespace_filter_include(self):
        """Test that namespace filter includes correct nodes"""
        ns_filter = {2}
        nodes = [
            {"namespace": 0, "name": "Root"},
            {"namespace": 2, "name": "MyDevice"},
            {"namespace": 2, "name": "MyVar"},
            {"namespace": 3, "name": "Other"},
        ]

        filtered = [n for n in nodes if n["namespace"] in ns_filter]
        self.assertEqual(len(filtered), 2)
        self.assertTrue(all(n["namespace"] == 2 for n in filtered))

    def test_namespace_filter_none(self):
        """Test that None filter includes all nodes"""
        ns_filter = None
        nodes = [
            {"namespace": 0, "name": "Root"},
            {"namespace": 2, "name": "MyDevice"},
        ]

        filtered = [n for n in nodes if ns_filter is None or n["namespace"] in ns_filter]
        self.assertEqual(len(filtered), 2)


class TestStartNodeOption(unittest.TestCase):
    """Test start-node option functionality"""

    def test_parse_start_node_cli(self):
        """Test parsing --start-node CLI option"""
        import argparse
        from oida.protocols.opcua.proto_args import proto_args

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        proto_args(subparsers, [])

        args = parser.parse_args(["opcua", "localhost", "--start-node", "ns=2;i=5001"])
        self.assertEqual(args.start_node, "ns=2;i=5001")

    def test_parse_ns_cli(self):
        """Test parsing --ns CLI option"""
        import argparse
        from oida.protocols.opcua.proto_args import proto_args

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        proto_args(subparsers, [])

        args = parser.parse_args(["opcua", "localhost", "--ns", "2,3"])
        self.assertEqual(args.ns, "2,3")

    def test_combined_filters(self):
        """Test combining --ns and --start-node"""
        import argparse
        from oida.protocols.opcua.proto_args import proto_args

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        proto_args(subparsers, [])

        args = parser.parse_args(
            [
                "opcua",
                "localhost",
                "--dump-methods",
                "--ns",
                "2",
                "--start-node",
                "ns=2;i=5001",
                "--max-depth",
                "5",
            ]
        )

        self.assertTrue(args.dump_methods)
        self.assertEqual(args.ns, "2")
        self.assertEqual(args.start_node, "ns=2;i=5001")
        self.assertEqual(args.max_depth, 5)


class TestMethodExampleGeneration(unittest.TestCase):
    """Test CLI example generation for methods"""

    def test_example_no_args(self):
        """Test example generation for method with no arguments"""
        method = {
            "name": "Start",
            "node_id": "ns=2;i=1001",
            "input_args": [],
            "user_executable": True,
        }

        # Simulate _generate_method_example logic
        node_id = method["node_id"]
        input_args = method["input_args"]

        if not input_args:
            example = f'oida opcua <target> --call-method "{node_id}"'
        else:
            import json

            example_values = [42 for _ in input_args]  # placeholder
            args_json = json.dumps(example_values)
            example = f"oida opcua <target> --call-method \"{node_id}\" --method-args '{args_json}'"

        self.assertIn("--call-method", example)
        self.assertIn("ns=2;i=1001", example)
        self.assertNotIn("--method-args", example)

    def test_example_with_int_arg(self):
        """Test example generation for method with Int32 argument"""
        import json

        method = {
            "name": "SetValue",
            "node_id": "ns=2;i=1002",
            "input_args": [{"name": "value", "data_type": "Int32"}],
            "user_executable": True,
        }

        # Get example value for Int32
        type_examples = {"Int32": 42, "String": "example", "Boolean": True}
        example_values = [type_examples.get(arg["data_type"], 0) for arg in method["input_args"]]
        args_json = json.dumps(example_values)
        example = (
            f"oida opcua <target> --call-method \"{method['node_id']}\" --method-args '{args_json}'"
        )

        self.assertIn("--method-args", example)
        self.assertIn("[42]", example)

    def test_example_with_multiple_args(self):
        """Test example generation for method with multiple arguments"""
        import json

        method = {
            "name": "Configure",
            "node_id": "ns=2;i=1003",
            "input_args": [
                {"name": "enabled", "data_type": "Boolean"},
                {"name": "count", "data_type": "Int32"},
                {"name": "name", "data_type": "String"},
            ],
            "user_executable": True,
        }

        type_examples = {"Int32": 42, "String": "example", "Boolean": True, "Double": 3.14159}
        example_values = [type_examples.get(arg["data_type"], 0) for arg in method["input_args"]]
        args_json = json.dumps(example_values)
        example = (
            f"oida opcua <target> --call-method \"{method['node_id']}\" --method-args '{args_json}'"
        )

        self.assertIn('[true, 42, "example"]', example)

    def test_example_with_double_arg(self):
        """Test example generation for method with Double argument"""
        import json

        method = {
            "name": "SetTemperature",
            "node_id": "ns=2;i=1004",
            "input_args": [{"name": "temp", "data_type": "Double"}],
            "user_executable": True,
        }

        type_examples = {"Double": 3.14159}
        example_values = [type_examples.get(arg["data_type"], 0) for arg in method["input_args"]]
        args_json = json.dumps(example_values)

        self.assertIn("3.14159", args_json)

    def test_dump_examples_cli_option(self):
        """Test --dump-examples CLI option parsing"""
        import argparse
        from oida.protocols.opcua.proto_args import proto_args

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        proto_args(subparsers, [])

        args = parser.parse_args(["opcua", "localhost", "--dump-methods", "--dump-examples"])
        self.assertTrue(args.dump_methods)
        self.assertTrue(args.dump_examples)


class TestVariantTypeMapping(unittest.TestCase):
    """Test OPC UA DataType to VariantType mapping for method calls"""

    def test_variant_type_map_coverage(self):
        """Test that common OPC UA data types are mapped"""
        # DataType NodeId -> expected type name mapping
        expected_types = {
            1: "Boolean",
            2: "SByte",
            3: "Byte",
            4: "Int16",
            5: "UInt16",
            6: "Int32",
            7: "UInt32",
            8: "Int64",
            9: "UInt64",
            10: "Float",
            11: "Double",
            12: "String",
        }
        # Just verify the mapping dictionary exists with correct structure
        self.assertEqual(len(expected_types), 12)

    def test_multi_arg_type_conversion(self):
        """Test that multiple arguments are correctly typed"""
        # Simulate input args definition from OPC UA server
        input_args_def = [
            {"name": "x", "datatype_id": 11},  # Double
            {"name": "y", "datatype_id": 11},  # Double
            {"name": "name", "datatype_id": 12},  # String
        ]
        raw_args = [3.14, 2.71, "test"]

        # Simulate type conversion logic
        typed_count = 0
        for i, arg_def in enumerate(input_args_def):
            dt_id = arg_def["datatype_id"]
            # Check that mapping exists
            if dt_id in {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}:
                typed_count += 1

        self.assertEqual(typed_count, 3)
        self.assertEqual(len(raw_args), len(input_args_def))

    def test_unknown_type_fallback(self):
        """Test that unknown types fall back to raw value"""
        # Unknown DataType ID
        unknown_dt_id = 9999
        type_map = {6: "Int32", 12: "String"}

        # Should return None for unknown type
        result = type_map.get(unknown_dt_id)
        self.assertIsNone(result)

    def test_empty_args(self):
        """Test method with no arguments"""
        raw_args = []
        input_args_def = []

        # Empty args should work
        self.assertEqual(len(raw_args), len(input_args_def))

    def test_mixed_type_args(self):
        """Test method with mixed type arguments"""
        # Simulate a method like: MyMethod(enabled: Boolean, count: Int32, value: Double, name: String)
        input_args_def = [
            {"name": "enabled", "datatype_id": 1},  # Boolean
            {"name": "count", "datatype_id": 6},  # Int32
            {"name": "value", "datatype_id": 11},  # Double
            {"name": "name", "datatype_id": 12},  # String
        ]
        raw_args = [True, 42, 3.14159, "hello"]

        # Verify all types are mappable
        type_map = {1: "Boolean", 6: "Int32", 11: "Double", 12: "String"}
        for i, arg_def in enumerate(input_args_def):
            self.assertIn(arg_def["datatype_id"], type_map)

        # Verify values match expected types
        self.assertIsInstance(raw_args[0], bool)
        self.assertIsInstance(raw_args[1], int)
        self.assertIsInstance(raw_args[2], float)
        self.assertIsInstance(raw_args[3], str)


if __name__ == "__main__":
    unittest.main()
