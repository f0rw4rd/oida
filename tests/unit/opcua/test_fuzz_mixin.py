#!/usr/bin/env python3
"""Behavioural tests for the OPC UA FuzzMixin.

Covers the confirm gate and dispatch in ``_handle_fuzz``, writable-node and
callable-method discovery, the typed fuzz-value generator, and ``_fuzz_method``
argument generation / status-code classification. Only the asyncua client/node
boundary is mocked; the fuzzing control flow runs for real (asyncio.sleep is
stubbed so tests stay fast).
"""

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from oida.protocols.opcua.helpers import _asyncua, ua
from oida.protocols.opcua.mixins.fuzz import FuzzMixin
from tests.service_gate import require_service


def _skip_if_no_asyncua():
    if not _asyncua.is_available:
        require_service("asyncua not available")


class _BrowseName:
    def __init__(self, name):
        self.Name = name


class _NodeId:
    def __init__(self, s):
        self._s = s

    def to_string(self):
        return self._s

    def __str__(self):
        return self._s


class _AttrResult:
    def __init__(self, value):
        self.Value = SimpleNamespace(Value=value)


class _FuzzHost(FuzzMixin):
    def __init__(self, args=None):
        self.args = args or SimpleNamespace(confirm=True)
        self.logger = MagicMock()
        self._client = MagicMock()


# ---------------------------------------------------------------------------
# _handle_fuzz dispatch
# ---------------------------------------------------------------------------


class TestHandleFuzzGate(unittest.IsolatedAsyncioTestCase):
    async def test_confirm_required(self):
        _skip_if_no_asyncua()
        host = _FuzzHost(SimpleNamespace(confirm=False))
        await host._handle_fuzz()
        host.logger.fail.assert_called()
        # No discovery should have started.

    async def test_nodes_mode_dispatches_to_writable_search(self):
        _skip_if_no_asyncua()
        host = _FuzzHost(
            SimpleNamespace(confirm=True, fuzz=True, fuzz_iterations=2, fuzz_max_targets=5)
        )
        host._find_writable_nodes = AsyncMock(
            return_value=[{"node_id": "ns=2;i=1", "name": "Var1"}]
        )
        host._fuzz_node = AsyncMock(
            return_value={"tests": 2, "writes": 2, "anomalies": 0, "crashes": 0}
        )
        await host._handle_fuzz()

        host._find_writable_nodes.assert_awaited_once()
        host._fuzz_node.assert_awaited_once_with("ns=2;i=1", 2)

    async def test_methods_mode_dispatches_to_method_search(self):
        _skip_if_no_asyncua()
        host = _FuzzHost(
            SimpleNamespace(
                confirm=True, fuzz=True, fuzz_mode="methods", fuzz_iterations=3, fuzz_max_targets=5
            )
        )
        host._find_callable_methods = AsyncMock(
            return_value=[{"node_id": "ns=2;i=99", "name": "DoThing", "input_args": []}]
        )
        host._fuzz_method = AsyncMock(
            return_value={"tests": 3, "calls": 3, "anomalies": 0, "crashes": 0}
        )
        await host._handle_fuzz()

        host._find_callable_methods.assert_awaited_once()
        host._fuzz_method.assert_awaited_once()
        # method_id forwarded as first positional arg
        self.assertEqual(host._fuzz_method.call_args[0][0], "ns=2;i=99")

    async def test_specific_node_targeted_directly(self):
        _skip_if_no_asyncua()
        host = _FuzzHost(
            SimpleNamespace(confirm=True, fuzz=True, fuzz_node="ns=3;i=7", fuzz_iterations=4)
        )
        host._find_writable_nodes = AsyncMock(return_value=[])
        host._fuzz_node = AsyncMock(
            return_value={"tests": 4, "writes": 4, "anomalies": 1, "crashes": 0}
        )
        await host._handle_fuzz()

        host._find_writable_nodes.assert_not_awaited()
        host._fuzz_node.assert_awaited_once_with("ns=3;i=7", 4)

    async def test_all_mode_runs_both(self):
        _skip_if_no_asyncua()
        host = _FuzzHost(
            SimpleNamespace(
                confirm=True, fuzz=True, fuzz_mode="all", fuzz_iterations=1, fuzz_max_targets=10
            )
        )
        host._find_writable_nodes = AsyncMock(return_value=[])
        host._find_callable_methods = AsyncMock(return_value=[])
        await host._handle_fuzz()
        host._find_writable_nodes.assert_awaited_once()
        host._find_callable_methods.assert_awaited_once()

    async def test_nodes_mode_no_writable_reports_none_found(self):
        _skip_if_no_asyncua()
        host = _FuzzHost(
            SimpleNamespace(confirm=True, fuzz=True, fuzz_iterations=1, fuzz_max_targets=5)
        )
        host._find_writable_nodes = AsyncMock(return_value=[])
        await host._handle_fuzz()
        host.logger.display.assert_any_call("No writable variable nodes found")

    async def test_methods_mode_no_methods_reports_none_found(self):
        _skip_if_no_asyncua()
        host = _FuzzHost(
            SimpleNamespace(
                confirm=True, fuzz=True, fuzz_mode="methods", fuzz_iterations=1, fuzz_max_targets=5
            )
        )
        host._find_callable_methods = AsyncMock(return_value=[])
        await host._handle_fuzz()
        host.logger.display.assert_any_call("No callable methods found")


class TestFuzzNodeNonVariable(unittest.IsolatedAsyncioTestCase):
    async def test_non_variable_node_skipped(self):
        _skip_if_no_asyncua()
        host = _FuzzHost()
        node = MagicMock()
        node.read_node_class = AsyncMock(return_value=ua.NodeClass.Object)
        host._client.get_node = MagicMock(return_value=node)

        result = await host._fuzz_node("ns=2;i=1", iterations=3)
        self.assertIsNone(result)
        host.logger.warning.assert_called()


# ---------------------------------------------------------------------------
# discovery helpers
# ---------------------------------------------------------------------------


def _variable_child(node_id, name, *, user_access_level, value=0, write_ok=True):
    child = MagicMock()
    child.nodeid = _NodeId(node_id)
    child.read_node_class = AsyncMock(return_value=ua.NodeClass.Variable)
    child.read_browse_name = AsyncMock(return_value=_BrowseName(name))
    child.read_value = AsyncMock(return_value=value)

    async def _read_attr(attr):
        return _AttrResult(user_access_level)

    child.read_attribute = AsyncMock(side_effect=_read_attr)

    async def _write(v):
        if not write_ok:
            raise RuntimeError("BadUserAccessDenied")

    child.write_value = AsyncMock(side_effect=_write)
    child.get_children = AsyncMock(return_value=[])
    return child


class _Container:
    def __init__(self, children):
        self._children = children

    async def get_children(self):
        return list(self._children)


class TestFindWritableNodes(unittest.IsolatedAsyncioTestCase):
    async def test_returns_only_verified_writable(self):
        _skip_if_no_asyncua()
        # writable bit (0x02) set and write succeeds -> included
        good = _variable_child("ns=2;i=10", "Setpoint", user_access_level=0x03, write_ok=True)
        # writable bit clear -> excluded by pre-filter
        ro = _variable_child("ns=2;i=11", "Temp", user_access_level=0x01)
        # writable bit set but write raises -> excluded after verification
        flaky = _variable_child("ns=2;i=12", "Locked", user_access_level=0x03, write_ok=False)

        objects = _Container([good, ro, flaky])
        host = _FuzzHost()
        host._client.get_objects_node = MagicMock(return_value=objects)

        result = await host._find_writable_nodes()
        names = {r["name"] for r in result}
        self.assertEqual(names, {"Setpoint"})
        self.assertEqual(result[0]["node_id"], "ns=2;i=10")


def _method_child(node_id, name, *, executable, user_executable, with_args=True):
    child = MagicMock()
    child.nodeid = _NodeId(node_id)
    child.read_node_class = AsyncMock(return_value=ua.NodeClass.Method)
    child.read_browse_name = AsyncMock(return_value=_BrowseName(name))

    async def _read_attr(attr):
        if attr == ua.AttributeIds.Executable:
            return _AttrResult(executable)
        if attr == ua.AttributeIds.UserExecutable:
            return _AttrResult(user_executable)
        return _AttrResult(None)

    child.read_attribute = AsyncMock(side_effect=_read_attr)
    child.get_children = AsyncMock(return_value=[])
    return child


class TestFindCallableMethods(unittest.IsolatedAsyncioTestCase):
    async def test_returns_executable_methods_only(self):
        _skip_if_no_asyncua()
        callable_m = _method_child("ns=2;i=20", "Reset", executable=True, user_executable=True)
        not_user = _method_child("ns=2;i=21", "AdminReset", executable=True, user_executable=False)
        objects = _Container([callable_m, not_user])

        host = _FuzzHost()
        host._client.get_objects_node = MagicMock(return_value=objects)
        host._get_method_arguments = AsyncMock(return_value=[{"name": "x", "type_id": 6}])

        result = await host._find_callable_methods()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "Reset")
        self.assertEqual(result[0]["node_id"], "ns=2;i=20")
        self.assertEqual(result[0]["input_args"], [{"name": "x", "type_id": 6}])


# ---------------------------------------------------------------------------
# _generate_fuzz_value
# ---------------------------------------------------------------------------


class TestGenerateFuzzValue(unittest.TestCase):
    def setUp(self):
        self.host = _FuzzHost()

    def test_boolean(self):
        self.assertIsInstance(self.host._generate_fuzz_value(1, 0), bool)

    def test_byte_bounds(self):
        for i in range(5):
            v = self.host._generate_fuzz_value(3, i)  # Byte
            self.assertTrue(0 <= v <= 255)

    def test_int32_includes_extremes(self):
        vals = {self.host._generate_fuzz_value(6, i) for i in range(4)}
        self.assertIn(2147483647, vals)
        self.assertIn(-2147483648, vals)

    def test_float_specials(self):
        import math

        vals = [self.host._generate_fuzz_value(10, i) for i in range(7)]
        self.assertTrue(any(math.isinf(v) for v in vals if isinstance(v, float)))
        self.assertTrue(any(math.isnan(v) for v in vals if isinstance(v, float)))

    def test_string_injection_payloads(self):
        payloads = [self.host._generate_fuzz_value(12, i) for i in range(13)]
        joined = "".join(p for p in payloads if isinstance(p, str))
        self.assertIn("DROP TABLE", joined)
        self.assertIn("../../../etc/passwd", joined)

    def test_bytestring(self):
        v = self.host._generate_fuzz_value(15, 1)
        self.assertIsInstance(v, bytes)

    def test_nodeid(self):
        _skip_if_no_asyncua()
        v = self.host._generate_fuzz_value(17, 0)
        # asyncua NodeId
        self.assertTrue(hasattr(v, "Identifier"))

    def test_unknown_type_default_cases(self):
        v = self.host._generate_fuzz_value(9999, 0)
        self.assertEqual(v, 0)


# ---------------------------------------------------------------------------
# _fuzz_method
# ---------------------------------------------------------------------------


class TestFuzzMethod(unittest.IsolatedAsyncioTestCase):
    def _host_with_parent(self, *, call_side_effect=None):
        host = _FuzzHost()
        method_node = MagicMock()
        parent_node = MagicMock()
        if call_side_effect is None:
            parent_node.call_method = AsyncMock(return_value=[None])
        else:
            parent_node.call_method = AsyncMock(side_effect=call_side_effect)

        def _get_node(node_id):
            return method_node if node_id == "ns=2;i=20" else parent_node

        host._client.get_node = MagicMock(side_effect=_get_node)
        host._get_method_arguments = AsyncMock(return_value=[])
        return host, method_node, parent_node

    async def test_successful_calls_counted(self):
        _skip_if_no_asyncua()
        host, _, parent = self._host_with_parent()
        method_info = {"parent": "ns=2;i=1", "input_args": [{"name": "n", "type_id": 6}]}
        with patch("asyncio.sleep", new=AsyncMock()):
            result = await host._fuzz_method("ns=2;i=20", iterations=4, method_info=method_info)

        self.assertEqual(result["tests"], 4)
        self.assertEqual(result["calls"], 4)
        self.assertEqual(result["crashes"], 0)
        self.assertGreaterEqual(parent.call_method.await_count, 4)

    async def test_expected_status_codes_not_anomalies(self):
        _skip_if_no_asyncua()

        def _raise_invalid_arg(method, *cargs):
            raise ua.UaStatusCodeError("BadInvalidArgument")

        host, _, _ = self._host_with_parent(call_side_effect=_raise_invalid_arg)
        method_info = {"parent": "ns=2;i=1", "input_args": [{"name": "n", "type_id": 6}]}
        with patch("asyncio.sleep", new=AsyncMock()):
            result = await host._fuzz_method("ns=2;i=20", iterations=3, method_info=method_info)

        self.assertEqual(result["calls"], 0)
        self.assertEqual(result["anomalies"], 0)
        self.assertEqual(result["crashes"], 0)

    async def test_timeout_counts_as_crash(self):
        _skip_if_no_asyncua()

        def _timeout(method, *cargs):
            raise RuntimeError("connection timeout while calling method")

        host, _, _ = self._host_with_parent(call_side_effect=_timeout)
        method_info = {"parent": "ns=2;i=1", "input_args": [{"name": "n", "type_id": 6}]}
        with patch("asyncio.sleep", new=AsyncMock()):
            result = await host._fuzz_method("ns=2;i=20", iterations=2, method_info=method_info)

        self.assertGreaterEqual(result["crashes"], 1)

    async def test_missing_parent_aborts(self):
        _skip_if_no_asyncua()
        host = _FuzzHost()
        method_node = MagicMock()
        method_node.get_references = AsyncMock(return_value=[])
        host._client.get_node = MagicMock(return_value=method_node)
        host._get_method_arguments = AsyncMock(return_value=[])

        with patch("asyncio.sleep", new=AsyncMock()):
            result = await host._fuzz_method("ns=2;i=20", iterations=2, method_info={})

        self.assertEqual(result["tests"], 0)
        host.logger.warning.assert_called()

    async def test_parent_resolved_via_inverse_reference(self):
        _skip_if_no_asyncua()
        host = _FuzzHost()
        method_node = MagicMock()
        parent_node = MagicMock()
        parent_node.call_method = AsyncMock(return_value=None)

        ref = SimpleNamespace(
            ReferenceTypeId=SimpleNamespace(Identifier=ua.ObjectIds.HasComponent),
            NodeId=_NodeId("ns=2;i=1"),
        )
        method_node.get_references = AsyncMock(return_value=[ref])

        def _get_node(node_id):
            return method_node if node_id == "ns=2;i=20" else parent_node

        host._client.get_node = MagicMock(side_effect=_get_node)
        host._get_method_arguments = AsyncMock(return_value=[])

        with patch("asyncio.sleep", new=AsyncMock()):
            result = await host._fuzz_method("ns=2;i=20", iterations=1, method_info=None)

        # Parent was found via the inverse HasComponent ref -> calls proceeded.
        self.assertEqual(result["tests"], 1)
        method_node.get_references.assert_awaited()


if __name__ == "__main__":
    unittest.main()
