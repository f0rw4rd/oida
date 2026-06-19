"""--test-rbac must not issue live Write service calls without --confirm.

CODE_REVIEW.md MEDIUM (credentials.py:218-229): the RBAC write-access probe
reads a variable and writes the value straight back for the first child nodes
of every auth method. That is a real Write against production variables and
must be gated on --confirm like every other write path in the OPC UA module.

The CredentialsMixin is mixed into the NXC ``opcua`` class whose ``self.args``
is a plain argparse Namespace (attribute access), so the gate uses
``getattr(self.args, "confirm", ...)`` to match the other write paths
(writes.py, methods.py, fuzz.py).
"""

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from oida.protocols.opcua.helpers import _asyncua, ua
from oida.protocols.opcua.mixins.credentials import CredentialsMixin


class _RBACHarness(CredentialsMixin):
    """Minimal host exposing just what _test_rbac touches."""

    def __init__(self, confirm):
        self.args = SimpleNamespace(confirm=confirm)
        self.logger = MagicMock()
        self.results = {"data": {}}
        self.host = "127.0.0.1"
        self._original_url = "opc.tcp://127.0.0.1:4840"
        self.default_port = 4840


def _make_variable_node():
    node = MagicMock()
    node.nodeid = "ns=2;i=1001"
    node.read_value = AsyncMock(return_value=123)
    node.write_value = AsyncMock()
    node.read_node_class = AsyncMock(return_value=ua.NodeClass.Variable)
    node.read_browse_name = AsyncMock(return_value="Var")
    return node


def _make_client(var_node):
    client = MagicMock()
    client.set_user = MagicMock()
    client.set_password = MagicMock()
    client.set_security_string = AsyncMock()
    client.connect = AsyncMock()
    client.disconnect = AsyncMock()

    objects = MagicMock()
    objects.get_children = AsyncMock(return_value=[var_node])
    client.get_objects_node = MagicMock(return_value=objects)

    server_node = MagicMock()
    server_node.get_methods = AsyncMock(return_value=[])
    client.get_node = MagicMock(return_value=server_node)
    return client


class TestRBACWriteConfirmGate(unittest.IsolatedAsyncioTestCase):
    async def _run(self, confirm):
        var_node = _make_variable_node()
        client = _make_client(var_node)
        harness = _RBACHarness(confirm=confirm)
        with patch(
            "oida.protocols.opcua.mixins.credentials._get_client_class",
            return_value=lambda *a, **k: client,
        ):
            await harness._test_rbac(
                "opc.tcp://127.0.0.1:4840", ["admin"], ["adminpass"]
            )
        return var_node

    async def test_write_back_skipped_without_confirm(self):
        if not _asyncua.is_available:
            self.skipTest("asyncua not available")
        var_node = await self._run(confirm=False)
        var_node.write_value.assert_not_called()

    async def test_write_back_runs_with_confirm(self):
        if not _asyncua.is_available:
            self.skipTest("asyncua not available")
        var_node = await self._run(confirm=True)
        var_node.write_value.assert_awaited()


if __name__ == "__main__":
    unittest.main()
