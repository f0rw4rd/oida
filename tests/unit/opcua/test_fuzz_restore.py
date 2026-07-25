"""_fuzz_node must restore an empty-but-valid original value.

CODE_REVIEW.md LOW (fuzz.py:155-176): ``_fuzz_node`` captured
``original = await read_value()`` (always bytes) and restored with the
truthiness guard ``if original: await write_value(original)``. For a node
whose value reads back as empty/None — encoded to ``b""`` — the guard was
falsy, so the restore was skipped and the node was left holding the last
fuzz payload. The guard must be ``original is not None`` so empty-but-valid
originals are written back.
"""

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from oida.protocols.opcua.helpers import _asyncua, ua
from oida.protocols.opcua.mixins.fuzz import FuzzMixin


class _FuzzHarness(FuzzMixin):
    def __init__(self, node):
        self.args = SimpleNamespace(confirm=True)
        self.logger = MagicMock()
        client = MagicMock()
        client.get_node = MagicMock(return_value=node)
        self._client = client


def _make_empty_value_node():
    """A Variable node whose value reads back as None (encodes to b"")."""
    node = MagicMock()
    node.read_node_class = AsyncMock(return_value=ua.NodeClass.Variable)
    # read_value() -> None means read_value() helper returns b"" (falsy).
    node.read_value = AsyncMock(return_value=None)
    node.write_value = AsyncMock()
    return node


class TestFuzzNodeRestoresEmptyOriginal(unittest.IsolatedAsyncioTestCase):
    async def test_empty_original_is_restored(self):
        if not _asyncua.is_available:
            self.skipTest("asyncua not available")

        node = _make_empty_value_node()
        harness = _FuzzHarness(node)

        # One deterministic, non-empty fuzz payload so the node ends the loop
        # holding b"\xff\xff" — the restore must overwrite it back to b"".
        def _fake_fuzz(original, count=10, **kwargs):
            yield (b"\xff\xff", "payload")

        with patch("oida.utils.fuzzer.fuzz", _fake_fuzz), patch("asyncio.sleep", new=AsyncMock()):
            result = await harness._fuzz_node("ns=2;i=1", iterations=1)

        self.assertIsNotNone(result)
        # The final write_value call must restore the original empty bytes,
        # not leave the node holding the b"\xff\xff" payload.
        last_written = node.write_value.await_args_list[-1].args[0]
        self.assertEqual(last_written, b"")
        self.assertGreaterEqual(node.write_value.await_count, 2)


if __name__ == "__main__":
    unittest.main()
