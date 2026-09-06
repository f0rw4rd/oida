"""_fuzz_node anomaly detection must compare like-with-like.

CODE_REVIEW.md MEDIUM (fuzz.py:162-166): the anomaly check compared the
re-encoded readback (bytes produced by read_value() re-encoding the stored
typed value) against the *raw* fuzz payload bytes. For int/float/str nodes
write_value() first decodes the raw bytes into a typed value, so the typed
round-trip almost never reproduces the original byte string (length and
encoding differ). A faithful, correctly-stored write was therefore flagged
as an anomaly on nearly every iteration, inflating the anomaly count.

The fix re-encodes the value that was actually written and compares that
against the re-encoded readback. These tests drive _fuzz_node against a
mock node that faithfully stores/returns whatever is written and assert
zero anomalies.
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


def _make_faithful_node(initial):
    """A Variable node that faithfully stores whatever value is written.

    read_value() returns the last value written (or `initial`), so a correct
    write must round-trip and must NOT be counted as an anomaly.
    """
    node = MagicMock()
    node.read_node_class = AsyncMock(return_value=ua.NodeClass.Variable)
    state = {"value": initial}

    async def _read():
        return state["value"]

    async def _write(value):
        state["value"] = value

    node.read_value = AsyncMock(side_effect=_read)
    node.write_value = AsyncMock(side_effect=_write)
    return node


class TestFuzzNodeAnomalyComparison(unittest.IsolatedAsyncioTestCase):
    async def _run(self, initial, payloads):
        node = _make_faithful_node(initial)
        harness = _FuzzHarness(node)

        def _fake_fuzz(original, count=10, **kwargs):
            for p in payloads:
                yield (p, "payload")

        with patch("oida.utils.fuzzer.fuzz", _fake_fuzz), patch("asyncio.sleep", new=AsyncMock()):
            result = await harness._fuzz_node("ns=2;i=1", iterations=len(payloads))
        self.assertIsNotNone(result)
        return result

    async def test_int_node_faithful_write_is_not_anomaly(self):
        if not _asyncua.is_available:
            self.skipTest("asyncua not available")
        # Raw payload b"\x05" decodes to int 5; readback re-encodes to
        # b"\x05\x00\x00\x00" != raw payload -> old code flagged an anomaly.
        result = await self._run(0, [b"\x05", b"\x2a", b"\xff\xff\xff\x7f"])
        self.assertEqual(result["writes"], 3)
        self.assertEqual(result["anomalies"], 0)
        self.assertEqual(result["crashes"], 0)

    async def test_float_node_faithful_write_is_not_anomaly(self):
        if not _asyncua.is_available:
            self.skipTest("asyncua not available")
        result = await self._run(0.0, [b"\x00\x00\x80\x3f", b"\x00\x00\x00\x40"])
        self.assertEqual(result["writes"], 2)
        self.assertEqual(result["anomalies"], 0)

    async def test_str_node_faithful_write_is_not_anomaly(self):
        if not _asyncua.is_available:
            self.skipTest("asyncua not available")
        # Even here, an empty initial encodes to b"" so the original-match arm
        # could mask it; use a non-empty initial so only the expected-match arm
        # can suppress the anomaly.
        result = await self._run("seed", [b"hello", b"world"])
        self.assertEqual(result["writes"], 2)
        self.assertEqual(result["anomalies"], 0)

    async def test_genuine_mismatch_still_flags_anomaly(self):
        if not _asyncua.is_available:
            self.skipTest("asyncua not available")
        # A corrupting node: it stores write+1 instead of the written value, so
        # readback (encoded write+1) differs from both `expected` (encoded
        # written value) AND `original` (the baseline encoding). That is a
        # genuine anomaly and must still be flagged after the fix. Guards
        # against the fix over-suppressing real divergence.
        node = MagicMock()
        node.read_node_class = AsyncMock(return_value=ua.NodeClass.Variable)
        state = {"value": 0}

        async def _read():
            return state["value"]

        async def _write(value):
            state["value"] = value + 1  # corrupt the stored value

        node.read_value = AsyncMock(side_effect=_read)
        node.write_value = AsyncMock(side_effect=_write)
        harness = _FuzzHarness(node)

        def _fake_fuzz(original, count=10, **kwargs):
            yield (b"\x07", "payload")  # decodes to 7, node stores 8

        with patch("oida.utils.fuzzer.fuzz", _fake_fuzz), patch("asyncio.sleep", new=AsyncMock()):
            result = await harness._fuzz_node("ns=2;i=1", iterations=1)
        self.assertIsNotNone(result)
        self.assertEqual(result["anomalies"], 1)


if __name__ == "__main__":
    unittest.main()
