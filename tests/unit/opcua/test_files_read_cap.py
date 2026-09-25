#!/usr/bin/env python3
"""
Regression test for OPC UA _read_file unbounded-read size cap.

Guards against: _read_file accumulated the entire file in memory
with no upper bound, letting a malicious/misconfigured server drive unbounded
memory growth. A configurable ceiling (args.max_read_bytes, default
DEFAULT_MAX_READ_BYTES) must abort the read and not store the partial blob.
"""

import asyncio
import types
import unittest
from unittest.mock import AsyncMock, MagicMock

from oida.protocols.opcua.mixins.files import FilesMixin, DEFAULT_MAX_READ_BYTES


class MockBrowseName:
    def __init__(self, name):
        self.Name = name


class _Reader(FilesMixin):
    """Minimal host object exposing just what _read_file touches."""

    def __init__(self, args, total_bytes, chunk_size=4096):
        self.args = args
        self.logger = MagicMock()
        self.results = {"data": {}}
        self._total = total_bytes
        self._served = 0
        self._chunk_size = chunk_size
        self.closed = False

        # Methods on the file node.
        self._methods = {
            "0:Open": object(),
            "0:Read": object(),
            "0:Close": object(),
        }

        file_node = MagicMock()
        file_node.read_browse_name = AsyncMock(return_value=MockBrowseName("evil.bin"))
        file_node.get_child = AsyncMock(side_effect=self._get_child)
        file_node.call_method = AsyncMock(side_effect=self._call_method)
        self._file_node = file_node

        self._client = MagicMock()
        self._client.get_node = MagicMock(return_value=file_node)

    async def _get_child(self, name):
        if name == "0:Size":
            size_node = MagicMock()
            size_node.read_value = AsyncMock(return_value=self._total)
            return size_node
        if name in self._methods:
            return self._methods[name]
        raise Exception(f"no child {name}")

    async def _call_method(self, method, *args):
        if method is self._methods["0:Open"]:
            return 1  # file handle
        if method is self._methods["0:Close"]:
            self.closed = True
            return None
        if method is self._methods["0:Read"]:
            remaining = self._total - self._served
            n = min(self._chunk_size, remaining)
            self._served += n
            return b"A" * n
        raise Exception("unexpected method")


def _args(**kw):
    ns = types.SimpleNamespace(read_file="ns=2;s=evil", file_output=None)
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


class _ShortChunkReader(_Reader):
    """Serves a short (but non-final) chunk mid-stream before EOF.

    Models the OPC UA Read method returning fewer bytes than requested
    without signalling EOF (allowed on server buffer boundaries). EOF is
    only the empty chunk after all bytes have been served.
    """

    def __init__(self, args, chunk_sizes):
        # chunk_sizes: explicit byte counts to serve per Read call; the loop
        # must keep reading until it observes an empty chunk.
        total = sum(chunk_sizes)
        super().__init__(args, total_bytes=total)
        self._schedule = list(chunk_sizes)

    async def _call_method(self, method, *args):
        if method is self._methods["0:Read"]:
            if self._schedule:
                n = self._schedule.pop(0)
                self._served += n
                return b"A" * n
            return b""  # EOF
        return await super()._call_method(method, *args)


class TestReadFileShortChunk(unittest.TestCase):
    def test_short_nonfinal_chunk_does_not_truncate(self):
        # Middle Read returns fewer than chunk_size (4096) bytes but is NOT
        # EOF: more data follows. The buggy `while bytes_read == chunk_size`
        # loop stopped here and reported a truncated size.
        cap = 1024 * 1024
        reader = _ShortChunkReader(
            _args(max_read_bytes=cap),
            chunk_sizes=[4096, 100, 4096, 2000],  # 100 is a short non-final read
        )
        asyncio.run(reader._read_file())

        self.assertIn("file_read", reader.results["data"])
        self.assertEqual(
            reader.results["data"]["file_read"]["size"],
            4096 + 100 + 4096 + 2000,
        )
        reader.logger.fail.assert_not_called()
        self.assertTrue(reader.closed)


class TestReadFileSizeCap(unittest.TestCase):
    def test_default_cap_is_used_when_arg_absent(self):
        # No max_read_bytes arg -> the module default ceiling applies.
        # Use a small streamed file so the read completes quickly; the point is
        # that the absent/zero arg does not disable capping (falls back to
        # DEFAULT_MAX_READ_BYTES, which is positive).
        self.assertGreater(DEFAULT_MAX_READ_BYTES, 0)
        reader = _Reader(_args(), total_bytes=10000)
        asyncio.run(reader._read_file())
        self.assertIn("file_read", reader.results["data"])
        reader.logger.fail.assert_not_called()

    def test_aborts_when_exceeding_cap(self):
        # Server streams more than the (small) configured ceiling.
        reader = _Reader(_args(max_read_bytes=4096), total_bytes=4096 * 50)
        asyncio.run(reader._read_file())

        # Read must be aborted and the partial content must NOT be stored.
        self.assertNotIn("file_read", reader.results["data"])
        self.assertTrue(reader.closed, "file handle should be closed on abort")
        reader.logger.fail.assert_called()

    def test_custom_lower_cap_enforced(self):
        reader = _Reader(_args(max_read_bytes=8192), total_bytes=64 * 1024)
        asyncio.run(reader._read_file())
        self.assertNotIn("file_read", reader.results["data"])
        reader.logger.fail.assert_called()

    def test_small_file_under_cap_succeeds(self):
        reader = _Reader(_args(max_read_bytes=1024 * 1024), total_bytes=10000)
        asyncio.run(reader._read_file())
        self.assertIn("file_read", reader.results["data"])
        self.assertEqual(reader.results["data"]["file_read"]["size"], 10000)
        reader.logger.fail.assert_not_called()


if __name__ == "__main__":
    unittest.main()
