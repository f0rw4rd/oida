"""coap_get_blockwise must bound its assembled payload.

Old behavior: a hostile server keeping M=1 indefinitely could drive
the scanner's bytearray to OOM.
"""

import asyncio
import unittest


class _Block2:
    """Mimics aiocoap's BlockOption tuple for response.opt.block2."""

    def __init__(self, block_number, more, size_exponent):
        self.block_number = block_number
        self.more = more
        self.size_exponent = size_exponent


class _FakeResponse:
    def __init__(self, payload, more=True, block_number=0, szx=5):
        self.payload = payload

        class _Code:
            def __str__(self):
                return "2.05 Content"

        self.code = _Code()

        class _Opt:
            pass

        self.opt = _Opt()
        self.opt.block2 = _Block2(block_number, more, szx)


class _FakeContext:
    """Returns a never-ending stream of 1024-byte blocks with M=1."""

    def __init__(self, block_payload=b"A" * 1024):
        self.block_payload = block_payload
        self.calls = 0

    def request(self, request):
        # Caller does: response = await ctx.request(req).response
        outer = self

        class _R:
            @property
            def response(self):
                async def _co():
                    outer.calls += 1
                    block_num = outer.calls - 1
                    # Always M=1 -> never terminates naturally
                    return _FakeResponse(
                        outer.block_payload, more=True, block_number=block_num, szx=5
                    )

                return _co()

        return _R()


class TestBlockwisePayloadCap(unittest.TestCase):
    def test_payload_cap_aborts_at_max(self):
        from oida.protocols.coap.helpers import coap_get_blockwise

        ctx = _FakeContext(block_payload=b"X" * 1024)

        # Small cap so the test completes quickly.
        code, payload = asyncio.run(
            coap_get_blockwise(ctx, "coap://h/big", block_size=1024, max_payload=5_000)
        )

        self.assertEqual(code, "aborted:payload-too-large")
        # Truncated to <= cap.
        self.assertLessEqual(len(payload), 5_000)
        # Old code (no cap) would have looped until the test framework
        # timed out - calls > a few is fine; runaway means thousands.
        self.assertLess(ctx.calls, 100)


if __name__ == "__main__":
    unittest.main()
