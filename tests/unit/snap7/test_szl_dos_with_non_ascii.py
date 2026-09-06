"""SZL parser DoS guard - more comprehensive than the existing test.

Covers additional fuzz inputs that should not hang or crash:
- huge record_len that overflows past buffer
- record_len=1 (still too small for index+payload)
- record_len=2 (just an index, no payload)
- truncated data after partial header
- legitimate small SZL still parses
"""

import struct
import threading
import unittest


class TestSZLParserHardenedDoS(unittest.TestCase):
    def _run_with_timeout(self, callable_, *args):
        holder = {}

        def target():
            try:
                holder["result"] = callable_(*args)
            except Exception as e:
                holder["error"] = e

        t = threading.Thread(target=target, daemon=True)
        t.start()
        t.join(timeout=2.0)
        self.assertFalse(t.is_alive(), f"{callable_.__name__} hung")
        return holder

    def test_record_len_1_does_not_hang(self):
        from oida.protocols.snap7.szl_parser import SZLParser

        header = struct.pack("<HH", 1, 1)
        body = struct.pack(">H", 7) + b"X" * 30
        data = header + body

        holder = self._run_with_timeout(SZLParser._parse_0x001c, data, 0)
        self.assertIn("result", holder)
        self.assertFalse(holder["result"].get("parsed", True))

    def test_record_len_2_does_not_hang(self):
        from oida.protocols.snap7.szl_parser import SZLParser

        header = struct.pack("<HH", 2, 1)
        body = struct.pack(">H", 7) + b"X" * 30
        data = header + body

        holder = self._run_with_timeout(SZLParser._parse_0x001c, data, 0)
        self.assertIn("result", holder)

    def test_huge_record_len_does_not_overread(self):
        from oida.protocols.snap7.szl_parser import SZLParser

        # record_len = 65535 (max uint16) but only 32 bytes of body.
        header = struct.pack("<HH", 65535, 1)
        body = b"X" * 32
        data = header + body

        holder = self._run_with_timeout(SZLParser._parse_0x001c, data, 0)
        self.assertIn("result", holder)
        # The loop's `while offset + record_len <= len(data)` returns
        # False immediately since 4 + 65535 > 36; parsed remains False.
        self.assertFalse(holder["result"].get("parsed", True))

    def test_truncated_after_header(self):
        from oida.protocols.snap7.szl_parser import SZLParser

        # Header says record_len=10, but body is only 5 bytes.
        header = struct.pack("<HH", 10, 1)
        body = b"\xab" * 5
        data = header + body

        holder = self._run_with_timeout(SZLParser._parse_0x001c, data, 0)
        self.assertIn("result", holder)

    def test_legitimate_small_szl_still_parses(self):
        """Don't be over-zealous - record_len=3 (minimum valid) must work."""
        from oida.protocols.snap7.szl_parser import SZLParser

        # 3-byte record: 2-byte index + 1-byte payload
        record_len = 3
        header = struct.pack("<HH", record_len, 1)
        body = struct.pack(">H", 7) + b"X"
        data = header + body

        holder = self._run_with_timeout(SZLParser._parse_0x001c, data, 0)
        self.assertIn("result", holder)
        # record_len=3 is at our guard boundary (>= 3); should parse.
        self.assertIsInstance(holder["result"], dict)


if __name__ == "__main__":
    unittest.main()
