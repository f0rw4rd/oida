"""Regression test: Redis AUTH passwords containing a comma are corrupted.

Root cause (src/oida/pcap/redis.py, ``_parse_bulk_values``, ~line 469-486):
when ``get_field()`` returns the comma-joined bytes-repr representation of a
RESP bulk-string-value list (e.g. "b'AUTH',b'pass,word'"), the parser did a
naive ``raw_str.split(",")``. That split has no notion of the ``b'...'``
literal boundaries, so it breaks *inside* a value that itself contains a
comma: "b'AUTH',b'pass,word'" splits into ["b'AUTH'", "b'pass", "word'"].
The middle fragment ("b'pass") fails the ``startswith(...) and endswith(...)``
wrapper check (no trailing quote), falls through to ``_decode_resp_hex``,
which cannot ``bytes.fromhex()`` it and returns the string verbatim --
*with* its ``b'`` prefix intact. The end result: an AUTH command with
password "pass,word" gets recorded as username "AUTH" (fine) but the
password value ends up mangled to "b'pass" (missing the rest, keeping the
raw Python bytes-repr prefix) instead of the real "pass,word".
"""

import pytest

from oida.pcap.redis import RedisPassiveListener

pytestmark = [pytest.mark.unit]


class TestParseBulkValuesCommaInPassword:
    def test_comma_inside_bulk_string_value_is_preserved(self):
        """FAILS before the fix: comma inside a bulk string value splits the
        b'...' literal apart instead of being treated as literal payload."""
        listener = RedisPassiveListener(interface="lo", timeout=1)

        raw = "b'AUTH',b'pass,word'"
        values = listener._parse_bulk_values(raw)

        assert values == ["AUTH", "pass,word"], (
            f"comma inside a RESP bulk string value was corrupted: {values!r}"
        )

    def test_password_with_comma_recorded_correctly(self):
        """End-to-end: AUTH with a comma-containing password must not leak
        a 'b'...' wrapper fragment into the recorded credential."""
        listener = RedisPassiveListener(interface="lo", timeout=1)

        raw = "b'AUTH',b'pass,word'"
        values = listener._parse_bulk_values(raw)
        assert len(values) == 2
        command, password = values[0], values[1]

        assert not password.startswith("b'"), (
            f"password retained the Python bytes-repr wrapper: {password!r}"
        )
        assert password == "pass,word"
        assert command == "AUTH"

    def test_no_comma_still_works(self):
        """Control: the common no-comma case must be unaffected."""
        listener = RedisPassiveListener(interface="lo", timeout=1)
        values = listener._parse_bulk_values("b'AUTH',b'secretpassword123'")
        assert values == ["AUTH", "secretpassword123"]
