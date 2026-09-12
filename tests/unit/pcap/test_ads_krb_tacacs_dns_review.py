"""Crash/hang review of ads.py, kerberos.py, tacacs.py, dns.py.

These 4 listeners were flagged as the remaining hand-rolled raw-byte
parsers (struct.unpack / int.from_bytes / while-loops over peer buffers)
in src/oida/pcap/. Each candidate below was inspected line-by-line and then
verified empirically: no crash, hang, or unbounded allocation was
reproducible on any of them.

Why they're safe (verified, not assumed):
  - ads.py ``_extract_data_hex``: every raw-byte offset is preceded by an
    explicit ``len(payload) < BASE + N`` guard, and the attacker-controlled
    ``cblength`` is clamped via ``min(data_off + cblength, len(payload))``
    before slicing.
  - kerberos.py ``_parse_encrypted_data``: the ASN.1-ish DER walker's
    ``pos`` cursor advances by >= 2 bytes every loop iteration *before*
    the attacker-controlled ``length`` is used, so the loop is bounded by
    len(raw) regardless of what ``length`` claims. The inflated ``length``
    is only ever used for (a) a bytes slice, which Python clamps
    automatically to the actual buffer size no matter how large the
    requested stop index is, and (b) ``pos += length``, which simply makes
    the while-condition false on the next check (loop terminates
    immediately) rather than looping forever.
  - tacacs.py ``_extract_encrypted_hash``: ``length`` (up to ~4GB, read
    from 4 attacker bytes) is only used in ``body[12:12+length]``, which
    Python clamps to the real buffer size -- no huge allocation, no loop
    at all in this function.
  - dns.py: contains no raw struct.unpack/int.from_bytes/manual byte
    slicing whatsoever -- all record parsing goes through tshark's
    already-dissected string/list fields via ``get_field``/
    ``get_all_fields``. Its one manual walker, ``_soa_rname_to_email``,
    iterates a Python *string* (not raw packet bytes) with a cursor that
    advances by 1 or 2 every iteration, strictly bounded by
    ``len(rname)``.

Per the review's own method ("if you can't reproduce, don't fix -- list
as unproven suspicion"): no bug was reproducible on any of the four
files, so no source change was made. The tests here are therefore
confirmatory regression coverage -- they pin the already-safe behavior
of each hot spot against maximally adversarial (huge / overflowing
length field) input, with a wall-clock bound proving termination.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from oida.pcap.ads import ADSPassiveListener
from oida.pcap.dns import DNSPassiveListener
from oida.pcap.kerberos import KerberosPassiveListener
from oida.pcap.tacacs import TACACSPassiveListener

HANG_BUDGET_S = 5.0  # generous; a real hang would never return


def _mk_tcp_packet(payload: bytes):
    """Minimal pyshark-like packet object with packet.tcp.payload as raw bytes."""
    tcp = SimpleNamespace(payload=payload)
    return SimpleNamespace(tcp=tcp)


# ---------------------------------------------------------------------------
# ads.py -- _extract_data_hex: cblength read from the wire, used to slice
# the TCP payload.
# ---------------------------------------------------------------------------


class TestADSExtractDataHex:
    def test_huge_cblength_read_response_is_clamped_not_oom(self):
        """cblength claims ~4GB; actual payload is tiny. Must clamp, not hang/OOM."""
        base = 38
        payload = bytearray(base + 8)
        # result(4) + cblength(4) -- cblength = 0xFFFFFFFF (little-endian)
        payload[base + 4 : base + 8] = (0xFFFFFFFF).to_bytes(4, "little")
        packet = _mk_tcp_packet(bytes(payload))

        start = time.monotonic()
        result = ADSPassiveListener._extract_data_hex(packet, cmd_id=0x0002, is_response=True)
        elapsed = time.monotonic() - start

        assert elapsed < HANG_BUDGET_S, f"_extract_data_hex hung/slow: {elapsed}s"
        # No data actually present after the header -> clamped to empty.
        assert result == ""

    def test_huge_cblength_with_trailing_data_returns_only_available_bytes(self):
        """cblength overstates the real data; result must not exceed actual payload."""
        base = 38
        trailing = b"\xde\xad\xbe\xef"
        payload = bytearray(base + 8)
        payload[base + 4 : base + 8] = (0xFFFFFFFF).to_bytes(4, "little")
        payload += trailing
        packet = _mk_tcp_packet(bytes(payload))

        start = time.monotonic()
        result = ADSPassiveListener._extract_data_hex(packet, cmd_id=0x0002, is_response=True)
        elapsed = time.monotonic() - start

        assert elapsed < HANG_BUDGET_S
        assert result == trailing.hex()

    def test_truncated_payload_below_header_returns_empty(self):
        packet = _mk_tcp_packet(b"\x00" * 10)
        assert ADSPassiveListener._extract_data_hex(packet, cmd_id=0x0002, is_response=True) == ""

    def test_control_well_formed_read_response(self):
        """Sanity control: well-formed input still extracts the correct data."""
        base = 38
        data = b"\x01\x02\x03\x04"
        payload = bytearray(base + 8)
        payload[base + 4 : base + 8] = len(data).to_bytes(4, "little")
        payload += data
        packet = _mk_tcp_packet(bytes(payload))

        result = ADSPassiveListener._extract_data_hex(packet, cmd_id=0x0002, is_response=True)
        assert result == data.hex()


# ---------------------------------------------------------------------------
# kerberos.py -- _parse_encrypted_data: hand-rolled DER walker over a
# hex-encoded EncryptedData blob.
# ---------------------------------------------------------------------------


class TestKerberosParseEncryptedData:
    def test_inflated_multibyte_length_terminates_and_does_not_oom(self):
        """A TLV claims a length so large it can't possibly fit -- must not hang/OOM."""
        # SEQUENCE tag+short-length, then one element: tag 0xA0, length-of-length
        # byte 0x84 (4 length bytes follow) claiming 0xFFFFFFFF.
        raw = bytes(
            [0x30, 0x20]  # outer SEQUENCE, short length (unused/ignored by parser)
            + [0xA0, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]  # inflated length claim
            + [0x02, 0x01, 0x11]  # a few real trailing bytes so len(raw) >= 10
        )
        start = time.monotonic()
        etype, cipher_hex = KerberosPassiveListener._parse_encrypted_data(raw.hex())
        elapsed = time.monotonic() - start

        assert elapsed < HANG_BUDGET_S, f"_parse_encrypted_data hung/slow: {elapsed}s"
        # Content got clamped to whatever bytes remained -- no crash either way.
        assert isinstance(etype, int)
        assert isinstance(cipher_hex, str)

    def test_short_buffer_returns_default(self):
        etype, cipher_hex = KerberosPassiveListener._parse_encrypted_data("3003020101")
        assert (etype, cipher_hex) == (0, "")

    def test_invalid_hex_returns_default(self):
        etype, cipher_hex = KerberosPassiveListener._parse_encrypted_data("not-hex-zz")
        assert (etype, cipher_hex) == (0, "")

    def test_control_well_formed_encrypted_data(self):
        """Sanity control: a well-formed EncryptedData SEQUENCE parses etype + cipher."""
        # SEQUENCE { [0] INTEGER etype=17, [2] OCTET STRING cipher=b'\xaa\xbb\xcc\xdd' }
        etype_tlv = bytes([0xA0, 0x03, 0x02, 0x01, 0x11])  # [0] INTEGER 17
        cipher_bytes = b"\xaa\xbb\xcc\xdd"
        cipher_tlv = bytes([0xA2, 2 + len(cipher_bytes), 0x04, len(cipher_bytes)]) + cipher_bytes
        body = etype_tlv + cipher_tlv
        raw = bytes([0x30, len(body)]) + body

        etype, cipher_hex = KerberosPassiveListener._parse_encrypted_data(raw.hex())
        assert etype == 17
        assert cipher_hex == cipher_bytes.hex()


# ---------------------------------------------------------------------------
# tacacs.py -- _extract_encrypted_hash: reads a 4-byte length field from the
# TACACS+ header and slices the body with it.
# ---------------------------------------------------------------------------


class TestTacacsExtractEncryptedHash:
    def _mk_listener(self):
        return TACACSPassiveListener(interface="lo", timeout=1)

    def test_huge_length_field_is_dropped_not_oom(self):
        """length claims ~4GB; only a handful of real bytes follow. Must drop, not hang/OOM.

        A declared length that overruns the captured bytes means the TACACS+
        record was split across TCP segments, so the cipher present is a
        truncated prefix. A mode-16100 hash built from a truncated cipher can
        never crack, so the listener drops the record rather than emitting a
        useless (and misleading) credential -- while never slicing past the
        available bytes, so there is no OOM.
        """
        header = bytearray(12)
        header[0] = 0xC0  # version
        header[1] = 0x01  # ptype = AUTHEN
        header[2] = 0x01  # seq (odd -> client request)
        header[3] = 0x00  # flags (encrypted, bit0 clear)
        header[8:12] = (0xFFFFFFFF).to_bytes(4, "big")  # length
        body = bytes(header) + b"\x01\x02\x03\x04\x05\x06\x07\x08"  # 8 trailing bytes
        packet = _mk_tcp_packet(body)

        listener = self._mk_listener()
        start = time.monotonic()
        listener._extract_encrypted_hash(packet, "10.0.0.1", "10.0.0.2", 4321, 49)
        elapsed = time.monotonic() - start

        assert elapsed < HANG_BUDGET_S, f"_extract_encrypted_hash hung/slow: {elapsed}s"
        # Declared length overruns the captured bytes -> split/malformed record, dropped.
        assert listener.credentials == []

    def test_truncated_body_below_minimum_is_dropped_gracefully(self):
        packet = _mk_tcp_packet(b"\x00" * 5)
        listener = self._mk_listener()
        listener._extract_encrypted_hash(packet, "10.0.0.1", "10.0.0.2", 4321, 49)
        assert listener.credentials == []

    def test_control_well_formed_authen_packet(self):
        """Sanity control: well-formed encrypted AUTHEN packet still yields a hash."""
        header = bytearray(12)
        header[0] = 0xC0
        header[1] = 0x01  # AUTHEN
        header[2] = 0x01  # odd seq -> client
        header[3] = 0x00  # encrypted
        cipher = b"\xaa\xbb\xcc\xdd\xee\xff"
        header[8:12] = len(cipher).to_bytes(4, "big")
        body = bytes(header) + cipher
        packet = _mk_tcp_packet(body)

        listener = self._mk_listener()
        listener._extract_encrypted_hash(packet, "10.0.0.1", "10.0.0.2", 4321, 49)
        assert len(listener.credentials) == 1
        assert listener.credentials[0].tacacs_cipher_hex == cipher.hex()


# ---------------------------------------------------------------------------
# dns.py -- _soa_rname_to_email: manual cursor walk over an rname string
# (already dissected by tshark, not raw packet bytes).
# ---------------------------------------------------------------------------


class TestDnsSoaRnameToEmail:
    @pytest.mark.parametrize(
        "rname",
        [
            "",
            ".",
            "trailing-backslash\\",  # dangling escape at end-of-string
            "a\\.b\\.c",  # every dot escaped -> no unescaped dot
            "\\" * 5000,  # long run of dangling-escape-like chars
            "no-dot-at-all",
        ],
    )
    def test_adversarial_rname_terminates(self, rname):
        start = time.monotonic()
        result = DNSPassiveListener._soa_rname_to_email(rname)
        elapsed = time.monotonic() - start
        assert elapsed < HANG_BUDGET_S
        assert isinstance(result, str)

    def test_control_well_formed_rname(self):
        assert DNSPassiveListener._soa_rname_to_email("admin.example.com") == "admin@example.com"

    def test_control_escaped_dot_in_local_part(self):
        assert (
            DNSPassiveListener._soa_rname_to_email("john\\.doe.example.com")
            == "john.doe@example.com"
        )
