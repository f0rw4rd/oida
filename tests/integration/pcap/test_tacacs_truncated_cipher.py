"""Regression test: a truncated TACACS+ segment must not yield a hash.

The TACACS+ header declares a body length. If the captured segment carries
fewer bytes than that (a record split across TCP segments, or a partial
capture), slicing ``body[12 : 12 + length]`` silently produces a short
ciphertext. A mode-16100 hash built from it can never crack, so emitting one
is worse than emitting nothing -- the operator burns GPU time on it.
"""

import pytest

from oida.pcap.tacacs import TACACSPassiveListener

pytestmark = [pytest.mark.integration]


class _Tcp:
    def __init__(self, payload: bytes):
        # pyshark renders tcp.payload as colon-separated hex
        self.payload = ":".join(f"{b:02x}" for b in payload)


class _Packet:
    sniff_timestamp = "1700000000.0"

    def __init__(self, payload: bytes):
        self.tcp = _Tcp(payload)

    def __getitem__(self, key):
        if str(key).lower() == "tcp":
            return self.tcp
        raise KeyError(key)

    def __contains__(self, key):
        return str(key).lower() == "tcp"


def _packet_with_payload(payload: bytes) -> _Packet:
    return _Packet(payload)


def _header(length: int, session_id: bytes = b"\x5f\xde\x8e\x68") -> bytes:
    """TACACS+ header: version, type=AUTHEN, seq, flags=0 (encrypted)."""
    return bytes([0xC0, 0x01, 0x02, 0x00]) + session_id + length.to_bytes(4, "big")


class TestTruncatedCipherRejected:
    def test_declared_length_longer_than_segment_yields_no_hash(self):
        """Header claims 40 bytes of body; only 9 are present."""
        listener = TACACSPassiveListener(interface="lo", timeout=1)
        payload = _header(40) + b"\xb8\x4e\x81\x7e\xfc\xd7\x27\xc0\x37"

        listener._extract_encrypted_hash(
            _packet_with_payload(payload), "10.0.0.1", "10.0.0.2", 50000, 49
        )

        assert listener.credentials == [], (
            "truncated ciphertext was emitted as a crackable hash: "
            f"{[c.hash_value for c in listener.credentials]}"
        )

    def test_complete_segment_still_yields_a_hash(self):
        """The guard must not reject well-formed records."""
        listener = TACACSPassiveListener(interface="lo", timeout=1)
        cipher = b"\xb8\x4e\x81\x7e\xfc\xd7\x27\xc0\x37"
        payload = _header(len(cipher)) + cipher

        listener._extract_encrypted_hash(
            _packet_with_payload(payload), "10.0.0.1", "10.0.0.2", 50000, 49
        )

        assert len(listener.credentials) == 1
        hash_value = listener.credentials[0].hash_value
        assert hash_value.startswith("$tacacs-plus$")
        assert cipher.hex() in hash_value
