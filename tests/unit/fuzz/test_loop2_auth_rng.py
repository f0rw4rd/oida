"""Regression tests for two verified fuzzer bugs.

F6  - MQTTAuthenticator built a MQTT 5.0 CONNECT without the mandatory
      Properties field, so a v5 broker rejects the packet at parse time and
      the auth sequence never reaches the broker's auth logic.
C8  - BaseFuzzer seeded the process-global ``random`` module, a global side
      effect that breaks reproducibility and makes concurrent fuzzers
      interfere with each other.
"""

import random

import pytest

from oida.fuzz.core.auth import MQTTAuthenticator


# =============================================================================
# F6 - MQTT 5.0 CONNECT Properties field
# =============================================================================


def _variable_header(packet: bytes) -> bytes:
    """Strip the fixed header (type byte + remaining-length varbytes)."""
    idx = 1
    while packet[idx] & 0x80:
        idx += 1
    return packet[idx + 1 :]


class TestMQTTv5ConnectProperties:
    """MQTT 5.0 CONNECT must carry a Properties section (3.1.2.11)."""

    def test_v5_connect_has_properties_length_after_keep_alive(self):
        auth = MQTTAuthenticator(client_id="oida", protocol_version=5)
        packet = _variable_header(auth._build_connect_packet())

        # 0..1 protocol name length, 2..5 "MQTT", 6 version, 7 flags,
        # 8..9 keep alive, 10 -> properties length varbyte.
        assert packet[:6] == b"\x00\x04MQTT"
        assert packet[6] == 5
        assert packet[8:10] == (60).to_bytes(2, "big")
        assert packet[10] == 0x00, "missing Properties length byte at offset 10"

        # Payload (client id) starts right after the empty properties field.
        assert packet[11:13] == len(b"oida").to_bytes(2, "big")
        assert packet[13:17] == b"oida"

    def test_v311_connect_has_no_properties_field(self):
        auth = MQTTAuthenticator(client_id="oida", protocol_version=4)
        packet = _variable_header(auth._build_connect_packet())

        assert packet[6] == 4
        # Payload starts immediately after keep alive - no properties byte.
        assert packet[10:12] == len(b"oida").to_bytes(2, "big")
        assert packet[12:16] == b"oida"

    def test_v5_remaining_length_accounts_for_properties(self):
        auth = MQTTAuthenticator(client_id="oida", protocol_version=5)
        packet = auth._build_connect_packet()

        assert packet[0] == 0x10
        assert packet[1] == len(packet) - 2  # single-byte remaining length here

    def test_v5_properties_payload_is_fuzzable(self):
        props = b"\x11\x00\x00\x00\x0a"  # Session Expiry Interval = 10
        auth = MQTTAuthenticator(client_id="oida", protocol_version=5, properties=props)
        packet = _variable_header(auth._build_connect_packet())

        assert packet[10] == len(props)
        assert packet[11 : 11 + len(props)] == props
        assert packet[11 + len(props) : 13 + len(props)] == len(b"oida").to_bytes(2, "big")

    def test_v5_properties_ignored_for_v311(self):
        props = b"\x11\x00\x00\x00\x0a"
        auth = MQTTAuthenticator(client_id="oida", protocol_version=4, properties=props)
        packet = _variable_header(auth._build_connect_packet())

        assert packet[10:12] == len(b"oida").to_bytes(2, "big")

    def test_v5_with_credentials_places_properties_before_payload(self):
        auth = MQTTAuthenticator(
            client_id="c", username="user", password="pass", protocol_version=5
        )
        packet = _variable_header(auth._build_connect_packet())

        assert packet[7] & 0x80  # username flag
        assert packet[7] & 0x40  # password flag
        assert packet[10] == 0x00
        body = packet[11:]
        assert body == (b"\x00\x01c" + b"\x00\x04user" + b"\x00\x04pass")


# =============================================================================
# C8 - per-instance RNG instead of global random.seed()
# =============================================================================


@pytest.fixture
def make_fuzzer():
    from oida.fuzz.core.base_fuzzer import BaseFuzzer
    from oida.fuzz.core.config import FuzzerConfig

    class Dummy(BaseFuzzer):
        def _define_protocol(self):
            pass

        def _configure_console_output(self):
            pass

        def _setup_monitor(self):
            class _M:
                def set_monitors(self, monitors):
                    pass

            return _M()

        def _log_monitor_config(self):
            pass

        def _log_capabilities(self):
            pass

    def _make(seed=None):
        config = FuzzerConfig(target_ip="127.0.0.1", target_port=1883, seed=seed)
        return Dummy(config)

    return _make


class TestFuzzerRNGIsolation:
    def test_same_seed_gives_identical_sequences(self, make_fuzzer):
        a = make_fuzzer(seed=1337)
        b = make_fuzzer(seed=1337)

        seq_a = [a.rng.random() for _ in range(10)]
        seq_b = [b.rng.random() for _ in range(10)]
        assert seq_a == seq_b

    def test_different_seeds_diverge(self, make_fuzzer):
        a = make_fuzzer(seed=1)
        b = make_fuzzer(seed=2)
        assert [a.rng.random() for _ in range(5)] != [b.rng.random() for _ in range(5)]

    def test_instances_do_not_interfere(self, make_fuzzer):
        """Interleaved draws from two same-seed fuzzers stay in lockstep."""
        a = make_fuzzer(seed=99)
        b = make_fuzzer(seed=99)
        interleaved_a = []
        interleaved_b = []
        for _ in range(5):
            interleaved_a.append(a.rng.randint(0, 2**32))
            interleaved_b.append(b.rng.randint(0, 2**32))
        assert interleaved_a == interleaved_b

    def test_construction_does_not_perturb_global_random(self, make_fuzzer):
        random.seed(4242)
        expected = [random.random() for _ in range(5)]

        random.seed(4242)
        make_fuzzer(seed=1337)
        actual = [random.random() for _ in range(5)]

        assert actual == expected, "constructing a seeded fuzzer reseeded global random"

    def test_rng_present_without_seed(self, make_fuzzer):
        f = make_fuzzer(seed=None)
        assert isinstance(f.rng, random.Random)
