"""OPC UA fuzzer use_session client-lifecycle regression test.

Covers: in use_session mode the fuzzer extracts the
live SecureChannelId/TokenId/AuthToken from an asyncua client, then must keep
that client connected for the duration of fuzzing. Disconnecting before the
channel/token is consumed invalidates the session server-side and silently
defeats authenticated fuzzing.

These tests assert:
  1. _define_state_machine() does NOT disconnect the asyncua client while
     extracting the channel/token (the client stays alive).
  2. fuzz_all() disconnects the client only AFTER the fuzz body runs, and the
     live token is still installed while fuzzing executes.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from oida.fuzz.core.config import FuzzerConfig

pytestmark = pytest.mark.core


def _make_fuzzer():
    """Build an OPCUAFuzzer with use_session enabled and console output off."""
    from oida.fuzz.protocols.opcua import OPCUAFuzzer

    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=4840,
        protocol_options={"use_session": True},
    )
    config.log_session = False
    config.console_output = False
    config.skip_pre_send_checks = True
    return OPCUAFuzzer(config)


def _make_mock_client():
    """An asyncua Client double exposing the internals _define_state_machine reads."""
    client = MagicMock(name="asyncua.Client")
    client.connect = AsyncMock(name="connect")
    client.disconnect = AsyncMock(name="disconnect")

    conn = MagicMock(name="SecureConnection")
    conn.security_token.ChannelId = 4242
    conn.security_token.TokenId = 99
    conn.remote_nonce = b"\x01\x02\x03\x04"

    protocol = MagicMock(name="protocol")
    protocol._connection = conn
    protocol.authentication_token = b"live-auth-token"

    client.uaclient.protocol = protocol
    return client


def test_state_machine_keeps_client_connected():
    """_define_state_machine must extract the channel/token WITHOUT disconnecting.

    Before the fix the asyncua client was disconnected in a finally block right
    after extraction, invalidating the channel/token; this asserts it stays live.
    """
    fuzzer = _make_fuzzer()
    client = _make_mock_client()

    with patch("asyncua.Client", return_value=client):
        fuzzer._define_state_machine()

    # Channel/token were extracted...
    assert fuzzer.secure_channel_id == 4242
    assert fuzzer.token_id == 99
    assert fuzzer.auth_token == b"live-auth-token"

    # ...and the client is still connected (NOT torn down during setup).
    client.connect.assert_awaited_once()
    client.disconnect.assert_not_awaited()
    assert fuzzer._asyncua_client is client
    assert fuzzer._asyncua_loop is not None


def test_fuzz_all_disconnects_after_fuzzing_with_live_token():
    """fuzz_all() must run the fuzz body with the live token, THEN disconnect.

    Records ordering: the asyncua client must remain connected (token still the
    live one) for the entire super().fuzz_all() body, and disconnect only after.
    """
    fuzzer = _make_fuzzer()
    client = _make_mock_client()

    with patch("asyncua.Client", return_value=client):
        fuzzer._define_state_machine()

    events = []

    def fake_fuzz_all(self):
        # During the fuzz body the channel/token must still be the live ones
        # and the client must NOT yet be disconnected.
        client.disconnect.assert_not_awaited()
        events.append(("fuzz", self.auth_token, self.secure_channel_id))

    client.disconnect.side_effect = lambda *a, **k: events.append(("disconnect",))

    with patch("oida.fuzz.core.base_fuzzer.BaseFuzzer.fuzz_all", fake_fuzz_all):
        fuzzer.fuzz_all()

    # Fuzz body ran with the live token, then the client was disconnected once,
    # in that order.
    assert events == [
        ("fuzz", b"live-auth-token", 4242),
        ("disconnect",),
    ]
    client.disconnect.assert_awaited_once()
    # Teardown is idempotent and clears the kept-alive references.
    assert fuzzer._asyncua_client is None
    assert fuzzer._asyncua_loop is None
