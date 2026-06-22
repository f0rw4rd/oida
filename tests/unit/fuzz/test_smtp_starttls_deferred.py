"""Regression tests for SMTP STARTTLS deferred-execution wiring.

Covers the MEDIUM finding that ``_create_smtp_starttls_state_machine`` drove the
EHLO/STARTTLS/TLS-handshake transition sequence during ``_define_state_machine``
(which base_fuzzer runs at session-creation time, *before* the fuzz loop opens
the target connection). The setup callbacks then hit
``self.session.targets[0]._target_connection`` on a connection that was not yet
open and the ``except`` re-raised, aborting STARTTLS fuzzing entirely against
real targets.

The fix defers the STARTTLS sequence to ``fuzz_all()`` and runs the handshake
over the dedicated ``_get_auth_socket()`` (mirroring the auth path).

These tests fail against the eager implementation and pass after the fix.
"""

from unittest.mock import patch

import pytest


def _make_starttls_fuzzer(use_auth=False):
    """Build an SMTPFuzzer with use_starttls=True over a *real* (non-mock)
    connection factory so the (previously eager) STARTTLS block is in scope.
    """
    from src.oida.fuzz.core.config import FuzzerConfig, ProtocolType
    from src.oida.fuzz.protocols.smtp import SMTPFuzzer

    config = FuzzerConfig(
        target_ip="192.0.2.10",
        target_port=587,
        protocol_type=ProtocolType.TCP,
    )
    config.protocol_options = {"use_starttls": True, "use_auth": use_auth}

    # connection_factory=None -> RealConnectionFactory (NOT a MockConnectionFactory),
    # which is exactly the case that triggered the eager-execution bug.
    fuzzer = SMTPFuzzer(config, connection_factory=None)
    return fuzzer


def test_define_state_machine_does_not_drive_starttls():
    """_define_state_machine must build the machine WITHOUT executing any
    STARTTLS transition (connection is not open yet at session-creation time).
    """
    fuzzer = _make_starttls_fuzzer()

    # Spy on the setup callbacks. Before the fix these were invoked during
    # _define_state_machine() (and touched an unopened socket / raised).
    with (
        patch.object(fuzzer, "_send_ehlo", return_value=True) as send_ehlo,
        patch.object(fuzzer, "_send_starttls", return_value=True) as send_starttls,
        patch.object(fuzzer, "_perform_ssl_handshake", return_value=True) as ssl_hs,
        patch.object(fuzzer, "_validate_tls_connection", return_value=True),
    ):
        # Must not raise (old code re-raised when the socket wasn't open).
        fuzzer._define_state_machine()

        # No transition callback fired during session-machine definition.
        assert send_ehlo.call_count == 0
        assert send_starttls.call_count == 0
        assert ssl_hs.call_count == 0

    # State machine exists and is still parked at the initial CONNECTED state.
    assert fuzzer.state_machine is not None
    assert fuzzer.state_machine.get_current_state_name() == "CONNECTED"


def test_run_starttls_sequence_drives_transitions():
    """The deferred _run_starttls_sequence() must execute the full upgrade
    sequence, invoking the setup callbacks and reaching EHLO_TLS_SENT.
    """
    fuzzer = _make_starttls_fuzzer()

    with (
        patch.object(fuzzer, "_send_ehlo", return_value=True) as send_ehlo,
        patch.object(fuzzer, "_send_starttls", return_value=True) as send_starttls,
        patch.object(fuzzer, "_perform_ssl_handshake", return_value=True) as ssl_hs,
        patch.object(fuzzer, "_validate_tls_connection", return_value=True),
    ):
        fuzzer._define_state_machine()
        fuzzer._run_starttls_sequence()

        # EHLO fires twice (initial + re-sent over TLS), STARTTLS + handshake once each.
        assert send_ehlo.call_count == 2
        assert send_starttls.call_count == 1
        assert ssl_hs.call_count == 1

    assert fuzzer.state_machine.get_current_state_name() == "EHLO_TLS_SENT"


def test_fuzz_all_defers_starttls_until_connection_ready():
    """fuzz_all() must drive the STARTTLS sequence (over the dedicated socket)
    and then close it, rather than relying on session-creation-time execution.
    """
    fuzzer = _make_starttls_fuzzer()

    with (
        patch.object(fuzzer, "_send_ehlo", return_value=True),
        patch.object(fuzzer, "_send_starttls", return_value=True),
        patch.object(fuzzer, "_perform_ssl_handshake", return_value=True),
        patch.object(fuzzer, "_validate_tls_connection", return_value=True),
    ):
        fuzzer._define_state_machine()

        with (
            patch.object(fuzzer, "_run_starttls_sequence") as run_seq,
            patch.object(fuzzer, "_close_auth_socket") as close_sock,
            patch("src.oida.fuzz.core.base_fuzzer.BaseFuzzer.fuzz_all") as super_fuzz_all,
        ):
            fuzzer.fuzz_all()

            run_seq.assert_called_once()
            close_sock.assert_called_once()
            super_fuzz_all.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
