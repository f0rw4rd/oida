"""Regression tests: child contexts must inherit crypto state and sequence managers.

``StateContext.create_child()`` is documented as a scoped view of its parent --
``get()`` and ``get_response()`` both fall back to the parent. Crypto state and
sequence managers did not: a child minted a fresh ``CryptoStateManager`` and a
fresh ``SequenceManager`` on first access. On a live connection that meant a
nested state restarted its sequence counter at zero (re-sending numbers the peer
had already seen) and saw empty nonces, keys and session tokens, with no error
to say the session material had been dropped.
"""

from oida.fuzz.core.session.sequence import SequenceConfig
from oida.fuzz.core.session.state_context import StateContext


def test_child_shares_parent_sequence_manager():
    parent = StateContext()
    parent.get_sequence_manager("tx").add_sequence(SequenceConfig(name="msg_id"))
    parent.get_sequence_manager("tx").get_and_increment("msg_id")
    parent.get_sequence_manager("tx").get_and_increment("msg_id")

    child = parent.create_child()

    # The counter continues instead of restarting at zero.
    assert child.get_sequence_manager("tx") is parent.get_sequence_manager("tx")
    assert child.get_sequence_manager("tx").get_and_increment("msg_id") == 2


def test_child_sees_parent_sequence_manager_existence():
    parent = StateContext()
    parent.get_sequence_manager("tx")

    child = parent.create_child()

    assert child.has_sequence_manager("tx") is True
    assert child.has_sequence_manager("other") is False


def test_child_shares_parent_crypto_state():
    parent = StateContext()
    parent.crypto.set_nonce("channel", b"\x01\x02\x03\x04")

    child = parent.create_child()

    assert child.crypto is parent.crypto
    assert child.crypto.get_nonce("channel") == b"\x01\x02\x03\x04"


def test_child_reports_inherited_crypto_state():
    parent = StateContext()
    child = parent.create_child()

    assert child.has_crypto_state() is False

    parent.crypto  # materialise it on the parent

    assert child.has_crypto_state() is True


def test_root_context_still_creates_its_own_state():
    root = StateContext()

    assert root.has_crypto_state() is False
    assert root.crypto is root.crypto
    assert root.has_crypto_state() is True
    assert root.get_sequence_manager("tx") is root.get_sequence_manager("tx")
