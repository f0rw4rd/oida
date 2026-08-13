"""Reproduction for the credential-log-leak gap class (TEST_GAP_AUDIT.md).

The passive PAP listener writes the harvested cleartext ``username:password`` to
its INFO log stream (``pap.py``). The whole class was invisible to the test suite
because NO test inspects what a listener logs -- and the obvious tool, pytest's
``caplog``, is silently defeated: ``get_module_logger()`` sets
``propagate=False`` (``ics_logger.py``), so records never reach the root logger
``caplog`` listens on, and a caplog-based leak assertion passes falsely.

This file proves both halves against real behavior:
  * ``capture_module_log`` attaches a handler DIRECTLY to the module logger and
    sees the emitted secret (the leak is real);
  * ``caplog`` does NOT see it (the trap that hid the class).

``capture_module_log`` is the seed of the reusable fixture the audit recommends
for a parametrized ``tests/contracts/test_no_credential_log_leak.py`` sweep.

NOTE ON INTENT: OIDA is a credential-harvesting pentest tool, so *displaying*
harvested creds may be intended. These are CHARACTERIZATION tests -- they pin
what the listener does today, not a policy that it must never log a secret. Flip
the ``assert secret in ...`` to ``assert secret not in ...`` only once a
redaction/masking behavior is decided.
"""

import logging
from contextlib import contextmanager

from oida.pcap.pap import PAPPassiveListener


class _Layer:
    """Attribute-only stand-in for a pyshark layer (get_field is plain getattr)."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakePAPPacket:
    """A PAP Authenticate-Request packet (eth + pap), no pyshark/tshark needed."""

    def __init__(self, *, peer_id, password, code="1", identifier="7", length="12"):
        self.eth = _Layer(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")
        self.pap = _Layer(
            code=code,
            identifier=identifier,
            peer_id=peer_id,
            password=password,
            length=length,
        )


class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


@contextmanager
def capture_module_log(logger, level=logging.INFO):
    """Capture records emitted by ``logger`` by attaching a handler to it directly.

    Do NOT use pytest ``caplog`` for oida module loggers: they set
    ``propagate=False``, so their records never reach the root logger caplog
    hooks -- caplog would capture nothing and any ``secret not in caplog.text``
    assertion would pass without testing anything.
    """
    handler = _ListHandler()
    handler.setLevel(level)
    logger.addHandler(handler)
    prev_level = logger.level
    # level 0 (NOTSET) or a coarser threshold would drop our records.
    if logger.level == logging.NOTSET or logger.level > level:
        logger.setLevel(level)
    try:
        yield handler.records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(prev_level)


def _messages(records, min_level=logging.INFO):
    return "\n".join(r.getMessage() for r in records if r.levelno >= min_level)


def test_pap_listener_emits_cleartext_password_at_info():
    """The listener writes the harvested cleartext password to INFO."""
    listener = PAPPassiveListener(interface="lo", timeout=1)
    secret = "s3cr3t-pap-pw"
    pkt = _FakePAPPacket(peer_id="admin", password=secret)

    with capture_module_log(listener.logger) as records:
        listener.process_packet(pkt)

    logged = _messages(records)
    assert secret in logged, f"expected cleartext password in INFO log; got: {logged!r}"
    assert "admin" in logged
    # Sanity: the credential was actually harvested (not a false-positive path).
    assert any(c.password == secret for c in listener.credentials)


def test_module_logger_does_not_propagate():
    """The mechanism that defeats caplog: module loggers do not propagate.

    This is why a naive ``caplog``-based leak test passes falsely and the whole
    credential-log-leak class stayed invisible.
    """
    listener = PAPPassiveListener(interface="lo", timeout=1)
    assert listener.logger.propagate is False


def test_caplog_silently_misses_the_leak(caplog):
    """Demonstration of the trap: caplog sees nothing even though a secret leaks.

    Characterization only -- asserts the CURRENT (broken-for-testing) behavior so
    a future reader understands why direct-attach capture is mandatory here.
    """
    listener = PAPPassiveListener(interface="lo", timeout=1)
    secret = "caplog-blind-pw"
    pkt = _FakePAPPacket(peer_id="bob", password=secret)

    with caplog.at_level(logging.INFO):
        listener.process_packet(pkt)

    # Proven leaking via direct attach in the test above; caplog cannot see it.
    assert secret not in caplog.text
