"""PAP passive listener logs harvested credentials -- INTENDED behavior.

OIDA is a credential-harvesting pentest tool: surfacing the ``username:password``
it recovers from a passive capture is a feature, not a leak. TEST_GAP_AUDIT.md
flagged this as a "credential-log-leak" class; the maintainer decision is that it
is intended (see the memory note ``credential-logging-is-intended``), so these
tests pin the harvest-display behavior rather than forbid it.

They ALSO document a real testing pitfall that the audit surfaced: oida's module
loggers set ``propagate=False`` (``ics_logger.py``), so pytest's ``caplog`` --
which listens on the root logger via propagation -- captures NOTHING from a
listener. Any future test that needs to inspect what a listener logs (for any
reason) must attach a handler DIRECTLY to the module logger, as
``capture_module_log`` does here; a ``caplog``-based assertion would pass without
testing anything.
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
    hooks -- caplog would capture nothing and the assertion would be vacuous.
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


def test_pap_listener_surfaces_harvested_password_at_info():
    """The listener surfaces the harvested cleartext credential at INFO (feature)."""
    listener = PAPPassiveListener(interface="lo", timeout=1)
    secret = "s3cr3t-pap-pw"
    pkt = _FakePAPPacket(peer_id="admin", password=secret)

    with capture_module_log(listener.logger) as records:
        listener.process_packet(pkt)

    logged = _messages(records)
    assert secret in logged, f"expected harvested password in INFO log; got: {logged!r}"
    assert "admin" in logged
    # Sanity: the credential was actually harvested (not a false-positive path).
    assert any(c.password == secret for c in listener.credentials)


def test_module_logger_does_not_propagate():
    """Module loggers set propagate=False -- the reason caplog can't see them."""
    listener = PAPPassiveListener(interface="lo", timeout=1)
    assert listener.logger.propagate is False


def test_caplog_cannot_capture_a_module_logger(caplog):
    """caplog captures nothing from a listener (propagate=False) -- the pitfall.

    Guards future test authors: inspecting listener output requires a
    direct-attach handler (capture_module_log), never caplog.
    """
    listener = PAPPassiveListener(interface="lo", timeout=1)
    secret = "caplog-blind-pw"
    pkt = _FakePAPPacket(peer_id="bob", password=secret)

    with caplog.at_level(logging.INFO):
        listener.process_packet(pkt)

    # Emitted (proven via direct attach above) but invisible to caplog.
    assert secret not in caplog.text
