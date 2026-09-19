"""PAP passive listener logs harvested credentials -- INTENDED behavior.

OIDA is a credential-harvesting pentest tool: surfacing the ``username:password``
it recovers from a passive capture is a feature, not a leak. TEST_GAP_AUDIT.md
flagged this as a "credential-log-leak" class; the maintainer decision is that it
is intended (see the memory note ``credential-logging-is-intended``), so these
tests pin the harvest-display behavior rather than forbid it.

They ALSO document a real testing pitfall that the audit surfaced: oida's module
loggers set ``propagate=False`` (``ics_logger.py``), so up to pytest 9.0
pytest's ``caplog`` -- which hooks the root logger via propagation -- captured
NOTHING from a listener. pytest 9.1 (#3697) added capture for
non-propagating loggers, so caplog works again; the direct-attach
``capture_module_log`` helper below remains the version-independent shape (see
``test_caplog_cannot_capture_a_module_logger`` for the history).
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

    Version-independent capture for oida module loggers (``propagate=False``):
    caplog was blind to them up to pytest 9.0 and works again from 9.1 (#3697).
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
    """caplog DOES capture a propagate=False logger as of pytest 9.1 (#3697).

    History / guard for future test authors: oida module loggers set
    ``propagate=False`` (ics_logger.py), and up to pytest 9.0 caplog -- which
    hooks the root logger -- captured NOTHING from them, so a caplog-based
    assertion on listener output silently asserted nothing. pytest 9.1
    (logging capture for non-propagating loggers) closed that blind spot and
    inverted this test's premise. Both capture shapes now work:

    * caplog is safe again for listener-log assertions on pytest >= 9.1;
    * the direct-attach ``capture_module_log`` helper stays valid (and stays
      the version-independent shape -- it does not depend on caplog internals).

    The propagate=False property itself (and thus the historical pitfall for
    anything reading the root logger other than caplog) is still pinned by
    test_module_logger_does_not_propagate above.
    """
    listener = PAPPassiveListener(interface="lo", timeout=1)
    secret = "caplog-blind-pw"
    pkt = _FakePAPPacket(peer_id="bob", password=secret)

    with caplog.at_level(logging.INFO):
        listener.process_packet(pkt)

    # pytest >= 9.1: caplog sees non-propagating logger records too.
    assert secret in caplog.text
