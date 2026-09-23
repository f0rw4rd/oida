"""Regression test for the KNXScanner logger-init bug.

KNXScanner.__init__ used to unconditionally overwrite the logger that
BaseScanner.__init__ established via _init_logger() with the ``logger``
parameter, which defaults to None. The factory run() path instantiates the
scanner as ``scanner_class(args)`` WITHOUT a logger, so self.logger became None and
the first ``self.logger.debug(...)`` in connect() raised AttributeError.
"""

from oida.protocols.knx.scanner import KNXScanner


def test_factory_run_path_keeps_base_logger():
    """No-logger instantiation (the factory run() path) must not
    clobber the base-class logger with None."""
    scanner = KNXScanner({"host": "10.0.0.5", "port": 3671})

    assert scanner.logger is not None
    # The base logger is a real ICSLogger exposing the NXC-style methods that
    # connect()/discover() call immediately.
    assert callable(scanner.logger.debug)
    # This call would raise AttributeError on a None logger.
    scanner.logger.debug("logger is usable")


def test_explicit_logger_still_overrides():
    """An explicitly passed logger must still win over the base logger."""

    class Sentinel:
        def debug(self, *a, **k):
            pass

    sentinel = Sentinel()
    scanner = KNXScanner({"host": "10.0.0.5", "port": 3671}, logger=sentinel)
    assert scanner.logger is sentinel
