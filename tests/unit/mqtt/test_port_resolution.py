"""Unit coverage for mqtt._resolve_default_port().

Regression guard: `--tls -p 1883` must be honored (not silently rewritten to
8883). The port default is None (unset) so proto_flow can tell an explicit
`-p 1883` from the old default; resolution then fills in only an unset port.
"""

import argparse

from oida.protocols.mqtt.cli_runner import mqtt


class _NullLogger:
    def debug(self, *a, **k):
        pass


def _resolve(port, tls):
    """Run _resolve_default_port on a bare mqtt instance (no scan)."""
    obj = mqtt.__new__(mqtt)
    obj.default_port = 1883
    obj.logger = _NullLogger()
    obj.args = argparse.Namespace(port=port, tls=tls)
    obj._resolve_default_port()
    return obj.args.port


class TestResolveDefaultPort:
    def test_unset_plaintext_defaults_1883(self):
        assert _resolve(port=None, tls=False) == 1883

    def test_unset_tls_defaults_8883(self):
        assert _resolve(port=None, tls=True) == 8883

    def test_explicit_1883_with_tls_is_honored(self):
        # The bug: this used to be forced to 8883.
        assert _resolve(port=1883, tls=True) == 1883

    def test_explicit_8883_without_tls_is_honored(self):
        assert _resolve(port=8883, tls=False) == 8883

    def test_explicit_nondefault_port_is_honored(self):
        assert _resolve(port=1884, tls=False) == 1884
