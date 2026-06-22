"""Regression tests for IPv6Scanner AsyncSniffer cleanup.

The bug: in both `_send_router_solicitation` and `_ping_multicast` the
AsyncSniffer is started before the send loop and sleep. If anything between
`sniffer.start()` and `sniffer.stop()` raises (e.g. a permission/interface
error mid-loop, or a KeyboardInterrupt which is not caught by `except
Exception`), the sniffer's background capture thread and raw socket were never
torn down, leaking threads and file descriptors across repeated scans.

These tests force the send to raise after `start()` and assert the sniffer is
still stopped (i.e. the `finally` ran).
"""

import sys

import pytest
from unittest.mock import patch


@pytest.fixture
def ipv6_scanner():
    from oida.protocols.discovery.ipv6 import IPv6Scanner

    return IPv6Scanner("eth0", timeout=1)


class _FakeSniffer:
    """Minimal AsyncSniffer stand-in tracking start/stop and `running` state."""

    def __init__(self, *args, **kwargs):
        self.started = False
        self.stopped = False
        self.running = False

    def start(self):
        self.started = True
        self.running = True

    def stop(self):
        self.stopped = True
        self.running = False


def _patched_scapy(fake_sniffer):
    """Patch the scapy.all symbols imported inside the IPv6Scanner methods."""
    scapy_all = sys.modules["scapy.all"]
    return [
        patch.object(scapy_all, "AsyncSniffer", lambda *a, **k: fake_sniffer),
        patch.object(scapy_all, "get_if_hwaddr", lambda iface: "00:11:22:33:44:55"),
    ]


class TestRouterSolicitationSnifferCleanup:
    def test_sniffer_stopped_when_send_raises(self, ipv6_scanner):
        """sniffer.stop() must run even if scapy_sendp raises after start()."""
        fake = _FakeSniffer()
        patches = _patched_scapy(fake)
        for p in patches:
            p.start()
        try:
            with patch(
                "oida.protocols.discovery.ipv6.get_interface_ipv6",
                return_value=["fe80::1"],
            ):
                with patch(
                    "oida.protocols.discovery.ipv6.scapy_sendp",
                    side_effect=OSError("interface vanished"),
                ):
                    # Broad except in the method swallows the OSError; no raise.
                    ipv6_scanner._send_router_solicitation()
        finally:
            for p in patches:
                p.stop()

        assert fake.started is True
        assert fake.stopped is True, "sniffer leaked: stop() not called after send error"
        assert fake.running is False

    def test_sniffer_stopped_on_keyboard_interrupt(self, ipv6_scanner):
        """KeyboardInterrupt (not an Exception) must still trigger cleanup."""
        fake = _FakeSniffer()
        patches = _patched_scapy(fake)
        for p in patches:
            p.start()
        try:
            with patch(
                "oida.protocols.discovery.ipv6.get_interface_ipv6",
                return_value=["fe80::1"],
            ):
                with patch(
                    "oida.protocols.discovery.ipv6.scapy_sendp",
                    side_effect=KeyboardInterrupt,
                ):
                    with pytest.raises(KeyboardInterrupt):
                        ipv6_scanner._send_router_solicitation()
        finally:
            for p in patches:
                p.stop()

        assert fake.started is True
        assert fake.stopped is True, "sniffer leaked on KeyboardInterrupt"

    def test_sniffer_stopped_on_clean_run(self, ipv6_scanner):
        """Happy path still stops the sniffer exactly once."""
        fake = _FakeSniffer()
        patches = _patched_scapy(fake)
        for p in patches:
            p.start()
        try:
            with patch(
                "oida.protocols.discovery.ipv6.get_interface_ipv6",
                return_value=["fe80::1"],
            ):
                with patch("oida.protocols.discovery.ipv6.scapy_sendp"):
                    with patch("oida.protocols.discovery.ipv6.time.sleep"):
                        ipv6_scanner._send_router_solicitation()
        finally:
            for p in patches:
                p.stop()

        assert fake.stopped is True


class TestPingMulticastSnifferCleanup:
    def test_sniffer_stopped_when_send_raises(self, ipv6_scanner):
        """sniffer.stop() must run even if scapy_sendp raises after start()."""
        from oida.protocols.discovery.core import IPV6_ALL_NODES

        fake = _FakeSniffer()
        patches = _patched_scapy(fake)
        for p in patches:
            p.start()
        try:
            with patch(
                "oida.protocols.discovery.ipv6.get_interface_ipv6",
                return_value=["fe80::1"],
            ):
                with patch(
                    "oida.protocols.discovery.ipv6.scapy_sendp",
                    side_effect=OSError("interface vanished"),
                ):
                    ipv6_scanner._ping_multicast(IPV6_ALL_NODES, "all-nodes")
        finally:
            for p in patches:
                p.stop()

        assert fake.started is True
        assert fake.stopped is True, "sniffer leaked: stop() not called after send error"
        assert fake.running is False

    def test_sniffer_stopped_on_keyboard_interrupt(self, ipv6_scanner):
        """KeyboardInterrupt (not an Exception) must still trigger cleanup."""
        from oida.protocols.discovery.core import IPV6_ALL_NODES

        fake = _FakeSniffer()
        patches = _patched_scapy(fake)
        for p in patches:
            p.start()
        try:
            with patch(
                "oida.protocols.discovery.ipv6.get_interface_ipv6",
                return_value=["fe80::1"],
            ):
                with patch(
                    "oida.protocols.discovery.ipv6.scapy_sendp",
                    side_effect=KeyboardInterrupt,
                ):
                    with pytest.raises(KeyboardInterrupt):
                        ipv6_scanner._ping_multicast(IPV6_ALL_NODES, "all-nodes")
        finally:
            for p in patches:
                p.stop()

        assert fake.started is True
        assert fake.stopped is True, "sniffer leaked on KeyboardInterrupt"
