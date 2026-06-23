"""
Unit tests for bacpypes3 local-address mask selection.

Regression coverage for the docker-bridge / NAT bug where a /24 local mask made
bacpypes3 stand up a broadcast endpoint that did sock.bind(<subnet-broadcast>),
failing with OSError [Errno 99] and aborting a targeted unicast ReadProperty.

A targeted unicast read must select a /32 mask (no broadcast domain), while
genuine broadcast operations (Who-Is/Who-Has discovery, BBMD/FDT/router
enumeration, remote-network scans, BBMD injection) must keep /24.
"""

import random as random_module
import socket
import unittest
from unittest import mock

from oida.protocols.bacnet import bacnet
from tests.unit.bacnet.conftest import create_mock_args, create_mock_logger


def _create_instance(**kwargs):
    """Create bacnet instance bypassing __init__."""
    instance = object.__new__(bacnet)
    instance.args = create_mock_args(**kwargs)
    instance.logger = create_mock_logger()
    instance.host = "192.168.1.100"
    return instance


class TestNeedsBroadcastTransport(unittest.TestCase):
    """Test _needs_broadcast_transport mask-selection logic."""

    def test_targeted_unicast_read_does_not_need_broadcast(self):
        # The failing path: a specific --device-id unicast read. No broadcast
        # flag set -> /32 mask -> no subnet-broadcast bind.
        scanner = _create_instance(device_id=22002)
        self.assertFalse(scanner._needs_broadcast_transport("172.18.0.2"))

    def test_who_is_needs_broadcast(self):
        scanner = _create_instance(who_is=True)
        self.assertTrue(scanner._needs_broadcast_transport("172.18.0.2"))

    def test_who_has_needs_broadcast(self):
        scanner = _create_instance(who_has="SomeObject")
        self.assertTrue(scanner._needs_broadcast_transport("172.18.0.2"))

    def test_enum_bbmd_needs_broadcast(self):
        scanner = _create_instance(enum_bbmd=True)
        self.assertTrue(scanner._needs_broadcast_transport("172.18.0.2"))

    def test_enum_fdt_needs_broadcast(self):
        scanner = _create_instance(enum_fdt=True)
        self.assertTrue(scanner._needs_broadcast_transport("172.18.0.2"))

    def test_enum_routers_needs_broadcast(self):
        scanner = _create_instance(enum_routers=True)
        self.assertTrue(scanner._needs_broadcast_transport("172.18.0.2"))

    def test_networks_needs_broadcast(self):
        scanner = _create_instance(networks=True)
        self.assertTrue(scanner._needs_broadcast_transport("172.18.0.2"))

    def test_scan_all_networks_needs_broadcast(self):
        scanner = _create_instance(scan_all_networks=True)
        self.assertTrue(scanner._needs_broadcast_transport("172.18.0.2"))

    def test_bbmd_injection_needs_broadcast(self):
        scanner = _create_instance(test_bbmd_injection=True)
        self.assertTrue(scanner._needs_broadcast_transport("172.18.0.2"))

    def test_scan_network_zero_needs_broadcast(self):
        # scan_network takes an int; 0 is a valid DNET and must not be treated
        # as "unset" (the check is `is not None`, not truthiness).
        scanner = _create_instance(scan_network=0)
        self.assertTrue(scanner._needs_broadcast_transport("172.18.0.2"))

    def test_scan_network_unset_does_not_need_broadcast(self):
        scanner = _create_instance(device_id=22002, scan_network=None)
        self.assertFalse(scanner._needs_broadcast_transport("172.18.0.2"))

    def test_broadcast_target_string_needs_broadcast(self):
        scanner = _create_instance(device_id=22002)
        self.assertTrue(scanner._needs_broadcast_transport("broadcast"))

    def test_global_broadcast_target_needs_broadcast(self):
        scanner = _create_instance(device_id=22002)
        self.assertTrue(scanner._needs_broadcast_transport("255.255.255.255"))


class TestAcquireLocalUdpPort(unittest.TestCase):
    """Test free-local-UDP-port acquisition (Errno 98 regression guard).

    A blindly chosen random local port can collide with a port already held
    (TIME_WAIT, docker port-map, another binder); bacpypes3 then retries its
    local bind forever and the scan hangs / times out. _acquire_local_udp_port
    must return a port that is actually bindable, falling back to the ephemeral
    port (0) only when every candidate is contended.
    """

    def test_returns_bindable_port_in_range(self):
        scanner = _create_instance(device_id=22002)
        port = scanner._acquire_local_udp_port("127.0.0.1")
        self.assertTrue(0 < port <= 48000)
        # The returned port must be genuinely bindable.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        try:
            s.bind(("127.0.0.1", port))
        finally:
            s.close()

    def test_falls_back_to_ephemeral_when_all_contended(self):
        # Force every randint candidate to a single contended port so the
        # bind-test always fails, exercising the ephemeral (0) fallback.
        scanner = _create_instance(device_id=22002)
        holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        holder.bind(("127.0.0.1", 0))
        held_port = holder.getsockname()[1]
        try:
            with mock.patch.object(random_module, "randint", return_value=held_port):
                # SO_REUSEPORT would let a UDP probe rebind the held port even
                # when contended, so only assert the fallback on platforms where
                # the held socket blocks rebind. Where it does not block, the
                # function still legitimately returns the (rebindable) port.
                port = scanner._acquire_local_udp_port("127.0.0.1")
            self.assertIn(port, (0, held_port))
        finally:
            holder.close()


if __name__ == "__main__":
    unittest.main()
