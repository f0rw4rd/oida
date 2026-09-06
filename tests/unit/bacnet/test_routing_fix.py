"""BAC0 vs bacpypes3 dispatch must follow real RFC 1918, not '172.' prefix.

Old code: any host starting with '172.' was treated as local. RFC 1918
only defines 172.16.0.0/12 (172.16 - 172.31) as private. Hosts in
172.0-172.15 and 172.32-172.255 are PUBLIC and were misrouted to the
BAC0 broadcast path which can't reach them. CODE_REVIEW.md HIGH.
"""

import ipaddress
import unittest


def _is_local(host: str) -> bool:
    """Mirror of the patched logic in bacnet/nxc_connection.py."""
    local_hosts = ("255.255.255.255", "127.0.0.1", "localhost")
    if host in local_hosts:
        return True
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


class TestBacnetHostClassification(unittest.TestCase):
    def test_rfc1918_private_ranges_are_local(self):
        for ip in (
            "10.0.0.1", "10.255.255.254",
            "172.16.0.1", "172.31.255.254",
            "192.168.0.1", "192.168.255.254",
            "127.0.0.1",
        ):
            self.assertTrue(_is_local(ip), f"{ip} must be local")

    def test_172_block_outside_rfc1918_is_remote(self):
        """The historical bug: 172.5.5.5 and 172.32.0.1 are PUBLIC."""
        for ip in ("172.5.5.5", "172.15.0.1", "172.32.0.1", "172.99.99.99"):
            self.assertFalse(_is_local(ip), f"{ip} must be remote (public)")

    def test_loopback_and_broadcast(self):
        self.assertTrue(_is_local("127.0.0.1"))
        self.assertTrue(_is_local("255.255.255.255"))
        self.assertTrue(_is_local("localhost"))

    def test_public_v4_routes_remote(self):
        # Avoid 203.0.113.0/24 — TEST-NET-3 is marked private by ipaddress.
        for ip in ("8.8.8.8", "1.1.1.1", "9.9.9.9"):
            self.assertFalse(_is_local(ip), f"{ip} must be remote")

    def test_hostnames_route_remote_by_default(self):
        """Hostnames (no IP) should NOT silently go through BAC0."""
        self.assertFalse(_is_local("example.com"))


if __name__ == "__main__":
    unittest.main()
