"""Regression test for CODE_REVIEW.md finding #13.

VRRPv3 (RFC 5798) advertisements dissect as scapy's distinct ``VRRPv3`` layer.
The passive VRRP listener previously matched only the ``VRRP`` (v2) layer, so
v3 advertisements were silently dropped and never reported. This test builds a
real VRRPv3 advertisement and asserts the listener parses and reports it.
"""

import pytest

scapy_vrrp = pytest.importorskip("scapy.layers.vrrp")
VRRPv3 = getattr(scapy_vrrp, "VRRPv3", None)


@pytest.mark.skipif(VRRPv3 is None, reason="installed scapy lacks VRRPv3 layer")
def test_vrrpv3_advertisement_is_reported():
    """A VRRPv3 advertisement must be parsed and reported, not dropped."""
    from scapy.all import IP, Ether

    from oida.protocols.discovery.vrrp import VRRPPassiveListener

    listener = VRRPPassiveListener(interface="eth0", timeout=1)

    pkt = (
        Ether(src="00:00:5e:00:01:07")
        / IP(src="10.0.0.1", dst="224.0.0.18", proto=112)
        / VRRPv3(vrid=7, priority=200, adv=100, addrlist=["10.0.0.254"])
    )

    listener.feed_packet(pkt)

    assert listener.discovered_devices, "VRRPv3 advertisement was silently dropped"
    device = next(iter(listener.discovered_devices.values()))
    assert device.vrrp_data["version"] == 3
    assert device.vrrp_data["vrid"] == 7
    assert device.vrrp_data["priority"] == 200
    assert device.vrrp_data["protocol"] == "VRRPv3"
    assert "10.0.0.254" in device.vrrp_data["virtual_ips"]
    # Master role inferred from observing an advertisement (RFC 5798 6.4.3).
    assert device.vrrp_data["is_master"] is True
