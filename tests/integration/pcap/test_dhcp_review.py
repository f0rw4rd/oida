"""Regression tests for dead tshark field names in the DHCP passive listener.

Two dead-field bugs found in the pcap bug hunt (both verified against the
tshark field registry and reproduced):

1. Option 67 boot-file capture read ``dhcp.option.boot_file_name`` (via the
   pyshark-sanitized literal ``option_boot_file_name``).  That field does not
   exist; tshark's field is ``dhcp.option.bootfile_name`` (no underscore
   between "boot" and "file").  PXE/iPXE Option 67 boot-file overrides -- a
   network-boot attack surface -- were silently dropped.

2. The MAC-type Option 61 client-identifier fallback read
   ``dhcp.option.client_id``, which does not exist; the real field is the bare
   ``dhcp.client_id``.  MAC-type client IDs were never recorded via that path.
"""

import glob
import os

import pytest

from tests.service_gate import require_import, require_service

from .conftest import FIXTURE_DIR, _skip_unless_pyshark

pytestmark = [pytest.mark.integration]


def _feed(pcap_path, use_ek, display_filter="dhcp"):
    import pyshark

    from oida.pcap.dhcp import DHCPPassiveListener

    kwargs = {"input_file": str(pcap_path), "display_filter": display_filter}
    if use_ek:
        kwargs["use_ek"] = True
    cap = pyshark.FileCapture(**kwargs)
    listener = DHCPPassiveListener(interface="lo", timeout=10)
    packets = list(cap)
    try:
        cap.close()
    except Exception:
        pass
    listener.feed_packets(iter(packets))
    return listener


def _write_option67_pcap(path):
    """A DHCP ACK carrying Option 67 (boot file name) = 'pxelinux.0'."""
    scapy_all = require_import("scapy.all")
    pkt = (
        scapy_all.Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")
        / scapy_all.IP(src="192.168.1.1", dst="192.168.1.50")
        / scapy_all.UDP(sport=67, dport=68)
        / scapy_all.BOOTP(
            op=2,
            yiaddr="192.168.1.50",
            siaddr="192.168.1.1",
            chaddr=b"\xaa\xbb\xcc\xdd\xee\xff",
        )
        / scapy_all.DHCP(
            options=[
                ("message-type", "ack"),
                ("server_id", "192.168.1.1"),
                (67, b"pxelinux.0"),
                "end",
            ]
        )
    )
    scapy_all.wrpcap(str(path), [pkt])


class TestDhcpOption67BootFile:
    @pytest.mark.parametrize("use_ek", [False, True])
    def test_option67_boot_file_extracted(self, tmp_path, use_ek):
        _skip_unless_pyshark()
        if use_ek:
            from .conftest import _ek_mode_available

            if not _ek_mode_available:
                require_service("pyshark EK-mode fork not installed")
        pcap = tmp_path / "dhcp_opt67.pcap"
        _write_option67_pcap(pcap)

        listener = _feed(pcap, use_ek=use_ek)
        boot_files = [
            ix.details.get("boot_file")
            for ix in listener.interactions
            if ix.details.get("boot_file")
        ]
        # Before the fix this was empty in both modes (dead field name).
        assert "pxelinux.0" in boot_files, (
            f"Option 67 boot file not captured -- dead tshark field name? got {boot_files}"
        )


class TestDhcpClientIdFallback:
    def _dhcp_fixture(self):
        candidates = sorted(glob.glob(os.path.join(FIXTURE_DIR, "dhcp", "*.pcap")))
        if not candidates:
            require_service("no DHCP fixtures present")
        return candidates

    def test_mac_type_client_id_recorded(self):
        _skip_unless_pyshark()
        # filtered_dhcp.pcap carries a MAC-type Option 61 (dhcp.client_id set,
        # dhcp.client_id.undef empty) -- exactly the case the dead fallback
        # missed.
        found = 0
        for pcap in self._dhcp_fixture():
            listener = _feed(pcap, use_ek=False)
            found += sum(1 for ix in listener.interactions if ix.details.get("client_id"))
        assert found > 0, (
            "no client_id recorded from any DHCP fixture -- the MAC-type Option 61 "
            "fallback field name is dead again"
        )
