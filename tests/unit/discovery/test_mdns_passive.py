"""
Behavioral tests for the scapy-based passive mDNS listener
(``oida.protocols.discovery.mdns.MDNSPassiveListener``) and the
DNS-SD active scanner's service-handling path.

Real scapy DNS packets are crafted and fed through ``feed_packet`` /
``_process_packet`` so the answer-record dispatch (A / AAAA / PTR / SRV / TXT)
and querier tracking all run for real. Only sniffer I/O is avoided by using
the direct-feed test hook.
"""

import threading
from unittest.mock import MagicMock, patch

from tests.service_gate import require_import

from oida.protocols.discovery.mdns import (
    MDNS_PORT,
    DNSSDScanner,
    MDNSPassiveListener,
    MDNSScanner,
)

scapy = require_import("scapy", reason="scapy not installed")


# ---------------------------------------------------------------------------
# scapy packet builders
# ---------------------------------------------------------------------------


def _answer_packet(answers, src_ip="192.168.1.55", src_mac="de:ad:be:ef:00:01", v6=False):
    """Build an mDNS response packet carrying one or more DNS answer records."""
    from scapy.all import DNS, IP, IPv6, UDP, Ether

    ancount = len(answers)
    an = None
    for rr in answers:
        an = rr if an is None else an / rr
    dns = DNS(qr=1, ancount=ancount, an=an)
    ip_layer = IPv6(src=src_ip) if v6 else IP(src=src_ip)
    return Ether(src=src_mac) / ip_layer / UDP(sport=MDNS_PORT, dport=MDNS_PORT) / dns


def _query_packet(qname, src_ip="192.168.1.57", src_mac="de:ad:be:ef:00:03"):
    """Build an mDNS query packet (used by the querier-tracking path)."""
    from scapy.all import DNS, DNSQR, IP, UDP, Ether

    q = DNSQR(qname=qname, qtype="PTR")
    # ancount must be explicitly 0 - None would raise inside _process_packet.
    dns = DNS(qr=0, qdcount=1, ancount=0, qd=q)
    return Ether(src=src_mac) / IP(src=src_ip) / UDP(sport=MDNS_PORT, dport=MDNS_PORT) / dns


def _make_listener():
    listener = MDNSPassiveListener.__new__(MDNSPassiveListener)
    listener.interface = "eth0"
    listener.timeout = 30
    listener.discovered_devices = {}
    listener.services = {}
    listener._lock = threading.Lock()
    return listener


# ===========================================================================
# A / AAAA record handling
# ===========================================================================


class TestMDNSPassiveAddressRecords:
    def test_a_record_creates_device_keyed_by_mac(self):
        from scapy.all import DNSRR

        listener = _make_listener()
        rr = DNSRR(rrname="printer.local.", type="A", rdata="192.168.1.55")
        listener.feed_packet(_answer_packet([rr], src_mac="de:ad:be:ef:00:01"))

        assert "de:ad:be:ef:00:01" in listener.discovered_devices
        dev = listener.discovered_devices["de:ad:be:ef:00:01"]
        assert dev.name == "printer.local"
        assert dev.ip_addresses == ["192.168.1.55"]
        assert dev.mac_address == "de:ad:be:ef:00:01"
        assert dev.mdns_data["hostname"] == "printer.local"
        assert dev.mdns_data["protocol"] == "mDNS/UDP"
        assert "mdns-passive" in dev.discovered_by

    def test_aaaa_record_sets_ipv6_flag(self):
        from scapy.all import DNSRR

        listener = _make_listener()
        rr = DNSRR(rrname="host6.local.", type="AAAA", rdata="fe80::1")
        listener.feed_packet(
            _answer_packet([rr], src_ip="fe80::abcd", src_mac="de:ad:be:ef:00:04", v6=True)
        )

        dev = listener.discovered_devices["de:ad:be:ef:00:04"]
        assert dev.name == "host6.local"
        assert dev.ip_addresses == ["fe80::1"]
        assert dev.mdns_data["ipv6"] is True

    def test_a_record_repeated_updates_last_seen(self):
        from scapy.all import DNSRR

        listener = _make_listener()
        rr = DNSRR(rrname="dev.local.", type="A", rdata="192.168.1.60")
        listener.feed_packet(_answer_packet([rr], src_mac="aa:aa:aa:aa:aa:aa"))
        first = listener.discovered_devices["aa:aa:aa:aa:aa:aa"].first_seen
        listener.feed_packet(_answer_packet([rr], src_mac="aa:aa:aa:aa:aa:aa"))
        assert len(listener.discovered_devices) == 1
        assert listener.discovered_devices["aa:aa:aa:aa:aa:aa"].first_seen == first


# ===========================================================================
# PTR / SRV / TXT service records
# ===========================================================================


class TestMDNSPassiveServiceRecords:
    def test_ptr_record_registers_service(self):
        from scapy.all import DNSRR

        listener = _make_listener()
        rr = DNSRR(rrname="_http._tcp.local.", type="PTR", rdata="Web._http._tcp.local.")
        listener.feed_packet(_answer_packet([rr]))

        assert "Web._http._tcp.local" in listener.services
        svc = listener.services["Web._http._tcp.local"]
        assert svc["type"] == "_http._tcp.local"
        assert svc["src_ip"] == "192.168.1.55"

    def test_srv_record_augments_existing_service(self):
        # The PTR comes off the wire; SRV structured fields (port/target) are
        # dropped by scapy on re-assembly, so the SRV record is fed straight
        # into the (real) handler with the fields a parsed SRV would carry.
        from scapy.all import DNSRR

        listener = _make_listener()
        ptr = DNSRR(rrname="_ipp._tcp.local.", type="PTR", rdata="Printer._ipp._tcp.local.")
        listener.feed_packet(_answer_packet([ptr]))
        assert "Printer._ipp._tcp.local" in listener.services

        srv = DNSRR(rrname="Printer._ipp._tcp.local.", type="SRV")
        srv.port = 631
        srv.target = b"host.local."
        listener._handle_srv_record("Printer._ipp._tcp.local.", srv, "192.168.1.55")

        svc = listener.services["Printer._ipp._tcp.local"]
        assert svc.get("port") == 631
        assert svc.get("target") == "host.local"

    def test_txt_record_augments_existing_service(self):
        from scapy.all import DNSRR

        listener = _make_listener()
        ptr = DNSRR(rrname="_http._tcp.local.", type="PTR", rdata="API._http._tcp.local.")
        listener.feed_packet(_answer_packet([ptr]))

        txt = DNSRR(rrname="API._http._tcp.local.", type="TXT")
        txt.rdata = [b"path=/api", b"v=2"]
        listener._handle_txt_record("API._http._tcp.local.", txt, "192.168.1.55")

        svc = listener.services["API._http._tcp.local"]
        assert "txt" in svc
        assert "path=/api" in svc["txt"]

    def test_srv_without_prior_ptr_is_noop(self):
        from scapy.all import DNSRR

        listener = _make_listener()
        srv = DNSRR(rrname="Orphan._x._tcp.local.", type="SRV")
        srv.port = 8080
        srv.target = b"h.local."
        listener._handle_srv_record("Orphan._x._tcp.local.", srv, "1.2.3.4")
        # No matching service entry -> nothing recorded, no crash.
        assert listener.services == {}


# ===========================================================================
# Querier tracking + dispatch guards
# ===========================================================================


class TestMDNSPassiveQuerierAndGuards:
    def test_query_packet_tracks_querier(self):
        listener = _make_listener()
        listener.feed_packet(_query_packet("_workstation._tcp.local.", src_mac="de:ad:be:ef:00:03"))

        assert "de:ad:be:ef:00:03" in listener.discovered_devices
        dev = listener.discovered_devices["de:ad:be:ef:00:03"]
        assert dev.mdns_data["querier"] is True
        assert dev.ip_addresses == ["192.168.1.57"]

    def test_packet_without_mac_falls_back_to_ip_key(self):
        from scapy.all import DNS, DNSRR, IP, UDP

        listener = _make_listener()
        rr = DNSRR(rrname="nomac.local.", type="A", rdata="192.168.1.70")
        # No Ether layer -> src_mac empty -> device keyed by mdns:<ip>
        pkt = (
            IP(src="192.168.1.70")
            / UDP(sport=MDNS_PORT, dport=MDNS_PORT)
            / DNS(qr=1, ancount=1, an=rr)
        )
        listener.feed_packet(pkt)
        assert "mdns:192.168.1.70" in listener.discovered_devices

    def test_non_mdns_port_ignored(self):
        from scapy.all import DNS, DNSRR, IP, UDP, Ether

        listener = _make_listener()
        rr = DNSRR(rrname="x.local.", type="A", rdata="1.2.3.4")
        pkt = (
            Ether(src="00:00:00:00:00:01")
            / IP(src="1.2.3.4")
            / UDP(sport=12345, dport=80)
            / DNS(qr=1, ancount=1, an=rr)
        )
        listener.feed_packet(pkt)
        assert listener.discovered_devices == {}

    def test_packet_without_dns_layer_ignored(self):
        from scapy.all import IP, UDP, Raw, Ether

        listener = _make_listener()
        pkt = (
            Ether(src="00:00:00:00:00:02")
            / IP(src="1.2.3.5")
            / UDP(sport=MDNS_PORT, dport=MDNS_PORT)
            / Raw(load=b"not dns")
        )
        # _safe_process_packet sees mDNS port + IP, hands to _process_packet,
        # which finds no DNS layer and returns without recording.
        listener.feed_packet(pkt)
        assert listener.discovered_devices == {}

    def test_feed_packets_returns_devices(self):
        from scapy.all import DNSRR

        listener = _make_listener()
        pkts = [
            _answer_packet(
                [DNSRR(rrname="a.local.", type="A", rdata="10.0.0.1")],
                src_mac="00:00:00:00:00:0a",
            ),
            _answer_packet(
                [DNSRR(rrname="b.local.", type="A", rdata="10.0.0.2")],
                src_mac="00:00:00:00:00:0b",
            ),
        ]
        result = listener.feed_packets(iter(pkts))
        assert len(result) == 2
        assert {"00:00:00:00:00:0a", "00:00:00:00:00:0b"} == set(result)


# ===========================================================================
# DNS-SD active scanner service handling (zeroconf info objects)
# ===========================================================================


class TestDNSSDServiceHandling:
    def _make_scanner(self):
        s = DNSSDScanner.__new__(DNSSDScanner)
        s.interface = "eth0"
        s.timeout = 10
        s.discovered_devices = {}
        s._lock = threading.Lock()
        s.nxc_logger = None
        return s

    def test_handle_service_creates_device(self):
        s = self._make_scanner()
        info = MagicMock()
        info.parsed_addresses.return_value = ["192.168.5.5"]
        info.port = 8080
        info.server = "plc.local."
        mock_zc = MagicMock()
        mock_zc.get_service_info.return_value = info

        s._handle_service(mock_zc, "_modbus._tcp.local.", "M._modbus._tcp.local.")

        assert "192.168.5.5" in s.discovered_devices
        dev = s.discovered_devices["192.168.5.5"]
        assert dev.name == "plc.local"
        assert dev.dnssd_data["services"][0]["port"] == 8080
        assert dev.dnssd_data["services"][0]["type"] == "_modbus._tcp.local."
        assert "dns-sd" in dev.discovered_by

    def test_handle_service_second_service_appends(self):
        s = self._make_scanner()
        mock_zc = MagicMock()

        info1 = MagicMock()
        info1.parsed_addresses.return_value = ["192.168.5.6"]
        info1.port = 80
        info1.server = "dev.local."
        mock_zc.get_service_info.return_value = info1
        s._handle_service(mock_zc, "_http._tcp.local.", "H._http._tcp.local.")

        info2 = MagicMock()
        info2.parsed_addresses.return_value = ["192.168.5.6"]
        info2.port = 443
        info2.server = "dev.local."
        mock_zc.get_service_info.return_value = info2
        s._handle_service(mock_zc, "_https._tcp.local.", "S._https._tcp.local.")

        dev = s.discovered_devices["192.168.5.6"]
        assert len(dev.dnssd_data["services"]) == 2

    def test_handle_service_no_addresses_skipped(self):
        s = self._make_scanner()
        info = MagicMock()
        info.parsed_addresses.return_value = []
        info.addresses = []
        mock_zc = MagicMock()
        mock_zc.get_service_info.return_value = info
        s._handle_service(mock_zc, "_http._tcp.local.", "H._http._tcp.local.")
        assert s.discovered_devices == {}

    def test_handle_service_info_none_skipped(self):
        s = self._make_scanner()
        mock_zc = MagicMock()
        mock_zc.get_service_info.return_value = None
        s._handle_service(mock_zc, "_http._tcp.local.", "H._http._tcp.local.")
        assert s.discovered_devices == {}

    def test_handle_service_raw_address_fallback(self):
        s = self._make_scanner()
        info = MagicMock()
        del info.parsed_addresses  # force the .addresses branch
        info.addresses = [b"\xc0\xa8\x05\x07"]  # 192.168.5.7
        info.port = 502
        info.server = "raw.local."
        mock_zc = MagicMock()
        mock_zc.get_service_info.return_value = info
        s._handle_service(mock_zc, "_modbus._tcp.local.", "R._modbus._tcp.local.")
        assert "192.168.5.7" in s.discovered_devices

    def test_handle_service_uses_nxc_logger(self):
        s = self._make_scanner()
        s.nxc_logger = MagicMock()
        info = MagicMock()
        info.parsed_addresses.return_value = ["192.168.5.8"]
        info.port = 80
        info.server = "log.local."
        mock_zc = MagicMock()
        mock_zc.get_service_info.return_value = info
        s._handle_service(mock_zc, "_http._tcp.local.", "L._http._tcp.local.")
        assert s.nxc_logger.success.called


# ===========================================================================
# DNS-SD scan() orchestration (zeroconf browse loop)
# ===========================================================================


class TestDNSSDScanOrchestration:
    def test_scan_browses_many_service_types(self):
        scanner = DNSSDScanner("eth0", timeout=1)
        from oida.utils import iface_info

        mock_zc = MagicMock()
        mock_browser = MagicMock()
        with (
            patch.object(
                iface_info,
                "ifaddresses",
                return_value={iface_info.AF_INET: [{"addr": "192.168.1.1"}]},
            ),
            patch("zeroconf.Zeroconf", return_value=mock_zc),
            patch("zeroconf.ServiceBrowser", return_value=mock_browser) as mock_b,
            patch("zeroconf.ServiceListener"),
            patch("time.sleep"),
        ):
            scanner.scan()

        # MDNS_SERVICE_TYPES + extra printer/cast/share types -> >10 browses
        assert mock_b.call_count > 10
        mock_zc.close.assert_called_once()

    def test_scan_no_ipv4_returns_empty(self):
        scanner = DNSSDScanner("eth0", timeout=1)
        from oida.utils import iface_info

        with patch.object(iface_info, "ifaddresses", return_value={}):
            assert scanner.scan() == {}


# ===========================================================================
# mDNS (zeroconf passive) scan() orchestration
# ===========================================================================


class TestMDNSScanOrchestration:
    def test_scan_browses_service_types_and_closes(self):
        scanner = MDNSScanner("eth0", timeout=1)
        from oida.utils import iface_info

        mock_zc = MagicMock()
        mock_browser = MagicMock()
        with (
            patch.object(
                iface_info,
                "ifaddresses",
                return_value={iface_info.AF_INET: [{"addr": "192.168.1.1"}]},
            ),
            patch("zeroconf.Zeroconf", return_value=mock_zc),
            patch("zeroconf.ServiceBrowser", return_value=mock_browser) as mock_b,
            patch("zeroconf.ServiceListener"),
            patch("time.sleep"),
        ):
            scanner.scan()

        assert mock_b.call_count > 5
        mock_zc.close.assert_called_once()

    def test_scan_no_ipv4_returns_empty(self):
        scanner = MDNSScanner("eth0", timeout=1)
        from oida.utils import iface_info

        with patch.object(iface_info, "ifaddresses", return_value={}):
            assert scanner.scan() == {}


# ===========================================================================
# Passive listener live-capture (sniffer I/O faked at the boundary)
# ===========================================================================


class TestMDNSPassiveLiveCapture:
    def test_live_capture_starts_and_stops_sniffer(self):
        listener = MDNSPassiveListener("eth0", timeout=1)

        fake_sniffer = MagicMock()
        fake_scapy = MagicMock()
        fake_scapy.AsyncSniffer.return_value = fake_sniffer

        # _scapy_all is a LazyModule: is_available True, call returns module.
        lazy = MagicMock()
        lazy.is_available = True
        lazy.return_value = fake_scapy

        with (
            patch("oida.protocols.discovery.mdns._scapy_all", lazy),
            patch("oida.protocols.discovery.mdns.time.sleep"),
        ):
            result = listener.scan()

        fake_sniffer.start.assert_called_once()
        fake_sniffer.stop.assert_called_once()
        assert result == {}

    def test_live_capture_scapy_unavailable(self):
        listener = MDNSPassiveListener("eth0", timeout=1)
        lazy = MagicMock()
        lazy.is_available = False
        with patch("oida.protocols.discovery.mdns._scapy_all", lazy):
            assert listener.scan() == {}
