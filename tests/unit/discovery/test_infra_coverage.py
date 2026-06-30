"""
Behavioral coverage tests for oida.protocols.discovery.infra.

Targets paths the existing test_infra.py does not exercise:
- the scan() send/receive/parse/store loop (driven through a mocked UDP
  socket; only the socket + broadcast-address enumeration are mocked, the
  parse + dedup + store logic runs for real),
- BJNPScanner._query_identity (IEEE-1284 device-id follow-up),
- IPMIScanner (_build_probe + ASF Presence Pong parsing),
- SLPScanner SAAdvert / DAAdvert reply parsing,
- _build_probe layouts for Sybase / XDMCP / BJNP.
"""

import socket
import struct
from contextlib import contextmanager
from unittest.mock import MagicMock, patch


from oida.protocols.discovery import infra


@contextmanager
def driven_socket(responses, broadcasts=("192.168.1.255",)):
    """Patch infra's UDP socket + broadcast enumeration with a scripted socket.

    responses: list of (data, (ip, port)) tuples returned by recvfrom, then
    socket.timeout repeats until the scan loop's wall-clock deadline expires.
    """
    mock_sock = MagicMock()
    seq = list(responses) + [socket.timeout()] * 50

    def _recvfrom(_bufsize):
        item = seq.pop(0) if seq else socket.timeout()
        if isinstance(item, BaseException):
            raise item
        return item

    mock_sock.recvfrom.side_effect = _recvfrom

    with (
        patch.object(infra, "create_udp_socket", return_value=mock_sock),
        patch.object(infra, "get_all_broadcast_addresses", return_value=list(broadcasts)),
    ):
        yield mock_sock


# ---------------------------------------------------------------------------
# HIDScanner.scan  (full send/recv/parse/store loop)
# ---------------------------------------------------------------------------
class TestHIDScanFlow:
    def test_scan_stores_parsed_device(self):
        scanner = infra.HIDScanner(interface="eth0", timeout=0.3)
        response = (
            b"discovered;70;00:11:22:33:44:55;Front Door;192.168.1.50;1;iCLASS SE;4.2.1;2024-01-15"
        )
        with driven_socket([(response, ("192.168.1.50", 4070))]) as sock:
            devices = scanner.scan()

        # Probe was broadcast to the HID port
        assert sock.sendto.called
        assert sock.sendto.call_args[0][1] == ("192.168.1.255", 4070)
        assert "192.168.1.50" in devices
        assert devices["192.168.1.50"].model == "iCLASS SE"

    def test_scan_skips_duplicate_ip(self):
        scanner = infra.HIDScanner(interface="eth0", timeout=0.3)
        resp = b"discovered;70;00:11:22:33:44:55;Door;192.168.1.50;1;EH400;3.5;2023-01-01"
        with driven_socket([(resp, ("192.168.1.50", 4070)), (resp, ("192.168.1.50", 4070))]):
            devices = scanner.scan()
        assert list(devices) == ["192.168.1.50"]

    def test_scan_ignores_unparseable_response(self):
        scanner = infra.HIDScanner(interface="eth0", timeout=0.2)
        with driven_socket([(b"garbage-no-marker", ("192.168.1.99", 4070))]):
            devices = scanner.scan()
        assert devices == {}


# ---------------------------------------------------------------------------
# MSSQLBrowserScanner.scan + multi-instance parse
# ---------------------------------------------------------------------------
class TestMSSQLScanFlow:
    def _ssrp(self, body: bytes) -> bytes:
        # 0x05 header + 2-byte length + payload
        return b"\x05" + struct.pack("<H", len(body)) + body

    def test_scan_parses_instance(self):
        scanner = infra.MSSQLBrowserScanner(interface="eth0", timeout=0.3)
        body = b"ServerName;SQLPROD;InstanceName;MSSQLSERVER;Version;15.0.2000.5;tcp;1433;"
        with driven_socket([(self._ssrp(body), ("192.168.1.60", 1434))]):
            devices = scanner.scan()
        assert "192.168.1.60" in devices
        d = devices["192.168.1.60"].mssql_data
        assert d["server_name"] == "SQLPROD"
        assert d["instance_name"] == "MSSQLSERVER"
        assert d["version"] == "15.0.2000.5"
        assert d["tcp_port"] == "1433"
        assert d["instance_count"] == 1

    def test_multi_instance_response(self):
        scanner = infra.MSSQLBrowserScanner(interface="eth0")
        body = (
            b"ServerName;HOST;InstanceName;INST1;Version;15.0;tcp;1433;;"
            b"ServerName;HOST;InstanceName;INST2;Version;15.0;tcp;1434;"
        )
        device = scanner._parse_response(self._ssrp(body), "192.168.1.61")
        assert device is not None
        assert device.mssql_data["instance_count"] == 2
        assert "+1 more" in device.description


# ---------------------------------------------------------------------------
# BJNPScanner: probe layout + scan + identity follow-up
# ---------------------------------------------------------------------------
class TestBJNP:
    def test_build_probe_layout(self):
        scanner = infra.BJNPScanner(interface="eth0")
        probe = scanner._build_probe(dev_type=1)
        assert probe[:4] == b"BJNP"
        assert probe[4] == 1  # device type (print)
        assert probe[5] == 0x01  # code = discover
        assert len(probe) == 16

    def test_scan_discovers_then_queries_identity(self):
        scanner = infra.BJNPScanner(interface="eth0", timeout=0.3)
        # Valid BJNP response header (>=16 bytes, magic + type/code + zero len)
        resp = b"BJNP" + bytes([1, 0]) + b"\x00" * 10
        with driven_socket([(resp, ("192.168.1.70", 8611))]):
            # Stub the per-device identity follow-up socket (separate socket())
            with patch("socket.socket") as id_sock_cls:
                id_sock = MagicMock()
                id_sock_cls.return_value = id_sock
                # IEEE 1284 device-id payload after a 16-byte BJNP header
                id_payload = b"BJNP\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                id_payload += b"MFG:Canon;MDL:PIXMA TR8520;DES:Inkjet MFP;VER:1.05;"
                id_sock.recvfrom.return_value = (id_payload, ("192.168.1.70", 8611))
                devices = scanner.scan()

        assert "192.168.1.70" in devices
        dev = devices["192.168.1.70"]
        # Identity query enriched the record
        assert dev.manufacturer == "Canon"
        assert dev.model == "PIXMA TR8520"
        assert dev.bjnp_data["version"] == "1.05"

    def test_query_identity_handles_socket_error(self):
        scanner = infra.BJNPScanner(interface="eth0")
        from oida.protocols.discovery.core import DiscoveredDevice

        device = DiscoveredDevice(ip_addresses=["1.2.3.4"], bjnp_data={})
        with patch("socket.socket") as id_sock_cls:
            id_sock_cls.return_value.recvfrom.side_effect = OSError("no route")
            # Must not raise
            scanner._query_identity("1.2.3.4", device)


# ---------------------------------------------------------------------------
# IPMIScanner: probe layout + ASF Presence Pong parse
# ---------------------------------------------------------------------------
class TestIPMI:
    def test_build_probe(self):
        scanner = infra.IPMIScanner(interface="eth0")
        probe = scanner._build_probe()
        assert len(probe) == 12
        assert probe[:4] == b"\x06\x00\xff\x06"  # RMCP header
        # ASF enterprise number 4542 (0x000011BE) follows
        assert struct.unpack_from(">I", probe, 4)[0] == 4542
        assert probe[8] == 0x80  # Presence Ping message type

    def _pong(self, enterprise=343, entities=0x81, interactions=0xA0):
        rmcp = b"\x06\x00\xff\x06"
        asf = struct.pack(">I", 4542) + bytes((0x40, 0x10)) + b"\x00" + b"\x10"
        block = (
            struct.pack(">I", enterprise)
            + b"\x00\x00\x00\x00"  # OEM
            + bytes((entities, interactions))
            + b"\x00" * 6
        )
        return rmcp + asf + block

    def test_parse_ipmi_supported_with_vendor(self):
        scanner = infra.IPMIScanner(interface="eth0")
        device = scanner._parse_response(self._pong(enterprise=343), "10.0.0.30")
        assert device is not None
        assert device.manufacturer == "Intel"
        assert device.device_type == "BMC (IPMI)"
        ipmi = device.ipmi_data
        assert ipmi["ipmi_supported"] is True
        assert ipmi["asf_v1"] is True
        assert ipmi["security_extensions"] is True
        assert ipmi["dash"] is True
        assert ipmi["iana_enterprise"] == 343

    def test_parse_non_ipmi_asf_device(self):
        scanner = infra.IPMIScanner(interface="eth0")
        # entities bit7 clear -> not IPMI; unknown enterprise -> no vendor
        device = scanner._parse_response(self._pong(enterprise=99999, entities=0x01), "10.0.0.31")
        assert device is not None
        assert device.device_type == "ASF-RMCP Device"
        assert device.ipmi_data["ipmi_supported"] is False
        assert device.manufacturer == "Unknown"

    def test_parse_rejects_wrong_class(self):
        scanner = infra.IPMIScanner(interface="eth0")
        # RMCP class byte not ASF (0x06) -> rejected
        bad = b"\x06\x00\xff\x07" + b"\x00" * 24
        assert scanner._parse_response(bad, "10.0.0.32") is None

    def test_parse_rejects_non_pong(self):
        scanner = infra.IPMIScanner(interface="eth0")
        rmcp = b"\x06\x00\xff\x06"
        asf = struct.pack(">I", 4542) + bytes((0x80, 0x10)) + b"\x00\x00"  # Ping, not Pong
        assert scanner._parse_response(rmcp + asf + b"\x00" * 16, "10.0.0.33") is None

    def test_parse_too_short(self):
        scanner = infra.IPMIScanner(interface="eth0")
        assert scanner._parse_response(b"\x06\x00\xff\x06", "10.0.0.34") is None

    def test_scan_stores_bmc(self):
        scanner = infra.IPMIScanner(interface="eth0", timeout=0.3)
        with driven_socket([(self._pong(), ("10.0.0.30", 623))]):
            devices = scanner.scan()
        assert "10.0.0.30" in devices
        assert devices["10.0.0.30"].device_type == "BMC (IPMI)"


# ---------------------------------------------------------------------------
# SLPScanner: SAAdvert / DAAdvert (SrvRply already covered elsewhere)
# ---------------------------------------------------------------------------
class TestSLPAdverts:
    def _slp(self, func: int, body: bytes) -> bytes:
        header = (
            bytes((2, func))
            + (16 + len(body)).to_bytes(3, "big")
            + struct.pack(">H", 0)  # flags
            + (0).to_bytes(3, "big")  # next-ext
            + struct.pack(">H", 1)  # XID
            + struct.pack(">H", 2)  # lang-tag len
            + b"en"
        )
        return header + body

    def test_saadvert(self):
        scanner = infra.SLPScanner(interface="eth0")
        url = b"service:service-agent://10.0.0.40"
        body = struct.pack(">H", len(url)) + url
        device = scanner._parse_response(self._slp(11, body), "10.0.0.40")
        assert device is not None
        assert device.slp_data["message"] == "SAAdvert"
        assert device.slp_data["urls"] == [url.decode()]

    def test_daadvert(self):
        scanner = infra.SLPScanner(interface="eth0")
        url = b"service:directory-agent://10.0.0.41"
        body = struct.pack(">H", 0) + struct.pack(">I", 12345) + struct.pack(">H", len(url)) + url
        device = scanner._parse_response(self._slp(8, body), "10.0.0.41")
        assert device is not None
        assert device.slp_data["message"] == "DAAdvert"
        assert device.slp_data["urls"] == [url.decode()]

    def test_unknown_function_rejected(self):
        scanner = infra.SLPScanner(interface="eth0")
        assert scanner._parse_response(self._slp(99, b""), "10.0.0.42") is None

    def test_scan_collects_agent(self):
        scanner = infra.SLPScanner(interface="eth0", timeout=0.3)
        url = b"service:service-agent://10.0.0.40"
        body = struct.pack(">H", len(url)) + url
        # SLP uses multicast (no broadcast list), so just patch the socket
        mock_sock = MagicMock()
        seq = [(self._slp(11, body), ("10.0.0.40", 427))] + [socket.timeout()] * 50

        def _recvfrom(_n):
            item = seq.pop(0) if seq else socket.timeout()
            if isinstance(item, BaseException):
                raise item
            return item

        mock_sock.recvfrom.side_effect = _recvfrom
        with patch.object(infra, "create_udp_socket", return_value=mock_sock):
            devices = scanner.scan()
        assert "10.0.0.40" in devices


# ---------------------------------------------------------------------------
# Probe layouts for Sybase / XDMCP
# ---------------------------------------------------------------------------
class TestProbeLayouts:
    def test_xdmcp_probe(self):
        scanner = infra.XDMCPScanner(interface="eth0")
        probe = scanner._build_probe()
        # version=1, opcode=3 (BroadcastQuery), length=1, then 1 auth byte
        version, opcode, length = struct.unpack(">HHH", probe[:6])
        assert version == 1
        assert opcode == 3
        assert length == 1
        assert len(probe) == 7

    def test_xdmcp_parse_willing(self):
        scanner = infra.XDMCPScanner(interface="eth0")
        # version(2)+opcode=5(2)+length(2)+auth_len(2)=0+host_len(2)+host+status_len(2)+status
        host = b"xterm-host"
        status = b"Linux 6.1"
        payload = (
            struct.pack(">HHH", 1, 5, 0)
            + struct.pack(">H", 0)  # auth name len
            + struct.pack(">H", len(host))
            + host
            + struct.pack(">H", len(status))
            + status
        )
        device = scanner._parse_response(payload, "10.0.0.80")
        assert device is not None
        assert device.xdmcp_data["hostname"] == "xterm-host"
        assert device.xdmcp_data["status"] == "Linux 6.1"

    def test_xdmcp_rejects_non_willing(self):
        scanner = infra.XDMCPScanner(interface="eth0")
        # opcode 7 != WILLING(5)
        assert scanner._parse_response(struct.pack(">HHH", 1, 7, 0), "10.0.0.81") is None

    def test_sybase_probe_layout(self):
        scanner = infra.SybaseScanner(interface="eth0")
        probe = scanner._build_probe()
        assert probe[0] == 0x1A  # TDS_MGMT type
        assert len(probe) == 61

    def test_sybase_parse_extracts_readable_strings(self):
        scanner = infra.SybaseScanner(interface="eth0")
        data = b"\x00\x01ASADEMO\x00\x02\x03prodserver\x00"
        device = scanner._parse_response(data, "10.0.0.90")
        assert device is not None
        # First readable run becomes the instance name
        assert device.sybase_data["instance_name"] == "ASADEMO"
        assert "prodserver" in device.sybase_data["server_info"]


# ---------------------------------------------------------------------------
# pcAnywhere: NR + ST status update (scan dispatch)
# ---------------------------------------------------------------------------
class TestPCAnywhere:
    def test_scan_nr_then_st_status(self):
        scanner = infra.PCAnywhereScanner(interface="eth0", timeout=0.4)
        # NR: "NR" + 24-byte name (underscore padded) + 8-byte caps
        name = b"WIN_SERVER" + b"_" * 14  # 24 bytes
        caps = b"REMOTE__"  # 8 bytes
        nr = b"NR" + name + caps
        # ST: byte[4] == 0x43 -> Available
        st = b"ST\x00\x00\x43"
        with driven_socket([(nr, ("10.0.0.100", 5632)), (st, ("10.0.0.100", 5632))]):
            devices = scanner.scan()

        assert "10.0.0.100" in devices
        pc = devices["10.0.0.100"].pcanywhere_data
        assert "WIN SERVER" in pc["server_name"]
        assert pc["status"] == "Available"

    def test_st_busy_status(self):
        scanner = infra.PCAnywhereScanner(interface="eth0")
        from oida.protocols.discovery.core import DiscoveredDevice

        # Seed a device, then apply a Busy ST response
        scanner.discovered_devices["10.0.0.101"] = DiscoveredDevice(
            ip_addresses=["10.0.0.101"], pcanywhere_data={}
        )
        scanner._parse_st_response(b"ST\x00\x00\x0b", "10.0.0.101")
        assert scanner.discovered_devices["10.0.0.101"].pcanywhere_data["status"] == "Busy"


# ---------------------------------------------------------------------------
# DB2 / Sybase / Jenkins / SonicWall scan-flow smoke through the loop
# ---------------------------------------------------------------------------
class TestOtherScanFlows:
    def test_db2_scan(self):
        scanner = infra.DB2Scanner(interface="eth0", timeout=0.3)
        resp = b"DB2RETADDR\x00SQL09010\x00DB2INST1\x00"
        with driven_socket([(resp, ("10.0.0.110", 523))]):
            devices = scanner.scan()
        assert "10.0.0.110" in devices
        d = devices["10.0.0.110"].db2_data
        assert d["version"] == "SQL09010"
        assert d["server_name"] == "DB2INST1"

    def test_sonicwall_scan(self):
        scanner = infra.SonicWallScanner(interface="eth0", timeout=0.3)
        # >=54 bytes; IP@40, netmask@44, serial@48, firmware@54
        resp = bytearray(b"\x00" * 54)
        resp[40:44] = socket.inet_aton("192.168.1.1")
        resp[44:48] = socket.inet_aton("255.255.255.0")
        resp[48:54] = bytes.fromhex("0006b1abcdef")
        resp += b"SonicOS 7.0\x00"
        with driven_socket([(bytes(resp), ("10.0.0.120", 26214))]):
            devices = scanner.scan()
        assert "10.0.0.120" in devices
        sw = devices["10.0.0.120"].sonicwall_data
        assert sw["device_ip"] == "192.168.1.1"
        assert sw["netmask"] == "255.255.255.0"
        assert sw["firmware"] == "SonicOS 7.0"

    def test_sybase_scan(self):
        scanner = infra.SybaseScanner(interface="eth0", timeout=0.3)
        resp = b"\x00\x01ASADEMO\x00\x02\x03demoserver\x00"
        with driven_socket([(resp, ("10.0.0.140", 2638))]):
            devices = scanner.scan()
        assert "10.0.0.140" in devices
        assert devices["10.0.0.140"].sybase_data["instance_name"] == "ASADEMO"

    def test_xdmcp_scan(self):
        scanner = infra.XDMCPScanner(interface="eth0", timeout=0.3)
        host = b"display-mgr"
        status = b"Willing to manage"
        payload = (
            struct.pack(">HHH", 1, 5, 0)
            + struct.pack(">H", 0)
            + struct.pack(">H", len(host))
            + host
            + struct.pack(">H", len(status))
            + status
        )
        with driven_socket([(payload, ("10.0.0.150", 177))]):
            devices = scanner.scan()
        assert "10.0.0.150" in devices
        assert devices["10.0.0.150"].xdmcp_data["hostname"] == "display-mgr"

    def test_jenkins_scan(self):
        scanner = infra.JenkinsScanner(interface="eth0", timeout=0.3)
        xml = (
            b"<hudson><version>2.426.1</version><url>http://ci.local/</url>"
            b"<server-id>abc123</server-id><slave-port>50000</slave-port></hudson>"
        )
        with driven_socket([(xml, ("10.0.0.130", 33848))]):
            devices = scanner.scan()
        assert "10.0.0.130" in devices
        j = devices["10.0.0.130"].jenkins_data
        assert j["version"] == "2.426.1"
        assert j["url"] == "http://ci.local/"
        assert j["slave_port"] == "50000"
