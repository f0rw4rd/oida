"""
Tests for IT infrastructure broadcast discovery scanners.

Tests cover all 9 scanners in oida.protocols.discovery.infra:
- HIDScanner, MSSQLBrowserScanner, BJNPScanner, SonicWallScanner,
  DB2Scanner, SybaseScanner, XDMCPScanner, JenkinsScanner, PCAnywhereScanner
"""

import struct

import pytest


# ---------------------------------------------------------------------------
# HIDScanner
# ---------------------------------------------------------------------------
class TestHIDScannerInit:
    def test_valid_init(self):
        from oida.protocols.discovery.infra import HIDScanner

        scanner = HIDScanner(interface="eth0", timeout=5.0)
        assert scanner.interface == "eth0"
        assert scanner.timeout == 5.0
        assert scanner.subnet is None
        assert scanner.discovered_devices == {}

    def test_init_with_subnet(self):
        from oida.protocols.discovery.infra import HIDScanner

        scanner = HIDScanner(interface="eth0", subnet="192.168.1.0/24", timeout=3.0)
        assert scanner.subnet == "192.168.1.0/24"

    def test_init_invalid_interface_empty(self):
        from oida.protocols.discovery.infra import HIDScanner

        with pytest.raises(ValueError, match="cannot be empty"):
            HIDScanner(interface="")

    def test_init_invalid_timeout_zero(self):
        from oida.protocols.discovery.infra import HIDScanner

        with pytest.raises(ValueError, match="must be positive"):
            HIDScanner(interface="eth0", timeout=0)

    def test_init_invalid_timeout_negative(self):
        from oida.protocols.discovery.infra import HIDScanner

        with pytest.raises(ValueError, match="must be positive"):
            HIDScanner(interface="eth0", timeout=-1)

    def test_init_invalid_subnet(self):
        from oida.protocols.discovery.infra import HIDScanner

        with pytest.raises(ValueError, match="Invalid subnet"):
            HIDScanner(interface="eth0", subnet="invalid")

    def test_hid_constants(self):
        from oida.protocols.discovery.infra import HIDScanner

        assert HIDScanner.PORT == 4070
        assert HIDScanner.DISCOVERY_PROBE == b"discover;013;"


class TestHIDScannerParseResponse:
    def test_valid_response(self):
        """Test parsing valid HID response with correct field mapping.

        Format confirmed by Metasploit exploit module:
        discovered;length;MAC;name;IP;unknown;model;version;build_date
        """
        from oida.protocols.discovery.infra import HIDScanner

        scanner = HIDScanner(interface="eth0")
        response = (
            b"discovered;70;00:11:22:33:44:55;Front Door;192.168.1.50;1;iCLASS SE;4.2.1;2024-01-15"
        )
        device = scanner._parse_response(response, "192.168.1.50")

        assert device is not None
        assert device.ip_addresses == ["192.168.1.50"]
        assert device.mac_address == "00:11:22:33:44:55"
        assert device.manufacturer == "HID Global"
        assert device.device_type == "Access Control"
        assert device.name == "Front Door"
        assert device.model == "iCLASS SE"
        assert "hid" in device.discovered_by
        assert device.hid_data is not None
        assert device.hid_data["device_name"] == "Front Door"
        assert device.hid_data["model"] == "iCLASS SE"
        assert device.hid_data["firmware_version"] == "4.2.1"
        assert device.hid_data["build_date"] == "2024-01-15"

    def test_rejects_response_without_discovered_marker(self):
        from oida.protocols.discovery.infra import HIDScanner

        scanner = HIDScanner(interface="eth0")
        # Missing "discovered" prefix
        response = b"00:11:22:33:44:55;Front Door;192.168.1.50;1;EH400;3.5.1;2023-06-01;x;y"
        device = scanner._parse_response(response, "192.168.1.50")
        assert device is None

    def test_rejects_too_few_fields(self):
        from oida.protocols.discovery.infra import HIDScanner

        scanner = HIDScanner(interface="eth0")
        # Only 5 fields, needs 9
        response = b"discovered;30;AA:BB:CC:DD:EE:FF;Reader1;10.0.0.5"
        device = scanner._parse_response(response, "10.0.0.5")
        assert device is None

    def test_empty_response(self):
        from oida.protocols.discovery.infra import HIDScanner

        scanner = HIDScanner(interface="eth0")
        device = scanner._parse_response(b"", "192.168.1.1")
        assert device is None

    def test_no_semicolons(self):
        from oida.protocols.discovery.infra import HIDScanner

        scanner = HIDScanner(interface="eth0")
        device = scanner._parse_response(b"nosemicolons", "192.168.1.1")
        assert device is None

    def test_vertx_evo_response(self):
        """Test with VertX EVO model (known vulnerable model from Metasploit)."""
        from oida.protocols.discovery.infra import HIDScanner

        scanner = HIDScanner(interface="eth0")
        response = b"discovered;82;AA:BB:CC:DD:EE:FF;Lobby Controller;10.0.0.5;1;V2-V2000;3.5.1.1483;2023-06-01"
        device = scanner._parse_response(response, "10.0.0.5")

        assert device is not None
        assert device.model == "V2-V2000"
        assert device.hid_data["firmware_version"] == "3.5.1.1483"


class TestHIDScannerScan:
    def test_scan_returns_empty_dict_on_no_responses(self):
        from oida.protocols.discovery.infra import HIDScanner

        scanner = HIDScanner(interface="nonexistent_interface_xyz", timeout=0.01)
        result = scanner.scan()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# MSSQLBrowserScanner
# ---------------------------------------------------------------------------
class TestMSSQLBrowserScannerInit:
    def test_valid_init(self):
        from oida.protocols.discovery.infra import MSSQLBrowserScanner

        scanner = MSSQLBrowserScanner(interface="eth0", timeout=5.0)
        assert scanner.interface == "eth0"
        assert scanner.timeout == 5.0
        assert scanner.discovered_devices == {}

    def test_init_invalid_interface_empty(self):
        from oida.protocols.discovery.infra import MSSQLBrowserScanner

        with pytest.raises(ValueError, match="cannot be empty"):
            MSSQLBrowserScanner(interface="")

    def test_init_invalid_timeout(self):
        from oida.protocols.discovery.infra import MSSQLBrowserScanner

        with pytest.raises(ValueError, match="must be positive"):
            MSSQLBrowserScanner(interface="eth0", timeout=0)

    def test_mssql_constants(self):
        from oida.protocols.discovery.infra import MSSQLBrowserScanner

        assert MSSQLBrowserScanner.PORT == 1434
        assert MSSQLBrowserScanner.DISCOVERY_PROBE == b"\x02"


class TestMSSQLBrowserScannerParseResponse:
    def test_valid_response(self):
        from oida.protocols.discovery.infra import MSSQLBrowserScanner

        scanner = MSSQLBrowserScanner(interface="eth0")
        # Build typical SQL Browser response
        # Header: 0x05 + 2 length bytes, then key-value pairs
        payload = (
            "ServerName;SQLSRV01;InstanceName;MSSQLSERVER;"
            "IsClustered;No;Version;16.0.1000.6;tcp;1433;np;\\\\SQLSRV01\\pipe\\sql\\query;"
        )
        data = b"\x05\x00\x00" + payload.encode("ascii")

        device = scanner._parse_response(data, "192.168.1.200")

        assert device is not None
        assert device.ip_addresses == ["192.168.1.200"]
        assert device.manufacturer == "Microsoft"
        assert device.device_type == "Database Server"
        assert "mssql" in device.discovered_by
        assert device.mssql_data is not None
        assert device.mssql_data["server_name"] == "SQLSRV01"
        assert device.mssql_data["instance_name"] == "MSSQLSERVER"
        assert device.mssql_data["version"] == "16.0.1000.6"
        assert device.mssql_data["tcp_port"] == "1433"
        assert device.mssql_data["instance_count"] == 1
        assert device.name == "SQLSRV01"

    def test_multiple_instances(self):
        """Test multi-instance parsing (instances separated by ;;)."""
        from oida.protocols.discovery.infra import MSSQLBrowserScanner

        scanner = MSSQLBrowserScanner(interface="eth0")
        payload = (
            "ServerName;SQLSRV01;InstanceName;MSSQLSERVER;Version;16.0.1000.6;tcp;1433;;"
            "ServerName;SQLSRV01;InstanceName;REPORTING;Version;16.0.1000.6;tcp;1434;;"
        )
        data = b"\x05\x00\x00" + payload.encode("ascii")

        device = scanner._parse_response(data, "192.168.1.200")

        assert device is not None
        assert device.mssql_data["instance_count"] == 2
        assert len(device.mssql_data["instances"]) == 2
        assert device.mssql_data["instances"][0]["InstanceName"] == "MSSQLSERVER"
        assert device.mssql_data["instances"][1]["InstanceName"] == "REPORTING"
        assert "+1 more" in device.description

    def test_response_too_short(self):
        from oida.protocols.discovery.infra import MSSQLBrowserScanner

        scanner = MSSQLBrowserScanner(interface="eth0")
        device = scanner._parse_response(b"\x05\x00", "192.168.1.1")
        assert device is None

    def test_empty_payload(self):
        from oida.protocols.discovery.infra import MSSQLBrowserScanner

        scanner = MSSQLBrowserScanner(interface="eth0")
        device = scanner._parse_response(b"\x05\x00\x00", "192.168.1.1")
        assert device is None

    def test_description_with_version_and_instance(self):
        from oida.protocols.discovery.infra import MSSQLBrowserScanner

        scanner = MSSQLBrowserScanner(interface="eth0")
        payload = "ServerName;DB01;InstanceName;MYINST;Version;15.0.4;"
        data = b"\x05\x00\x00" + payload.encode("ascii")

        device = scanner._parse_response(data, "10.0.0.1")
        assert device is not None
        assert "15.0.4" in device.description
        assert "MYINST" in device.description


class TestMSSQLBrowserScannerScan:
    def test_scan_returns_empty_dict_on_no_responses(self):
        from oida.protocols.discovery.infra import MSSQLBrowserScanner

        scanner = MSSQLBrowserScanner(interface="nonexistent_interface_xyz", timeout=0.01)
        result = scanner.scan()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# BJNPScanner
# ---------------------------------------------------------------------------
class TestBJNPScannerInit:
    def test_valid_init(self):
        from oida.protocols.discovery.infra import BJNPScanner

        scanner = BJNPScanner(interface="eth0", timeout=5.0)
        assert scanner.interface == "eth0"
        assert scanner.timeout == 5.0
        assert scanner.discovered_devices == {}

    def test_init_invalid_interface_empty(self):
        from oida.protocols.discovery.infra import BJNPScanner

        with pytest.raises(ValueError, match="cannot be empty"):
            BJNPScanner(interface="")

    def test_init_invalid_timeout(self):
        from oida.protocols.discovery.infra import BJNPScanner

        with pytest.raises(ValueError, match="must be positive"):
            BJNPScanner(interface="eth0", timeout=0)

    def test_bjnp_constants(self):
        from oida.protocols.discovery.infra import BJNPScanner

        assert BJNPScanner.PORTS == [8611, 8612]
        assert BJNPScanner.BJNP_MAGIC == b"BJNP"


class TestBJNPScannerBuildProbe:
    def test_probe_structure(self):
        from oida.protocols.discovery.infra import BJNPScanner

        scanner = BJNPScanner(interface="eth0")
        probe = scanner._build_probe(dev_type=1)

        assert len(probe) == 16
        assert probe[:4] == b"BJNP"
        assert probe[4] == 1  # type = print
        assert probe[5] == 0x01  # code = discover

    def test_probe_scan_type(self):
        from oida.protocols.discovery.infra import BJNPScanner

        scanner = BJNPScanner(interface="eth0")
        probe = scanner._build_probe(dev_type=2)

        assert probe[4] == 2  # type = scan


class TestBJNPScannerParseResponse:
    def test_valid_response(self):
        from oida.protocols.discovery.infra import BJNPScanner

        scanner = BJNPScanner(interface="eth0")
        # Build BJNP response: magic(4) + type(1) + code(1) + seq(2) + session(2) + length(4) + pad(2)
        response = struct.pack(">4sBBHHI2x", b"BJNP", 1, 0x01, 0, 0, 0)

        device = scanner._parse_response(response, "192.168.1.30")

        assert device is not None
        assert device.ip_addresses == ["192.168.1.30"]
        assert device.manufacturer == "Canon"
        assert device.device_type == "Printer"
        assert "bjnp" in device.discovered_by
        assert device.bjnp_data is not None

    def test_response_too_short(self):
        from oida.protocols.discovery.infra import BJNPScanner

        scanner = BJNPScanner(interface="eth0")
        device = scanner._parse_response(b"BJNP" + b"\x00" * 5, "192.168.1.1")
        assert device is None

    def test_wrong_magic(self):
        from oida.protocols.discovery.infra import BJNPScanner

        scanner = BJNPScanner(interface="eth0")
        response = struct.pack(">4sBBHHI2x", b"XXXX", 1, 0x01, 0, 0, 0)
        device = scanner._parse_response(response, "192.168.1.1")
        assert device is None

    def test_response_with_payload(self):
        from oida.protocols.discovery.infra import BJNPScanner

        scanner = BJNPScanner(interface="eth0")
        payload = b"hello world"
        # BJNP header: magic(4) + type(1) + code(1) + seq(2) + session(2) + length(4) + pad(2)
        # payload_len is at bytes 8:12, payload starts at byte 16
        header = struct.pack(">4sBBHHI2x", b"BJNP", 1, 0x01, 0, 0, len(payload))
        response = header + payload

        device = scanner._parse_response(response, "192.168.1.30")
        assert device is not None
        # _parse_response reads length from offset 8:12 and payload from offset 16
        assert "payload" in device.bjnp_data
        assert device.bjnp_data["payload"] == payload.hex()


class TestBJNPScannerScan:
    def test_scan_returns_empty_dict_on_no_responses(self):
        from oida.protocols.discovery.infra import BJNPScanner

        scanner = BJNPScanner(interface="nonexistent_interface_xyz", timeout=0.01)
        result = scanner.scan()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# SonicWallScanner
# ---------------------------------------------------------------------------
class TestSonicWallScannerInit:
    def test_valid_init(self):
        from oida.protocols.discovery.infra import SonicWallScanner

        scanner = SonicWallScanner(interface="eth0", timeout=5.0)
        assert scanner.interface == "eth0"
        assert scanner.timeout == 5.0
        assert scanner.discovered_devices == {}

    def test_init_invalid_interface_empty(self):
        from oida.protocols.discovery.infra import SonicWallScanner

        with pytest.raises(ValueError, match="cannot be empty"):
            SonicWallScanner(interface="")

    def test_init_invalid_timeout(self):
        from oida.protocols.discovery.infra import SonicWallScanner

        with pytest.raises(ValueError, match="must be positive"):
            SonicWallScanner(interface="eth0", timeout=0)

    def test_sonicwall_constants(self):
        from oida.protocols.discovery.infra import SonicWallScanner

        assert SonicWallScanner.PORT == 26214
        assert SonicWallScanner.DISCOVERY_PROBE == b"ackfin ping\x00"


class TestSonicWallScannerParseResponse:
    def test_valid_response(self):
        from oida.protocols.discovery.infra import SonicWallScanner

        scanner = SonicWallScanner(interface="eth0")

        # Build response: 54+ bytes with IP@40, netmask@44, serial@48, firmware@54
        response = bytearray(80)
        response[40:44] = bytes([10, 0, 0, 1])  # Device IP
        response[44:48] = bytes([255, 255, 255, 0])  # Netmask
        response[48:54] = bytes.fromhex("aabbccddeeff")  # Serial
        firmware = b"SonicOS 7.0.1\x00"
        response[54 : 54 + len(firmware)] = firmware

        device = scanner._parse_response(bytes(response), "10.0.0.1")

        assert device is not None
        assert device.ip_addresses == ["10.0.0.1"]
        assert device.manufacturer == "SonicWall"
        assert device.device_type == "Firewall"
        assert "sonicwall" in device.discovered_by
        assert device.sonicwall_data is not None
        assert device.sonicwall_data["device_ip"] == "10.0.0.1"
        assert device.sonicwall_data["netmask"] == "255.255.255.0"
        assert device.sonicwall_data["serial"] == "aabbccddeeff"
        assert device.sonicwall_data["firmware"] == "SonicOS 7.0.1"

    def test_response_too_short(self):
        from oida.protocols.discovery.infra import SonicWallScanner

        scanner = SonicWallScanner(interface="eth0")
        device = scanner._parse_response(b"\x00" * 30, "10.0.0.1")
        assert device is None

    def test_minimal_response_no_firmware(self):
        from oida.protocols.discovery.infra import SonicWallScanner

        scanner = SonicWallScanner(interface="eth0")
        # Exactly 54 bytes, no firmware field
        response = bytearray(54)
        response[40:44] = bytes([172, 16, 0, 1])
        response[44:48] = bytes([255, 255, 0, 0])
        response[48:54] = bytes.fromhex("112233445566")

        device = scanner._parse_response(bytes(response), "172.16.0.1")
        assert device is not None
        assert "sonicwall" in device.discovered_by
        assert "112233445566" in device.description


class TestSonicWallScannerScan:
    def test_scan_returns_empty_dict_on_no_responses(self):
        from oida.protocols.discovery.infra import SonicWallScanner

        scanner = SonicWallScanner(interface="nonexistent_interface_xyz", timeout=0.01)
        result = scanner.scan()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# DB2Scanner
# ---------------------------------------------------------------------------
class TestDB2ScannerInit:
    def test_valid_init(self):
        from oida.protocols.discovery.infra import DB2Scanner

        scanner = DB2Scanner(interface="eth0", timeout=5.0)
        assert scanner.interface == "eth0"
        assert scanner.timeout == 5.0
        assert scanner.discovered_devices == {}

    def test_init_invalid_interface_empty(self):
        from oida.protocols.discovery.infra import DB2Scanner

        with pytest.raises(ValueError, match="cannot be empty"):
            DB2Scanner(interface="")

    def test_init_invalid_timeout(self):
        from oida.protocols.discovery.infra import DB2Scanner

        with pytest.raises(ValueError, match="must be positive"):
            DB2Scanner(interface="eth0", timeout=0)

    def test_db2_constants(self):
        from oida.protocols.discovery.infra import DB2Scanner

        assert DB2Scanner.PORT == 523
        assert DB2Scanner.DISCOVERY_PROBE == b"DB2GETADDR\x00SQL09010\x00"


class TestDB2ScannerParseResponse:
    def test_valid_response(self):
        from oida.protocols.discovery.infra import DB2Scanner

        scanner = DB2Scanner(interface="eth0")
        response = b"DB2RETADDR\x00SQL11050\x00DBSERVER01\x00"

        device = scanner._parse_response(response, "192.168.1.50")

        assert device is not None
        assert device.ip_addresses == ["192.168.1.50"]
        assert device.manufacturer == "IBM"
        assert device.device_type == "Database Server"
        assert "db2" in device.discovered_by
        assert device.db2_data is not None
        assert device.db2_data["version"] == "SQL11050"
        assert device.db2_data["server_name"] == "DBSERVER01"
        assert "SQL11050" in device.description

    def test_no_db2retaddr_marker(self):
        from oida.protocols.discovery.infra import DB2Scanner

        scanner = DB2Scanner(interface="eth0")
        device = scanner._parse_response(b"SOMETHING_ELSE\x00", "192.168.1.1")
        assert device is None

    def test_empty_response(self):
        from oida.protocols.discovery.infra import DB2Scanner

        scanner = DB2Scanner(interface="eth0")
        device = scanner._parse_response(b"", "192.168.1.1")
        assert device is None

    def test_response_without_version(self):
        from oida.protocols.discovery.infra import DB2Scanner

        scanner = DB2Scanner(interface="eth0")
        response = b"DB2RETADDR\x00MYSERVER\x00"

        device = scanner._parse_response(response, "10.0.0.5")
        assert device is not None
        assert device.name == "MYSERVER"
        assert device.description == "IBM DB2"


class TestDB2ScannerScan:
    def test_scan_returns_empty_dict_on_no_responses(self):
        from oida.protocols.discovery.infra import DB2Scanner

        scanner = DB2Scanner(interface="nonexistent_interface_xyz", timeout=0.01)
        result = scanner.scan()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# SybaseScanner
# ---------------------------------------------------------------------------
class TestSybaseScannerInit:
    def test_valid_init(self):
        from oida.protocols.discovery.infra import SybaseScanner

        scanner = SybaseScanner(interface="eth0", timeout=5.0)
        assert scanner.interface == "eth0"
        assert scanner.timeout == 5.0
        assert scanner.discovered_devices == {}

    def test_init_invalid_interface_empty(self):
        from oida.protocols.discovery.infra import SybaseScanner

        with pytest.raises(ValueError, match="cannot be empty"):
            SybaseScanner(interface="")

    def test_init_invalid_timeout(self):
        from oida.protocols.discovery.infra import SybaseScanner

        with pytest.raises(ValueError, match="must be positive"):
            SybaseScanner(interface="eth0", timeout=0)

    def test_sybase_constants(self):
        from oida.protocols.discovery.infra import SybaseScanner

        assert SybaseScanner.PORT == 2638


class TestSybaseScannerBuildProbe:
    def test_probe_structure(self):
        from oida.protocols.discovery.infra import SybaseScanner

        scanner = SybaseScanner(interface="eth0")
        probe = scanner._build_probe()

        assert len(probe) == 61
        assert probe[0] == 0x1A  # TDS_MGMT type


class TestSybaseScannerParseResponse:
    def test_valid_response_with_name(self):
        from oida.protocols.discovery.infra import SybaseScanner

        scanner = SybaseScanner(interface="eth0")
        # Build a response with a readable server name
        response = b"\x1a\x00" + b"SYBASE_PROD" + b"\x00" * 20

        device = scanner._parse_response(response, "192.168.1.60")

        assert device is not None
        assert device.ip_addresses == ["192.168.1.60"]
        assert device.manufacturer == "SAP/Sybase"
        assert device.device_type == "Database Server"
        assert "sybase" in device.discovered_by
        assert device.sybase_data is not None

    def test_response_too_short(self):
        from oida.protocols.discovery.infra import SybaseScanner

        scanner = SybaseScanner(interface="eth0")
        device = scanner._parse_response(b"\x1a", "192.168.1.1")
        assert device is None

    def test_empty_response(self):
        from oida.protocols.discovery.infra import SybaseScanner

        scanner = SybaseScanner(interface="eth0")
        device = scanner._parse_response(b"", "192.168.1.1")
        assert device is None


class TestSybaseScannerScan:
    def test_scan_returns_empty_dict_on_no_responses(self):
        from oida.protocols.discovery.infra import SybaseScanner

        scanner = SybaseScanner(interface="nonexistent_interface_xyz", timeout=0.01)
        result = scanner.scan()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# XDMCPScanner
# ---------------------------------------------------------------------------
class TestXDMCPScannerInit:
    def test_valid_init(self):
        from oida.protocols.discovery.infra import XDMCPScanner

        scanner = XDMCPScanner(interface="eth0", timeout=5.0)
        assert scanner.interface == "eth0"
        assert scanner.timeout == 5.0
        assert scanner.discovered_devices == {}

    def test_init_invalid_interface_empty(self):
        from oida.protocols.discovery.infra import XDMCPScanner

        with pytest.raises(ValueError, match="cannot be empty"):
            XDMCPScanner(interface="")

    def test_init_invalid_timeout(self):
        from oida.protocols.discovery.infra import XDMCPScanner

        with pytest.raises(ValueError, match="must be positive"):
            XDMCPScanner(interface="eth0", timeout=0)

    def test_xdmcp_constants(self):
        from oida.protocols.discovery.infra import XDMCPScanner

        assert XDMCPScanner.PORT == 177


class TestXDMCPScannerBuildProbe:
    def test_probe_structure(self):
        from oida.protocols.discovery.infra import XDMCPScanner

        scanner = XDMCPScanner(interface="eth0")
        probe = scanner._build_probe()

        assert len(probe) == 7
        # version=1, opcode=3 (BroadcastQuery), length=1
        version, opcode, length = struct.unpack(">HHH", probe[:6])
        assert version == 1
        assert opcode == 3
        assert length == 1


class TestXDMCPScannerParseResponse:
    def test_valid_willing_response(self):
        from oida.protocols.discovery.infra import XDMCPScanner

        scanner = XDMCPScanner(interface="eth0")

        # Build WILLING response: version(2)+opcode(2)+length(2)+auth_len(2)+host_len(2)+host+status_len(2)+status
        hostname = b"workstation01"
        status = b"Linux 6.1"
        response = struct.pack(">HHH", 1, 5, 0)  # version=1, opcode=5 (WILLING)
        response += struct.pack(">H", 0)  # auth_name_len = 0
        response += struct.pack(">H", len(hostname)) + hostname
        response += struct.pack(">H", len(status)) + status

        device = scanner._parse_response(response, "192.168.1.70")

        assert device is not None
        assert device.ip_addresses == ["192.168.1.70"]
        assert device.device_type == "Display Manager"
        assert "xdmcp" in device.discovered_by
        assert device.xdmcp_data is not None
        assert device.xdmcp_data["hostname"] == "workstation01"
        assert device.xdmcp_data["status"] == "Linux 6.1"
        assert device.name == "workstation01"

    def test_wrong_opcode(self):
        from oida.protocols.discovery.infra import XDMCPScanner

        scanner = XDMCPScanner(interface="eth0")
        # opcode=3 (BROADCAST_QUERY, not WILLING)
        response = struct.pack(">HHH", 1, 3, 0)
        device = scanner._parse_response(response, "192.168.1.1")
        assert device is None

    def test_response_too_short(self):
        from oida.protocols.discovery.infra import XDMCPScanner

        scanner = XDMCPScanner(interface="eth0")
        device = scanner._parse_response(b"\x00\x01", "192.168.1.1")
        assert device is None

    def test_willing_with_auth_name(self):
        from oida.protocols.discovery.infra import XDMCPScanner

        scanner = XDMCPScanner(interface="eth0")
        auth = b"MIT-MAGIC-COOKIE-1"
        hostname = b"myhost"
        response = struct.pack(">HHH", 1, 5, 0)
        response += struct.pack(">H", len(auth)) + auth
        response += struct.pack(">H", len(hostname)) + hostname
        response += struct.pack(">H", 0)  # empty status

        device = scanner._parse_response(response, "10.0.0.1")
        assert device is not None
        assert device.xdmcp_data["hostname"] == "myhost"


class TestXDMCPScannerScan:
    def test_scan_returns_empty_dict_on_no_responses(self):
        from oida.protocols.discovery.infra import XDMCPScanner

        scanner = XDMCPScanner(interface="nonexistent_interface_xyz", timeout=0.01)
        result = scanner.scan()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# JenkinsScanner
# ---------------------------------------------------------------------------
class TestJenkinsScannerInit:
    def test_valid_init(self):
        from oida.protocols.discovery.infra import JenkinsScanner

        scanner = JenkinsScanner(interface="eth0", timeout=5.0)
        assert scanner.interface == "eth0"
        assert scanner.timeout == 5.0
        assert scanner.discovered_devices == {}

    def test_init_invalid_interface_empty(self):
        from oida.protocols.discovery.infra import JenkinsScanner

        with pytest.raises(ValueError, match="cannot be empty"):
            JenkinsScanner(interface="")

    def test_init_invalid_timeout(self):
        from oida.protocols.discovery.infra import JenkinsScanner

        with pytest.raises(ValueError, match="must be positive"):
            JenkinsScanner(interface="eth0", timeout=0)

    def test_jenkins_constants(self):
        from oida.protocols.discovery.infra import JenkinsScanner

        assert JenkinsScanner.PORT == 33848


class TestJenkinsScannerParseResponse:
    def test_valid_hudson_response(self):
        from oida.protocols.discovery.infra import JenkinsScanner

        scanner = JenkinsScanner(interface="eth0")
        response = (
            b"<hudson>"
            b"<version>2.426.3</version>"
            b"<url>http://192.168.1.80:8080/</url>"
            b"<server-id>abc123def456</server-id>"
            b"<slave-port>50000</slave-port>"
            b"</hudson>"
        )

        device = scanner._parse_response(response, "192.168.1.80")

        assert device is not None
        assert device.ip_addresses == ["192.168.1.80"]
        assert device.manufacturer == "Jenkins/CloudBees"
        assert device.device_type == "CI/CD Server"
        assert "jenkins" in device.discovered_by
        assert device.jenkins_data is not None
        assert device.jenkins_data["version"] == "2.426.3"
        assert device.jenkins_data["url"] == "http://192.168.1.80:8080/"
        assert device.jenkins_data["server_id"] == "abc123def456"
        assert device.jenkins_data["slave_port"] == "50000"
        assert "2.426.3" in device.description

    def test_jenkins_tag_response(self):
        from oida.protocols.discovery.infra import JenkinsScanner

        scanner = JenkinsScanner(interface="eth0")
        response = b"<jenkins><version>2.400</version></jenkins>"

        device = scanner._parse_response(response, "10.0.0.1")
        assert device is not None
        assert device.jenkins_data["version"] == "2.400"

    def test_non_jenkins_response(self):
        from oida.protocols.discovery.infra import JenkinsScanner

        scanner = JenkinsScanner(interface="eth0")
        device = scanner._parse_response(b"random garbage data", "192.168.1.1")
        assert device is None

    def test_empty_response(self):
        from oida.protocols.discovery.infra import JenkinsScanner

        scanner = JenkinsScanner(interface="eth0")
        device = scanner._parse_response(b"", "192.168.1.1")
        assert device is None

    def test_version_only_response(self):
        from oida.protocols.discovery.infra import JenkinsScanner

        scanner = JenkinsScanner(interface="eth0")
        response = b"<hudson><version>2.300</version></hudson>"

        device = scanner._parse_response(response, "10.0.0.5")
        assert device is not None
        assert device.jenkins_data["version"] == "2.300"
        assert "url" not in device.jenkins_data


class TestJenkinsScannerScan:
    def test_scan_returns_empty_dict_on_no_responses(self):
        from oida.protocols.discovery.infra import JenkinsScanner

        scanner = JenkinsScanner(interface="nonexistent_interface_xyz", timeout=0.01)
        result = scanner.scan()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# PCAnywhereScanner
# ---------------------------------------------------------------------------
class TestPCAnywhereScannerInit:
    def test_valid_init(self):
        from oida.protocols.discovery.infra import PCAnywhereScanner

        scanner = PCAnywhereScanner(interface="eth0", timeout=5.0)
        assert scanner.interface == "eth0"
        assert scanner.timeout == 5.0
        assert scanner.discovered_devices == {}

    def test_init_invalid_interface_empty(self):
        from oida.protocols.discovery.infra import PCAnywhereScanner

        with pytest.raises(ValueError, match="cannot be empty"):
            PCAnywhereScanner(interface="")

    def test_init_invalid_timeout(self):
        from oida.protocols.discovery.infra import PCAnywhereScanner

        with pytest.raises(ValueError, match="must be positive"):
            PCAnywhereScanner(interface="eth0", timeout=0)

    def test_pcanywhere_constants(self):
        from oida.protocols.discovery.infra import PCAnywhereScanner

        assert PCAnywhereScanner.PORT == 5632
        assert PCAnywhereScanner.NQ_PROBE == b"NQ"
        assert PCAnywhereScanner.ST_PROBE == b"ST"
        assert PCAnywhereScanner.DISCOVERY_PROBE == b"NQ"


class TestPCAnywhereScannerParseResponse:
    def test_valid_nr_response(self):
        from oida.protocols.discovery.infra import PCAnywhereScanner

        scanner = PCAnywhereScanner(interface="eth0")
        # Build Metasploit-style NR response: NR + 24-byte name + 8-byte caps
        name_field = b"WORKSTATION01" + b"\x00" * 11  # 24 bytes padded
        caps_field = b"AHM_____"  # 8 bytes
        response = b"NR" + name_field + caps_field

        device = scanner._parse_response(response, "192.168.1.90")

        assert device is not None
        assert device.ip_addresses == ["192.168.1.90"]
        assert device.manufacturer == "Symantec"
        assert device.device_type == "Remote Access"
        assert "pcanywhere" in device.discovered_by
        assert device.pcanywhere_data is not None
        assert device.pcanywhere_data["server_name"] == "WORKSTATION01"
        assert "capabilities" in device.pcanywhere_data
        assert device.name == "WORKSTATION01"

    def test_wrong_prefix(self):
        from oida.protocols.discovery.infra import PCAnywhereScanner

        scanner = PCAnywhereScanner(interface="eth0")
        device = scanner._parse_response(b"XX" + b"SERVER\x00", "192.168.1.1")
        assert device is None

    def test_response_too_short(self):
        from oida.protocols.discovery.infra import PCAnywhereScanner

        scanner = PCAnywhereScanner(interface="eth0")
        device = scanner._parse_response(b"N", "192.168.1.1")
        assert device is None

    def test_nr_only_no_name(self):
        from oida.protocols.discovery.infra import PCAnywhereScanner

        scanner = PCAnywhereScanner(interface="eth0")
        device = scanner._parse_response(b"NR\x00", "192.168.1.1")
        assert device is not None
        # Falls back to IP-based name
        assert "192.168.1.1" in device.name

    def test_st_response_available(self):
        from oida.protocols.discovery.infra import PCAnywhereScanner

        scanner = PCAnywhereScanner(interface="eth0")
        # Set up a discovered device first
        from oida.protocols.discovery.core import DiscoveredDevice

        scanner.discovered_devices["192.168.1.90"] = DiscoveredDevice(
            ip_addresses=["192.168.1.90"],
            pcanywhere_data={"server_name": "WS01"},
        )

        # Parse ST response: byte[4] = 0x43 (67) = Available
        st_data = b"ST\x00\x00\x43\x00\x00"
        scanner._parse_st_response(st_data, "192.168.1.90")

        assert scanner.discovered_devices["192.168.1.90"].pcanywhere_data["status"] == "Available"

    def test_st_response_busy(self):
        from oida.protocols.discovery.infra import PCAnywhereScanner

        scanner = PCAnywhereScanner(interface="eth0")
        from oida.protocols.discovery.core import DiscoveredDevice

        scanner.discovered_devices["10.0.0.1"] = DiscoveredDevice(
            ip_addresses=["10.0.0.1"],
            pcanywhere_data={"server_name": "SRV01"},
        )

        st_data = b"ST\x00\x00\x0b\x00\x00"
        scanner._parse_st_response(st_data, "10.0.0.1")

        assert scanner.discovered_devices["10.0.0.1"].pcanywhere_data["status"] == "Busy"


class TestPCAnywhereScannerScan:
    def test_scan_returns_empty_dict_on_no_responses(self):
        from oida.protocols.discovery.infra import PCAnywhereScanner

        scanner = PCAnywhereScanner(interface="nonexistent_interface_xyz", timeout=0.01)
        result = scanner.scan()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# DiscoveredDevice data fields
# ---------------------------------------------------------------------------
class TestInfraDataFields:
    """Test that all 9 new data fields exist on DiscoveredDevice"""

    def test_all_infra_fields_exist(self):
        from oida.protocols.discovery.core import DiscoveredDevice

        device = DiscoveredDevice()
        for field in [
            "hid_data",
            "mssql_data",
            "bjnp_data",
            "sonicwall_data",
            "db2_data",
            "sybase_data",
            "xdmcp_data",
            "jenkins_data",
            "pcanywhere_data",
        ]:
            assert hasattr(device, field), f"Missing field: {field}"
            assert getattr(device, field) is None

    def test_field_assignment(self):
        from oida.protocols.discovery.core import DiscoveredDevice

        device = DiscoveredDevice(
            hid_data={"mac_address": "00:11:22:33:44:55"},
            jenkins_data={"version": "2.400"},
        )
        assert device.hid_data["mac_address"] == "00:11:22:33:44:55"
        assert device.jenkins_data["version"] == "2.400"


# ---------------------------------------------------------------------------
# DiscoveredDevice merge_from for infra fields
# ---------------------------------------------------------------------------
class TestInfraMerge:
    """Test merge_from logic for all 9 infra data fields"""

    def test_merge_infra_fields_from_empty(self):
        from oida.protocols.discovery.core import DiscoveredDevice

        device1 = DiscoveredDevice(ip_addresses=["192.168.1.1"])
        device2 = DiscoveredDevice(
            ip_addresses=["192.168.1.1"],
            hid_data={"model": "iCLASS"},
            mssql_data={"version": "16.0"},
            bjnp_data={"type": 1},
            sonicwall_data={"serial": "abc"},
            db2_data={"version": "SQL11"},
            sybase_data={"instance_name": "ASA"},
            xdmcp_data={"hostname": "ws01"},
            jenkins_data={"version": "2.400"},
            pcanywhere_data={"server_name": "PC01"},
        )

        updated = device1.merge_from(device2)

        assert "hid_data" in updated
        assert "mssql_data" in updated
        assert "bjnp_data" in updated
        assert "sonicwall_data" in updated
        assert "db2_data" in updated
        assert "sybase_data" in updated
        assert "xdmcp_data" in updated
        assert "jenkins_data" in updated
        assert "pcanywhere_data" in updated

        assert device1.hid_data == {"model": "iCLASS"}
        assert device1.jenkins_data == {"version": "2.400"}

    def test_merge_infra_fields_no_overwrite(self):
        from oida.protocols.discovery.core import DiscoveredDevice

        device1 = DiscoveredDevice(
            ip_addresses=["10.0.0.1"],
            jenkins_data={"version": "2.300"},
            mssql_data={"version": "15.0"},
        )
        device2 = DiscoveredDevice(
            ip_addresses=["10.0.0.1"],
            jenkins_data={"version": "2.400"},
            mssql_data={"version": "16.0"},
        )

        updated = device1.merge_from(device2)

        # Existing data should NOT be overwritten
        assert "jenkins_data" not in updated
        assert "mssql_data" not in updated
        assert device1.jenkins_data["version"] == "2.300"
        assert device1.mssql_data["version"] == "15.0"


# ---------------------------------------------------------------------------
# DiscoveryScanner enable flags
# ---------------------------------------------------------------------------
class TestInfraEnableFlags:
    """Test DiscoveryScanner enable flags for infra probes"""

    def test_infra_enabled_in_active_mode(self):
        from oida.protocols.discovery.scanner import DiscoveryScanner

        scanner = DiscoveryScanner({"target": "eth0", "active": True})

        for name in [
            "hid",
            "mssql",
            "bjnp",
            "sonicwall",
            "db2",
            "sybase",
            "xdmcp",
            "jenkins",
            "pcanywhere",
        ]:
            assert getattr(scanner, f"enable_{name}") is True, f"enable_{name} should be True"

    def test_infra_disabled_in_passive_mode(self):
        from oida.protocols.discovery.scanner import DiscoveryScanner

        scanner = DiscoveryScanner({"target": "eth0"})  # passive only

        for name in [
            "hid",
            "mssql",
            "bjnp",
            "sonicwall",
            "db2",
            "sybase",
            "xdmcp",
            "jenkins",
            "pcanywhere",
        ]:
            assert getattr(scanner, f"enable_{name}") is False, f"enable_{name} should be False"

    def test_infra_disabled_in_arp_only_mode(self):
        from oida.protocols.discovery.scanner import DiscoveryScanner

        scanner = DiscoveryScanner({"target": "eth0", "arp": True})

        for name in [
            "hid",
            "mssql",
            "bjnp",
            "sonicwall",
            "db2",
            "sybase",
            "xdmcp",
            "jenkins",
            "pcanywhere",
        ]:
            assert getattr(scanner, f"enable_{name}") is False, f"enable_{name} should be False"

    def test_individual_toggle_flags(self):
        from oida.protocols.discovery.scanner import DiscoveryScanner

        scanner = DiscoveryScanner(
            {
                "target": "eth0",
                "active": True,
                "no-mssql": True,
                "no-bjnp": True,
                "no-jenkins": True,
            }
        )

        assert scanner.enable_mssql is False
        assert scanner.enable_bjnp is False
        assert scanner.enable_jenkins is False
        # Others still enabled
        assert scanner.enable_hid is True
        assert scanner.enable_sonicwall is True
        assert scanner.enable_db2 is True
        assert scanner.enable_sybase is True
        assert scanner.enable_xdmcp is True
        assert scanner.enable_pcanywhere is True


# ---------------------------------------------------------------------------
# Scanner registry entries
# ---------------------------------------------------------------------------
class TestInfraScannerRegistry:
    """Test that infra scanners are registered in _SCANNER_CONFIGS"""

    def test_all_infra_in_scanner_configs(self):
        from oida.protocols.discovery.scanner import _SCANNER_CONFIGS

        for name in [
            "hid",
            "mssql",
            "bjnp",
            "sonicwall",
            "db2",
            "sybase",
            "xdmcp",
            "jenkins",
            "pcanywhere",
        ]:
            assert name in _SCANNER_CONFIGS, f"{name} not in _SCANNER_CONFIGS"
            config = _SCANNER_CONFIGS[name]
            assert config[3] == "broadcast", f"{name} should be category 'broadcast'"
            assert config[2] == 10, f"{name} should have timeout_limit 10"


# ---------------------------------------------------------------------------
# Protocol field mapping in core.py
# ---------------------------------------------------------------------------
class TestInfraFieldMapping:
    """Test that protocol->field mapping works for infra scanners"""

    def test_create_device_with_protocol_data(self):
        from oida.protocols.discovery.core import DiscoveredDevice

        # Verify all infra fields can be set via constructor
        for proto, field in [
            ("hid", "hid_data"),
            ("mssql", "mssql_data"),
            ("bjnp", "bjnp_data"),
            ("sonicwall", "sonicwall_data"),
            ("db2", "db2_data"),
            ("sybase", "sybase_data"),
            ("xdmcp", "xdmcp_data"),
            ("jenkins", "jenkins_data"),
            ("pcanywhere", "pcanywhere_data"),
        ]:
            kwargs = {field: {"test": True}, "discovered_by": [proto]}
            device = DiscoveredDevice(**kwargs)
            assert getattr(device, field) == {"test": True}
            assert proto in device.discovered_by


# ---------------------------------------------------------------------------
# Lazy imports from __init__.py
# ---------------------------------------------------------------------------
class TestInfraLazyImports:
    """Test that all scanner classes are importable from the package"""

    def test_all_scanners_importable(self):
        from oida.protocols.discovery import (
            HIDScanner,
            MSSQLBrowserScanner,
            BJNPScanner,
            SonicWallScanner,
            DB2Scanner,
            SybaseScanner,
            XDMCPScanner,
            JenkinsScanner,
            PCAnywhereScanner,
        )

        # Verify they're actual classes
        for cls in [
            HIDScanner,
            MSSQLBrowserScanner,
            BJNPScanner,
            SonicWallScanner,
            DB2Scanner,
            SybaseScanner,
            XDMCPScanner,
            JenkinsScanner,
            PCAnywhereScanner,
        ]:
            assert callable(cls)
