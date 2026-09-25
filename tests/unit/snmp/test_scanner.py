"""
Tests for SNMPScanner class (pysnmp v7 API)
"""

import pytest

pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")


@pytest.fixture
def snmp_scanner_class():
    """Get SNMPScanner class"""
    from oida.protocols.snmp.scanner import SNMPScanner

    return SNMPScanner


@pytest.fixture
def snmp_constants():
    """Get SNMP constants module"""
    from oida.protocols.snmp import constants

    return constants


class TestSNMPScannerInit:
    """Test SNMPScanner initialization"""

    def test_default_parameters(self, snmp_scanner_class):
        """Test scanner with default parameters"""
        scanner = snmp_scanner_class({"rhost": "192.168.1.1"})

        assert scanner.port == 161
        assert scanner.community == "public"
        assert scanner.version == "2c"

    def test_custom_community(self, snmp_scanner_class):
        """Test scanner with custom community string"""
        scanner = snmp_scanner_class({"rhost": "192.168.1.1", "community": "private"})

        assert scanner.community == "private"

    def test_snmpv3_parameters(self, snmp_scanner_class):
        """Test scanner with SNMPv3 parameters"""
        scanner = snmp_scanner_class(
            {
                "rhost": "192.168.1.1",
                "snmp_version": "3",
                "snmp_user": "admin",
                "snmp_auth_pass": "authpass",
                "snmp_priv_pass": "privpass",
                "snmp_auth_protocol": "SHA",
                "snmp_priv_protocol": "AES128",
            }
        )

        assert scanner.version == "3"
        assert scanner.username == "admin"
        assert scanner.auth_pass == "authpass"
        assert scanner.priv_pass == "privpass"


class TestVendorOIDs:
    """Test vendor OID mappings"""

    def test_vendor_oids_dict_exists(self, snmp_constants):
        """Test that VENDOR_OIDS dict exists and has entries"""
        assert hasattr(snmp_constants, "VENDOR_OIDS")
        assert isinstance(snmp_constants.VENDOR_OIDS, dict)
        assert len(snmp_constants.VENDOR_OIDS) > 50

    def test_siemens_pen(self, snmp_constants):
        """Test Siemens enterprise PEN mapping"""
        assert "4329" in snmp_constants.VENDOR_OIDS
        assert snmp_constants.VENDOR_OIDS["4329"] == "Siemens"

    def test_schneider_pen(self, snmp_constants):
        """Test Schneider enterprise PEN mapping"""
        assert "3833" in snmp_constants.VENDOR_OIDS
        assert snmp_constants.VENDOR_OIDS["3833"] == "Schneider"

    def test_moxa_pen(self, snmp_constants):
        """Test Moxa enterprise PEN mapping"""
        assert "8691" in snmp_constants.VENDOR_OIDS
        assert snmp_constants.VENDOR_OIDS["8691"] == "Moxa"

    def test_hirschmann_pen(self, snmp_constants):
        """Test Hirschmann enterprise PEN mapping"""
        assert "248" in snmp_constants.VENDOR_OIDS
        assert snmp_constants.VENDOR_OIDS["248"] == "Hirschmann"


class TestVendorSpecificOIDs:
    """Test vendor-specific OID definitions"""

    def test_vendor_specific_oids_exists(self, snmp_constants):
        """Test that VENDOR_SPECIFIC_OIDS dict exists"""
        assert hasattr(snmp_constants, "VENDOR_SPECIFIC_OIDS")
        assert isinstance(snmp_constants.VENDOR_SPECIFIC_OIDS, dict)
        assert len(snmp_constants.VENDOR_SPECIFIC_OIDS) > 30

    def test_siemens_oids(self, snmp_constants):
        """Test Siemens vendor-specific OIDs"""
        assert "Siemens" in snmp_constants.VENDOR_SPECIFIC_OIDS
        siemens = snmp_constants.VENDOR_SPECIFIC_OIDS["Siemens"]

        assert "Serial" in siemens
        assert "SW_Version" in siemens
        assert siemens["Serial"].startswith(".1.3.6.1.4.1.4329")

    def test_moxa_oids(self, snmp_constants):
        """Test Moxa vendor-specific OIDs (verified from LibreNMS)"""
        assert "Moxa" in snmp_constants.VENDOR_SPECIFIC_OIDS
        moxa = snmp_constants.VENDOR_SPECIFIC_OIDS["Moxa"]

        assert "Serial" in moxa
        assert "FW_Version" in moxa
        assert ".1.3.6.1.4.1.8691" in moxa["Serial"]

    def test_hirschmann_oids(self, snmp_constants):
        """Test Hirschmann vendor-specific OIDs (verified from LibreNMS)"""
        assert "Hirschmann" in snmp_constants.VENDOR_SPECIFIC_OIDS
        hirschmann = snmp_constants.VENDOR_SPECIFIC_OIDS["Hirschmann"]

        assert "Serial" in hirschmann
        assert "FW_Version" in hirschmann
        assert "SW_Version" in hirschmann
        assert ".1.3.6.1.4.1.248" in hirschmann["Serial"]

    def test_eaton_oids(self, snmp_constants):
        """Test Eaton vendor-specific OIDs (verified from LibreNMS XUPS-MIB)"""
        assert "Eaton" in snmp_constants.VENDOR_SPECIFIC_OIDS
        eaton = snmp_constants.VENDOR_SPECIFIC_OIDS["Eaton"]

        assert "Model" in eaton
        assert "Serial" in eaton
        assert "FW_Version" in eaton
        assert eaton["Serial"].endswith(".6.0")


class TestARPTableParsing:
    """Test ARP table extraction"""

    def test_arp_table_method_exists(self, snmp_scanner_class):
        """Test that _get_arp_table method exists"""
        scanner = snmp_scanner_class({"rhost": "192.168.1.1"})
        assert hasattr(scanner, "_get_arp_table")


class TestMACTableParsing:
    """Test MAC table (CAM table) extraction"""

    def test_mac_table_method_exists(self, snmp_scanner_class):
        """Test that _get_mac_table method exists"""
        scanner = snmp_scanner_class({"rhost": "192.168.1.1"})
        assert hasattr(scanner, "_get_mac_table")


class TestVendorDetection:
    """Test vendor detection from sysObjectID"""

    def test_detect_siemens_scalance(self, snmp_constants):
        """Test detection of Siemens SCALANCE from sysObjectID"""
        sys_object_id = "1.3.6.1.4.1.4329.6.3.1"

        parts = sys_object_id.split(".")
        if len(parts) >= 7:
            pen = parts[6]
            vendor = snmp_constants.VENDOR_OIDS.get(pen, "Unknown")
            assert vendor == "Siemens"

    def test_detect_hirschmann(self, snmp_constants):
        """Test detection of Hirschmann from sysObjectID"""
        sys_object_id = "1.3.6.1.4.1.248.14.1.1"

        parts = sys_object_id.split(".")
        if len(parts) >= 7:
            pen = parts[6]
            vendor = snmp_constants.VENDOR_OIDS.get(pen, "Unknown")
            assert vendor == "Hirschmann"


class TestSNMPVersions:
    """Test SNMP version handling"""

    def test_snmpv1_config(self, snmp_scanner_class):
        """Test SNMPv1 configuration"""
        scanner = snmp_scanner_class({"rhost": "192.168.1.1", "snmp_version": "1"})
        assert scanner.version == "1"

    def test_snmpv2c_config(self, snmp_scanner_class):
        """Test SNMPv2c configuration"""
        scanner = snmp_scanner_class({"rhost": "192.168.1.1", "snmp_version": "2c"})
        assert scanner.version == "2c"

    def test_snmpv3_noauthnopriv(self, snmp_scanner_class):
        """Test SNMPv3 noAuthNoPriv"""
        scanner = snmp_scanner_class(
            {
                "rhost": "192.168.1.1",
                "snmp_version": "3",
                "snmp_user": "user",
            }
        )
        assert scanner.version == "3"
        assert scanner.username == "user"

    def test_snmpv3_authpriv(self, snmp_scanner_class):
        """Test SNMPv3 authPriv"""
        scanner = snmp_scanner_class(
            {
                "rhost": "192.168.1.1",
                "snmp_version": "3",
                "snmp_user": "admin",
                "snmp_auth_pass": "authpass123",
                "snmp_priv_pass": "privpass123",
                "snmp_auth_protocol": "SHA",
                "snmp_priv_protocol": "AES128",
            }
        )
        assert scanner.auth_pass == "authpass123"
        assert scanner.priv_pass == "privpass123"


class TestStandardOIDs:
    """Test standard MIB-II OIDs"""

    def test_sysdescr_oid(self, snmp_constants):
        """Test sysDescr OID"""
        assert "sysDescr" in snmp_constants.SNMP_OIDS
        assert snmp_constants.SNMP_OIDS["sysDescr"] == ".1.3.6.1.2.1.1.1.0"

    def test_sysobjectid_oid(self, snmp_constants):
        """Test sysObjectID OID"""
        assert "sysObjectID" in snmp_constants.SNMP_OIDS
        assert snmp_constants.SNMP_OIDS["sysObjectID"] == ".1.3.6.1.2.1.1.2.0"

    def test_sysname_oid(self, snmp_constants):
        """Test sysName OID"""
        assert "sysName" in snmp_constants.SNMP_OIDS
        assert snmp_constants.SNMP_OIDS["sysName"] == ".1.3.6.1.2.1.1.5.0"


class TestDefaultCommunities:
    """Test default community string list"""

    def test_default_communities_removed(self, snmp_constants):
        """DEFAULT_COMMUNITIES was removed - communities are built-in to scanner."""
        assert not hasattr(snmp_constants, "DEFAULT_COMMUNITIES")


class TestEnumUsersFlag:
    """Test --enum-users flag initialization and _enum_v3_users method."""

    def test_enum_users_default_false(self, snmp_scanner_class):
        """Test enum_users defaults to False when not specified."""
        scanner = snmp_scanner_class({"rhost": "192.168.1.1"})
        assert scanner.enum_users is False

    def test_enum_users_set_true(self, snmp_scanner_class):
        """Test enum_users is True when --enum-users is passed."""
        scanner = snmp_scanner_class({"rhost": "192.168.1.1", "enum_users": True})
        assert scanner.enum_users is True

    def test_enum_users_has_method(self, snmp_scanner_class):
        """Test _enum_v3_users method exists on scanner."""
        scanner = snmp_scanner_class({"rhost": "192.168.1.1"})
        assert hasattr(scanner, "_enum_v3_users")
        assert callable(scanner._enum_v3_users)

    def test_enum_users_coexists_with_enum_v3(self, snmp_scanner_class):
        """Test enum_users and enum_v3 are independent flags."""
        scanner = snmp_scanner_class(
            {
                "rhost": "192.168.1.1",
                "enum_users": True,
                "enum_v3": "",
            }
        )
        assert scanner.enum_users is True
        assert scanner.enum_v3 is True
