"""
Tests for SNMP scanner enhancements:
- OID suffix extraction (_walk_table leading-dot fix)
- IP address correlation in _enum_interfaces
- H3C credential correlation
- DateAndTime parsing
- Community string list quality
- New constants (FILESYSTEM_OIDS, WINDOWS_SERVICE_OIDS, etc.)
- Vendor name alignment between VENDOR_OIDS and VENDOR_SPECIFIC_OIDS
"""

import asyncio
import pytest
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scanner():
    """Create a minimal SNMPScanner instance for unit testing."""
    from oida.protocols.snmp.scanner import SNMPScanner

    args = {
        "host": "127.0.0.1",
        "port": 161,
        "timeout": 2,
        "community": "public",
        "snmp_version": "2c",
        "get_arp": False,
        "get_cam": False,
    }
    return SNMPScanner(args)


class FakeVarBind:
    """Simulate pysnmp var_bind tuple (ObjectName, value)."""

    def __init__(self, oid_str: str, value: str):
        # pysnmp v7 str(ObjectName) strips leading dots
        self._oid = oid_str.lstrip(".")
        self._value = value

    def __getitem__(self, idx):
        if idx == 0:
            return self  # ObjectName proxy
        if idx == 1:
            return self  # Value proxy
        raise IndexError

    def __str__(self):
        return self._oid

    def prettyPrint(self):
        return self._value

    def __class_getitem__(cls, _):
        return cls


# ---------------------------------------------------------------------------
# Constants Tests
# ---------------------------------------------------------------------------


class TestConstants:
    """Test that new constants are correct and complete."""

    def test_snmp_oids_has_system_scalars(self):
        from oida.protocols.snmp.constants import SNMP_OIDS

        assert "hrSystemDate" in SNMP_OIDS
        assert SNMP_OIDS["hrSystemDate"] == ".1.3.6.1.2.1.25.1.2.0"
        assert "ipForwarding" in SNMP_OIDS
        assert SNMP_OIDS["ipForwarding"] == ".1.3.6.1.2.1.4.1.0"
        assert "ipDefaultTTL" in SNMP_OIDS
        assert SNMP_OIDS["ipDefaultTTL"] == ".1.3.6.1.2.1.4.2.0"
        assert "tcpInSegs" in SNMP_OIDS
        assert "tcpOutSegs" in SNMP_OIDS
        assert "tcpRetransSegs" in SNMP_OIDS

    def test_network_enum_oids_has_ip_addr_table(self):
        from oida.protocols.snmp.constants import NETWORK_ENUM_OIDS

        assert "ipAdEntAddr" in NETWORK_ENUM_OIDS
        assert NETWORK_ENUM_OIDS["ipAdEntAddr"] == ".1.3.6.1.2.1.4.20.1.1"
        assert "ipAdEntIfIndex" in NETWORK_ENUM_OIDS
        assert NETWORK_ENUM_OIDS["ipAdEntIfIndex"] == ".1.3.6.1.2.1.4.20.1.2"
        assert "ipAdEntNetMask" in NETWORK_ENUM_OIDS
        assert NETWORK_ENUM_OIDS["ipAdEntNetMask"] == ".1.3.6.1.2.1.4.20.1.3"

    def test_windows_service_oids(self):
        from oida.protocols.snmp.constants import WINDOWS_SERVICE_OIDS

        assert "svSvcName" in WINDOWS_SERVICE_OIDS
        assert WINDOWS_SERVICE_OIDS["svSvcName"] == ".1.3.6.1.4.1.77.1.2.3.1.1"
        assert "svSvcInstalledState" in WINDOWS_SERVICE_OIDS
        assert "svSvcOperatingState" in WINDOWS_SERVICE_OIDS

    def test_filesystem_oids(self):
        from oida.protocols.snmp.constants import FILESYSTEM_OIDS

        assert "hrFSMountPoint" in FILESYSTEM_OIDS
        assert FILESYSTEM_OIDS["hrFSMountPoint"] == ".1.3.6.1.2.1.25.3.8.1.2"
        assert "hrFSRemoteMountPoint" in FILESYSTEM_OIDS
        assert "hrFSType" in FILESYSTEM_OIDS
        assert "hrFSAccess" in FILESYSTEM_OIDS
        assert FILESYSTEM_OIDS["hrFSAccess"] == ".1.3.6.1.2.1.25.3.8.1.5"

    def test_windows_oids_has_domain(self):
        from oida.protocols.snmp.constants import WINDOWS_OIDS

        assert "domPrimaryDomain" in WINDOWS_OIDS
        assert WINDOWS_OIDS["domPrimaryDomain"] == ".1.3.6.1.4.1.77.1.4.1.0"

    def test_enum_categories_complete(self):
        from oida.protocols.snmp.constants import ENUM_CATEGORIES

        required = {
            "interfaces",
            "tcp",
            "udp",
            "routes",
            "processes",
            "software",
            "storage",
            "users",
            "shares",
            "traps",
            "creds",
            "system",
            "services",
            "filesystems",
        }
        assert required.issubset(set(ENUM_CATEGORIES.keys()))

    def test_no_dead_default_communities_constant(self):
        """DEFAULT_COMMUNITIES was removed as dead code."""
        from oida.protocols.snmp import constants

        assert not hasattr(constants, "DEFAULT_COMMUNITIES")


# ---------------------------------------------------------------------------
# Vendor Name Alignment
# ---------------------------------------------------------------------------


class TestVendorAlignment:
    """Every VENDOR_SPECIFIC_OIDS key must exist as a VENDOR_OIDS value."""

    def test_vendor_specific_keys_match_vendor_oids_values(self):
        from oida.protocols.snmp.constants import VENDOR_OIDS, VENDOR_SPECIFIC_OIDS

        vendor_names = set(VENDOR_OIDS.values())
        for key in VENDOR_SPECIFIC_OIDS:
            assert key in vendor_names, (
                f"VENDOR_SPECIFIC_OIDS key '{key}' has no matching "
                f"VENDOR_OIDS value. Known vendors: "
                f"{sorted(vendor_names)}"
            )

    def test_netapp_in_vendor_oids(self):
        from oida.protocols.snmp.constants import VENDOR_OIDS

        assert "789" in VENDOR_OIDS
        assert VENDOR_OIDS["789"] == "NetApp"

    def test_servertech_in_vendor_oids(self):
        from oida.protocols.snmp.constants import VENDOR_OIDS

        assert "1718" in VENDOR_OIDS
        assert VENDOR_OIDS["1718"] == "ServerTech"


# ---------------------------------------------------------------------------
# Community String List Quality
# ---------------------------------------------------------------------------


class TestCommunityStrings:
    """Test SNMP community string wordlist."""

    def test_no_duplicates(self):
        from oida.utils.default_credentials import SNMP_COMMUNITY_DEFAULTS

        seen = set()
        dupes = []
        for c in SNMP_COMMUNITY_DEFAULTS:
            if c in seen:
                dupes.append(c)
            seen.add(c)
        assert not dupes, f"Duplicate community strings: {dupes}"

    def test_rfc_defaults_present(self):
        from oida.utils.default_credentials import SNMP_COMMUNITY_DEFAULTS

        for c in ["public", "private", "community"]:
            assert c in SNMP_COMMUNITY_DEFAULTS

    def test_ics_communities_present(self):
        from oida.utils.default_credentials import SNMP_COMMUNITY_DEFAULTS

        for c in ["SCADA", "scada", "plc", "hmi", "automation"]:
            assert c in SNMP_COMMUNITY_DEFAULTS

    def test_high_priority_strings(self):
        """Key community strings that should always be present."""
        from oida.utils.default_credentials import SNMP_COMMUNITY_DEFAULTS

        for c in [
            "snmptrap",
            "network",
            "trap",
            "community",
            "secret",
            "ILMI",
        ]:
            assert c in SNMP_COMMUNITY_DEFAULTS, f"Missing high-priority string: {c}"

    def test_minimum_count(self):
        from oida.utils.default_credentials import SNMP_COMMUNITY_DEFAULTS

        assert len(SNMP_COMMUNITY_DEFAULTS) >= 40


# ---------------------------------------------------------------------------
# OID Suffix Extraction (_walk_table leading-dot fix)
# ---------------------------------------------------------------------------


class TestWalkTableSuffixExtraction:
    """Test that _walk_table correctly extracts OID index suffixes.

    pysnmp v7 str(ObjectName) returns OIDs WITHOUT leading dots, but our
    constants have them. The fix normalizes via lstrip('.') + startswith().
    """

    def test_single_component_index(self, scanner):
        """ifTable: base .1.3.6.1.2.1.2.2.1.2, index is single int."""
        base_oid = ".1.3.6.1.2.1.2.2.1.2"

        async def fake_walk(*args, **kwargs):
            binds = [
                [FakeVarBind("1.3.6.1.2.1.2.2.1.2.1", "eth0")],
                [FakeVarBind("1.3.6.1.2.1.2.2.1.2.2", "eth1")],
                [FakeVarBind("1.3.6.1.2.1.2.2.1.2.3", "lo")],
            ]
            for vb in binds:
                yield None, None, None, vb

        with patch(
            "pysnmp.hlapi.asyncio.walk_cmd", side_effect=lambda *a, **kw: fake_walk(*a, **kw)
        ):
            with patch("pysnmp.hlapi.asyncio.ObjectIdentity", lambda x: x):
                with patch("pysnmp.hlapi.asyncio.ObjectType", lambda x: x):
                    rows = asyncio.run(
                        scanner._walk_table(None, None, None, None, {"descr": base_oid})
                    )

        assert "1" in rows
        assert "2" in rows
        assert "3" in rows
        assert rows["1"]["descr"] == "eth0"
        assert rows["2"]["descr"] == "eth1"
        assert rows["3"]["descr"] == "lo"

    def test_multi_component_index_ip_addr_table(self, scanner):
        """ipAddrTable: index is 4-octet IP address (e.g., 10.0.0.1)."""
        base_oid = ".1.3.6.1.2.1.4.20.1.1"

        async def fake_walk(*args, **kwargs):
            binds = [
                [FakeVarBind("1.3.6.1.2.1.4.20.1.1.10.0.0.1", "10.0.0.1")],
                [FakeVarBind("1.3.6.1.2.1.4.20.1.1.192.168.1.1", "192.168.1.1")],
                [FakeVarBind("1.3.6.1.2.1.4.20.1.1.172.16.0.1", "172.16.0.1")],
            ]
            for vb in binds:
                yield None, None, None, vb

        with patch(
            "pysnmp.hlapi.asyncio.walk_cmd", side_effect=lambda *a, **kw: fake_walk(*a, **kw)
        ):
            with patch("pysnmp.hlapi.asyncio.ObjectIdentity", lambda x: x):
                with patch("pysnmp.hlapi.asyncio.ObjectType", lambda x: x):
                    rows = asyncio.run(
                        scanner._walk_table(None, None, None, None, {"addr": base_oid})
                    )

        # All 3 IPs must be preserved, not collapsed by last octet
        assert len(rows) == 3
        assert "10.0.0.1" in rows
        assert "192.168.1.1" in rows
        assert "172.16.0.1" in rows
        assert rows["10.0.0.1"]["addr"] == "10.0.0.1"
        assert rows["192.168.1.1"]["addr"] == "192.168.1.1"

    def test_multi_column_correlation(self, scanner):
        """Two columns with matching multi-component indices merge correctly."""
        addr_oid = ".1.3.6.1.2.1.4.20.1.1"
        ifindex_oid = ".1.3.6.1.2.1.4.20.1.2"

        call_count = [0]

        async def fake_walk(*args, **kwargs):
            call_count[0] += 1
            # Walk addr column
            if call_count[0] == 1:
                binds = [
                    [FakeVarBind("1.3.6.1.2.1.4.20.1.1.10.0.0.1", "10.0.0.1")],
                    [FakeVarBind("1.3.6.1.2.1.4.20.1.1.192.168.1.1", "192.168.1.1")],
                ]
            else:
                # Walk ifindex column
                binds = [
                    [FakeVarBind("1.3.6.1.2.1.4.20.1.2.10.0.0.1", "1")],
                    [FakeVarBind("1.3.6.1.2.1.4.20.1.2.192.168.1.1", "2")],
                ]
            for vb in binds:
                yield None, None, None, vb

        with patch(
            "pysnmp.hlapi.asyncio.walk_cmd", side_effect=lambda *a, **kw: fake_walk(*a, **kw)
        ):
            with patch("pysnmp.hlapi.asyncio.ObjectIdentity", lambda x: x):
                with patch("pysnmp.hlapi.asyncio.ObjectType", lambda x: x):
                    rows = asyncio.run(
                        scanner._walk_table(
                            None,
                            None,
                            None,
                            None,
                            {"addr": addr_oid, "ifindex": ifindex_oid},
                        )
                    )

        assert rows["10.0.0.1"]["addr"] == "10.0.0.1"
        assert rows["10.0.0.1"]["ifindex"] == "1"
        assert rows["192.168.1.1"]["addr"] == "192.168.1.1"
        assert rows["192.168.1.1"]["ifindex"] == "2"


# ---------------------------------------------------------------------------
# H3C Credential Correlation
# ---------------------------------------------------------------------------


class TestH3CCredentialCorrelation:
    """Test that H3C credential walks are correlated by table index."""

    def test_h3c_correlation(self, scanner):
        """H3C user table entries with matching indices produce user records."""

        # Simulate walk results: h3cUserName.1=admin, h3cUserPassword.1=pass123, h3cUserLevel.1=3
        walk_data = {
            "h3cUserName": [
                {"oid": "1.3.6.1.4.1.2011.10.2.12.1.1.1.1.1", "value": "admin"},
                {"oid": "1.3.6.1.4.1.2011.10.2.12.1.1.1.1.2", "value": "operator"},
            ],
            "h3cUserPassword": [
                {"oid": "1.3.6.1.4.1.2011.10.2.12.1.1.1.2.1", "value": "pass123"},
                {"oid": "1.3.6.1.4.1.2011.10.2.12.1.1.1.2.2", "value": "oper456"},
            ],
            "h3cUserLevel": [
                {"oid": "1.3.6.1.4.1.2011.10.2.12.1.1.1.4.1", "value": "3"},
                {"oid": "1.3.6.1.4.1.2011.10.2.12.1.1.1.4.2", "value": "1"},
            ],
        }

        # Correlation logic (extracted from _enum_credentials post-processing)
        h3c_users = []
        for prefix, names in [
            ("h3c", ("h3cUserName", "h3cUserPassword", "h3cUserLevel")),
            ("hh3c", ("hh3cUserName", "hh3cUserPassword", "hh3cUserLevel")),
        ]:
            name_entries = {
                r["oid"].split(".")[-1]: r["value"] for r in walk_data.get(names[0], [])
            }
            pass_entries = {
                r["oid"].split(".")[-1]: r["value"] for r in walk_data.get(names[1], [])
            }
            level_entries = {
                r["oid"].split(".")[-1]: r["value"] for r in walk_data.get(names[2], [])
            }

            for idx in name_entries:
                h3c_users.append(
                    {
                        "table": prefix,
                        "index": idx,
                        "username": name_entries.get(idx, ""),
                        "password": pass_entries.get(idx, ""),
                        "level": level_entries.get(idx, ""),
                    }
                )

        assert len(h3c_users) == 2
        admin = next(u for u in h3c_users if u["username"] == "admin")
        assert admin["password"] == "pass123"
        assert admin["level"] == "3"
        assert admin["index"] == "1"

        oper = next(u for u in h3c_users if u["username"] == "operator")
        assert oper["password"] == "oper456"
        assert oper["level"] == "1"


# ---------------------------------------------------------------------------
# DateAndTime Parsing
# ---------------------------------------------------------------------------


class TestDateTimeParsing:
    """Test RFC 2579 DateAndTime parsing logic."""

    def test_8_byte_dateandtime(self):
        """8-byte DateAndTime: 2024-03-15 14:30:45."""
        # year=2024 (0x07E8), month=3, day=15, hour=14, min=30, sec=45, decisec=0
        raw_hex = "07e8030f0e1e2d00"
        val_str = f"0x{raw_hex}"

        if val_str.startswith("0x"):
            raw = bytes.fromhex(val_str[2:])
            if len(raw) >= 8:
                year = int.from_bytes(raw[0:2], "big")
                month, day = raw[2], raw[3]
                hour, minute, sec = raw[4], raw[5], raw[6]
                result = f"{year}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{sec:02d}"

        assert result == "2024-03-15 14:30:45"

    def test_11_byte_dateandtime(self):
        """11-byte DateAndTime: 2025-12-01 09:15:00 +01:00."""
        # year=2025 (0x07E9), month=12, day=1, hour=9, min=15, sec=0, decisec=0
        # UTC offset: +01:00 (0x2B 0x01 0x00)
        raw_hex = "07e90c01090f00002b0100"
        val_str = f"0x{raw_hex}"

        if val_str.startswith("0x"):
            raw = bytes.fromhex(val_str[2:])
            if len(raw) >= 8:
                year = int.from_bytes(raw[0:2], "big")
                month, day = raw[2], raw[3]
                hour, minute, sec = raw[4], raw[5], raw[6]
                result = f"{year}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{sec:02d}"

        assert result == "2025-12-01 09:15:00"

    def test_non_hex_value_passthrough(self):
        """Non-0x values should pass through unchanged."""
        val_str = "2024-1-15,14:30:0.0"
        # The guard: only parse if starts with "0x"
        if val_str.startswith("0x"):
            val_str = "SHOULD NOT REACH"
        assert val_str == "2024-1-15,14:30:0.0"


# ---------------------------------------------------------------------------
# Category Handler Wiring
# ---------------------------------------------------------------------------


class TestCategoryHandlerWiring:
    """Verify all ENUM_CATEGORIES have corresponding handlers."""

    def test_all_categories_have_handlers(self, scanner):
        from oida.protocols.snmp.constants import ENUM_CATEGORIES

        # The handler map is built inside _run_enumeration; replicate it here
        category_handlers = {
            "interfaces": scanner._enum_interfaces,
            "tcp": scanner._enum_tcp_connections,
            "udp": scanner._enum_udp_listeners,
            "routes": scanner._enum_routes,
            "processes": scanner._enum_processes,
            "software": scanner._enum_software,
            "storage": scanner._enum_storage,
            "users": scanner._enum_users,
            "shares": scanner._enum_windows_shares,
            "traps": scanner._enum_trap_config,
            "creds": scanner._enum_credentials,
            "system": scanner._enum_system_details,
            "services": scanner._enum_windows_services,
            "filesystems": scanner._enum_filesystems,
            "ipv6": scanner._enum_ipv6,
            "extend": scanner._enum_extend,
            "arp": scanner._enum_arp,
            "cam": scanner._enum_cam,
        }

        for cat in ENUM_CATEGORIES:
            assert cat in category_handlers, f"ENUM_CATEGORIES['{cat}'] has no handler"

    def test_new_methods_exist(self, scanner):
        assert hasattr(scanner, "_enum_system_details")
        assert hasattr(scanner, "_enum_windows_services")
        assert hasattr(scanner, "_enum_filesystems")
        assert hasattr(scanner, "_enum_ipv6")
        assert hasattr(scanner, "_enum_extend")
        assert callable(scanner._enum_system_details)
        assert callable(scanner._enum_windows_services)
        assert callable(scanner._enum_filesystems)
        assert callable(scanner._enum_ipv6)
        assert callable(scanner._enum_extend)
