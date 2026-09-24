"""
Deep unit tests for HostEnumerationMixin.

Each test drives an async enum handler directly with a mocked pysnmp command
layer and asserts the parsed/correlated structure and the security findings it
emits. The handlers are coroutines taking (engine, auth_data, transport,
context) -- we pass None for all four since the transport is fully mocked.
"""

from __future__ import annotations

import asyncio

from tests.unit.snmp.conftest import (
    FakeVarBind,
    get_router,
    make_walk,
    make_walk_error,
    patch_pysnmp,
    walk_router,
)


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# _walk_table -- core multi-column correlation engine
# ---------------------------------------------------------------------------


class TestWalkTable:
    def test_base_oid_exact_match_uses_zero_index(self, scanner):
        """A scalar that returns the base OID exactly maps to index '0'."""
        base = ".1.3.6.1.2.1.1.5"
        walk = make_walk([FakeVarBind("1.3.6.1.2.1.1.5", "router1")])
        with patch_pysnmp(walk=walk):
            rows = run(scanner._walk_table(None, None, None, None, {"name": base}))
        assert rows == {"0": {"name": "router1"}}

    def test_sparse_sentinel_cells_are_skipped(self, scanner):
        """rfc1905 sentinel values must not create a row."""
        from pysnmp.proto import rfc1905

        base = ".1.3.6.1.2.1.2.2.1.2"
        sentinel = rfc1905.NoSuchInstance("")

        async def gen(*_a, **_k):
            yield None, None, None, [FakeVarBind(f"{base.lstrip('.')}.1", "eth0")]
            vb = _SentinelVarBind(f"{base.lstrip('.')}.2", sentinel)
            yield None, None, None, [vb]

        with patch_pysnmp(walk=lambda *a, **k: gen(*a, **k)):
            rows = run(scanner._walk_table(None, None, None, None, {"d": base}))
        assert "1" in rows
        assert "2" not in rows

    def test_walk_error_indication_breaks_cleanly(self, scanner):
        """An error_indication on the first PDU yields no rows, no crash."""
        with patch_pysnmp(walk=make_walk_error("requestTimedOut")):
            rows = run(scanner._walk_table(None, None, None, None, {"x": ".1.2.3"}))
        assert rows == {}


class _SentinelVarBind:
    def __init__(self, oid, sentinel_obj):
        self._oid = oid
        self._val = sentinel_obj

    def __getitem__(self, idx):
        if idx == 0:
            return _S(self._oid)
        if idx == 1:
            return self._val
        raise IndexError


class _S:
    def __init__(self, oid):
        self._oid = oid

    def __str__(self):
        return self._oid


# ---------------------------------------------------------------------------
# _enum_interfaces
# ---------------------------------------------------------------------------


class TestEnumInterfaces:
    def test_interface_parsing_and_ip_correlation(self, scanner):
        from oida.protocols.snmp.constants import NETWORK_ENUM_OIDS as N

        col_data = {
            N["ifDescr"]: [FakeVarBind(N["ifDescr"] + ".1", "GigabitEthernet0/1")],
            N["ifType"]: [FakeVarBind(N["ifType"] + ".1", "6")],
            N["ifSpeed"]: [FakeVarBind(N["ifSpeed"] + ".1", "1000000000")],
            N["ifPhysAddress"]: [FakeVarBind(N["ifPhysAddress"] + ".1", "0xaabbccddeeff")],
            N["ifOperStatus"]: [FakeVarBind(N["ifOperStatus"] + ".1", "1")],
            N["ifInOctets"]: [FakeVarBind(N["ifInOctets"] + ".1", "100")],
            N["ifOutOctets"]: [FakeVarBind(N["ifOutOctets"] + ".1", "200")],
            N["ipAdEntAddr"]: [FakeVarBind(N["ipAdEntAddr"] + ".192.168.1.10", "192.168.1.10")],
            N["ipAdEntIfIndex"]: [FakeVarBind(N["ipAdEntIfIndex"] + ".192.168.1.10", "1")],
            N["ipAdEntNetMask"]: [
                FakeVarBind(N["ipAdEntNetMask"] + ".192.168.1.10", "255.255.255.0")
            ],
        }
        with patch_pysnmp(walk=walk_router(col_data)):
            result = run(scanner._enum_interfaces(None, None, None, None))

        assert result["count"] == 1
        iface = result["interfaces"][0]
        assert iface["descr"] == "GigabitEthernet0/1"
        assert iface["status"] == "up"
        assert iface["speed_str"] == "1Gbps"
        assert iface["mac"] == "aa:bb:cc:dd:ee:ff"
        assert iface["ip_addresses"] == [{"addr": "192.168.1.10", "mask": "255.255.255.0"}]
        assert result["up"] == 1
        assert "192.168.1.10" in result["discovered_targets"]

    def test_loopback_excluded_from_discovered_targets(self, scanner):
        from oida.protocols.snmp.constants import NETWORK_ENUM_OIDS as N

        col_data = {
            N["ipAdEntAddr"]: [FakeVarBind(N["ipAdEntAddr"] + ".127.0.0.1", "127.0.0.1")],
            N["ipAdEntIfIndex"]: [FakeVarBind(N["ipAdEntIfIndex"] + ".127.0.0.1", "1")],
        }
        with patch_pysnmp(walk=walk_router(col_data)):
            result = run(scanner._enum_interfaces(None, None, None, None))
        assert result["discovered_targets"] == []

    def test_speed_formatting_mbps(self, scanner):
        from oida.protocols.snmp.constants import NETWORK_ENUM_OIDS as N

        col_data = {
            N["ifDescr"]: [FakeVarBind(N["ifDescr"] + ".1", "fa0")],
            N["ifSpeed"]: [FakeVarBind(N["ifSpeed"] + ".1", "100000000")],
            N["ifOperStatus"]: [FakeVarBind(N["ifOperStatus"] + ".1", "2")],  # down
        }
        with patch_pysnmp(walk=walk_router(col_data)):
            result = run(scanner._enum_interfaces(None, None, None, None))
        iface = result["interfaces"][0]
        assert iface["speed_str"] == "100Mbps"
        assert iface["status"] == "down"
        assert result["up"] == 0


# ---------------------------------------------------------------------------
# _enum_tcp_connections / _enum_udp_listeners
# ---------------------------------------------------------------------------


class TestEnumTcp:
    def test_listen_state_extracts_listener_port(self, scanner):
        from oida.protocols.snmp.constants import NETWORK_ENUM_OIDS as N

        base = N["tcpConnState"].lstrip(".")
        oid = f"{base}.0.0.0.0.502.0.0.0.0.0"
        walk = make_walk([FakeVarBind(oid, "2")])  # listen
        with patch_pysnmp(walk=walk):
            result = run(scanner._enum_tcp_connections(None, None, None, None))
        conn = result["connections"][0]
        assert conn["local_port"] == 502
        assert conn["state"] == "listen"
        assert 502 in result["listeners"]

    def test_established_not_a_listener(self, scanner):
        from oida.protocols.snmp.constants import NETWORK_ENUM_OIDS as N

        base = N["tcpConnState"].lstrip(".")
        oid = f"{base}.10.0.0.5.443.10.0.0.9.51000"
        walk = make_walk([FakeVarBind(oid, "5")])  # established
        with patch_pysnmp(walk=walk):
            result = run(scanner._enum_tcp_connections(None, None, None, None))
        assert result["listeners"] == []
        assert result["connections"][0]["state"] == "established"


class TestEnumUdp:
    def test_udp_listener_parsing(self, scanner):
        from oida.protocols.snmp.constants import NETWORK_ENUM_OIDS as N

        base = N["udpLocalAddress"].lstrip(".")
        oid = f"{base}.0.0.0.0.161"
        walk = make_walk([FakeVarBind(oid, "0.0.0.0")])
        with patch_pysnmp(walk=walk):
            result = run(scanner._enum_udp_listeners(None, None, None, None))
        assert result["count"] == 1
        assert 161 in result["ports"]


# ---------------------------------------------------------------------------
# _enum_storage -- byte math + percent
# ---------------------------------------------------------------------------


class TestEnumStorage:
    def test_storage_byte_math(self, scanner):
        from oida.protocols.snmp.constants import HOST_RESOURCE_OIDS as H

        col = {
            H["hrStorageDescr"]: [FakeVarBind(H["hrStorageDescr"] + ".1", "/")],
            H["hrStorageAllocationUnits"]: [
                FakeVarBind(H["hrStorageAllocationUnits"] + ".1", "4096")
            ],
            H["hrStorageSize"]: [FakeVarBind(H["hrStorageSize"] + ".1", "1000")],
            H["hrStorageUsed"]: [FakeVarBind(H["hrStorageUsed"] + ".1", "250")],
        }
        with patch_pysnmp(walk=walk_router(col)):
            result = run(scanner._enum_storage(None, None, None, None))
        s = result["storage"][0]
        assert s["total_bytes"] == 1000 * 4096
        assert s["used_bytes"] == 250 * 4096
        assert s["pct_used"] == 25.0


# ---------------------------------------------------------------------------
# _enum_processes
# ---------------------------------------------------------------------------


class TestEnumProcesses:
    def test_process_type_and_status_mapping(self, scanner):
        from oida.protocols.snmp.constants import HOST_RESOURCE_OIDS as H

        col = {
            H["hrSWRunName"]: [FakeVarBind(H["hrSWRunName"] + ".7", "sshd")],
            H["hrSWRunPath"]: [FakeVarBind(H["hrSWRunPath"] + ".7", "/usr/sbin/sshd")],
            H["hrSWRunParameters"]: [FakeVarBind(H["hrSWRunParameters"] + ".7", "-D")],
            H["hrSWRunPerfCPU"]: [FakeVarBind(H["hrSWRunPerfCPU"] + ".7", "150")],
            H["hrSWRunPerfMem"]: [FakeVarBind(H["hrSWRunPerfMem"] + ".7", "20480")],
        }
        with patch_pysnmp(walk=walk_router(col)):
            result = run(scanner._enum_processes(None, None, None, None))
        proc = result["processes"][0]
        assert proc["pid"] == "7"
        assert proc["name"] == "sshd"
        assert proc["cpu_cs"] == 150
        assert proc["mem_kb"] == 20480


# ---------------------------------------------------------------------------
# _enum_filesystems -- writable remote mount finding
# ---------------------------------------------------------------------------


class TestEnumFilesystems:
    def test_writable_remote_mount_emits_finding(self, scanner):
        from oida.protocols.snmp.constants import FILESYSTEM_OIDS as F

        col = {
            F["hrFSMountPoint"]: [FakeVarBind(F["hrFSMountPoint"] + ".1", "/mnt/share")],
            F["hrFSRemoteMountPoint"]: [
                FakeVarBind(F["hrFSRemoteMountPoint"] + ".1", "nas:/export")
            ],
            F["hrFSType"]: [FakeVarBind(F["hrFSType"] + ".1", "nfs")],
            F["hrFSAccess"]: [FakeVarBind(F["hrFSAccess"] + ".1", "1")],  # readWrite
        }
        with patch_pysnmp(walk=walk_router(col)):
            result = run(scanner._enum_filesystems(None, None, None, None))
        fs = result["filesystems"][0]
        assert fs["access"] == "readWrite"
        assert "Insecure configuration" in scanner.logger.finding_titles

    def test_readonly_remote_mount_no_finding(self, scanner):
        from oida.protocols.snmp.constants import FILESYSTEM_OIDS as F

        col = {
            F["hrFSMountPoint"]: [FakeVarBind(F["hrFSMountPoint"] + ".1", "/mnt/ro")],
            F["hrFSRemoteMountPoint"]: [FakeVarBind(F["hrFSRemoteMountPoint"] + ".1", "nas:/ro")],
            F["hrFSAccess"]: [FakeVarBind(F["hrFSAccess"] + ".1", "2")],  # readOnly
        }
        with patch_pysnmp(walk=walk_router(col)):
            run(scanner._enum_filesystems(None, None, None, None))
        assert "Insecure configuration" not in scanner.logger.finding_titles


# ---------------------------------------------------------------------------
# _enum_system_details -- DateAndTime + IP forwarding finding
# ---------------------------------------------------------------------------


class TestEnumSystemDetails:
    def test_dateandtime_parsing_and_forwarding_finding(self, scanner):
        from oida.protocols.snmp.constants import SNMP_OIDS, WINDOWS_OIDS

        responses = {
            SNMP_OIDS["hrSystemDate"]: "0x07e8030f0e1e2d00",  # 2024-03-15 14:30:45
            SNMP_OIDS["ipForwarding"]: "1",
            SNMP_OIDS["ipDefaultTTL"]: "64",
            SNMP_OIDS["tcpInSegs"]: "10",
            SNMP_OIDS["tcpOutSegs"]: "20",
            SNMP_OIDS["tcpRetransSegs"]: "1",
            WINDOWS_OIDS["domPrimaryDomain"]: "CORP",
        }
        with patch_pysnmp(get=get_router(responses)):
            result = run(scanner._enum_system_details(None, None, None, None))
        details = result["details"]
        assert details["hrSystemDate"] == "2024-03-15 14:30:45"
        assert details["ipForwarding"] == "1"
        assert "IP forwarding enabled" in scanner.logger.finding_titles

    def test_no_forwarding_finding_when_disabled(self, scanner):
        from oida.protocols.snmp.constants import SNMP_OIDS

        with patch_pysnmp(get=get_router({SNMP_OIDS["ipForwarding"]: "2"})):
            run(scanner._enum_system_details(None, None, None, None))
        assert "IP forwarding enabled" not in scanner.logger.finding_titles


# ---------------------------------------------------------------------------
# _enum_windows_services
# ---------------------------------------------------------------------------


class TestEnumWindowsServices:
    def test_service_state_mapping(self, scanner):
        from oida.protocols.snmp.constants import WINDOWS_SERVICE_OIDS as W

        col = {
            W["svSvcName"]: [FakeVarBind(W["svSvcName"] + ".1", "Spooler")],
            W["svSvcInstalledState"]: [FakeVarBind(W["svSvcInstalledState"] + ".1", "4")],
            W["svSvcOperatingState"]: [FakeVarBind(W["svSvcOperatingState"] + ".1", "1")],
        }
        with patch_pysnmp(walk=walk_router(col)):
            result = run(scanner._enum_windows_services(None, None, None, None))
        svc = result["services"][0]
        assert svc["name"] == "Spooler"
        assert svc["installed_state"] == "installed"
        assert svc["operating_state"] == "active"
        assert result["active"] == 1


# ---------------------------------------------------------------------------
# _enum_users (Windows LanManager)
# ---------------------------------------------------------------------------


class TestEnumUsers:
    def test_user_list_extraction(self, scanner):
        from oida.protocols.snmp.constants import WINDOWS_OIDS

        base = WINDOWS_OIDS["svUserName"].lstrip(".")
        walk = make_walk(
            [FakeVarBind(f"{base}.1", "Administrator")],
            [FakeVarBind(f"{base}.2", "Guest")],
        )
        with patch_pysnmp(walk=walk):
            result = run(scanner._enum_users(None, None, None, None))
        assert result["count"] == 2
        assert "Administrator" in result["users"]
        assert "Guest" in result["users"]


# ---------------------------------------------------------------------------
# _enum_ipv6 -- RFC 4293 address decode + scope classification
# ---------------------------------------------------------------------------


class TestEnumIpv6:
    def test_global_ipv6_decode_and_scope(self, scanner):
        from oida.protocols.snmp.constants import IPV6_ENUM_OIDS

        base = IPV6_ENUM_OIDS["ipAddressIfIndex"].lstrip(".")
        octets = [0x26, 0x06, 0x47, 0x00] + [0] * 11 + [1]  # 2606:4700::1 (global)
        suffix = "2.16." + ".".join(str(o) for o in octets)
        walk = make_walk([FakeVarBind(f"{base}.{suffix}", "3")])
        with patch_pysnmp(walk=walk):
            result = run(scanner._enum_ipv6(None, None, None, None))
        addrs = result["addresses"]
        assert len(addrs) == 1
        assert addrs[0]["address"] == "2606:4700::1"
        assert addrs[0]["scope"] == "global"
        assert addrs[0]["if_index"] == "3"
        assert result["global"] == 1

    def test_link_local_ipv6_scope(self, scanner):
        from oida.protocols.snmp.constants import IPV6_ENUM_OIDS

        base = IPV6_ENUM_OIDS["ipAddressIfIndex"].lstrip(".")
        octets = [0xFE, 0x80] + [0] * 13 + [1]
        suffix = "2.16." + ".".join(str(o) for o in octets)
        walk = make_walk([FakeVarBind(f"{base}.{suffix}", "1")])
        with patch_pysnmp(walk=walk):
            result = run(scanner._enum_ipv6(None, None, None, None))
        assert result["addresses"][0]["scope"] == "link-local"
        assert result["global"] == 0


# ---------------------------------------------------------------------------
# _enum_extend -- injected script RCE finding + name decode
# ---------------------------------------------------------------------------


class TestEnumExtend:
    def test_injected_extend_script_rce_finding(self, scanner):
        from oida.protocols.snmp.constants import NETSNMP_EXTEND_OIDS as E

        name_suffix = "1.120"  # len(1) + ASCII 'x'
        cfg = {
            E["nsExtendCommand"]: [FakeVarBind(f"{E['nsExtendCommand']}.{name_suffix}", "/bin/sh")],
            E["nsExtendArgs"]: [FakeVarBind(f"{E['nsExtendArgs']}.{name_suffix}", "-c id")],
            E["nsExtendStorage"]: [FakeVarBind(f"{E['nsExtendStorage']}.{name_suffix}", "2")],
        }
        with patch_pysnmp(walk=walk_router(cfg)):
            result = run(scanner._enum_extend(None, None, None, None))
        ext = result["extends"][0]
        assert ext["name"] == "x"
        assert ext["command"] == "/bin/sh"
        assert "volatile (INJECTED)" in ext["storage"]
        assert "RCE risk" in scanner.logger.finding_titles

    def test_permanent_extend_no_rce_finding(self, scanner):
        from oida.protocols.snmp.constants import NETSNMP_EXTEND_OIDS as E

        name_suffix = "1.121"
        cfg = {
            E["nsExtendCommand"]: [FakeVarBind(f"{E['nsExtendCommand']}.{name_suffix}", "/bin/df")],
            E["nsExtendStorage"]: [FakeVarBind(f"{E['nsExtendStorage']}.{name_suffix}", "4")],
        }
        with patch_pysnmp(walk=walk_router(cfg)):
            result = run(scanner._enum_extend(None, None, None, None))
        assert "permanent (config)" in result["extends"][0]["storage"]
        assert "RCE risk" not in scanner.logger.finding_titles


# ---------------------------------------------------------------------------
# _enum_credentials -- H3C correlation + process-arg cred scanning
# ---------------------------------------------------------------------------


class TestEnumCredentials:
    def test_h3c_user_correlation_and_finding(self, scanner):
        from oida.protocols.snmp.constants import CREDENTIAL_OIDS as C

        col = {
            C["h3cUserName"]: [FakeVarBind(C["h3cUserName"] + ".1", "admin")],
            C["h3cUserPassword"]: [FakeVarBind(C["h3cUserPassword"] + ".1", "secret123")],
            C["h3cUserLevel"]: [FakeVarBind(C["h3cUserLevel"] + ".1", "3")],
        }
        with patch_pysnmp(walk=walk_router(col)):
            result = run(scanner._enum_credentials(None, None, None, None))
        users = result["h3c_users"]
        assert len(users) == 1
        assert users[0]["username"] == "admin"
        assert users[0]["password"] == "secret123"
        assert users[0]["level"] == "3"
        assert any("H3C credential found" in d for d in scanner.logger.finding_details)

    def test_process_arg_credential_detection(self, scanner):
        from oida.protocols.snmp.constants import HOST_RESOURCE_OIDS as H

        col = {
            H["hrSWRunName"]: [FakeVarBind(H["hrSWRunName"] + ".42", "mysqld")],
            H["hrSWRunParameters"]: [
                FakeVarBind(H["hrSWRunParameters"] + ".42", "--password=hunter2")
            ],
        }
        with patch_pysnmp(walk=walk_router(col)):
            result = run(scanner._enum_credentials(None, None, None, None))
        pc = result["process_credentials"]
        assert len(pc) == 1
        assert pc[0]["process"] == "mysqld"
        assert "password" in pc[0]["match"].lower()

    def test_no_credentials_found(self, scanner):
        with patch_pysnmp(walk=walk_router({})):
            result = run(scanner._enum_credentials(None, None, None, None))
        assert result["total"] == 0
        assert result["h3c_users"] == []
        assert result["process_credentials"] == []


# ---------------------------------------------------------------------------
# _enum_trap_config -- community discovery
# ---------------------------------------------------------------------------


class TestEnumTraps:
    def test_trap_community_discovery(self, scanner):
        from oida.protocols.snmp.constants import TRAP_CONFIG_OIDS as T

        col = {
            T["snmpTargetAddrTAddress"]: [
                FakeVarBind(T["snmpTargetAddrTAddress"] + ".1", "0xc0a80101a161")
            ],
            T["snmpCommunityName"]: [FakeVarBind(T["snmpCommunityName"] + ".1", "trapsecret")],
        }
        with patch_pysnmp(walk=walk_router(col)):
            result = run(scanner._enum_trap_config(None, None, None, None))
        assert "trapsecret" in result["discovered_communities"]
        assert result["count"] == 1


# ---------------------------------------------------------------------------
# _enum_routes
# ---------------------------------------------------------------------------


class TestEnumRoutes:
    def test_route_type_mapping(self, scanner):
        from oida.protocols.snmp.constants import NETWORK_ENUM_OIDS as N

        col = {
            N["ipRouteDest"]: [FakeVarBind(N["ipRouteDest"] + ".0.0.0.0", "0.0.0.0")],
            N["ipRouteNextHop"]: [FakeVarBind(N["ipRouteNextHop"] + ".0.0.0.0", "10.0.0.1")],
            N["ipRouteMask"]: [FakeVarBind(N["ipRouteMask"] + ".0.0.0.0", "0.0.0.0")],
            N["ipRouteIfIndex"]: [FakeVarBind(N["ipRouteIfIndex"] + ".0.0.0.0", "1")],
            N["ipRouteType"]: [FakeVarBind(N["ipRouteType"] + ".0.0.0.0", "4")],  # indirect
        }
        with patch_pysnmp(walk=walk_router(col)):
            result = run(scanner._enum_routes(None, None, None, None))
        route = result["routes"][0]
        assert route["next_hop"] == "10.0.0.1"
        assert route["type"] == "indirect"


# ---------------------------------------------------------------------------
# _get_arp_table
# ---------------------------------------------------------------------------


class TestArp:
    def test_arp_table_mac_formatting(self, scanner):
        oid = "1.3.6.1.2.1.4.22.1.2.5.10.0.0.9"
        walk = make_walk([FakeVarBind(oid, "0xaabbccddeeff")])
        with patch_pysnmp(walk=walk):
            entries = run(scanner._get_arp_table(None, None, None, None))
        assert entries == [{"ip": "10.0.0.9", "mac": "aa:bb:cc:dd:ee:ff"}]

    def test_arp_skips_zero_mac(self, scanner):
        oid = "1.3.6.1.2.1.4.22.1.2.5.10.0.0.9"
        walk = make_walk([FakeVarBind(oid, "0x000000000000")])
        with patch_pysnmp(walk=walk):
            entries = run(scanner._get_arp_table(None, None, None, None))
        assert entries == []


# ---------------------------------------------------------------------------
# _analyze_enum_security -- pure logic, drives every finding branch
# ---------------------------------------------------------------------------


class TestAnalyzeEnumSecurity:
    def test_ics_listener_finding(self, scanner):
        scanner._analyze_enum_security({"tcp": {"listeners": [502, 22]}})
        details = " ".join(scanner.logger.finding_details)
        assert "Modbus" in details

    def test_risky_windows_account_finding(self, scanner):
        scanner._analyze_enum_security({"users": {"users": ["Guest", "alice"]}})
        details = " ".join(scanner.logger.finding_details)
        assert "Guest" in details
        assert scanner.logger.security_finding.call_count == 1

    def test_admin_share_finding(self, scanner):
        scanner._analyze_enum_security(
            {"shares": {"shares": [{"name": "C$", "path": "C:\\"}, {"name": "data", "path": ""}]}}
        )
        details = " ".join(scanner.logger.finding_details)
        assert "C$" in details
        assert scanner.logger.security_finding.call_count == 1

    def test_extra_trap_community_finding(self, scanner):
        scanner.community = "mycomm"
        scanner._analyze_enum_security(
            {"traps": {"discovered_communities": ["public", "mycomm", "extra"]}}
        )
        details = " ".join(scanner.logger.finding_details)
        assert "extra" in details
        assert scanner.logger.security_finding.call_count == 1

    def test_extend_and_ipv6_and_proc_cred_findings(self, scanner):
        scanner._analyze_enum_security(
            {
                "extend": {"count": 2},
                "ipv6": {"global": 3},
                "creds": {"process_credentials": [{"x": 1}]},
            }
        )
        titles = scanner.logger.finding_titles
        assert "RCE risk" in titles
        assert "Hidden attack surface" in titles
        assert "Credential exposure" in titles

    def test_no_findings_for_clean_results(self, scanner):
        scanner._analyze_enum_security({"tcp": {"listeners": [22, 80]}})
        assert scanner.logger.security_finding.call_count == 0


# ---------------------------------------------------------------------------
# _query_vendor_oids
# ---------------------------------------------------------------------------


class TestQueryVendorOids:
    def test_unknown_vendor_returns_empty(self, scanner):
        result = run(scanner._query_vendor_oids("NoSuchVendor", None, None, None, None))
        assert result == {}

    def test_known_vendor_collects_values(self, scanner):
        from oida.protocols.snmp.constants import VENDOR_SPECIFIC_OIDS

        vendor = "Siemens"
        first_oid = next(iter(VENDOR_SPECIFIC_OIDS[vendor].values()))

        async def get(*args, **kwargs):
            from tests.unit.snmp.conftest import _base_oid_from_args

            base = _base_oid_from_args(args)
            if base == first_oid:
                return None, 0, 0, [FakeVarBind(base, "SN-12345")]
            return "noSuchName", 0, 0, []

        with patch_pysnmp(get=get):
            result = run(scanner._query_vendor_oids(vendor, None, None, None, None))
        assert "SN-12345" in result.values()


# ---------------------------------------------------------------------------
# _run_enumeration -- dispatch + unknown category + analysis wiring
# ---------------------------------------------------------------------------


class TestRunEnumeration:
    def test_unknown_category_warns_and_skips(self, scanner):
        scanner.enum_categories = ["bogus"]
        result = scanner._run_enumeration((None, None, None, None))
        assert "bogus" not in result
        scanner.logger.warning.assert_called()

    def test_handler_dispatch_and_analysis(self, scanner, monkeypatch):
        scanner.enum_categories = ["interfaces"]

        async def fake_iface(engine, auth_data, transport, context):
            return {"interfaces": [], "count": 0, "up": 0, "discovered_targets": []}

        monkeypatch.setattr(scanner, "_enum_interfaces", fake_iface)

        called = {}
        monkeypatch.setattr(
            scanner, "_analyze_enum_security", lambda r: called.update(ran=True, results=r)
        )

        import pysnmp.hlapi.asyncio as hl

        class _UT:
            @staticmethod
            async def create(*a, **k):
                return object()

        monkeypatch.setattr(hl, "SnmpEngine", lambda *a, **k: object())
        monkeypatch.setattr(hl, "UdpTransportTarget", _UT)

        result = scanner._run_enumeration((None, None, None, None))
        assert "interfaces" in result
        assert called.get("ran")
        assert "interfaces" in called["results"]
