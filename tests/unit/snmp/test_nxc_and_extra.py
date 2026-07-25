"""
Tests for the NXC-style snmp connection wrapper and a few remaining
host-enumeration / write-access code paths.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

from .conftest import FakeVarBind, make_walk, patch_pysnmp


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# cli_runner.snmp -- method-level tests (bypass NetworkConnection.__init__)
# ---------------------------------------------------------------------------


def _bare_snmp():
    """Construct an snmp instance without running NetworkConnection.__init__."""
    from oida.protocols.snmp.cli_runner import snmp

    obj = object.__new__(snmp)
    obj.logger = MagicMock()
    obj.results = {"data": {}, "success": None}
    return obj


class TestNxcConnection:
    def test_enum_host_info_success(self):
        obj = _bare_snmp()
        obj.scanner = MagicMock()
        obj.scanner.run_scan.return_value = {"host": "10.0.0.5", "vendor": "Cisco"}
        obj.enum_host_info()
        assert obj.results["success"] is True
        assert obj.results["data"]["vendor"] == "Cisco"

    def test_enum_host_info_error_marks_failure(self):
        obj = _bare_snmp()
        obj.scanner = MagicMock()
        obj.scanner.run_scan.return_value = {"error": "connection_failed"}
        obj.enum_host_info()
        assert obj.results["success"] is False
        obj.logger.fail.assert_called()

    def test_enum_host_info_missing_deps_no_extra_fail(self):
        obj = _bare_snmp()
        obj.scanner = MagicMock()
        obj.scanner.run_scan.return_value = {"error": "missing_dependencies"}
        obj.enum_host_info()
        assert obj.results["success"] is False
        # missing_dependencies is excluded from the extra fail() log
        obj.logger.fail.assert_not_called()

    def test_print_host_info_is_noop_tally_moved_to_teardown(self):
        # The per-scan findings tally moved to NetworkConnection's proto_flow
        # teardown (printed uniformly for every protocol); snmp deliberately no
        # longer overrides print_host_info, so it is a no-op even with findings.
        obj = _bare_snmp()
        obj.logger.findings = [{"title": "x"}, {"title": "y"}]
        obj.print_host_info()
        obj.logger.display.assert_not_called()

    def test_print_host_info_no_findings_silent(self):
        obj = _bare_snmp()
        obj.logger.findings = []
        obj.print_host_info()
        obj.logger.display.assert_not_called()

    def test_create_conn_obj_missing_deps(self):
        obj = _bare_snmp()
        obj._convert_args_to_dict = lambda: {"host": "10.0.0.5"}
        with patch("oida.protocols.snmp.scanner.SNMPScanner") as SC:
            inst = SC.return_value
            inst.check_dependencies.return_value = False
            ok = obj.create_conn_obj()
        assert ok is False
        assert obj.results["success"] is False
        obj.logger.fail.assert_called()

    def test_create_conn_obj_success_shares_logger(self):
        obj = _bare_snmp()
        obj._convert_args_to_dict = lambda: {"host": "10.0.0.5"}
        with patch("oida.protocols.snmp.scanner.SNMPScanner") as SC:
            inst = SC.return_value
            inst.check_dependencies.return_value = True
            ok = obj.create_conn_obj()
        assert ok is True
        # logger was shared into the scanner
        assert obj.scanner.logger is obj.logger

    def test_proto_flow_stops_when_conn_obj_fails(self):
        obj = _bare_snmp()
        obj.create_conn_obj = MagicMock(return_value=False)
        obj.enum_host_info = MagicMock()
        obj.print_host_info = MagicMock()
        obj.proto_flow()
        obj.enum_host_info.assert_not_called()
        obj.print_host_info.assert_not_called()


# ---------------------------------------------------------------------------
# _get_mac_table -- multi-pass MAC + port + status correlation
# ---------------------------------------------------------------------------


class TestGetMacTable:
    def test_mac_port_status_correlation(self, scanner):
        mac_base = "1.3.6.1.2.1.17.4.3.1.1"
        port_base = "1.3.6.1.2.1.17.4.3.1.2"
        status_base = "1.3.6.1.2.1.17.4.3.1.3"
        # MAC 00:11:22:33:44:55 -> suffix 0.17.34.51.68.85
        mac_suffix = "0.17.34.51.68.85"

        def walk(*args, **kwargs):
            async def gen():
                yield None, None, None, [FakeVarBind(f"{mac_base}.{mac_suffix}", "x")]

            return gen()

        async def get(*args, **kwargs):
            from .conftest import _base_oid_from_args

            base = _base_oid_from_args(args).lstrip(".")
            if base.startswith(port_base):
                return None, 0, 0, [FakeVarBind(base, "5", "Integer32")]
            if base.startswith(status_base):
                return None, 0, 0, [FakeVarBind(base, "3", "Integer32")]
            return None, 0, 0, []

        with patch_pysnmp(walk=walk, get=get):
            entries = run(scanner._get_mac_table(None, None, None, None))
        assert len(entries) == 1
        e = entries[0]
        assert e["mac"] == "00:11:22:33:44:55"
        assert e["port"] == 5
        assert e["status"] == "learned"

    def test_empty_bridge_table_falls_back_to_dot1q(self, scanner):
        # bridge MAC walk yields nothing; dot1q walk yields a VLAN entry.
        fdb_base = "1.3.6.1.2.1.17.7.1.2.2.1.2"
        vlan_mac_suffix = "10.0.17.34.51.68.85"  # vlan 10 + MAC

        def walk(*args, **kwargs):
            from .conftest import _base_oid_from_args

            base = _base_oid_from_args(args).lstrip(".")

            async def gen():
                if base.startswith(fdb_base):
                    yield (
                        None,
                        None,
                        None,
                        [FakeVarBind(f"{fdb_base}.{vlan_mac_suffix}", "7", "Integer32")],
                    )

            return gen()

        with patch_pysnmp(walk=walk, get=lambda *a, **k: _empty_get()):
            entries = run(scanner._get_mac_table(None, None, None, None))
        assert len(entries) == 1
        assert entries[0]["vlan"] == 10
        assert entries[0]["port"] == 7
        assert entries[0]["mac"] == "00:11:22:33:44:55"


async def _empty_get(*a, **k):
    return None, 0, 0, []


# ---------------------------------------------------------------------------
# _check_write_access -- sync wrapper emits finding on writable
# ---------------------------------------------------------------------------


class TestCheckWriteAccess:
    def test_writable_result_emits_finding(self, scanner):
        with patch(
            "oida.protocols.snmp.mixins.write_access.asyncio.run",
            return_value={"writable": True, "method": "set_probe", "detail": "ok"},
        ):
            out = scanner._check_write_access(None, None, None, None)
        assert out["writable"] is True
        assert "Writable access" in scanner.logger.finding_titles

    def test_readonly_result_no_finding(self, scanner):
        with patch(
            "oida.protocols.snmp.mixins.write_access.asyncio.run",
            return_value={"writable": False, "method": "vacm", "detail": "read-only"},
        ):
            out = scanner._check_write_access(None, None, None, None)
        assert out["writable"] is False
        assert "Writable access" not in scanner.logger.finding_titles


# ---------------------------------------------------------------------------
# _async_check_write -- v1/v2c skips VACM, goes straight to SET probe
# ---------------------------------------------------------------------------


class TestAsyncCheckWrite:
    def test_v2c_skips_vacm(self, scanner, monkeypatch):
        scanner.version = "2c"
        vacm_called = {"n": 0}

        async def fake_vacm(*a, **k):
            vacm_called["n"] += 1
            return {"conclusive": True}

        async def fake_set_probe(*a, **k):
            return {"conclusive": True, "writable": False, "method": "set_probe"}

        monkeypatch.setattr(scanner, "_vacm_check", fake_vacm)
        monkeypatch.setattr(scanner, "_set_probe", fake_set_probe)
        out = run(scanner._async_check_write(None, None, None, None))
        assert vacm_called["n"] == 0
        assert out["method"] == "set_probe"

    def test_v3_conclusive_vacm_short_circuits(self, scanner, monkeypatch):
        scanner.version = "3"

        async def fake_vacm(*a, **k):
            return {"conclusive": True, "writable": False, "method": "vacm"}

        set_called = {"n": 0}

        async def fake_set_probe(*a, **k):
            set_called["n"] += 1
            return {"conclusive": True}

        monkeypatch.setattr(scanner, "_vacm_check", fake_vacm)
        monkeypatch.setattr(scanner, "_set_probe", fake_set_probe)
        out = run(scanner._async_check_write(None, None, None, None))
        assert out["method"] == "vacm"
        assert set_called["n"] == 0


# ---------------------------------------------------------------------------
# scan_targets -- multi-target helper
# ---------------------------------------------------------------------------


class TestScanTargets:
    def test_collects_successful_targets(self):
        from oida.protocols.snmp import scanner as scanner_mod

        captured = {}

        class FakeScanner:
            def __init__(self, args):
                captured["args"] = args

            def connect(self):
                return ("eng", "auth", "tr", "ctx")

            def discover(self, conn):
                return {"vendor": "Cisco"}

            def disconnect(self, conn):
                pass

        with patch.object(scanner_mod, "SNMPScanner", FakeScanner):
            out = scanner_mod.scan_targets(["10.0.0.1"], community="private")
        assert out["10.0.0.1"]["vendor"] == "Cisco"
        assert captured["args"]["community"] == "private"

    def test_connection_failure_skipped(self):
        from oida.protocols.snmp import scanner as scanner_mod

        class FakeScanner:
            def __init__(self, args):
                pass

            def connect(self):
                return None

        with patch.object(scanner_mod, "SNMPScanner", FakeScanner):
            out = scanner_mod.scan_targets(["10.0.0.9"])
        assert out == {}


# ---------------------------------------------------------------------------
# _enum_software (uncovered handler)
# ---------------------------------------------------------------------------


class TestEnumSoftware:
    def test_software_listing(self, scanner):
        from oida.protocols.snmp.constants import HOST_RESOURCE_OIDS as H

        base = H["hrSWInstalledName"].lstrip(".")
        walk = make_walk(
            [FakeVarBind(f"{base}.1", "openssh")],
            [FakeVarBind(f"{base}.2", "nginx")],
        )

        def router(*args, **kwargs):
            from .conftest import _base_oid_from_args

            b = _base_oid_from_args(args).lstrip(".")

            async def gen():
                if b == base:
                    yield None, None, None, [FakeVarBind(f"{base}.1", "openssh")]
                    yield None, None, None, [FakeVarBind(f"{base}.2", "nginx")]

            return gen()

        with patch_pysnmp(walk=router):
            result = run(scanner._enum_software(None, None, None, None))
        names = [s["name"] for s in result["software"]]
        assert "openssh" in names
        assert "nginx" in names
        _ = walk
