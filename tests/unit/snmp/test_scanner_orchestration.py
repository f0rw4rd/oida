"""
Orchestration-level tests for SNMPScanner (scanner.py).

Covers _get_auth_data version branching, _validate_snmp_key, _analyze_security
finding emission, _async_discover vendor parsing, _display_banner, and the
run_scan phase gating (brute/comma-community/enum/write/raw) with the network
layer mocked.
"""

from __future__ import annotations

import asyncio

import pytest

from .conftest import FakeVarBind, get_router, patch_pysnmp


def run(coro):
    return asyncio.run(coro)


def make_scanner(**kw):
    from oida.protocols.snmp.scanner import SNMPScanner
    from .conftest import RecordingLogger

    args = {"host": "10.0.0.5", "port": 161, "timeout": 1, "snmp_version": "2c"}
    args.update(kw)
    s = SNMPScanner(args)
    s.logger = RecordingLogger()
    return s


# ---------------------------------------------------------------------------
# _validate_snmp_key
# ---------------------------------------------------------------------------


class TestValidateSnmpKey:
    def test_short_key_raises(self):
        from oida.protocols.snmp.scanner import _validate_snmp_key

        with pytest.raises(ValueError, match="at least 8"):
            _validate_snmp_key("short", "auth password")

    def test_valid_key_passes_through(self):
        from oida.protocols.snmp.scanner import _validate_snmp_key

        assert _validate_snmp_key("longenough", "auth password") == "longenough"

    def test_empty_key_allowed(self):
        from oida.protocols.snmp.scanner import _validate_snmp_key

        assert _validate_snmp_key("", "auth password") == ""


# ---------------------------------------------------------------------------
# __init__ auth parsing
# ---------------------------------------------------------------------------


class TestAuthParsing:
    def test_colon_auth_becomes_v3(self):
        s = make_scanner(auth="admin:authpass1:privpass1")
        assert s.version == "3"
        assert s.username == "admin"
        assert s.auth_pass == "authpass1"
        assert s.priv_pass == "privpass1"
        assert s.security_level == "authPriv"

    def test_user_authpass_only_is_authnopriv(self):
        s = make_scanner(auth="admin:authpass1")
        assert s.security_level == "authNoPriv"
        assert s.priv_pass == ""

    def test_plain_community(self):
        s = make_scanner(community="private")
        assert s.version == "2c"
        assert s.community == "private"

    def test_fine_grained_user_forces_v3(self):
        s = make_scanner(snmp_user="netadmin")
        assert s.version == "3"
        assert s.username == "netadmin"
        # No auth pass -> noAuthNoPriv inferred
        assert s.security_level == "noAuthNoPriv"

    def test_enum_all_expands_categories(self):
        from oida.protocols.snmp.constants import ENUM_CATEGORIES

        s = make_scanner(enum="all")
        assert set(s.enum_categories) == set(ENUM_CATEGORIES.keys())

    def test_enum_csv_parsed(self):
        s = make_scanner(enum="interfaces, tcp ,udp")
        assert s.enum_categories == ["interfaces", "tcp", "udp"]


# ---------------------------------------------------------------------------
# _get_auth_data
# ---------------------------------------------------------------------------


class TestGetAuthData:
    def test_v2c_community_data(self):
        s = make_scanner(community="public", snmp_version="2c")
        auth = s._get_auth_data()
        # pysnmp CommunityData -- message processing model 1 for v2c
        assert auth is not None
        assert auth.message_processing_model == 1

    def test_v1_community_data_mpmodel0(self):
        s = make_scanner(community="public", snmp_version="1")
        auth = s._get_auth_data()
        assert auth.message_processing_model == 0

    def test_v3_without_username_returns_none(self):
        s = make_scanner(snmp_version="3")
        s.username = ""
        assert s._get_auth_data() is None
        assert "credentials" in s._last_error

    def test_v3_short_key_fails_gracefully(self):
        s = make_scanner(snmp_version="3", snmp_user="admin")
        s.security_level = "authNoPriv"
        s.auth_pass = "short"  # < 8 chars -> ValueError caught -> None
        assert s._get_auth_data() is None
        s.logger.fail.assert_called()

    def test_v3_noauthnopriv_builds_usm(self):
        s = make_scanner(snmp_version="3", snmp_user="admin")
        s.security_level = "noAuthNoPriv"
        auth = s._get_auth_data()
        assert auth is not None


# ---------------------------------------------------------------------------
# _analyze_security
# ---------------------------------------------------------------------------


class TestAnalyzeSecurity:
    def test_v1_emits_legacy_and_cleartext(self):
        s = make_scanner(snmp_version="1")
        s._analyze_security({"sys_info": {"sysContact": "x", "sysLocation": "y"}})
        titles = s.logger.finding_titles
        assert "Legacy protocol" in titles
        assert "No encryption" in titles

    def test_v2c_public_default_credentials(self):
        s = make_scanner(snmp_version="2c", community="public")
        s._analyze_security({"sys_info": {"sysContact": "x", "sysLocation": "y"}})
        titles = s.logger.finding_titles
        assert "No encryption" in titles
        assert "Default credentials" in titles

    def test_v2c_nonpublic_no_default_finding(self):
        s = make_scanner(snmp_version="2c", community="custom")
        s._analyze_security({"sys_info": {"sysContact": "x", "sysLocation": "y"}})
        assert "Default credentials" not in s.logger.finding_titles

    def test_v3_no_cleartext_finding(self):
        s = make_scanner(snmp_version="3", snmp_user="admin")
        s._analyze_security({"sys_info": {"sysContact": "x", "sysLocation": "y"}})
        assert "No encryption" not in s.logger.finding_titles

    def test_missing_contact_location_warns(self):
        s = make_scanner(snmp_version="2c", community="custom")
        s._analyze_security({"sys_info": {}})
        s.logger.warning.assert_called()


# ---------------------------------------------------------------------------
# _async_discover -- vendor parsing from sysObjectID
# ---------------------------------------------------------------------------


class TestAsyncDiscover:
    def test_vendor_parsed_from_sysobjectid(self):
        from oida.protocols.snmp.constants import SNMP_OIDS

        s = make_scanner()

        responses = {
            SNMP_OIDS["sysDescr"]: "Siemens SCALANCE",
            SNMP_OIDS["sysObjectID"]: "1.3.6.1.4.1.4329.6.3.1",
            SNMP_OIDS["sysName"]: "plc1",
        }

        async def get(*args, **kwargs):
            from .conftest import _base_oid_from_args

            base = _base_oid_from_args(args)
            val = responses.get(base)
            if val is None:
                return None, 0, 0, []
            return None, 0, 0, [FakeVarBind(base, val)]

        with patch_pysnmp(get=get):
            # _query_vendor_oids also runs; route it through the same get (returns
            # nothing for vendor OIDs -> empty vendor_info).
            result = run(s._async_discover(None, None, None, None))

        assert result["vendor"] == "Siemens"
        assert result["sys_info"]["sysName"] == "plc1"

    def test_unknown_enterprise_pen_labeled(self):
        from oida.protocols.snmp.constants import SNMP_OIDS

        s = make_scanner()
        responses = {
            SNMP_OIDS["sysDescr"]: "Generic",
            SNMP_OIDS["sysObjectID"]: "1.3.6.1.4.1.99999.1",
        }
        with patch_pysnmp(get=get_router(responses)):
            result = run(s._async_discover(None, None, None, None))
        assert result["vendor"] == "Enterprise:99999"

    def test_empty_sysinfo_returns_empty(self):
        s = make_scanner()
        with patch_pysnmp(get=get_router({})):
            result = run(s._async_discover(None, None, None, None))
        assert result == {}


# ---------------------------------------------------------------------------
# _display_banner
# ---------------------------------------------------------------------------


class TestDisplayBanner:
    def test_banner_includes_name_vendor_desc(self):
        s = make_scanner()
        s._display_banner(
            {
                "sys_info": {"sysName": "rtr1", "sysDescr": "Cisco IOS"},
                "vendor": "Cisco",
            }
        )
        success_msgs = [str(c.args[0]) for c in s.logger.success.call_args_list if c.args]
        joined = " ".join(success_msgs)
        assert "rtr1" in joined
        assert "Cisco" in joined

    def test_empty_discovery_is_noop(self):
        s = make_scanner()
        s._display_banner({})
        s.logger.success.assert_not_called()


# ---------------------------------------------------------------------------
# run_scan -- phase gating
# ---------------------------------------------------------------------------


class TestRunScanGating:
    def _prep(self, s, monkeypatch):
        monkeypatch.setattr(s, "check_dependencies", lambda: True)
        monkeypatch.setattr(s, "validate_target", lambda h, p: True)
        monkeypatch.setattr(s, "export_results", lambda: None)
        monkeypatch.setattr(s, "get_target_info", lambda: (s.host, s.port))

    def test_comma_community_none_valid_aborts(self, monkeypatch):
        s = make_scanner(community="a,b,c")
        self._prep(s, monkeypatch)
        monkeypatch.setattr(s, "_test_communities", lambda c: [])
        out = s.run_scan()
        assert out == {"error": "no_valid_community"}

    def test_comma_community_selects_first_valid(self, monkeypatch):
        s = make_scanner(community="a,b,c")
        self._prep(s, monkeypatch)
        monkeypatch.setattr(s, "_test_communities", lambda c: ["b"])
        monkeypatch.setattr(s, "connect", lambda: None)  # stop after community phase
        out = s.run_scan()
        assert s.community == "b"
        assert out["tested_communities"] == ["b"]
        # connect() returned None -> connection_failed recorded
        assert out.get("error") == "connection_failed"

    def test_brute_requires_confirm(self, monkeypatch):
        s = make_scanner(default_creds=True, confirm_brute=False)
        self._prep(s, monkeypatch)
        out = s.run_scan()
        assert out == {}
        s.logger.fail.assert_called()

    def test_brute_sets_discovered_community(self, monkeypatch):
        s = make_scanner(default_creds=True, confirm_brute=True)
        self._prep(s, monkeypatch)
        monkeypatch.setattr(s, "_brute_communities", lambda: ["found"])
        monkeypatch.setattr(s, "connect", lambda: None)
        out = s.run_scan()
        assert s.community == "found"
        assert out["brute"] == ["found"]

    def test_enum_users_requires_confirm(self, monkeypatch):
        s = make_scanner(snmp_version="3", snmp_user="admin", enum_users=True, confirm_brute=False)
        self._prep(s, monkeypatch)
        out = s.run_scan()
        s.logger.fail.assert_called()
        assert "v3_user_enum" not in out

    def test_enum_v3_on_v2c_version_rejected(self, monkeypatch):
        # explicit -V 2c with --enum-v3 -> rejected
        s = make_scanner(snmp_version="2c", enum_v3="", confirm_brute=True)
        self._prep(s, monkeypatch)
        out = s.run_scan()
        s.logger.fail.assert_called()
        assert "v3_enumeration" not in out

    def test_missing_dependencies_short_circuits(self, monkeypatch):
        s = make_scanner()
        monkeypatch.setattr(s, "check_dependencies", lambda: False)
        out = s.run_scan()
        assert out == {"error": "missing_dependencies"}

    def test_invalid_target_short_circuits(self, monkeypatch):
        s = make_scanner()
        monkeypatch.setattr(s, "check_dependencies", lambda: True)
        monkeypatch.setattr(s, "get_target_info", lambda: (s.host, s.port))
        monkeypatch.setattr(s, "validate_target", lambda h, p: False)
        monkeypatch.setattr(s, "export_results", lambda: None)
        out = s.run_scan()
        assert out == {"error": "invalid_target"}
