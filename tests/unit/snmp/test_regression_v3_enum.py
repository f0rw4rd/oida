"""
Regression tests for SNMP bugs that the integration suite missed because it is
skip-gated on a Docker mock (so CI never ran it). Each test exercises the code
path directly with mocked pysnmp so the bug would turn the test red without a
live agent.

- V1: `_probe_v3` imported a non-existent `_pad_snmp_key` -> ImportError on every
      authenticated probe (silently swallowed as TIMEOUT in some callers).
- V5: `-E/--enum-v3` with the default `-V auto` was rejected ("requires SNMPv3")
      because the enum-v3 branch forced version=3 only AFTER its v1/v2c guard.
- V2: `enum_limit` was enforced per-column, so a wide table extracted up to
      limit x num_columns rows instead of `limit` total.
"""

import asyncio
from unittest.mock import patch

from .test_snmp_enhancements import FakeVarBind, scanner  # noqa: F401  (reuse fixture)


def _make_scanner(**overrides):
    from oida.protocols.snmp.scanner import SNMPScanner

    args = {
        "host": "127.0.0.1",
        "port": 161,
        "timeout": 1,
        "snmp_version": "2c",
    }
    args.update(overrides)
    return SNMPScanner(args)


# ---------------------------------------------------------------------------
# V1 -- _probe_v3 must not crash on the auth/priv key path
# ---------------------------------------------------------------------------


class TestV1ProbeImport:
    def test_authnopriv_probe_does_not_raise_importerror(self, scanner):
        """An authNoPriv probe builds an auth key -> exercises the import that
        used to be `_pad_snmp_key` (nonexistent). Must classify, not crash."""
        with patch(
            "oida.protocols.snmp.mixins.v3_enumeration.asyncio.run",
            return_value=(None, 0, 0),
        ):
            result = scanner._probe_v3("admin", auth_pass="admin123", sec_level="authNoPriv")
        assert result == "SUCCESS"

    def test_authpriv_probe_does_not_raise_importerror(self, scanner):
        with patch(
            "oida.protocols.snmp.mixins.v3_enumeration.asyncio.run",
            return_value=(None, 0, 0),
        ):
            result = scanner._probe_v3(
                "admin", auth_pass="admin123", priv_pass="privpass1", sec_level="authPriv"
            )
        assert result == "SUCCESS"

    def test_short_key_is_skipped_not_fatal(self, scanner):
        """A < 8-char wordlist entry can't be a valid RFC 3414 key -> skip it
        (SHORT_KEY) instead of raising and aborting the whole brute phase."""
        result = scanner._probe_v3("admin", auth_pass="short", sec_level="authNoPriv")
        assert result == "SHORT_KEY"


# ---------------------------------------------------------------------------
# V5 -- -E/--enum-v3 with -V auto must reach phase 1 (force v3)
# ---------------------------------------------------------------------------


class TestV5EnumV3AutoVersion:
    def test_enum_v3_auto_forces_v3_and_runs(self, monkeypatch):
        s = _make_scanner(snmp_version="auto", enum_v3="", confirm_brute=True)
        assert s._version_auto and s.enum_v3

        called = {}
        monkeypatch.setattr(s, "check_dependencies", lambda: True)
        monkeypatch.setattr(s, "validate_target", lambda h, p: True)
        monkeypatch.setattr(s, "export_results", lambda: None)

        def fake_enum_v3():
            called["ran"] = True
            return {"valid_users": [], "credentials": []}

        monkeypatch.setattr(s, "_enum_v3", fake_enum_v3)
        s.run_scan()

        assert called.get("ran"), "enum_v3 branch never ran -- version guard rejected -V auto"
        assert s.version == "3"

    def test_enum_users_auto_forces_v3_and_runs(self, monkeypatch):
        s = _make_scanner(snmp_version="auto", enum_users=True, confirm_brute=True)
        assert s._version_auto and s.enum_users

        called = {}
        monkeypatch.setattr(s, "check_dependencies", lambda: True)
        monkeypatch.setattr(s, "validate_target", lambda h, p: True)
        monkeypatch.setattr(s, "export_results", lambda: None)

        def fake_enum_users(usernames):
            called["ran"] = True
            return {"valid_users": []}

        monkeypatch.setattr(s, "_enum_v3_users", fake_enum_users)
        s.run_scan()

        assert called.get("ran"), "enum_users branch never ran -- version guard rejected -V auto"
        assert s.version == "3"


# ---------------------------------------------------------------------------
# V2 -- enum_limit is a table-wide row cap, not per column
# ---------------------------------------------------------------------------


class TestV2EnumLimitTableWide:
    def test_walk_table_caps_total_rows(self, scanner):
        scanner.enum_limit = 3
        base_a = ".1.3.6.1.2.1.4.20.1.1"
        base_b = ".1.3.6.1.2.1.4.20.1.2"
        calls = [0]

        async def fake_walk(*args, **kwargs):
            calls[0] += 1
            base = (base_a if calls[0] == 1 else base_b).lstrip(".")
            for i in range(1, 7):  # 6 distinct index suffixes per column
                yield None, None, None, [FakeVarBind(f"{base}.{i}", f"val{i}")]

        with (
            patch("pysnmp.hlapi.asyncio.walk_cmd", side_effect=lambda *a, **k: fake_walk(*a, **k)),
            patch("pysnmp.hlapi.asyncio.ObjectIdentity", lambda x: x),
            patch("pysnmp.hlapi.asyncio.ObjectType", lambda x: x),
        ):
            rows = asyncio.run(
                scanner._walk_table(None, None, None, None, {"a": base_a, "b": base_b})
            )

        # Before the fix this returned 6 (limit reset per column); now <= 3 total.
        assert len(rows) <= 3, f"enum_limit not table-wide: got {len(rows)} rows"

    def test_walk_table_skips_out_of_scope_oids(self, scanner):
        """A sibling subtree (...1.1 vs ...1.10) must not be merged into rows."""
        base = ".1.3.6.1.2.1.4.22.1.2"

        async def fake_walk(*args, **kwargs):
            b = base.lstrip(".")
            yield None, None, None, [FakeVarBind(f"{b}.100", "in-scope")]
            # sibling column ...1.20 -- NOT under base + "."
            yield None, None, None, [FakeVarBind("1.3.6.1.2.1.4.22.1.20.5", "sibling")]

        with (
            patch("pysnmp.hlapi.asyncio.walk_cmd", side_effect=lambda *a, **k: fake_walk(*a, **k)),
            patch("pysnmp.hlapi.asyncio.ObjectIdentity", lambda x: x),
            patch("pysnmp.hlapi.asyncio.ObjectType", lambda x: x),
        ):
            rows = asyncio.run(scanner._walk_table(None, None, None, None, {"mac": base}))

        assert list(rows.keys()) == ["100"], f"out-of-scope OID leaked into rows: {rows}"
