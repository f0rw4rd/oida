"""
Unit tests for V3EnumerationMixin.

_probe_v3's network call (asyncio.run) is mocked to return error tuples so the
classifier branches are exercised; the multi-phase orchestrators (_enum_v3_users
and _enum_v3) mock _probe_v3 itself to assert phase wiring, finding emission and
the --confirm gate.
"""

from __future__ import annotations

from unittest.mock import patch


# ---------------------------------------------------------------------------
# _probe_v3 -- classifier (asyncio.run mocked)
# ---------------------------------------------------------------------------


class TestProbeV3Classifier:
    def _patch_run(self, ret):
        return patch("oida.protocols.snmp.mixins.v3_enumeration.asyncio.run", return_value=ret)

    def test_success_when_no_error(self, scanner):
        with self._patch_run((None, 0, 0)):
            assert scanner._probe_v3("admin", sec_level="noAuthNoPriv") == "SUCCESS"

    def test_authorization_error_status_is_wrong_level(self, scanner):
        # error_indication None but error_status 16 -> VACM needs higher level
        with self._patch_run((None, 16, 0)):
            assert scanner._probe_v3("admin", sec_level="noAuthNoPriv") == "WRONG_LEVEL"

    def test_unknown_user_classified(self, scanner):
        class UnknownUserName(Exception):
            pass

        with self._patch_run((UnknownUserName("Unknown USM user"), 0, 0)):
            assert scanner._probe_v3("nope", sec_level="noAuthNoPriv") == "INVALID_USER"

    def test_wrong_auth_classified(self, scanner):
        class WrongDigest(Exception):
            pass

        with self._patch_run((WrongDigest("authenticationFailure"), 0, 0)):
            res = scanner._probe_v3("admin", auth_pass="password1", sec_level="authNoPriv")
        assert res == "WRONG_AUTH"

    def test_decryption_error_is_wrong_priv(self, scanner):
        class DecryptionError(Exception):
            pass

        with self._patch_run((DecryptionError("decryptionError"), 0, 0)):
            res = scanner._probe_v3(
                "admin", auth_pass="password1", priv_pass="password2", sec_level="authPriv"
            )
        assert res == "WRONG_PRIV"

    def test_short_key_skipped(self, scanner):
        # < 8 char passphrase -> SHORT_KEY without any network call
        assert scanner._probe_v3("admin", auth_pass="short", sec_level="authNoPriv") == "SHORT_KEY"

    def test_timeout_on_exception(self, scanner):
        with patch(
            "oida.protocols.snmp.mixins.v3_enumeration.asyncio.run",
            side_effect=TimeoutError(),
        ):
            assert scanner._probe_v3("admin", sec_level="noAuthNoPriv") == "TIMEOUT"

    def test_unrecognized_error_is_error(self, scanner):
        # An unrecognized pysnmp error indication is surfaced as ERROR (with the
        # detail stashed in _last_v3_error), not silently masqueraded as a
        # no-response TIMEOUT. See _probe_v3 docstring.
        with self._patch_run((ValueError("weird transport glitch"), 0, 0)):
            assert scanner._probe_v3("admin", sec_level="noAuthNoPriv") == "ERROR"


# ---------------------------------------------------------------------------
# _enum_v3_users -- phase 1 username enumeration
# ---------------------------------------------------------------------------


class TestEnumV3Users:
    def test_noauth_user_emits_finding_and_credential(self, scanner):
        scanner.brute_rate = 0
        with patch.object(scanner, "_probe_v3", return_value="SUCCESS"):
            out = scanner._enum_v3_users(["admin"])
        assert out["valid_users"] == [{"username": "admin", "level": "noAuthNoPriv"}]
        assert out["credentials"][0]["username"] == "admin"
        # Finding title is user-specific, e.g. "No authentication (user 'admin')".
        assert any("No authentication" in t for t in scanner.logger.finding_titles)

    def test_wrong_level_marks_auth_required(self, scanner):
        scanner.brute_rate = 0
        with patch.object(scanner, "_probe_v3", return_value="WRONG_LEVEL"):
            out = scanner._enum_v3_users(["admin"])
        assert out["valid_users"] == [{"username": "admin", "level": "authRequired"}]
        assert out["credentials"] == []

    def test_invalid_user_not_recorded(self, scanner):
        scanner.brute_rate = 0
        with patch.object(scanner, "_probe_v3", return_value="INVALID_USER"):
            out = scanner._enum_v3_users(["nope", "alsono"])
        assert out["valid_users"] == []

    def test_aborts_after_consecutive_timeouts(self, scanner):
        scanner.brute_rate = 0
        # 30 usernames -> max_consecutive_timeouts = max(3, 3) = 3.
        usernames = [f"u{i}" for i in range(30)]
        calls = {"n": 0}

        def probe(username, **kw):
            calls["n"] += 1
            return "TIMEOUT"

        with patch.object(scanner, "_probe_v3", side_effect=probe):
            out = scanner._enum_v3_users(usernames)
        # Should bail well before testing all 30.
        assert calls["n"] < 30
        assert out["valid_users"] == []


# ---------------------------------------------------------------------------
# _enum_v3 -- 3-phase orchestration
# ---------------------------------------------------------------------------


class TestEnumV3:
    def _scanner(self, **kw):
        from oida.protocols.snmp.scanner import SNMPScanner
        from tests.unit.snmp.conftest import RecordingLogger

        args = {
            "host": "10.0.0.5",
            "port": 161,
            "timeout": 1,
            "snmp_version": "3",
            "brute_rate": 0,
        }
        args.update(kw)
        s = SNMPScanner(args)
        s.logger = RecordingLogger()
        return s

    def test_no_users_found_returns_empty(self):
        s = self._scanner()
        with patch.object(s, "_enum_v3_users", return_value={"valid_users": [], "credentials": []}):
            with patch("oida.utils.export_utils.export_table"):
                out = s._enum_v3()
        # _enum_v3 also reports whether the host answered at all (host_responded).
        assert out == {"valid_users": [], "credentials": [], "host_responded": True}

    def test_all_noauth_users_short_circuit_before_phase2(self):
        s = self._scanner()
        p1 = {
            "valid_users": [{"username": "guest", "level": "noAuthNoPriv"}],
            "credentials": [{"username": "guest", "security_level": "noAuthNoPriv"}],
        }
        with patch.object(s, "_enum_v3_users", return_value=p1):
            with patch.object(s, "_probe_v3") as probe:
                with patch("oida.utils.export_utils.export_table"):
                    out = s._enum_v3()
        probe.assert_not_called()  # no auth_needed users -> phase 2 skipped
        assert out["valid_users"] == p1["valid_users"]

    def test_phase2_gated_by_confirm(self):
        s = self._scanner(confirm_brute=False)
        p1 = {"valid_users": [{"username": "admin", "level": "authRequired"}], "credentials": []}
        with patch.object(s, "_enum_v3_users", return_value=p1):
            with patch("oida.utils.export_utils.export_table"):
                out = s._enum_v3()
        # Phase 2 refused -> no credentials, fail logged.
        assert out["credentials"] == []
        assert any("phase 2" in d for d in _fail_msgs(s.logger))

    def test_phase2_finds_auth_credentials(self):
        s = self._scanner(confirm_brute=True, snmp_auth_pass="public")
        p1 = {"valid_users": [{"username": "admin", "level": "authRequired"}], "credentials": []}

        # auth_pass provided + single password + single proto -> is_single_auth,
        # so SUCCESS on first probe yields credentials.
        with patch.object(s, "_enum_v3_users", return_value=p1):
            with patch.object(s, "_probe_v3", return_value="SUCCESS"):
                with patch("oida.utils.export_utils.export_table"):
                    out = s._enum_v3()
        creds = out["credentials"]
        assert len(creds) == 1
        assert creds[0]["username"] == "admin"
        assert creds[0]["auth_pass"] == "public"
        assert creds[0]["security_level"] == "authNoPriv"
        assert "Credential disclosure" in s.logger.finding_titles

    def test_wrong_level_auth_credential_survives_failed_priv_brute(self):
        """Phase 2 proves the auth password (WRONG_LEVEL = needs priv). If phase 3
        never cracks the priv key, the proven auth credential must NOT be lost --
        the export row must still carry auth_protocol + auth_pass."""
        s = self._scanner(confirm_brute=True, snmp_auth_pass="public")
        p1 = {"valid_users": [{"username": "admin", "level": "authRequired"}], "credentials": []}

        # Phase 2 single-shot returns WRONG_LEVEL (auth ok, priv required);
        # every phase-3 priv probe fails (WRONG_PRIV) so no full crack happens.
        def probe(username, **kw):
            if kw.get("sec_level") == "authPriv":
                return "WRONG_PRIV"
            return "WRONG_LEVEL"

        with patch.object(s, "_enum_v3_users", return_value=p1):
            with patch.object(s, "_probe_v3", side_effect=probe):
                with patch("oida.utils.export_utils.export_table"):
                    out = s._enum_v3()

        creds = out["credentials"]
        assert len(creds) == 1, "the proven auth credential was dropped"
        cred = creds[0]
        assert cred["username"] == "admin"
        assert cred["auth_pass"] == "public"
        assert cred["auth_protocol"]  # protocol captured
        # The internal 'authRequired-priv' sentinel is mapped to a user-facing
        # label before results are returned/exported (priv key never cracked).
        assert cred["security_level"] == "authNoPriv (priv key not recovered)"
        assert "priv_pass" not in cred  # priv never cracked

    def test_wrong_level_then_priv_success_upgrades_in_place(self):
        """When phase 3 cracks the priv key, the phase-2 auth entry is upgraded to
        authPriv in place -- exactly one credential row, fully populated."""
        s = self._scanner(confirm_brute=True, snmp_auth_pass="public", snmp_priv_pass="privpass1")
        p1 = {"valid_users": [{"username": "admin", "level": "authRequired"}], "credentials": []}

        def probe(username, **kw):
            if kw.get("sec_level") == "authPriv":
                return "SUCCESS"
            return "WRONG_LEVEL"

        with patch.object(s, "_enum_v3_users", return_value=p1):
            with patch.object(s, "_probe_v3", side_effect=probe):
                with patch("oida.utils.export_utils.export_table"):
                    out = s._enum_v3()

        creds = out["credentials"]
        assert len(creds) == 1, "duplicate credential rows for the same user"
        cred = creds[0]
        assert cred["username"] == "admin"
        assert cred["security_level"] == "authPriv"
        assert cred["auth_pass"] == "public"
        assert cred["priv_pass"] == "privpass1"

    def test_target_user_skips_phase1(self):
        s = self._scanner(confirm_brute=True, enum_v3="bob", snmp_auth_pass="password1")
        # enum_v3="bob" -> target user, phase 1 skipped; bob marked authRequired.
        with patch.object(s, "_enum_v3_users") as p1:
            with patch.object(s, "_probe_v3", return_value="SUCCESS"):
                with patch("oida.utils.export_utils.export_table"):
                    out = s._enum_v3()
        p1.assert_not_called()
        assert any(u["username"] == "bob" for u in out["valid_users"])


def _fail_msgs(logger):
    return [str(c.args[0]) for c in logger.fail.call_args_list if c.args]
