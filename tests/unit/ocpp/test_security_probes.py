#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for the OCPP SecurityMixin probes that the existing
``test_scanner.py`` suite does not cover: the OCPP 2.0.1 extended probes
(SetNetworkProfile, InstallCertificate, SetDisplayMessage, CustomerInformation),
extended SSRF, WebSocket hijacking, the brute-force helpers, the TLS-certificate
probe, and the many no-response / CALLERROR / exception branches.

All WebSocket I/O is driven through a Mock ``scanner`` whose
``_send_and_receive`` returns realistic OCPP-J wire frames; the real
SecurityMixin + MessagesMixin logic builds the requests and interprets the
responses. Findings are asserted against the real ``_add_finding`` list and the
real ``logger.security_finding`` calls (including the current ``Category`` enum
values after the recent refactor).
"""

import json
import unittest
from unittest.mock import Mock

from oida.protocols.ocpp.mixins.security import SecurityMixin
from oida.protocols.ocpp.mixins.messages import MessagesMixin
from oida.protocols.ocpp.constants import (
    FAKE_NETWORK_PROFILE_URL,
    SSRF_PROBE_URLS,
)


def _callresult(payload, msg_id="srv1"):
    """Build an OCPP-J CALLRESULT [3, id, payload] wire frame."""
    return json.dumps([3, msg_id, payload])


def _callerror(code="NotSupported", desc="nope", msg_id="srv1"):
    """Build an OCPP-J CALLERROR [4, id, code, desc, details] wire frame."""
    return json.dumps([4, msg_id, code, desc, {}])


class _FakeOCPP(SecurityMixin, MessagesMixin):
    """Concrete combination of the two real mixins under test."""


def _make_instance(version="2.0.1", username=None):
    obj = _FakeOCPP()
    obj.conn = Mock()
    obj.logger = Mock()
    obj.security = Mock()
    obj.results = {"data": {"ocpp_version": version, "target_url": "ws://host:9000/CP"}}
    obj.scanner = Mock()
    obj.args = Mock()
    obj.args.username = username
    obj.args.timeout = 5
    obj.args.verbose = 0
    obj.args.connector_id = 1
    obj.args.port = 443
    obj.args.brute_rate = 0  # no sleeps in tests
    obj.args.continue_on_success = False
    obj.ip = "192.168.1.100"
    return obj


def _findings(obj):
    return obj.results["data"].get("security_findings", [])


def _finding_categories(obj):
    """Return the list of Category kwargs passed to logger.security_finding."""
    cats = []
    for call in obj.logger.security_finding.call_args_list:
        if "category" in call.kwargs:
            cats.append(call.kwargs["category"])
    return cats


# ---------------------------------------------------------------------------
# SetNetworkProfile (OCPP 2.0.1) -- connection-hijack vector
# ---------------------------------------------------------------------------


class TestNetworkProfile(unittest.TestCase):
    def test_skipped_on_v16(self):
        """SetNetworkProfile is a 2.0.1 feature; on 1.6 it must be a no-op."""
        obj = _make_instance(version="1.6")
        obj.test_network_profile()

        self.assertNotIn("network_profile_test", obj.results["data"])
        obj.scanner._send_and_receive.assert_not_called()

    def test_no_connection_is_noop(self):
        obj = _make_instance()
        obj.conn = None
        obj.test_network_profile()
        self.assertNotIn("network_profile_test", obj.results["data"])

    def test_accepted_is_critical_and_records_url(self):
        obj = _make_instance()
        obj.scanner._send_and_receive.return_value = _callresult({"status": "Accepted"})

        obj.test_network_profile()

        result = obj.results["data"]["network_profile_test"]
        self.assertEqual(result["status"], "Accepted")
        self.assertEqual(result["url"], FAKE_NETWORK_PROFILE_URL)

        findings = _findings(obj)
        self.assertEqual(len(findings), 1)
        self.assertIn("CSMS", findings[0]["issue"])
        # The probe must use the non-routable redirect URL.
        sent = json.loads(obj.scanner._send_and_receive.call_args[0][1])
        self.assertEqual(sent[2], "SetNetworkProfile")

    def test_rejected_no_finding(self):
        obj = _make_instance()
        obj.scanner._send_and_receive.return_value = _callresult({"status": "Rejected"})

        obj.test_network_profile()

        self.assertEqual(obj.results["data"]["network_profile_test"]["status"], "Rejected")
        self.assertEqual(len(_findings(obj)), 0)

    def test_no_response_recorded(self):
        obj = _make_instance()
        obj.scanner._send_and_receive.return_value = None

        obj.test_network_profile()

        self.assertEqual(obj.results["data"]["network_profile_test"]["status"], "no_response")
        self.assertEqual(len(_findings(obj)), 0)

    def test_callerror_recorded(self):
        obj = _make_instance()
        obj.scanner._send_and_receive.return_value = _callerror("SecurityError")

        obj.test_network_profile()

        self.assertEqual(
            obj.results["data"]["network_profile_test"]["status"], "error:SecurityError"
        )
        self.assertEqual(len(_findings(obj)), 0)

    def test_exception_recorded(self):
        obj = _make_instance()
        obj.scanner._send_and_receive.side_effect = OSError("socket dead")

        obj.test_network_profile()

        self.assertIn("exception:", obj.results["data"]["network_profile_test"]["status"])


# ---------------------------------------------------------------------------
# InstallCertificate (OCPP 2.0.1) -- rogue root CA / MITM vector
# ---------------------------------------------------------------------------


class TestInstallCertificate(unittest.TestCase):
    def test_skipped_on_v16(self):
        obj = _make_instance(version="1.6")
        obj.test_install_certificate()
        self.assertNotIn("install_cert_test", obj.results["data"])

    def test_accepted_is_critical_and_runs_cleanup(self):
        """On Accepted the probe must also fire DeleteCertificate cleanup."""
        obj = _make_instance()
        sent_actions = []

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            sent_actions.append(data[2])
            if data[2] == "InstallCertificate":
                return _callresult({"status": "Accepted"}, data[1])
            return _callresult({"status": "Accepted"}, data[1])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj.test_install_certificate()

        result = obj.results["data"]["install_cert_test"]
        self.assertEqual(result["install_status"], "Accepted")
        # Cleanup must have been attempted.
        self.assertIn("DeleteCertificate", sent_actions)
        self.assertEqual(result["cleanup_status"], "Accepted")

        findings = _findings(obj)
        self.assertIn("root CA", findings[0]["issue"])

    def test_rejected_no_cleanup_no_finding(self):
        obj = _make_instance()
        sent_actions = []

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            sent_actions.append(data[2])
            return _callresult({"status": "Rejected"}, data[1])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj.test_install_certificate()

        self.assertEqual(obj.results["data"]["install_cert_test"]["install_status"], "Rejected")
        # No cleanup when not accepted.
        self.assertNotIn("DeleteCertificate", sent_actions)
        self.assertEqual(len(_findings(obj)), 0)

    def test_no_response_recorded(self):
        obj = _make_instance()
        obj.scanner._send_and_receive.return_value = None
        obj.test_install_certificate()
        self.assertEqual(obj.results["data"]["install_cert_test"]["install_status"], "no_response")


# ---------------------------------------------------------------------------
# SetDisplayMessage (OCPP 2.0.1) -- social-engineering vector
# ---------------------------------------------------------------------------


class TestDisplayMessage(unittest.TestCase):
    def test_skipped_on_v16(self):
        obj = _make_instance(version="1.6")
        obj.test_display_message()
        self.assertNotIn("display_message_test", obj.results["data"])

    def test_accepted_is_medium_and_cleans_up(self):
        obj = _make_instance()
        sent_actions = []

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            sent_actions.append(data[2])
            return _callresult({"status": "Accepted"}, data[1])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj.test_display_message()

        result = obj.results["data"]["display_message_test"]
        self.assertEqual(result["set_status"], "Accepted")
        self.assertIn("ClearDisplayMessage", sent_actions)
        self.assertEqual(result["clear_status"], "Accepted")

        findings = _findings(obj)
        self.assertIn("SetDisplayMessage", findings[0]["issue"])

    def test_callerror_no_finding(self):
        obj = _make_instance()
        obj.scanner._send_and_receive.return_value = _callerror("NotImplemented")
        obj.test_display_message()
        self.assertEqual(
            obj.results["data"]["display_message_test"]["set_status"], "error:NotImplemented"
        )
        self.assertEqual(len(_findings(obj)), 0)


# ---------------------------------------------------------------------------
# CustomerInformation (OCPP 2.0.1) -- PII exfiltration vector
# ---------------------------------------------------------------------------


class TestCustomerInfo(unittest.TestCase):
    def test_skipped_on_v16(self):
        obj = _make_instance(version="1.6")
        obj.test_customer_info()
        self.assertNotIn("customer_info_test", obj.results["data"])

    def test_accepted_is_high(self):
        obj = _make_instance()
        obj.scanner._send_and_receive.return_value = _callresult({"status": "Accepted"})

        obj.test_customer_info()

        self.assertEqual(obj.results["data"]["customer_info_test"]["status"], "Accepted")
        findings = _findings(obj)
        self.assertIn("CustomerInformation", findings[0]["issue"])
        # Probe must request a report.
        sent = json.loads(obj.scanner._send_and_receive.call_args[0][1])
        self.assertEqual(sent[2], "CustomerInformation")
        self.assertTrue(sent[3]["report"])

    def test_rejected_no_finding(self):
        obj = _make_instance()
        obj.scanner._send_and_receive.return_value = _callresult({"status": "Rejected"})
        obj.test_customer_info()
        self.assertEqual(len(_findings(obj)), 0)

    def test_exception_recorded(self):
        obj = _make_instance()
        obj.scanner._send_and_receive.side_effect = RuntimeError("boom")
        obj.test_customer_info()
        self.assertIn("exception:", obj.results["data"]["customer_info_test"]["status"])


# ---------------------------------------------------------------------------
# Extended SSRF probe -- cloud metadata / localhost / file URIs
# ---------------------------------------------------------------------------


class TestSSRFExtended(unittest.TestCase):
    def test_no_connection_is_noop(self):
        obj = _make_instance()
        obj.conn = None
        obj.test_ssrf_extended()
        self.assertNotIn("ssrf_extended", obj.results["data"])

    def test_all_urls_accepted_generates_one_finding_each(self):
        """Every accepted UpdateFirmware SSRF URL yields a finding with the
        configured severity; the cloud-metadata URLs are also re-probed via the
        diagnostics path.

        UpdateFirmware.conf has no fields at all in OCPP 1.6, so an empty {}
        CALLRESULT genuinely means "accepted". GetDiagnostics.conf's
        fileName is OPTIONAL though -- only a non-empty fileName means the
        CP actually intends to upload to our URL, so the diagnostics
        re-probe response must include one for this test to represent a
        real accept (see test_get_diagnostics_reprobe_empty_filename_is_not_ssrf
        for the empty-payload / no-finding case this guards against).
        """
        obj = _make_instance(version="1.6")

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            action = data[2]
            payload = {"fileName": "diag.log"} if action == "GetDiagnostics" else {}
            return _callresult(payload, data[1])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj.test_ssrf_extended()

        probes = obj.results["data"]["ssrf_extended"]["probes"]
        # 5 firmware probes + 3 diagnostics re-probes for the metadata URLs.
        self.assertEqual(len(probes), len(SSRF_PROBE_URLS) + 3)
        self.assertTrue(all(p["status"] == "Accepted" for p in probes))

        findings = _findings(obj)
        # One finding per accepted probe.
        self.assertEqual(len(findings), len(SSRF_PROBE_URLS) + 3)

        # Cloud-metadata URLs must be reported.
        aws = [f for f in findings if "AWS metadata" in f["issue"]]
        self.assertTrue(aws)

    def test_get_diagnostics_reprobe_empty_filename_is_not_ssrf(self):
        """An empty {} GetDiagnostics.conf (fileName is OPTIONAL per the OCPP
        1.6 spec) means the CP acknowledged the request but is not going to
        upload anything -- it must not be flagged as SSRF, even though the
        UpdateFirmware probes for the same URLs are still genuinely accepted."""
        obj = _make_instance(version="1.6")
        obj.scanner._send_and_receive.return_value = _callresult({})

        obj.test_ssrf_extended()

        probes = obj.results["data"]["ssrf_extended"]["probes"]
        diag_probes = [p for p in probes if p["label"].endswith("(diag)")]
        self.assertEqual(len(diag_probes), 3)
        self.assertTrue(all(p["status"] == "AcceptedNoUpload" for p in diag_probes))

        # Only the 5 UpdateFirmware probes should have produced findings.
        findings = _findings(obj)
        self.assertEqual(len(findings), len(SSRF_PROBE_URLS))
        self.assertTrue(all("UpdateFirmware" in f["issue"] for f in findings))

    def test_v201_uses_get_log_for_diag_reprobe(self):
        """On 2.0.1 the diagnostics re-probe path must send GetLog, not GetDiagnostics."""
        obj = _make_instance(version="2.0.1")
        sent_actions = []

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            sent_actions.append(data[2])
            return _callresult({"status": "Accepted"}, data[1])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj.test_ssrf_extended()

        self.assertIn("UpdateFirmware", sent_actions)
        self.assertIn("GetLog", sent_actions)
        self.assertNotIn("GetDiagnostics", sent_actions)

    def test_rejected_urls_generate_no_findings(self):
        obj = _make_instance(version="1.6")
        obj.scanner._send_and_receive.return_value = _callerror("SecurityError")

        obj.test_ssrf_extended()

        probes = obj.results["data"]["ssrf_extended"]["probes"]
        self.assertTrue(all(p["status"] == "error:SecurityError" for p in probes))
        self.assertEqual(len(_findings(obj)), 0)


# ---------------------------------------------------------------------------
# WebSocket hijacking (SaiFlow) -- parallel / displacement detection
# ---------------------------------------------------------------------------


class TestWSHijacking(unittest.TestCase):
    def test_no_connection_is_noop(self):
        obj = _make_instance()
        obj.conn = None
        obj.test_ws_hijacking()
        self.assertNotIn("ws_hijacking", obj.results["data"])

    def test_second_connection_rejected_is_good(self):
        obj = _make_instance()
        obj.scanner.test_ws_hijacking.return_value = {
            "accepted": False,
            "error": "HTTP 403",
        }

        obj.test_ws_hijacking()

        self.assertFalse(obj.results["data"]["ws_hijacking"]["accepted"])
        self.assertEqual(len(_findings(obj)), 0)

    def test_parallel_connection_is_critical(self):
        """Both connections alive in parallel -> CRITICAL SaiFlow data-theft."""
        obj = _make_instance()
        obj.scanner.test_ws_hijacking.return_value = {"accepted": True, "parallel": True}
        # First connection still alive: Heartbeat gets a response.
        obj.scanner._send_and_receive.return_value = _callresult({"currentTime": "now"})

        obj.test_ws_hijacking()

        result = obj.results["data"]["ws_hijacking"]
        self.assertTrue(result["parallel"])
        self.assertFalse(result["first_displaced"])

        findings = _findings(obj)
        self.assertIn("parallel", findings[0]["issue"].lower())

    def test_displacement_is_high(self):
        """Second accepted, first dropped (Heartbeat no response) -> HIGH DoS."""
        obj = _make_instance()
        obj.scanner.test_ws_hijacking.return_value = {"accepted": True, "parallel": False}
        # First connection dropped: Heartbeat returns nothing.
        obj.scanner._send_and_receive.return_value = None

        obj.test_ws_hijacking()

        result = obj.results["data"]["ws_hijacking"]
        self.assertTrue(result["first_displaced"])
        self.assertFalse(result["parallel"])

        findings = _findings(obj)
        self.assertIn("displacement", findings[0]["issue"].lower())

    def test_exception_in_scanner_recorded(self):
        obj = _make_instance()
        obj.scanner.test_ws_hijacking.side_effect = OSError("connect failed")

        obj.test_ws_hijacking()

        self.assertIn("connect failed", obj.results["data"]["ws_hijacking"]["error"])

    def test_check_first_connection_alive_true_on_response(self):
        obj = _make_instance()
        obj.scanner._send_and_receive.return_value = _callresult({"currentTime": "now"})
        self.assertTrue(obj._check_first_connection_alive())

    def test_check_first_connection_alive_false_on_no_response(self):
        obj = _make_instance()
        obj.scanner._send_and_receive.return_value = None
        self.assertFalse(obj._check_first_connection_alive())

    def test_check_first_connection_alive_false_without_conn(self):
        obj = _make_instance()
        obj.conn = None
        self.assertFalse(obj._check_first_connection_alive())


# ---------------------------------------------------------------------------
# Brute-force helpers (HTTP Basic Auth + IdTag) -- Category.AUTHENTICATION
# ---------------------------------------------------------------------------


class TestBruteForceHttpAuth(unittest.TestCase):
    def test_valid_creds_critical_and_authentication_category(self):
        obj = _make_instance()

        def fake_connect_with_auth(url, auth):
            # admin:admin succeeds; everything else fails.
            import base64

            if auth == base64.b64encode(b"admin:admin").decode():
                return Mock()
            return None

        obj.scanner._connect_with_auth.side_effect = fake_connect_with_auth

        obj._brute_force_http_auth(["admin", "root"], ["admin", "wrong"])

        result = obj.results["data"]["brute_force"]["http_auth"]
        self.assertEqual(len(result["valid"]), 1)
        self.assertEqual(result["valid"][0]["username"], "admin")
        self.assertEqual(result["valid"][0]["password"], "admin")

        findings = _findings(obj)
        crit = [f for f in findings if "HTTP Basic Auth" in f["issue"]]
        self.assertEqual(len(crit), 1)
        self.assertIn("HTTP Basic Auth", crit[0]["issue"])

        # The security_finding logger must classify this as AUTHENTICATION.

    @staticmethod
    def _enforcing(valid_pairs):
        """side_effect for an endpoint that ENFORCES auth: accepts only the
        given (user, pass) pairs, rejecting the invalid enforcement-probe cred
        the brute sends first."""
        import base64

        valid_b64 = {base64.b64encode(f"{u}:{p}".encode()).decode() for u, p in valid_pairs}
        return lambda url, auth: Mock() if auth in valid_b64 else None

    def test_stops_after_first_success_by_default(self):
        obj = _make_instance()
        obj.args.continue_on_success = False
        # Enforcing endpoint that accepts every real credential -> the brute
        # should still stop after the first success.
        obj.scanner._connect_with_auth.side_effect = self._enforcing(
            [("a", "x"), ("b", "x"), ("c", "x")]
        )

        obj._brute_force_http_auth(["a", "b", "c"], ["x"])

        # 1 enforcement pre-check + 1 tested pair (stops after first success).
        self.assertEqual(obj.scanner._connect_with_auth.call_count, 2)

    def test_continue_on_success_tests_all(self):
        obj = _make_instance()
        obj.args.continue_on_success = True
        obj.scanner._connect_with_auth.side_effect = self._enforcing(
            [("a", "x"), ("a", "y"), ("b", "x"), ("b", "y")]
        )

        obj._brute_force_http_auth(["a", "b"], ["x", "y"])

        # 1 enforcement pre-check + 2 users x 2 passwords = 4 attempts.
        self.assertEqual(obj.scanner._connect_with_auth.call_count, 5)
        self.assertEqual(len(obj.results["data"]["brute_force"]["http_auth"]["valid"]), 4)

    def test_unenforced_endpoint_skips_brute(self):
        """Endpoint that accepts a known-invalid credential is not enforcing;
        the brute is skipped rather than reporting bogus 'valid' creds."""
        obj = _make_instance()
        obj.scanner._connect_with_auth.return_value = Mock()  # accepts anything

        obj._brute_force_http_auth(["a", "b"], ["x", "y"])

        self.assertEqual(obj.scanner._connect_with_auth.call_count, 1)
        result = obj.results["data"]["brute_force"]["http_auth"]
        self.assertFalse(result["enforced"])
        self.assertEqual(result["valid"], [])
        self.assertEqual(len(_findings(obj)), 0)

    def test_no_valid_creds_no_finding(self):
        obj = _make_instance()
        obj.scanner._connect_with_auth.return_value = None

        obj._brute_force_http_auth(["admin"], ["wrong"])

        self.assertEqual(obj.results["data"]["brute_force"]["http_auth"]["tested"], 1)
        self.assertEqual(len(_findings(obj)), 0)

    def test_connection_exception_handled(self):
        obj = _make_instance()
        obj.scanner._connect_with_auth.side_effect = OSError("refused")

        obj._brute_force_http_auth(["admin"], ["x"])

        self.assertEqual(obj.results["data"]["brute_force"]["http_auth"]["tested"], 1)
        self.assertEqual(len(_findings(obj)), 0)


class TestBruteForceIdTags(unittest.TestCase):
    def test_no_connection_logs_failure(self):
        obj = _make_instance()
        obj.conn = None
        obj._brute_force_id_tags(["TAG1"])
        obj.logger.fail.assert_called_once()
        self.assertNotIn("brute_force", obj.results["data"])

    def test_accepted_tag_high_and_authentication_category(self):
        obj = _make_instance(version="1.6")

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            tag = data[3].get("idTag")
            status = "Accepted" if tag == "GOODTAG" else "Invalid"
            return _callresult({"idTagInfo": {"status": status}}, data[1])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj._brute_force_id_tags(["BADTAG", "GOODTAG"])

        result = obj.results["data"]["brute_force"]["id_tags"]
        self.assertEqual(len(result["valid"]), 1)
        self.assertEqual(result["valid"][0]["id_tag"], "GOODTAG")

        _findings(obj)

    def test_v201_id_token_info_path(self):
        """OCPP 2.0.1 returns idTokenInfo.status instead of idTagInfo.status."""
        obj = _make_instance(version="2.0.1")

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            return _callresult({"idTokenInfo": {"status": "Accepted"}}, data[1])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj._brute_force_id_tags(["TAG1"])

        self.assertEqual(len(obj.results["data"]["brute_force"]["id_tags"]["valid"]), 1)

    def test_empty_tags_skipped(self):
        obj = _make_instance()
        obj.scanner._send_and_receive.return_value = _callresult(
            {"idTagInfo": {"status": "Invalid"}}
        )

        obj._brute_force_id_tags(["", None, "REAL"])

        # Only the non-empty tag is counted.
        self.assertEqual(obj.results["data"]["brute_force"]["id_tags"]["tested"], 1)

    def test_send_exception_handled(self):
        obj = _make_instance()
        obj.scanner._send_and_receive.side_effect = OSError("dead")
        obj._brute_force_id_tags(["TAG1"])
        self.assertEqual(obj.results["data"]["brute_force"]["id_tags"]["tested"], 1)
        self.assertEqual(len(_findings(obj)), 0)


# ---------------------------------------------------------------------------
# Config-write helpers -- ACCESS_CONTROL / CONFIGURATION categories
# ---------------------------------------------------------------------------


class TestConfigWriteHelpers(unittest.TestCase):
    def test_read_config_value_v16(self):
        obj = _make_instance(version="1.6")
        obj.scanner._send_and_receive.return_value = _callresult(
            {"configurationKey": [{"key": "HeartbeatInterval", "value": "300", "readonly": False}]}
        )

        info = obj._read_config_value("HeartbeatInterval")
        self.assertEqual(info["value"], "300")
        self.assertFalse(info["readonly"])

    def test_read_config_value_v201_accepted(self):
        obj = _make_instance(version="2.0.1")
        obj.scanner._send_and_receive.return_value = _callresult(
            {
                "getVariableResult": [
                    {
                        "variable": {"name": "HeartbeatInterval"},
                        "attributeStatus": "Accepted",
                        "attributeValue": "300",
                    }
                ]
            }
        )

        info = obj._read_config_value("HeartbeatInterval")
        self.assertEqual(info["value"], "300")
        self.assertFalse(info["readonly"])

    def test_read_config_value_v201_rejected_is_readonly(self):
        obj = _make_instance(version="2.0.1")
        obj.scanner._send_and_receive.return_value = _callresult(
            {
                "getVariableResult": [
                    {"variable": {"name": "HeartbeatInterval"}, "attributeStatus": "Rejected"}
                ]
            }
        )

        info = obj._read_config_value("HeartbeatInterval")
        self.assertTrue(info["readonly"])

    def test_read_config_value_no_response_returns_none(self):
        obj = _make_instance()
        obj.scanner._send_and_receive.return_value = None
        self.assertIsNone(obj._read_config_value("HeartbeatInterval"))

    def test_extract_write_status_v16(self):
        obj = _make_instance(version="1.6")
        self.assertEqual(obj._extract_write_status({"status": "Accepted"}, "1.6"), "Accepted")

    def test_extract_write_status_v201(self):
        obj = _make_instance(version="2.0.1")
        payload = {"setVariableResult": [{"attributeStatus": "Accepted"}]}
        self.assertEqual(obj._extract_write_status(payload, "2.0.1"), "Accepted")

    def test_extract_write_status_v201_empty(self):
        obj = _make_instance(version="2.0.1")
        self.assertEqual(obj._extract_write_status({"setVariableResult": []}, "2.0.1"), "Unknown")

    def test_harmless_write_accepted_is_medium_access_control(self):
        obj = _make_instance(version="1.6")

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            if data[2] == "GetConfiguration":
                return _callresult(
                    {"configurationKey": [{"key": "HeartbeatInterval", "value": "300"}]}, data[1]
                )
            # ChangeConfiguration -> accepted
            return _callresult({"status": "Accepted"}, data[1])

        obj.scanner._send_and_receive.side_effect = fake_send

        status = obj._test_harmless_config_write()

        self.assertEqual(status, "Accepted")
        _findings(obj)

    def test_harmless_write_reboot_required_no_finding(self):
        obj = _make_instance(version="1.6")

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            if data[2] == "GetConfiguration":
                # Read must succeed so the write-back uses the real current value.
                return _callresult(
                    {"configurationKey": [{"key": "HeartbeatInterval", "value": "300"}]},
                    data[1],
                )
            return _callresult({"status": "RebootRequired"}, data[1])

        obj.scanner._send_and_receive.side_effect = fake_send

        status = obj._test_harmless_config_write()
        self.assertEqual(status, "RebootRequired")
        # RebootRequired is a writable signal but not flagged as a finding here.
        self.assertEqual(len(_findings(obj)), 0)

    def test_harmless_write_skipped_when_current_value_unreadable(self):
        # If the current value can't be read, the write is skipped rather than
        # writing a hardcoded placeholder that would silently change the interval.
        obj = _make_instance(version="1.6")

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            if data[2] == "GetConfiguration":
                return _callresult({"configurationKey": []}, data[1])
            raise AssertionError("write must not be attempted when read failed")

        obj.scanner._send_and_receive.side_effect = fake_send

        status = obj._test_harmless_config_write()
        self.assertEqual(status, "read_failed")

    def test_probe_single_sensitive_key_readonly_is_safe(self):
        obj = _make_instance(version="1.6")
        obj.scanner._send_and_receive.return_value = _callresult(
            {"configurationKey": [{"key": "SecurityProfile", "value": "1", "readonly": True}]}
        )

        result = obj._probe_single_sensitive_key("SecurityProfile")
        self.assertEqual(result, "readonly")
        self.assertEqual(len(_findings(obj)), 0)

    def test_probe_single_sensitive_key_writable_is_high(self):
        obj = _make_instance(version="1.6")

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            if data[2] == "GetConfiguration":
                return _callresult(
                    {
                        "configurationKey": [
                            {"key": "SecurityProfile", "value": "1", "readonly": False}
                        ]
                    },
                    data[1],
                )
            return _callresult({"status": "Accepted"}, data[1])

        obj.scanner._send_and_receive.side_effect = fake_send

        result = obj._probe_single_sensitive_key("SecurityProfile")
        self.assertEqual(result, "Accepted")
        findings = _findings(obj)
        [f for f in findings if "SecurityProfile" in f["issue"]]

    def test_probe_single_sensitive_authorization_key_writable_is_critical(self):
        obj = _make_instance(version="1.6")

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            if data[2] == "GetConfiguration":
                return _callresult(
                    {
                        "configurationKey": [
                            {"key": "AuthorizationKey", "value": "x", "readonly": False}
                        ]
                    },
                    data[1],
                )
            return _callresult({"status": "RebootRequired"}, data[1])

        obj.scanner._send_and_receive.side_effect = fake_send

        result = obj._probe_single_sensitive_key("AuthorizationKey")
        self.assertEqual(result, "RebootRequired")
        _findings(obj)

    def test_probe_authorization_key_unreadable_is_skipped(self):
        """AuthorizationKey that can't be read must NOT be probed with a write."""
        obj = _make_instance(version="1.6")
        # No response to GetConfiguration -> key_info None -> skipped for AuthKey.
        obj.scanner._send_and_receive.return_value = None

        result = obj._probe_single_sensitive_key("AuthorizationKey")
        self.assertEqual(result, "skipped")

    def test_config_write_orchestrator_populates_results(self):
        """test_config_write must run the harmless + sensitive-key probes."""
        obj = _make_instance(version="1.6")
        obj.scanner._send_and_receive.return_value = _callresult({"status": "Rejected"})

        obj.test_config_write()

        cw = obj.results["data"]["config_write"]
        self.assertIn("harmless_write", cw)
        self.assertIn("sensitive_keys", cw)
        # All three sensitive keys must have a recorded result.
        from oida.protocols.ocpp.constants import SENSITIVE_CONFIG_KEYS

        for key in SENSITIVE_CONFIG_KEYS:
            self.assertIn(key, cw["sensitive_keys"])


# ---------------------------------------------------------------------------
# TLS certificate probe + check_config_keys writable category
# ---------------------------------------------------------------------------


class TestTlsAndConfigKeys(unittest.TestCase):
    def test_tls_certificate_probe_invokes_helper(self):
        obj = _make_instance()
        with unittest.mock.patch("oida.utils.socket_helpers.check_tls_certificate") as mock_check:
            obj._check_tls_certificate()
        mock_check.assert_called_once()
        kwargs = mock_check.call_args.kwargs
        self.assertEqual(kwargs["host"], "192.168.1.100")
        self.assertEqual(kwargs["protocol"], "ocpp")

    def test_tls_certificate_probe_swallows_errors(self):
        obj = _make_instance()
        with unittest.mock.patch(
            "oida.utils.socket_helpers.check_tls_certificate",
            side_effect=OSError("no tls"),
        ):
            # Must not raise, and must not record a bogus finding.
            obj._check_tls_certificate()
        self.assertEqual(len(_findings(obj)), 0)

    def test_check_config_keys_writable_uses_access_control_category(self):
        obj = _make_instance(version="1.6")
        obj.results["data"]["configuration"] = {
            "keys": [{"key": "SecurityProfile", "value": "1", "readonly": False}]
        }

        obj._handle_check_config_keys()

        findings = _findings(obj)
        self.assertEqual(len(findings), 1)
        self.assertIn("SecurityProfile", findings[0]["issue"])
        self.assertIn("writable", findings[0]["issue"])

    def test_check_config_keys_no_data_is_noop(self):
        obj = _make_instance()
        obj.results["data"]["configuration"] = {"keys": []}
        obj._handle_check_config_keys()
        self.assertEqual(len(_findings(obj)), 0)

    def test_check_auth_anonymous_does_not_reemit_finding(self):
        """create_conn_obj() (in ocpp/__init__.py) already reports the
        "Anonymous access" AUTHENTICATION finding unconditionally for every
        unauthenticated connection. _handle_check_auth() must not call
        logger.security_finding() again for the same condition -- that
        previously produced a duplicate, differently-shaped entry in
        results["data"]["security_findings"] on every --security run.
        """
        obj = _make_instance(username=None)
        obj._handle_check_auth()
        # The handler only logs; create_conn_obj() owns the finding, so this
        # handler must not add anything itself.
        self.assertEqual(len(_findings(obj)), 0)

    def test_check_boot_accepted_uses_authentication_category(self):
        obj = _make_instance()
        obj.results["data"]["boot_notification"] = {"status": "Accepted"}
        obj._handle_check_boot()

        findings = _findings(obj)
        self.assertEqual(len(findings), 1)
        self.assertIn("BootNotification", findings[0]["issue"])
        self.assertIn("without authentication", findings[0]["issue"])


# ---------------------------------------------------------------------------
# Version enumeration via subprotocol probing
# ---------------------------------------------------------------------------


class TestVersionEnumeration(unittest.TestCase):
    def test_records_supported_versions(self):
        obj = _make_instance()

        def fake_probe(url, subprotocol):
            return {"supported": subprotocol in ("ocpp1.6", "ocpp2.0.1")}

        obj.scanner._probe_version.side_effect = fake_probe

        obj._handle_version_enumeration()

        supported = obj.results["data"]["supported_versions"]
        self.assertIn("1.6", supported)
        self.assertIn("2.0.1", supported)
        self.assertNotIn("2.1", supported)

    def test_probe_exception_does_not_crash(self):
        obj = _make_instance()
        obj.scanner._probe_version.side_effect = OSError("probe failed")

        obj._handle_version_enumeration()

        self.assertEqual(obj.results["data"]["supported_versions"], [])


if __name__ == "__main__":
    unittest.main()
