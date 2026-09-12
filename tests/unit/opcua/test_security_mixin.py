#!/usr/bin/env python3
"""Behavioural tests for the OPC UA SecurityMixin.

Focus is ``_check_server_security`` (reads namespace-0 diagnostic nodes and
emits findings / stores structured results) and ``_check_certificate`` (routes
endpoint certs through the central display function). Only the asyncua client
boundary is mocked; the parsing, finding emission and result aggregation run
for real.
"""

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from oida.protocols.opcua.mixins.security import SecurityMixin
from oida.utils.ics_logger import ICSLogger


class _ValueNode:
    """A namespace-0 node whose read_value() returns a fixed value (or raises)."""

    def __init__(self, value=None, error=None):
        self._value = value
        self._error = error

    async def read_value(self):
        if self._error is not None:
            raise self._error
        return self._value


class _Client:
    """Fake client resolving ns=0;i=<n> diagnostic nodes from a dict."""

    def __init__(self, node_map):
        # node_map: {"ns=0;i=2994": _ValueNode(...), ...}
        self._node_map = node_map

    def get_node(self, node_id):
        if node_id in self._node_map:
            return self._node_map[node_id]
        # Unknown node -> read_value raises so the mixin's try/except path runs.
        return _ValueNode(error=RuntimeError(f"BadNodeIdUnknown {node_id}"))


class _SecHost(SecurityMixin):
    def __init__(self, node_map, use_real_logger=False):
        self.args = SimpleNamespace(port=4840, timeout=10)
        if use_real_logger:
            self.logger = ICSLogger("opcua", "10.0.0.5", 4840)
            self.logger.clear_findings()
        else:
            self.logger = MagicMock()
        self.results = {"data": {}}
        self.host = "10.0.0.5"
        self._client = _Client(node_map)


# Node-id constants from the mixin docstring.
AUDITING = "ns=0;i=2994"
PROFILES = "ns=0;i=2269"
DIAG_FLAG = "ns=0;i=2294"
REJ_SESS = "ns=0;i=2279"
REJ_REQ = "ns=0;i=2287"
SESS_COUNT = "ns=0;i=2277"
SESS_DIAG = "ns=0;i=3707"
SEC_DIAG = "ns=0;i=3708"
REDUNDANCY = "ns=0;i=3709"


class TestCheckServerSecurityAuditing(unittest.IsolatedAsyncioTestCase):
    async def test_auditing_disabled_emits_finding(self):
        host = _SecHost({AUDITING: _ValueNode(value=False)}, use_real_logger=True)
        info = await host._check_server_security()

        self.assertFalse(info["auditing"])
        findings = host.logger.to_list()
        titles = {f["title"] for f in findings}
        self.assertIn("Insecure configuration", titles)
        f = next(x for x in findings if x["title"] == "Insecure configuration")
        self.assertIn("Auditing", f["detail"])

    async def test_auditing_enabled_no_finding(self):
        host = _SecHost({AUDITING: _ValueNode(value=True)}, use_real_logger=True)
        info = await host._check_server_security()
        self.assertTrue(info["auditing"])
        titles = {f["title"] for f in host.logger.to_list()}
        self.assertNotIn("Insecure configuration", titles)


class TestCheckServerSecurityProfiles(unittest.IsolatedAsyncioTestCase):
    async def test_rbac_advertised(self):
        profiles = [
            "http://opcfoundation.org/UA-Profile/Security/UserAccessFull",
            "http://opcfoundation.org/UA-Profile/Server/StandardUA",
        ]
        host = _SecHost({PROFILES: _ValueNode(value=profiles)})
        info = await host._check_server_security()
        self.assertEqual(info["server_profiles"], profiles)
        self.assertTrue(info["rbac_supported"])

    async def test_rbac_not_advertised_warns(self):
        host = _SecHost({PROFILES: _ValueNode(value=["http://example/NoRbac"])})
        info = await host._check_server_security()
        self.assertFalse(info["rbac_supported"])
        host.logger.warning.assert_any_call("  RBAC: not advertised in server profiles")


class TestCheckServerSecurityCounters(unittest.IsolatedAsyncioTestCase):
    async def test_rejection_and_session_counts(self):
        host = _SecHost(
            {
                REJ_SESS: _ValueNode(value=3),
                REJ_REQ: _ValueNode(value=7),
                SESS_COUNT: _ValueNode(value=5),
            }
        )
        info = await host._check_server_security()
        self.assertEqual(info["security_rejected_sessions"], 3)
        self.assertEqual(info["security_rejected_requests"], 7)
        self.assertEqual(info["current_session_count"], 5)

    async def test_diagnostics_flag_enabled(self):
        host = _SecHost({DIAG_FLAG: _ValueNode(value=True)})
        info = await host._check_server_security()
        self.assertTrue(info["diagnostics_enabled"])
        host.logger.display.assert_any_call("  Diagnostics: enabled (may leak info)")


class TestCheckServerSecuritySessionDiagnostics(unittest.IsolatedAsyncioTestCase):
    async def test_session_diagnostics_parsed(self):
        client_desc = SimpleNamespace(
            ApplicationName=SimpleNamespace(Text="ScadaClient"),
            ApplicationUri="urn:scada:client",
        )
        sess = SimpleNamespace(
            SessionId="ns=1;i=42",
            SessionName="OperatorSession",
            ClientDescription=client_desc,
            EndpointUrl="opc.tcp://server:4840",
            ClientConnectionTime="2026-01-01T00:00:00",
            ClientLastContactTime="2026-01-01T00:05:00",
            CurrentSubscriptionsCount=2,
            CurrentMonitoredItemsCount=10,
        )
        host = _SecHost({SESS_DIAG: _ValueNode(value=[sess])})
        info = await host._check_server_security()

        sessions = info["sessions"]
        self.assertEqual(len(sessions), 1)
        s = sessions[0]
        self.assertEqual(s["session_name"], "OperatorSession")
        self.assertEqual(s["client_app"], "ScadaClient")
        self.assertEqual(s["client_uri"], "urn:scada:client")
        self.assertEqual(s["subscriptions"], 2)
        self.assertEqual(s["monitored_items"], 10)


class TestCheckServerSecuritySecurityDiagnostics(unittest.IsolatedAsyncioTestCase):
    async def test_session_security_parsed(self):
        sess = SimpleNamespace(
            SessionId="ns=1;i=42",
            ClientUserIdOfSession="operator",
            ClientUserIdHistory=["operator"],
            AuthenticationMechanism="UserName",
            Encoding="UA Binary",
            TransportProtocol="opc.tcp",
            SecurityMode="SignAndEncrypt",
            SecurityPolicyUri="http://opcfoundation.org/UA/SecurityPolicy/Basic256Sha256",
            ClientCertificate=None,
        )
        host = _SecHost({SEC_DIAG: _ValueNode(value=[sess])})
        info = await host._check_server_security()

        sec = info["session_security"]
        self.assertEqual(len(sec), 1)
        s = sec[0]
        self.assertEqual(s["username"], "operator")
        self.assertEqual(s["auth_mechanism"], "UserName")
        self.assertEqual(s["security_mode"], "SignAndEncrypt")
        # Policy URI is reduced to just the trailing path segment.
        self.assertEqual(s["security_policy"], "Basic256Sha256")

    async def test_security_diagnostics_secure_channel_required(self):
        # A BadSecurityModeInsufficient error must be handled gracefully and
        # surface the dedicated "requires secure channel" message.
        host = _SecHost({SEC_DIAG: _ValueNode(error=RuntimeError("BadSecurityModeInsufficient"))})
        info = await host._check_server_security()
        self.assertNotIn("session_security", info)
        host.logger.display.assert_any_call("  User info: requires secure channel (SignAndEncrypt)")


class TestCheckServerSecurityRedundancy(unittest.IsolatedAsyncioTestCase):
    async def test_redundancy_named(self):
        host = _SecHost({REDUNDANCY: _ValueNode(value=3)})
        info = await host._check_server_security()
        self.assertEqual(info["redundancy_support"], "Hot")
        host.logger.display.assert_any_call("  Redundancy: Hot")

    async def test_redundancy_out_of_range(self):
        host = _SecHost({REDUNDANCY: _ValueNode(value=99)})
        info = await host._check_server_security()
        self.assertEqual(info["redundancy_support"], "99")


class TestCheckServerSecurityResultsStored(unittest.IsolatedAsyncioTestCase):
    async def test_results_aggregated_into_data(self):
        host = _SecHost(
            {
                AUDITING: _ValueNode(value=True),
                SESS_COUNT: _ValueNode(value=1),
            }
        )
        info = await host._check_server_security()
        # The returned dict is the same object stored under results.data.
        self.assertIs(host.results["data"]["security_info"], info)
        self.assertIn("auditing", info)
        self.assertIn("current_session_count", info)

    async def test_all_reads_failing_yields_empty_info(self):
        # Every diagnostic node raises -> info dict ends up empty, no crash.
        host = _SecHost({})
        info = await host._check_server_security()
        self.assertEqual(info, {})
        self.assertIs(host.results["data"]["security_info"], info)


class TestCheckCertificate(unittest.IsolatedAsyncioTestCase):
    async def test_certificate_issues_stored(self):
        ep1 = SimpleNamespace(ServerCertificate=b"\x30\x82certbytes")
        ep2 = SimpleNamespace(ServerCertificate=b"\x30\x82other")
        host = _SecHost({})
        host._client = MagicMock()
        host._client.get_endpoints = AsyncMock(return_value=[ep1, ep2])

        fake_info = {"issues": ["self-signed", "expired"]}
        with patch(
            "oida.utils.security_findings.display_cert_info", return_value=fake_info
        ) as disp:
            await host._check_certificate()

        # Only the first cert-bearing endpoint is checked.
        disp.assert_called_once()
        self.assertEqual(host.results["data"]["certificate_issues"], ["self-signed", "expired"])

    async def test_certificate_skips_empty_then_uses_next(self):
        ep_empty = SimpleNamespace(ServerCertificate=None)
        ep_real = SimpleNamespace(ServerCertificate=b"\x30\x82realcert")
        host = _SecHost({})
        host._client = MagicMock()
        host._client.get_endpoints = AsyncMock(return_value=[ep_empty, ep_real])

        captured = {}

        def _disp(logger, cert, protocol, target, verbose):
            captured["cert"] = cert
            captured["protocol"] = protocol
            return {"issues": []}

        with patch("oida.utils.security_findings.display_cert_info", _disp):
            await host._check_certificate()

        self.assertEqual(captured["cert"], b"\x30\x82realcert")
        self.assertEqual(captured["protocol"], "opcua")
        self.assertEqual(host.results["data"]["certificate_issues"], [])

    async def test_certificate_get_endpoints_error_fails_gracefully(self):
        host = _SecHost({})
        host._client = MagicMock()
        host._client.get_endpoints = AsyncMock(side_effect=RuntimeError("BadTimeout"))
        await host._check_certificate()
        host.logger.fail.assert_called()
        self.assertNotIn("certificate_issues", host.results["data"])


if __name__ == "__main__":
    unittest.main()
