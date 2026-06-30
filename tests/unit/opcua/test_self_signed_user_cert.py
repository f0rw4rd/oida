"""OPC UA self-signed *user* certificate acceptance test (OpalOPC plugin 10016).

Distinct from the app/secure-channel cert probe: this presents an untrusted
self-signed X509 token as a *user identity*. A server that activates a session
with it does not validate user certs against a trust list.

Same honest-reporting discipline as the app-cert probe: only explicit
cert/identity-rejection codes count as a clean rejection; timeouts and
unrelated errors are inconclusive.
"""

import asyncio
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

from oida.protocols.opcua.mixins import security as sec_mod
from oida.protocols.opcua.mixins.security import SecurityMixin


class _StubLogger:
    def __init__(self):
        self.success_calls = []
        self.findings = []

    def display(self, *a, **k):
        pass

    def debug(self, *a, **k):
        pass

    def warning(self, *a, **k):
        pass

    def success(self, *a, **k):
        self.success_calls.append(a[0] if a else "")

    def security_finding(self, title, **k):
        self.findings.append(title)


class _Harness(SecurityMixin):
    def __init__(self):
        self.logger = _StubLogger()
        self.debug = False
        self.host = "h"
        self._original_url = "opc.tcp://h:4840"
        self.args = mock.Mock(port=4840, timeout=5)


def _cert_endpoint(policy="None"):
    token = SimpleNamespace(TokenType=SimpleNamespace(name="Certificate"))
    return SimpleNamespace(
        UserIdentityTokens=[token],
        SecurityPolicyUri=f"http://x#{policy}",
        EndpointUrl="opc.tcp://h:4840",
    )


def _anon_endpoint():
    token = SimpleNamespace(TokenType=SimpleNamespace(name="Anonymous"))
    return SimpleNamespace(
        UserIdentityTokens=[token],
        SecurityPolicyUri="http://x#None",
        EndpointUrl="opc.tcp://h:4840",
    )


@contextmanager
def _client(connect_behavior, record=None):
    """Stub all crypto + the Client; connect_behavior() runs inside connect()."""

    class _FakeClient:
        def __init__(self, *a, **k):
            self.application_uri = None
            self.certificate_validator = None
            if record is not None:
                record["connect_url"] = k.get("url", a[0] if a else None)

        async def set_security(self, *a, **k):
            if record is not None:
                record["set_security"] = True

        async def load_client_certificate(self, *a, **k):
            if record is not None:
                record["loaded_user_cert"] = True

        async def load_private_key(self, *a, **k):
            if record is not None:
                record["loaded_user_key"] = True

        async def connect(self):
            return connect_behavior()

        async def disconnect(self):
            pass

    avail = mock.Mock(is_available=True)
    avail.setup_self_signed_certificate = mock.AsyncMock(return_value=None)
    sec_pol = mock.Mock(SecurityPolicyBasic256Sha256=object())
    x509 = mock.Mock(is_available=True)
    x509.x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH = 1

    with (
        mock.patch.object(sec_mod, "_asyncua_cert_gen", avail),
        mock.patch.object(sec_mod, "_asyncua_sec_policies", sec_pol),
        mock.patch.object(sec_mod, "_cryptography_x509", x509),
        mock.patch("oida.protocols.opcua.helpers._get_client_class", return_value=_FakeClient),
    ):
        yield


def _ok():
    return None


def _raise(exc):
    def _inner():
        raise exc

    return _inner


class TestSelfSignedUserCert(unittest.TestCase):
    def test_not_applicable_when_no_cert_token(self):
        h = _Harness()
        # No connect should ever be attempted; crypto need not even be stubbed.
        result = asyncio.run(h._test_self_signed_user_cert_acceptance([_anon_endpoint()]))
        self.assertFalse(result["applicable"])
        self.assertFalse(result["tested"])
        self.assertEqual(h.logger.findings, [])

    def test_connects_to_reachable_url_not_advertised_endpoint(self):
        # The server advertises an unroutable EndpointUrl (its own hostname /
        # 0.0.0.0); the probe must connect to the address we actually reached
        # (self._original_url), since asyncua selects the endpoint by policy.
        h = _Harness()
        h._original_url = "opc.tcp://10.0.0.5:4840/scan"
        ep = SimpleNamespace(
            UserIdentityTokens=[SimpleNamespace(TokenType=SimpleNamespace(name="Certificate"))],
            SecurityPolicyUri="http://x#None",
            EndpointUrl="opc.tcp://unroutable-internal-host:4840",
        )
        record = {}
        with _client(_ok, record):
            asyncio.run(h._test_self_signed_user_cert_acceptance([ep]))
        self.assertEqual(record.get("connect_url"), "opc.tcp://10.0.0.5:4840/scan")

    def test_accepts_untrusted_user_cert_is_finding(self):
        h = _Harness()
        record = {}
        with _client(_ok, record):
            result = asyncio.run(h._test_self_signed_user_cert_acceptance([_cert_endpoint("None")]))
        self.assertTrue(result["applicable"])
        self.assertTrue(result["tested"])
        self.assertTrue(result["accepts_untrusted_user_cert"])
        self.assertIn("Self-signed user certificate accepted", h.logger.findings)
        # None-policy endpoint => no secure channel needed, user cert/key loaded.
        self.assertNotIn("set_security", record)
        self.assertTrue(record.get("loaded_user_cert"))
        self.assertTrue(record.get("loaded_user_key"))

    def test_policy_endpoint_sets_up_secure_channel(self):
        h = _Harness()
        record = {}
        with _client(_ok, record):
            result = asyncio.run(
                h._test_self_signed_user_cert_acceptance([_cert_endpoint("Basic256Sha256")])
            )
        self.assertTrue(result["accepts_untrusted_user_cert"])
        # Policy endpoint => secure channel app cert configured.
        self.assertTrue(record.get("set_security"))

    def test_genuine_rejection_reports_clean(self):
        h = _Harness()
        with _client(_raise(Exception("BadIdentityTokenRejected"))):
            result = asyncio.run(h._test_self_signed_user_cert_acceptance([_cert_endpoint("None")]))
        self.assertTrue(result["tested"])
        self.assertFalse(result["accepts_untrusted_user_cert"])
        self.assertIn("rejection_reason", result)
        self.assertEqual(len(h.logger.success_calls), 1)
        self.assertEqual(h.logger.findings, [])

    def test_timeout_is_inconclusive(self):
        h = _Harness()
        with _client(_raise(asyncio.TimeoutError())):
            result = asyncio.run(h._test_self_signed_user_cert_acceptance([_cert_endpoint("None")]))
        self.assertFalse(result["tested"])
        self.assertEqual(result.get("status"), "inconclusive")
        self.assertNotIn("rejection_reason", result)
        self.assertEqual(h.logger.findings, [])

    def test_unrelated_error_is_inconclusive(self):
        h = _Harness()
        with _client(_raise(OSError("connection reset"))):
            result = asyncio.run(h._test_self_signed_user_cert_acceptance([_cert_endpoint("None")]))
        self.assertFalse(result["tested"])
        self.assertEqual(result.get("status"), "inconclusive")
        self.assertEqual(h.logger.findings, [])


if __name__ == "__main__":
    unittest.main()
