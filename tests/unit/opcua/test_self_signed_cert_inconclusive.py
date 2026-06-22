"""OPC UA self-signed-cert probe must not report vuln-clean on unrelated errors.

CODE_REVIEW.md #14 [HIGH]:
mixins/security.py _test_self_signed_cert_acceptance treated asyncio.TimeoutError
and any error mentioning "timeout"/"certificate" as proof the server REJECTS
untrusted client certs (logger.success). A timeout / unrelated cert-handshake
error says nothing about the server's trust decision, so a genuinely vulnerable
server could be silently reported clean (false negative).

Fix: timeouts and ambiguous errors -> tested=False, status="inconclusive";
only explicit cert-rejection codes -> rejection (tested=True, rejection_reason).
"""

import asyncio
import unittest
from contextlib import contextmanager
from unittest import mock

from oida.protocols.opcua.mixins import security as sec_mod
from oida.protocols.opcua.mixins.security import SecurityMixin


class _StubLogger:
    def __init__(self):
        self.success_calls = []

    def display(self, *a, **k):
        pass

    def debug(self, *a, **k):
        pass

    def warning(self, *a, **k):
        pass

    def success(self, *a, **k):
        self.success_calls.append(a[0] if a else "")


class _Harness(SecurityMixin):
    def __init__(self):
        self.logger = _StubLogger()
        self.debug = False
        self.args = mock.Mock(port=4840)


@contextmanager
def _connect_raises(exc):
    """Make the probe reach connect() and raise `exc`, with all crypto stubbed."""

    class _FakeClient:
        def __init__(self, *a, **k):
            self.application_uri = None
            self.certificate_validator = None

        async def set_security(self, *a, **k):
            pass

        async def connect(self):
            raise exc

        async def disconnect(self):
            pass

    avail = mock.Mock(is_available=True)
    avail.setup_self_signed_certificate = mock.AsyncMock(return_value=None)
    sec_pol = mock.Mock(SecurityPolicyBasic256Sha256=object())
    validator = mock.Mock(
        CertificateValidator=lambda *a, **k: object(),
        CertificateValidatorOptions=mock.Mock(EXT_VALIDATION=1),
    )
    x509 = mock.Mock(is_available=True)
    x509.x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH = 1

    with (
        mock.patch.object(sec_mod, "_asyncua_cert_gen", avail),
        mock.patch.object(sec_mod, "_asyncua_sec_policies", sec_pol),
        mock.patch.object(sec_mod, "_asyncua_validator", validator),
        mock.patch.object(sec_mod, "_cryptography_x509", x509),
        mock.patch("oida.protocols.opcua.helpers._get_client_class", return_value=_FakeClient),
    ):
        yield


class TestSelfSignedCertInconclusive(unittest.TestCase):
    def _run(self, exc):
        h = _Harness()
        with _connect_raises(exc):
            return h, asyncio.run(h._test_self_signed_cert_acceptance("opc.tcp://h:4840"))

    def test_timeout_is_inconclusive_not_clean(self):
        h, result = self._run(asyncio.TimeoutError())
        # MUST NOT be reported as a completed rejection (vuln-clean).
        self.assertFalse(result.get("tested"))
        self.assertEqual(result.get("status"), "inconclusive")
        self.assertNotIn("rejection_reason", result)
        self.assertFalse(result["accepts_untrusted_client_cert"])
        self.assertEqual(h.logger.success_calls, [])

    def test_unrelated_certificate_error_is_inconclusive(self):
        # Error string merely mentions "certificate" — not a trust decision.
        h, result = self._run(OSError("certificate file unreadable"))
        self.assertFalse(result.get("tested"))
        self.assertEqual(result.get("status"), "inconclusive")
        self.assertNotIn("rejection_reason", result)
        self.assertEqual(h.logger.success_calls, [])

    def test_genuine_rejection_still_reports_clean(self):
        h, result = self._run(Exception("BadSecurityChecksFailed: untrusted cert"))
        self.assertTrue(result.get("tested"))
        self.assertIn("rejection_reason", result)
        self.assertFalse(result["accepts_untrusted_client_cert"])
        self.assertEqual(len(h.logger.success_calls), 1)


if __name__ == "__main__":
    unittest.main()
