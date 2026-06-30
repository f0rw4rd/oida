"""OPC UA pre-auth endpoint summary must flag MessageSecurityMode.Invalid.

Gap parity with OpalOPC plugin 10005 (SecurityModeInvalid): an endpoint that
advertises ``MessageSecurityMode.Invalid`` (enum value 0) is a spec violation
and must be surfaced as a security issue, not silently bucketed/dropped.
"""

import asyncio
import unittest
from types import SimpleNamespace
from unittest import mock

from oida.protocols.opcua.mixins.discovery import DiscoveryMixin


class _StubLogger:
    def __init__(self):
        self.warnings = []

    def display(self, *a, **k):
        pass

    def debug(self, *a, **k):
        pass

    def warning(self, *a, **k):
        self.warnings.append(a[0] if a else "")


class _Harness(DiscoveryMixin):
    def __init__(self):
        self.logger = _StubLogger()
        self.args = mock.Mock(test_cert_trust=False)
        self.results = {"data": {}}


def _ep(mode_name, policy_uri="", tokens=None):
    return SimpleNamespace(
        SecurityMode=SimpleNamespace(name=mode_name),
        SecurityPolicyUri=policy_uri,
        UserIdentityTokens=tokens or [],
        ServerCertificate=None,
    )


class TestSecurityModeInvalid(unittest.TestCase):
    def test_invalid_mode_flagged(self):
        h = _Harness()
        endpoints = [_ep("Invalid", policy_uri=""), _ep("SignAndEncrypt", "x#Basic256Sha256")]
        asyncio.run(h._show_endpoints_summary(endpoints))

        self.assertTrue(h.results["data"]["has_mode_invalid"])
        self.assertTrue(any("Invalid" in w for w in h.logger.warnings))

    def test_no_invalid_mode_not_flagged(self):
        h = _Harness()
        endpoints = [_ep("None_", policy_uri=""), _ep("SignAndEncrypt", "x#Basic256Sha256")]
        asyncio.run(h._show_endpoints_summary(endpoints))

        self.assertFalse(h.results["data"]["has_mode_invalid"])


if __name__ == "__main__":
    unittest.main()
