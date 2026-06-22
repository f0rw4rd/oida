"""Tests for fail-closed issuer-trust evaluation in security_findings.

Regression for the MEDIUM finding: _is_issuer_trusted() used to fail OPEN
(return True) when the system root store was empty or when trust evaluation
raised, silently suppressing the 'Untrusted CA' security finding. It must now
fail CLOSED: return False on an empty store and None ("could not verify") on
error, and check_certificate() must emit a finding in both cases.
"""

import datetime

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from oida.utils import security_findings


def _make_ca_signed_cert():
    """Build a leaf cert whose issuer != subject (CA-signed shape)."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Definitely Not Trusted CA Inc"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Definitely Not Trusted Root"),
        ]
    )
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Device Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "device.example.local"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    return cert


class _CapturingLogger:
    def __init__(self):
        self.findings = []

    def security_finding(self, title, detail=None):
        self.findings.append((title, detail))

    def debug(self, *a, **k):
        pass

    def display(self, *a, **k):
        pass

    def warning(self, *a, **k):
        pass


class _EmptyStoreCtx:
    def get_ca_certs(self, binary_form=False):
        return []


class _RaisingCtx:
    def get_ca_certs(self, binary_form=False):
        raise OSError("trust store unavailable")


def test_empty_root_store_treated_as_untrusted(monkeypatch):
    """Empty system root store must NOT be read as 'trusted' (fail closed)."""
    cert = _make_ca_signed_cert()
    monkeypatch.setattr(
        __import__("ssl"),
        "create_default_context",
        lambda: _EmptyStoreCtx(),
    )
    assert security_findings._is_issuer_trusted(cert) is False


def test_trust_eval_error_returns_none(monkeypatch):
    """An exception during trust evaluation must yield None, not True."""
    cert = _make_ca_signed_cert()
    monkeypatch.setattr(
        __import__("ssl"),
        "create_default_context",
        lambda: _RaisingCtx(),
    )
    assert security_findings._is_issuer_trusted(cert) is None


def test_check_certificate_emits_untrusted_on_empty_store(monkeypatch):
    """check_certificate must emit the Untrusted CA finding on empty store."""
    cert = _make_ca_signed_cert()
    monkeypatch.setattr(
        __import__("ssl"),
        "create_default_context",
        lambda: _EmptyStoreCtx(),
    )
    log = _CapturingLogger()
    issues = security_findings.check_certificate(log, cert, "tls", "host")
    assert "Untrusted CA (not in system root store)" in issues
    assert any("Untrusted CA" in t for t, _ in log.findings)


def test_check_certificate_emits_unverified_on_error(monkeypatch):
    """check_certificate must surface 'could not verify' instead of dropping it."""
    cert = _make_ca_signed_cert()
    monkeypatch.setattr(
        __import__("ssl"),
        "create_default_context",
        lambda: _RaisingCtx(),
    )
    log = _CapturingLogger()
    issues = security_findings.check_certificate(log, cert, "tls", "host")
    assert "Could not verify issuer trust" in issues
    assert any("Could not verify issuer trust" in t for t, _ in log.findings)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
