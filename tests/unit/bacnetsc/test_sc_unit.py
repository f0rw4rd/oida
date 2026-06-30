"""
Unit tests for BACnet/SC pure logic (no network, no Docker):

  * wss:// URI parsing (parse_sc_uri)
  * permissive-by-default TLS context (build_client_context)
  * TLS-version / cipher / server-cert audit findings
  * rogue-cert minting

The end-to-end SC handshake + inherited-action coverage lives in the
integration suite (needs the real bacnet-stack BSC mock).
"""

import datetime
import ssl

import pytest

from oida.protocols.bacnet.mixins.sc import parse_sc_uri
from oida.protocols.bacnet import sc_tls


# --- URI parsing -----------------------------------------------------------


def test_parse_wss_uri_explicit_port():
    host, port, norm = parse_sc_uri("wss://10.0.0.5:47800", 47808)
    assert host == "10.0.0.5"
    assert port == 47800
    assert norm == "wss://10.0.0.5:47800"


def test_parse_wss_uri_default_port():
    host, port, norm = parse_sc_uri("wss://device.local", 47808)
    assert host == "device.local"
    assert port == 47808
    assert norm == "wss://device.local:47808"


def test_parse_bare_hostport_assumes_wss():
    host, port, norm = parse_sc_uri("10.0.0.5:47800", 47808)
    assert host == "10.0.0.5"
    assert port == 47800
    assert norm == "wss://10.0.0.5:47800"


def test_parse_rejects_non_ws_scheme():
    with pytest.raises(ValueError):
        parse_sc_uri("http://10.0.0.5:80", 47808)


def test_parse_rejects_empty_host():
    with pytest.raises(ValueError):
        parse_sc_uri("wss://", 47808)


# --- TLS context: permissive by default ------------------------------------


def test_context_is_permissive_by_default():
    ctx = sc_tls.build_client_context()
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


def test_context_pins_max_version_for_downgrade_probe():
    ctx = sc_tls.build_client_context(max_version=ssl.TLSVersion.TLSv1_2)
    assert ctx.maximum_version == ssl.TLSVersion.TLSv1_2
    # Still permissive — no --insecure flag exists.
    assert ctx.verify_mode == ssl.CERT_NONE


# --- audit findings --------------------------------------------------------


class _FindingLog:
    """Minimal logger capturing security_finding(title, category, detail)."""

    def __init__(self):
        self.findings = []

    def security_finding(self, title, category="", detail=""):
        self.findings.append((title, str(category), detail))

    def titles(self):
        return [t for t, _c, _d in self.findings]


def test_tls_version_finding_fires_below_13():
    log = _FindingLog()
    sc_tls.audit_tls_version(("TLS_AES_256_GCM_SHA384", "TLSv1.2", 256), log)
    assert any("TLS 1.3" in t for t in log.titles())


def test_tls_version_finding_silent_on_13():
    log = _FindingLog()
    sc_tls.audit_tls_version(("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), log)
    assert log.findings == []


def test_cipher_finding_fires_on_weak_token():
    log = _FindingLog()
    sc_tls.audit_cipher(("ECDHE-RSA-DES-CBC3-SHA", "TLSv1.2", 112), log)
    titles = log.titles()
    assert any("cipher" in t.lower() for t in titles)


def test_cipher_finding_silent_on_strong():
    log = _FindingLog()
    sc_tls.audit_cipher(("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), log)
    assert log.findings == []


def _mint_cert(self_signed=True, key_size=2048, sig_sha1=False, not_after_days=3650):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device")])
    issuer = (
        subject if self_signed else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "real-ca")])
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    algo = hashes.SHA1() if sig_sha1 else hashes.SHA256()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=not_after_days))
    )
    cert = builder.sign(key, algo)
    return cert.public_bytes(serialization.Encoding.DER)


def test_server_cert_self_signed_finding():
    log = _FindingLog()
    der = _mint_cert(self_signed=True)
    sc_tls.audit_server_cert(der, "10.0.0.5", log)
    assert any("self-signed" in t.lower() for t in log.titles())


def test_server_cert_weak_rsa_finding():
    log = _FindingLog()
    der = _mint_cert(self_signed=False, key_size=1024)
    sc_tls.audit_server_cert(der, "10.0.0.5", log)
    assert any("weak rsa" in t.lower() for t in log.titles())


def test_server_cert_expired_finding():
    log = _FindingLog()
    der = _mint_cert(self_signed=False, not_after_days=-1)
    sc_tls.audit_server_cert(der, "10.0.0.5", log)
    assert any("expired" in t.lower() for t in log.titles())


def test_rogue_cert_files_are_usable():
    cert, key = sc_tls.make_rogue_cert_files()
    # Loading into a context must succeed (valid self-signed pair).
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    import os

    os.unlink(cert)
    os.unlink(key)
