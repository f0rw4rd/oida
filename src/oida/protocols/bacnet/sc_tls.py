"""
BACnet/SC TLS context construction + automatic security posture checks.

Two responsibilities:

1. build_client_context(...) — builds the ssl.SSLContext OIDA uses to dial the
   device/hub. PERMISSIVE BY DEFAULT (verify_mode=CERT_NONE, check_hostname=
   False): this is a pentest tool that must connect to whatever is there. The
   client cert/key, when supplied, are always loaded and PRESENTED so the device
   sees a mutual-auth attempt.

2. audit_* helpers — run automatically on every SC connection (no flag) and
   emit findings via logger.security_finding(..., Category.ENCRYPTION|
   AUTHENTICATION). They verify the device ENFORCES its security settings, not
   merely that a connection succeeded:
     * TLS version (BACnet/SC mandates 1.3 — flag < 1.3)
     * weak/deprecated cipher suites
     * server certificate hygiene (self-signed/untrusted, expiry, weak key,
       weak signature algorithm, SAN/hostname mismatch)
     * MUTUAL-AUTH ENFORCEMENT — the most important check: re-dial with NO
       client cert and with a ROGUE self-signed client cert; a device/hub that
       accepts either is critically misconfigured.
"""

from __future__ import annotations

import datetime
import ssl
import tempfile
from typing import Optional

from ...utils.common_types import Category


def build_client_context(
    ca: Optional[str] = None,
    cert: Optional[str] = None,
    key: Optional[str] = None,
    *,
    min_version: Optional[int] = None,
    max_version: Optional[int] = None,
) -> ssl.SSLContext:
    """Build a PERMISSIVE TLS client context for BACnet/SC.

    Server-cert verification is intentionally disabled (CERT_NONE,
    check_hostname False) — no --insecure flag exists because permissive IS the
    default for this tool. A supplied client cert/key is still loaded and
    presented for mutual-auth testing. min/max_version let the audit probes pin
    a TLS version (e.g. force 1.2 to test downgrade acceptance).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if min_version is not None:
        ctx.minimum_version = min_version  # type: ignore[assignment]
    if max_version is not None:
        ctx.maximum_version = max_version  # type: ignore[assignment]
    if cert and key:
        ctx.load_cert_chain(certfile=cert, keyfile=key)
    if ca:
        try:
            ctx.load_verify_locations(cafile=ca)
        except Exception:
            pass
    return ctx


# --- certificate inspection -------------------------------------------------


def _load_cryptography():
    """Lazy import cryptography (only needed for cert hygiene parsing)."""
    try:
        from cryptography import x509  # noqa: F401
        from cryptography.hazmat.primitives.asymmetric import rsa, ec  # noqa: F401

        return True
    except Exception:
        return False


def audit_tls_version(cipher_tuple, logger) -> None:
    """cipher_tuple = (name, tls_version, secret_bits) from getpeercert path."""
    if not cipher_tuple:
        return
    name, version, _bits = cipher_tuple
    if version and version != "TLSv1.3":
        logger.security_finding(
            "BACnet/SC not using TLS 1.3",
            Category.ENCRYPTION,
            f"Negotiated {version}; BACnet/SC (ANSI/ASHRAE 135 Annex AB) "
            f"mandates TLS 1.3. Device accepts a weaker TLS version.",
        )


_WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES", "MD5", "NULL", "EXPORT", "CBC")


def audit_cipher(cipher_tuple, logger) -> None:
    if not cipher_tuple:
        return
    name, _version, bits = cipher_tuple
    upper = (name or "").upper()
    if any(tok in upper for tok in _WEAK_CIPHER_TOKENS):
        logger.security_finding(
            "Weak/deprecated TLS cipher suite",
            Category.ENCRYPTION,
            f"Negotiated cipher {name} is weak or deprecated.",
        )
    if bits and bits < 128:
        logger.security_finding(
            "Weak TLS cipher key length",
            Category.ENCRYPTION,
            f"Negotiated cipher {name} provides only {bits}-bit security.",
        )


def audit_server_cert(cert_der: Optional[bytes], host: str, logger) -> None:
    """Inspect the server's operational certificate for hygiene problems."""
    if not cert_der:
        return
    if not _load_cryptography():
        return
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.hazmat.primitives import hashes

    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as e:
        logger.debug(f"BACnet/SC server certificate could not be parsed for audit: {e}")
        return

    # Self-signed — SC expects a real PKI chain. A DN equality test
    # (issuer == subject) is only a heuristic: it false-positives on an
    # intermediate-signed cert that happens to reuse a name and false-negatives
    # on a self-issued cert with a cosmetically different issuer string. Verify
    # the signature against the cert's OWN public key (cryptography >= 40's
    # verify_directly_issued_by); only assert "self-signed" when both the name
    # matches AND the cert actually signed itself. Fall back to the DN heuristic
    # if the API is unavailable.
    try:
        names_match = cert.issuer == cert.subject
        self_signed = names_match
        if names_match and hasattr(cert, "verify_directly_issued_by"):
            try:
                cert.verify_directly_issued_by(cert)
                self_signed = True
            except Exception:
                # Name collision but NOT signed by itself (e.g. a sub-CA reusing
                # the DN): genuinely chains to another issuer, so not self-signed.
                self_signed = False
        if self_signed:
            logger.security_finding(
                "BACnet/SC server certificate is self-signed",
                Category.ENCRYPTION,
                f"Subject == issuer ({cert.subject.rfc4514_string()}) and the "
                f"cert is signed by its own key; it does not chain to a CA.",
            )
    except Exception as e:
        logger.debug(f"BACnet/SC cert self-signed check could not run: {e}")

    # Validity window.
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:  # older cryptography
        not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    if now > not_after:
        logger.security_finding(
            "BACnet/SC server certificate expired",
            Category.ENCRYPTION,
            f"Expired {not_after.isoformat()}.",
        )
    if now < not_before:
        logger.security_finding(
            "BACnet/SC server certificate not yet valid",
            Category.ENCRYPTION,
            f"Not valid before {not_before.isoformat()}.",
        )

    # Public-key strength.
    try:
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey) and pub.key_size < 2048:
            logger.security_finding(
                "BACnet/SC server certificate weak RSA key",
                Category.ENCRYPTION,
                f"RSA key size {pub.key_size} < 2048 bits.",
            )
        elif isinstance(pub, ec.EllipticCurvePublicKey) and pub.curve.key_size < 256:
            logger.security_finding(
                "BACnet/SC server certificate weak EC curve",
                Category.ENCRYPTION,
                f"EC curve {pub.curve.name} ({pub.curve.key_size} bits) < 256.",
            )
    except Exception as e:
        logger.debug(f"BACnet/SC cert public-key strength check could not run: {e}")

    # Signature algorithm.
    try:
        sig = cert.signature_hash_algorithm
        if isinstance(sig, (hashes.MD5, hashes.SHA1)):
            logger.security_finding(
                "BACnet/SC server certificate weak signature algorithm",
                Category.ENCRYPTION,
                f"Signed with {sig.name}; SHA-1/MD5 are broken.",
            )
    except Exception as e:
        logger.debug(f"BACnet/SC cert signature-algorithm check could not run: {e}")

    # SAN / hostname presence. A mismatch is NOT a security finding here: we
    # connect permissively (check_hostname=False), pentest targets are routinely
    # dialed by IP that the operational cert's SAN never lists, and the SC peer
    # is ultimately authenticated by its operational X.509 identity, not by
    # hostname. Emit the mismatch at debug only so it doesn't drown real findings.
    # A genuinely MISSING SAN extension is still flagged (real hygiene gap).
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.DNSName)
        ips = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
        if host and host not in names and host not in ips:
            logger.debug(
                f"BACnet/SC server cert SAN does not list connected host '{host}' "
                f"(DNS={names}, IP={ips}); informational — connecting permissively."
            )
    except x509.ExtensionNotFound:
        logger.security_finding(
            "BACnet/SC server certificate missing SAN",
            Category.ENCRYPTION,
            "Certificate has no Subject Alternative Name extension.",
        )
    except Exception as e:
        logger.debug(f"BACnet/SC cert SAN check could not run: {e}")


# --- rogue / no-cert probe material -----------------------------------------


def make_rogue_cert_files() -> tuple[str, str]:
    """Mint a throwaway self-signed client cert+key (for the rogue-cert probe).

    Returns (cert_path, key_path) of NamedTemporaryFiles. Caller need not delete
    them (tempfile dir is cleaned by the OS); they are unlinked best-effort.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OIDA-Rogue-Client")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_f = tempfile.NamedTemporaryFile(prefix="oida_rogue_cert_", suffix=".pem", delete=False)
    key_f = tempfile.NamedTemporaryFile(prefix="oida_rogue_key_", suffix=".pem", delete=False)
    cert_f.write(cert.public_bytes(serialization.Encoding.PEM))
    key_f.write(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_f.close()
    key_f.close()
    return cert_f.name, key_f.name
