"""
Certificate Analysis Utilities

Standalone functions for X.509 certificate checking and display.
These are used by protocol scanners that encounter TLS certificates.

The SecurityFindings class has been removed. Security findings are now
reported directly via logger.security_finding() on ICSLogger, which
both prints and collects findings for export.
"""

from typing import List, Optional, Dict, Any

import logging

logger = logging.getLogger(__name__)


# =============================================================================
# Certificate Analysis Functions
# =============================================================================


def _normalize_org_name(name: str) -> str:
    """Normalize organization name for comparison."""
    import re

    name = name.lower().strip()
    suffixes = [
        r"\s*,?\s*llc\.?$",
        r"\s*,?\s*inc\.?$",
        r"\s*,?\s*ltd\.?$",
        r"\s*,?\s*corp\.?$",
        r"\s*,?\s*co\.?$",
        r"\s*,?\s*limited$",
        r"\s*,?\s*gmbh$",
        r"\s*,?\s*s\.?a\.?$",
        r"\s*,?\s*s\.?p\.?a\.?$",
        r"\s*/\d+$",
    ]
    for suffix in suffixes:
        name = re.sub(suffix, "", name, flags=re.IGNORECASE)
    return name.strip()


def _is_issuer_trusted(cert) -> bool:
    """Check if the certificate's issuer appears to be from a trusted CA organization."""
    import ssl
    import warnings
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    try:
        ctx = ssl.create_default_context()
        system_cas = ctx.get_ca_certs(binary_form=True)

        if not system_cas:
            return True

        issuer = cert.issuer

        issuer_orgs = set()
        for attr in issuer:
            if attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
                issuer_orgs.add(_normalize_org_name(attr.value))

        trusted_orgs = set()
        for ca_der in system_cas:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    ca_cert = x509.load_der_x509_certificate(ca_der, default_backend())

                if ca_cert.subject == issuer:
                    return True

                for attr in ca_cert.subject:
                    if attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
                        trusted_orgs.add(_normalize_org_name(attr.value))
            except Exception as e:
                logger.debug(f"with warnings.catch_warnings():: {e}")
                continue

        if issuer_orgs & trusted_orgs:
            return True

        return False

    except Exception as e:
        logger.debug(f"Operation failed: {e}")
        return True


def check_certificate(
    logger,
    cert,
    protocol: str,
    target: Optional[str] = None,
) -> List[str]:
    """
    Check X.509 certificate for common security issues.

    Issues checked:
        - Self-signed certificate
        - Untrusted CA
        - Expired certificate
        - Not yet valid certificate
        - Weak signature algorithm (MD5, SHA1)
        - Short RSA key (< 2048 bits)
        - Short EC key (< 256 bits)
        - Deprecated key type (DSA)
        - Wildcard certificate

    Args:
        logger: ICSLogger instance -- findings are reported via logger.security_finding()
        cert: Certificate in various formats (x509, PEM, DER, SSLSocket)
        protocol: Protocol name (for display only)
        target: Target identifier (for display only)

    Returns:
        List of issue descriptions found
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
    from cryptography.x509.oid import ExtensionOID

    issues = []

    x509_cert = _to_x509_cert(cert)
    if x509_cert is None:
        return issues

    subject = x509_cert.subject
    issuer = x509_cert.issuer
    not_before = x509_cert.not_valid_before_utc
    not_after = x509_cert.not_valid_after_utc

    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)

    # Self-signed check
    if subject == issuer:
        issues.append("Self-signed certificate")
        logger.security_finding(
            "Certificate: Self-signed certificate",
            detail=f"Subject: {subject.rfc4514_string()}",
        )
    else:
        if not _is_issuer_trusted(x509_cert):
            issues.append("Untrusted CA (not in system root store)")
            logger.security_finding(
                "Certificate: Untrusted CA",
                detail=f"Issuer not in system trust store: {issuer.rfc4514_string()}",
            )

    # Expired check
    if now > not_after:
        days_expired = (now - not_after).days
        issues.append(f"Expired certificate ({days_expired} days ago)")
        logger.security_finding(
            "Certificate: Expired certificate",
            detail=f"Expired {days_expired} days ago on {not_after.strftime('%Y-%m-%d')}",
        )

    # Not yet valid check
    if now < not_before:
        days_until = (not_before - now).days
        issues.append(f"Certificate not yet valid ({days_until} days)")
        logger.security_finding(
            "Certificate: Not yet valid",
            detail=f"Valid from {not_before.strftime('%Y-%m-%d')} ({days_until} days away)",
        )

    # Weak signature algorithm
    sig_hash = x509_cert.signature_hash_algorithm
    if sig_hash:
        if isinstance(sig_hash, hashes.MD5):
            issues.append("Weak signature algorithm: MD5")
            logger.security_finding(
                "Certificate: Weak signature algorithm",
                detail="MD5 is cryptographically broken",
            )
        elif isinstance(sig_hash, hashes.SHA1):
            issues.append("Weak signature algorithm: SHA1")
            logger.security_finding(
                "Certificate: Weak signature algorithm",
                detail="SHA1 is deprecated",
            )

    # Key strength checks
    public_key = x509_cert.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        key_size = public_key.key_size
        if key_size < 2048:
            issues.append(f"Short RSA key: {key_size} bits")
            logger.security_finding(
                "Certificate: Short RSA key",
                detail=f"{key_size} bits (minimum 2048 recommended)",
            )
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_size = public_key.key_size
        if key_size < 256:
            issues.append(f"Short EC key: {key_size} bits")
            logger.security_finding(
                "Certificate: Short EC key",
                detail=f"{key_size} bits (minimum 256 recommended)",
            )
    elif isinstance(public_key, dsa.DSAPublicKey):
        issues.append("Deprecated key type: DSA")
        logger.security_finding(
            "Certificate: Deprecated key type",
            detail="DSA keys are deprecated",
        )

    # Wildcard certificate check
    try:
        san_ext = x509_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_names = san_ext.value.get_values_for_type(x509.DNSName)
        for name in san_names:
            if name.startswith("*"):
                issues.append(f"Wildcard certificate: {name}")
                logger.security_finding(
                    "Certificate: Wildcard certificate",
                    detail=f"SAN: {name}",
                )
                break
    except x509.ExtensionNotFound:
        for attr in subject:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                if attr.value.startswith("*"):
                    issues.append(f"Wildcard certificate: {attr.value}")
                    logger.security_finding(
                        "Certificate: Wildcard certificate",
                        detail=f"CN: {attr.value}",
                    )

    return issues


def _to_x509_cert(cert):
    """Convert various certificate formats to cryptography x509.Certificate"""
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    if isinstance(cert, x509.Certificate):
        return cert

    if isinstance(cert, str):
        if "BEGIN CERTIFICATE" in cert:
            return x509.load_pem_x509_certificate(cert.encode(), default_backend())
        try:
            return x509.load_der_x509_certificate(bytes.fromhex(cert), default_backend())
        except Exception as e:
            logger.debug(f"Return value computation failed: {e}")
            return None

    if isinstance(cert, bytes):
        if b"BEGIN CERTIFICATE" in cert:
            return x509.load_pem_x509_certificate(cert, default_backend())
        try:
            return x509.load_der_x509_certificate(cert, default_backend())
        except Exception as e:
            logger.debug(f"Return value computation failed: {e}")
            return None

    if hasattr(cert, "getpeercert"):
        der_cert = cert.getpeercert(binary_form=True)
        if der_cert:
            return x509.load_der_x509_certificate(der_cert, default_backend())
        return None

    if isinstance(cert, dict):
        return None

    return None


def _extract_extensions(x509_cert) -> Dict[str, Any]:
    """Extract X.509 extensions into a structured dictionary.

    Returns dict with human-readable keys like 'san', 'key_usage', 'eku', etc.
    Each value is a dict with 'critical' bool and parsed 'value'.
    """
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    result: Dict[str, Any] = {}

    try:
        extensions = x509_cert.extensions
    except Exception as e:
        logger.debug(f"Failed to get extensions: {e}")
        return result

    for ext in extensions:
        oid = ext.oid
        critical = ext.critical
        value = ext.value

        try:
            if oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                names = []
                for name in value:
                    if isinstance(name, x509.DNSName):
                        names.append(f"DNS:{name.value}")
                    elif isinstance(name, x509.IPAddress):
                        names.append(f"IP:{name.value}")
                    elif isinstance(name, x509.RFC822Name):
                        names.append(f"Email:{name.value}")
                    elif isinstance(name, x509.UniformResourceIdentifier):
                        names.append(f"URI:{name.value}")
                    elif isinstance(name, x509.DirectoryName):
                        names.append(f"DirName:{name.value.rfc4514_string()}")
                    elif isinstance(name, x509.RegisteredID):
                        names.append(f"RID:{name.value.dotted_string}")
                    else:
                        names.append(str(name.value))
                result["san"] = {"critical": critical, "value": names}

            elif oid == ExtensionOID.KEY_USAGE:
                usages = []
                if value.digital_signature:
                    usages.append("digitalSignature")
                if value.content_commitment:
                    usages.append("nonRepudiation")
                if value.key_encipherment:
                    usages.append("keyEncipherment")
                if value.data_encipherment:
                    usages.append("dataEncipherment")
                if value.key_agreement:
                    usages.append("keyAgreement")
                if value.key_cert_sign:
                    usages.append("keyCertSign")
                if value.crl_sign:
                    usages.append("cRLSign")
                try:
                    if value.encipher_only:
                        usages.append("encipherOnly")
                except ValueError as e:
                    logger.debug(f"if value.encipher_only:: {e}")
                try:
                    if value.decipher_only:
                        usages.append("decipherOnly")
                except ValueError as e:
                    logger.debug(f"if value.decipher_only:: {e}")
                result["key_usage"] = {"critical": critical, "value": usages}

            elif oid == ExtensionOID.EXTENDED_KEY_USAGE:
                usages = []
                for usage in value:
                    name = usage._name if hasattr(usage, "_name") else usage.dotted_string
                    usages.append(name)
                result["extended_key_usage"] = {"critical": critical, "value": usages}

            elif oid == ExtensionOID.BASIC_CONSTRAINTS:
                result["basic_constraints"] = {
                    "critical": critical,
                    "value": {
                        "ca": value.ca,
                        "path_length": value.path_length,
                    },
                }

            elif oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                result["subject_key_identifier"] = {
                    "critical": critical,
                    "value": value.digest.hex(),
                }

            elif oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                aki: Dict[str, Any] = {"critical": critical, "value": {}}
                if value.key_identifier:
                    aki["value"]["key_id"] = value.key_identifier.hex()
                if value.authority_cert_serial_number is not None:
                    aki["value"]["serial"] = value.authority_cert_serial_number
                result["authority_key_identifier"] = aki

            elif oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
                points = []
                for dp in value:
                    if dp.full_name:
                        for name in dp.full_name:
                            if isinstance(name, x509.UniformResourceIdentifier):
                                points.append(name.value)
                result["crl_distribution_points"] = {"critical": critical, "value": points}

            elif oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
                entries = []
                for desc in value:
                    method = (
                        desc.access_method._name
                        if hasattr(desc.access_method, "_name")
                        else desc.access_method.dotted_string
                    )
                    loc = ""
                    if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                        loc = desc.access_location.value
                    entries.append({"method": method, "location": loc})
                result["authority_info_access"] = {"critical": critical, "value": entries}

            elif oid == ExtensionOID.CERTIFICATE_POLICIES:
                policies = []
                for policy in value:
                    oid_str = policy.policy_identifier.dotted_string
                    label = oid_str
                    if oid_str == "2.23.140.1.2.1":
                        label = "DV"
                    elif oid_str == "2.23.140.1.2.2":
                        label = "OV"
                    elif oid_str == "2.23.140.1.1":
                        label = "EV"
                    elif oid_str == "2.5.29.32.0":
                        label = "anyPolicy"
                    policies.append({"oid": oid_str, "label": label})
                result["certificate_policies"] = {"critical": critical, "value": policies}

            elif oid == ExtensionOID.NAME_CONSTRAINTS:
                nc: Dict[str, Any] = {"critical": critical, "value": {}}
                if value.permitted_subtrees:
                    nc["value"]["permitted"] = [str(s.value) for s in value.permitted_subtrees]
                if value.excluded_subtrees:
                    nc["value"]["excluded"] = [str(s.value) for s in value.excluded_subtrees]
                result["name_constraints"] = nc

            elif oid == ExtensionOID.INHIBIT_ANY_POLICY:
                result["inhibit_any_policy"] = {
                    "critical": critical,
                    "value": value.skip_certs,
                }

            elif oid == ExtensionOID.OCSP_NO_CHECK:
                result["ocsp_no_check"] = {"critical": critical, "value": True}

            else:
                # Unknown / uncommon extension — store OID and raw type
                ext_name = oid._name if hasattr(oid, "_name") else oid.dotted_string
                result[ext_name] = {
                    "critical": critical,
                    "value": type(value).__name__,
                    "oid": oid.dotted_string,
                }

        except Exception:
            ext_name = oid._name if hasattr(oid, "_name") else oid.dotted_string
            result[ext_name] = {"critical": critical, "value": "parse error"}

    return result


def get_cert_info(cert) -> Dict[str, Any]:
    """
    Extract certificate information as a dictionary.

    Returns:
        Dictionary with certificate details including thumbprint and extensions
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

    x509_cert = _to_x509_cert(cert)
    if x509_cert is None:
        return {"error": "Could not parse certificate"}

    public_key = x509_cert.public_key()
    key_type = "unknown"
    key_size = 0

    if isinstance(public_key, rsa.RSAPublicKey):
        key_type = "RSA"
        key_size = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_type = f"EC ({public_key.curve.name})"
        key_size = public_key.key_size
    elif isinstance(public_key, dsa.DSAPublicKey):
        key_type = "DSA"
        key_size = public_key.key_size

    thumbprint = x509_cert.fingerprint(hashes.SHA256()).hex().upper()

    # Extract X.509 extensions
    extensions = _extract_extensions(x509_cert)

    return {
        "subject": x509_cert.subject.rfc4514_string(),
        "issuer": x509_cert.issuer.rfc4514_string(),
        "serial": x509_cert.serial_number,
        "not_before": x509_cert.not_valid_before_utc.isoformat(),
        "not_after": x509_cert.not_valid_after_utc.isoformat(),
        "key_type": key_type,
        "key_size": key_size,
        "signature_algorithm": x509_cert.signature_algorithm_oid._name,
        "self_signed": x509_cert.subject == x509_cert.issuer,
        "thumbprint": thumbprint,
        "extensions": extensions,
    }


def display_cert_info(
    logger,
    cert,
    protocol: str = "tls",
    target: Optional[str] = None,
    results: Optional[Dict[str, Any]] = None,
    save_dir: str = "",
    verbose: bool = False,
    cert_chain: Optional[List[bytes]] = None,
) -> Dict[str, Any]:
    """
    Display certificate information and run security checks.

    Args:
        logger: ICSLogger instance with display(), warning(), and security_finding() methods
        cert: Certificate in various formats (DER, PEM, x509, SSLSocket)
        protocol: Protocol name for security findings (default: "tls")
        target: Target identifier for security findings
        results: Optional dict to store cert info under 'certificate' key
        save_dir: Directory to save certificates (default: platform temp dir)
        verbose: If True, show detailed info (chain, thumbprint, CA details)
        cert_chain: Optional list of DER-encoded certificates in chain order

    Returns:
        Certificate info dictionary with 'issues' key listing any problems
    """
    import os
    from cryptography.hazmat.primitives.serialization import Encoding

    if not save_dir:
        from .platform_compat import get_cert_save_dir

        save_dir = get_cert_save_dir()

    info = get_cert_info(cert)
    if "error" in info:
        logger.debug(f"Certificate parse error: {info['error']}")
        return info

    if results is not None:
        results["certificate"] = info

    # Save certificate to filesystem (only if verbose)
    thumbprint = info.get("thumbprint", "")
    if thumbprint and verbose:
        try:
            os.makedirs(save_dir, exist_ok=True)
            cert_path = os.path.join(save_dir, f"{thumbprint}.pem")
            if not os.path.exists(cert_path):
                x509_cert = _to_x509_cert(cert)
                if x509_cert:
                    pem_data = x509_cert.public_bytes(Encoding.PEM)
                    with open(cert_path, "wb") as f:
                        f.write(pem_data)
            if os.path.exists(cert_path):
                info["saved_path"] = cert_path
        except Exception as e:
            logger.debug(f"Failed to save certificate: {e}")

    # Display certificate info (compact format)
    subject = info.get("subject", "Unknown")
    expires = info.get("not_after", "?")[:10]
    logger.display(f"X509 certificate: {subject} (expires {expires})")

    # Always show key X.509 extensions
    extensions = info.get("extensions", {})
    _display_extensions_compact(logger, extensions)

    # Verbose: show certificate chain and additional details
    if verbose:
        logger.display("Certificate chain:")
        logger.display(f"  [0] {subject}")
        logger.display(f"      Key: {info.get('key_size', '?')}-bit {info.get('key_type', '?')}")
        logger.display(
            f"      Valid: {info.get('not_before', '?')[:10]} - {info.get('not_after', '?')[:10]}"
        )
        if thumbprint:
            saved_path = info.get("saved_path", "")
            path_info = f" -> {saved_path}" if saved_path else ""
            logger.display(f"      Thumbprint: {thumbprint[:32]}...{path_info}")

        if cert_chain and len(cert_chain) > 1:
            for i, chain_cert_der in enumerate(cert_chain[1:], start=1):
                chain_info = get_cert_info(chain_cert_der)
                if "error" not in chain_info:
                    logger.display(f"  [{i}] {chain_info.get('subject', 'Unknown')}")
                    logger.display(
                        f"      Key: {chain_info.get('key_size', '?')}-bit {chain_info.get('key_type', '?')}"
                    )
                    logger.display(
                        f"      Valid: {chain_info.get('not_before', '?')[:10]} - {chain_info.get('not_after', '?')[:10]}"
                    )
        elif not info.get("self_signed", False):
            logger.display(f"  [1] {info.get('issuer', 'Unknown')} (issuer - chain not available)")

        # Verbose: show remaining extensions not covered by compact display
        _display_extensions_verbose(logger, extensions)

    # Run security checks (findings print inline via logger.security_finding())
    issues = check_certificate(logger, cert, protocol, target)

    info["issues"] = issues

    # Show CA details for untrusted CA issues in verbose mode
    if verbose:
        for issue in issues:
            if "Untrusted CA" in issue:
                issuer_dn = info.get("issuer", "")
                _show_ca_details(logger, issuer_dn)

    return info


def _display_extensions_compact(logger, extensions: Dict[str, Any]) -> None:
    """Show key X.509 extensions in compact format (always displayed)."""
    if not extensions:
        return

    # SAN
    san = extensions.get("san")
    if san:
        names = san["value"]
        crit = " [CRITICAL]" if san["critical"] else ""
        display = ", ".join(names[:6])
        if len(names) > 6:
            display += f" (+{len(names) - 6} more)"
        logger.display(f"  SAN{crit}: {display}")

    # Key Usage
    ku = extensions.get("key_usage")
    if ku:
        crit = " [CRITICAL]" if ku["critical"] else ""
        logger.display(f"  Key Usage{crit}: {', '.join(ku['value'])}")

    # Extended Key Usage
    eku = extensions.get("extended_key_usage")
    if eku:
        crit = " [CRITICAL]" if eku["critical"] else ""
        # Friendly names for common EKU OIDs
        _eku_names = {
            "serverAuth": "TLS Server",
            "clientAuth": "TLS Client",
            "codeSigning": "Code Signing",
            "emailProtection": "Email",
            "timeStamping": "Timestamping",
            "OCSPSigning": "OCSP Signing",
        }
        usages = [_eku_names.get(u, u) for u in eku["value"]]
        logger.display(f"  EKU{crit}: {', '.join(usages)}")

    # Basic Constraints
    bc = extensions.get("basic_constraints")
    if bc:
        crit = " [CRITICAL]" if bc["critical"] else ""
        ca = "CA:TRUE" if bc["value"]["ca"] else "CA:FALSE"
        path = (
            f", pathlen:{bc['value']['path_length']}"
            if bc["value"]["path_length"] is not None
            else ""
        )
        logger.display(f"  Basic Constraints{crit}: {ca}{path}")


def _display_extensions_verbose(logger, extensions: Dict[str, Any]) -> None:
    """Show remaining X.509 extensions in verbose mode (excludes those shown in compact)."""
    if not extensions:
        return

    # Keys already shown by compact display
    _compact_keys = {"san", "key_usage", "extended_key_usage", "basic_constraints"}
    remaining = {k: v for k, v in extensions.items() if k not in _compact_keys}

    if not remaining:
        return

    logger.display("  Additional X.509 Extensions:")

    for name, ext in remaining.items():
        crit = "[CRITICAL] " if ext.get("critical") else ""
        value = ext.get("value", "")

        if name == "subject_key_identifier":
            display = value[:32] + "..." if len(value) > 32 else value
        elif name == "authority_key_identifier":
            kid = value.get("key_id", "")
            display = (kid[:32] + "...") if len(kid) > 32 else kid or "issuer-based"
        elif name == "crl_distribution_points":
            display = ", ".join(value[:2])
            if len(value) > 2:
                display += "..."
        elif name == "authority_info_access":
            parts = [f"{e['method']}:{e['location'][:50]}" for e in value[:2]]
            display = ", ".join(parts)
            if len(value) > 2:
                display += "..."
        elif name == "certificate_policies":
            display = ", ".join(p["label"] for p in value[:3])
        elif name == "name_constraints":
            parts = []
            if value.get("permitted"):
                parts.append(f"permitted: {', '.join(value['permitted'][:3])}")
            if value.get("excluded"):
                parts.append(f"excluded: {', '.join(value['excluded'][:3])}")
            display = "; ".join(parts)
        elif name == "inhibit_any_policy":
            display = f"skip_certs: {value}"
        elif name == "ocsp_no_check":
            display = "present"
        elif isinstance(value, str):
            display = value
        else:
            display = str(value)

        # Human-friendly label
        label = name.replace("_", " ").title()
        logger.display(f"      {crit}{label}: {display}")


def _show_ca_details(logger, issuer_dn: str) -> None:
    """Show details about why a CA is not trusted."""
    import ssl
    import warnings
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    issuer_org = "Unknown"
    if "O=" in issuer_dn:
        for part in issuer_dn.split(","):
            if part.strip().startswith("O="):
                issuer_org = part.strip()[2:]
                break

    logger.display(f"      Issuer organization: {issuer_org}")
    logger.display(f"      Issuer DN: {issuer_dn}")

    try:
        ctx = ssl.create_default_context()
        system_cas = ctx.get_ca_certs(binary_form=True)

        similar_cas = []
        issuer_org_lower = issuer_org.lower()

        for ca_der in system_cas:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    ca_cert = x509.load_der_x509_certificate(ca_der, default_backend())
                ca_subj = ca_cert.subject.rfc4514_string()

                for attr in ca_cert.subject:
                    if attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
                        if issuer_org_lower[:5] in attr.value.lower():
                            similar_cas.append(ca_subj)
                            break
            except Exception as e:
                logger.debug(f"with warnings.catch_warnings():: {e}")
                continue

        if similar_cas:
            logger.display("      Similar trusted CAs found:")
            for ca in similar_cas[:3]:
                logger.display(f"        - {ca}")
        else:
            logger.display("      No similar CAs in system trust store")
            logger.display(f"      System has {len(system_cas)} trusted root CAs")

    except Exception as e:
        logger.debug(f"Could not check trust store: {e}")


def _display_cert_extensions(logger, cert) -> None:
    """Display X.509 certificate extensions in verbose mode."""
    try:
        x509_cert = _to_x509_cert(cert)
        if x509_cert is None:
            return

        extensions = x509_cert.extensions
        if not extensions:
            return

        logger.display("  X.509 Extensions:")

        for ext in extensions:
            oid = ext.oid
            critical = "[CRITICAL] " if ext.critical else ""
            name = oid._name if hasattr(oid, "_name") else str(oid.dotted_string)

            value = ext.value
            formatted = _format_extension_value(oid, value)

            if formatted:
                logger.display(f"      {critical}{name}: {formatted}")

    except Exception as e:
        logger.debug(f"Failed to parse extensions: {e}")


def _format_extension_value(oid, value) -> str:
    """Format X.509 extension value for display."""
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    try:
        if oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            names = []
            for name in value:
                if isinstance(name, x509.DNSName):
                    names.append(f"DNS:{name.value}")
                elif isinstance(name, x509.IPAddress):
                    names.append(f"IP:{name.value}")
                elif isinstance(name, x509.RFC822Name):
                    names.append(f"Email:{name.value}")
                elif isinstance(name, x509.UniformResourceIdentifier):
                    names.append(f"URI:{name.value}")
            return ", ".join(names[:5]) + ("..." if len(names) > 5 else "")

        elif oid == ExtensionOID.KEY_USAGE:
            usages = []
            if value.digital_signature:
                usages.append("digitalSignature")
            if value.key_encipherment:
                usages.append("keyEncipherment")
            if value.content_commitment:
                usages.append("nonRepudiation")
            if value.data_encipherment:
                usages.append("dataEncipherment")
            if value.key_agreement:
                usages.append("keyAgreement")
            if value.key_cert_sign:
                usages.append("keyCertSign")
            if value.crl_sign:
                usages.append("cRLSign")
            return ", ".join(usages)

        elif oid == ExtensionOID.EXTENDED_KEY_USAGE:
            usages = []
            for usage in value:
                name = usage._name if hasattr(usage, "_name") else str(usage.dotted_string)
                name = name.replace("serverAuth", "TLS Server")
                name = name.replace("clientAuth", "TLS Client")
                name = name.replace("codeSigning", "Code Signing")
                name = name.replace("emailProtection", "Email")
                usages.append(name)
            return ", ".join(usages)

        elif oid == ExtensionOID.BASIC_CONSTRAINTS:
            ca = "CA:TRUE" if value.ca else "CA:FALSE"
            path_len = f", pathlen:{value.path_length}" if value.path_length is not None else ""
            return f"{ca}{path_len}"

        elif oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
            return value.digest.hex()[:32] + "..."

        elif oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
            if value.key_identifier:
                return value.key_identifier.hex()[:32] + "..."
            return "issuer-based"

        elif oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
            points = []
            for dp in value:
                if dp.full_name:
                    for name in dp.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            points.append(name.value)
            return ", ".join(points[:2]) + ("..." if len(points) > 2 else "")

        elif oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
            info = []
            for desc in value:
                method = desc.access_method._name if hasattr(desc.access_method, "_name") else "?"
                if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                    info.append(f"{method}:{desc.access_location.value[:50]}")
            return ", ".join(info[:2]) + ("..." if len(info) > 2 else "")

        elif oid == ExtensionOID.CERTIFICATE_POLICIES:
            policies = []
            for policy in value:
                oid_str = policy.policy_identifier.dotted_string
                if oid_str.startswith("2.23.140.1.2"):
                    policies.append(
                        "DV" if oid_str.endswith(".1") else "OV" if oid_str.endswith(".2") else "EV"
                    )
                else:
                    policies.append(oid_str[:20] + "...")
            return ", ".join(policies[:3])

        else:
            return type(value).__name__

    except Exception as e:
        logger.debug(f"Operation failed: {e}")
        return "parse error"
