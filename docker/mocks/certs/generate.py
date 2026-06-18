#!/usr/bin/env python3
"""
Generate shared test certificates for OIDA mock services.

Run once, commit outputs. Other services (MQTT, DNP3, HTTP/2) can migrate later.

Usage:
    python docker/mocks/certs/generate.py
"""

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERT_DIR = Path(__file__).parent
NO_ENC = serialization.NoEncryption()
VALIDITY = datetime.timedelta(days=3650)  # ~10 years


def _write_key(path: Path, key):
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            NO_ENC,
        )
    )


def _write_cert(path: Path, cert):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def generate():
    # ------------------------------------------------------------------
    # Shared CA
    # ------------------------------------------------------------------
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "OIDA Test CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OIDA"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + VALIDITY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    _write_cert(CERT_DIR / "ca.pem", ca_cert)
    _write_key(CERT_DIR / "ca.key", ca_key)
    print("  CA certificate written")

    # ------------------------------------------------------------------
    # modbus-tls server cert (SAN: localhost, 127.0.0.1, modbus-tls)
    # ------------------------------------------------------------------
    srv_dir = CERT_DIR / "modbus-tls"
    srv_dir.mkdir(exist_ok=True)

    srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "modbus-tls-server"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OIDA"),
                ]
            )
        )
        .issuer_name(ca_name)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + VALIDITY)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.DNSName("modbus-tls-server"),
                    x509.DNSName("modbus-tls"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write_cert(srv_dir / "server.pem", srv_cert)
    _write_key(srv_dir / "server.key", srv_key)
    print("  modbus-tls server certificate written")

    # ------------------------------------------------------------------
    # iec104-tls server cert (SAN: localhost, 127.0.0.1, iec104-tls)
    # ------------------------------------------------------------------
    iec_dir = CERT_DIR / "iec104-tls"
    iec_dir.mkdir(exist_ok=True)

    iec_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    iec_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "iec104-tls-server"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OIDA"),
                ]
            )
        )
        .issuer_name(ca_name)
        .public_key(iec_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + VALIDITY)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.DNSName("iec104-tls-server"),
                    x509.DNSName("iec104-tls"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write_cert(iec_dir / "server.pem", iec_cert)
    _write_key(iec_dir / "server.key", iec_key)
    print("  iec104-tls server certificate written")

    # ------------------------------------------------------------------
    # Shared client cert (for mTLS tests)
    # ------------------------------------------------------------------
    cli_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cli_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "oida-test-client"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OIDA"),
                ]
            )
        )
        .issuer_name(ca_name)
        .public_key(cli_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + VALIDITY)
        .sign(ca_key, hashes.SHA256())
    )
    _write_cert(CERT_DIR / "client.pem", cli_cert)
    _write_key(CERT_DIR / "client.key", cli_key)
    print("  Client certificate written")

    # ------------------------------------------------------------------
    # Bogus self-signed cert (NOT from shared CA — for invalid cert tests)
    # ------------------------------------------------------------------
    bogus_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bogus_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "bogus-client"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BOGUS"),
        ]
    )
    bogus_cert = (
        x509.CertificateBuilder()
        .subject_name(bogus_name)
        .issuer_name(bogus_name)  # self-signed
        .public_key(bogus_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + VALIDITY)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(bogus_key, hashes.SHA256())
    )
    _write_cert(CERT_DIR / "bogus.pem", bogus_cert)
    _write_key(CERT_DIR / "bogus.key", bogus_key)
    print("  Bogus certificate written")

    print(f"\nAll certs generated in {CERT_DIR}")


if __name__ == "__main__":
    generate()
