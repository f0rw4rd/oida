#!/usr/bin/env python3
"""
Mock Modbus TLS Server for testing OIDA Modbus scanner --tls mode

Implements Modbus/TCP Security (port 802) with:
  - Self-signed CA + server certificate (generated at startup)
  - Optional client certificate authentication (mTLS)
  - Same register map as the standard modbus_server.py

Credentials / Certificates:
  CA:     /certs/ca.pem
  Server: /certs/server.pem + /certs/server.key
  Client: /certs/client.pem + /certs/client.key  (for mTLS testing)

Environment:
  MODBUS_TLS_PORT  - Listen port (default: 802)
  MODBUS_MTLS      - Require client cert: 0=no, 1=yes (default: 1)
"""

import asyncio
import logging
import os
import ssl
import struct
import sys
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import ipaddress

from pymodbus.server import ModbusTlsServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusServerContext

try:
    from pymodbus.datastore import ModbusSlaveContext
except ImportError:
    from pymodbus.datastore import ModbusDeviceContext as ModbusSlaveContext
try:
    from pymodbus.device import ModbusDeviceIdentification
except ImportError:
    from pymodbus import ModbusDeviceIdentification

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

CERT_DIR = Path("/certs")


# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------


def generate_certificates(cert_dir: Path, require_client: bool = True):
    """Generate CA, server, and (optionally) client certificates."""
    cert_dir.mkdir(parents=True, exist_ok=True)

    # --- CA key + cert ---
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "OIDA Modbus Test CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OIDA"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # --- Server key + cert ---
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
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
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

    # --- Client key + cert ---
    cli_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cli_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "modbus-tls-client"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OIDA"),
                ]
            )
        )
        .issuer_name(ca_name)
        .public_key(cli_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .sign(ca_key, hashes.SHA256())
    )

    # Write files
    no_enc = serialization.NoEncryption()

    (cert_dir / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    (cert_dir / "ca.key").write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, no_enc
        )
    )
    (cert_dir / "server.pem").write_bytes(srv_cert.public_bytes(serialization.Encoding.PEM))
    (cert_dir / "server.key").write_bytes(
        srv_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, no_enc
        )
    )
    (cert_dir / "client.pem").write_bytes(cli_cert.public_bytes(serialization.Encoding.PEM))
    (cert_dir / "client.key").write_bytes(
        cli_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, no_enc
        )
    )

    log.info("Certificates generated in %s", cert_dir)
    return cert_dir


# ---------------------------------------------------------------------------
# Register map  (same as modbus_server.py)
# ---------------------------------------------------------------------------


def float32_to_regs(value: float) -> list:
    packed = struct.pack(">f", value)
    return [(packed[0] << 8) | packed[1], (packed[2] << 8) | packed[3]]


def uint32_to_regs(value: int) -> list:
    return [(value >> 16) & 0xFFFF, value & 0xFFFF]


def create_device_identity():
    identity = ModbusDeviceIdentification()
    identity[0x00] = "OIDA Mock Devices"
    identity[0x01] = "OIDA-MODBUS-TLS"
    identity[0x02] = "2.0.0"
    identity[0x03] = "https://github.com/oida"
    identity[0x04] = "Mock Industrial PLC (TLS)"
    identity[0x05] = "OIDA-TLS"
    identity[0x06] = "OIDA Modbus TLS Server"
    return identity


def create_modbus_context():
    hr_data = [0] * 100

    hr_data[0] = 1  # system_status: on
    hr_data[1] = 1  # operation_mode: auto
    hr_data[2] = 0  # error_code
    hr_data[3] = 1234  # uptime_hours

    hr_data[10:12] = float32_to_regs(25.5)
    hr_data[12:14] = float32_to_regs(3.14)
    hr_data[14:16] = float32_to_regs(100.0)

    hr_data[20:22] = float32_to_regs(24.8)
    hr_data[22:24] = float32_to_regs(3.12)
    hr_data[24:26] = float32_to_regs(98.5)

    hr_data[30:32] = uint32_to_regs(86400)
    hr_data[32:34] = uint32_to_regs(1000)

    hr_data[40] = 75
    hr_data[41] = 50
    hr_data[42] = 1

    slave_context = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0x00, [1, 0, 1, 0] * 25),
        co=ModbusSequentialDataBlock(0x00, [0] * 100),
        hr=ModbusSequentialDataBlock(0x00, hr_data),
        ir=ModbusSequentialDataBlock(0x00, [0] * 100),
    )
    try:
        return ModbusServerContext(slaves=slave_context, single=True)
    except TypeError:
        return ModbusServerContext(devices=slave_context, single=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main():
    port = int(os.environ.get("MODBUS_TLS_PORT", "802"))
    require_mtls = os.environ.get("MODBUS_MTLS", "1") == "1"

    print("=" * 50)
    print("  Modbus TLS Server (pymodbus)")
    print(f"  Port: {port}")
    print(f"  mTLS: {'required' if require_mtls else 'optional'}")
    print("=" * 50)

    # Generate certs if they don't exist
    if not (CERT_DIR / "server.pem").exists():
        generate_certificates(CERT_DIR, require_client=require_mtls)
    else:
        log.info("Using existing certificates in %s", CERT_DIR)

    # Build SSL context
    sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sslctx.load_cert_chain(
        certfile=str(CERT_DIR / "server.pem"),
        keyfile=str(CERT_DIR / "server.key"),
    )
    sslctx.load_verify_locations(cafile=str(CERT_DIR / "ca.pem"))

    if require_mtls:
        sslctx.verify_mode = ssl.CERT_REQUIRED
        log.info("Client certificate verification REQUIRED (mTLS)")
    else:
        sslctx.verify_mode = ssl.CERT_OPTIONAL
        log.info("Client certificate verification OPTIONAL")

    context = create_modbus_context()

    server = ModbusTlsServer(
        context=context,
        identity=create_device_identity(),
        address=("0.0.0.0", port),
        sslctx=sslctx,
    )

    log.info("Modbus TLS server listening on port %d", port)
    await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
