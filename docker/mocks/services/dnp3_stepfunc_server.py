#!/usr/bin/env python3
"""
DNP3 Mock Outstation using pydnp3-stepfunc (stepfunc/dnp3 Rust library)

A proper protocol-compliant DNP3 outstation for testing the OIDA DNP3 scanner.
Uses the production Rust DNP3 stack for full protocol compliance.

Configurable via environment variables. One outstation per server instance
(pydnp3-stepfunc routes by source IP, not DNP3 address, so multiple
outstations on a single TCP endpoint require non-overlapping IP filters).
For multi-drop testing, run separate containers with different addresses.

Environment Variables:
    DNP3_PORT              - Bind port (default: 20000)
    DNP3_OUTSTATION_ADDR   - Outstation address(es), comma-separated (default: "1")
    DNP3_MASTER_ADDR       - Expected master address (default: 1)
    DNP3_BI_COUNT          - Binary input count per outstation (default: 10)
    DNP3_AI_COUNT          - Analog input count per outstation (default: 10)
    DNP3_CT_COUNT          - Counter count per outstation (default: 5)
    DNP3_BO_COUNT          - Binary output count per outstation (default: 5)
    DNP3_AO_COUNT          - Analog output count per outstation (default: 5)
    DNP3_UPDATE_INTERVAL   - Value update interval in seconds (default: 5)
    DNP3_LOG_LEVEL         - Logging level: DEBUG, INFO, WARN, ERROR (default: INFO)
    DNP3_DEVICE_NAME       - Device name for attributes (default: "OIDA DNP3 Mock")
    DNP3_SERIAL            - Device serial number (default: "OIDA-DNP3-001")
    DNP3_SOFTWARE_VERSION  - Software version attribute (default: "1.0.0")
    DNP3_HARDWARE_VERSION  - Hardware version attribute (default: "Rev-A")
    DNP3_TLS               - Enable TLS mode (default: false)
    DNP3_TLS_DNS_NAME      - DNS name for TLS certificates (default: "localhost")
"""

import datetime
import ipaddress
import logging
import math
import os
import pathlib
import signal
import sys
import time as _time

from dnp3 import Runtime
from dnp3._ffi import lib
from dnp3.outstation import (
    OutstationServer,
    OutstationConfig,
    EventBufferConfig,
    OutstationApplication,
    OutstationInformation,
    ControlHandler,
    EventClass,
)
from dnp3.handler import ConnectionStateListener
from dnp3.logging import configure_logging, LogLevel

# TLS support -- conditionally imported
try:
    from dnp3.outstation import TlsServerConfig, CertificateMode, MinTlsVersion

    _tls_available = True
except ImportError:
    _tls_available = False


# ---------------------------------------------------------------------------
# TLS certificate generation
# ---------------------------------------------------------------------------


def generate_self_signed_certs(cert_dir: str, dns_name: str = "localhost"):
    """Generate a self-signed CA, server cert, and client cert for TLS testing.

    Writes the following files into cert_dir:
        ca.pem          - CA certificate (PEM)
        ca-key.pem      - CA private key (PEM, unencrypted)
        server.pem      - Server certificate signed by CA (PEM)
        server-key.pem  - Server private key (PEM, unencrypted)
        client.pem      - Client certificate signed by CA (PEM)
        client-key.pem  - Client private key (PEM, unencrypted)
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    cert_path = pathlib.Path(cert_dir)
    cert_path.mkdir(parents=True, exist_ok=True)

    now = datetime.datetime.now(datetime.timezone.utc)
    one_year = datetime.timedelta(days=365)

    # --- CA ---
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "OIDA DNP3 Mock CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OIDA Test"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + one_year)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # --- Server cert ---
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, dns_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OIDA Test"),
        ]
    )
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + one_year)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(dns_name),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                key_cert_sign=False,
                crl_sign=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # --- Client cert ---
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, dns_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OIDA Test"),
        ]
    )
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_name)
        .issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + one_year)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(dns_name),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                key_cert_sign=False,
                crl_sign=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Write all files
    no_enc = serialization.NoEncryption()

    def _write_key(path, key):
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                no_enc,
            )
        )

    def _write_cert(path, cert):
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    _write_cert(cert_path / "ca.pem", ca_cert)
    _write_key(cert_path / "ca-key.pem", ca_key)
    _write_cert(cert_path / "server.pem", server_cert)
    _write_key(cert_path / "server-key.pem", server_key)
    _write_cert(cert_path / "client.pem", client_cert)
    _write_key(cert_path / "client-key.pem", client_key)

    return {
        "ca_cert": str(cert_path / "ca.pem"),
        "ca_key": str(cert_path / "ca-key.pem"),
        "server_cert": str(cert_path / "server.pem"),
        "server_key": str(cert_path / "server-key.pem"),
        "client_cert": str(cert_path / "client.pem"),
        "client_key": str(cert_path / "client-key.pem"),
    }


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("dnp3-outstation")


# ---------------------------------------------------------------------------
# Database initialization  (uses high-level Database API)
# ---------------------------------------------------------------------------


def init_database(
    outstation,
    bi_count,
    ai_count,
    ct_count,
    bo_count,
    ao_count,
    device_name="OIDA DNP3 Mock",
    serial_number="OIDA-DNP3-001",
    outstation_addr=1,
    software_version="1.0.0",
    hardware_version="Rev-A",
):
    """Populate the outstation database with test data points and attributes."""

    def _init_db(db):
        # Binary inputs
        for i in range(bi_count):
            db.add_binary_input(
                i,
                EventClass.CLASS1,
                static_variation=lib.DNP3_STATIC_BINARY_INPUT_VARIATION_GROUP1_VAR2,
                event_variation=lib.DNP3_EVENT_BINARY_INPUT_VARIATION_GROUP2_VAR2,
            )

        # Analog inputs
        for i in range(ai_count):
            db.add_analog_input(
                i,
                EventClass.CLASS1,
                static_variation=lib.DNP3_STATIC_ANALOG_INPUT_VARIATION_GROUP30_VAR5,
                event_variation=lib.DNP3_EVENT_ANALOG_INPUT_VARIATION_GROUP32_VAR5,
                deadband=0.0,
            )

        # Counters
        for i in range(ct_count):
            db.add_counter(
                i,
                EventClass.CLASS1,
                static_variation=lib.DNP3_STATIC_COUNTER_VARIATION_GROUP20_VAR1,
                event_variation=lib.DNP3_EVENT_COUNTER_VARIATION_GROUP22_VAR1,
                deadband=0,
            )

        # Binary output status
        for i in range(bo_count):
            db.add_binary_output_status(
                i,
                EventClass.CLASS1,
                static_variation=lib.DNP3_STATIC_BINARY_OUTPUT_STATUS_VARIATION_GROUP10_VAR2,
                event_variation=lib.DNP3_EVENT_BINARY_OUTPUT_STATUS_VARIATION_GROUP11_VAR2,
            )

        # Analog output status
        for i in range(ao_count):
            db.add_analog_output_status(
                i,
                EventClass.CLASS1,
                static_variation=lib.DNP3_STATIC_ANALOG_OUTPUT_STATUS_VARIATION_GROUP40_VAR3,
                event_variation=lib.DNP3_EVENT_ANALOG_OUTPUT_STATUS_VARIATION_GROUP42_VAR5,
                deadband=0.0,
            )

        # Device attributes
        db.define_string_attr(
            0,
            False,
            lib.DNP3_ATTRIBUTE_VARIATIONS_DEVICE_MANUFACTURERS_NAME,
            "OIDA Mock",
        )
        db.define_string_attr(
            0,
            False,
            lib.DNP3_ATTRIBUTE_VARIATIONS_PRODUCT_NAME_AND_MODEL,
            device_name,
        )
        db.define_string_attr(
            0,
            False,
            lib.DNP3_ATTRIBUTE_VARIATIONS_DEVICE_SERIAL_NUMBER,
            serial_number,
        )
        db.define_string_attr(
            0,
            True,
            lib.DNP3_ATTRIBUTE_VARIATIONS_USER_ASSIGNED_LOCATION,
            f"Outstation {outstation_addr} - OIDA Test",
        )
        db.define_string_attr(
            0,
            False,
            lib.DNP3_ATTRIBUTE_VARIATIONS_DEVICE_MANUFACTURER_SOFTWARE_VERSION,
            software_version,
        )
        db.define_string_attr(
            0,
            False,
            lib.DNP3_ATTRIBUTE_VARIATIONS_DEVICE_MANUFACTURER_HARDWARE_VERSION,
            hardware_version,
        )

    outstation.transaction(_init_db)


# ---------------------------------------------------------------------------
# Periodic value updates  (uses high-level Database API)
# ---------------------------------------------------------------------------


def update_values(outstation, bi_count, ai_count, ct_count, cycle, addr_offset=0):
    """Update data point values to simulate a live outstation."""

    def _update(db):
        # Binary inputs -- toggle every few cycles
        for i in range(bi_count):
            val = ((cycle + i + addr_offset) % 4) < 2
            db.update_binary_input(i, val, online=True)

        # Analog inputs -- sine wave with per-outstation offset
        for i in range(ai_count):
            val = 100.0 + i * 10.0 + addr_offset + 5.0 * math.sin(cycle * 0.1 + i)
            db.update_analog_input(i, val, online=True)

        # Counters -- incrementing
        for i in range(ct_count):
            val = (cycle * (i + 1)) + addr_offset
            db.update_counter(i, val, online=True)

    outstation.transaction(_update)


# ---------------------------------------------------------------------------
# Configuration parsing
# ---------------------------------------------------------------------------

LOG_LEVEL_MAP = {
    "DEBUG": LogLevel.DEBUG,
    "INFO": LogLevel.INFO,
    "WARN": LogLevel.WARN,
    "WARNING": LogLevel.WARN,
    "ERROR": LogLevel.ERROR,
}


def parse_config():
    """Parse configuration from environment variables."""
    port = int(os.environ.get("DNP3_PORT", "20000"))

    # Outstation addresses -- supports comma-separated for multi-outstation
    addr_str = os.environ.get("DNP3_OUTSTATION_ADDR", "1")
    outstation_addrs = [int(a.strip()) for a in addr_str.split(",")]

    master_addr = int(os.environ.get("DNP3_MASTER_ADDR", "1"))
    bi_count = int(os.environ.get("DNP3_BI_COUNT", "10"))
    ai_count = int(os.environ.get("DNP3_AI_COUNT", "10"))
    ct_count = int(os.environ.get("DNP3_CT_COUNT", "5"))
    bo_count = int(os.environ.get("DNP3_BO_COUNT", "5"))
    ao_count = int(os.environ.get("DNP3_AO_COUNT", "5"))
    update_interval = float(os.environ.get("DNP3_UPDATE_INTERVAL", "5"))
    log_level_str = os.environ.get("DNP3_LOG_LEVEL", "INFO").upper()
    log_level = LOG_LEVEL_MAP.get(log_level_str, LogLevel.INFO)
    device_name = os.environ.get("DNP3_DEVICE_NAME", "OIDA DNP3 Mock")
    serial_number = os.environ.get("DNP3_SERIAL", "OIDA-DNP3-001")
    software_version = os.environ.get("DNP3_SOFTWARE_VERSION", "1.0.0")
    hardware_version = os.environ.get("DNP3_HARDWARE_VERSION", "Rev-A")

    # TLS configuration
    tls_enabled = os.environ.get("DNP3_TLS", "false").lower() in ("true", "1", "yes")
    tls_dns_name = os.environ.get("DNP3_TLS_DNS_NAME", "localhost")

    return {
        "port": port,
        "outstation_addrs": outstation_addrs,
        "master_addr": master_addr,
        "bi_count": bi_count,
        "ai_count": ai_count,
        "ct_count": ct_count,
        "bo_count": bo_count,
        "ao_count": ao_count,
        "update_interval": update_interval,
        "log_level": log_level,
        "device_name": device_name,
        "serial_number": serial_number,
        "software_version": software_version,
        "hardware_version": hardware_version,
        "tls_enabled": tls_enabled,
        "tls_dns_name": tls_dns_name,
    }


# ---------------------------------------------------------------------------
# Server setup helpers
# ---------------------------------------------------------------------------

# We keep explicit references to OutstationApplication / OutstationInformation /
# ControlHandler / ConnectionStateListener instances so the garbage collector
# does not reclaim them while the Rust library still holds pointers to the
# embedded CFFI callbacks.
_outstation_refs = []


def add_outstation_to_server(server, addr, master_addr, cfg):
    """Add one outstation to the server and initialise its database."""
    app = OutstationApplication()
    info = OutstationInformation()
    ctrl = ControlHandler()
    listener = ConnectionStateListener()

    config = OutstationConfig(
        outstation_address=addr,
        master_address=master_addr,
        event_buffer=EventBufferConfig(
            binary=max(50, cfg["bi_count"] * 2),
            double_bit_binary=10,
            binary_output_status=max(10, cfg["bo_count"] * 2),
            counter=max(20, cfg["ct_count"] * 2),
            frozen_counter=10,
            analog=max(50, cfg["ai_count"] * 2),
            analog_output_status=max(10, cfg["ao_count"] * 2),
        ),
    )

    outstation = server.add_outstation(
        config=config,
        application=app,
        information=info,
        control_handler=ctrl,
        listener=listener,
    )

    # Keep references alive
    _outstation_refs.append((app, info, ctrl, listener))

    init_database(
        outstation,
        cfg["bi_count"],
        cfg["ai_count"],
        cfg["ct_count"],
        cfg["bo_count"],
        cfg["ao_count"],
        device_name=cfg["device_name"],
        serial_number=cfg["serial_number"],
        outstation_addr=addr,
        software_version=cfg["software_version"],
        hardware_version=cfg["hardware_version"],
    )

    return outstation


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    cfg = parse_config()
    bind_addr = f"0.0.0.0:{cfg['port']}"

    configure_logging(cfg["log_level"])

    tls_enabled = cfg["tls_enabled"]
    tls_dns_name = cfg["tls_dns_name"]

    log.info("=" * 60)
    log.info("DNP3 Stepfunc Outstation Server")
    log.info("=" * 60)
    log.info("  Bind address:     %s", bind_addr)
    log.info("  Outstation addrs: %s", cfg["outstation_addrs"])
    log.info("  Master address:   %s", cfg["master_addr"])
    log.info(
        "  Points per outstation: %d BI, %d AI, %d CT, %d BO, %d AO",
        cfg["bi_count"],
        cfg["ai_count"],
        cfg["ct_count"],
        cfg["bo_count"],
        cfg["ao_count"],
    )
    log.info("  Update interval:  %.1f s", cfg["update_interval"])
    log.info("  Device name:      %s", cfg["device_name"])
    log.info("  Serial number:    %s", cfg["serial_number"])
    log.info("  TLS:              %s", "enabled" if tls_enabled else "disabled")
    if tls_enabled:
        log.info("  TLS DNS name:     %s", tls_dns_name)
    log.info("=" * 60)
    sys.stdout.flush()

    # Generate TLS certificates if TLS mode is enabled
    tls_config = None
    if tls_enabled:
        if not _tls_available:
            log.error(
                "TLS requested but TlsServerConfig not available in this "
                "version of pydnp3-stepfunc. Falling back to plain TCP."
            )
            tls_enabled = False
        else:
            cert_dir = "/app/certs"
            log.info("Generating self-signed certificates in %s ...", cert_dir)
            try:
                cert_paths = generate_self_signed_certs(cert_dir, dns_name=tls_dns_name)
                log.info("  CA cert:     %s", cert_paths["ca_cert"])
                log.info("  Server cert: %s", cert_paths["server_cert"])
                log.info("  Server key:  %s", cert_paths["server_key"])
                log.info("  Client cert: %s (for scanner use)", cert_paths["client_cert"])
                log.info("  Client key:  %s (for scanner use)", cert_paths["client_key"])

                tls_config = TlsServerConfig(
                    dns_name=tls_dns_name,
                    peer_cert_path=cert_paths["ca_cert"],
                    local_cert_path=cert_paths["server_cert"],
                    private_key_path=cert_paths["server_key"],
                    password="",
                    min_tls_version=MinTlsVersion.V12,
                    certificate_mode=CertificateMode.AUTHORITY_BASED,
                    allow_client_name_wildcard=True,
                )
                log.info(
                    "TLS server config created (certificate_mode=AUTHORITY_BASED, "
                    "allow_client_name_wildcard=True)"
                )
            except Exception as exc:
                log.error("Failed to set up TLS: %s -- falling back to plain TCP", exc)
                tls_enabled = False
                tls_config = None

    with Runtime(num_threads=4) as runtime:
        if tls_config is not None:
            log.info("Creating TLS outstation server on %s", bind_addr)
            server = OutstationServer(runtime, address=bind_addr, tls_config=tls_config)
        else:
            server = OutstationServer(runtime, address=bind_addr)

        outstations = []
        for addr in cfg["outstation_addrs"]:
            try:
                os_obj = add_outstation_to_server(
                    server,
                    addr,
                    cfg["master_addr"],
                    cfg,
                )
                outstations.append((addr, os_obj))
                log.info("  Added outstation addr=%d", addr)
            except Exception as exc:
                # pydnp3-stepfunc routes by source IP (address_filter),
                # not DNP3 link-layer address. Multiple outstations on one
                # TCP server require non-overlapping source-IP filters.
                # With the default any-IP filter, only one outstation per
                # server is supported. Log and skip.
                log.warning(
                    "  Could not add outstation addr=%d: %s "
                    "(only one outstation per server is supported "
                    "with wildcard address filters)",
                    addr,
                    exc,
                )

        if not outstations:
            log.error("No outstations could be added -- exiting")
            sys.exit(1)

        server.bind()

        log.info("Server bound and accepting connections")
        sys.stdout.flush()

        running = True

        def signal_handler(sig, frame):
            nonlocal running
            running = False

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        cycle = 0
        try:
            while running:
                _time.sleep(cfg["update_interval"])
                cycle += 1
                for addr, os_obj in outstations:
                    update_values(
                        os_obj,
                        cfg["bi_count"],
                        cfg["ai_count"],
                        cfg["ct_count"],
                        cycle,
                        addr_offset=addr,
                    )
        except KeyboardInterrupt:
            pass

        log.info("Shutting down...")
        server.destroy()
        log.info("Server stopped")


if __name__ == "__main__":
    main()
