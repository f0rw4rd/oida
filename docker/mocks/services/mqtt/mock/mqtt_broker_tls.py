#!/usr/bin/env python3
"""
Mock MQTT Broker - TLS with Client Certificate Authentication
For testing OIDA MQTT scanner TLS features

Features:
- TLS 1.2/1.3 encryption
- Optional client certificate authentication
- Password auth over TLS
- Combined cert + password auth

Ports:
- 8883: TLS with optional client cert
- 8884: TLS with mandatory client cert (mutual TLS)
"""

import asyncio
import logging
import ssl
import subprocess
from pathlib import Path

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
log = logging.getLogger("mqtt-broker-tls")


# Import the auth broker as base
from mqtt_broker_auth import MQTTBrokerAuth


def generate_test_certificates(cert_dir: Path):
    """Generate self-signed CA and server certificates for testing"""

    ca_key = cert_dir / "ca.key"
    ca_cert = cert_dir / "ca.crt"
    server_key = cert_dir / "server.key"
    server_cert = cert_dir / "server.crt"
    server_csr = cert_dir / "server.csr"
    client_key = cert_dir / "client.key"
    client_cert = cert_dir / "client.crt"
    client_csr = cert_dir / "client.csr"

    # Check if certs already exist
    if ca_cert.exists() and server_cert.exists():
        log.info(f"Using existing certificates in {cert_dir}")
        return {
            "ca_cert": str(ca_cert),
            "server_cert": str(server_cert),
            "server_key": str(server_key),
            "client_cert": str(client_cert),
            "client_key": str(client_key),
        }

    log.info(f"Generating test certificates in {cert_dir}")

    try:
        # Generate CA key and certificate
        subprocess.run(
            ["openssl", "genrsa", "-out", str(ca_key), "2048"], check=True, capture_output=True
        )

        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-new",
                "-nodes",
                "-key",
                str(ca_key),
                "-sha256",
                "-days",
                "365",
                "-out",
                str(ca_cert),
                "-subj",
                "/CN=MQTT-Mock-CA/O=OIDA/C=US",
            ],
            check=True,
            capture_output=True,
        )

        # Generate server key and certificate
        subprocess.run(
            ["openssl", "genrsa", "-out", str(server_key), "2048"], check=True, capture_output=True
        )

        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                str(server_key),
                "-out",
                str(server_csr),
                "-subj",
                "/CN=localhost/O=OIDA/C=US",
            ],
            check=True,
            capture_output=True,
        )

        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(server_csr),
                "-CA",
                str(ca_cert),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-out",
                str(server_cert),
                "-days",
                "365",
                "-sha256",
            ],
            check=True,
            capture_output=True,
        )

        # Generate client key and certificate
        subprocess.run(
            ["openssl", "genrsa", "-out", str(client_key), "2048"], check=True, capture_output=True
        )

        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                str(client_key),
                "-out",
                str(client_csr),
                "-subj",
                "/CN=mqtt-client/O=OIDA/C=US",
            ],
            check=True,
            capture_output=True,
        )

        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(client_csr),
                "-CA",
                str(ca_cert),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-out",
                str(client_cert),
                "-days",
                "365",
                "-sha256",
            ],
            check=True,
            capture_output=True,
        )

        log.info("Certificates generated successfully")

        return {
            "ca_cert": str(ca_cert),
            "server_cert": str(server_cert),
            "server_key": str(server_key),
            "client_cert": str(client_cert),
            "client_key": str(client_key),
        }

    except subprocess.CalledProcessError as e:
        log.error(f"Failed to generate certificates: {e}")
        raise
    except FileNotFoundError:
        log.error("OpenSSL not found. Install openssl to generate test certificates.")
        raise


class MQTTBrokerTLS(MQTTBrokerAuth):
    """
    MQTT Broker with TLS Support

    Extends MQTTBrokerAuth with:
    - TLS encryption
    - Optional client certificate authentication
    - Mutual TLS mode
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8883,
        cert_dir: str = None,
        require_client_cert: bool = False,
    ):
        super().__init__(host, port)

        self.require_client_cert = require_client_cert

        # Set up certificate directory
        if cert_dir:
            self.cert_dir = Path(cert_dir)
        else:
            self.cert_dir = Path(__file__).parent / "certs"

        self.cert_dir.mkdir(exist_ok=True)

        # Generate or load certificates
        self.certs = generate_test_certificates(self.cert_dir)

        self.stats["broker/version"] = "MockMQTT-TLS 1.0.0"
        self.stats["broker/tls/enabled"] = True
        self.stats["broker/tls/client_cert_required"] = require_client_cert

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for the broker"""

        # Server context
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Load server certificate
        ctx.load_cert_chain(certfile=self.certs["server_cert"], keyfile=self.certs["server_key"])

        # Load CA for client certificate verification
        ctx.load_verify_locations(cafile=self.certs["ca_cert"])

        if self.require_client_cert:
            ctx.verify_mode = ssl.CERT_REQUIRED
            log.info("Client certificate REQUIRED (mutual TLS)")
        else:
            ctx.verify_mode = ssl.CERT_OPTIONAL
            log.info("Client certificate OPTIONAL")

        return ctx

    async def start(self):
        """Start the TLS MQTT broker"""

        ssl_ctx = self._create_ssl_context()

        server = await asyncio.start_server(self._handle_client, self.host, self.port, ssl=ssl_ctx)

        mode = "MUTUAL TLS (cert required)" if self.require_client_cert else "TLS (cert optional)"
        log.info(f"MQTT Broker ({mode}) started on {self.host}:{self.port}")
        log.info(f"CA cert: {self.certs['ca_cert']}")
        log.info(f"Server cert: {self.certs['server_cert']}")
        log.info(f"Test client cert: {self.certs['client_cert']}")

        asyncio.create_task(self._update_stats())
        asyncio.create_task(self._simulate_data())

        async with server:
            await server.serve_forever()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle client with TLS info extraction"""
        addr = writer.get_extra_info("peername")
        ssl_obj = writer.get_extra_info("ssl_object")

        # Extract TLS info
        if ssl_obj:
            cipher = ssl_obj.cipher()
            version = ssl_obj.version()
            peer_cert = ssl_obj.getpeercert()

            log.info(f"TLS connection from {addr}")
            log.info(f"  Cipher: {cipher[0] if cipher else 'unknown'}")
            log.info(f"  Version: {version}")

            if peer_cert:
                subject = dict(x[0] for x in peer_cert.get("subject", []))
                cn = subject.get("commonName", "unknown")
                log.info(f"  Client cert CN: {cn}")
            elif self.require_client_cert:
                log.warning("  No client certificate (required!)")
                writer.close()
                await writer.wait_closed()
                return

        # Continue with normal MQTT handling
        await super()._handle_client(reader, writer)


async def main():
    """Start TLS brokers"""

    cert_dir = Path(__file__).parent / "certs"
    cert_dir.mkdir(exist_ok=True)

    # Generate certs first
    try:
        certs = generate_test_certificates(cert_dir)
        print("\n" + "=" * 60)
        print("Test certificates generated:")
        print(f"  CA cert:     {certs['ca_cert']}")
        print(f"  Server cert: {certs['server_cert']}")
        print(f"  Client cert: {certs['client_cert']}")
        print(f"  Client key:  {certs['client_key']}")
        print("=" * 60 + "\n")
    except Exception as e:
        log.error(f"Certificate generation failed: {e}")
        log.info("TLS broker will not start without certificates")
        return

    # Port 8883: TLS with optional client cert
    tls_optional = MQTTBrokerTLS(
        host="0.0.0.0", port=8883, cert_dir=str(cert_dir), require_client_cert=False
    )

    # Port 8884: Mutual TLS (client cert required)
    tls_required = MQTTBrokerTLS(
        host="0.0.0.0", port=8884, cert_dir=str(cert_dir), require_client_cert=True
    )

    print("Starting TLS MQTT Brokers:")
    print("  Port 8883 - TLS (client cert optional, password auth)")
    print("  Port 8884 - Mutual TLS (client cert required)")
    print("")
    print("Test with:")
    print(f"  mosquitto_sub -h localhost -p 8883 --cafile {certs['ca_cert']} -t '#'")
    print(f"  mosquitto_sub -h localhost -p 8884 --cafile {certs['ca_cert']} \\")
    print(f"    --cert {certs['client_cert']} --key {certs['client_key']} -t '#'")
    print("")

    await asyncio.gather(
        tls_optional.start(),
        tls_required.start(),
    )


if __name__ == "__main__":
    asyncio.run(main())
