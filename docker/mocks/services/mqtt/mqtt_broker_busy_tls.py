#!/usr/bin/env python3
"""
Mock MQTT Broker - High Activity, Strict Security, TLS Enabled
For testing OIDA MQTT scanner against busy brokers with TLS

Combines features from mqtt_broker_busy.py with TLS support:
- TLS 1.2/1.3 encryption
- Username/password authentication REQUIRED
- NO wildcard subscriptions allowed
- High message throughput (50+ topics, 100ms-2s updates)
- Optional client certificate authentication

Ports:
- 1886: Plain TCP (no TLS) - handled by mqtt_broker_busy.py
- 8885: TLS with password auth (client cert optional)
- 8886: Mutual TLS (client cert required) + password auth
"""

import asyncio
import logging
import ssl
import subprocess
from pathlib import Path

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
log = logging.getLogger("mqtt-broker-busy-tls")

# Import the busy broker as base
from mqtt_broker_busy import MQTTBrokerBusy, USERS


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
                "/CN=MQTT-Busy-CA/O=OIDA/C=US",
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
                "/CN=mqtt-busy-server/O=OIDA/C=US",
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
                "/CN=mqtt-busy-client/O=OIDA/C=US",
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


class MQTTBrokerBusyTLS(MQTTBrokerBusy):
    """
    MQTT Broker with TLS Support - High Activity, Strict Security

    Combines:
    - All features from MQTTBrokerBusy (auth, no wildcards, high throughput)
    - TLS encryption
    - Optional client certificate authentication
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8885,
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

        self.stats["version"] = "MockMQTT-Busy-TLS 1.0.0"
        self.stats["tls_enabled"] = True
        self.stats["client_cert_required"] = require_client_cert

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
        """Start the TLS MQTT broker with high activity simulation"""

        ssl_ctx = self._create_ssl_context()

        server = await asyncio.start_server(self._handle_client, self.host, self.port, ssl=ssl_ctx)

        mode = "MUTUAL TLS (cert required)" if self.require_client_cert else "TLS (cert optional)"
        log.info(f"MQTT Broker BUSY ({mode}) started on {self.host}:{self.port}")
        log.info("Security: Authentication REQUIRED, Wildcards DENIED, TLS ENABLED")
        log.info(f"CA cert: {self.certs['ca_cert']}")
        log.info(f"Server cert: {self.certs['server_cert']}")
        log.info(f"Available users: {list(USERS.keys())}")

        # Start all background simulation tasks (inherited from MQTTBrokerBusy)
        asyncio.create_task(self._update_stats())
        asyncio.create_task(self._simulate_fast_sensors())
        asyncio.create_task(self._simulate_medium_sensors())
        asyncio.create_task(self._simulate_slow_data())
        asyncio.create_task(self._simulate_plc_status())
        asyncio.create_task(self._simulate_drives())
        asyncio.create_task(self._simulate_alarms())
        asyncio.create_task(self._simulate_hmi_updates())
        asyncio.create_task(self._simulate_scada_data())

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
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return

        # Continue with normal MQTT handling (includes auth check)
        await super()._handle_client(reader, writer)


async def main():
    """Start TLS busy brokers"""

    cert_dir = Path(__file__).parent / "certs"
    cert_dir.mkdir(exist_ok=True)

    # Generate certs first
    try:
        certs = generate_test_certificates(cert_dir)
        print("\n" + "=" * 60)
        print("MQTT Busy TLS Broker - Test Certificates")
        print("=" * 60)
        print(f"  CA cert:     {certs['ca_cert']}")
        print(f"  Server cert: {certs['server_cert']}")
        print(f"  Client cert: {certs['client_cert']}")
        print(f"  Client key:  {certs['client_key']}")
        print("=" * 60 + "\n")
    except Exception as e:
        log.error(f"Certificate generation failed: {e}")
        log.info("TLS broker will not start without certificates")
        return

    # Port 8885: TLS with password auth (client cert optional)
    tls_optional = MQTTBrokerBusyTLS(
        host="0.0.0.0", port=8885, cert_dir=str(cert_dir), require_client_cert=False
    )

    # Port 8886: Mutual TLS (client cert required) + password auth
    tls_required = MQTTBrokerBusyTLS(
        host="0.0.0.0", port=8886, cert_dir=str(cert_dir), require_client_cert=True
    )

    print("Starting BUSY TLS MQTT Brokers:")
    print("  Port 8885 - TLS + password auth (client cert optional)")
    print("  Port 8886 - Mutual TLS + password auth (client cert required)")
    print("")
    print("Security features:")
    print("  - Authentication REQUIRED (no anonymous)")
    print("  - Wildcard subscriptions DENIED (# and + rejected)")
    print("  - High activity (50+ topics, 100ms-2s intervals)")
    print("")
    print("Test users: admin:admin123, scada:scada, operator:op3r4t0r")
    print("")
    print("Test with:")
    print(f"  mosquitto_sub -h localhost -p 8885 --cafile {certs['ca_cert']} \\")
    print("    -u admin -P admin123 -t 'sensors/temperature/fast/1'")
    print("")
    print(f"  mosquitto_sub -h localhost -p 8886 --cafile {certs['ca_cert']} \\")
    print(f"    --cert {certs['client_cert']} --key {certs['client_key']} \\")
    print("    -u admin -P admin123 -t 'plc/status/1'")
    print("")

    await asyncio.gather(
        tls_optional.start(),
        tls_required.start(),
    )


if __name__ == "__main__":
    asyncio.run(main())
