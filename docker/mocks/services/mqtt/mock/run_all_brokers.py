#!/usr/bin/env python3
"""
Run all MQTT mock brokers for OIDA testing

Starts 9 brokers with different security configurations:
- Port 1883: Insecure (anonymous, no TLS, wildcard subs)
- Port 1884: Auth required (weak credentials)
- Port 1885: Sparkplug B enabled
- Port 1886: BUSY - Auth required, NO wildcards, high activity
- Port 8883: TLS with optional client cert
- Port 8884: Mutual TLS (client cert required)
- Port 8885: BUSY TLS - Auth + no wildcards + high activity + TLS
- Port 8886: BUSY Mutual TLS - Same as 8885 but client cert required

Usage:
    python run_all_brokers.py [--no-tls]
    # Or with Docker:
    docker build -t mqtt-mock .
    docker run -p 1883-1886:1883-1886 -p 8883-8886:8883-8886 mqtt-mock
"""

import asyncio
import logging
import signal
import sys
import argparse

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
log = logging.getLogger("mqtt-mock-runner")


async def main(enable_tls: bool = True):
    """Start all MQTT brokers concurrently"""

    log.info("=" * 70)
    log.info("OIDA Mock MQTT Broker Suite")
    log.info("=" * 70)
    log.info("")
    log.info("Starting brokers:")
    log.info("  Port 1883 - INSECURE (anonymous, no TLS, wildcard subs)")
    log.info("  Port 1884 - AUTH REQUIRED (weak credentials for brute-force)")
    log.info("  Port 1885 - SPARKPLUG B (ICS/SCADA simulation)")
    log.info("  Port 1886 - BUSY (auth required, NO wildcards, 50+ topics)")
    if enable_tls:
        log.info("  Port 8883 - TLS (optional client cert + password auth)")
        log.info("  Port 8884 - MUTUAL TLS (client cert required)")
        log.info("  Port 8885 - BUSY TLS (auth + no wildcards + high activity)")
        log.info("  Port 8886 - BUSY MUTUAL TLS (client cert + auth + no wildcards)")
    log.info("")
    log.info("Test credentials for port 1884/8883:")
    log.info("  admin:admin, user:password, operator:operator123")
    log.info("  guest:guest, test:test, mqtt:mqtt, ics:ics123, plc:plc2024")
    log.info("")
    log.info("Test credentials for BUSY brokers (1886/8885/8886):")
    log.info("  admin:admin123, scada:scada, operator:op3r4t0r")
    log.info("  sensor:sensor, readonly:readonly, hmi:hmi2024, historian:hist0ry")
    log.info("")
    log.info("Sparkplug groups on port 1885:")
    log.info("  spBv1.0/Factory-Floor/#")
    log.info("  spBv1.0/SCADA/#")
    log.info("  spBv1.0/Building-Automation/#")
    log.info("")
    log.info("BUSY broker topics (1886/8885/8886) - NO WILDCARDS ALLOWED:")
    log.info("  sensors/temperature/fast/{1-5}, sensors/pressure/fast/{1-5}")
    log.info("  sensors/flow/{1-10}, sensors/level/{1-10}")
    log.info("  plc/status/{1-5}, plc/diagnostics/{1-5}")
    log.info("  factory/drives/{1-10}, alarms/active/*, alarms/summary")
    log.info("  hmi/screen/overview, scada/rtu/{1-3}/status")
    log.info("=" * 70)

    # Import brokers
    from mqtt_broker_insecure import MQTTBrokerInsecure
    from mqtt_broker_auth import MQTTBrokerAuth
    from mqtt_broker_sparkplug import MQTTBrokerSparkplug
    from mqtt_broker_busy import MQTTBrokerBusy

    # Create broker instances
    insecure_broker = MQTTBrokerInsecure(host="0.0.0.0", port=1883)
    auth_broker = MQTTBrokerAuth(host="0.0.0.0", port=1884)
    sparkplug_broker = MQTTBrokerSparkplug(host="0.0.0.0", port=1885)
    busy_broker = MQTTBrokerBusy(host="0.0.0.0", port=1886)

    brokers = [
        insecure_broker.start(),
        auth_broker.start(),
        sparkplug_broker.start(),
        busy_broker.start(),
    ]

    # Add TLS brokers if enabled
    if enable_tls:
        try:
            from mqtt_broker_tls import MQTTBrokerTLS
            from mqtt_broker_busy_tls import MQTTBrokerBusyTLS
            from pathlib import Path

            cert_dir = Path(__file__).parent / "certs"
            cert_dir.mkdir(exist_ok=True)

            tls_optional = MQTTBrokerTLS(
                host="0.0.0.0", port=8883, cert_dir=str(cert_dir), require_client_cert=False
            )
            tls_required = MQTTBrokerTLS(
                host="0.0.0.0", port=8884, cert_dir=str(cert_dir), require_client_cert=True
            )
            busy_tls_optional = MQTTBrokerBusyTLS(
                host="0.0.0.0", port=8885, cert_dir=str(cert_dir), require_client_cert=False
            )
            busy_tls_required = MQTTBrokerBusyTLS(
                host="0.0.0.0", port=8886, cert_dir=str(cert_dir), require_client_cert=True
            )

            brokers.append(tls_optional.start())
            brokers.append(tls_required.start())
            brokers.append(busy_tls_optional.start())
            brokers.append(busy_tls_required.start())

        except Exception as e:
            log.warning(f"TLS brokers disabled: {e}")
            log.info("Run with --no-tls to suppress this warning")

    # Run all brokers concurrently
    try:
        await asyncio.gather(*brokers)
    except asyncio.CancelledError:
        log.info("Brokers shutting down...")


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    log.info(f"Received signal {signum}, shutting down...")
    sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OIDA Mock MQTT Brokers")
    parser.add_argument(
        "--no-tls", action="store_true", help="Disable TLS brokers (ports 8883, 8884)"
    )
    args = parser.parse_args()

    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        asyncio.run(main(enable_tls=not args.no_tls))
    except KeyboardInterrupt:
        log.info("Shutdown requested")
    except Exception as e:
        log.error(f"Error: {e}")
        sys.exit(1)
