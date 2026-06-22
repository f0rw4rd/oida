# Mock MQTT Brokers for MSF-ICS Testing
FROM python:3.11-slim

LABEL maintainer="msf-ics"
LABEL description="Mock MQTT brokers with various security configurations for testing"

WORKDIR /app

# Install openssl for certificate generation
RUN apt-get update && apt-get install -y --no-install-recommends openssl && \
    rm -rf /var/lib/apt/lists/*

# Copy all broker implementations
COPY mqtt_broker_insecure.py .
COPY mqtt_broker_auth.py .
COPY mqtt_broker_sparkplug.py .
COPY mqtt_broker_busy.py .
COPY mqtt_broker_tls.py .
COPY mqtt_broker_busy_tls.py .
COPY run_all_brokers.py .

# Create certs directory
RUN mkdir -p /app/certs

# Expose ports for each broker configuration
# 1883 - Insecure (anonymous, no TLS, no ACLs)
# 1884 - Auth required (weak credentials)
# 1885 - Sparkplug B enabled (ICS data simulation)
# 1886 - BUSY (auth required, NO wildcards, high activity)
# 8883 - TLS with optional client cert
# 8884 - Mutual TLS (client cert required)
# 8885 - BUSY TLS (auth + no wildcards + high activity + TLS)
# 8886 - BUSY Mutual TLS (client cert + auth + no wildcards)
EXPOSE 1883 1884 1885 1886 8883 8884 8885 8886

# Run all brokers
CMD ["python3", "run_all_brokers.py"]
