FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    snmpd snmp libsnmp-dev \
    python3-minimal \
    iproute2 net-tools procps \
    && rm -rf /var/lib/apt/lists/*

# Copy all configs and scripts
COPY snmpd.conf snmpd-windows.conf snmpd-switch.conf snmpd-v3only.conf /etc/snmp/
COPY pass_persist.py /usr/local/bin/pass_persist.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/pass_persist.py

EXPOSE 161/udp
ENV SNMP_PROFILE=linux

CMD ["/entrypoint.sh"]
