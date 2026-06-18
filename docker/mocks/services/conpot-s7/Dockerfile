# Conpot S7comm Mock Server
# Simulates Siemens S7-300 CPU 315-2 PN/DP for testing oida snap7 scanner
#
# Based on Honeynet Conpot ICS honeypot with custom S7comm template.
# Provides COTP/ISO-TSAP + S7comm protocol handling with SZL responses.

FROM honeynet/conpot:latest

# Copy custom S7comm-only template
COPY template.xml /opt/conpot-s7/template.xml
COPY s7comm/ /opt/conpot-s7/s7comm/

EXPOSE 10201

CMD ["/home/conpot/.local/bin/conpot", "-f", \
     "--template", "/opt/conpot-s7", \
     "--logfile", "/var/log/conpot/conpot.log", \
     "--temp_dir", "/tmp"]
