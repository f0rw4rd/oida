# Conpot Modbus TCP Mock Server
# Simulates Schneider Modicon M340 PLC for testing oida modbus scanner
#
# Based on Honeynet Conpot ICS honeypot with custom Modbus template.
# Provides Modbus TCP with FC 1-4 (coils, discrete inputs, input/holding
# registers) and FC 43 MEI device identification.

FROM honeynet/conpot:latest

# Copy custom Modbus-only template
COPY template.xml /opt/conpot-modbus/template.xml
COPY modbus/ /opt/conpot-modbus/modbus/

EXPOSE 5020

CMD ["/home/conpot/.local/bin/conpot", "-f", \
     "--template", "/opt/conpot-modbus", \
     "--logfile", "/var/log/conpot/conpot.log", \
     "--temp_dir", "/tmp"]
