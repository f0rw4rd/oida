# Conpot IEC 60870-5-104 Mock Server
# Simulates Siemens S7-300 CP 343-1 IT gateway for testing oida iec104 scanner
#
# Based on Honeynet Conpot ICS honeypot with custom IEC 104 template.
# Provides IEC 104 protocol handling with multiple data types:
#   - Type 1/45:  Single-point information / Single command
#   - Type 3/46:  Double-point information / Double command
#   - Type 11/49: Measured value scaled / Setpoint scaled
#   - Type 13/50: Measured value float  / Setpoint float

FROM honeynet/conpot:latest

# Copy custom IEC 104 template
COPY template.xml /opt/conpot-iec104/template.xml
COPY IEC104/ /opt/conpot-iec104/IEC104/

EXPOSE 2404

CMD ["/home/conpot/.local/bin/conpot", "-f", \
     "--template", "/opt/conpot-iec104", \
     "--logfile", "/var/log/conpot/conpot.log", \
     "--temp_dir", "/tmp"]
