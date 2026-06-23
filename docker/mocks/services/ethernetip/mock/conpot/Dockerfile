# Conpot EtherNet/IP Mock Server
# Simulates Allen-Bradley ControlLogix 5571 for testing oida ethernetip scanner
#
# Based on Honeynet Conpot ICS honeypot with custom ENIP template.
# Provides EtherNet/IP encapsulation + CIP protocol handling with
# ListIdentity, ListServices, RegisterSession, and tag read/write.

FROM honeynet/conpot:latest

# Copy custom ENIP-only template
COPY template.xml /opt/conpot-enip/template.xml
COPY enip/ /opt/conpot-enip/enip/

EXPOSE 44818

CMD ["/home/conpot/.local/bin/conpot", "-f", \
     "--template", "/opt/conpot-enip", \
     "--logfile", "/var/log/conpot/conpot.log", \
     "--temp_dir", "/tmp"]
