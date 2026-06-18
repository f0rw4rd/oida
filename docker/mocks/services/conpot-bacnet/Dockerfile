# Conpot BACnet Mock Server
# Simulates an Alerton VAV-DD BACnet/IP controller for testing oida bacnet scanner
#
# Based on Honeynet Conpot ICS honeypot with custom BACnet template.
# Provides BACnet/IP protocol handling: Who-Is, I-Am, ReadProperty responses.

FROM honeynet/conpot:latest

# Copy custom BACnet-only template
COPY template.xml /opt/conpot-bacnet/template.xml
COPY bacnet/ /opt/conpot-bacnet/bacnet/

EXPOSE 47808/udp

CMD ["/home/conpot/.local/bin/conpot", "-f", \
     "--template", "/opt/conpot-bacnet", \
     "--logfile", "/var/log/conpot/conpot.log", \
     "--temp_dir", "/tmp"]
