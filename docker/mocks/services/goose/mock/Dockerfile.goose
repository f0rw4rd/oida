FROM python:3.11-slim

# No extra dependencies -- goose_publisher.py uses only Python stdlib
# (socket.AF_PACKET + struct for raw Ethernet frame construction).

COPY goose_publisher.py /opt/goose/goose_publisher.py

WORKDIR /opt/goose

CMD ["python3", "-u", "goose_publisher.py"]
