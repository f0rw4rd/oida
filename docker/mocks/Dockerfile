FROM python:3.11-slim

LABEL maintainer="f0rw4rd"
LABEL description="ICS Mock Services for Protocol Fuzzing"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    supervisor \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements-mock.txt .
RUN pip install --no-cache-dir -r requirements-mock.txt

# Copy all service files
COPY services/ /app/services/
COPY configs/ /app/configs/

# Create log directory
RUN mkdir -p /var/log/oida

# Copy supervisor config
COPY configs/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose all ICS protocol ports
EXPOSE 502 4840 48898 44818 47808 20000 2404

# Start all services via supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
