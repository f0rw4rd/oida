# Dockerfile for libiec61850 MMS test servers
# Multi-stage: build in bookworm, run in bookworm-slim (shares layer with python:3.11-slim)
# Produces 7 server binaries + TLS certs in a slim runtime image

# ── stage 1: build ──────────────────────────────────────────────────────
FROM debian:bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Download libiec61850 v1.6.0
RUN wget -q https://github.com/mz-automation/libiec61850/archive/refs/tags/v1.6.0.tar.gz \
    && tar -xzf v1.6.0.tar.gz \
    && rm v1.6.0.tar.gz

# Download mbedTLS for TLS support
RUN cd libiec61850-1.6.0/third_party && \
    mkdir -p mbedtls && cd mbedtls && \
    wget -q https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v2.28.0.tar.gz && \
    tar -xzf v2.28.0.tar.gz && \
    mv mbedtls-2.28.0 mbedtls-2.28 && \
    rm v2.28.0.tar.gz

# Build libiec61850 with all examples
WORKDIR /build/libiec61850-1.6.0
RUN mkdir build && cd build && cmake .. && make -j$(nproc)

# Build custom TLS + password auth server
COPY mms_tls_auth_server.c /build/mms_tls_auth_server/
RUN cp examples/server_example_password_auth/static_model.c /build/mms_tls_auth_server/ && \
    cp examples/server_example_password_auth/static_model.h /build/mms_tls_auth_server/ && \
    cd /build/mms_tls_auth_server && \
    gcc -o mms_tls_auth_server \
        mms_tls_auth_server.c static_model.c \
        -I/build/libiec61850-1.6.0/src/iec61850/inc \
        -I/build/libiec61850-1.6.0/src/mms/inc \
        -I/build/libiec61850-1.6.0/src/common/inc \
        -I/build/libiec61850-1.6.0/hal/inc \
        -I/build/libiec61850-1.6.0/src/tls/inc \
        -I/build/libiec61850-1.6.0/src/logging \
        -I. \
        /build/libiec61850-1.6.0/build/src/libiec61850.a \
        /build/libiec61850-1.6.0/build/hal/libhal.a \
        -lpthread -lm

# ── stage 2: runtime ────────────────────────────────────────────────────
FROM debian:bookworm-slim

# Copy server binaries
COPY --from=builder /build/libiec61850-1.6.0/build/examples/server_example_basic_io/server_example_basic_io /usr/local/bin/
COPY --from=builder /build/libiec61850-1.6.0/build/examples/server_example_goose/server_example_goose /usr/local/bin/
COPY --from=builder /build/libiec61850-1.6.0/build/examples/server_example_config_file/server_example_config_file /usr/local/bin/
COPY --from=builder /build/libiec61850-1.6.0/build/examples/server_example_control/server_example_control /usr/local/bin/
COPY --from=builder /build/libiec61850-1.6.0/build/examples/server_example_61400_25/server_example_61400_25 /usr/local/bin/
COPY --from=builder /build/libiec61850-1.6.0/build/examples/server_example_password_auth/server_example_password_auth /usr/local/bin/
COPY --from=builder /build/mms_tls_auth_server/mms_tls_auth_server /usr/local/bin/

# Copy TLS certificates
RUN mkdir -p /etc/iec61850/certs
COPY --from=builder /build/libiec61850-1.6.0/examples/tls_server_example/server_CA1_1.key /etc/iec61850/certs/
COPY --from=builder /build/libiec61850-1.6.0/examples/tls_server_example/server_CA1_1.pem /etc/iec61850/certs/
COPY --from=builder /build/libiec61850-1.6.0/examples/tls_server_example/root_CA1.pem /etc/iec61850/certs/
COPY --from=builder /build/libiec61850-1.6.0/examples/tls_server_example/client_CA1_1.pem /etc/iec61850/certs/
COPY --from=builder /build/libiec61850-1.6.0/examples/tls_server_example/client_CA1_2.pem /etc/iec61850/certs/

# Copy model/config files
COPY --from=builder /build/libiec61850-1.6.0/examples/server_example_config_file/*.cfg /etc/iec61850/

# Startup script
RUN echo '#!/bin/sh\n\
echo "Available IEC 61850 test servers:"\n\
echo "1. server_example_basic_io - Basic I/O operations"\n\
echo "2. server_example_goose - GOOSE publisher"\n\
echo "3. server_example_control - Control operations"\n\
echo "4. server_example_61400_25 - Wind power plant data model"\n\
echo "5. server_example_config_file - Server with config file"\n\
echo "6. server_example_password_auth - Password auth (user1/user2@testpw)"\n\
echo "7. mms_tls_auth_server - TLS + password auth (admin/operator@mms)"\n\
echo ""\n\
echo "Starting server_example_basic_io on port 102..."\n\
echo ""\n\
exec /usr/local/bin/server_example_basic_io "$@"' > /usr/local/bin/start-server.sh && \
    chmod +x /usr/local/bin/start-server.sh

EXPOSE 102

CMD ["/usr/local/bin/start-server.sh"]
