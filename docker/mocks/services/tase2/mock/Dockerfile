# FreeTASE2 Mock Server
# Builds libiec61850 with Python bindings for TASE.2/ICCP (IEC 60870-6)
#
# Implements: Block 1 (Basic), Block 2 (RBE), Block 5 (Device Control)
# Based on: https://github.com/mz-automation/libiec61850
# License: GPLv3

FROM python:3.11-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    cmake \
    build-essential \
    swig \
    python3-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Clone libiec61850
WORKDIR /build
RUN git clone --depth 1 https://github.com/mz-automation/libiec61850.git

# Clone FreeTase2 for TASE.2 abstractions
RUN git clone --depth 1 https://github.com/aklira/FreeTase2.git

# Download and extract mbedtls 3.6.0 for R-GOOSE support
WORKDIR /build/libiec61850/third_party/mbedtls
RUN wget -q https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.6.0.tar.gz && \
    tar xzf v3.6.0.tar.gz && \
    rm v3.6.0.tar.gz

# Build libiec61850 with Python bindings and R-GOOSE support
WORKDIR /build/libiec61850
RUN mkdir build && cd build && \
    cmake .. \
        -DBUILD_PYTHON_BINDINGS=ON \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_TESTS=OFF \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc) && \
    make install

# Find and collect Python bindings.
# The SWIG build produces pyiec61850.py + _pyiec61850.so (module name is
# "pyiec61850", not "iec61850") -- the old patterns here ("_iec61850.so",
# "iec61850.py") never matched anything, so the compiled extension was never
# copied and the container crash-looped with "No module named 'iec61850'".
# FreeTase2 (vendored below) imports `iec61850` directly, so also drop in a
# compatibility shim re-exporting the real module under that name.
RUN mkdir -p /build/python_bindings && \
    find /build/libiec61850 -name "pyiec61850.py" -exec cp {} /build/python_bindings/ \; && \
    find /build/libiec61850 -name "_pyiec61850.so" -exec cp {} /build/python_bindings/ \; && \
    printf '%s\n' \
        '"""Compat shim: FreeTase2 imports `iec61850`; the built SWIG module is `pyiec61850`."""' \
        'from pyiec61850 import *  # noqa: F401,F403' \
        > /build/python_bindings/iec61850.py

# Verify SWIG bindings are properly linked
RUN ldconfig && \
    python3 -c "import sys; sys.path.insert(0, '/build/python_bindings'); import iec61850; print('[OK] libiec61850 SWIG bindings OK')"

# Runtime image
FROM python:3.11-slim-bookworm

# Copy built library
COPY --from=builder /usr/local/lib/libiec61850* /usr/local/lib/

# Copy Python bindings
COPY --from=builder /build/python_bindings/* /usr/local/lib/python3.11/site-packages/

# Copy FreeTase2 library
COPY --from=builder /build/FreeTase2/tase2 /usr/local/lib/python3.11/site-packages/tase2

# Update library cache
RUN ldconfig

# Create app directory
WORKDIR /app

# Copy server files
COPY tase2_types.py /app/
COPY tase2_server_spec.py /app/server.py

# Expose TASE.2/MMS port (ISO-TSAP)
EXPOSE 102

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1', 102)); s.close()" || exit 1

ENTRYPOINT ["python", "/app/server.py"]
CMD ["--port", "102"]
