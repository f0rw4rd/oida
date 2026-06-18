# IEC 60870-5-104/101 Mock Server
#
# Build: docker build -t iec104-server .
#
# Run (IEC 104 only):
#   docker run -p 2404:2404 iec104-server
#
# Run (IEC 101 with serial port):
#   docker run --device=/dev/ttyUSB0 iec104-server -p 0 -s /dev/ttyUSB0 -b 9600
#
# Run (both IEC 104 and 101):
#   docker run -p 2404:2404 --device=/dev/ttyUSB0 iec104-server -s /dev/ttyUSB0
#

FROM debian:bookworm-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    && rm -rf /var/lib/apt/lists/*

# Clone and build lib60870
WORKDIR /build
RUN git clone --depth 1 https://github.com/mz-automation/lib60870.git

WORKDIR /build/lib60870/lib60870-C
RUN mkdir -p build && cd build && cmake .. && make -j$(nproc)

# Copy server source and build
WORKDIR /build/server
COPY iec104_server.c .

# Build the server (library is in build/src/)
# Includes both IEC 104 (TCP) and IEC 101 (serial) support
RUN gcc -o iec104_server iec104_server.c \
    -I/build/lib60870/lib60870-C/src/inc/api \
    -I/build/lib60870/lib60870-C/src/inc/internal \
    -I/build/lib60870/lib60870-C/src/common/inc \
    -I/build/lib60870/lib60870-C/src/hal/inc \
    -I/build/lib60870/lib60870-C/src/hal/serial \
    -I/build/lib60870/lib60870-C/src/file-service \
    -L/build/lib60870/lib60870-C/build/src \
    -Wl,-Bstatic -llib60870 -Wl,-Bdynamic \
    -lpthread \
    -lm

# Final stage - minimal runtime image
FROM debian:bookworm-slim

# Install runtime dependencies (minimal)
RUN apt-get update && apt-get install -y \
    libpthread-stubs0-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy built binary
COPY --from=builder /build/server/iec104_server /usr/local/bin/

# Create non-root user
RUN useradd -r -s /bin/false iec104

# Expose IEC 104 port
EXPOSE 2404

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD timeout 2 bash -c '</dev/tcp/localhost/2404' || exit 1

# Run as non-root (but need to use port 2404)
# For ports < 1024, we need root or capabilities
USER root

ENTRYPOINT ["/usr/local/bin/iec104_server"]
CMD ["-p", "2404"]
