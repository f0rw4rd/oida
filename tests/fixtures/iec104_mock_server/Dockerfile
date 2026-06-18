FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    && rm -rf /var/lib/apt/lists/*

# Clone and build lib60870
WORKDIR /opt
RUN git clone --depth 1 https://github.com/mz-automation/lib60870.git

# Copy patched file_server.c with F_DR_TA_1 directory support
COPY file_server_patched.c /opt/lib60870/lib60870-C/src/file-service/file_server.c

WORKDIR /opt/lib60870/lib60870-C
RUN mkdir build && cd build && \
    cmake .. -DCMAKE_POLICY_VERSION_MINIMUM=3.5 && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Copy and build our server
WORKDIR /app
COPY server.c .

RUN gcc -o iec104_server server.c \
    -I/usr/local/include/lib60870 \
    -llib60870 \
    -lpthread

EXPOSE 2404

CMD ["./iec104_server"]
