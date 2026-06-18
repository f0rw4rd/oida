# VNC (Virtual Network Computing) / RFB - Reference Materials

## Protocol Overview

VNC uses the RFB (Remote Frame Buffer) protocol for remote desktop access. Widely used in ICS for remote HMI access.

- **Transport**: TCP port 5900+ (5900 for display :0, 5901 for :1, etc.)
- **Handshake**: ProtocolVersion -> Security Type -> Security Handshake -> ClientInit -> ServerInit
- **Messages**: FramebufferUpdate, SetPixelFormat, SetEncodings, FramebufferUpdateRequest, KeyEvent, PointerEvent, CutText
- **Security Types**: None (1), VNC Authentication (2), TLS (18), VeNCrypt (19+)

## Wireshark Dissectors

- **VNC/RFB**: [packet-vnc.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-vnc.c)

## Open-Source Implementations

| Project | Language | Link |
|---------|----------|------|
| **LibVNCServer** | C | [github.com/LibVNC/libvncserver](https://github.com/LibVNC/libvncserver) |
| **TigerVNC** | C++ | [github.com/TigerVNC/tigervnc](https://github.com/TigerVNC/tigervnc) |
| **noVNC** | JavaScript | [github.com/novnc/noVNC](https://github.com/novnc/noVNC) |

## Fuzzing Tools

| Tool | Description | Link |
|------|-------------|------|
| **Mutiny Fuzzer (Cisco Talos)** | Network fuzzer with VNC/RFB-specific fuzzer configuration targeting port 5900 TCP | [github.com/Cisco-Talos/mutiny-fuzzer](https://github.com/Cisco-Talos/mutiny-fuzzer/blob/master/sample_apps/vnc/data/vnc-1.fuzzer) |
| **AFLNet** | Greybox protocol fuzzer with state-feedback, applicable to VNC server fuzzing | [github.com/aflnet/aflnet](https://github.com/aflnet/aflnet) |
| **ProFuzzBench** | Benchmark for stateful protocol fuzzing, can target VNC servers | [github.com/profuzzbench/profuzzbench](https://github.com/profuzzbench/profuzzbench) |
| **Fuzzotron** | TCP/UDP network daemon fuzzer with crash detection | [github.com/denandz/fuzzotron](https://github.com/denandz/fuzzotron) |
| **Fuzzowski** | Network protocol fuzzer supporting protocol definition for custom targets | [github.com/nccgroup/fuzzowski](https://github.com/nccgroup/fuzzowski) |

## Attack Surface Notes

- **Server-side FramebufferUpdate**: The largest server-side attack surface is in encoding/decoding FramebufferUpdate messages. Encoding-specific decoders (Tight, ZRLE, Hextile, CoRRE) each have independent parsing code. TightVNC CVE-2019-15680 (HandleCoRREBBP) and LibVNCServer heap overflows demonstrate that individual encoding handlers are the most common source of memory corruption.
- **Integer overflows in dimensions**: Width * height * bytes_per_pixel calculations routinely overflow. CVE-2022-23967 (TightVNC) shows that passing -1 to malloc yields a zero-size allocation followed by massive writes. CVE-2023-43826 (Apache Guacamole) shows the same pattern in FramebufferUpdate rectangle handling.
- **Handshake/init phase**: ProtocolVersion, SecurityType selection, and ServerInit (desktop name with length prefix) are all pre-auth server-side parsing targets. CVE-2020-14397 (LibVNCServer NULL deref in ClientInit) shows crashes in the init phase.
- **Compressed data streams**: ZRLE and Tight encodings use zlib compression. Crafted compressed data can cause decompression bombs or buffer overflows when decompressed size exceeds allocation.
- **ICS relevance**: VNC is widely used for remote HMI access in industrial environments, often without encryption or with weak VNC authentication. Server-side parsing bugs are directly exploitable from the network.
- **VMware VNC**: Cisco Talos found VNC vulnerabilities in VMware products using the Decept Proxy + Mutiny Fuzzer workflow, demonstrating that even enterprise VNC implementations contain server-side bugs in standard RFB message handlers.

## Common Parsing Vulnerabilities

1. **FramebufferUpdate Rectangles**: Width * height * bytes_per_pixel exceeding allocation
2. **Encoding-Specific Parsing**: Tight, ZRLE, Hextile encodings with complex sub-rect structures
3. **SetPixelFormat**: bits_per_pixel, color_max, shift values creating impossible combinations
4. **CutText**: 4-byte text length field with very large values
5. **Security Handshake**: DES challenge-response with crafted server challenge
6. **ServerInit**: Desktop name string with length prefix
7. **ZLib Compressed Data**: Compressed encoding data exceeding decompressed buffer
