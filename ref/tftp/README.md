# TFTP (Trivial File Transfer Protocol) - Reference Materials

## Protocol Overview

TFTP (RFC 1350) is a simplified file transfer protocol using UDP. No authentication, no directory listing - only read and write operations. Used extensively in ICS/embedded systems for firmware updates, configuration file transfer, and PXE boot.

- **Transport**: UDP port 69 (initial), then ephemeral ports for transfer
- **Opcodes**: RRQ (1), WRQ (2), DATA (3), ACK (4), ERROR (5), OACK (6)
- **Block Size**: Default 512 bytes, extensible via RFC 2348
- **Transfer Modes**: netascii, octet, mail (deprecated)

## Wireshark Dissectors

- **TFTP**: [packet-tftp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-tftp.c)

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **tftpd-hpa** | C | HPA's TFTP server | [kernel.org/pub/software/network/tftp/](https://www.kernel.org/pub/software/network/tftp/) |
| **py3tftp** | Python | Python 3 TFTP implementation | [github.com/sirMackk/py3tftp](https://github.com/sirMackk/py3tftp) |
| **dnsmasq** | C | Includes TFTP server | [thekelleys.org.uk/dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) |
| **Scapy** | Python | TFTP layer | [github.com/secdev/scapy](https://github.com/secdev/scapy) |

## Common Parsing Vulnerabilities

### 1. Filename Handling
- Null-terminated filename string with no length limit in protocol
- Path traversal via ../ sequences (no directory concept in TFTP)
- Filename with null bytes, special characters, extremely long names

### 2. Block Number Overflow
- 16-bit block number wraps at 65535 (Sorcerer's Apprentice Syndrome)
- Block number 0 in unexpected contexts
- Out-of-order blocks, duplicate blocks

### 3. Option Extension (RFC 2347)
- Null-terminated option name + null-terminated value pairs
- blksize, tsize, timeout options with extreme values
- blksize=0 or blksize > 65464 (max UDP payload)
- Unknown option names

### 4. Error Packet Injection
- UDP-based - error packets from spoofed sources
- Error code values outside defined range (0-7)
- Error message string with no length limit

## Fuzzing Tools

| Tool | Description | Link |
|------|-------------|------|
| **Fuzzowski** | Network protocol fuzzer with built-in TFTP fuzzer module | [github.com/nccgroup/fuzzowski](https://github.com/nccgroup/fuzzowski) |
| **Fuzzowski-ICS** | ICS-focused fork of Fuzzowski with TFTP support | [github.com/h0rac/fuzzowski-ics](https://github.com/h0rac/fuzzowski-ics) |
| **tftp-fuzz (NullSecurity)** | Standalone Python TFTP fuzzer for discovering bugs in TFTP servers | [github.com/nullsecuritynet/tools](https://github.com/nullsecuritynet/tools/blob/main/fuzzer/tftp-fuzz/release/tftp-fuzz.py) |
| **BooFuzz** | General-purpose fuzzer with TFTP examples | [github.com/jtpereyda/boofuzz](https://github.com/jtpereyda/boofuzz) |
| **DotDotPwn** | Directory traversal fuzzer supporting TFTP, FTP, HTTP | [github.com/wireghoul/dotdotpwn](https://github.com/wireghoul/dotdotpwn) |
| **CheckPoint TFTP Fuzzer** | Sulley-based TFTP fuzzer used to discover PXE Dust vulnerabilities | [github.com/CheckPointSW/Cyber-Research](https://github.com/CheckPointSW/Cyber-Research/blob/master/Vulnerability/PXE_Dust/tftp-sulley-fuzzer.py) |
| **Metasploit TFTP Fuzzer** | Metasploit auxiliary module for simple TFTP fuzzing | [OffSec Metasploit Unleashed](https://www.offsec.com/metasploit-unleashed/simple-tftp-fuzzer/) |

## Attack Surface Notes

- **Filename parsing is the #1 target**: TFTP has no authentication, so filename in RRQ/WRQ is the primary pre-auth attack surface. Both path traversal and buffer overflow in filename handling are extremely common (CVE-2019-12253 SolarWinds, CVE-2020-29368 Nucleus RTOS).
- **Embedded/RTOS TFTP stacks**: The NUCLEUS:13 research (Forescout) found stack overflows in Siemens Nucleus RTOS TFTP/FTP servers affecting 3+ billion deployed devices in healthcare and critical infrastructure. These stacks often lack ASLR/stack canaries.
- **Option extension parsing**: RFC 2347 option extensions (blksize, tsize, timeout) are null-terminated key-value pairs with no length limits in the protocol. The CVE-2021-3939 tftpd-hpa blksize overflow demonstrates that even mature implementations mishandle option values.
- **UDP-based -- no connection state**: TFTP runs over UDP, making it trivial to spoof source addresses and inject error/data packets into active transfers.
- **PXE boot chain**: TFTP is critical in PXE boot. Compromising a TFTP server or injecting responses can lead to boot-level code execution on all network-booting hosts.

## Key Vulnerability Patterns for Fuzzing

1. **Path Traversal**: ../../../etc/passwd in RRQ/WRQ filename
2. **Block Size Option**: blksize=0, very large values, non-numeric values
3. **Block Number Wrapping**: Transfers exceeding 32MB (65535 * 512 bytes)
4. **Filename Length**: Extremely long filenames exceeding server buffer
5. **Mode String**: Invalid mode strings, null bytes in mode
