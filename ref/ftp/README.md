# FTP (File Transfer Protocol) - Reference Materials

## Protocol Overview

FTP (RFC 959) is a standard protocol for file transfer. It uses a control connection (TCP port 21) for commands/replies and separate data connections (port 20 active, ephemeral passive) for file transfers. FTP is text-based with simple command/response format.

- **Control**: TCP port 21
- **Data**: TCP port 20 (active mode) or ephemeral port (passive mode, PASV/EPSV)
- **Commands**: USER, PASS, LIST, RETR, STOR, CWD, PWD, TYPE, PORT, PASV, EPSV, QUIT, etc.
- **Replies**: 3-digit status code + text (e.g., "220 Welcome", "530 Login incorrect")
- **Modes**: Active (PORT), Passive (PASV), Extended Passive (EPSV)

## Wireshark Dissectors

- **FTP**: [packet-ftp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-ftp.c)
- **FTP-DATA**: [packet-ftp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-ftp.c) (same file)
- Command/response parsing, PORT/PASV data connection tracking

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **vsftpd** | C | Very Secure FTP Daemon | [security.appspot.com/vsftpd.html](https://security.appspot.com/vsftpd.html) |
| **ProFTPD** | C | Professional FTP daemon | [github.com/proftpd/proftpd](https://github.com/proftpd/proftpd) |
| **pyftpdlib** | Python | Python FTP server library | [github.com/giampaolo/pyftpdlib](https://github.com/giampaolo/pyftpdlib) |
| **ftplib** | Python | Python standard library FTP client | Built into Python |

## Common Parsing Vulnerabilities

### 1. Command Injection
- Long command arguments exceeding buffer sizes
- Null bytes in command arguments
- CRLF injection in USER/PASS/CWD/MKD arguments
- Glob patterns in LIST/NLST arguments

### 2. PORT/PASV Address Parsing
- PORT command: h1,h2,h3,h4,p1,p2 (IP + port) - bounce attack to internal services
- PASV response parsing: address extraction from parentheses
- EPSV: |||port| format parsing
- Invalid IP addresses, port 0, privileged ports

### 3. Path Traversal
- CWD with ../../../ sequences
- RETR/STOR with absolute paths or traversal sequences
- Symbolic link following
- Unicode/encoding-based traversal

### 4. Reply Parsing
- Multi-line replies (3-digit + hyphen, then 3-digit + space to end)
- Very long reply lines
- Unexpected reply codes for given command
- Reply injection via filename (LIST output)

### 5. Data Connection Issues
- Data connection race conditions (TOCTOU)
- Very large file transfers exhausting resources
- Data connection timeout handling
- Active mode connection to arbitrary hosts (FTP bounce)

## Fuzzing Tools

| Tool | Description | Link |
|------|-------------|------|
| **AFLNet** | Greybox fuzzer for network protocols with state-feedback; has FTP-specific corpus support | [github.com/aflnet/aflnet](https://github.com/aflnet/aflnet) |
| **StateAFL** | AFL extension maximizing both code coverage and protocol state coverage for stateful servers | [github.com/stateafl/stateafl](https://github.com/stateafl/stateafl) |
| **ProFuzzBench** | Benchmark suite with automation scripts for fuzzing LightFTP and other FTP servers via AFLNet/StateAFL | [github.com/profuzzbench/profuzzbench](https://github.com/profuzzbench/profuzzbench) |
| **Fuzzowski** | Network protocol fuzzer with FTP support, assists in crash identification | [github.com/nccgroup/fuzzowski](https://github.com/nccgroup/fuzzowski) |
| **BooFuzz** | Successor to Sulley fuzzing framework, supports custom FTP protocol definitions | [github.com/jtpereyda/boofuzz](https://github.com/jtpereyda/boofuzz) |

### Research

- **GitHub Security Lab**: [Fuzzing sockets, part 1: FTP servers](https://securitylab.github.com/resources/fuzzing-sockets-FTP/) - Tutorial on fuzzing FTP servers with AFL, including authentication handling and corpus design.

## Attack Surface Notes

- **Pre-auth attack surface**: Banner parsing, USER/PASS command handling, FEAT response. ProFTPD CVE-2023-51713 shows even single-byte OOB reads in command parsing can crash daemons.
- **Post-auth attack surface**: SITE commands (CPFR/CPTO in mod_copy), LIST/NLST glob handling (vsftpd CVE-2011-0762), data transfer pool management (ProFTPD CVE-2020-9273 UAF).
- **Embedded/ICS FTP**: Siemens Nucleus RTOS FTP stack (NUCLEUS:13) shows classic stack overflows in USER command length validation -- ICS FTP servers often lack modern mitigations.
- **Module-specific surface**: ProFTPD modules (mod_copy, mod_sftp, mod_tls) each add independent parsing code with their own bug classes.

## Notable Research

- **"FTP Bounce Attack"** - Classic attack using PORT command
- **ProFTPD/vsftpd vulnerability history** - Rich CVE history
