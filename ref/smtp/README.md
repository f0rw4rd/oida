# SMTP (Simple Mail Transfer Protocol) - Reference Materials

## Protocol Overview

SMTP (RFC 5321) is the standard protocol for email transmission. Text-based command/response protocol using TCP.

- **Transport**: TCP port 25 (MTA-to-MTA), port 587 (submission), port 465 (SMTPS)
- **Commands**: HELO/EHLO, MAIL FROM, RCPT TO, DATA, QUIT, RSET, VRFY, EXPN, AUTH, STARTTLS
- **Response**: 3-digit code + text

## Wireshark Dissectors

- **SMTP**: [packet-smtp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-smtp.c)

## Open-Source Implementations

| Project | Language | Link |
|---------|----------|------|
| **Postfix** | C | [github.com/vdukhovni/postfix](https://github.com/vdukhovni/postfix) |
| **Exim** | C | [github.com/Exim/exim](https://github.com/Exim/exim) |
| **aiosmtpd** | Python | [github.com/aio-libs/aiosmtpd](https://github.com/aio-libs/aiosmtpd) |

## Fuzzing Tools

| Tool | Description | Link |
|------|-------------|------|
| **AFLNet** | Greybox fuzzer for network protocols with state-feedback; supports SMTP protocol natively | [github.com/aflnet/aflnet](https://github.com/aflnet/aflnet) |
| **StateAFL** | AFL extension for stateful servers, maximizing protocol state coverage | [github.com/stateafl/stateafl](https://github.com/stateafl/stateafl) |
| **ProFuzzBench** | Benchmark suite with SMTP fuzzing targets (Exim, Postfix) | [github.com/profuzzbench/profuzzbench](https://github.com/profuzzbench/profuzzbench) |
| **Fuzzowski** | Network protocol fuzzer with protocol definition support | [github.com/nccgroup/fuzzowski](https://github.com/nccgroup/fuzzowski) |
| **BooFuzz** | Successor to Sulley, supports custom protocol definitions including SMTP | [github.com/jtpereyda/boofuzz](https://github.com/jtpereyda/boofuzz) |

## Attack Surface Notes

- **Pre-auth surface**: EHLO/HELO hostname parsing, STARTTLS negotiation (Exim CVE-2019-15846 TLS SNI heap overflow), AUTH mechanism selection (CVE-2023-42115 OOB write in external auth).
- **21Nails class (Exim)**: Qualys found 21 vulnerabilities in Exim including UAF in TLS (CVE-2020-28018), integer overflow in receive_msg (CVE-2020-28020), and function pointer corruption after BDAT error (CVE-2020-28019). These represent the full spectrum of memory corruption bug classes in a single SMTP server.
- **SMTP Smuggling**: CVE-2023-51764 (Postfix) demonstrates that line-ending interpretation differences (LF vs CRLF) between MTAs allow email spoofing and SPF bypass. The fundamental issue is Postfix accepting bare LF as line terminator.
- **SPF/DKIM parsing**: Exim CVE-2023-42118 shows integer underflow in libspf2 macro parsing -- any SPF evaluation code is attack surface reachable by unauthenticated senders.
- **BDAT/chunked transfer**: The BDAT command (RFC 3030) is a relatively uncommon code path in many MTAs, making it a fertile area for undiscovered bugs.

## Common Parsing Vulnerabilities

1. **MAIL FROM/RCPT TO Address Parsing**: Angle brackets, quoted local parts, long addresses
2. **EHLO Hostname**: Extremely long hostnames, special characters
3. **DATA Termination**: "." on a line by itself - byte stuffing issues
4. **MIME Parsing**: Content-Type boundaries, nested multipart, encoded headers
5. **AUTH Command**: Base64 encoded credentials with padding issues
6. **Pipelining**: Multiple commands sent before responses received
7. **STARTTLS Stripping**: Command injection before/during TLS negotiation
