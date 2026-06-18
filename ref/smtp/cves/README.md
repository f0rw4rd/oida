# SMTP - Notable CVEs

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2018-6789 | Exim (< 4.90.1) | Off-by-one heap overflow in base64d() SMTP listener | Heap Overflow / RCE | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-6789) |
| CVE-2019-15846 | Exim (< 4.92.2) | Heap overflow in TLS SNI processing via backslash-null | Heap Overflow / RCE | 9.8 | [Exim Advisory](https://www.exim.org/static/doc/security/CVE-2019-15846.txt) |
| CVE-2019-10149 | Exim (4.87-4.91) | RCE via crafted RCPT TO recipient address (expand_string) | Command Injection / RCE | 9.8 | [Qualys Advisory](https://www.qualys.com/2019/06/05/cve-2019-10149/return-wizard-rce-exim.txt) |
| CVE-2020-28018 | Exim (4.90-4.93) | Use-after-free in TLS via stale server_corked pointer (21Nails) | UAF / RCE | 9.8 | [Qualys 21Nails](https://www.qualys.com/2021/05/04/21nails/21nails.txt) |
| CVE-2020-28019 | Exim (4.88-4.94.1) | Stack exhaustion from recursive bdat_getc after BDAT error (21Nails) | Stack Exhaustion / DoS | 7.5 | [Qualys 21Nails](https://www.qualys.com/2021/05/04/21nails/21nails.txt) |
| CVE-2020-28020 | Exim (< 4.92) | Integer overflow in receive_msg() header handling (21Nails) | Integer Overflow / RCE | 9.8 | [Qualys 21Nails](https://www.qualys.com/2021/05/04/21nails/21nails.txt) |
| CVE-2023-42115 | Exim (< 4.96.1) | Out-of-bounds write in SMTP AUTH external handler | OOB Write / RCE | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-42115) |
| CVE-2023-42116 | Exim (< 4.96.1) | Stack-based buffer overflow in NTLM challenge handling | Stack Overflow / RCE | 8.1 | [NVD](https://nvd.nist.gov/vuln/detail/cve-2023-42116) |
| CVE-2023-42117 | Exim | Improper validation of user-supplied data in SMTP service | Memory Corruption / RCE | 8.1 | [SOCRadar](https://socradar.io/zero-day-vulnerabilities-in-exim-email-server-risk-of-rce-cve-2023-42115-cve-2023-42116-cve-2023-42117-and-more/) |
| CVE-2023-42118 | Exim (libspf2) | Integer underflow during SPF macro parsing before memcpy | Integer Underflow / RCE | 8.8 | [NVD](https://nvd.nist.gov/vuln/detail/cve-2023-42118) |
| CVE-2023-51766 | Postfix | SMTP smuggling via inconsistent line ending handling | Smuggling | 5.3 | [Postfix Advisory](https://www.postfix.org/) |
| CVE-2021-3618 | Multiple (ALPACA attack) | Cross-protocol attack via TLS server certificate sharing | MITM | 7.4 | [ALPACA](https://alpaca-attack.com/) |
| CVE-2020-12641 | Roundcube | SMTP command injection via crafted message data | Injection / RCE | 9.8 | [Roundcube Advisory](https://roundcube.net/news/) |

## Detailed Writeups -- Server-Side Parsing Bugs

The following CVEs pass the fuzzer test: sending malformed/crafted bytes on the wire triggers
the bug. Logic flaws (CVE-2019-10149 command injection via expand_string), protocol design
issues (CVE-2023-51766 SMTP smuggling, CVE-2021-3618 ALPACA), and client-side bugs
(CVE-2020-12641 Roundcube) are excluded from detailed analysis.

---

### CVE-2018-6789
- **Product**: Exim < 4.90.1 (all versions since first commit)
- **Type**: Heap-based Buffer Overflow (off-by-one)
- **CVSS**: 9.8 (NVD)
- **Server-side**: Yes -- Exim SMTP daemon parses base64-encoded AUTH credentials via the `base64d()` function in `base64.c`
- **Root cause**: The `base64d()` function allocates the decode buffer with `store_get(3*(Ustrlen(code)/4) + 1)`, which computes `3n+1` bytes for input of length `4n+3`. However, when the input is not valid base64 and has length `4n+3`, the decoder consumes `3n+2` bytes while only `3n+1` bytes were allocated. This produces a controllable one-byte heap overflow.
- **Trigger**: Send an SMTP AUTH command (e.g., AUTH CRAM-MD5) with a base64-encoded response whose decoded length is exactly `4n+3` bytes (e.g., 3, 7, 11, 15...) and contains invalid base64 characters. The off-by-one overflow byte is fully attacker-controlled.
- **PoC**: [github.com/synacktiv/Exim-CVE-2018-6789](https://github.com/synacktiv/Exim-CVE-2018-6789) | [github.com/c0llision/exim-vuln-poc](https://github.com/c0llision/exim-vuln-poc) | [github.com/martinclauss/exim-rce-cve-2018-6789](https://github.com/martinclauss/exim-rce-cve-2018-6789)
- **Metasploit**: N/A
- **ExploitDB**: [EDB-44571](https://www.exploit-db.com/exploits/44571)
- **Advisory**: [DEVCORE technical writeup](https://devco.re/blog/2018/03/06/exim-off-by-one-RCE-exploiting-CVE-2018-6789-en/)
- **Analysis**: Classic off-by-one from an incorrect buffer size calculation in base64 decoding. A fuzzer mutating base64 payloads in AUTH commands -- specifically varying lengths around `4n+3` boundaries and injecting non-alphabet bytes -- would trigger this reliably. The single overflow byte is enough to corrupt heap metadata and achieve full RCE via heap grooming. Mutation strategy: length-boundary base64 strings with invalid characters in AUTH PLAIN/LOGIN/CRAM-MD5 responses.

---

### CVE-2019-15846
- **Product**: Exim < 4.92.2
- **Type**: Heap-based Buffer Overflow
- **CVSS**: 9.8 (NVD)
- **Server-side**: Yes -- Exim parses the TLS Server Name Indication (SNI) field from the ClientHello during TLS handshake setup
- **Root cause**: The SNI value is read from the spool via `string_unprinting(string_copy())`. Both functions use `store_get()` to allocate buffers. The destination buffer is allocated immediately after the source buffer in the heap. When the SNI ends with a backslash-null (`\\\0`) sequence, `string_unprinting()` reads past the end of the source buffer into the destination buffer, transforming an out-of-bounds read into an out-of-bounds write. The overflow length and contents are both attacker-controlled.
- **Trigger**: Initiate a TLS handshake to the Exim SMTP server (STARTTLS or implicit TLS on port 465) with a ClientHello containing an SNI field ending in a backslash followed by a null byte (`\\\x00`). The heap overflow occurs when the spool file is later processed by `string_unprinting()`.
- **PoC**: [github.com/synacktiv/Exim-CVE-2019-15846](https://github.com/synacktiv/Exim-CVE-2019-15846) (spool file generator + exploitation materials)
- **Metasploit**: N/A (feature request at [rapid7/metasploit-framework#12284](https://github.com/rapid7/metasploit-framework/issues/12284), no official module)
- **Advisory**: [Exim CVE-2019-15846.txt](https://www.exim.org/static/doc/security/CVE-2019-15846.txt) | [Qualys analysis in exim.git](https://github.com/Exim/exim/blob/master/doc/doc-txt/cve-2019-15846/qualys.mbx)
- **Analysis**: The bug is in how Exim unescapes backslash sequences from stored SNI strings. A fuzzer targeting the TLS ClientHello SNI extension with trailing backslash-null sequences and other escape characters would trigger this. The overflow overwrites a free malloc chunk header, allowing the attacker to control large regions of heap memory. Mutation strategy: fuzz the SNI extension field in TLS ClientHello with backslash sequences, null bytes, and escape character combinations. Any Exim server accepting TLS is vulnerable regardless of TLS library (OpenSSL or GnuTLS).

---

### CVE-2020-28018
- **Product**: Exim 4.90 through 4.93 (builds with OpenSSL TLS)
- **Type**: Use-After-Free
- **CVSS**: 9.8 (NVD)
- **Server-side**: Yes -- Exim SMTP server fails to reset a static pointer in `tls_write()` after `smtp_reset()` frees POOL_MAIN memory
- **Root cause**: The `tls_write()` function in `tls-openssl.c` uses a static variable `server_corked` that caches a `struct gstring` pointer and its associated string buffer allocated in `POOL_MAIN` memory. When PIPELINING is enabled (default), SMTP responses are buffered in this structure. When `smtp_reset()` calls `store_reset()`, all `POOL_MAIN` memory is freed -- but `server_corked` is never reset to NULL. The next call to `tls_write()` uses the dangling pointer, writing into freed and potentially reallocated memory.
- **Trigger**: Connect to an Exim server with STARTTLS enabled (OpenSSL build). Complete TLS handshake. Send a sequence of SMTP commands that causes `smtp_reset()` to be called (e.g., a MAIL FROM followed by RSET or a rejected message), then send additional commands that trigger `tls_write()`. The stale `server_corked` pointer dereferences freed heap memory.
- **PoC**: [github.com/lockedbyte/CVE-Exploits/tree/master/CVE-2020-28018](https://github.com/lockedbyte/CVE-Exploits/tree/master/CVE-2020-28018) (C exploit) | [github.com/dorkerdevil/CVE-2020-28018](https://github.com/dorkerdevil/CVE-2020-28018) | [adepts.of0x.cc analysis](https://adepts.of0x.cc/exim-cve-2020-28018/)
- **Metasploit**: N/A
- **Advisory**: [Qualys 21Nails](https://www.qualys.com/2021/05/04/21nails/21nails.txt) | [Exim CVE-2020-28018-OCORK.txt](https://www.exim.org/static/doc/security/CVE-2020-qualys/CVE-2020-28018-OCORK.txt)
- **Analysis**: This is a state-dependent UAF triggered by a specific sequence of SMTP commands over TLS. Exploitation builds arbitrary read/write primitives: step 1 leaks heap pointers from `header_line` structs, step 2 reads heap to find Exim configuration, step 3 overwrites config with `${run{<cmd>}}` for RCE. A stateful protocol fuzzer that sends varied SMTP command sequences after STARTTLS (especially RSET, MAIL FROM, DATA abort patterns) would trigger the crash. Mutation strategy: vary SMTP command ordering and pipelining patterns after TLS handshake, with focus on state transitions that invoke `smtp_reset()` while TLS write buffering is active.

---

### CVE-2020-28020
- **Product**: Exim 4.00 through 4.94.1 (exploitable pre-4.92)
- **Type**: Integer Overflow to Buffer Overflow
- **CVSS**: 9.8 (NVD)
- **Server-side**: Yes -- Exim SMTP server's `receive_msg()` function overflows an integer when processing email header continuation lines
- **Root cause**: Exim limits mail headers to 1MB (`header_maxsize`), but an attacker can bypass this limit by sending only continuation lines (lines starting with whitespace after a newline). The `header_size` variable is doubled repeatedly via `header_size *= 2` in a loop without checking for integer overflow. When `header_size` exceeds `INT_MAX/2`, the multiplication wraps to a negative value. This negative size is passed to `store_extend()`/`store_get()`, resulting in a small heap allocation that is subsequently overwritten with attacker-controlled data. The fix added `if (header_size >= INT_MAX/2)` before the doubling.
- **Trigger**: Send an email via SMTP DATA with a header consisting of approximately 512MB-1GB of continuation lines. Each line is whitespace-prefixed (e.g., `\r\n ` repeated). Exim transforms bare `\n` into `\n ` (continuation line), reducing required bandwidth to approximately 512MB. The integer overflow occurs after roughly 10 doublings of `header_size` past 1MB.
- **PoC**: No standalone public PoC (technical details in Qualys advisory; exploit requires approximately 3GB of memory)
- **Metasploit**: N/A
- **Advisory**: [Qualys 21Nails](https://www.qualys.com/2021/05/04/21nails/21nails.txt) | [Exim CVE-2020-28020-HSIZE.txt](https://www.exim.org/static/doc/security/CVE-2020-qualys/CVE-2020-28020-HSIZE.txt) | [oss-security discussion](https://www.openwall.com/lists/oss-security/2021/07/25/1)
- **Analysis**: Classic integer overflow from unchecked doubling of a size variable during header parsing. A fuzzer generating emails with extremely long continuation-line headers (gigabytes of whitespace-prefixed lines) would trigger this. The negative allocation size leads to heap corruption that can be shaped into RCE. Mutation strategy: send DATA payloads with massive header blocks consisting entirely of continuation lines (`\n<space>` or `\r\n<space>` repeated). Focus on header sizes near power-of-two boundaries approaching INT_MAX.

---

### CVE-2020-28019
- **Product**: Exim 4.88 through 4.94.1
- **Type**: Stack Exhaustion / Denial of Service (potential code execution)
- **CVSS**: 7.5 (NVD)
- **Server-side**: Yes -- Exim SMTP server fails to reset the `receive_getc` function pointer after a BDAT command error, leading to recursive function calls
- **Root cause**: When Exim processes a BDAT command (RFC 3030 chunked transfer), it replaces the `receive_getc` function pointer with `bdat_getc()` at line 5275 of the receive path. If the BDAT payload exceeds `message_size_limit` (50MB default), Exim re-enters `smtp_setup_msg()` without resetting `receive_getc` back to its original value. Subsequent calls to `smtp_read_command()` invoke `receive_getc()` which still points to `bdat_getc()`. Since `bdat_getc()` itself calls `smtp_read_command()`, this creates infinite mutual recursion that exhausts the stack.
- **Trigger**: Connect to an Exim SMTP server. Send `EHLO x`, `MAIL FROM:<a@b>`, then `BDAT <size>` where `<size>` exceeds `message_size_limit` (default 50MB). After the error, send another `BDAT` command. The recursive `bdat_getc() -> smtp_read_command() -> receive_getc() -> bdat_getc()` cycle exhausts the stack, crashing the process.
- **PoC**: No public PoC (technical details in Qualys advisory and Exim advisory)
- **Metasploit**: N/A
- **Advisory**: [Qualys 21Nails](https://www.qualys.com/2021/05/04/21nails/21nails.txt) | [Exim CVE-2020-28019-BDATA.txt](https://www.exim.org/static/doc/security/CVE-2020-qualys/CVE-2020-28019-BDATA.txt)
- **Analysis**: This is a state machine bug where error handling in the BDAT code path fails to restore function pointers, creating a re-entrancy hazard. A stateful fuzzer exercising the BDAT command with oversized payloads followed by additional SMTP commands would trigger the recursive crash. Mutation strategy: send BDAT commands with sizes near and above `message_size_limit`, then immediately follow with more BDAT or other SMTP commands. The BDAT code path is relatively uncommon and underexercised in most MTA testing, making it a high-value fuzzing target.

---

### CVE-2023-42115
- **Product**: Exim < 4.96.1
- **Type**: Out-of-Bounds Write
- **CVSS**: 9.8 (NVD)
- **Server-side**: Yes -- Exim SMTP service writes past the end of the `auth_vars[]` buffer when processing AUTH commands with the External authentication scheme
- **Root cause**: When the External authentication mechanism is configured, Exim processes user-supplied AUTH data without properly validating its length or the resulting index calculations. The code writes two pointers beyond the bounds of the `auth_vars` array, corrupting adjacent memory. The flaw is classified as CWE-787 (Out-of-bounds Write). The specific issue is that user-supplied data in the AUTH exchange is used to index into `auth_vars[]` without bounds checking.
- **Trigger**: Connect to an Exim SMTP server configured with External (or SPA/NTLM) authentication. Send an `AUTH EXTERNAL` command followed by crafted authentication data that causes writes past the end of the `auth_vars[]` buffer. The server must have `authenticators` configured with the `external` driver.
- **PoC**: [github.com/kirinse/cve-2023-42115](https://github.com/kirinse/cve-2023-42115) (reverse shell exploit script)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-42115) | [ZDI-CAN-17434](https://www.zerodayinitiative.com/advisories/ZDI-23-1468/) | [Arctic Wolf](https://arcticwolf.com/resources/blog/cve-2023-42115/)
- **Analysis**: The OOB write is triggered by malformed AUTH data that causes an out-of-bounds index into a fixed-size array. A fuzzer sending oversized or specially structured AUTH command payloads would trigger this. The pre-auth attack surface makes this particularly dangerous for internet-facing mail servers. Mutation strategy: fuzz AUTH command parameters with varied lengths and structures, focusing on the External auth mechanism. Vary the number of fields, inject oversized tokens, and test boundary conditions in the auth data parsing.

---

### CVE-2023-42116
- **Product**: Exim < 4.96.1
- **Type**: Stack-based Buffer Overflow
- **CVSS**: 8.1 (ZDI) / 9.8 (NIST)
- **Server-side**: Yes -- Exim SMTP server overflows a fixed-size stack buffer when processing NTLM challenge responses during SPA/NTLM authentication
- **Root cause**: During NTLM authentication (SPA), Exim's NTLM challenge-response handling copies user-supplied data into a fixed-length stack buffer without validating that the data length does not exceed the buffer's allocated size. The attacker-controlled NTLM response data overflows the stack buffer, overwriting the saved return address and other stack frames. This is a classic CWE-121 (Stack-based Buffer Overflow).
- **Trigger**: Connect to an Exim SMTP server with SPA/NTLM authentication enabled. Initiate `AUTH NTLM` or `AUTH SPA`. Send a crafted NTLM Type 3 (authenticate) message with oversized fields (e.g., an oversized LmChallengeResponse or NtChallengeResponse blob) that exceeds the stack buffer size. The overflow corrupts the return address on the stack.
- **PoC**: No public PoC (disclosed via ZDI-CAN-17515 / ZDI-23-1470)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/cve-2023-42116) | [ZDI-23-1470](https://www.zerodayinitiative.com/advisories/ZDI-23-1470/) | [Red Hat Bugzilla](https://bugzilla.redhat.com/show_bug.cgi?id=2241528)
- **Analysis**: Straightforward stack smash from unchecked length in NTLM authentication parsing. A fuzzer targeting AUTH SPA/NTLM flows with oversized NTLM message fields would trigger this immediately. The NTLM Type 3 message contains multiple variable-length fields (domain, username, LM response, NT response, session key) -- any of these with an oversized length field paired with a large payload blob will overflow the stack buffer. Mutation strategy: fuzz NTLM Type 1/2/3 message structures within AUTH SPA commands, focusing on length fields that control memcpy sizes into stack buffers. Disable NTLM authentication if not required to eliminate this attack surface entirely.

---

### CVE-2023-42118
- **Product**: Exim with libspf2
- **Type**: Integer Underflow
- **CVSS**: 8.8 (NVD NIST) / 7.5 (ZDI)
- **Server-side**: Yes -- Exim evaluates SPF records for incoming mail, and libspf2 parses SPF macro strings with an integer underflow before a memory write
- **Root cause**: In the libspf2 library used by Exim for SPF record evaluation, the SPF macro parsing code does not properly validate user-supplied data, resulting in an integer underflow (CWE-191) before writing to memory. The underflow occurs when processing SPF TXT record macros (e.g., `%{s}`, `%{l}`, `%{o}` expansions). The underflowed size value is then used as a length parameter for a memory write operation, leading to corruption.
- **Trigger**: An attacker sends an email from a domain whose DNS SPF TXT record contains a crafted macro string that triggers the integer underflow in libspf2's macro expansion code. The Exim server performs SPF validation on the incoming mail, fetches the attacker-controlled SPF record via DNS, and the libspf2 parser underflows during macro expansion. The attack requires network adjacency or control of a DNS zone.
- **PoC**: No public PoC (disclosed via ZDI-CAN-17578 / ZDI-23-1472)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/cve-2023-42118) | [ZDI-23-1472](https://www.zerodayinitiative.com/advisories/ZDI-23-1472/) | [libspf2 issue #45](https://github.com/shevek/libspf2/issues/45)
- **Analysis**: This is an indirect parsing bug -- the malformed input is not the SMTP bytes themselves but the SPF DNS record that Exim fetches and parses during mail reception. The integer underflow in macro expansion is a classic size calculation error. A fuzzer would need to target the libspf2 library directly with crafted SPF record strings containing edge-case macro sequences. Mutation strategy: fuzz SPF TXT record macro strings (`%{s}`, `%{l}`, `%{o}`, `%{d}`, `%{i}`, `%{p}`, `%{h}`, `%{v}`) with varied lengths, nested expansions, and boundary values that could cause integer underflow in length calculations.

---

## Exploit PoCs and References

| CVE ID | PoC / Exploit | Link |
|--------|---------------|------|
| CVE-2018-6789 | Synacktiv Exim base64d RCE exploit materials | [github.com/synacktiv/Exim-CVE-2018-6789](https://github.com/synacktiv/Exim-CVE-2018-6789) |
| CVE-2018-6789 | c0llision Exim vulnerability PoC | [github.com/c0llision/exim-vuln-poc](https://github.com/c0llision/exim-vuln-poc) |
| CVE-2018-6789 | Learning environment for Exim base64d RCE | [github.com/martinclauss/exim-rce-cve-2018-6789](https://github.com/martinclauss/exim-rce-cve-2018-6789) |
| CVE-2018-6789 | ExploitDB entry with exploit code | [EDB-44571](https://www.exploit-db.com/exploits/44571) |
| CVE-2019-15846 | Synacktiv spool file generator and exploitation materials | [github.com/synacktiv/Exim-CVE-2019-15846](https://github.com/synacktiv/Exim-CVE-2019-15846) |
| CVE-2019-15846 | Nmap detection script | [github.com/d3k4z/nmap-cve2019-15846](https://github.com/d3k4z/nmap-cve2019-15846) |
| CVE-2020-28018 | lockedbyte C exploit for Exim 4.93 UAF | [github.com/lockedbyte/CVE-Exploits/tree/master/CVE-2020-28018](https://github.com/lockedbyte/CVE-Exploits/tree/master/CVE-2020-28018) |
| CVE-2020-28018 | Detailed analysis and PoC development walkthrough | [adepts.of0x.cc/exim-cve-2020-28018](https://adepts.of0x.cc/exim-cve-2020-28018/) |
| CVE-2020-28018 | dorkerdevil exploit and detection tools | [github.com/dorkerdevil/CVE-2020-28018](https://github.com/dorkerdevil/CVE-2020-28018) |
| CVE-2020-28018 | zr0tt Exim4 4.93 exploit | [github.com/zr0tt/CVE-2020-28018](https://github.com/zr0tt/CVE-2020-28018) |
| CVE-2023-42115 | Reverse shell exploit script for Exim AUTH OOB write | [github.com/kirinse/cve-2023-42115](https://github.com/kirinse/cve-2023-42115) |
| CVE-2023-51764 | Postfix SMTP smuggling PoC (Expect script) | [github.com/duy-31/CVE-2023-51764](https://github.com/duy-31/CVE-2023-51764) |
| 21Nails (all) | Full Qualys advisory covering 21 Exim vulnerabilities with technical analysis | [Qualys 21Nails](https://www.qualys.com/2021/05/04/21nails/21nails.txt) |
| SMTP Smuggling | Research site covering SMTP smuggling across multiple MTAs | [smtpsmuggling.com](https://smtpsmuggling.com/) |

## Key Vulnerability Patterns for Fuzzing

1. **Base64 Decoding (AUTH)**: Off-by-one from incorrect buffer size calculation when input length is `4n+3` (CVE-2018-6789). Fuzz all AUTH mechanisms with varied-length base64 payloads.
2. **TLS SNI Parsing**: Backslash escape sequences in SNI fields cause heap overflow in `string_unprinting()` (CVE-2019-15846). Fuzz TLS ClientHello SNI with escape characters and null bytes.
3. **Header Continuation Lines**: Integer overflow when doubling `header_size` for massive continuation-line headers (CVE-2020-28020). Send DATA with gigabyte-scale headers of `\n<space>` sequences.
4. **BDAT/Chunked Transfer**: Function pointer not reset after BDAT error leads to recursive stack exhaustion (CVE-2020-28019). Fuzz BDAT with oversized payloads and varied command sequences after errors.
5. **TLS State Machine (UAF)**: Stale pointer in `tls_write()` after `smtp_reset()` frees buffered data (CVE-2020-28018). Fuzz SMTP command sequences after STARTTLS with focus on state transitions.
6. **AUTH Mechanism Parsing**: OOB write in External auth (CVE-2023-42115), stack overflow in NTLM challenge (CVE-2023-42116). Fuzz AUTH with oversized payloads targeting each mechanism.
7. **SPF Macro Expansion**: Integer underflow in libspf2 macro parsing (CVE-2023-42118). Fuzz SPF TXT record strings with edge-case macro sequences.
8. **Pipelining**: Commands sent before reply to previous command can trigger state confusion.
9. **Line Ending Confusion**: CR vs LF vs CRLF handling differences between MTAs (SMTP smuggling).
