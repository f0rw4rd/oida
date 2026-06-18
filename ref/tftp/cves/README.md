# TFTP - Notable CVEs

## Summary Table

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2008-1611 | TFTP Server SP 1.4 (Windows) | Stack-based overflow via long filename in RRQ/WRQ | Stack Overflow / RCE | 10.0 (v2) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2008-1611) |
| CVE-2008-2161 | Open TFTP Server SP 1.4/1.5 | Buffer overflow via long TFTP error packet (sprintf) | Buffer Overflow / RCE | 10.0 (v2) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2008-2161) |
| CVE-2019-12568 | Open TFTP Server SP 1.66 | Stack overflow in logMess() via long TFTP error packet | Stack Overflow / RCE | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-12568) |
| CVE-2018-10387 | Open TFTP Server SP 1.66 | Heap overflow via long TFTP error packet | Heap Overflow / RCE | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-10387) |
| CVE-2019-5482 | curl/libcurl 7.19.4-7.65.3 | Heap overflow in tftp_receive_packet() from OACK without BLKSIZE | Heap Overflow / RCE | 9.8 | [curl Advisory](https://curl.se/docs/CVE-2019-5482.html) |
| CVE-2006-6184 | Allied Telesyn AT-TFTP 1.9 | Stack overflow via long filename in GET/PUT | Stack Overflow / RCE | 10.0 (v2) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2006-6184) |
| CVE-2002-2226 | TFTPD32 <= 2.21 | Stack overflow via long filename in RRQ | Stack Overflow / RCE | 7.5 (v2) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2002-2226) |
| CVE-2009-2957 | dnsmasq < 2.50 (TFTP) | Heap overflow in tftp_request() via long filename + prefix | Heap Overflow / RCE | 6.8 (v2) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2009-2957) |
| CVE-2011-2199 | tftpd-hpa < 5.1 | Buffer overflow via utimeout option value | Buffer Overflow / RCE | 7.5 (v2) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2011-2199) |
| CVE-2021-31885 | Siemens Nucleus NET TFTP (NUCLEUS:13) | OOB read in TFTP server via malformed commands | OOB Read / Info Leak | 7.5 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-21-313-03) |
| CVE-2021-41054 | atftp <= 0.7.4 | Buffer overflow from OACK + data buffer-size miscalculation | Buffer Overflow / DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-41054) |
| CVE-2002-0813 | Cisco IOS 11.1/11.2/11.3 TFTP | Heap overflow via long filename in TFTP request | Heap Overflow / DoS | 7.1 (v2) | [Cisco Advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20020730-ioc-tftp-lfn) |

### Entries Removed from Previous Version (failed fuzzer test)

The following CVEs were previously listed but have been removed because they either do not
exist as TFTP vulnerabilities or fail the server-side parsing bug filter:

- **CVE-2021-3939**: Actually affects Ubuntu accountsservice (double-free in D-Bus handler), not tftpd-hpa.
- **CVE-2020-29368**: NVD shows this as a Linux kernel mm/khugepaged.c race condition, not Nucleus RTOS TFTP.
- **CVE-2021-37620**: Actually affects Exiv2 image metadata library (OOB read), not Nucleus RTOS TFTP.
- **CVE-2015-0470**: Actually affects Oracle Java SE 8 Hotspot, not Cisco IP Phones TFTP.
- **CVE-2021-31884**: Affects Siemens Nucleus DHCP client (hostname parsing), not the TFTP component.
- **CVE-2018-10548**: Affects PHP ext/ldap (NULL deref), not PXE TFTP clients.
- **CVE-2019-12253**: SolarWinds TFTP path traversal -- logic flaw (directory escape), not a parsing/memory corruption bug. Would not be found by a byte-level fuzzer.

## Exploit PoCs and References

| CVE ID | PoC / Exploit | Link |
|--------|---------------|------|
| CVE-2008-1611 | TFTP Server 1.4 RRQ stack overflow -- full exploit with shellcode | [Exploit-DB #18345](https://www.exploit-db.com/exploits/18345) |
| CVE-2008-1611 | TFTP Server 1.4 WRQ stack overflow -- Egghunter technique | [Exploit-DB #40138](https://www.exploit-db.com/exploits/40138) |
| CVE-2008-1611 | TFTP Server 1.4 WRQ overflow -- Metasploit module | [Exploit-DB #18759](https://www.exploit-db.com/exploits/18759) |
| CVE-2008-1611 | SEH overwrite exploit (Python) | [GitHub Gist - mgeeky](https://gist.github.com/mgeeky/a18249e449b4445b87003cea8af48173) |
| CVE-2008-2161 | Open TFTP Server SP 1.4 error packet overflow -- Metasploit | [Rapid7](https://www.rapid7.com/db/modules/exploit/windows/tftp/opentftp_error_code/) |
| CVE-2006-6184 | AT-TFTP 1.9 long filename overflow exploit (Python) | [GitHub - shauntdergrigorian](https://github.com/shauntdergrigorian/cve-2006-6184) |
| CVE-2006-6184 | AT-TFTP 1.9 long filename overflow -- simplified | [GitHub - b03902043](https://github.com/b03902043/CVE-2006-6184) |
| CVE-2002-2226 | TFTPD32 long filename overflow -- Metasploit | [Exploit-DB #16349](https://www.exploit-db.com/exploits/16349) |
| CVE-2009-2957 | dnsmasq < 2.50 heap overflow + NULL deref PoC | [Exploit-DB #9617](https://www.exploit-db.com/exploits/9617) |
| N/A | Pinkie 2.15 TFTP remote buffer overflow PoC (32KB RRQ filename) | [Exploit-DB #50535](https://www.exploit-db.com/exploits/50535) |
| N/A | CheckPoint PXE Dust -- Sulley-based TFTP fuzzer | [GitHub - CheckPointSW](https://github.com/CheckPointSW/Cyber-Research/blob/master/Vulnerability/PXE_Dust/tftp-sulley-fuzzer.py) |
| NUCLEUS:13 | Forescout research on Siemens Nucleus RTOS TCP/IP stack | [Forescout Blog](https://www.forescout.com/blog/new-critical-vulnerabilities-found-on-nucleus-tcp-ip-stack/) |

---

## Detailed CVE Writeups

### CVE-2008-1611
- **Product**: TFTP Server SP 1.4 for Windows
- **Type**: Stack-based Buffer Overflow / RCE
- **CVSS**: 10.0 (v2: AV:N/AC:L/Au:N/C:C/I:C/A:C)
- **Server-side**: Yes -- the TFTP server copies the filename from incoming RRQ/WRQ packets into a fixed-size stack buffer without bounds checking
- **Root cause**: The server appends the user-supplied filename from a RRQ or WRQ packet to the TFTP server binary's installation path on the stack. No length check is performed before the concatenation. When the combined path exceeds the stack buffer, the return address and SEH handler are overwritten. The corrupted path is then passed to fopen(), which returns NULL, and the NULL pointer flows into strcmp(), triggering the overwrite at a controlled location.
- **Trigger**: Send a TFTP RRQ (opcode 0x0001) or WRQ (opcode 0x0002) packet with a filename field containing approximately 476+ bytes of attacker-controlled data, followed by a null byte and "netascii" mode string. The filename overwrites the stack frame including the saved return address.
- **PoC**: [Exploit-DB #18345 (RRQ)](https://www.exploit-db.com/exploits/18345), [Exploit-DB #40138 (WRQ, Egghunter)](https://www.exploit-db.com/exploits/40138), [GitHub Gist - mgeeky SEH overwrite](https://gist.github.com/mgeeky/a18249e449b4445b87003cea8af48173)
- **Metasploit**: `exploit/windows/tftp/tftpserver_wrq_bof`
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2008-1611)
- **Analysis**: Classic stack buffer overflow in filename handling. A fuzzer mutating the filename field in RRQ/WRQ packets with incrementally longer strings will trigger this immediately. The protocol's null-terminated filename field with no length limit is the root issue. Mutation strategy: length expansion on the filename field from 1 byte to 64KB. The mandatory trailing null byte in TFTP filenames is actually useful for the attacker as it provides a reliable null-terminated write primitive. When run as a Windows service, code execution happens at SYSTEM privilege level.

### CVE-2008-2161
- **Product**: Open TFTP Server SP 1.4 and 1.5 for Windows
- **Type**: Buffer Overflow / RCE (sprintf-based)
- **CVSS**: 10.0 (v2: AV:N/AC:L/Au:N/C:C/I:C/A:C)
- **Server-side**: Yes -- the TFTP server uses sprintf() to format error packet messages into a fixed-size buffer without checking the length of the error message string
- **Root cause**: When the TFTP server receives a packet with the opcode field set to ERROR (opcode 5), it extracts the error message string and passes it to sprintf() for logging. The sprintf() call writes into a stack or heap buffer without bounds checking. A long error message string overflows this buffer, corrupting adjacent memory and allowing control of execution flow.
- **Trigger**: Send a TFTP ERROR packet (opcode 0x0005) with error code field followed by an error message string exceeding approximately 500 bytes. The server processes the error packet and the sprintf() in the error handling path overflows.
- **PoC**: [Exploit-DB #5563](https://www.exploit-db.com/exploits/5563)
- **Metasploit**: `exploit/windows/tftp/opentftp_error_code`
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2008-2161)
- **Analysis**: This is a less commonly fuzzed attack surface -- the ERROR packet (opcode 5) is typically sent from server to client, but nothing prevents a client from sending it to the server, and the server still parses it. The sprintf() without bounds checking is the classic vulnerable pattern. Fuzzing strategy: mutate the error message field in ERROR packets with long strings and format string specifiers. Also note the related CVE-2019-12568 and CVE-2018-10387 which target the same product's logMess function in version 1.66, showing the vendor never fully fixed the pattern.

### CVE-2019-5482
- **Product**: curl/libcurl 7.19.4 through 7.65.3
- **Type**: Heap Buffer Overflow
- **CVSS**: 9.8 (v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Server-side**: No -- this is a client-side bug in curl's TFTP handler. However, it is triggered by a malicious TFTP server sending a crafted OACK response to the client. Included because it demonstrates a critical TFTP parsing flaw triggered by malformed bytes on the wire, and many embedded devices use libcurl as a TFTP client for firmware updates.
- **Root cause**: In the function `tftp_receive_packet()`, when a TFTP client requests a BLKSIZE smaller than 512 bytes and the server responds with an OACK that omits the BLKSIZE option, libcurl allocates a receive buffer sized for the requested (smaller) block size but then calls `recvfrom()` with the default 512-byte size as the length parameter. The server's subsequent DATA packets (up to 512 bytes) overflow the undersized heap buffer.
- **Trigger**: (1) Client sends RRQ with option "blksize" set to a value less than 512 (e.g., "blksize\0128\0"). (2) Server responds with OACK that does NOT include the blksize option. (3) Server then sends DATA packets with 512-byte blocks. The recvfrom() call writes 512 bytes into a buffer allocated for only 128 bytes.
- **PoC**: No public PoC. The fix commit is [curl/curl@facb0e4](https://github.com/curl/curl/commit/facb0e4662415b5f28163e853dc6742ac5fafb3d).
- **Metasploit**: N/A
- **Advisory**: [curl Advisory](https://curl.se/docs/CVE-2019-5482.html), [HackerOne #684603](https://hackerone.com/reports/684603)
- **Analysis**: This vulnerability illustrates a subtle state machine parsing flaw: the client assumes that if it requested a smaller BLKSIZE and got an OACK back, the OACK confirms the smaller size. But if the OACK omits BLKSIZE, the server uses the default 512 bytes while the client allocated for the smaller size. Fuzzing strategy for TFTP servers that also test client behavior: send OACK responses that selectively omit requested options, then follow with DATA packets using the default block size. The mismatch between allocated and used buffer sizes is a classic heap overflow pattern. Discovered by Thomas Vegas.

### CVE-2006-6184
- **Product**: Allied Telesyn AT-TFTP Server 1.9 (Windows)
- **Type**: Stack-based Buffer Overflow / RCE
- **CVSS**: 10.0 (v2: AV:N/AC:L/Au:N/C:C/I:C/A:C)
- **Server-side**: Yes -- the TFTP server copies the filename from GET/PUT (RRQ/WRQ) requests into a fixed-size stack buffer without length validation
- **Root cause**: The AT-TFTP server reads the null-terminated filename string from incoming RRQ or WRQ packets and copies it into a stack-allocated buffer without checking if the filename length exceeds the buffer size. A filename longer than the buffer (approximately 227 bytes to reach EIP) overwrites the saved return address on the stack, giving the attacker control of the instruction pointer.
- **Trigger**: Send a TFTP RRQ (opcode 0x0001) or WRQ (opcode 0x0002) packet containing a filename field of approximately 230+ bytes followed by null byte and mode string "netascii\0". The filename content overwrites the stack return address.
- **PoC**: [GitHub - shauntdergrigorian/cve-2006-6184](https://github.com/shauntdergrigorian/cve-2006-6184), [GitHub - b03902043/CVE-2006-6184](https://github.com/b03902043/CVE-2006-6184), [GitHub - brianwrf/cve-2006-6184](https://github.com/brianwrf/cve-2006-6184)
- **Metasploit**: `exploit/windows/tftp/attftp_long_filename`
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2006-6184), [IBM X-Force #30539](https://exchange.xforce.ibmcloud.com/vulnerabilities/30539)
- **Analysis**: Nearly identical root cause to CVE-2008-1611 and CVE-2002-2226 -- fixed-size stack buffer for a protocol field with no inherent length limit. The TFTP protocol defines filenames as null-terminated strings with no maximum length, making every implementation that uses a fixed buffer for filename storage vulnerable to this class of bug. Mutation strategy: simple length expansion of the filename field in RRQ/WRQ packets. Multiple independent PoC implementations exist on GitHub, making this a well-understood exploitation primitive. EPSS score of 80.58% indicates high exploitation probability.

### CVE-2009-2957
- **Product**: dnsmasq < 2.50 (TFTP server component, when --enable-tftp is used)
- **Type**: Heap Buffer Overflow / RCE
- **CVSS**: 6.8 (v2: AV:N/AC:M/Au:N/C:P/I:P/A:P)
- **Server-side**: Yes -- the dnsmasq TFTP server concatenates a configured directory prefix and the client-supplied filename into a heap buffer without checking the combined length
- **Root cause**: In the `tftp_request()` function in `tftp.c`, dnsmasq first calls `strncat(daemon->namebuff, daemon->tftp_prefix, MAXDNAME)` to copy the configured TFTP root directory prefix into a heap-allocated buffer of MAXDNAME bytes (default 1025). It then calls `strncat(daemon->namebuff, filename, MAXDNAME)` to append the client-supplied filename. The third argument to `strncat` is the maximum number of characters to copy, NOT the remaining space in the buffer. If the prefix is long (e.g., 900 bytes) and the filename is also long (e.g., 200 bytes), the combined write exceeds the 1025-byte buffer, causing a heap overflow.
- **Trigger**: Configure dnsmasq with a TFTP prefix of approximately 800-900 bytes (e.g., `--tftp-root=/very/long/path/...`). Then send a TFTP RRQ (opcode 0x0001) with a filename of 200+ bytes. The strncat of prefix + filename exceeds MAXDNAME (1025) bytes and corrupts adjacent heap metadata.
- **PoC**: [Exploit-DB #9617](https://www.exploit-db.com/exploits/9617) (Core Security Technologies)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2009-2957), [CoreSec Advisory](https://www.coresecurity.com/core-labs/advisories/dnsmasq-vulnerabilities)
- **Analysis**: This is a subtle vulnerability because the buffer size (MAXDNAME = 1025) seems generous for a filename, but the bug depends on server configuration (prefix length). The misuse of strncat's length parameter is a well-known C programming error -- the third argument limits bytes to append, not total buffer size. Discovered by Pablo Jorge and Alberto Solino during Bugweek 2009 at Core Security. Fuzzing strategy: long filenames in RRQ packets. The exploitability depends on the target's tftp_prefix configuration, so the same input may crash one deployment but not another. Affects dnsmasq on Linux home routers, embedded devices, and DNS/DHCP appliances. The related CVE-2009-2958 is a NULL pointer dereference in the same function when the filename is empty.

### CVE-2011-2199
- **Product**: tftpd-hpa < 5.1
- **Type**: Buffer Overflow / RCE
- **CVSS**: 7.5 (v2: AV:N/AC:L/Au:N/C:P/I:P/A:P)
- **Server-side**: Yes -- the TFTP server fails to validate the length of the "utimeout" option value before writing it into a fixed-size buffer
- **Root cause**: When processing TFTP option extensions (RFC 2347), tftpd-hpa reads the null-terminated "utimeout" option value string from the RRQ/WRQ packet and writes it into a buffer without adequate bounds checking. A long utimeout value overflows the destination buffer, corrupting stack or heap memory. Note: the original table listed this as a "format string" vulnerability, but NVD (CWE-119) and all references classify it as a buffer overflow.
- **Trigger**: Send a TFTP RRQ (opcode 0x0001) with RFC 2347 option extensions including the option name "utimeout\0" followed by a value string exceeding the expected buffer size (e.g., 500+ bytes of 'A' characters followed by null byte). The packet format is: `\x00\x01filename\0netascii\0utimeout\0AAAAAA...AAA\0`.
- **PoC**: No public exploit PoC found. Patch available in tftpd-hpa git repository at kernel.org.
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2011-2199), [Red Hat Bugzilla](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2011-2199), [Gentoo GLSA 201206-12](https://security.gentoo.org/glsa/201206-12)
- **Analysis**: tftpd-hpa is one of the most widely deployed TFTP servers on Linux systems (default in many distributions). This vulnerability is in the option extension parsing code, which is a rich attack surface because RFC 2347 allows arbitrary option name/value pairs as null-terminated strings with no length limits. Fuzzing strategy: mutate the option value fields in RRQ/WRQ packets. Specifically test "blksize", "tsize", "timeout", and "utimeout" with values of varying lengths (1 byte to 64KB). Also test with malformed option names, missing null terminators between option name/value pairs, and extremely large numbers of option pairs.

### CVE-2021-31885
- **Product**: Siemens Nucleus NET (Nucleus RTOS TCP/IP stack) -- TFTP server component
- **Type**: Out-of-Bounds Read / Information Leak
- **CVSS**: 7.5 (v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
- **Server-side**: Yes -- the Nucleus RTOS TFTP server reads beyond buffer boundaries when processing malformed TFTP commands, leaking memory contents to the attacker
- **Root cause**: The TFTP server application uses an incorrect length value (CWE-805: Buffer Access with Incorrect Length Value) when processing incoming TFTP commands. Malformed commands cause the server to read beyond the TFTP memory buffer boundaries, and the out-of-bounds data is returned to the requesting client. This allows an unauthenticated remote attacker to read arbitrary memory contents from the TFTP server process.
- **Trigger**: Send malformed TFTP commands (specific malformed field details not publicly disclosed by Forescout/Siemens) that cause the server to miscalculate buffer boundaries. The server reads past the end of the TFTP command buffer and includes the OOB data in its response, leaking heap/stack contents.
- **PoC**: No public PoC. Technical details published in Forescout NUCLEUS:13 research report.
- **Metasploit**: N/A
- **Advisory**: [CISA ICS-CERT ICSA-21-313-03](https://www.cisa.gov/news-events/ics-advisories/icsa-21-313-03), [Siemens SSA-044112](https://cert-portal.siemens.com/productcert/html/ssa-044112.html), [Forescout NUCLEUS:13](https://www.forescout.com/research-labs/nucleus-13/)
- **Analysis**: This affects the Nucleus RTOS TCP/IP stack which is deployed in 3+ billion devices across healthcare, automotive, and critical infrastructure. The TFTP server runs on embedded devices that typically lack ASLR and stack canaries, making even information leaks extremely dangerous (leaked memory may contain keys, credentials, or heap layout useful for chaining with other NUCLEUS:13 bugs like the FTP stack overflow CVE-2021-31886). Fuzzing strategy: send truncated TFTP commands with fields shorter than expected, commands with incorrect field boundaries, and packets that exercise edge cases in length parsing. The Forescout team discovered this through manual code review and targeted fuzzing of the Nucleus NET stack.

### CVE-2021-41054
- **Product**: atftp <= 0.7.4
- **Type**: Buffer Overflow / DoS
- **CVSS**: 7.5 (v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Server-side**: Yes -- the atftp server miscalculates buffer sizes when handling combinations of OACK, data, and option fields
- **Root cause**: In `tftpd_file.c`, the buffer-size handling logic does not properly account for the combined size of data, OACK response fields, and other option values when computing how much data to copy (CWE-120: Buffer Copy without Checking Size of Input). When a client sends a request with specific option combinations, the server constructs a response that overflows the allocated buffer.
- **Trigger**: Send a TFTP RRQ with a combination of option extensions (blksize, tsize, etc.) where the total option response size, combined with data content, exceeds the server's internal buffer allocation. The specific trigger involves the interaction between OACK construction and data buffering.
- **PoC**: No public PoC.
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-41054), [Debian DLA-2820-1](https://lists.debian.org/debian-lts-announce/2021/11/msg00014.html)
- **Analysis**: atftp is widely deployed on Linux as an alternative to tftpd-hpa, commonly used for PXE booting and firmware updates. This vulnerability is in the option negotiation response path -- the server allocates a buffer for the response but does not account for all the option fields that will be written into it. Fuzzing strategy: send RRQ packets with large numbers of option extensions, options with very long values, and unusual combinations of options that stress the buffer allocation logic. The OACK response construction is a particularly important fuzz target because it involves variable-length output assembled from multiple input fields.

### CVE-2019-12568
- **Product**: Open TFTP Server SP 1.66 and earlier
- **Type**: Stack-based Buffer Overflow / RCE
- **CVSS**: 9.8 (v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Server-side**: Yes -- the TFTP server's logMess() function copies a TFTP error message into a stack buffer using an unbounded string operation
- **Root cause**: The `logMess()` logging function in Open TFTP Server receives the error message string from incoming TFTP ERROR packets and copies it into a fixed-size stack buffer without length validation (CWE-787: Out-of-bounds Write). This is the same fundamental pattern as CVE-2008-2161 (sprintf in error handling) but in the logging function of a later version, showing the vendor did not comprehensively audit all string handling paths after the original vulnerability.
- **Trigger**: Send a TFTP ERROR packet (opcode 0x0005, error code 0x0000) with an error message string exceeding approximately 500 bytes followed by a null terminator. The packet structure is: `\x00\x05\x00\x00AAAA...AAA\x00`.
- **PoC**: No public standalone PoC, but the vulnerability is a straightforward adaptation of the CVE-2008-2161 exploit technique (same product family, same packet type, different internal function).
- **Metasploit**: N/A (the related CVE-2008-2161 has `exploit/windows/tftp/opentftp_error_code`)
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-12568)
- **Analysis**: This is a textbook example of an incomplete fix. The original CVE-2008-2161 was in the sprintf() error formatting path, patched in 1.4/1.5. But the logMess() function in version 1.66 has the same unbounded copy pattern on the same ERROR packet input. A fuzzer targeting ERROR packets with long message strings would rediscover both bugs. Mutation strategy: mutate the error message field in TFTP ERROR packets. Also fuzz the error code field (2-byte value before the message) with invalid codes to test error-handling error-handling paths.

---

## Key Vulnerability Patterns for Fuzzing

1. **Filename Buffer Overflow**: The most exploited TFTP vulnerability class. The protocol specifies filenames as null-terminated strings with no maximum length (CVE-2008-1611, CVE-2006-6184, CVE-2002-2226, CVE-2009-2957, CVE-2002-0813). Every TFTP server that copies the filename into a fixed-size buffer is vulnerable. Mutation: length expansion from 1 byte to 64KB.

2. **Error Packet Message Overflow**: TFTP ERROR packets (opcode 5) contain a null-terminated error message with no length limit. Servers that log or format this message through sprintf/strcpy are vulnerable (CVE-2008-2161, CVE-2019-12568, CVE-2018-10387). Mutation: long error message strings.

3. **Option Extension Parsing**: RFC 2347 option extensions (blksize, tsize, timeout, utimeout) are null-terminated key-value pairs with no inherent length limits. Buffer overflows in option value handling are common (CVE-2011-2199, CVE-2021-41054). Mutation: long option values, many option pairs, malformed null-termination.

4. **OACK Response Handling**: Mismatch between requested options and OACK contents can cause buffer allocation errors (CVE-2019-5482). Mutation: OACK with missing, extra, or reordered option fields.

5. **Buffer Length Miscalculation**: Combined sizes of multiple variable-length fields (filename + prefix, data + options) exceed allocated buffer (CVE-2009-2957 prefix + filename, CVE-2021-41054 data + OACK + options). Mutation: maximize all variable-length fields simultaneously.

6. **Embedded RTOS TFTP Stacks**: RTOS implementations often lack modern mitigations (ASLR, stack canaries, NX) and have minimal input validation (CVE-2021-31885, CVE-2002-0813). Information leaks via OOB reads are especially dangerous on these targets because leaked memory may contain cryptographic keys or heap metadata useful for exploitation chaining.
