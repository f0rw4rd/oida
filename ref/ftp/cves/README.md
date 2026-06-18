# FTP - Notable CVEs

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2010-4221 | ProFTPD 1.3.2rc3 - 1.3.3b | Stack overflow in pr_netio_telnet_gets() via Telnet IAC escape sequences, pre-auth RCE | Stack Overflow / RCE | 10.0 (v2) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2010-4221) |
| CVE-2020-9273 | ProFTPD 1.3.5 - 1.3.7 | Use-after-free in memory pool allocation during data transfer interruption | UAF / RCE | 8.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-9273) |
| CVE-2006-5815 | ProFTPD <= 1.3.0 | Stack-based buffer overflow in sreplace() in src/support.c | Stack Overflow / RCE | 10.0 (v2) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2006-5815) |
| CVE-2011-0762 | vsftpd < 2.3.3 | Glob expression DoS in STAT command via vsf_filename_passes_filter() | DoS | 4.0 (v2) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2011-0762) |
| CVE-2011-1137 | ProFTPD <= 1.3.3d | Integer overflow in mod_sftp SSH message length parsing causes OOM kill | Integer Overflow / DoS | 5.0 (v2) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2011-1137) |
| CVE-2023-51713 | ProFTPD < 1.3.8a | One-byte out-of-bounds read in make_ftp_cmd (main.c) due to mishandling of quote/backslash semantics, causes daemon crash | OOB Read / DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-51713) |
| CVE-2021-31886 | Siemens Nucleus RTOS FTP Server | FTP server fails to validate length of USER command, stack-based buffer overflow leading to RCE | Stack Overflow / RCE | 9.8 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-21-313-03) |
| CVE-2021-31887 | Siemens Nucleus RTOS FTP Server | FTP server fails to validate length of PWD/XPWD command, stack-based buffer overflow leading to RCE | Stack Overflow / RCE | 8.8 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-21-313-03) |
| CVE-2021-46854 | ProFTPD < 1.3.7c | Memory disclosure in mod_radius due to copying password in 16-byte blocks without bounds check | Info Disclosure / OOB Read | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-46854) |
| CVE-2021-31885 | Siemens Nucleus RTOS TFTP Server | TFTP server doesn't properly validate length of the "PUT" command, enabling stack-based overflow | Stack Overflow | 7.5 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-21-313-03) |

## Exploit PoCs and References

| CVE ID | PoC / Exploit | Link |
|--------|---------------|------|
| CVE-2010-4221 | Metasploit module with ROP chain exploit (Debian/Ubuntu targets) | [ExploitDB 16851](https://www.exploit-db.com/exploits/16851) |
| CVE-2020-9273 | Full analysis and exploitation of use-after-free in ProFTPD pool allocator, with working exploit code | [github.com/ptef/CVE-2020-9273](https://github.com/ptef/CVE-2020-9273) |
| CVE-2020-9273 | Detailed writeup on heap UAF exploitation in ProFTPD | [adepts.of0x.cc](https://adepts.of0x.cc/proftpd-cve-2020-9273-exploit/) |
| CVE-2020-9273 | Phrack article on exploiting CVE-2020-9273 | [Phrack Issue 72](https://phrack.org/issues/72/8_md) |
| CVE-2006-5815 | Metasploit module for sreplace buffer overflow | [ExploitDB 16852](https://www.exploit-db.com/exploits/16852) |
| CVE-2011-0762 | vsftpd 2.3.2 DoS PoC script | [ExploitDB 16270](https://www.exploit-db.com/exploits/16270) |
| CVE-2011-1137 | ProFTPD mod_sftp integer overflow DoS PoC | [ExploitDB 16129](https://www.exploit-db.com/exploits/16129) |

---

## Detailed Writeups

### CVE-2010-4221
- **Product**: ProFTPD 1.3.2rc3 through 1.3.3b
- **Type**: Stack-Based Buffer Overflow (pre-auth RCE)
- **CVSS**: 10.0 (v2: AV:N/AC:L/Au:N/C:C/I:C/A:C); no v3 score assigned by NVD
- **Server-side**: Yes -- the server's FTP command reader in `pr_netio_telnet_gets()` (netio.c) processes inline Telnet IAC escape bytes embedded in the control channel stream
- **Root cause**: The function reads FTP commands from the control socket and strips Telnet IAC sequences. When an unrecognized IAC byte is encountered with `buflen == 1`, the code decrements `buflen` twice: once in the IAC handler's default case (`*bp++ = TELNET_IAC; buflen--;`) and once after the switch (`*bp++ = cp; buflen--;`). Because `buflen` is `size_t` (unsigned), this causes an integer underflow from 0 to `SIZE_MAX`, making the loop continue copying attacker-controlled bytes far beyond the stack buffer.
- **Trigger**: Send raw bytes to port 21 containing a large number of `\xff` (TELNET_IAC) bytes followed by non-IAC bytes. No authentication required. The payload is sent before any FTP command processing occurs, making this a pre-authentication attack.
- **PoC**: [ExploitDB 16851](https://www.exploit-db.com/exploits/16851) (Metasploit module by jduck)
- **Metasploit**: `exploit/linux/ftp/proftp_telnet_iac`
- **Advisory**: [NVD CVE-2010-4221](https://nvd.nist.gov/vuln/detail/CVE-2010-4221)
- **Analysis**: Classic unsigned integer underflow leading to unbounded stack write. A fuzzer that embeds Telnet IAC bytes (`\xff`) at various positions within FTP command input would trigger this. The key mutation strategy is inserting `\xff` bytes into the command stream, particularly at positions that cause the buffer-remaining counter to hit exactly 1 before the double-decrement path. Nmap includes an NSE detection script (`ftp-vuln-cve2010-4221`). The Metasploit exploit uses ROP to bypass ASLR/NX on Debian and Ubuntu targets.

### CVE-2020-9273
- **Product**: ProFTPD 1.3.5 through 1.3.7rc2
- **Type**: Use-After-Free / Remote Code Execution
- **CVSS**: 8.8 (v3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
- **Server-side**: Yes -- the server's pool allocator uses a freed memory block when handling a command on the control channel while a data transfer is active
- **Root cause**: When an FTP data transfer is active and a command is sent on the control channel (interrupting the transfer), the pool allocator in `alloc_pool()` (pool.c) follows a corrupted pool pointer. Specifically, `pcalloc` in `netio.c:1066` calls `alloc_pool()` which calls `new_block()` to obtain a freed memory block, but the pool pointer `p` has been corrupted by the data channel activity. The data channel allows binary data to overwrite the `resp_pool` structure (referenced via `session.curr_cmd_rec->pool`), corrupting critical pointers like `p->last`, `p->cleanups`, and `p->sub_pools`. When the allocator subsequently dereferences these pointers, it operates on attacker-controlled memory.
- **Trigger**: (1) Authenticate to FTP server; (2) Initiate a data transfer (e.g., STOR or RETR via PASV/PORT); (3) While the data channel is transferring, send a command (e.g., ABOR or any other command) on the control channel to interrupt the transfer; (4) The binary payload sent through the data channel corrupts the heap, and the control channel command triggers the use-after-free when the pool allocator processes the response. Requires authentication (low privilege).
- **PoC**: [github.com/ptef/CVE-2020-9273](https://github.com/ptef/CVE-2020-9273) (full exploit with RCE), [adepts.of0x.cc writeup](https://adepts.of0x.cc/proftpd-cve-2020-9273-exploit/), [Phrack Issue 72 Article 8](https://phrack.org/issues/72/8_md)
- **Metasploit**: N/A
- **Advisory**: [GitHub Issue #903](https://github.com/proftpd/proftpd/issues/903), [NVD CVE-2020-9273](https://nvd.nist.gov/vuln/detail/CVE-2020-9273)
- **Analysis**: This is a stateful bug requiring interleaved control/data channel activity. A stateful FTP fuzzer that opens data connections and then sends commands on the control channel during active transfers would find this. The key mutation strategy is varying the timing and content of control channel commands relative to data transfer state, and sending crafted binary data through the data channel to corrupt pool metadata. The exploit achieves full RCE bypassing ASLR, PIE, NX, Full RELRO, and stack canaries by manipulating pool allocator internals.

### CVE-2023-51713
- **Product**: ProFTPD before 1.3.8a (versions 1.2.0 through 1.3.8rc4)
- **Type**: Out-of-Bounds Read / Denial of Service
- **CVSS**: 7.5 (v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Server-side**: Yes -- the server's FTP command parser in `make_ftp_cmd()` reads one byte past the end of the input buffer when processing backslash/quote escape sequences
- **Root cause**: The `make_ftp_cmd()` function in `main.c` parses FTP commands and handles quote (`"`) and backslash (`\`) escape characters. When a backslash or quote appears at the very end of the command string (i.e., at the last byte before the null terminator), the parser advances past the end of the string to process the escaped character, causing a one-byte out-of-bounds read. Depending on what is in the adjacent memory, this causes a crash (segfault) of the daemon.
- **Trigger**: Send an FTP command where the last character before CRLF is a backslash (`\`) or unmatched quote (`"`). For example: `USER test\\\r\n` where the backslash is the final character of the argument. No authentication required -- this is a pre-auth crash.
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [NVD CVE-2023-51713](https://nvd.nist.gov/vuln/detail/CVE-2023-51713), [GitHub Advisory GHSA-6959-h9pv-vhf9](https://github.com/advisories/GHSA-6959-h9pv-vhf9), fix tracked in [proftpd/proftpd#1683](https://github.com/proftpd/proftpd/issues/1683)
- **Analysis**: A textbook example of off-by-one parsing in escape sequence handling. A fuzzer that appends special characters (backslash, quotes) at the end of FTP command strings would trigger this immediately. The mutation strategy is simple: place `\` or `"` as the terminal character of command arguments. This is pre-auth, so it can be found with zero-state fuzzing of the command parser. Despite being only a 1-byte OOB read, it reliably crashes the daemon.

### CVE-2021-31886
- **Product**: Siemens Nucleus NET (Nucleus RTOS TCP/IP Stack), affects Nucleus ReadyStart V3 < V2017.02.4, Nucleus Source Code, and numerous Siemens building automation products (APOGEE MBC/MEC/PXC, TALON TC, Capital VSTAR)
- **Type**: Stack-Based Buffer Overflow / Remote Code Execution
- **CVSS**: 9.8 (v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Server-side**: Yes -- the embedded FTP server copies the USER command argument into a fixed-size stack buffer without checking length
- **Root cause**: The Nucleus RTOS FTP server implementation does not validate the length of the `USER` command argument before copying it into a fixed-size stack buffer. When a username exceeding the buffer size is received, a classic stack-based buffer overflow occurs, overwriting the return address and enabling control-flow hijacking. The embedded RTOS environment typically lacks modern exploit mitigations (ASLR, stack canaries, NX), making exploitation straightforward.
- **Trigger**: Connect to the FTP service (typically port 21) and send `USER <string exceeding ~256 bytes>\r\n`. No prior authentication is required. The overflow occurs during the initial authentication exchange.
- **PoC**: Forescout published a demonstration video as part of NUCLEUS:13 research. No standalone public PoC script is available, but the trigger is trivially reproducible.
- **Metasploit**: N/A
- **Advisory**: [CISA ICS-CERT ICSA-21-313-03](https://www.cisa.gov/news-events/ics-advisories/icsa-21-313-03), [Siemens SSA-044112](https://cert-portal.siemens.com/productcert/html/ssa-044112.html), [Forescout NUCLEUS:13](https://www.forescout.com/research-labs/nucleus-13/)
- **Analysis**: This is the simplest possible FTP parsing bug: no length check on a string copy of the USER argument. Any fuzzer that sends oversized arguments to FTP commands would find this instantly. The Nucleus RTOS is used in over 3 billion embedded devices (healthcare, building automation, automotive), and Forescout identified 5,500 vulnerable devices across 127 customer networks. The lack of ASLR/NX in embedded RTOS environments makes the stack overflow directly exploitable for RCE. Mutation strategy: simple length extension of USER/PASS command arguments with incrementing sizes.

### CVE-2021-31887
- **Product**: Siemens Nucleus NET (Nucleus RTOS TCP/IP Stack), same product set as CVE-2021-31886
- **Type**: Stack-Based Buffer Overflow / Remote Code Execution
- **CVSS**: 8.8 (v3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
- **Server-side**: Yes -- the embedded FTP server copies the PWD/XPWD command response data into a fixed-size stack buffer without checking length
- **Root cause**: The Nucleus RTOS FTP server does not validate the length of the `PWD` or `XPWD` command argument before processing it, leading to a stack-based buffer overflow. The vulnerability is analogous to CVE-2021-31886 but affects a different FTP command handler. Unlike the USER command overflow, this one requires prior authentication (low privilege).
- **Trigger**: Authenticate to the FTP service, then send a `PWD` or `XPWD` command with a crafted argument that exceeds the internal buffer size. The overflow occurs during command processing.
- **PoC**: No standalone public PoC. Part of Forescout NUCLEUS:13 disclosure.
- **Metasploit**: N/A
- **Advisory**: [CISA ICS-CERT ICSA-21-313-03](https://www.cisa.gov/news-events/ics-advisories/icsa-21-313-03), [NVD CVE-2021-31887](https://nvd.nist.gov/vuln/detail/CVE-2021-31887)
- **Analysis**: Same root cause pattern as CVE-2021-31886 but in a different command handler, demonstrating that the Nucleus FTP implementation has systemic missing length validation across multiple commands. A fuzzer that iterates through all FTP commands with oversized arguments would find both bugs. The post-auth requirement limits the attack surface slightly, but default/weak credentials are common on embedded devices.

### CVE-2006-5815
- **Product**: ProFTPD 1.2.x through 1.3.0
- **Type**: Stack-Based Buffer Overflow / Remote Code Execution
- **CVSS**: 10.0 (v2: AV:N/AC:L/Au:N/C:C/I:C/A:C); no v3 score assigned by NVD
- **Server-side**: Yes -- the server's `sreplace()` function in `src/support.c` overflows a stack buffer when performing string replacements on `.message` file contents triggered by CWD
- **Root cause**: The `sreplace()` function performs in-place string replacement on user-controlled content (`.message` files displayed when a user enters a directory via CWD). The function allocates a fixed-size buffer on the stack but does not account for the case where replacement strings are longer than the original strings, leading to a stack buffer overflow. An attacker who can upload a `.message` file with crafted content can trigger the overflow when any user (including the attacker) CWDs into that directory.
- **Trigger**: (1) Upload a crafted `.message` file to a writable FTP directory, containing strings that expand during `sreplace()` processing (the file contains ProFTPD display variables like `%T`, `%F`, etc. that expand to longer strings); (2) Execute `CWD <directory>` to enter the directory containing the crafted file; (3) The server processes the `.message` file through `sreplace()`, triggering the stack overflow.
- **PoC**: [ExploitDB 16852](https://www.exploit-db.com/exploits/16852) (Metasploit module), [ExploitDB 2856](https://www.exploit-db.com/exploits/2856) (original Metasploit module)
- **Metasploit**: `exploit/linux/ftp/proftp_sreplace`
- **Advisory**: [NVD CVE-2006-5815](https://nvd.nist.gov/vuln/detail/CVE-2006-5815)
- **Analysis**: This is a second-order parsing bug: the malformed input is a file uploaded via the data channel, then parsed server-side when a CWD triggers `.message` display. A fuzzer targeting this would need to upload files with expansion variables and then CWD into the directory. The mutation strategy is crafting `.message` file contents with repeated `%`-variables that expand to long strings during replacement. This was discovered by Evgeny Legerov and was part of the VulnDisco Pack since December 2005.

### CVE-2011-1137
- **Product**: ProFTPD 1.3.3d and earlier (mod_sftp module)
- **Type**: Integer Overflow / Denial of Service (OOM Kill)
- **CVSS**: 5.0 (v2: AV:N/AC:L/Au:N/C:N/I:N/A:P); no v3 score assigned by NVD
- **Server-side**: Yes -- the mod_sftp module's SSH packet length parser accepts a malformed length value that causes an integer overflow in memory allocation
- **Root cause**: The `mod_sftp` module parses SSH message length fields from incoming packets. A crafted SSH message with an extremely large length field causes an integer overflow in the size calculation used for memory allocation. The resulting allocation size wraps around to a small value, but the server then attempts to read the declared (huge) amount of data, consuming all available memory until the OOM killer terminates the process.
- **Trigger**: Connect to the ProFTPD SFTP port and send a crafted SSH message with a length field set to a value near `0xFFFFFFFF`. No SSH authentication is required -- the malformed packet can be sent during the initial key exchange. The server allocates memory based on the overflowed calculation and enters a read loop consuming memory until killed.
- **PoC**: [ExploitDB 16129](https://www.exploit-db.com/exploits/16129)
- **Metasploit**: N/A
- **Advisory**: [NVD CVE-2011-1137](https://nvd.nist.gov/vuln/detail/CVE-2011-1137), [Red Hat Bugzilla 681718](https://bugzilla.redhat.com/show_bug.cgi?id=681718), [Debian Bug 616179](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=616179)
- **Analysis**: Classic integer overflow in a network packet length field. A fuzzer that mutates SSH packet length fields to boundary values (0, 1, 0x7FFFFFFF, 0xFFFFFFFF, 0x80000000) would trigger this immediately. This demonstrates why mod_sftp adds significant attack surface to ProFTPD -- the SSH protocol's binary framing introduces integer overflow risks that the text-based FTP protocol does not have. Mutation strategy: set the 4-byte SSH packet length field to values near `UINT32_MAX`.

### CVE-2011-0762
- **Product**: vsftpd before 2.3.3 (tested on 2.3.0, 2.3.1, 2.3.2)
- **Type**: Denial of Service (CPU exhaustion / process slot exhaustion)
- **CVSS**: 4.0 (v2: AV:N/AC:L/Au:S/C:N/I:N/A:P); no v3 score assigned by NVD
- **Server-side**: Yes -- the server's `vsf_filename_passes_filter()` function in `ls.c` enters pathological backtracking when processing crafted glob patterns in STAT commands
- **Root cause**: The `vsf_filename_passes_filter()` function uses a glob matching algorithm with exponential worst-case complexity. When a STAT command contains a deeply nested glob pattern (e.g., `{*,*,*,*,*,...}`), the matching algorithm enters catastrophic backtracking, consuming 100% CPU. By opening multiple FTP sessions and sending crafted STAT commands in parallel, an attacker can exhaust all process slots and CPU resources.
- **Trigger**: Authenticate to the vsftpd server, then send `STAT {*,*,*,*,*,*,*,*,*,*}\r\n` (or similar deeply nested glob patterns using LIST/NLST). Multiple concurrent sessions amplify the effect. Requires authentication.
- **PoC**: [ExploitDB 16270](https://www.exploit-db.com/exploits/16270) (by Maksymilian Arciemowicz)
- **Metasploit**: N/A
- **Advisory**: [NVD CVE-2011-0762](https://nvd.nist.gov/vuln/detail/CVE-2011-0762), [Red Hat Bugzilla](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2011-0762)
- **Analysis**: This is an algorithmic complexity attack triggered by crafted input bytes. A fuzzer that generates glob patterns with increasing nesting depth and wildcard count in STAT/LIST/NLST arguments would find this. The mutation strategy is generating combinatorial glob expressions: `{*,*,...}` with increasing comma-separated entries, `**/**/...` deep path wildcards, and combinations of `?`, `*`, `[...]`, and `{...}` glob operators. While "only" a DoS, it demonstrates that text parsing of wildcard patterns is a significant attack surface in FTP servers.

---

## Key Vulnerability Patterns for Fuzzing

1. **Command Argument Length**: Oversized arguments for USER, PASS, CWD, MKD, RMD -- classic stack overflows in embedded FTP stacks (Nucleus RTOS CVE-2021-31886, CVE-2021-31887)
2. **Telnet IAC Injection**: Embedding `\xff` (Telnet IAC) bytes in FTP command stream to trigger escape sequence parsing bugs (ProFTPD CVE-2010-4221)
3. **Glob Patterns in STAT/LIST/NLST**: Complex glob patterns causing CPU exhaustion (vsftpd CVE-2011-0762)
4. **Backslash/Quote Escaping**: Terminal escape characters at end of command strings (ProFTPD CVE-2023-51713)
5. **Data Channel Interleaving**: Sending control channel commands during active data transfers (ProFTPD CVE-2020-9273)
6. **SSH/SFTP Packet Lengths**: Integer overflows in binary SSH framing for SFTP-enabled servers (ProFTPD CVE-2011-1137)
7. **Display File Processing**: Crafted `.message` files with expansion variables (ProFTPD CVE-2006-5815)
8. **Multi-line Reply Parsing**: Malformed multi-line reply sequences
9. **PORT/PASV Address Parsing**: Crafted IP:port targeting internal services (FTP bounce)
10. **Transfer Mode/Type**: Binary/ASCII mode confusion for data parsing
