# NTP - Notable CVEs

CVEs related to parsing and processing vulnerabilities in NTP implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2014-9295 | ntpd | Multiple buffer overflows in crypto-NAK, ctl_putdata, configure | Buffer Overflow / RCE | 7.5 | [NTP Advisory](https://support.ntp.org/bin/view/Main/SecurityNotice#Recent_Vulnerabilities) |
| CVE-2014-9296 | ntpd | Missing return in error path of receive() | Logic Error | 5.0 | [NTP Advisory](https://support.ntp.org/bin/view/Main/SecurityNotice) |
| CVE-2015-7855 | ntpd | decodenetnum() assertion failure from crafted mode 6/7 | DoS | 6.5 | [NTP Advisory](https://support.ntp.org/bin/view/Main/SecurityNotice) |
| CVE-2015-7853 | ntpd | Buffer overflow in refclock_datum_receive() | Buffer Overflow | 9.8 | [NTP Advisory](https://support.ntp.org/bin/view/Main/SecurityNotice) |
| CVE-2016-4953 | ntpd | CRYPTO-NAK crash from spoofed packets | DoS | 7.5 | [NTP Advisory](https://support.ntp.org/bin/view/Main/SecurityNotice) |
| CVE-2016-7434 | ntpd | Null pointer dereference in mrulist query | DoS | 7.5 | [NTP Advisory](https://support.ntp.org/bin/view/Main/SecurityNotice) |
| CVE-2018-7170 | ntpd | Authenticated mode 6 packets allow ephemeral peer spoofing | Auth Bypass | 5.3 | [NTP Advisory](https://support.ntp.org/bin/view/Main/SecurityNotice) |
| CVE-2019-8936 | ntpd | Null pointer dereference in authenticated mode 6 request | DoS | 7.5 | [NTP Advisory](https://support.ntp.org/bin/view/Main/SecurityNotice) |
| CVE-2023-26551 | ntpd | mstolfp() out-of-bounds write from crafted ASCII input | OOB Write | 5.6 | [NTP Advisory](https://support.ntp.org/bin/view/Main/SecurityNotice) |
| CVE-2023-26553 | ntpd | mstolfp() out-of-bounds write (variant) | OOB Write | 5.6 | [NTP Advisory](https://support.ntp.org/bin/view/Main/SecurityNotice) |
| CVE-2020-11868 | ntpd | Crafted symmetric mode packets cause off-path DoS | DoS | 7.5 | [NTP Advisory](https://support.ntp.org/bin/view/Main/SecurityNotice) |

## Exploits and PoCs

### CVE-2014-9295
- **Product**: ntpd (multiple versions)
- **Type**: Buffer Overflow / RCE
- **CVSS**: 7.5
- **Server-side**: Yes -- multiple buffer overflows in crypto-NAK handling, ctl_putdata, and configure functions allow remote code execution
- **Root cause**: Three distinct buffer overflow paths: (1) crypto-NAK response processing does not bounds-check input, (2) ctl_putdata in mode 6 control message handling overflows output buffer, (3) configure command processing overflows internal buffers
- **PoC**: No public RCE PoC (DoS PoCs exist)
- **Metasploit**: N/A
- **Advisory**: [NTP Advisory](https://support.ntp.org/bin/view/Main/SecurityNotice)
- **Analysis**: Fuzzing mode 6 control messages with oversized data payloads and configure commands with long arguments would trigger these overflows.

### CVE-2015-7853
- **Product**: ntpd
- **Type**: Buffer Overflow
- **CVSS**: 9.8
- **Server-side**: Yes -- buffer overflow in refclock_datum_receive() when processing reference clock data
- **Root cause**: Reference clock data processing function does not validate input length before copying into fixed-size buffer
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [NTP Advisory](https://support.ntp.org/bin/view/Main/SecurityNotice)
- **Analysis**: Fuzzing reference clock data input paths with oversized payloads would trigger this overflow. Requires the system to have a Datum reference clock configured.

### CVE-2015-7855
- **Product**: ntpd
- **Type**: DoS (Assertion Failure)
- **CVSS**: 6.5
- **Server-side**: Yes -- decodenetnum() assertion failure from crafted mode 6/7 packets causes daemon crash
- **Root cause**: Mode 6/7 packet processing passes crafted network address data to decodenetnum() which fails an assertion on invalid input format
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [NTP Advisory](https://support.ntp.org/bin/view/Main/SecurityNotice)
- **Analysis**: Fuzzing mode 6 and mode 7 packets with malformed network address fields in data payloads would trigger the assertion failure.

### CVE-2016-7434
- **Product**: ntpd
- **Type**: NULL Pointer Dereference / DoS
- **CVSS**: 7.5
- **Server-side**: Yes -- null pointer dereference in mrulist query processing
- **Root cause**: Mode 6 mrulist query handler does not validate for NULL pointer conditions when processing crafted query parameters
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [NTP Advisory](https://support.ntp.org/bin/view/Main/SecurityNotice)
- **Analysis**: Fuzzing mode 6 mrulist queries (opcode for MRU list retrieval) with missing or malformed parameters would trigger the NULL dereference.

### CVE-2019-8936
- **Product**: ntpd
- **Type**: NULL Pointer Dereference / DoS
- **CVSS**: 7.5
- **Server-side**: Yes -- null pointer dereference in authenticated mode 6 request handling
- **Root cause**: Control message handler does not properly validate authenticated mode 6 request data before dereferencing internal pointers
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [NTP Advisory](https://support.ntp.org/bin/view/Main/SecurityNotice)
- **Analysis**: Fuzzing authenticated mode 6 control packets with malformed data fields would trigger the NULL pointer dereference.

### CVE-2023-26551
- **Product**: ntpd 4.2.8p15
- **Type**: Out-of-Bounds Write
- **CVSS**: 5.6
- **Server-side**: No (affects ntpq client, not ntpd daemon) -- out-of-bounds write in mstolfp() from crafted ASCII timestamp input in the cp<cpdec loop
- **Root cause**: The mstolfp function in libntp/mstolfp.c does not properly bounds-check the decimal portion of ASCII timestamp strings, allowing an out-of-bounds write in the parsing loop
- **PoC**: [github.com/spwpun/ntp-4.2.8p15-cves](https://github.com/spwpun/ntp-4.2.8p15-cves/blob/main/CVE-2023-26551)
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-26551)
- **Analysis**: Fuzzing the mstolfp() function with crafted ASCII timestamp strings containing unusual decimal portions would trigger the OOB write. While this affects the client (ntpq), the same parsing code exists in the library.

### CVE-2023-26553
- **Product**: ntpd 4.2.8p15
- **Type**: Out-of-Bounds Write
- **CVSS**: 5.6
- **Server-side**: No (affects ntpq client) -- out-of-bounds write in mstolfp() when copying the trailing number portion of timestamp strings
- **Root cause**: Variant of CVE-2023-26551; the trailing number copy in mstolfp does not validate destination buffer bounds
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-26553)
- **Analysis**: Related to CVE-2023-26551; fuzzing timestamp string parsing with various trailing number formats would find this variant.

## Key Vulnerability Patterns for Fuzzing

1. **Mode 6 Control Messages**: Variable-length data fields, fragmented responses, opcode dispatch
2. **Mode 7 Private Messages**: Implementation-specific request codes, data item count/size
3. **Extension Field Length**: Length not multiple of 4, length exceeding packet, zero length
4. **MAC Authentication**: Key ID + digest with ambiguous total length
5. **Timestamp Values**: Zero timestamps, far-future timestamps, NaN-equivalent values
6. **Control Message Fragmentation**: More bit + offset + count for fragmented responses
7. **Kiss-o'-Death Reference ID**: ASCII strings in Reference ID at stratum 0/16
8. **Version Number**: VN field values 0 or 5+ (only 3/4 are standard)
