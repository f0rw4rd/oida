# HTTP/1.x - Notable CVEs

CVEs related to parsing and processing vulnerabilities in HTTP implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2023-44487 | Multiple HTTP/2 implementations | Rapid Reset attack (DoS via stream creation/cancellation) | DoS | 7.5 | [HTTP/2 Rapid Reset](https://www.cve.org/CVERecord?id=CVE-2023-44487) |
| CVE-2023-25690 | Apache httpd | HTTP request smuggling via mod_proxy with RewriteRule | Request Smuggling | 9.8 | [Apache Advisory](https://httpd.apache.org/security/vulnerabilities_24.html) |
| CVE-2022-31813 | Apache httpd | IP-based authentication bypass via crafted X-Forwarded-* headers | Auth Bypass | 9.8 | [Apache Advisory](https://httpd.apache.org/security/vulnerabilities_24.html) |
| CVE-2021-22947 | curl | STARTTLS protocol injection via HTTP CONNECT | MITM | 5.9 | [curl Advisory](https://curl.se/docs/CVE-2021-22947.html) |
| CVE-2021-22901 | curl | Use-after-free in HTTP/2 connection reuse | UAF / RCE | 8.1 | [curl Advisory](https://curl.se/docs/CVE-2021-22901.html) |
| CVE-2019-11043 | PHP-FPM (via nginx) | Buffer underflow via crafted PATH_INFO in FastCGI | RCE | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-11043) |
| CVE-2021-44228 | Apache Log4j (via HTTP) | Log4Shell - JNDI injection via HTTP header values | RCE | 10.0 | [Apache Advisory](https://logging.apache.org/log4j/2.x/security.html) |
| CVE-2022-22720 | Apache httpd | HTTP request smuggling via malformed request body | Request Smuggling | 9.8 | [Apache Advisory](https://httpd.apache.org/security/vulnerabilities_24.html) |
| CVE-2020-11724 | OpenResty/nginx | HTTP request smuggling via Transfer-Encoding whitespace | Request Smuggling | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-11724) |
| CVE-2021-33193 | Apache httpd | HTTP/2 method confusion leading to request smuggling | Request Smuggling | 7.5 | [Apache Advisory](https://httpd.apache.org/security/vulnerabilities_24.html) |
| CVE-2023-27522 | Apache httpd | HTTP response smuggling via mod_proxy_uwsgi | Response Smuggling | 7.5 | [Apache Advisory](https://httpd.apache.org/security/vulnerabilities_24.html) |

## Exploits and PoCs

### CVE-2025-55315
- **Product**: ASP.NET Core Kestrel (all supported versions: 8.x, 9.x, 10.x)
- **Type**: HTTP Request Smuggling
- **CVSS**: 9.9
- **Server-side**: Yes -- Kestrel treats a lone `\n` in chunk extensions as part of the extension and continues searching for `\r\n`, while proxies interpret the lone `\n` as a line terminator
- **Root cause**: Inconsistent parsing of chunk extension line terminators; Kestrel accepts lone LF while upstream proxies do not, creating CL/TE desync
- **PoC**: [github.com/ZemarKhos/CVE-2025-55315-PoC-Exploit](https://github.com/ZemarKhos/CVE-2025-55315-PoC-Exploit), [Gist by N3mes1s](https://gist.github.com/N3mes1s/d0897c13ca199e739ecc2b562f466040)
- **Metasploit**: N/A
- **Advisory**: [Microsoft Advisory](https://www.microsoft.com/en-us/msrc/blog/2025/10/understanding-cve-2025-55315)
- **Analysis**: Fuzzing chunked transfer encoding with various line terminator combinations (LF, CRLF, CR, lone CR, lone LF within chunk extensions) would reveal the parsing inconsistency.

### CVE-2025-32094
- **Product**: Akamai HTTP servers
- **Type**: HTTP Request Smuggling
- **CVSS**: N/A
- **Server-side**: Yes -- an OPTIONS request with `Expect: 100-continue` header and obsolete line folding creates parsing discrepancy between in-path servers
- **Root cause**: Inconsistent handling of obsolete line folding (obs-fold) in headers between frontend and backend servers
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [Akamai Blog](https://www.akamai.com/blog/security/cve-2025-32094-http-request-smuggling)
- **Analysis**: Fuzzing with obs-fold line continuations (space/tab at start of header continuation line) in combination with various HTTP methods would find this desync.

### CVE-2024-6827
- **Product**: Gunicorn (Python WSGI HTTP Server)
- **Type**: HTTP Request Smuggling
- **CVSS**: N/A
- **Server-side**: Yes -- improper validation of Transfer-Encoding header; falls back to Content-Length when Transfer-Encoding is not correctly handled
- **Root cause**: TE/CL fallback logic does not properly reject ambiguous requests with both headers, allowing session poisoning and cache poisoning
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [Snyk](https://security.snyk.io/vuln/SNYK-PYTHON-GUNICORN-9510910)
- **Analysis**: Classic CL.TE smuggling vector. A fuzzer sending requests with both Content-Length and Transfer-Encoding headers with conflicting body sizes would trigger this.

### CVE-2024-34350
- **Product**: Next.js
- **Type**: HTTP Request Smuggling
- **CVSS**: N/A
- **Server-side**: Yes -- inconsistent interpretation of crafted HTTP requests in Next.js server
- **Root cause**: Parsing ambiguity in request handling between Next.js and upstream proxies
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [Snyk](https://security.snyk.io/vuln/SNYK-JS-NEXT-6828456)
- **Analysis**: Fuzzing HTTP request framing (CL/TE combinations, header variations) against Next.js behind a reverse proxy would reveal the desync.

### CVE-2023-25690
- **Product**: Apache httpd (mod_proxy with RewriteRule)
- **Type**: HTTP Request Smuggling
- **CVSS**: 9.8
- **Server-side**: Yes -- mod_proxy with URL rewriting enabled allows request smuggling via crafted request URIs
- **Root cause**: RewriteRule transforms request URI in a way that introduces ambiguity in how mod_proxy forwards the request to the backend
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [Apache Advisory](https://httpd.apache.org/security/vulnerabilities_24.html)
- **Analysis**: Fuzzing URI path with encoded characters, newlines, and special sequences against Apache with mod_proxy and RewriteRule would trigger the smuggling condition.

### CVE-2022-22720
- **Product**: Apache httpd
- **Type**: HTTP Request Smuggling
- **CVSS**: 9.8
- **Server-side**: Yes -- Apache does not close inbound connection when errors are encountered discarding the request body, allowing smuggling via malformed body
- **Root cause**: Error handling in request body parsing fails to close the connection, causing subsequent data to be interpreted as the next request
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [Apache Advisory](https://httpd.apache.org/security/vulnerabilities_24.html)
- **Analysis**: Fuzzing malformed request bodies (invalid chunked encoding, truncated bodies) that trigger parsing errors would reveal the connection-reuse smuggling.

### CVE-2019-11043
- **Product**: PHP-FPM via nginx
- **Type**: Buffer Underflow / RCE
- **CVSS**: 9.8
- **Server-side**: Yes -- crafted PATH_INFO in FastCGI request causes buffer underflow in PHP-FPM, leading to remote code execution
- **Root cause**: Specific nginx configuration with `fastcgi_split_path_info` regex allows crafted newline in URI to corrupt PATH_INFO, causing env variable overflow in PHP-FPM
- **PoC**: Multiple public PoCs available
- **Metasploit**: `exploit/multi/http/php_fpm_rce`
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-11043)
- **Analysis**: Fuzzing URI paths with newline characters (%0a) against nginx+PHP-FPM configurations would trigger the PATH_INFO corruption.

## Key Vulnerability Patterns for Fuzzing

1. **CL/TE Conflicts**: Content-Length and Transfer-Encoding both present with conflicting body sizes
2. **Chunked Encoding**: Invalid hex in chunk size, chunk extensions, incomplete last-chunk
3. **Header Injection**: CRLF sequences in header values, obs-fold line continuations
4. **URI Encoding**: Double-encoding, overlong UTF-8, null bytes, path traversal sequences
5. **Content-Length Variants**: Negative values, duplicates, signed vs unsigned parsing, leading +/-
6. **Method + Version**: Non-standard methods, HTTP/0.9, HTTP/2.0 over plaintext
7. **Multiple Host Headers**: Different values in multiple Host headers
8. **Header Size Limits**: Exceeding implementation-specific header size limits
