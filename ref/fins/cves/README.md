# FINS (Omron) - Notable CVEs

CVEs related to parsing and processing vulnerabilities in FINS/Omron implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2019-18269 | Omron SYSMAC CS/CJ/CP/NJ/NX Series | Incomplete validation of FINS header allows access to unexpected functionality | Improper Validation | 8.6 | [CISA Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-19-346-02) |

## Key Vulnerability Patterns for Fuzzing

1. **FINS/TCP Length Field**: 4-byte length in TCP header - large values, zero, negative-equivalent
2. **Memory Area Code + Address**: Invalid area codes, addresses exceeding area boundaries
3. **Command Code Range**: Unknown command codes (vendor-specific range), mixed MR/MC/AR prefixes
4. **No Authentication by Default**: All commands accepted without credentials
5. **FINS Header Addressing**: DNA/DA1/DA2 routing through gateways - spoofed source addresses
6. **Response Data Size**: Commands like Memory Read with large item counts causing oversized responses
7. **Multiple Commands in TCP Stream**: FINS/TCP connection with rapidly sent commands overwhelming parser
8. **Program Area Operations**: Upload/download commands with corrupt program data

## Exploits and PoCs

### CVE-2022-33971
- **Product**: Omron NJ/NX Series Controllers
- **Type**: DoS / RCE
- **CVSS**: 8.3
- **Server-side**: Yes -- crafted requests cause denial of service or code execution
- **Root cause**: Improper validation of requests allows an attacker to cause DoS or execute malicious programs
- **PoC**: No public PoC (discovered during Pipedream malware analysis)
- **Metasploit**: N/A
- **Advisory**: [NVD CVE-2022-33971](https://nvd.nist.gov/vuln/detail/CVE-2022-33971)
- **Analysis**: Found during the same Pipedream analysis by Dragos. Allows an attacker on the network to crash the controller or achieve code execution. Combined with the lack of FINS authentication, an attacker can first enumerate via FINS then exploit this for full control.

### CVE-2019-18269
- **Product**: Omron SYSMAC CS/CJ/CP/NJ/NX Series
- **Type**: Improper Validation / Access to Unexpected Functionality
- **CVSS**: 8.6
- **Server-side**: Yes -- incomplete validation of FINS header allows access to unintended functionality
- **Root cause**: The FINS header fields (DNA/DA1/DA2/SNA/SA1/SA2) are not fully validated, allowing access to functionality not intended to be exposed
- **PoC**: No public PoC
- **Metasploit**: N/A
- **Advisory**: [CISA ICSA-19-346-02](https://www.cisa.gov/news-events/ics-advisories/icsa-19-346-02)
- **Analysis**: FINS header address fields can be manipulated to reach functionality beyond normal API scope. Fuzzing the DNA/DA1/DA2 routing fields and command codes with unexpected values would find this class of bug.
