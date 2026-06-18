# HL7 - Notable CVEs

CVEs related to parsing and processing vulnerabilities in HL7 implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2021-3432 | HAPI HL7 (Java) | XML External Entity injection via HL7 v2.x XML encoding | XXE | 7.5 | [GitHub Advisory](https://github.com/hapifhir/hapi-hl7v2/security) |
| CVE-2019-14819 | OpenNMS | HL7 message handling RCE | RCE | 8.8 | [OpenNMS Advisory](https://www.opennms.org/en/blog/) |
| CVE-2020-14957 | HAPI FHIR (HL7 ecosystem) | ReDoS in narrative sanitization | DoS | 5.3 | [GitHub Advisory](https://github.com/hapifhir/hapi-fhir/security) |
| CVE-2020-14959 | Mirth Connect | HL7 message parsing DoS via crafted segments | DoS | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-14959) |
| CVE-2018-15466 | Philips IntelliSpace PACS | HL7 interface vulnerability allows patient data manipulation | Data Integrity | 5.3 | [CISA ICSMA](https://www.cisa.gov/news-events/ics-advisories/icsma-18-340-01) |

## Key Vulnerability Patterns for Fuzzing

1. **MLLP Framing**: Missing/duplicate Start/End blocks, embedded control characters within message body
2. **Encoding Character Redefinition**: MSH-1/MSH-2 with unusual delimiters (e.g., using pipe as component separator)
3. **Segment Field Count**: Segments with far more or fewer fields than expected for their type
4. **Escape Sequences**: Malformed \X..\ hex escapes, unclosed sequences, nested escapes
5. **Message Size**: Very large messages between MLLP framing characters (no size limit in protocol)
6. **Z-Segments**: Custom segments with arbitrary content
7. **Field Repetitions**: Excessive repetitions of repeatable fields (separated by ~)
8. **Data Type Validation**: Invalid dates (month 13, day 32), malformed timestamps with timezone
9. **HL7 v2.x XML Encoding**: Alternative XML encoding mode - enables XXE, XSS, and XML bomb attacks
10. **Java Deserialization**: HL7 integration engines (Mirth Connect, HAPI) are Java-based - deserialization attacks via crafted message content

## Exploits and PoCs

### CVE-2020-14959
- **Product**: NextGen Mirth Connect
- **Type**: Denial of Service
- **CVSS**: 7.5
- **Server-side**: Yes -- HL7 message parsing crashes on crafted segments
- **Root cause**: Improper handling of malformed HL7 message segments causing unhandled exceptions in the parsing pipeline
- **PoC**: No public PoC
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-14959)
- **Analysis**: This is a direct HL7 message parsing vulnerability. Crafted segments with unexpected field counts or content cause the server to crash. A protocol-aware HL7 fuzzer mutating segment structure would reproduce this class of bug.

