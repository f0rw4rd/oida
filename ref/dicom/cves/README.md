# DICOM - Notable CVEs

CVEs related to parsing and processing vulnerabilities in DICOM implementations, relevant to fuzzing.

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2022-24782 | Orthanc | Path traversal via crafted DICOM instance URI | Path Traversal | 6.5 | [Orthanc Advisory](https://book.orthanc-server.com/faq/security.html) |
| CVE-2019-16530 | DCMTK | Heap buffer overflow in DICOM data element parsing | Heap Overflow | 9.8 | [DCMTK Advisory](https://support.dcmtk.org/redmine/projects/dcmtk/wiki/DCMTK_Security_Fixes) |
| CVE-2021-41687 | DCMTK | Path traversal via C-STORE SOP Instance UID | Path Traversal | 7.5 | [DCMTK Advisory](https://support.dcmtk.org/redmine/projects/dcmtk/wiki/DCMTK_Security_Fixes) |
| CVE-2022-2121 | DCMTK | Null pointer dereference in DICOM dataset parsing | DoS | 6.5 | [DCMTK Advisory](https://support.dcmtk.org/redmine/projects/dcmtk/wiki/DCMTK_Security_Fixes) |
| CVE-2020-4007 | VMware Workspace ONE (DICOM) | DICOM service processing vulnerability | RCE | 9.8 | [VMware Advisory](https://www.vmware.com/security/advisories.html) |
| CVE-2019-11687 | GDCM | Heap-based buffer overflow in DICOM JPEG parsing | Heap Overflow | 7.8 | [GDCM Advisory](https://github.com/malaterre/GDCM/issues) |
| CVE-2019-1010228 | GDCM | Out-of-bounds read in DICOM data element | OOB Read | 6.5 | [GDCM Advisory](https://github.com/malaterre/GDCM/issues) |
| CVE-2022-22772 | Philips IntelliBridge | DICOM association handling vulnerability | DoS | 6.5 | [CISA ICSMA](https://www.cisa.gov/news-events/ics-advisories/icsma-22-045-01) |
| CVE-2019-18922 | Allied Telesis AT-DICOM | Path traversal in DICOM file storage | Path Traversal | 7.5 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-18922) |
| CVE-2023-29060 | BD Alaris Infusion | DICOM/HL7 network service allows unauthorized access | Auth Bypass | 5.4 | [CISA ICSMA](https://www.cisa.gov/news-events/ics-advisories/icsma-23-166-01) |
| CVE-2021-41688 | DCMTK | Heap buffer overflow in DICOM association negotiation | Heap Overflow | 7.5 | [DCMTK Advisory](https://support.dcmtk.org/redmine/projects/dcmtk/wiki/DCMTK_Security_Fixes) |
| CVE-2024-24989 | pydicom | ReDoS in DICOM UID parsing | DoS | 5.3 | [GitHub Advisory](https://github.com/pydicom/pydicom/security) |
| CVE-2024-24793 | libdicom 1.0.5 | Use-after-free in DICOM element parsing (duplicate tags) | UAF / RCE | 8.1 | [Talos TALOS-2024-1931](https://talosintelligence.com/vulnerability_reports/TALOS-2024-1931) |
| CVE-2024-24794 | libdicom 1.0.5 | Use-after-free in Sequence VR parsing (parse_meta_sequence_end) | UAF / RCE | 8.1 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-24794) |
| CVE-2024-47796 | DCMTK 3.6.8 | Out-of-bounds write in nowindow functionality via crafted DICOM file | OOB Write | 8.4 | [Talos TALOS-2024-2122](https://talosintelligence.com/vulnerability_reports/TALOS-2024-2122) |
| CVE-2024-52333 | DCMTK 3.6.8 | Out-of-bounds write in determineMinMax via crafted DICOM file | OOB Write | 8.4 | [Talos TALOS-2024-2121](https://talosintelligence.com/vulnerability_reports/TALOS-2024-2121) |
| CVE-2022-2119 | DCMTK < 3.6.7 | Path traversal in SCP allowing arbitrary DICOM file write | Path Traversal / RCE | 7.5 | [CISA ICSMA-22-174-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-22-174-01) |
| CVE-2022-2120 | DCMTK < 3.6.7 | Path traversal in SCU allowing arbitrary DICOM file write | Path Traversal / RCE | 7.5 | [CISA ICSMA-22-174-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-22-174-01) |
| CVE-2023-33466 | Orthanc < 1.12.0 | Arbitrary file overwrite via DICOM polyglot file upload leading to RCE | File Write / RCE | 8.8 | [Shielder Advisory](https://www.shielder.com/blog/2023/10/cve-2023-33466-exploiting-healthcare-servers-with-polyglot-files/) |
| CVE-2025-3483 | MedDream PACS Server < 7.3.5.860 | Stack buffer overflow in DICOM file parsing -- unauth RCE | Stack Overflow / RCE | 9.8 | [ZDI-25-243](https://www.zerodayinitiative.com/advisories/ZDI-25-243/) |
| CVE-2025-2263 | Sante PACS Server < 4.2.3 | Stack buffer overflow in login decryption (OpenSSL EVP_DecryptUpdate) | Stack Overflow / RCE | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-2263) |
| CVE-2025-2264 | Sante PACS Server < 4.2.3 | Path traversal allowing arbitrary file download | Path Traversal | 9.8 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-2264) |
| CVE-2025-0572 | Sante PACS Server | Arbitrary DCM file write via directory traversal in C-STORE | File Write | 6.5 | [GitHub Advisory](https://github.com/advisories/GHSA-mpwr-28xv-5hw9) |
| CVE-2025-11266 | GDCM < 3.2.2 | Out-of-bounds write via integer underflow in PixelData fragment parsing | OOB Write | 6.6 | [CISA ICSMA-25-345-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-345-01) |
| CVE-2025-35975 | MicroDicom DICOM Viewer | Out-of-bounds write in DCM file parsing allowing code execution | OOB Write / RCE | 8.8 | [CISA ICSMA-25-121-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-121-01) |
| CVE-2025-2357 | DCMTK < 3.6.9 | Segfault in JPEG-LS decoder from invalid JPEG-LS data | DoS | -- | [DCMTK Advisory](https://support.dcmtk.org/redmine/projects/dcmtk/wiki/DCMTK_Security_Fixes) |

## Key Vulnerability Patterns for Fuzzing

1. **PDU Length Field**: 4-byte length for each PDU - values exceeding memory, mismatched with content
2. **Association Negotiation**: Excessive presentation contexts, unknown transfer syntaxes, max PDU size extremes
3. **Data Element Length**: Undefined length (0xFFFFFFFF) with missing delimiter items, explicit VR length mismatches
4. **Sequence Nesting**: Deeply nested SQ elements causing stack exhaustion
5. **Private Tags**: Odd-group data elements with arbitrary VR and content (no dictionary validation)
6. **Pixel Data Fragments**: Encapsulated pixel data with malformed fragment offsets
7. **Transfer Syntax Confusion**: Parsing with wrong endianness or VR mode
8. **C-STORE SOP Instance UID**: Path traversal via UIDs used as filenames
9. **Association Item Types**: Unknown item types in A-ASSOCIATE-RQ/AC
10. **VR-Specific Parsing**: Each Value Representation has specific format requirements - wrong data for VR type

## Exploits and PoCs

### CVE-2019-11687
- **Product**: GDCM (Grassroots DICOM) < 3.0.0
- **Type**: Heap-based Buffer Overflow
- **CVSS**: 7.8
- **Server-side**: Yes -- JPEG codec parsing in GDCM overflows a heap buffer when processing crafted compressed pixel data in a DICOM file
- **Root cause**: The JPEG decoder did not validate decompressed data size against the allocated output buffer. A crafted DICOM file with malformed JPEG-compressed pixel data could write past the end of the heap allocation.
- **PoC**: [kosmokato/bad-dicom](https://github.com/kosmokato/bad-dicom) -- handcrafted DICOM exploitation framework for this CVE
- **Advisory**: [GDCM Issues](https://github.com/malaterre/GDCM/issues)
- **Analysis**: Classic heap overflow in image codec parsing. A fuzzer generating DICOM files with mutated JPEG-compressed pixel data would trigger this. The GDCM library is embedded in many medical imaging applications (SimpleITK, 3D Slicer, medInria).

### CVE-2024-24793 / CVE-2024-24794
- **Product**: Imaging Data Commons libdicom 1.0.5
- **Type**: Use-After-Free
- **CVSS**: 8.1
- **Server-side**: Yes -- DICOM element parsing frees memory prematurely when encountering duplicate tags (CVE-2024-24793) or during Sequence VR end-of-sequence parsing (CVE-2024-24794)
- **Root cause**: When a DICOM file contains two elements with the same tag, the first element's memory is freed but the pointer remains in use. In CVE-2024-24794, `parse_meta_sequence_end()` triggers a UAF during Sequence Value Representation parsing. Both allow heap corruption.
- **PoC**: No public standalone PoC, but Cisco Talos published technical details with reproduction steps
- **Advisory**: [Talos TALOS-2024-1931](https://talosintelligence.com/vulnerability_reports/TALOS-2024-1931), [GitHub Advisory GHSA-6989-vr9p-xx57](https://github.com/advisories/GHSA-6989-vr9p-xx57)
- **Analysis**: Excellent fuzzing target. Generating DICOM files with duplicate tags or malformed sequence delimiters is straightforward. The UAF can potentially be escalated to arbitrary code execution via heap feng shui.

### CVE-2024-47796 / CVE-2024-52333
- **Product**: OFFIS DCMTK 3.6.8
- **Type**: Out-of-bounds Write
- **CVSS**: 8.4
- **Server-side**: Yes -- the `nowindow` (CVE-2024-47796) and `determineMinMax` (CVE-2024-52333) image processing functions write past buffer boundaries when processing crafted DICOM files
- **Root cause**: Improper array index validation. The image rendering functions compute buffer indices from DICOM metadata (rows, columns, bits allocated) without checking that the resulting index falls within the allocated buffer. A crafted DICOM file with inconsistent dimension metadata causes out-of-bounds writes.
- **PoC**: No public PoC. Discovered by Emmanuel Tacheau of Cisco Talos.
- **Advisory**: [Talos TALOS-2024-2122](https://talosintelligence.com/vulnerability_reports/TALOS-2024-2122), [Talos TALOS-2024-2121](https://talosintelligence.com/vulnerability_reports/TALOS-2024-2121)
- **Analysis**: These are found by mutating DICOM header fields (Rows, Columns, BitsAllocated, BitsStored, HighBit) to create inconsistencies between declared dimensions and actual pixel data size. A structure-aware DICOM fuzzer would systematically find these.

### CVE-2023-33466
- **Product**: Orthanc < 1.12.0
- **Type**: Arbitrary File Overwrite leading to RCE
- **CVSS**: 8.8
- **Server-side**: Yes -- Orthanc allows authenticated users to upload DICOM instances via the REST API; the storage path is derived from DICOM metadata without sufficient sanitization
- **Root cause**: When storing a DICOM file, Orthanc uses the SOP Instance UID to construct the filesystem path. By crafting a polyglot file that is simultaneously a valid DICOM instance and a valid Orthanc JSON configuration, an attacker can overwrite the server's configuration file. The DICOM preamble (128 zero bytes + "DICM") provides space for the JSON payload. After overwriting the config to enable Lua scripting, the attacker triggers a server restart via POST /tools/reset and then executes arbitrary Lua code.
- **PoC**: [ShielderSec/poc/CVE-2023-33466](https://github.com/ShielderSec/poc/blob/main/CVE-2023-33466/exploit.py) -- full Python exploit
- **Advisory**: [Shielder Blog](https://www.shielder.com/blog/2023/10/cve-2023-33466-exploiting-healthcare-servers-with-polyglot-files/), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-33466)
- **Analysis**: Demonstrates a creative attack combining DICOM file format knowledge with server configuration mechanics. A fuzzer generating DICOM files with path traversal sequences in SOP Instance UID and other metadata fields would probe for this class of vulnerability.

### CVE-2025-3483
- **Product**: MedDream PACS Server < 7.3.5.860
- **Type**: Stack-based Buffer Overflow (Unauthenticated RCE)
- **CVSS**: 9.8
- **Server-side**: Yes -- the DICOM file parser does not validate the length of user-supplied data before copying to a fixed-length stack buffer
- **Root cause**: When parsing incoming DICOM files (received via C-STORE or file upload), a data element's value is copied to a stack-allocated buffer without checking that the value length fits. Oversized values overwrite the stack frame, allowing return address control.
- **PoC**: No public PoC (discovered via ZDI)
- **Advisory**: [ZDI-25-243](https://www.zerodayinitiative.com/advisories/ZDI-25-243/), [NVD CVE-2025-3483](https://nvd.nist.gov/vuln/detail/CVE-2025-3483)
- **Analysis**: Classic stack buffer overflow in DICOM parsing. No authentication required. A fuzzer generating DICOM files with oversized data element values (particularly string VRs like LO, SH, PN) would immediately find this class of bug.

### CVE-2025-2263
- **Product**: Sante PACS Server < 4.2.3
- **Type**: Stack-based Buffer Overflow (Unauthenticated RCE)
- **CVSS**: 9.8
- **Server-side**: Yes -- the web server login handler passes user-supplied encrypted username/password to OpenSSL EVP_DecryptUpdate with a fixed 0x80-byte output buffer
- **Root cause**: A fixed-size stack buffer (128 bytes) is used as the output for OpenSSL decryption of the username and password fields. An attacker supplying a long encrypted value overflows this buffer on the stack.
- **PoC**: No public PoC
- **Advisory**: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-2263)
- **Analysis**: While this is in the web interface rather than DICOM protocol parsing, it demonstrates the attack surface of PACS server web portals. Fuzzing the HTTP login endpoint with oversized credential fields catches this.

### CVE-2025-11266
- **Product**: GDCM (Grassroots DICOM) < 3.2.2
- **Type**: Out-of-bounds Write via Integer Underflow
- **CVSS**: 6.6
- **Server-side**: Yes -- parsing encapsulated PixelData fragments triggers an unsigned integer underflow in buffer index calculation
- **Root cause**: When processing DICOM files with compressed (encapsulated) PixelData, the fragment offset calculation uses unsigned integer arithmetic. A crafted fragment offset causes underflow, producing a large positive index that writes outside the allocated buffer, leading to a segmentation fault.
- **PoC**: No public PoC
- **Advisory**: [CISA ICSMA-25-345-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-345-01), [GitHub Advisory GHSA-7qcj-ww2g-7w6j](https://github.com/advisories/GHSA-7qcj-ww2g-7w6j)
- **Analysis**: Fuzzing DICOM files with mutated encapsulated pixel data fragment offsets and Basic Offset Table entries would reproduce this. The integer underflow pattern is a classic target for structure-aware fuzzers.
