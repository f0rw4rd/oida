# IPv4 - Notable CVEs

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2020-11896 | Treck TCP/IP (Ripple20) | IP fragmentation handling RCE in embedded IP stack | RCE | 10.0 | [JSOF Ripple20](https://www.jsof-tech.com/disclosures/ripple20/) |
| CVE-2021-24086 | Windows TCP/IP | IPv4/IPv6 fragment reassembly DoS | DoS | 7.5 | [Microsoft Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-24086) |
| CVE-2018-5391 | Linux Kernel (FragmentSmack) | IP fragment reassembly CPU exhaustion via crafted fragments | DoS | 7.5 | [Linux Kernel](https://git.kernel.org/) |
| CVE-1999-0016 | Multiple (Teardrop) | Overlapping IP fragments crash kernel | DoS | 5.0 | Historical |
| CVE-2024-20467 | Cisco IOS XE | IPv4 fragment reassembly resource mismanagement causes device reload | DoS | 8.6 | [PoC on GitHub](https://github.com/saler-cve/PoC-Exploit-CVE-2024-20467) |

## Key Fuzzing Targets

1. **Fragment Reassembly**: Overlapping fragments, tiny fragment offset, MF flag without data
2. **IHL Field**: Values < 5, values pointing past total length
3. **Total Length**: Mismatched with actual frame size
4. **IP Options**: Invalid option lengths, record route with 0 pointer, source route to loopback
5. **Checksum Validation**: Off-by-one in checksum, partial checksums with offloading
6. **VFR (Virtual Fragment Reassembly)**: Cisco-specific VFR-enabled interfaces are a separate attack surface for fragment handling (CVE-2024-20467)
