# Ethernet - Notable CVEs

| CVE ID | Affected Product | Description | Type | CVSS | Link |
|--------|-----------------|-------------|------|------|------|
| CVE-2020-11896 | Treck TCP/IP Stack (Ripple20) | Malformed Ethernet frame processing in embedded IP stack | RCE | 10.0 | [JSOF Ripple20](https://www.jsof-tech.com/disclosures/ripple20/) |
| CVE-2020-11897 | Treck TCP/IP Stack (Ripple20) | OOB write in IPv6 over Ethernet processing | OOB Write | 10.0 | [JSOF Ripple20](https://www.jsof-tech.com/disclosures/ripple20/) |
| CVE-2020-25578 | FreeBSD | Ethernet frame handling in jail environments | Info Disclosure | 5.3 | [FreeBSD Advisory](https://www.freebsd.org/security/advisories/) |
| CVE-2020-24490 | Linux Kernel Bluetooth | Heap overflow in HCI event handling (BT over Ethernet) | Heap Overflow | 7.5 | [Linux Kernel](https://git.kernel.org/) |

| CVE-2021-3031 | Palo Alto PAN-OS (Etherleak) | Ethernet frame padding bytes not cleared, leaking firewall memory into packets | Info Disclosure | 4.3 | [PAN-OS Advisory](https://security.paloaltonetworks.com/CVE-2021-3031) |
| CVE-2003-0001 | Multiple NIC Drivers (Etherleak) | NIC drivers pad Ethernet frames with kernel memory instead of null bytes | Info Disclosure | 5.0 | [Exploit-DB 3555](https://www.exploit-db.com/exploits/3555) |
| CVE-2020-24588 | Wi-Fi (FragAttacks) | A-MSDU flag in plaintext QoS header not authenticated, allowing frame injection | Frame Injection | 3.5 | [FragAttacks PoC](https://github.com/vanhoefm/fragattacks) |
| CVE-2020-26145 | Wi-Fi (FragAttacks) | Accepting plaintext broadcast fragments as full frames in encrypted networks | Frame Injection | 6.5 | [FragAttacks PoC](https://github.com/vanhoefm/fragattacks) |

## Key Vulnerability Patterns for Fuzzing

1. **EtherType/Length Ambiguity**: Values in the gray zone causing misidentification
2. **VLAN Tag Stacking**: Multiple 802.1Q tags to bypass security controls
3. **Runt/Oversized Frames**: Frames below minimum (64) or above maximum (1518/9022) size
4. **ARP Spoofing**: Malformed ARP hardware/protocol sizes, gratuitous ARP
5. **LLC/SNAP Headers**: When length field < 1536, LLC parsing with invalid DSAP/SSAP
6. **Etherleak (Frame Padding)**: Ethernet frame padding leaking kernel/device memory to adjacent hosts
7. **A-MSDU Aggregation**: QoS header A-MSDU flag not authenticated, enabling frame injection (FragAttacks)
