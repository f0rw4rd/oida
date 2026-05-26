# Protocols with reference material but no OIDA fuzzer module

These protocols have curated `ref/<proto>/` material (README, libs, CVEs,
tshark fields) but no entry in `src/oida/fuzz/protocols/` and so no
fuzzer is registered. They are the strongest candidates for new fuzzer
modules — the spec work is done.

## ICS / OT

| Protocol | ref/ folder | Why no fuzzer | Difficulty |
|---|---|---|---|
| Siemens S7 / S7comm | `ref/s7comm/` | python-snap7 doesn't expose raw-frame send; need boofuzz custom socket | Medium |
| PROFINET DCP | `ref/profinet_dcp/` | Layer-2 only; needs raw-socket boofuzz target | Medium |
| EtherCAT | `ref/ethercat/` | Layer-2; pysoem is master-mode only | Hard |
| TASE.2 / ICCP | `ref/tase2/` | Builds on MMS; could derive from `mms.py` | Easy |
| GOOSE | `ref/goose/` | Layer-2 multicast; raw-socket target | Medium |
| HART-IP | `ref/hartip/` | hartip-py provides good client; ~1-day port | Easy |
| KNX / EIB | `ref/knx/` | xknx tunneling protocol well-documented | Medium |
| FINS (Omron) | `ref/fins/` | Simple UDP protocol; ~1-day write | Easy |
| Industrial Ethernet (generic) | `ref/industrial_ethernet/` | Umbrella; pick specific protocol first | n/a |

## Network / discovery

| Protocol | ref/ folder | Why no fuzzer | Difficulty |
|---|---|---|---|
| BFD | `ref/bfd/` | Layer-3 hello protocol; small surface | Easy |
| BGP | `ref/bgp/` | Large surface (RFC 4271 + many extensions); medium-large fuzzer | Hard |
| CDP | `ref/cdp/` | Layer-2; Cisco proprietary | Medium |
| EIGRP | `ref/eigrp/` | Layer-3; Cisco | Medium |
| GLBP / HSRP / VRRP | `ref/glbp/`, `ref/hsrp/`, `ref/vrrp/` | All Cisco/IETF redundancy; similar shape | Easy |
| IGMP / PIM | `ref/igmp/`, `ref/pim/` | Multicast control; raw-socket | Medium |
| LDAP | `ref/ldap/` | ASN.1 BER over TCP; nontrivial | Hard |
| LLDP | `ref/lldp/` | Layer-2 discovery (already in passive listener) | Medium |
| NTLM | `ref/ntlm/` | Embedded in SMB/HTTP; not standalone | Hard |
| OSPF | `ref/ospf/` | IP protocol 89; raw-socket | Hard |
| RIP | `ref/rip/` | UDP 520; simple | Easy |
| RDP | `ref/rdp/` | T.128 channel layering | Hard |
| SIP | `ref/sip/` | Text protocol like SMTP; medium | Medium |
| SSDP / IRC / TLS | various | TLS would be huge; SSDP small | varies |
| Kerberos | `ref/kerberos/` | ASN.1 BER + crypto; hard | Hard |
| RADIUS / TACACS / PAP | various | AAA protocols; small individual surface | Medium |
| LLMNR / mDNS-SD | (in mdns) | covered by mdns fuzzer | done |

## Database / storage

| Protocol | ref/ folder | Difficulty |
|---|---|---|
| MSSQL TDS | `ref/mssql/` | Complex framing; hard |
| MySQL | `ref/mysql/` | Documented wire protocol; medium |
| PostgreSQL | `ref/pgsql/` | Documented wire protocol; medium |
| IMAP / POP3 / SMB | various | Text/binary mix; medium each |

## Healthcare

| Protocol | ref/ folder | Difficulty |
|---|---|---|
| DICOM | `ref/dicom/` | pynetdicom client; surface is large (~100 commands) | Hard |

## How to add a new fuzzer

1. Read the protocol's `ref/<proto>/README.md` (dissector + library refs).
2. Read `ref/<proto>/cves/README.md` for parser-bug history.
3. Pick a base class — `StatefulFuzzer` for handshake-based, `BaseFuzzer`
   for stateless.
4. Define `RequestInfo` entries with category metadata.
5. Build boofuzz `Request` objects with appropriate primitives (favour
   `Word`/`String`/`Bytes` over `Static` for anything that should mutate).
6. Add to `src/oida/fuzz/protocols/__init__.py` registry.
7. Add tests under `tests/unit/fuzz/`.

The modbus, opcua, and iec104 fuzzers are good templates depending on
how stateful the target protocol is.
