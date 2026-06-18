# Protocol Reference Materials

Reference materials for all protocols fuzzed by OIDA. Each protocol folder contains:
- `README.md` - Wireshark dissector links, open-source parsers, common parsing vulnerabilities
- `cves/README.md` - Notable CVEs relevant to fuzzing (parsing bugs, buffer overflows, DoS)

## Protocol Index

### Industrial Control Systems (ICS)

| Protocol | Folder | Transport | Wireshark Dissector |
|----------|--------|-----------|-------------------|
| Modbus TCP/RTU | [modbus/](modbus/) | TCP:502, Serial | `packet-mbtcp.c` |
| DNP3 | [dnp3/](dnp3/) | TCP:20000, Serial | `packet-dnp.c` |
| IEC 60870-5-104 | [iec104/](iec104/) | TCP:2404 | `packet-iec104.c` |
| BACnet | [bacnet/](bacnet/) | UDP:47808 | `packet-bacnet.c`, `packet-bacapp.c` |
| EtherNet/IP (CIP) | [ethernetip/](ethernetip/) | TCP:44818, UDP:2222 | `packet-enip.c`, `packet-cip.c` |
| ADS/TwinCAT | [ads/](ads/) | TCP:48898 | `packet-ams.c` |
| MMS/IEC 61850 | [mms/](mms/) | TCP:102 (TPKT) | `packet-mms.c` |
| TASE.2/ICCP | [tase2/](tase2/) | TCP:102 (MMS) | `packet-mms.c` |
| PROFINET DCP | [profinet_dcp/](profinet_dcp/) | Ethernet:0x8892 | `packet-pn-dcp.c` |
| HART-IP | [hartip/](hartip/) | TCP/UDP:5094 | `packet-hartip.c` |
| FINS (Omron) | [fins/](fins/) | UDP/TCP:9600 | `packet-omron-fins.c` |
| OPC UA | [opcua/](opcua/) | TCP:4840 | `plugins/epan/opcua/` |

### IoT Protocols

| Protocol | Folder | Transport | Wireshark Dissector |
|----------|--------|-----------|-------------------|
| MQTT | [mqtt/](mqtt/) | TCP:1883/8883 | `packet-mqtt.c` |
| CoAP | [coap/](coap/) | UDP:5683/5684 | `packet-coap.c` |
| BLE/GATT | [gatt/](gatt/) | BLE L2CAP | `packet-btatt.c` |

### Network Infrastructure

| Protocol | Folder | Transport | Wireshark Dissector |
|----------|--------|-----------|-------------------|
| DNS | [dns/](dns/) | UDP/TCP:53 | `packet-dns.c` |
| mDNS | [mdns/](mdns/) | UDP:5353 | `packet-dns.c` |
| DHCP/DHCPv6 | [dhcp/](dhcp/) | UDP:67-68/546-547 | `packet-dhcp.c`, `packet-dhcpv6.c` |
| NTP | [ntp/](ntp/) | UDP:123 | `packet-ntp.c` |
| SNMP v1/v2c/v3 | [snmp/](snmp/) | UDP:161-162 | `packet-snmp.c` |

### Web and Application

| Protocol | Folder | Transport | Wireshark Dissector |
|----------|--------|-----------|-------------------|
| HTTP/1.x | [http/](http/) | TCP:80/443 | `packet-http.c` |
| HTTP/2 | [http2/](http2/) | TCP:443 (h2) | `packet-http2.c` |
| FTP | [ftp/](ftp/) | TCP:21/20 | `packet-ftp.c` |
| TFTP | [tftp/](tftp/) | UDP:69 | `packet-tftp.c` |
| SMTP | [smtp/](smtp/) | TCP:25/587/465 | `packet-smtp.c` |
| VNC/RFB | [vnc/](vnc/) | TCP:5900+ | `packet-vnc.c` |

### Healthcare

| Protocol | Folder | Transport | Wireshark Dissector |
|----------|--------|-----------|-------------------|
| HL7 v2.x | [hl7/](hl7/) | TCP:2575 (MLLP) | `packet-hl7.c` |
| DICOM | [dicom/](dicom/) | TCP:104/11112 | `packet-dcm.c` |

### Layer 2 / Layer 3

| Protocol | Folder | Transport | Wireshark Dissector |
|----------|--------|-----------|-------------------|
| Ethernet | [ethernet/](ethernet/) | Layer 2 | `packet-eth.c` |
| Industrial Ethernet | [industrial_ethernet/](industrial_ethernet/) | Layer 2 | `packet-pn-rt.c`, `packet-ethercat.c` |
| IPv4 | [ipv4/](ipv4/) | Layer 3 | `packet-ip.c` |
| IPv6 | [ipv6/](ipv6/) | Layer 3 | `packet-ipv6.c` |
| ICMP/ICMPv6 | [icmp/](icmp/) | Layer 3 | `packet-icmp.c`, `packet-icmpv6.c` |

## Top Vulnerability Patterns Across Protocols

These patterns are consistently the most productive fuzzing targets across all protocols:

1. **Length Field Mismatches** - Protocol-stated length vs. actual data available. Found in every protocol.
2. **ASN.1 BER/TLV Encoding** - Affects SNMP, MMS, OPC UA, DICOM, LDAP. Indefinite lengths, nested constructed types, and multi-byte tag encoding.
3. **Fragment/Segment Reassembly** - IP fragmentation, TCP segmentation, DNP3 transport segments, COTP segmentation, HTTP/2 chunking. Memory exhaustion and overlap attacks.
4. **State Machine Violations** - Sending messages out of expected sequence. Affects every stateful protocol.
5. **Variable-Length Integer Encoding** - MQTT remaining length, CoAP option delta, ASN.1 OID subidentifiers, HTTP/2 HPACK integer prefix encoding.
6. **String/Name Handling** - DNS name compression pointers, HL7 escape sequences, DICOM VR-specific string formats, FTP path traversal.
7. **Nested/Recursive Structures** - ASN.1 constructed types, DHCPv6 nested options, BACnet segmented APDUs, DICOM sequence items.
8. **Authentication Bypass** - Many ICS protocols (Modbus, FINS, ADS, HART-IP, PROFINET DCP) have zero authentication by design.

## Wireshark Dissector Source Base URL

All Wireshark dissectors are at:
```
https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/
```

Plugins (like OPC UA) are at:
```
https://gitlab.com/wireshark/wireshark/-/tree/master/plugins/epan/
```
