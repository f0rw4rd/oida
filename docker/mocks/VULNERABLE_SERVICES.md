# Vulnerable Services Launch Commands

All vulnerable services are behind Docker Compose profiles. Use these commands from the `docker/mocks` directory.

## Quick Start

```bash
# Launch ALL vulnerable services (heavy!)
docker-compose --profile vuln-services up -d

# Stop all vulnerable services
docker-compose --profile vuln-services down
```

---

## By Protocol

### MQTT (Memory Corruption)
```bash
docker-compose --profile vuln-mqtt up -d
```
| Port | Service | CVE | Vulnerability |
|------|---------|-----|---------------|
| 11883 | mqtt-cve-2017-7651 | CVE-2017-7651 | Heap overflow on client_id > 256 bytes |
| 11884 | mqtt-cve-2021-34432 | CVE-2021-34432 | QoS 2 use-after-free |
| 11885 | mqtt-cve-2017-7650 | CVE-2017-7650 | Stack overflow on topic > 128 bytes |

### Modbus
```bash
# These run without profile (always available)
docker-compose up -d modbus-vuln modbus-cve-2024-10918 modbus-cve-2022-0367
```
| Port | Service | CVE | Vulnerability |
|------|---------|-----|---------------|
| 5020 | modbus-vuln | - | Stack overflow on MBAP length > 57 |
| 5021 | modbus-cve-2022-0367 | CVE-2022-0367 | Heap overflow in FC 0x17 |
| 5022 | modbus-cve-2024-10918 | CVE-2024-10918 | Stack overflow in FC 0x05/0x06 |

### OPC UA
```bash
docker-compose --profile vuln-opcua up -d
```
| Port | Service | CVE | Vulnerability |
|------|---------|-----|---------------|
| 4843 | opcua-cve-2022-25761 | CVE-2022-25761 | Heap overflow in NodeId parsing |
| 4844 | opcua-cve-2021-34821 | CVE-2021-34821 | Stack overflow in UA_String |
| 4845 | opcua-cve-2019-19135 | CVE-2019-19135 | Use-after-free in subscription |

### IEC 104
```bash
docker-compose --profile vuln-iec104 up -d
```
| Port | Service | CVE | Vulnerability |
|------|---------|-----|---------------|
| 2406 | iec104-cve-2022-0369 | CVE-2022-0369 | Integer overflow in ASDU parsing |
| 2407 | iec104-cve-2020-15025 | CVE-2020-15025 | Buffer overflow in CP56Time2a |
| 2408 | iec104-cve-2019-18858 | CVE-2019-18858 | Heap overflow in IOA handling |

### DNP3
```bash
docker-compose --profile vuln-dnp3 up -d
```
| Port | Service | CVE | Vulnerability |
|------|---------|-----|---------------|
| 20005 | dnp3-cve-2020-28875 | CVE-2020-28875 | Stack overflow in link layer |
| 20006 | dnp3-cve-2019-18996 | CVE-2019-18996 | Heap corruption in transport |
| 20007 | dnp3-cve-2017-7938 | CVE-2017-7938 | Buffer overflow in object parsing |

### MMS / IEC 61850
```bash
docker-compose --profile vuln-mms up -d
```
| Port | Service | CVE | Vulnerability |
|------|---------|-----|---------------|
| 10103 | mms-cve-2022-24760 | CVE-2022-24760 | Buffer overflow in MMS PDU |
| 10104 | mms-cve-2019-6138 | CVE-2019-6138 | Heap overflow in GOOSE |
| 10105 | mms-cve-2018-12731 | CVE-2018-12731 | Stack overflow in ASN.1 decode |

### BACnet
```bash
docker-compose --profile vuln-bacnet up -d
```
| Port | Service | CVE | Vulnerability |
|------|---------|-----|---------------|
| 47809/udp | bacnet-cve-2021-42543 | CVE-2021-42543 | APDU decode overflow |
| 47810/udp | bacnet-cve-2019-12480 | CVE-2019-12480 | Heap overflow in property parsing |
| 47811/udp | bacnet-cve-2018-10630 | CVE-2018-10630 | Buffer overflow in packet processing |

### EtherNet/IP
```bash
docker-compose --profile vuln-ethernetip up -d
```
| Port | Service | CVE | Vulnerability |
|------|---------|-----|---------------|
| 44820 | ethernetip-cve-2021-27498 | CVE-2021-27498 | Heap overflow in CIP message |
| 44821 | ethernetip-cve-2020-25055 | CVE-2020-25055 | Stack overflow in assembly |
| 44822 | ethernetip-cve-2019-10952 | CVE-2019-10952 | Out-of-bounds write |

### SMTP
```bash
docker-compose --profile vuln-smtp up -d
```
| Port | Service | CVE | Vulnerability |
|------|---------|-----|---------------|
| 2520 | smtp-mock | - | Fuzz testing target |
| 2525 | smtp-opensmtpd-cve-2020-7247 | CVE-2020-7247 | Shell injection RCE |
| 2526 | smtp-exim-cve-2019-15846 | CVE-2019-15846 | TLS SNI heap overflow |
| 2527 | smtp-exim-cve-2019-16928 | CVE-2019-16928 | EHLO heap overflow |

### VNC
```bash
docker-compose --profile vuln-vnc up -d
```
| Port | Service | CVE | Vulnerability |
|------|---------|-----|---------------|
| 5901 | vnc-tightvnc-cve-2019-8287 | CVE-2019-8287 | Heap buffer overflow |
| 5902 | vnc-libvncserver-cve-2018-20019 | CVE-2018-20019 | Heap overflow |
| 5903 | vnc-cve-2020-14397 | CVE-2020-14397 | NULL pointer dereference |

### DNS
```bash
docker-compose --profile vuln-dns up -d
```
| Port | Service | CVE | Vulnerability |
|------|---------|-----|---------------|
| 10053/udp | dns-dnsmasq-cve-2017-14491 | CVE-2017-14491 | Heap buffer overflow |
| 10054/udp | dns-dnsmasq-cve-2020-25681 | CVE-2020-25681 | DNSpooq buffer overflow |
| 10055/udp | dns-cve-2020-25682 | CVE-2020-25682 | DNSSEC heap overflow |

### CoAP
```bash
docker-compose --profile vuln-coap up -d
```
| Port | Service | CVE | Vulnerability |
|------|---------|-----|---------------|
| 15683/udp | coap-libcoap-cve-2024-0962 | CVE-2024-0962 | Buffer overflow |
| 15685/udp | coap-californium | - | Reference implementation |
| 15686/udp | coap-cve-2023-35862 | CVE-2023-35862 | Memory corruption |

### DICOM
```bash
docker-compose --profile vuln-dicom up -d
```
| Port | Service | CVE | Vulnerability |
|------|---------|-----|---------------|
| 14242 | dicom-orthanc-cve-2023-33466 | CVE-2023-33466 | Path traversal |
| 14243 | dicom-cve-2022-29155 | CVE-2022-29155 | Path traversal |
| 14244 | dicom-cve-2019-19016 | CVE-2019-19016 | Buffer overflow in parsing |

### HTTP
```bash
docker-compose --profile vuln-http up -d
```
| Port | Service | CVE | Vulnerability |
|------|---------|-----|---------------|
| 8083 | http-nginx-cve-2021-23017 | CVE-2021-23017 | DNS resolver heap overflow |
| 8084 | http-apache-cve-2019-0211 | CVE-2019-0211 | Privilege escalation |
| 8085 | http-apache-cve-2018-1312 | CVE-2018-1312 | mod_auth_digest use-after-free |

### FTP
```bash
docker-compose --profile vuln-ftp up -d
```
| Port | Service | CVE | Vulnerability |
|------|---------|-----|---------------|
| 2121 | ftp-vsftpd-cve-2021-3618 | CVE-2021-3618 | ALPACA TLS attack |
| 2122 | ftp-proftpd-cve-2015-3306 | CVE-2015-3306 | mod_copy use-after-free |
| 2123 | ftp-proftpd-cve-2019-12815 | CVE-2019-12815 | Arbitrary file copy |

### SNMP
```bash
docker-compose --profile vuln-snmp up -d
```
| Port | Service | CVE | Vulnerability |
|------|---------|-----|---------------|
| 16161/udp | snmp-cve-2022-24805 | CVE-2022-24805 | ipDefaultTTL buffer overflow |
| 16162/udp | snmp-cve-2020-15861 | CVE-2020-15861 | AgentX heap overflow |
| 16163/udp | snmp-cve-2018-18066 | CVE-2018-18066 | NULL pointer dereference |

### NTP
```bash
docker-compose --profile vuln-ntp up -d
```
| Port | Service | CVE | Vulnerability |
|------|---------|-----|---------------|
| 12300/udp | ntp-cve-2020-11868 | CVE-2020-11868 | DoS via malformed packet |
| 12301/udp | ntp-cve-2018-12327 | CVE-2018-12327 | Stack buffer overflow |
| 12302/udp | ntp-cve-2016-9042 | CVE-2016-9042 | Origin timestamp bypass |

### HL7
```bash
docker-compose --profile vuln-hl7 up -d
```
| Port | Service | CVE | Vulnerability |
|------|---------|-----|---------------|
| 2576 | hl7-cve-2020-14964 | CVE-2020-14964 | Mirth XXE in HL7 parsing |
| 2577 | hl7-cve-2019-17564 | CVE-2019-17564 | RCE |
| 2578 | hl7-cve-2018-11797 | CVE-2018-11797 | DoS via malformed messages |

---

## Individual Service Launch

```bash
# Launch specific service
docker-compose --profile vuln-mqtt up -d mqtt-cve-2017-7651

# View logs
docker logs -f mqtt-cve-2017-7651

# Stop specific service
docker-compose stop mqtt-cve-2017-7651

# Restart after crash
docker-compose --profile vuln-mqtt restart mqtt-cve-2017-7651
```

---

## Notes

- All vulnerable services compiled with protections **disabled** (`-fno-stack-protector`, `-z execstack`, `-no-pie`)
- Services use `restart: "no"` - they stay down after crash for detection
- **FOR SECURITY TESTING ONLY** - Do not expose to untrusted networks
