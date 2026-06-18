#!/usr/bin/env python3
"""
Mock SNMP Agent for testing SNMPScanner

Simulates an ICS device (Siemens SCALANCE switch) with:
- Standard MIB-II OIDs (sysDescr, sysName, sysObjectID, etc.)
- ARP table entries (ipNetToMediaTable)
- MAC table entries (dot1dTpFdbTable)
- Vendor-specific OIDs (Siemens)

Usage:
    python snmp_server.py [--port 161] [--community public]
"""

import argparse
import asyncio
import logging
import signal
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


# Simulated device data - Siemens SCALANCE X208
DEVICE_DATA = {
    # Standard MIB-II
    "sysDescr": "Siemens SCALANCE X208 Industrial Ethernet Switch",
    "sysObjectID": "1.3.6.1.4.1.4329.6.3.1",  # Siemens SCALANCE
    "sysUpTime": 123456789,
    "sysContact": "admin@example.com",
    "sysName": "SCALANCE-X208-PLC01",
    "sysLocation": "Plant Floor - Area 1",
    "sysServices": 78,
    # Siemens-specific
    "siemens_serial": "S7P-1234-5678-9ABC",
    "siemens_fw": "V4.5.2",
    "siemens_hw": "Rev.3",
    "siemens_order": "6GK5208-0BA10-2AA3",
}

# Simulated ARP table (ipNetToMediaTable)
# Format: {interface_index: {ip: mac}}
ARP_TABLE = {
    1: {
        "192.168.1.10": "00:1b:1b:aa:bb:cc",
        "192.168.1.20": "00:1b:1b:dd:ee:ff",
        "192.168.1.30": "00:0e:8c:11:22:33",  # Siemens PLC
        "192.168.1.40": "00:80:f4:44:55:66",  # Telemecanique
        "192.168.1.50": "00:01:05:77:88:99",  # Beckhoff
    },
    2: {
        "10.0.0.100": "3c:7c:3f:aa:aa:aa",
        "10.0.0.101": "3c:7c:3f:bb:bb:bb",
    },
}

# Simulated MAC table (dot1dTpFdbTable)
MAC_TABLE = [
    {"mac": "00:1b:1b:aa:bb:cc", "port": 1},
    {"mac": "00:1b:1b:dd:ee:ff", "port": 2},
    {"mac": "00:0e:8c:11:22:33", "port": 3},
    {"mac": "00:80:f4:44:55:66", "port": 4},
    {"mac": "00:01:05:77:88:99", "port": 5},
    {"mac": "3c:7c:3f:aa:aa:aa", "port": 6},
    {"mac": "3c:7c:3f:bb:bb:bb", "port": 7},
]


def build_oid_tree():
    """Build OID tree with simulated data"""
    oids = {}

    # Standard MIB-II (iso.org.dod.internet.mgmt.mib-2.system)
    oids["1.3.6.1.2.1.1.1.0"] = ("str", DEVICE_DATA["sysDescr"])  # sysDescr
    oids["1.3.6.1.2.1.1.2.0"] = ("oid", DEVICE_DATA["sysObjectID"])  # sysObjectID
    oids["1.3.6.1.2.1.1.3.0"] = ("int", DEVICE_DATA["sysUpTime"])  # sysUpTime
    oids["1.3.6.1.2.1.1.4.0"] = ("str", DEVICE_DATA["sysContact"])  # sysContact
    oids["1.3.6.1.2.1.1.5.0"] = ("str", DEVICE_DATA["sysName"])  # sysName
    oids["1.3.6.1.2.1.1.6.0"] = ("str", DEVICE_DATA["sysLocation"])  # sysLocation
    oids["1.3.6.1.2.1.1.7.0"] = ("int", DEVICE_DATA["sysServices"])  # sysServices

    # ARP table: ipNetToMediaPhysAddress
    # OID format: .1.3.6.1.2.1.4.22.1.2.{ifIndex}.{ipAddr}
    for if_index, entries in ARP_TABLE.items():
        for ip, mac in entries.items():
            oid = f"1.3.6.1.2.1.4.22.1.2.{if_index}.{ip}"
            # Convert MAC to bytes format
            mac_bytes = bytes.fromhex(mac.replace(":", ""))
            oids[oid] = ("mac", mac_bytes)

    # MAC table: dot1dTpFdbAddress
    # OID format: .1.3.6.1.2.1.17.4.3.1.1.{mac_as_decimals}
    for entry in MAC_TABLE:
        mac = entry["mac"]
        mac_decimals = ".".join(str(int(b, 16)) for b in mac.split(":"))
        oid = f"1.3.6.1.2.1.17.4.3.1.1.{mac_decimals}"
        mac_bytes = bytes.fromhex(mac.replace(":", ""))
        oids[oid] = ("mac", mac_bytes)

        # Also add port mapping
        port_oid = f"1.3.6.1.2.1.17.4.3.1.2.{mac_decimals}"
        oids[port_oid] = ("int", entry["port"])

    # Siemens vendor-specific OIDs (PEN 4329)
    oids["1.3.6.1.4.1.4329.6.3.2.1.1.3.0"] = ("str", DEVICE_DATA["siemens_serial"])
    oids["1.3.6.1.4.1.4329.6.3.2.1.1.5.0"] = ("str", DEVICE_DATA["siemens_fw"])
    oids["1.3.6.1.4.1.4329.6.3.2.1.1.4.0"] = ("str", DEVICE_DATA["siemens_hw"])
    oids["1.3.6.1.4.1.4329.6.3.2.1.1.2.0"] = ("str", DEVICE_DATA["siemens_order"])

    return oids


async def handle_snmp_request(data, addr, sock, oids, community):
    """Handle incoming SNMP request using pysnmp v6"""
    try:
        from pysnmp.proto import api
        from pysnmp.proto.api import v2c

        # Decode version
        msg_ver = api.decodeMessageVersion(data)
        if msg_ver in api.protoModules:
            pMod = api.protoModules[msg_ver]
        else:
            logger.warning(f"Unsupported SNMP version: {msg_ver}")
            return

        # Parse request
        req_msg, _ = api.decodeMessage(data)
        req_pdu = pMod.apiMessage.getPDU(req_msg)

        # Check community
        recv_community = pMod.apiMessage.getCommunity(req_msg)
        if recv_community != community.encode():
            logger.warning(f"Invalid community from {addr}: {recv_community}")
            return

        # Get request type
        pdu_type = req_pdu.tagSet

        # Build response
        rsp_msg = pMod.apiMessage.getResponse(req_msg)
        rsp_pdu = pMod.apiMessage.getPDU(rsp_msg)

        var_binds = pMod.apiPDU.getVarBinds(req_pdu)
        rsp_var_binds = []

        for oid_obj, val in var_binds:
            oid = oid_obj.prettyPrint()
            # Remove leading dot if present
            oid_clean = oid.lstrip(".")

            if oid_clean in oids:
                oid_type, value = oids[oid_clean]
                if oid_type == "mac":
                    rsp_var_binds.append((oid_obj, v2c.OctetString(value)))
                elif oid_type == "int":
                    rsp_var_binds.append((oid_obj, v2c.Integer(value)))
                elif oid_type == "oid":
                    rsp_var_binds.append((oid_obj, v2c.ObjectIdentifier(value)))
                else:
                    rsp_var_binds.append((oid_obj, v2c.OctetString(str(value))))
            else:
                # OID not found - return noSuchObject
                rsp_var_binds.append((oid_obj, pMod.apiPDU.noSuchObject))

        pMod.apiPDU.setVarBinds(rsp_pdu, rsp_var_binds)

        # Encode and send response
        rsp_data = api.encodeMessage(rsp_msg)
        sock.sendto(rsp_data, addr)
        logger.debug(f"Response sent to {addr}")

    except Exception as e:
        logger.error(f"Error processing request: {e}")


async def run_snmp_server(host, port, community):
    """Run SNMP server using raw UDP sockets"""
    import socket

    oids = build_oid_tree()

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.setblocking(False)

    logger.info(f"SNMP server listening on {host}:{port}")
    logger.info(f"Community: {community}")
    logger.info(f"OIDs registered: {len(oids)}")

    # Print sample OIDs
    logger.info("Sample OIDs:")
    count = 0
    for oid, (oid_type, value) in oids.items():
        if count < 5:
            display_val = value if oid_type != "mac" else value.hex()
            logger.info(f"  {oid} = {display_val}")
            count += 1

    logger.info(f"ARP entries: {sum(len(v) for v in ARP_TABLE.values())}")
    logger.info(f"MAC entries: {len(MAC_TABLE)}")

    loop = asyncio.get_event_loop()

    while True:
        try:
            data, addr = await loop.sock_recvfrom(sock, 65535)
            logger.debug(f"Request from {addr}, {len(data)} bytes")
            await handle_snmp_request(data, addr, sock, oids, community)
        except BlockingIOError:
            await asyncio.sleep(0.01)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Socket error: {e}")
            await asyncio.sleep(0.1)


def main():
    parser = argparse.ArgumentParser(description="Mock SNMP Agent for ICS testing")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=161, help="SNMP port")
    parser.add_argument("--community", default="public", help="SNMP community string")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Handle signals
    def signal_handler(sig, frame):
        logger.info("Shutting down...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run the agent
    try:
        asyncio.run(run_snmp_server(args.host, args.port, args.community))
    except KeyboardInterrupt:
        logger.info("Interrupted")
    except PermissionError:
        logger.error(
            f"Permission denied for port {args.port}. Try running as root or use port > 1024"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
