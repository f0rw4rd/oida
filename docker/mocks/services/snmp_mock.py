"""SNMP Mock Server - Simulates a Siemens SCALANCE X208 Industrial Ethernet Switch.

Uses pysnmp v4 CommandResponder API to serve SNMP GET/GETNEXT/GETBULK requests
with realistic ICS device data.
"""

import os
import sys

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.proto.api import v2c

SNMP_PORT = int(os.environ.get("SNMP_PORT", "10161"))
SNMP_COMMUNITY = os.environ.get("SNMP_COMMUNITY", "public")


def main():
    print(f"Starting SNMP mock (Siemens SCALANCE X208) on UDP port {SNMP_PORT}")

    # Create SNMP engine
    snmpEngine = engine.SnmpEngine()

    # Transport setup - bind to all interfaces
    config.addTransport(
        snmpEngine,
        udp.domainName,
        udp.UdpTransport().openServerMode(("0.0.0.0", SNMP_PORT)),
    )

    # SNMPv2c community
    config.addV1System(snmpEngine, "public-area", SNMP_COMMUNITY)

    # Allow full read access
    config.addVacmUser(snmpEngine, 2, "public-area", "noAuthNoPriv", (1, 3, 6), (1, 3, 6))

    # Create SNMP context
    snmpContext = context.SnmpContext(snmpEngine)

    # Get MIB builder and set custom system values
    mibInstrum = snmpContext.getMibInstrum()
    mibBuild = mibInstrum.getMibBuilder()

    # Load system MIB
    mibBuild.loadModules("SNMPv2-MIB")

    # Set system values to simulate Siemens SCALANCE X208
    (sysDescr,) = mibBuild.importSymbols("SNMPv2-MIB", "sysDescr")
    sysDescr.syntax = v2c.OctetString("Siemens SCALANCE X208 Industrial Ethernet Switch")

    (sysObjectID,) = mibBuild.importSymbols("SNMPv2-MIB", "sysObjectID")
    sysObjectID.syntax = v2c.ObjectIdentifier((1, 3, 6, 1, 4, 1, 4329, 6, 3, 1))

    (sysName,) = mibBuild.importSymbols("SNMPv2-MIB", "sysName")
    sysName.syntax = v2c.OctetString("SCALANCE-X208-PLC01")

    (sysLocation,) = mibBuild.importSymbols("SNMPv2-MIB", "sysLocation")
    sysLocation.syntax = v2c.OctetString("Plant Floor - Area 1")

    (sysContact,) = mibBuild.importSymbols("SNMPv2-MIB", "sysContact")
    sysContact.syntax = v2c.OctetString("admin@example.com")

    # Register command responders
    cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
    cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
    cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

    print(f"SNMP agent listening on 0.0.0.0:{SNMP_PORT}")
    print(f"Community: {SNMP_COMMUNITY}")
    print("sysDescr: Siemens SCALANCE X208 Industrial Ethernet Switch")
    print("sysObjectID: 1.3.6.1.4.1.4329.6.3.1 (Siemens)")
    print("sysName: SCALANCE-X208-PLC01")
    sys.stdout.flush()

    snmpEngine.transportDispatcher.jobStarted(1)

    try:
        snmpEngine.transportDispatcher.runDispatcher()
    except KeyboardInterrupt:
        snmpEngine.transportDispatcher.closeDispatcher()
    except Exception as e:
        print(f"SNMP agent error: {e}", file=sys.stderr)
        snmpEngine.transportDispatcher.closeDispatcher()
        raise


if __name__ == "__main__":
    main()
