"""
SNMP OID constants and vendor mappings.

Contains:
- SNMP_OIDS: Standard MIB-2 system OIDs (RFC 1213)
- VENDOR_OIDS: Enterprise OID -> vendor name mappings
- VENDOR_SPECIFIC_OIDS: Vendor-specific OID sets for extra device info
- WINDOWS_SERVICE_OIDS: Windows service enumeration OIDs
- FILESYSTEM_OIDS: Filesystem table OIDs
"""

# Standard MIB-2 OIDs (RFC 1213)
SNMP_OIDS = {
    "sysDescr": ".1.3.6.1.2.1.1.1.0",
    "sysObjectID": ".1.3.6.1.2.1.1.2.0",
    "sysUpTime": ".1.3.6.1.2.1.1.3.0",
    "sysContact": ".1.3.6.1.2.1.1.4.0",
    "sysName": ".1.3.6.1.2.1.1.5.0",
    "sysLocation": ".1.3.6.1.2.1.1.6.0",
    "sysServices": ".1.3.6.1.2.1.1.7.0",
    # Extended system scalars
    "hrSystemDate": ".1.3.6.1.2.1.25.1.2.0",  # RFC 2579 DateAndTime
    "ipForwarding": ".1.3.6.1.2.1.4.1.0",  # 1=forwarding (router), 2=not
    "ipDefaultTTL": ".1.3.6.1.2.1.4.2.0",  # OS fingerprinting
    "tcpInSegs": ".1.3.6.1.2.1.6.10.0",  # TCP segments received
    "tcpOutSegs": ".1.3.6.1.2.1.6.11.0",  # TCP segments sent
    "tcpRetransSegs": ".1.3.6.1.2.1.6.12.0",  # TCP retransmissions
}

# Walk lists (auto-built from VENDOR_OIDS below)
# Populated after VENDOR_OIDS definition
WALK_LISTS: dict = {}

# Vendor OIDs (enterprise .1.3.6.1.4.1.X) from IANA
# Comprehensive ICS/industrial vendor mapping
VENDOR_OIDS = {
    # Major networking vendors
    "9": "Cisco",
    "11": "HP",
    "43": "3Com",
    "116": "Hitachi",
    "171": "D-Link",
    "207": "Allied Telesis",
    "311": "Microsoft",
    "343": "Intel",
    "674": "Dell",
    "890": "Zyxel",
    "1588": "Brocade",
    "1916": "Extreme Networks",
    "2011": "Huawei",
    "2272": "Polycom",
    "2435": "Fluke Networks",
    "2544": "ADVA Optical",
    "2620": "Check Point",
    "2636": "Juniper",
    "3224": "Netscreen",
    "4526": "Netgear",
    "6141": "Aruba",
    "6486": "Alcatel-Lucent",
    "6876": "VMware",
    "8072": "Net-SNMP",
    "8741": "SonicWall",
    "12356": "Fortinet",
    "14823": "Aruba",  # Aruba Networks (alternate)
    "14988": "MikroTik",
    "25461": "Palo Alto",
    "25506": "H3C",
    "30065": "Arista",
    "41112": "Ubiquiti",
    # ICS/Industrial automation vendors
    "95": "Rockwell",  # Allen-Bradley
    "244": "Lantronix",  # Serial device servers
    "248": "Hirschmann",  # Belden/Hirschmann industrial switches
    "318": "APC",  # Schneider Electric UPS
    "339": "Siemens",  # Siemens AG (legacy)
    "476": "Vertiv",  # Liebert (legacy)
    "534": "Eaton",  # Eaton Corporation
    "850": "Tripp Lite",  # Tripp Lite UPS
    "908": "ABB",  # ABB (formerly Elsag Bailey)
    "1890": "Red Lion",  # Red Lion Controls
    "2254": "Delta",  # Delta UPS
    "3808": "CyberPower",  # CyberPower UPS
    "3833": "Schneider",  # Schneider Electric
    "3854": "AKCP",  # AKCP Environmental
    "4131": "Tridium",  # Niagara Framework
    "4196": "Siemens",  # Siemens Automation & Drives
    "4329": "Siemens",  # Siemens AG
    "4346": "Phoenix Contact",  # FL SWITCH
    "4399": "Johnson Controls",  # Building automation
    "5130": "Omron",  # Omron
    "5491": "Riello",  # Riello UPS
    "5528": "Schneider",  # Schneider Electric (alternate)
    "5861": "Mitsubishi",  # Mitsubishi Heavy Industries
    "6574": "Synology",  # Synology NAS
    "8691": "Moxa",  # Industrial serial/ethernet
    "10297": "Advantech",  # Advantech EKI switches
    "13400": "Emerson",  # Emerson Network Power
    "13576": "WAGO",  # WAGO PLCs
    "13742": "Raritan",  # Raritan PDUs
    "15004": "Ruggedcom",  # Siemens Ruggedcom
    "16177": "Westermo",  # Westermo switches
    "21239": "Vertiv",  # Vertiv (new PEN)
    "22638": "Siemens",  # Siemens PTD EA
    "24681": "QNAP",  # QNAP NAS
    "25157": "Beckhoff",  # Beckhoff Automation
    "29312": "B&R",  # B&R Automation
    "30140": "Advantech",  # Advantech Gateways
    "31823": "SEL",  # Schweitzer Engineering
    "789": "NetApp",  # NetApp storage
    "1718": "ServerTech",  # Server Technology PDU
}

# Build WALK_LISTS from VENDOR_OIDS: vendor name -> list of enterprise subtrees
for _pen, _name in VENDOR_OIDS.items():
    _key = _name.lower().replace(" ", "_").replace("&", "and")
    WALK_LISTS.setdefault(_key, []).append(f".1.3.6.1.4.1.{_pen}")
WALK_LISTS["all"] = [f".1.3.6.1.4.1.{pen}" for pen in VENDOR_OIDS]
WALK_LISTS["enterprise"] = [".1.3.6.1.4.1"]

# Vendor-specific OIDs for extra device information
# Sources: MIB files, vendor documentation, verified via SNMP walk
# NOTE: Only vendor-specific OIDs (no generic ENTITY-MIB .1.3.6.1.2.1.47)
VENDOR_SPECIFIC_OIDS = {
    # === INDUSTRIAL ETHERNET SWITCHES ===
    "Hirschmann": {
        # PEN: 248 - Verified from LibreNMS HMPRIV-MGMT-SNMP-MIB
        "Serial": ".1.3.6.1.4.1.248.14.1.1.9.1.10.1",  # hmSysGroupSerialNum
        "SW_Version": ".1.3.6.1.4.1.248.14.1.1.9.1.5.1",  # hmSysGroupSwVersion
        "HW_Version": ".1.3.6.1.4.1.248.14.1.1.9.1.4.1",  # hmSysGroupHwVersion
        "FW_Version": ".1.3.6.1.4.1.248.14.1.1.2.0",  # hmSysVersion
        "Boot_Version": ".1.3.6.1.4.1.248.14.1.1.19.0",  # hmSysBootVersion
        "Product": ".1.3.6.1.4.1.248.14.1.1.1.0",  # hmSysProduct
        # MACH3 chassis serial numbers
        "Serial_CPU": ".1.3.6.1.4.1.248.14.1.1.3.3.1.0",  # hmSerialNumCpu
        "Serial_BB": ".1.3.6.1.4.1.248.14.1.1.3.3.2.0",  # hmSerialNumBB (basic board)
        "Serial_BP": ".1.3.6.1.4.1.248.14.1.1.3.3.3.0",  # hmSerialNumBP (backplane)
        # Module serial numbers
        "Mod_Serial": ".1.3.6.1.4.1.248.14.1.1.10.1.10.1",  # hmSysModSerialNum
        "Mod_Version": ".1.3.6.1.4.1.248.14.1.1.10.1.5.1",  # hmSysModVersion
        # Power supply
        "PS_Serial": ".1.3.6.1.4.1.248.14.1.1.12.1.3.1",  # hmPSSerialNumber
    },
    "Moxa": {
        # PEN: 8691 - Verified from LibreNMS MOXA-SYSTEM-INFO-MIB, MOXA-IKS6726A-MIB
        # New unified MIB (MOXA-SYSTEM-INFO-MIB)
        "Serial": ".1.3.6.1.4.1.8691.602.1.1.2.2.3.0",  # siStatProductInfoSerialNumber
        "FW_Version": ".1.3.6.1.4.1.8691.602.1.1.2.2.1.0",  # siStatProductInfoFirmwareVersion
        # Legacy switch MIB (MOXA-IKS6726A-MIB, MOXA-EDSG516E-MIB)
        "Model": ".1.3.6.1.4.1.8691.7.116.1.2.0",  # switchModel
        "Legacy_FW": ".1.3.6.1.4.1.8691.7.116.1.4.0",  # firmwareVersion (legacy)
        "Legacy_Serial": ".1.3.6.1.4.1.8691.7.69.1.37.0",  # serialNumber (EDSG516E)
        # NPort series
        "NPort_Model": ".1.3.6.1.4.1.8691.2.8.1.1.1.0",
        "NPort_Serial": ".1.3.6.1.4.1.8691.2.8.1.1.2.0",
    },
    "Ruggedcom": {
        # PEN: 15004 - Siemens Ruggedcom
        "Serial": ".1.3.6.1.4.1.15004.4.2.3.1.0",
        "SW_Version": ".1.3.6.1.4.1.15004.4.2.3.2.0",
        "FW_Version": ".1.3.6.1.4.1.15004.4.2.3.3.0",
    },
    "Phoenix Contact": {
        # PEN: 4346 - Phoenix Contact FL SWITCH
        "Serial": ".1.3.6.1.4.1.4346.11.11.1.2.6.0",  # flWorkFWCtrlSerial
        "FW_Version": ".1.3.6.1.4.1.4346.11.11.1.2.1.0",  # flWorkFWCtrlVersion
    },
    "Westermo": {
        # PEN: 16177
        "Serial": ".1.3.6.1.4.1.16177.1.1.1.3.0",
        "FW_Version": ".1.3.6.1.4.1.16177.1.1.1.4.0",
    },
    # === PLCs / CONTROLLERS ===
    "Siemens": {
        # PEN: 4329 - Siemens SCALANCE/SIMATIC NET
        "Order_Number": ".1.3.6.1.4.1.4329.6.3.2.1.1.2.0",
        "Serial": ".1.3.6.1.4.1.4329.6.3.2.1.1.3.0",
        "HW_Version": ".1.3.6.1.4.1.4329.6.3.2.1.1.4.0",
        "SW_Version": ".1.3.6.1.4.1.4329.6.3.2.1.1.5.0",
    },
    "Schneider": {
        # PEN: 3833 - Schneider Electric/Modicon
        # Verified from LibreNMS PM8ECCMIB and Modicon MIBs
        # Modicon PLC OIDs
        "Module": ".1.3.6.1.4.1.3833.1.7.1.0",
        "Version": ".1.3.6.1.4.1.3833.1.7.2.0",
        "Family": ".1.3.6.1.4.1.3833.1.7.11.0",
        # PM8ECC Power Meter OIDs (3833.1.100)
        "PM_Serial": ".1.3.6.1.4.1.3833.1.100.1.1.4.0",  # midSerialNumber
        "PM_FW_Version": ".1.3.6.1.4.1.3833.1.100.1.1.5.0",  # midFirmwareVersion
        "PM_MIB_Version": ".1.3.6.1.4.1.3833.1.100.1.1.1.0",  # mibVersion
    },
    "B&R": {
        # PEN: 29312 - B&R Automation
        "Module": ".1.3.6.1.4.1.29312.1.1.0",
        "Serial": ".1.3.6.1.4.1.29312.1.2.0",
        "Version": ".1.3.6.1.4.1.29312.1.4.1.0",
        "Hostname": ".1.3.6.1.4.1.29312.1.6.1.0",
    },
    "WAGO": {
        # PEN: 13576 - WAGO PLCs
        "Serial": ".1.3.6.1.4.1.13576.1.1.1.2.0",
        "FW_Version": ".1.3.6.1.4.1.13576.1.1.1.3.0",
        "Model": ".1.3.6.1.4.1.13576.1.1.1.1.0",
        # IO-Check MIB
        "FirmwareIndex": ".1.3.6.1.4.1.13576.10.1.10.1.0",
        "HardwareIndex": ".1.3.6.1.4.1.13576.10.1.10.2.0",
        "FwlIndex": ".1.3.6.1.4.1.13576.10.1.10.3.0",
        "IOCheck_Version": ".1.3.6.1.4.1.13576.10.1.10.4.0",
    },
    "Beckhoff": {
        # PEN: 25157 - Beckhoff Automation
        "Serial": ".1.3.6.1.4.1.25157.1.1.1.2.0",
        "FW_Version": ".1.3.6.1.4.1.25157.1.1.1.3.0",
    },
    "Rockwell": {
        # PEN: 95 - Allen-Bradley/Rockwell
        "Serial": ".1.3.6.1.4.1.95.2.2.1.1.3.0",
        "FW_Version": ".1.3.6.1.4.1.95.2.2.1.1.4.0",
    },
    # === POWER AUTOMATION / GRID ===
    "ABB": {
        # PEN: 908 - Verified from LibreNMS ABB-MODULARUPS-MIB
        # upsIdent group: 908.1.1.1.1
        "Model": ".1.3.6.1.4.1.908.1.1.1.1.1.0",  # upsIdentManufacturer
        "FW_Version": ".1.3.6.1.4.1.908.1.1.1.1.3.0",  # upsIdentUPSSoftwareVersion
        "Agent_Version": ".1.3.6.1.4.1.908.1.1.1.1.4.0",  # upsIdentAgentSoftwareVersion
        "Name": ".1.3.6.1.4.1.908.1.1.1.1.5.0",  # upsIdentName
    },
    "Hitachi": {
        # PEN: 116 (Hitachi) - formerly ABB Power Grids / Hitachi Energy
        "Serial": ".1.3.6.1.4.1.116.5.11.4.1.1.6.1.2.0",
        "FW_Version": ".1.3.6.1.4.1.116.5.11.4.1.1.6.1.3.0",
        "Model": ".1.3.6.1.4.1.116.5.11.4.1.1.6.1.1.0",
    },
    "SEL": {
        # PEN: 31823 - Schweitzer Engineering Laboratories
        "Serial": ".1.3.6.1.4.1.31823.1.1.1.0",
        "FW_Version": ".1.3.6.1.4.1.31823.1.1.2.0",
    },
    # === UPS / POWER ===
    "APC": {
        # PEN: 318 - Verified from LibreNMS PowerNet-MIB
        # upsBasicIdent group: 318.1.1.1.1.1
        "Model": ".1.3.6.1.4.1.318.1.1.1.1.1.1.0",  # upsBasicIdentModel
        "Name": ".1.3.6.1.4.1.318.1.1.1.1.1.2.0",  # upsBasicIdentName
        # upsAdvIdent group: 318.1.1.1.1.2
        "FW_Version": ".1.3.6.1.4.1.318.1.1.1.1.2.1.0",  # upsAdvIdentFirmwareRevision
        "Manufacture_Date": ".1.3.6.1.4.1.318.1.1.1.1.2.2.0",  # upsAdvIdentDateOfManufacture
        "Serial": ".1.3.6.1.4.1.318.1.1.1.1.2.3.0",  # upsAdvIdentSerialNumber
    },
    "Eaton": {
        # PEN: 534 - Verified from LibreNMS XUPS-MIB
        # xupsIdent group: 534.1.1
        "Model": ".1.3.6.1.4.1.534.1.1.2.0",  # xupsIdentModel
        "FW_Version": ".1.3.6.1.4.1.534.1.1.3.0",  # xupsIdentSoftwareVersion
        "Part_Number": ".1.3.6.1.4.1.534.1.1.5.0",  # xupsIdentPartNumber
        "Serial": ".1.3.6.1.4.1.534.1.1.6.0",  # xupsIdentSerialNumber
        # xupsAgent group: 534.1.14
        "Agent_Version": ".1.3.6.1.4.1.534.1.14.3.0",  # xupsAgentSoftwareVersion
        "Agent_Serial": ".1.3.6.1.4.1.534.1.14.5.0",  # xupsAgentSerialNumber
    },
    "Vertiv": {
        # PEN: 476 - Liebert (legacy) and PEN: 21239 - Vertiv (new)
        # Verified from LibreNMS VERTIV-V5-MIB
        # New Vertiv MIB (21239.5.2.1 deviceInfo)
        "Model": ".1.3.6.1.4.1.21239.5.2.1.2.0",  # productModel
        "Version": ".1.3.6.1.4.1.21239.5.2.1.3.0",  # productVersion
        "Serial": ".1.3.6.1.4.1.21239.5.2.1.4.0",  # productSerialNumber
        "MAC": ".1.3.6.1.4.1.21239.5.2.1.5.0",  # productMacAddress
        # Legacy Liebert MIB (476.1.42)
        "Legacy_Model": ".1.3.6.1.4.1.476.1.42.2.1.2.0",
        "Legacy_Serial": ".1.3.6.1.4.1.476.1.42.2.1.4.0",
        "Legacy_FW": ".1.3.6.1.4.1.476.1.42.2.1.3.0",
    },
    "Riello": {
        # PEN: 5491 - Riello UPS
        "Model": ".1.3.6.1.4.1.5491.10.1.1.2.0",
        "Serial": ".1.3.6.1.4.1.5491.10.1.1.4.0",
        "FW_Version": ".1.3.6.1.4.1.5491.10.1.1.3.0",
    },
    "Tripp Lite": {
        # PEN: 850 - Tripp Lite
        "Model": ".1.3.6.1.4.1.850.1.1.1.1.0",
        "Serial": ".1.3.6.1.4.1.850.1.1.1.2.0",
        "FW_Version": ".1.3.6.1.4.1.850.1.1.1.3.0",
    },
    "CyberPower": {
        # PEN: 3808 - CyberPower
        "Model": ".1.3.6.1.4.1.3808.1.1.1.1.1.1.0",
        "Serial": ".1.3.6.1.4.1.3808.1.1.1.1.2.3.0",
        "FW_Version": ".1.3.6.1.4.1.3808.1.1.1.1.2.1.0",
    },
    "Delta": {
        # PEN: 2254 - Verified from LibreNMS DeltaUPS-MIB
        "FW_Version": ".1.3.6.1.4.1.2254.2.4.1.1.3.0",  # dupsIdentUPSSoftwareVersion
        "Agent_Version": ".1.3.6.1.4.1.2254.2.4.1.1.4.0",  # dupsIdentAgentSoftwareVersion
    },
    # === NETWORK / SECURITY ===
    "Cisco": {
        # PEN: 9 - Cisco Systems
        "Serial": ".1.3.6.1.4.1.9.3.6.3.0",  # chassisSerialNumberString
        "IOS_Version": ".1.3.6.1.4.1.9.2.1.73.0",  # ciscoVersion
        "Chassis_ID": ".1.3.6.1.4.1.9.3.6.1.0",  # chassisId
        "Catalyst_Serial": ".1.3.6.1.4.1.9.5.1.3.1.1.26.1",  # moduleSerialNumber
    },
    "Juniper": {
        # PEN: 2636 - Juniper Networks
        "Model": ".1.3.6.1.4.1.2636.3.1.2.0",
        "Serial": ".1.3.6.1.4.1.2636.3.1.3.0",
        "Version": ".1.3.6.1.4.1.2636.3.1.4.0",
    },
    "Fortinet": {
        # PEN: 12356 - Fortinet
        "Serial": ".1.3.6.1.4.1.12356.100.1.1.1.0",
        "FW_Version": ".1.3.6.1.4.1.12356.101.4.1.1.0",
    },
    "Palo Alto": {
        # PEN: 25461 - Palo Alto Networks
        "Serial": ".1.3.6.1.4.1.25461.2.1.2.1.3.0",
        "SW_Version": ".1.3.6.1.4.1.25461.2.1.2.1.1.0",
        "HW_Version": ".1.3.6.1.4.1.25461.2.1.2.1.2.0",
    },
    "Check Point": {
        # PEN: 2620 - Check Point
        "Serial": ".1.3.6.1.4.1.2620.1.6.16.3.0",
        "FW_Version": ".1.3.6.1.4.1.2620.1.6.4.1.0",
    },
    "SonicWall": {
        # PEN: 8741 - SonicWall
        "Serial": ".1.3.6.1.4.1.8741.1.3.1.1.0",
        "FW_Version": ".1.3.6.1.4.1.8741.1.3.1.2.0",
    },
    # === ENTERPRISE SWITCHES ===
    "HP": {
        # PEN: 11 - HP / ProCurve
        "Serial": ".1.3.6.1.4.1.11.2.36.1.1.2.9.0",
        "FW_Version": ".1.3.6.1.4.1.11.2.14.11.5.1.1.3.0",
    },
    "Aruba": {
        # PEN: 14823 - Aruba Networks
        "Model": ".1.3.6.1.4.1.14823.2.2.1.2.1.12.0",
        "Serial": ".1.3.6.1.4.1.14823.2.2.1.2.1.13.0",
        "FW_Version": ".1.3.6.1.4.1.14823.2.2.1.2.1.14.0",
    },
    "Extreme Networks": {
        # PEN: 1916 - Extreme Networks
        "Serial": ".1.3.6.1.4.1.1916.1.1.1.18.0",
        "FW_Version": ".1.3.6.1.4.1.1916.1.1.1.13.0",
    },
    "Netgear": {
        # PEN: 4526 - Netgear
        "Serial": ".1.3.6.1.4.1.4526.10.1.1.1.4.0",
        "FW_Version": ".1.3.6.1.4.1.4526.11.11.1.0",
    },
    # === WIRELESS / SMB ===
    "MikroTik": {
        # PEN: 14988 - MikroTik
        "Model": ".1.3.6.1.4.1.14988.1.1.7.1.0",
        "Serial": ".1.3.6.1.4.1.14988.1.1.7.3.0",
        "FW_Version": ".1.3.6.1.4.1.14988.1.1.7.4.0",
        "License": ".1.3.6.1.4.1.14988.1.1.4.4.0",
    },
    "Ubiquiti": {
        # PEN: 41112 - Ubiquiti
        "Model": ".1.3.6.1.4.1.41112.1.6.3.1.0",
        "Serial": ".1.3.6.1.4.1.41112.1.6.3.3.0",
        "FW_Version": ".1.3.6.1.4.1.41112.1.6.3.6.0",
    },
    "Zyxel": {
        # PEN: 890 - Zyxel
        "Model": ".1.3.6.1.4.1.890.1.15.3.1.11.0",
        "Serial": ".1.3.6.1.4.1.890.1.15.3.1.12.0",
        "FW_Version": ".1.3.6.1.4.1.890.1.15.3.1.6.0",
    },
    # === BUILDING AUTOMATION ===
    "Tridium": {
        # PEN: 4131 - Tridium/Niagara
        "SW_Version": ".1.3.6.1.4.1.4131.1.1.0",
    },
    "Johnson Controls": {
        # PEN: 4399 - Johnson Controls
        "Serial": ".1.3.6.1.4.1.4399.2.1.1.1.0",
        "FW_Version": ".1.3.6.1.4.1.4399.2.1.1.2.0",
    },
    # === GATEWAYS / RTUs ===
    "Advantech": {
        # PEN: 10297 (EKI switches) and PEN: 30140 (gateways)
        # Verified from LibreNMS ADVANTECH-EKI-PRONEER-MIB
        # EKI Switch MIB (10297.101.1.1)
        "Loader_Version": ".1.3.6.1.4.1.10297.101.1.1.2.0",  # loaderVersion
        "FW_Version": ".1.3.6.1.4.1.10297.101.1.1.3.0",  # firmwareVersion
        "FW_Date": ".1.3.6.1.4.1.10297.101.1.1.4.0",  # firmwareDate
        "Build_Version": ".1.3.6.1.4.1.10297.101.1.1.5.0",  # buildVersion
        # Gateway MIB (30140.6)
        "Model": ".1.3.6.1.4.1.30140.6.1.0",
        "Gateway_FW": ".1.3.6.1.4.1.30140.6.2.0",
        "Serial": ".1.3.6.1.4.1.30140.6.3.0",
        "IMEI": ".1.3.6.1.4.1.30140.6.4.0",
    },
    "Red Lion": {
        # PEN: 1890 - Red Lion Controls
        "Serial": ".1.3.6.1.4.1.1890.1.2.1.1.0",
        "FW_Version": ".1.3.6.1.4.1.1890.1.2.1.2.0",
    },
    "Lantronix": {
        # PEN: 244 - Lantronix
        "Serial": ".1.3.6.1.4.1.244.1.1.4.0",
        "FW_Version": ".1.3.6.1.4.1.244.1.1.3.0",
    },
    # === STORAGE ===
    "Synology": {
        # PEN: 6574 - Synology
        "Model": ".1.3.6.1.4.1.6574.1.5.1.0",
        "Serial": ".1.3.6.1.4.1.6574.1.5.2.0",
        "FW_Version": ".1.3.6.1.4.1.6574.1.5.3.0",
    },
    "QNAP": {
        # PEN: 24681 - QNAP
        "Model": ".1.3.6.1.4.1.24681.1.2.12.0",
        "Serial": ".1.3.6.1.4.1.24681.1.2.17.0",
        "FW_Version": ".1.3.6.1.4.1.24681.1.2.18.0",
    },
    "NetApp": {
        # PEN: 789 - NetApp
        "Model": ".1.3.6.1.4.1.789.1.1.5.0",
        "Serial": ".1.3.6.1.4.1.789.1.1.9.0",
        "FW_Version": ".1.3.6.1.4.1.789.1.1.2.0",
    },
    # === ENVIRONMENTAL / PDU ===
    "AKCP": {
        # PEN: 3854 - AKCP
        "Serial": ".1.3.6.1.4.1.3854.1.2.2.1.1.0",
        "FW_Version": ".1.3.6.1.4.1.3854.1.2.2.1.3.0",
    },
    "Raritan": {
        # PEN: 13742 - Raritan
        "FW_Version": ".1.3.6.1.4.1.13742.4.1.1.1.0",
        "Serial": ".1.3.6.1.4.1.13742.4.1.1.5.0",
    },
    "ServerTech": {
        # PEN: 1718 - Server Technology
        "Serial": ".1.3.6.1.4.1.1718.3.1.1.0",
        "FW_Version": ".1.3.6.1.4.1.1718.3.1.6.0",
    },
}

# VACM (View-based Access Control Model) OIDs — RFC 3415
VACM_OIDS = {
    "vacmAccessReadViewName": ".1.3.6.1.6.3.16.1.4.1.5",
    "vacmAccessWriteViewName": ".1.3.6.1.6.3.16.1.4.1.6",
}

# HOST-RESOURCES-MIB (RFC 2790)
HOST_RESOURCE_OIDS = {
    "hrSWRunName": ".1.3.6.1.2.1.25.4.2.1.2",
    "hrSWRunPath": ".1.3.6.1.2.1.25.4.2.1.4",
    "hrSWRunParameters": ".1.3.6.1.2.1.25.4.2.1.5",
    "hrSWRunType": ".1.3.6.1.2.1.25.4.2.1.6",
    "hrSWRunStatus": ".1.3.6.1.2.1.25.4.2.1.7",
    "hrSWInstalledName": ".1.3.6.1.2.1.25.6.3.1.2",
    "hrSWInstalledType": ".1.3.6.1.2.1.25.6.3.1.4",
    "hrSWInstalledDate": ".1.3.6.1.2.1.25.6.3.1.5",
    "hrStorageDescr": ".1.3.6.1.2.1.25.2.3.1.3",
    "hrStorageType": ".1.3.6.1.2.1.25.2.3.1.2",
    "hrStorageAllocationUnits": ".1.3.6.1.2.1.25.2.3.1.4",
    "hrStorageSize": ".1.3.6.1.2.1.25.2.3.1.5",
    "hrStorageUsed": ".1.3.6.1.2.1.25.2.3.1.6",
    # hrSWRunPerfTable (RFC 2790) — per-process performance
    "hrSWRunPerfCPU": ".1.3.6.1.2.1.25.5.1.1.1",
    "hrSWRunPerfMem": ".1.3.6.1.2.1.25.5.1.1.2",
}

# Network enumeration OIDs (MIB-2)
NETWORK_ENUM_OIDS = {
    # Interface table columns
    "ifDescr": ".1.3.6.1.2.1.2.2.1.2",
    "ifType": ".1.3.6.1.2.1.2.2.1.3",
    "ifSpeed": ".1.3.6.1.2.1.2.2.1.5",
    "ifPhysAddress": ".1.3.6.1.2.1.2.2.1.6",
    "ifOperStatus": ".1.3.6.1.2.1.2.2.1.8",
    "ifInOctets": ".1.3.6.1.2.1.2.2.1.10",
    "ifOutOctets": ".1.3.6.1.2.1.2.2.1.16",
    # TCP connection table columns
    "tcpConnState": ".1.3.6.1.2.1.6.13.1.1",
    # UDP listener table
    "udpLocalAddress": ".1.3.6.1.2.1.7.5.1.1",
    # IP routing table columns
    "ipRouteDest": ".1.3.6.1.2.1.4.21.1.1",
    "ipRouteNextHop": ".1.3.6.1.2.1.4.21.1.7",
    "ipRouteMask": ".1.3.6.1.2.1.4.21.1.11",
    "ipRouteIfIndex": ".1.3.6.1.2.1.4.21.1.2",
    "ipRouteType": ".1.3.6.1.2.1.4.21.1.8",
    # IP address table columns (ipAddrTable)
    "ipAdEntAddr": ".1.3.6.1.2.1.4.20.1.1",
    "ipAdEntIfIndex": ".1.3.6.1.2.1.4.20.1.2",
    "ipAdEntNetMask": ".1.3.6.1.2.1.4.20.1.3",
}

# Windows LanManager MIB OIDs
WINDOWS_OIDS = {
    "svUserName": ".1.3.6.1.4.1.77.1.2.25.1.1",
    "svShareName": ".1.3.6.1.4.1.77.1.2.27.1.1",
    "svSharePath": ".1.3.6.1.4.1.77.1.2.27.1.2",
    "svShareComment": ".1.3.6.1.4.1.77.1.2.27.1.3",
    "domPrimaryDomain": ".1.3.6.1.4.1.77.1.4.1.0",
}

# Windows LanManager Services MIB OIDs
WINDOWS_SERVICE_OIDS = {
    "svSvcName": ".1.3.6.1.4.1.77.1.2.3.1.1",
    "svSvcInstalledState": ".1.3.6.1.4.1.77.1.2.3.1.2",
    "svSvcOperatingState": ".1.3.6.1.4.1.77.1.2.3.1.3",
}

# HOST-RESOURCES-MIB Filesystem table (RFC 2790)
FILESYSTEM_OIDS = {
    "hrFSMountPoint": ".1.3.6.1.2.1.25.3.8.1.2",
    "hrFSRemoteMountPoint": ".1.3.6.1.2.1.25.3.8.1.3",
    "hrFSType": ".1.3.6.1.2.1.25.3.8.1.4",
    "hrFSAccess": ".1.3.6.1.2.1.25.3.8.1.5",  # 1=readWrite, 2=readOnly
}

# Trap configuration OIDs (SNMP-TARGET-MIB, SNMP-COMMUNITY-MIB)
TRAP_CONFIG_OIDS = {
    "snmpTargetAddrTAddress": ".1.3.6.1.6.3.12.1.2.1.3",
    "snmpTargetAddrParams": ".1.3.6.1.6.3.12.1.2.1.7",
    "snmpTargetParamsSecurityName": ".1.3.6.1.6.3.12.1.3.1.4",
    "snmpCommunityName": ".1.3.6.1.6.3.18.1.1.1.2",
}

# Credential hunting OIDs — walked by --enum creds
CREDENTIAL_OIDS = {
    # Standard: additional community strings (SNMP-COMMUNITY-MIB)
    "snmpCommunityName": ".1.3.6.1.6.3.18.1.1.1.2",
    "snmpCommunitySecurityName": ".1.3.6.1.6.3.18.1.1.1.3",
    # Standard: SNMPv3 usernames (USM user table)
    "usmUserSecurityName": ".1.3.6.1.6.3.15.1.2.2.1.3",
    # Standard: trap destination credentials (SNMP-TARGET-MIB)
    "snmpTargetParamsSecurityName": ".1.3.6.1.6.3.12.1.3.1.4",
    # Cisco: IOS version (for exploit targeting)
    "ciscoVersion": ".1.3.6.1.4.1.9.2.1.73",
    # Huawei/H3C: user table with passwords (old PEN 2011)
    "h3cUserName": ".1.3.6.1.4.1.2011.10.2.12.1.1.1.1",
    "h3cUserPassword": ".1.3.6.1.4.1.2011.10.2.12.1.1.1.2",
    "h3cUserLevel": ".1.3.6.1.4.1.2011.10.2.12.1.1.1.4",
    # H3C: user table with passwords (new PEN 25506)
    "hh3cUserName": ".1.3.6.1.4.1.25506.2.12.1.1.1.1",
    "hh3cUserPassword": ".1.3.6.1.4.1.25506.2.12.1.1.1.2",
    "hh3cUserLevel": ".1.3.6.1.4.1.25506.2.12.1.1.1.4",
    # H3C user state (old + new PEN) — completes user/password/level set
    "h3cUserState": ".1.3.6.1.4.1.2011.10.2.12.1.1.1.5",
    "hh3cUserState": ".1.3.6.1.4.1.25506.2.12.1.1.1.5",
    # Brocade ADX: admin users + password hashes (PEN 1991)
    "brocadeAdxAdminUser": ".1.3.6.1.4.1.1991.1.1.2.9.2.1.1",
    "brocadeAdxAdminPassword": ".1.3.6.1.4.1.1991.1.1.2.9.2.1.2",
    # Ambit U10C019: cable modem users + passwords (PEN 4684)
    "ambitUser": ".1.3.6.1.4.1.4684.2.17.1.1.1.1",
    "ambitPassword": ".1.3.6.1.4.1.4684.2.17.1.1.1.2",
    # Netopia 3347: wireless credentials (PEN 304)
    "netopiaWepKey": ".1.3.6.1.4.1.304.1.3.1.26.1.14.1.4",
    "netopiaWpaPsk": ".1.3.6.1.4.1.304.1.3.1.26.1.14.1.9",
    "netopiaSsid": ".1.3.6.1.4.1.304.1.3.1.26.1.14.1.3",
}

# IPv6 address table OIDs (RFC 4293 ipAddressTable)
IPV6_ENUM_OIDS = {
    "ipAddressIfIndex": ".1.3.6.1.2.1.4.34.1.3",  # maps addr type+bytes → ifIndex
}

# NET-SNMP Extend OIDs (nsExtendObjects)
NETSNMP_EXTEND_OIDS = {
    "nsExtendCommand": ".1.3.6.1.4.1.8072.1.3.2.2.1.2",  # command path
    "nsExtendArgs": ".1.3.6.1.4.1.8072.1.3.2.2.1.3",  # arguments
    "nsExtendExecType": ".1.3.6.1.4.1.8072.1.3.2.2.1.6",  # exec(1) or shell(2)
    "nsExtendStorage": ".1.3.6.1.4.1.8072.1.3.2.2.1.8",  # permanent(4)/volatile(2)
    "nsExtendStatus": ".1.3.6.1.4.1.8072.1.3.2.2.1.9",  # row status
    "nsExtendOutput1Line": ".1.3.6.1.4.1.8072.1.3.2.3.1.1",  # first line of output
    "nsExtendResult": ".1.3.6.1.4.1.8072.1.3.2.3.1.3",  # exit code
}

# Credential patterns for process argument scanning (hrSWRunParameters)
#
# Two-level system:
#   CRED_PATTERNS — high-confidence, context-free (matched against all processes)
#   CRED_PATTERNS_CONTEXT — process-name-aware (only matched when name matches key)
#
# Sources: HTB writeups (Pandora, Mischief, Mentor), LinPEAS, GitGuardian,
# secrets-patterns-db, Metasploit snmp_enum, real-world pentesting patterns.

# Level 1: High-confidence patterns (no process name context needed)
# These match against hrSWRunParameters (args only, NOT process name).
CRED_PATTERNS = [
    # Long-form password/secret flags (generic, works for most tools)
    r"--(?:password|passwd|pwd|secret(?:-key)?|token|api[_-]?key|auth[_-]?(?:token|key|pass)"
    r"|access[_-]?key|private[_-]?key|client[_-]?secret|vault-password(?:-file)?"
    r"|password-file|http-password|db-password)[= ](\S+)",
    # Short-form: password=, passwd=, pwd=, secret=, token=, api_key= (key=value style)
    # Word boundary prevents matching "MySecret" or "mqtt_secret" as false positives
    r"(?<!\w)(?:password|passwd|pwd|secret|token|api[_-]?key)[= ](\S+)",
    # URIs with embedded credentials: scheme://user:pass@host
    # Supports +/- in schemes (mongodb+srv://), non-word chars in user/pass
    r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]{1,64}:[^/\s:@]{1,64}@[^\s]+",
]

# Level 2: Process-name-aware patterns (only matched when hrSWRunName matches key)
# Keys are regex patterns matched against the process name (case-insensitive).
# This avoids false positives like `ssh -p 22` or `mkdir -p`.
CRED_PATTERNS_CONTEXT = {
    # Sshpass — the #1 HTB SNMP finding (Pandora, Mentor)
    r"sshpass": [
        r"-p\s+(\S+)",
    ],
    # Curl with credentials: -u user:pass, --user user:pass
    r"curl": [
        r"(?:-u|--user)\s+(\S+:\S+)",
    ],
    # Wget with password
    r"wget": [
        r"--(?:http-)?password[= ](\S+)",
    ],
    # LDAP tools: ldapsearch -w password, ldapmodify -w password
    r"ldap": [
        r"-w\s+(\S+)",
    ],
    # Redis auth: redis-cli -a password
    r"redis-cli": [
        r"-a\s+(\S+)",
    ],
    # MQTT: mosquitto_pub/sub -P password
    r"mosquitto_(?:pub|sub)": [
        r"-P\s+(\S+)",
    ],
    # Docker/Podman login: -p password
    r"docker|podman": [
        r"(?:-p\s+|--password[= ])(\S+)",
    ],
    # SMB: smbclient -U user%password
    r"smbclient": [
        r"-U\s+\S+%(\S+)",
    ],
    # MySQL/MariaDB: -pPASSWORD (no space after -p)
    r"mysql|mariadb|mysqldump|mysqlimport|mysqladmin": [
        r"-p(\S+)",
    ],
    # MongoDB: mongosh --password VALUE, mongodb://user:pass@host
    r"mongosh?|mongodump|mongorestore|mongoexport|mongoimport": [
        r"--password[= ](\S+)",
        r"mongodb(?:\+srv)?://\w+:\S+@",
    ],
    # PostgreSQL: psql postgres://user:pass@host
    r"psql|pg_dump|pg_restore|pg_basebackup": [
        r"(?:postgresql|postgres)://\w+:\S+@",
    ],
    # SQL Server: sqlcmd -P password
    r"sqlcmd|osql|bcp": [
        r"-P\s+(\S+)",
    ],
    # RDP clients: xfreerdp /p:password, rdesktop -p password
    r"xfreerdp|rdesktop|freerdp": [
        r"(?:/p:|--password[= ]|-p\s+)(\S+)",
    ],
    # Ansible vault
    r"ansible": [
        r"--vault-password(?:-file)?[= ](\S+)",
    ],
    # OpenVPN auth file
    r"openvpn": [
        r"--(?:auth-user-pass|tls-auth|secret)\s+(\S+)",
    ],
    # Kubectl with bearer token
    r"kubectl": [
        r"--token[= ](\S+)",
    ],
    # FTP clients
    r"lftp|ncftp|ftp": [
        r"-u\s+\S+,(\S+)",
        r"(?:-p|--password)[= ]\s*(\S+)",
    ],
    # Rsync password file
    r"rsync": [
        r"--password-file[= ](\S+)",
    ],
    # Archive tools: 7z -pPASSWORD, zip -P PASSWORD
    r"7z|7za": [
        r"-p(\S+)",
    ],
    r"zip": [
        r"-P\s+(\S+)",
    ],
    # Backup tools: restic, borg, duplicity
    r"restic|borg|duplicity": [
        r"--password[= ](\S+)",
    ],
    # AWS CLI
    r"aws": [
        r"(?:--secret-key|aws_secret_access_key)[= ](\S+)",
    ],
    # Azure CLI
    r"az": [
        r"(?:-p|--password|--client-secret)[= ]\s*(\S+)",
    ],
    # InfluxDB / Cassandra
    r"influx|cqlsh": [
        r"(?:--password[= ]|-p\s+)(\S+)",
    ],
}

# Lookup tables for decoding enumeration values
TCP_STATES = {
    1: "closed",
    2: "listen",
    3: "synSent",
    4: "synReceived",
    5: "established",
    6: "finWait1",
    7: "finWait2",
    8: "closeWait",
    9: "lastAck",
    10: "closing",
    11: "timeWait",
    12: "deleteTCB",
}

HR_SW_RUN_STATUS = {1: "running", 2: "runnable", 3: "notRunnable", 4: "invalid"}
HR_SW_RUN_TYPE = {1: "unknown", 2: "operatingSystem", 3: "deviceDriver", 4: "application"}

IP_ROUTE_TYPES = {1: "other", 2: "invalid", 3: "direct", 4: "indirect"}

IF_OPER_STATUS = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "notPresent",
    7: "lowerLayerDown",
}

HR_STORAGE_TYPES = {
    ".1.3.6.1.2.1.25.2.1.1": "Other",
    ".1.3.6.1.2.1.25.2.1.2": "RAM",
    ".1.3.6.1.2.1.25.2.1.3": "VirtualMemory",
    ".1.3.6.1.2.1.25.2.1.4": "FixedDisk",
    ".1.3.6.1.2.1.25.2.1.5": "RemovableDisk",
    ".1.3.6.1.2.1.25.2.1.9": "FlashMemory",
    ".1.3.6.1.2.1.25.2.1.10": "NetworkDisk",
}

# Known ICS protocol ports for security analysis
ICS_PORTS = {
    102: "S7/MMS",
    502: "Modbus",
    2404: "IEC-104",
    4840: "OPC-UA",
    4843: "OPC-UA-TLS",
    20000: "DNP3",
    44818: "EtherNet/IP",
    47808: "BACnet",
    48898: "ADS",
    1089: "FF-HSE",
    34962: "PROFINET",
    34963: "PROFINET",
    34964: "PROFINET",
}

# Enumeration category definitions
ENUM_CATEGORIES = {
    "interfaces": "Network interfaces",
    "tcp": "TCP connections",
    "udp": "UDP listeners",
    "routes": "IP routing table",
    "arp": "ARP table (ipNetToMediaTable)",
    "cam": "CAM/MAC forwarding table (dot1dTpFdbTable)",
    "processes": "Running processes",
    "software": "Installed software",
    "storage": "Storage/disks",
    "users": "Windows user accounts (LanManager MIB)",
    "shares": "Windows shares",
    "traps": "Trap configuration",
    "creds": "Credential hunting",
    "system": "System details (date, forwarding, TTL, TCP stats)",
    "services": "Windows services",
    "filesystems": "Mounted filesystems",
    "ipv6": "IPv6 addresses (ipAddressTable)",
    "extend": "NET-SNMP extend scripts (RCE detection)",
}
