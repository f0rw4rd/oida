#!/usr/bin/env python3
"""pass_persist handler for OIDA SNMP mock enterprise OIDs.

net-snmp pass_persist protocol:
  stdin:  PING         -> stdout: PONG
  stdin:  get\n<oid>   -> stdout: <oid>\n<type>\n<value>  (or NONE)
  stdin:  getnext\n<oid> -> stdout: <oid>\n<type>\n<value> (or NONE)
  stdin:  set\n<oid>\n<type>\n<value> -> stdout: not-writable

Usage:
  pass_persist .1.3.6.1.4.1.77 /usr/local/bin/pass_persist.py --subtree lanmanager
  pass_persist .1.3.6.1.4.1.2011 /usr/local/bin/pass_persist.py --subtree h3c
  pass_persist .1.3.6.1.4.1.25506 /usr/local/bin/pass_persist.py --subtree h3c-new
  pass_persist .1.3.6.1.2.1.17 /usr/local/bin/pass_persist.py --subtree bridge
"""

import sys

# =============================================================================
# Data trees - each maps OID string -> (type, value)
# =============================================================================

# Windows LanManager MIB (PEN 77)
# svUserName: .1.3.6.1.4.1.77.1.2.25.1.1.<index>
# svShareName/Path/Comment: .1.3.6.1.4.1.77.1.2.27.1.{1,2,3}.<index>
# svSvcName/InstalledState/OperatingState: .1.3.6.1.4.1.77.1.2.3.1.{1,2,3}.<index>
# domPrimaryDomain: .1.3.6.1.4.1.77.1.4.1.0
LANMANAGER_DATA = {
    # svUserName table - Windows user accounts
    ".1.3.6.1.4.1.77.1.2.25.1.1.1": ("string", "Administrator"),
    ".1.3.6.1.4.1.77.1.2.25.1.1.2": ("string", "Guest"),
    ".1.3.6.1.4.1.77.1.2.25.1.1.3": ("string", "OPCuser"),
    ".1.3.6.1.4.1.77.1.2.25.1.1.4": ("string", "SCADAadmin"),
    ".1.3.6.1.4.1.77.1.2.25.1.1.5": ("string", "HistorianSvc"),
    # svSvcName table - Windows service names
    ".1.3.6.1.4.1.77.1.2.3.1.1.1": ("string", "OPCServer"),
    ".1.3.6.1.4.1.77.1.2.3.1.1.2": ("string", "ModbusTCP"),
    ".1.3.6.1.4.1.77.1.2.3.1.1.3": ("string", "Historian"),
    ".1.3.6.1.4.1.77.1.2.3.1.1.4": ("string", "WinDefend"),
    # svSvcInstalledState - 1=installed for all
    ".1.3.6.1.4.1.77.1.2.3.1.2.1": ("integer", "1"),
    ".1.3.6.1.4.1.77.1.2.3.1.2.2": ("integer", "1"),
    ".1.3.6.1.4.1.77.1.2.3.1.2.3": ("integer", "1"),
    ".1.3.6.1.4.1.77.1.2.3.1.2.4": ("integer", "1"),
    # svSvcOperatingState - 1=active, 2=paused
    ".1.3.6.1.4.1.77.1.2.3.1.3.1": ("integer", "1"),
    ".1.3.6.1.4.1.77.1.2.3.1.3.2": ("integer", "1"),
    ".1.3.6.1.4.1.77.1.2.3.1.3.3": ("integer", "1"),
    ".1.3.6.1.4.1.77.1.2.3.1.3.4": ("integer", "2"),
    # svShareName table - share names
    ".1.3.6.1.4.1.77.1.2.27.1.1.1": ("string", "C$"),
    ".1.3.6.1.4.1.77.1.2.27.1.1.2": ("string", "ADMIN$"),
    ".1.3.6.1.4.1.77.1.2.27.1.1.3": ("string", "IPC$"),
    ".1.3.6.1.4.1.77.1.2.27.1.1.4": ("string", "SCADAData"),
    # svSharePath table - share paths
    ".1.3.6.1.4.1.77.1.2.27.1.2.1": ("string", "C:\\"),
    ".1.3.6.1.4.1.77.1.2.27.1.2.2": ("string", "C:\\Windows"),
    ".1.3.6.1.4.1.77.1.2.27.1.2.3": ("string", ""),
    ".1.3.6.1.4.1.77.1.2.27.1.2.4": ("string", "D:\\SCADAData"),
    # svShareComment table - share descriptions
    ".1.3.6.1.4.1.77.1.2.27.1.3.1": ("string", "Default share"),
    ".1.3.6.1.4.1.77.1.2.27.1.3.2": ("string", "Remote Admin"),
    ".1.3.6.1.4.1.77.1.2.27.1.3.3": ("string", "Remote IPC"),
    ".1.3.6.1.4.1.77.1.2.27.1.3.4": ("string", "SCADA historian data"),
    # domPrimaryDomain
    ".1.3.6.1.4.1.77.1.4.1.0": ("string", "ICS-PLANT.LOCAL"),
}

# H3C credential tables - old PEN 2011 (Huawei/H3C legacy)
# h3cUserName/Password/Level/State: .1.3.6.1.4.1.2011.10.2.12.1.1.1.{1,2,4,5}.<index>
H3C_DATA = {
    # h3cUserName
    ".1.3.6.1.4.1.2011.10.2.12.1.1.1.1.1": ("string", "admin"),
    ".1.3.6.1.4.1.2011.10.2.12.1.1.1.1.2": ("string", "monitor"),
    ".1.3.6.1.4.1.2011.10.2.12.1.1.1.1.3": ("string", "operator"),
    # h3cUserPassword
    ".1.3.6.1.4.1.2011.10.2.12.1.1.1.2.1": ("string", "admin123"),
    ".1.3.6.1.4.1.2011.10.2.12.1.1.1.2.2": ("string", "monitor1"),
    ".1.3.6.1.4.1.2011.10.2.12.1.1.1.2.3": ("string", "oper@tor"),
    # h3cUserLevel - 3=admin, 1=monitor, 2=operator
    ".1.3.6.1.4.1.2011.10.2.12.1.1.1.4.1": ("integer", "3"),
    ".1.3.6.1.4.1.2011.10.2.12.1.1.1.4.2": ("integer", "1"),
    ".1.3.6.1.4.1.2011.10.2.12.1.1.1.4.3": ("integer", "2"),
    # h3cUserState - 1=active, 2=blocked (P2 addition)
    ".1.3.6.1.4.1.2011.10.2.12.1.1.1.5.1": ("integer", "1"),
    ".1.3.6.1.4.1.2011.10.2.12.1.1.1.5.2": ("integer", "1"),
    ".1.3.6.1.4.1.2011.10.2.12.1.1.1.5.3": ("integer", "2"),
}

# H3C credential tables - new PEN 25506 (H3C post-split)
# hh3cUserName/Password/Level/State: .1.3.6.1.4.1.25506.2.12.1.1.1.{1,2,4,5}.<index>
H3C_NEW_DATA = {
    # hh3cUserName
    ".1.3.6.1.4.1.25506.2.12.1.1.1.1.1": ("string", "admin"),
    ".1.3.6.1.4.1.25506.2.12.1.1.1.1.2": ("string", "monitor"),
    ".1.3.6.1.4.1.25506.2.12.1.1.1.1.3": ("string", "operator"),
    # hh3cUserPassword
    ".1.3.6.1.4.1.25506.2.12.1.1.1.2.1": ("string", "admin123"),
    ".1.3.6.1.4.1.25506.2.12.1.1.1.2.2": ("string", "monitor1"),
    ".1.3.6.1.4.1.25506.2.12.1.1.1.2.3": ("string", "oper@tor"),
    # hh3cUserLevel
    ".1.3.6.1.4.1.25506.2.12.1.1.1.4.1": ("integer", "3"),
    ".1.3.6.1.4.1.25506.2.12.1.1.1.4.2": ("integer", "1"),
    ".1.3.6.1.4.1.25506.2.12.1.1.1.4.3": ("integer", "2"),
    # hh3cUserState - 1=active, 2=blocked (P2 addition)
    ".1.3.6.1.4.1.25506.2.12.1.1.1.5.1": ("integer", "1"),
    ".1.3.6.1.4.1.25506.2.12.1.1.1.5.2": ("integer", "1"),
    ".1.3.6.1.4.1.25506.2.12.1.1.1.5.3": ("integer", "2"),
}

# Brocade ADX admin users - PEN 1991 (P2 addition)
# brocadeAdxAdminUser/Password: .1.3.6.1.4.1.1991.1.1.2.9.2.1.{1,2}.<index>
BROCADE_DATA = {
    # brocadeAdxAdminUser
    ".1.3.6.1.4.1.1991.1.1.2.9.2.1.1.1": ("string", "admin"),
    ".1.3.6.1.4.1.1991.1.1.2.9.2.1.1.2": ("string", "readonly"),
    # brocadeAdxAdminPassword (hashed)
    ".1.3.6.1.4.1.1991.1.1.2.9.2.1.2.1": ("string", "$1$abc$hashedpassword"),
    ".1.3.6.1.4.1.1991.1.1.2.9.2.1.2.2": ("string", "$1$def$readonlyhash"),
}

# Bridge MIB - dot1dTpFdb table (MAC forwarding database)
# dot1dTpFdbAddress/Port/Status: .1.3.6.1.2.1.17.4.3.1.{1,2,3}.<index>
# Index is the MAC address encoded as dotted decimal of each octet
BRIDGE_DATA = {
    # dot1dTpFdbAddress - MAC addresses as printable strings
    # Scanner extracts MACs from the OID suffix, not the value, so format doesn't matter
    ".1.3.6.1.2.1.17.4.3.1.1.0.26.43.60.77.1": ("string", "00:1a:2b:3c:4d:01"),
    ".1.3.6.1.2.1.17.4.3.1.1.0.26.43.60.77.2": ("string", "00:1a:2b:3c:4d:02"),
    ".1.3.6.1.2.1.17.4.3.1.1.0.222.173.190.239.1": ("string", "00:de:ad:be:ef:01"),
    ".1.3.6.1.2.1.17.4.3.1.1.0.222.173.190.239.2": ("string", "00:de:ad:be:ef:02"),
    ".1.3.6.1.2.1.17.4.3.1.1.170.187.204.221.238.255": ("string", "aa:bb:cc:dd:ee:ff"),
    # dot1dTpFdbPort - bridge port number
    ".1.3.6.1.2.1.17.4.3.1.2.0.26.43.60.77.1": ("integer", "1"),
    ".1.3.6.1.2.1.17.4.3.1.2.0.26.43.60.77.2": ("integer", "1"),
    ".1.3.6.1.2.1.17.4.3.1.2.0.222.173.190.239.1": ("integer", "2"),
    ".1.3.6.1.2.1.17.4.3.1.2.0.222.173.190.239.2": ("integer", "3"),
    ".1.3.6.1.2.1.17.4.3.1.2.170.187.204.221.238.255": ("integer", "4"),
    # dot1dTpFdbStatus - 3=learned, 5=self
    ".1.3.6.1.2.1.17.4.3.1.3.0.26.43.60.77.1": ("integer", "3"),
    ".1.3.6.1.2.1.17.4.3.1.3.0.26.43.60.77.2": ("integer", "3"),
    ".1.3.6.1.2.1.17.4.3.1.3.0.222.173.190.239.1": ("integer", "3"),
    ".1.3.6.1.2.1.17.4.3.1.3.0.222.173.190.239.2": ("integer", "3"),
    ".1.3.6.1.2.1.17.4.3.1.3.170.187.204.221.238.255": ("integer", "5"),
}

# Map subtree names to data dicts
SUBTREES = {
    "lanmanager": LANMANAGER_DATA,
    "h3c": H3C_DATA,
    "h3c-new": H3C_NEW_DATA,
    "brocade": BROCADE_DATA,
    "bridge": BRIDGE_DATA,
}


def oid_key(oid):
    """Convert dotted OID string to tuple of ints for proper numeric sorting."""
    return tuple(int(x) for x in oid.strip(".").split("."))


def main():
    if len(sys.argv) < 3 or sys.argv[1] != "--subtree":
        sys.stderr.write("Usage: pass_persist.py --subtree <name>\n")
        sys.exit(1)

    subtree_name = sys.argv[2]
    if subtree_name not in SUBTREES:
        sys.stderr.write(f"Unknown subtree: {subtree_name}\n")
        sys.exit(1)

    data = SUBTREES[subtree_name]
    # Sort OIDs numerically for GETNEXT
    sorted_oids = sorted(data.keys(), key=oid_key)

    while True:
        try:
            line = sys.stdin.readline().strip()
        except (EOFError, IOError):
            break

        if not line:
            continue

        if line == "PING":
            sys.stdout.write("PONG\n")
            sys.stdout.flush()
            continue

        if line in ("get", "getnext"):
            cmd = line
            try:
                oid = sys.stdin.readline().strip()
            except (EOFError, IOError):
                break

            if cmd == "get":
                if oid in data:
                    typ, val = data[oid]
                    sys.stdout.write(f"{oid}\n{typ}\n{val}\n")
                else:
                    sys.stdout.write("NONE\n")

            elif cmd == "getnext":
                # Find first OID strictly greater than requested
                oid_tuple = oid_key(oid)
                found = False
                for candidate in sorted_oids:
                    if oid_key(candidate) > oid_tuple:
                        typ, val = data[candidate]
                        sys.stdout.write(f"{candidate}\n{typ}\n{val}\n")
                        found = True
                        break
                if not found:
                    sys.stdout.write("NONE\n")

            sys.stdout.flush()
            continue

        if line == "set":
            # Read OID, type, value lines then reject
            try:
                sys.stdin.readline()  # oid
                sys.stdin.readline()  # type value
            except (EOFError, IOError):
                break
            sys.stdout.write("not-writable\n")
            sys.stdout.flush()
            continue


if __name__ == "__main__":
    main()
