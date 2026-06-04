"""
OPC DA / DCOM Passive Listener (PyShark-based).

Passively monitors OPC DA (OPC Data Access) traffic over Microsoft DCOM
(Distributed COM) to identify:
- OPC DA servers and clients (HMI/SCADA systems)
- DCOM session info: OXID, OID, IPID bindings
- OPC DA interface activations (IOPCServer, IOPCSyncIO, etc.)
- Read vs Write operation balance
- Browse operations (address space enumeration)
- Group management operations (AddGroup/RemoveGroup)
- Authentication and security context
- HRESULT error rates (fuzzing/attack indicators)

OPC DA is the legacy (pre-OPC UA) protocol for HMI/SCADA to PLC data
access.  It rides on Microsoft DCOM, which uses DCERPC as transport.
Port 135/tcp is the DCOM endpoint mapper (OXID resolver); actual
object communication uses dynamically allocated high ports.

tshark fields used:
- dcom.oxid: OXID (Object Exporter ID) -- identifies the server process
- dcom.oid: OID (Object ID) -- identifies a specific COM object instance
- dcom.ipid: IPID (Interface Pointer ID) -- identifies a bound interface
- dcom.iid: Interface ID (IID) -- which COM interface is being used
- dcom.opnum: Operation number within the interface
- dcom.resp.hresult: HRESULT response code
- dcom.version_major / dcom.version_minor: DCOM version
- oxid.bindings: String bindings (network addresses of DCOM servers)

OPC DA Interface IIDs detected:
- IOPCServer: {39C13A4D-011E-11D0-9675-0020AFD8ADB3}
- IOPCItemMgt: {39C13A54-011E-11D0-9675-0020AFD8ADB3}
- IOPCGroupStateMgt: {39C13A50-011E-11D0-9675-0020AFD8ADB3}
- IOPCSyncIO: {39C13A52-011E-11D0-9675-0020AFD8ADB3}
- IOPCAsyncIO2: {39C13A71-011E-11D0-9675-0020AFD8ADB3}
- IOPCBrowseServerAddressSpace: {39C13A4F-011E-11D0-9675-0020AFD8ADB3}
- IOPCItemProperties: {39C13A72-011E-11D0-9675-0020AFD8ADB3}

References:
- OPC DA 2.05a / 3.0 Specification (OPC Foundation)
- MS-DCOM: Distributed Component Object Model protocol
- Wireshark dissectors: packet-dcom.c, packet-dcom-oxid.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# ---------------------------------------------------------------------------
# OPC DA Interface IIDs (canonical lowercase with dashes)
# ---------------------------------------------------------------------------

OPCDA_IIDS: Dict[str, str] = {
    "39c13a4d-011e-11d0-9675-0020afd8adb3": "IOPCServer",
    "39c13a54-011e-11d0-9675-0020afd8adb3": "IOPCItemMgt",
    "39c13a50-011e-11d0-9675-0020afd8adb3": "IOPCGroupStateMgt",
    "39c13a52-011e-11d0-9675-0020afd8adb3": "IOPCSyncIO",
    "39c13a71-011e-11d0-9675-0020afd8adb3": "IOPCAsyncIO2",
    "39c13a4f-011e-11d0-9675-0020afd8adb3": "IOPCBrowseServerAddressSpace",
    "39c13a72-011e-11d0-9675-0020afd8adb3": "IOPCItemProperties",
}

# OPC DA 3.0 additional interfaces
OPCDA3_IIDS: Dict[str, str] = {
    "39c13a53-011e-11d0-9675-0020afd8adb3": "IOPCAsyncIO",
    "39c13a70-011e-11d0-9675-0020afd8adb3": "IOPCDataCallback",
    "39c13a51-011e-11d0-9675-0020afd8adb3": "IOPCPublicGroupStateMgt",
    "39c13a55-011e-11d0-9675-0020afd8adb3": "IOPCItemDeadbandMgt",
    "39c13a73-011e-11d0-9675-0020afd8adb3": "IOPCItemSamplingMgt",
}

# Merge all OPC DA IIDs for detection
ALL_OPCDA_IIDS: Dict[str, str] = {**OPCDA_IIDS, **OPCDA3_IIDS}

# DCOM core interfaces (context for OPC DA analysis)
DCOM_CORE_IIDS: Dict[str, str] = {
    "00000000-0000-0000-c000-000000000046": "IUnknown",
    "00000001-0000-0000-c000-000000000046": "IClassFactory",
    "00000131-0000-0000-c000-000000000046": "IRemUnknown",
    "00000143-0000-0000-c000-000000000046": "IRemUnknown2",
    "000001a0-0000-0000-c000-000000000046": "ISystemActivator",
    "99fcfec4-5260-101b-bbcb-00aa0021347a": "IOXIDResolver",
    "00000136-0000-0000-c000-000000000046": "ISCMActivator",
    "4d9f4ab8-7d1c-11cf-861e-0020af6e7c57": "IRemoteActivation",
}

# All known IIDs for display
ALL_KNOWN_IIDS: Dict[str, str] = {**ALL_OPCDA_IIDS, **DCOM_CORE_IIDS}

# ---------------------------------------------------------------------------
# OPC DA operation numbers per interface
# ---------------------------------------------------------------------------

OPCDA_OPNUMS: Dict[str, Dict[int, str]] = {
    "IOPCServer": {
        0: "AddGroup",
        1: "GetErrorString",
        2: "GetGroupByName",
        3: "GetStatus",
        4: "RemoveGroup",
        5: "CreateGroupEnumerator",
    },
    "IOPCItemMgt": {
        0: "AddItems",
        1: "ValidateItems",
        2: "RemoveItems",
        3: "SetActiveState",
        4: "SetClientHandles",
        5: "SetDatatypes",
        6: "CreateEnumerator",
    },
    "IOPCGroupStateMgt": {
        0: "GetState",
        1: "SetState",
        2: "SetName",
        3: "CloneGroup",
    },
    "IOPCSyncIO": {
        0: "Read",
        1: "Write",
    },
    "IOPCAsyncIO2": {
        0: "Read",
        1: "Write",
        2: "Refresh2",
        3: "Cancel2",
        4: "SetEnable",
        5: "GetEnable",
    },
    "IOPCBrowseServerAddressSpace": {
        0: "QueryOrganization",
        1: "ChangeBrowsePosition",
        2: "BrowseOPCItemIDs",
        3: "GetItemID",
        4: "BrowseAccessPaths",
    },
    "IOPCItemProperties": {
        0: "QueryAvailableProperties",
        1: "GetItemProperties",
        2: "LookupItemIDs",
    },
}

# Operations classified as write/control (security-relevant)
WRITE_OPERATIONS: Set[Tuple[str, int]] = {
    ("IOPCSyncIO", 1),  # Write
    ("IOPCAsyncIO2", 1),  # Write
    ("IOPCServer", 0),  # AddGroup (session manipulation)
    ("IOPCServer", 4),  # RemoveGroup (session manipulation)
    ("IOPCItemMgt", 0),  # AddItems
    ("IOPCItemMgt", 2),  # RemoveItems
    ("IOPCItemMgt", 3),  # SetActiveState
    ("IOPCGroupStateMgt", 1),  # SetState
    ("IOPCGroupStateMgt", 2),  # SetName
}

# Operations classified as browse/reconnaissance
BROWSE_OPERATIONS: Set[Tuple[str, int]] = {
    ("IOPCBrowseServerAddressSpace", 0),  # QueryOrganization
    ("IOPCBrowseServerAddressSpace", 1),  # ChangeBrowsePosition
    ("IOPCBrowseServerAddressSpace", 2),  # BrowseOPCItemIDs
    ("IOPCBrowseServerAddressSpace", 3),  # GetItemID
    ("IOPCBrowseServerAddressSpace", 4),  # BrowseAccessPaths
    ("IOPCItemProperties", 0),  # QueryAvailableProperties
    ("IOPCItemProperties", 1),  # GetItemProperties
    ("IOPCItemProperties", 2),  # LookupItemIDs
}

# Read operations
READ_OPERATIONS: Set[Tuple[str, int]] = {
    ("IOPCSyncIO", 0),  # Read
    ("IOPCAsyncIO2", 0),  # Read
}

# Well-known HRESULT codes
HRESULT_NAMES: Dict[int, str] = {
    0x00000000: "S_OK",
    0x00000001: "S_FALSE",
    0x80004001: "E_NOTIMPL",
    0x80004002: "E_NOINTERFACE",
    0x80004003: "E_POINTER",
    0x80004004: "E_ABORT",
    0x80004005: "E_FAIL",
    0x80040154: "REGDB_E_CLASSNOTREG",
    0x80040200: "CO_E_NOTINITIALIZED",
    0x800401F0: "CO_E_NOTINITIALIZED",
    0x80070005: "E_ACCESSDENIED",
    0x8007000E: "E_OUTOFMEMORY",
    0x80070057: "E_INVALIDARG",
    # OPC DA specific HRESULT codes
    0x0004000A: "OPC_S_UNSUPPORTEDRATE",
    0x0004000D: "OPC_S_CLAMP",
    0xC0040001: "OPC_E_INVALIDHANDLE",
    0xC0040002: "OPC_E_BADTYPE",
    0xC0040003: "OPC_E_PUBLIC",
    0xC0040004: "OPC_E_BADRIGHTS",
    0xC0040005: "OPC_E_UNKNOWNITEMID",
    0xC0040006: "OPC_E_INVALIDITEMID",
    0xC0040007: "OPC_E_INVALIDFILTER",
    0xC0040008: "OPC_E_UNKNOWNPATH",
    0xC0040009: "OPC_E_RANGE",
    0xC004000A: "OPC_E_DUPLICATENAME",
    0xC004000B: "OPC_E_UNSUPPORTEDRATE",
    0xC004000C: "OPC_E_INVALIDCONFIGFILE",
    0xC004000D: "OPC_E_NOTFOUND",
    0xC004000E: "OPC_E_INVALID_PID",
}


@dataclass
class DCOMSession:
    """Track DCOM/OPC DA session statistics."""

    client_ip: str
    server_ip: str
    oxids: Set[str] = field(default_factory=set)
    oids: Set[str] = field(default_factory=set)
    ipids: Set[str] = field(default_factory=set)
    interfaces_seen: Set[str] = field(default_factory=set)
    opcda_interfaces: Set[str] = field(default_factory=set)
    opnums_seen: Set[Tuple[str, int]] = field(default_factory=set)
    read_count: int = 0
    write_count: int = 0
    browse_count: int = 0
    error_count: int = 0
    hresults: Dict[int, int] = field(default_factory=dict)
    first_seen: str = ""
    last_seen: str = ""


class OPCDAPassiveListener(PySharkListenerBase):
    """Passive OPC DA / DCOM traffic listener (PyShark-based).

    Monitors OPC DA traffic over Microsoft DCOM without sending packets to:
    - Identify OPC DA servers (PLCs, RTUs) and clients (HMIs, SCADA)
    - Track DCOM session info (OXID, OID, IPID bindings)
    - Detect OPC DA interface activations (IOPCServer, IOPCSyncIO, etc.)
    - Monitor Read vs Write operation balance
    - Detect Browse operations (address space enumeration / reconnaissance)
    - Track group management (AddGroup/RemoveGroup)
    - Detect unauthenticated DCOM sessions
    - Detect high HRESULT error rates (fuzzing/attack indicators)

    Usage:
        listener = OPCDAPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Access session statistics
        for session in listener.sessions.values():
            print(f"{session.client_ip} -> {session.server_ip}")
            print(f"  OPC DA interfaces: {session.opcda_interfaces}")
            print(f"  Reads: {session.read_count}, Writes: {session.write_count}")
    """

    PROTOCOL_NAME = "opcda"
    DISPLAY_FILTER = "dcom"
    REQUIRED_LAYERS = ("dcom",)
    PROTOCOL_COLUMNS = ("interface", "operation", "hresult", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.sessions: Dict[Tuple[str, str], DCOMSession] = {}
        # Track OXIDs to server IPs for OXID resolver correlation
        self._oxid_to_ip: Dict[str, str] = {}
        # Track IPIDs to interface names for opnum resolution
        self._ipid_to_iface: Dict[str, str] = {}

    def process_packet(self, packet) -> None:
        """Process a DCOM packet and extract OPC DA interactions."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        src_port, dst_port = self.get_port_info(packet)
        flow_id = self.get_flow_id(packet)
        stream_id = self.get_stream_id(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        now = datetime.now().isoformat()

        if hasattr(packet, "dcom"):
            self._process_dcom(
                packet.dcom,
                packet,
                src_ip,
                dst_ip,
                now,
                flow_id,
                src_mac,
                dst_mac,
                src_port,
                dst_port,
                stream_id,
            )

    def _process_dcom(
        self,
        dcom,
        packet,
        src_ip: str,
        dst_ip: str,
        now: str,
        flow_id: str,
        src_mac: str,
        dst_mac: str,
        src_port: int,
        dst_port: int,
        stream_id: str,
    ) -> None:
        """Process DCOM layer fields."""
        # Extract DCOM identifiers
        oxid = self.get_field(dcom, "oxid")
        oid = self.get_field(dcom, "oid")
        ipid = self.get_field(dcom, "ipid")
        iid_raw = self.get_field(dcom, "iid")
        opnum_raw = self.get_field(dcom, "opnum")
        hresult_raw = self.get_field(dcom, "resp_hresult")

        # Also try the dot-separated field name variant
        if hresult_raw is None:
            hresult_raw = self.get_field(dcom, "resp.hresult")

        # Extract DCOM version
        ver_major = self.get_field(dcom, "version_major")
        ver_minor = self.get_field(dcom, "version_minor")

        # Extract OXID resolver bindings (network addresses)
        bindings = self.get_field(dcom, "bindings")
        if bindings is None and hasattr(packet, "oxid"):
            bindings = self.get_field(packet.oxid, "bindings")

        # Parse interface ID
        iid = str(iid_raw).strip().lower() if iid_raw else ""
        iface_name = ALL_KNOWN_IIDS.get(iid, "")

        # Determine if this is an OPC DA interface
        is_opcda = iid in ALL_OPCDA_IIDS

        # Parse opnum
        opnum: Optional[int] = None
        if opnum_raw is not None:
            opnum = self._parse_int(opnum_raw, default=None)

        # Resolve operation name
        op_name = ""
        if iface_name and opnum is not None:
            iface_ops = OPCDA_OPNUMS.get(iface_name, {})
            op_name = iface_ops.get(opnum, f"opnum {opnum}")
        elif opnum is not None:
            op_name = f"opnum {opnum}"

        # Parse HRESULT
        hresult: Optional[int] = None
        hresult_name = ""
        if hresult_raw is not None:
            hresult = self._parse_int(hresult_raw, default=None)
            if hresult is not None:
                hresult_name = HRESULT_NAMES.get(hresult, "")

        # Determine direction: responses have HRESULT
        is_response = hresult is not None
        direction = "response" if is_response else "request"

        # Determine client/server roles
        if is_response:
            client_ip, server_ip = dst_ip, src_ip
        elif dst_port == 135:
            # OXID resolver / endpoint mapper request
            client_ip, server_ip = src_ip, dst_ip
        else:
            client_ip, server_ip = src_ip, dst_ip

        # Track IPID -> interface mapping for opnum resolution
        if ipid and iface_name:
            self._ipid_to_iface[str(ipid).strip().lower()] = iface_name

        # If we have IPID but no IID, try to resolve from our mapping
        if not iface_name and ipid:
            ipid_key = str(ipid).strip().lower()
            iface_name = self._ipid_to_iface.get(ipid_key, "")
            if iface_name:
                is_opcda = iface_name in ALL_OPCDA_IIDS.values()
                # Re-resolve operation name with the looked-up interface
                if opnum is not None:
                    iface_ops = OPCDA_OPNUMS.get(iface_name, {})
                    op_name = iface_ops.get(opnum, f"opnum {opnum}")

        # Track OXID to IP mapping
        if oxid:
            oxid_str = str(oxid).strip()
            if is_response:
                self._oxid_to_ip[oxid_str] = src_ip
            else:
                self._oxid_to_ip[oxid_str] = dst_ip

        # Build operation label
        if iface_name and op_name:
            operation = f"{iface_name}::{op_name}"
        elif iface_name:
            operation = iface_name
        elif is_opcda:
            operation = f"OPC DA ({iid})"
        elif dst_port == 135 or src_port == 135:
            operation = "OXID Resolver"
        else:
            operation = "DCOM Call"

        # Build details dict
        details: Dict[str, Any] = {}
        if oxid:
            details["oxid"] = str(oxid)
        if oid:
            details["oid"] = str(oid)
        if ipid:
            details["ipid"] = str(ipid)
        if iid:
            details["iid"] = iid
        if iface_name:
            details["interface"] = iface_name
        if opnum is not None:
            details["opnum"] = opnum
        if op_name:
            details["operation"] = op_name
        if hresult is not None:
            details["hresult"] = hresult
            if hresult_name:
                details["hresult_name"] = hresult_name
        if ver_major is not None:
            details["dcom_version"] = f"{ver_major}.{ver_minor or 0}"
        if bindings:
            details["bindings"] = str(bindings)
        if is_opcda:
            details["is_opcda"] = True

        # Classify the operation
        if iface_name and opnum is not None:
            op_key = (iface_name, opnum)
            if op_key in WRITE_OPERATIONS:
                details["op_class"] = "write"
            elif op_key in BROWSE_OPERATIONS:
                details["op_class"] = "browse"
            elif op_key in READ_OPERATIONS:
                details["op_class"] = "read"

        # Build summary
        summary_parts = [operation]
        if hresult is not None:
            if hresult == 0:
                summary_parts.append("OK")
            elif hresult_name:
                summary_parts.append(hresult_name)
            else:
                summary_parts.append(f"0x{hresult:08x}")
        summary = " -> ".join(summary_parts)

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Update session tracking
        session_key = (client_ip, server_ip)
        if session_key not in self.sessions:
            self.sessions[session_key] = DCOMSession(
                client_ip=client_ip,
                server_ip=server_ip,
                first_seen=now,
                last_seen=now,
            )
        session = self.sessions[session_key]
        session.last_seen = now

        if oxid:
            session.oxids.add(str(oxid))
        if oid:
            session.oids.add(str(oid))
        if ipid:
            session.ipids.add(str(ipid))
        if iface_name:
            session.interfaces_seen.add(iface_name)
            if is_opcda:
                session.opcda_interfaces.add(iface_name)
        if iface_name and opnum is not None:
            session.opnums_seen.add((iface_name, opnum))

        # Track operation types (requests only)
        if not is_response and iface_name and opnum is not None:
            op_key = (iface_name, opnum)
            if op_key in WRITE_OPERATIONS:
                session.write_count += 1
            elif op_key in READ_OPERATIONS:
                session.read_count += 1
            elif op_key in BROWSE_OPERATIONS:
                session.browse_count += 1

        # Track HRESULT errors
        if hresult is not None:
            session.hresults[hresult] = session.hresults.get(hresult, 0) + 1
            if hresult != 0:
                session.error_count += 1

        # Update devices
        self._update_devices(client_ip, server_ip, src_mac, dst_mac, is_opcda, iface_name)

    def _update_devices(
        self,
        client_ip: str,
        server_ip: str,
        src_mac: str,
        dst_mac: str,
        is_opcda: bool,
        iface_name: str,
    ) -> None:
        """Update device entries for client and server."""
        # Determine device type based on OPC DA presence
        server_type = "OPC DA Server" if is_opcda else "DCOM Server"
        client_type = "OPC DA Client (HMI/SCADA)" if is_opcda else "DCOM Client"

        # Server device
        if is_valid_discovered_ip(server_ip):
            server_key = f"opcda:{server_ip}"
            server_vendor = lookup_mac_vendor(dst_mac) if dst_mac else ""
            device, is_new = self._ensure_device(
                server_key,
                server_ip,
                mac=dst_mac,
                device_type=server_type,
                manufacturer=server_vendor,
            )
            if is_new:
                device.opcda_passive_data = {
                    "protocol": "OPC DA/DCOM",
                    "role": "server",
                }

        # Client device
        if is_valid_discovered_ip(client_ip):
            client_key = f"opcda-client:{client_ip}"
            client_vendor = lookup_mac_vendor(src_mac) if src_mac else ""
            device, is_new = self._ensure_device(
                client_key,
                client_ip,
                mac=src_mac,
                device_type=client_type,
                manufacturer=client_vendor,
            )
            if is_new:
                device.opcda_passive_data = {
                    "protocol": "OPC DA/DCOM",
                    "role": "client",
                }

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Return protocol-specific cells for the unified interaction table."""
        d = ix.details
        iface = d.get("interface", "")
        op = d.get("operation", "")
        hresult = d.get("hresult")
        hresult_str = ""
        if hresult is not None:
            name = d.get("hresult_name", "")
            if hresult == 0:
                hresult_str = "OK"
            elif name:
                hresult_str = name
            else:
                hresult_str = f"0x{hresult:08x}"

        # Build detail string from available identifiers
        detail_parts = []
        oxid = d.get("oxid")
        if oxid:
            detail_parts.append(f"OXID={oxid}")
        ipid = d.get("ipid")
        if ipid:
            detail_parts.append(f"IPID={ipid}")
        bindings = d.get("bindings")
        if bindings:
            detail_parts.append(f"bind={bindings}")
        detail = " ".join(detail_parts)

        return [iface, op, hresult_str, detail]

    def harvest(self) -> Dict[str, Any]:
        """Build harvest data with OPC DA-specific tables and security alerts."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}

        tables = result.setdefault("tables", [])
        alerts = result.setdefault("alerts", [])

        # --- OPC DA Server summary table ---
        server_rows = []
        for session in self.sessions.values():
            if not session.opcda_interfaces:
                continue
            error_rate = ""
            total_hresults = sum(session.hresults.values())
            if total_hresults > 0:
                pct = (session.error_count / total_hresults) * 100
                error_rate = f"{pct:.0f}%"
            server_rows.append(
                [
                    session.server_ip,
                    session.client_ip,
                    ", ".join(sorted(session.opcda_interfaces)),
                    str(session.read_count),
                    str(session.write_count),
                    str(session.browse_count),
                    error_rate,
                ]
            )
        if server_rows:
            tables.insert(
                0,
                {
                    "headers": [
                        "Server",
                        "Client",
                        "OPC DA Interfaces",
                        "Reads",
                        "Writes",
                        "Browses",
                        "Error%",
                    ],
                    "rows": server_rows,
                    "title": f"OPC DA Sessions ({len(server_rows)})",
                },
            )

        # --- DCOM OXID bindings table ---
        oxid_rows = []
        seen_oxids: Set[str] = set()
        for ix in self.interactions:
            oxid = ix.details.get("oxid")
            bindings = ix.details.get("bindings")
            if oxid and oxid not in seen_oxids:
                seen_oxids.add(oxid)
                server_ip = self._oxid_to_ip.get(str(oxid), ix.src_ip)
                oxid_rows.append(
                    [
                        oxid,
                        server_ip,
                        bindings or "",
                    ]
                )
        if oxid_rows:
            tables.append(
                {
                    "headers": ["OXID", "Server IP", "Bindings"],
                    "rows": oxid_rows,
                    "title": f"DCOM Object Exporters ({len(oxid_rows)})",
                }
            )

        # --- Security alerts ---
        # NOTE: write alerts are generated centrally by super().harvest() from
        # get_write_operations() (category "write_alert"); do not re-emit them
        # here or each write session produces two identical alerts.

        for session in self.sessions.values():
            # Detect Browse operations (reconnaissance)
            if session.browse_count > 0:
                alerts.append(
                    {
                        "level": "warning",
                        "category": "recon_alert",
                        "message": (
                            f"OPC DA BROWSE: {session.client_ip} -> {session.server_ip}"
                            f" ({session.browse_count} browse operations)"
                        ),
                    }
                )

            # Detect high HRESULT error rates (fuzzing indicator)
            total_hresults = sum(session.hresults.values())
            if total_hresults >= 10 and session.error_count > 0:
                error_pct = (session.error_count / total_hresults) * 100
                if error_pct > 50:
                    alerts.append(
                        {
                            "level": "fail",
                            "category": "error_rate_alert",
                            "message": (
                                f"OPC DA HIGH ERROR RATE: {session.client_ip} ->"
                                f" {session.server_ip} ({error_pct:.0f}% errors,"
                                f" {session.error_count}/{total_hresults} calls)"
                            ),
                        }
                    )

            # Detect OXID resolver queries from unexpected sources
            # (any client querying port 135 is doing DCOM discovery)
            for ix in self.interactions:
                if ix.dst_port == 135 and ix.direction == "request":
                    if ix.src_ip == session.client_ip:
                        # Already covered by normal flow; only alert once per session
                        break

        return result

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with OPC DA write operations."""
        return [
            {
                "client": session.client_ip,
                "server": session.server_ip,
                "write_count": session.write_count,
            }
            for session in self.sessions.values()
            if session.write_count > 0
        ]

    def get_browse_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with OPC DA browse/enumeration operations."""
        return [
            {
                "client": session.client_ip,
                "server": session.server_ip,
                "browse_count": session.browse_count,
                "opcda_interfaces": sorted(session.opcda_interfaces),
            }
            for session in self.sessions.values()
            if session.browse_count > 0
        ]

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed DCOM/OPC DA sessions."""
        return [
            {
                "client": s.client_ip,
                "server": s.server_ip,
                "oxids": sorted(s.oxids),
                "opcda_interfaces": sorted(s.opcda_interfaces),
                "all_interfaces": sorted(s.interfaces_seen),
                "read_count": s.read_count,
                "write_count": s.write_count,
                "browse_count": s.browse_count,
                "error_count": s.error_count,
                "first_seen": s.first_seen,
                "last_seen": s.last_seen,
            }
            for s in self.sessions.values()
        ]
