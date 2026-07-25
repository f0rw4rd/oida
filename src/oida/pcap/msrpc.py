"""
MSRPC/DCERPC Passive Listener for Windows RPC interface enumeration.

Passively captures DCERPC traffic to extract:
- Interface UUIDs (IFIDs) mapping to known Windows services
- Operation numbers (opnums) resolved to human-readable names
- Bind/bind_ack exchanges revealing available interfaces
- Endpoint mapper queries
- Authentication method detection (NTLMSSP, Kerberos, etc.)
- Call ID correlation for request/response matching
- Per-stream context tracking for interface resolution across PDUs

DCERPC is security-relevant because:
- Interface UUIDs reveal Windows infrastructure services
- SAMR, LSARPC, DRSUAPI interfaces indicate domain controller traffic
- Opnum analysis reveals specific operations (password changes, user enum)
- Endpoint mapper queries reveal available RPC services
- Auth type/level reveals encryption and integrity settings

tshark fields used (packet.dcerpc.*):
- dcerpc.ver: Protocol version
- dcerpc.ver_minor: Protocol minor version
- dcerpc.pkt_type: PDU type (bind=11, bind_ack=12, request=0, response=2)
- dcerpc.cn_bind_to_uuid: Interface UUID in Bind/Alter_Context
- dcerpc.if_id: Interface UUID (fallback)
- dcerpc.opnum: Operation number
- dcerpc.cn_ctx_id: Context ID (references bound interface)
- dcerpc.cn_call_id: Call ID for request/response correlation
- dcerpc.cn_num_ctx_items: Number of context items in bind
- dcerpc.cn_max_xmit: Max transmit fragment size
- dcerpc.cn_max_recv: Max receive fragment size
- dcerpc.cn_sec_addr: Secondary address (port) in Bind_Ack
- dcerpc.cn_ack_result: Bind acknowledgement result
- dcerpc.cn_alloc_hint: Allocation hint (expected stub data size)
- dcerpc.cn_frag_len: Fragment length
- dcerpc.auth_type: Authentication type (NTLMSSP=10, Kerberos=16, etc.)
- dcerpc.auth_level: Authentication level (Connect=2, Integrity=5, Privacy=6)
- dcerpc.auth_ctx_id: Authentication context ID
- dcerpc.fragment: Fragment flags
"""

from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor


# PDU type mapping
PDU_TYPES = {
    "0": "Request",
    "1": "Ping",
    "2": "Response",
    "3": "Fault",
    "4": "Working",
    "5": "NoCall",
    "6": "Reject",
    "7": "Ack",
    "8": "CL_Cancel",
    "9": "Fack",
    "10": "Cancel_Ack",
    "11": "Bind",
    "12": "Bind_Ack",
    "13": "Bind_Nak",
    "14": "Alter_Context",
    "15": "Alter_Context_Resp",
    "16": "Shutdown",
    "17": "CO_Cancel",
    "18": "Orphaned",
}

# Well-known interface UUIDs -> service names
WELL_KNOWN_IFIDS = {
    "4b324fc8-1670-01d3-1278-5a47bf6ee188": "SRVSVC",
    "12345778-1234-abcd-ef00-0123456789ab": "LSARPC",
    "12345778-1234-abcd-ef00-0123456789ac": "SAMR",
    "e3514235-4b06-11d1-ab04-00c04fc2dcd2": "DRSUAPI",
    "6bffd098-a112-3610-9833-46c3f87e345a": "WKSSVC",
    "12345678-1234-abcd-ef00-01234567cffb": "NETLOGON",
    "e1af8308-5d1f-11c9-91a4-08002b14a0fa": "EPMAPPER",
    "e1aff308-5d1f-11c9-91a4-08002b14a0fa": "EPMAPPER",  # Alternate byte order
    "367abb81-9844-35f1-ad32-98f038001003": "SVCCTL",
    "338cd001-2244-31f1-aaaa-900038001003": "WINREG",
    "4d9f4ab8-7d1c-11cf-861e-0020af6e7c57": "ATSVC",
    "1ff70682-0a51-30e8-076d-740be8cee98b": "ATSVC_V1",
    "86d35949-83c9-4044-b424-db363231fd0c": "ITaskScheduler",
    "3919286a-b10c-11d0-9ba8-00c04fd92ef5": "DSSETUP",
    "12345678-1234-abcd-ef00-0123456789ab": "SPOOLSS",
    "4fc742e0-4a10-11cf-8273-00aa004ae673": "DFSNM",
    "c681d488-d850-11d0-8c52-00c04fd90f7e": "EFSR",
    "df1941c5-fe89-4e79-bf10-463657acf44d": "EFSR_V2",
    "00000136-0000-0000-c000-000000000046": "ISCMActivator",
    "000001a0-0000-0000-c000-000000000046": "ISystemActivator",
    "99fcfec4-5260-101b-bbcb-00aa0021347a": "IOXIDResolver",
    "afa8bd80-7d8a-11c9-bef4-08002b102989": "MGMT",
    "c9ac6db5-82b7-4e55-ae8a-e464ed7b4277": "IWbemLevel1Login",
    "d4781cd6-e5d3-44df-ad94-930efe48a887": "IWbemLoginClientID",
    "9556dc99-828c-11cf-a37e-00aa003240c7": "IWbemServices",
    "76f226c3-ec14-4325-8a99-6a46348418ae": "IRemoteWinspool",
    "894de0c0-0d55-11d3-a322-00c04fa321a1": "IWinHttpAutoProxySvc",
    "1a9134dd-7b39-45ba-ad88-44d01ca47f28": "FSRVP",
    # DCOM core interfaces
    "00000001-0000-0000-c000-000000000046": "IClassFactory",
    "00000131-0000-0000-c000-000000000046": "IRemUnknown",
    "00000143-0000-0000-c000-000000000046": "IRemActivation",
    "e60c73e6-88f9-11cf-9af1-0020af6e72f4": "ISystemActivator_v0",
    # BITS / Background Intelligent Transfer
    "3dde7c30-165d-11d1-ab8f-00805f14db40": "IBackgroundCopyManager",
    # Certificate services
    "5ca4a760-ebb1-11cf-8611-00a0245420ed": "ICertPassage",
    "91ae6020-9e3c-11cf-8d7c-00aa003240c7": "ICertRequest",
    "d99e6e70-fc88-11d0-b498-00a0c90312f3": "ICertRequest2",
    "0d72a7d4-6148-11d1-b4aa-00c04fb66ea0": "ICertAdminD",
    "7c44d7d4-31d5-424c-bd5e-2b3e1f323d22": "ICertAdminD2",
    # BackupKey protocol (DPAPI)
    "4a2f4d4c-9c5e-11d1-b886-00c04fb960b1": "BKRP",
    # FRS (File Replication Service)
    "ecec0d70-a603-11d0-96b1-00a0c91ece30": "FRSRPC",
    "d049b186-814f-11d1-9a3c-00c04fc9b232": "FRSAPI",
    "897e2e5f-93f3-4376-9c9c-fd2277495c27": "FrsTransport",
    # FTRSVC (File Tracking)
    "f5cc59b4-4264-101a-8c59-08002b2f8426": "FTRSVC",
    # DNS Server
    "e3d0d746-d2af-40fd-8dc7-c735dfd7be9a": "DNSServer",
    "50abc2a4-574d-40b3-9d66-ee4fd5fba076": "DNSServer_v5",
    # Event Log
    "65a93890-fab9-43a3-b2a5-1e330ac28f11": "EVENTLOG_V6",
    "82273fdc-e32a-18c3-3f78-827929dc23ea": "EVENTLOG",
    # LSA Capabilities
    "0b6edbfa-4a24-4fc6-8a23-942b1eca65d1": "LSACAP",
    # Firewall
    "6b5bdd1e-528c-422c-af8c-a4079be4fe48": "RemoteFW",
    # WDS Transport
    "afc07e2e-311c-4435-808c-c483ffeec7c9": "WdsTransportServer",
    # Distributed Link Tracking
    "d4b7df28-4d4c-4c89-880b-07f19a4d3c82": "TRKWKS",
    # DRS (Active Directory replication)
    "4da1c422-943d-11d1-acae-00c04fc2aa3f": "DRS",
    # DHCP
    "3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5": "DHCP",
    "5b821720-f63b-11d0-aad2-00c04fc324db": "DHCP_V2",
    # SSDP
    "4b112204-0e19-11d3-b42b-0000f81feb9f": "SSDPSRV",
    # WINS
    "1544f5e0-613c-11d1-93df-00c04fd7bd09": "WINS",
    "811109bf-a4e1-11d1-ab54-00a0c91e9b45": "WINS_V2",
    # Witness Service (cluster)
    "ccd8c074-d0e5-4a40-92b4-d074faa6ba28": "WitnessService",
}

# Authentication type names (dcerpc.auth_type)
AUTH_TYPES = {
    "0": "None",
    "1": "OSF-Private",
    "9": "SPNEGO",
    "10": "NTLMSSP",
    "16": "Kerberos",
    "17": "Netlogon",
    "18": "SchannelTLS",
    "68": "PKU2U",
}

# Authentication level names (dcerpc.auth_level)
AUTH_LEVELS = {
    "0": "Default",
    "1": "None",
    "2": "Connect",
    "3": "Call",
    "4": "Packet",
    "5": "Integrity",
    "6": "Privacy",
}

# Bind ack result names (dcerpc.cn_ack_result)
ACK_RESULTS = {
    "0": "Acceptance",
    "1": "User rejection",
    "2": "Provider rejection",
    "3": "Negotiate ACK",
}

# ---------------------------------------------------------------------------
# Per-interface opnum tables for security-relevant services
# ---------------------------------------------------------------------------

SAMR_OPNUMS = {
    "0": "Connect",
    "1": "Close",
    "5": "LookupDomainInSamServer",
    "6": "EnumerateDomainsInSamServer",
    "7": "OpenDomain",
    "12": "CreateGroupInDomain",
    "13": "EnumerateUsersInDomain",
    "14": "CreateAliasInDomain",
    "15": "EnumerateGroupsInDomain",
    "16": "EnumerateAliasesInDomain",
    "19": "LookupIdsInDomain",
    "25": "QueryInformationGroup",
    "34": "OpenUser",
    "36": "QueryInformationUser",
    "37": "SetInformationUser",
    "38": "ChangePasswordUser",
    "44": "GetAliasMembership",
    "47": "LookupNamesInDomain",
    "50": "QueryDisplayInformation",
    "52": "GetDisplayEnumerationIndex",
    "57": "Connect2",
    "62": "Connect4",
    "64": "Connect5",
}

LSARPC_OPNUMS = {
    "0": "Close",
    "6": "OpenPolicy",
    "14": "LookupNames",
    "15": "LookupSids",
    "26": "QueryInformationPolicy",
    "44": "OpenPolicy2",
    "57": "LookupSids2",
    "58": "LookupNames2",
    "68": "LookupNames3",
    "76": "LookupSids3",
    "77": "LookupNames4",
}

DRSUAPI_OPNUMS = {
    "0": "DsBind",
    "1": "DsUnbind",
    "2": "DsReplicaSync",
    "3": "DsGetNCChanges",
    "4": "DsReplicaUpdateRefs",
    "12": "DsCrackNames",
    "13": "DsWriteAccountSpn",
    "16": "DsGetDomainControllerInfo",
    "19": "DsAddEntry",
}

SVCCTL_OPNUMS = {
    "0": "CloseServiceHandle",
    "1": "ControlService",
    "2": "DeleteService",
    "3": "LockServiceDatabase",
    "4": "QueryServiceObjectSecurity",
    "5": "SetServiceObjectSecurity",
    "6": "QueryServiceStatus",
    "7": "SetServiceStatus",
    "8": "UnlockServiceDatabase",
    "11": "ChangeServiceConfigW",
    "12": "CreateServiceW",
    "13": "EnumDependentServicesW",
    "14": "EnumServicesStatusW",
    "15": "OpenSCManagerW",
    "16": "OpenServiceW",
    "17": "QueryServiceConfigW",
    "18": "QueryServiceLockStatusW",
    "19": "StartServiceW",
    "24": "CreateServiceA",
    "26": "EnumServicesStatusA",
    "27": "OpenSCManagerA",
    "28": "OpenServiceA",
    "36": "QueryServiceConfig2W",
    "42": "EnumServicesStatusExW",
}

SRVSVC_OPNUMS = {
    "0": "NetrCharDevEnum",
    "8": "NetrConnectionEnum",
    "9": "NetrFileEnum",
    "15": "NetrShareEnum",
    "16": "NetrShareGetInfo",
    "17": "NetrShareSetInfo",
    "18": "NetrShareDel",
    "21": "NetrServerGetInfo",
    "24": "NetrServerDiskEnum",
    "28": "NetrRemoteTOD",
    "31": "NetrpSetFileSecurity",
    "36": "NetrShareEnumSticky",
    "48": "NetrShareDelEx",
}

NETLOGON_OPNUMS = {
    "2": "NetrLogonSamLogon",
    "4": "NetrServerReqChallenge",
    "6": "NetrServerAuthenticate2",
    "15": "NetrLogonSamLogonWithFlags",
    "21": "NetrLogonGetDomainInfo",
    "26": "NetrServerAuthenticate3",
    "29": "NetrLogonSamLogonEx",
    "30": "DsrAddressToSiteNamesExW",
    "34": "DsrGetForestTrustInformation",
    "39": "NetrServerGetTrustInfo",
    "40": "OpnumThatRemovesRestriction",
    "45": "NetrLogonSamLogonCompute",
}

WINREG_OPNUMS = {
    "0": "OpenClassesRoot",
    "1": "OpenCurrentUser",
    "2": "OpenLocalMachine",
    "5": "CloseKey",
    "6": "CreateKey",
    "7": "DeleteKey",
    "8": "DeleteValue",
    "9": "EnumKey",
    "10": "EnumValue",
    "11": "FlushKey",
    "15": "OpenKey",
    "16": "QueryInfoKey",
    "17": "QueryValue",
    "20": "SetKeySecurity",
    "22": "SetValue",
    "26": "QueryMultipleValues",
    "35": "BaseRegGetVersion",
}

ATSVC_OPNUMS = {
    "0": "NetrJobAdd",
    "1": "NetrJobDel",
    "2": "NetrJobEnum",
    "3": "NetrJobGetInfo",
}

ITASKSCHEDULER_OPNUMS = {
    "1": "SchRpcRegisterTask",
    "2": "SchRpcRetrieveTask",
    "3": "SchRpcCreateFolder",
    "4": "SchRpcSetSecurity",
    "5": "SchRpcGetSecurity",
    "6": "SchRpcEnumFolders",
    "7": "SchRpcEnumTasks",
    "8": "SchRpcEnumInstances",
    "9": "SchRpcGetInstanceInfo",
    "10": "SchRpcStopInstance",
    "11": "SchRpcStop",
    "12": "SchRpcRun",
    "13": "SchRpcDelete",
    "14": "SchRpcRename",
    "15": "SchRpcScheduledRuntimes",
    "16": "SchRpcGetLastRunInfo",
    "17": "SchRpcGetTaskInfo",
    "18": "SchRpcGetNumberOfMissedRuns",
    "19": "SchRpcEnableTask",
    "20": "SchRpcGetRunningTasksByUser",
    "21": "SchRpcHighestVersion",
}

WKSSVC_OPNUMS = {
    "0": "NetrWkstaGetInfo",
    "1": "NetrWkstaSetInfo",
    "2": "NetrWkstaUserEnum",
    "13": "NetrWkstaTransportEnum",
    "20": "NetrJoinDomain2",
    "22": "NetrUnjoinDomain2",
    "23": "NetrRenameMachineInDomain2",
    "25": "NetrGetJoinableOUs2",
    "26": "NetrAddAlternateComputerName",
    "27": "NetrRemoveAlternateComputerName",
}

EPMAPPER_OPNUMS = {
    "0": "ept_insert",
    "1": "ept_delete",
    "2": "ept_lookup",
    "3": "ept_map",
    "4": "ept_lookup_handle_free",
    "5": "ept_inq_object",
    "6": "ept_mgmt_delete",
}

DSSETUP_OPNUMS = {
    "0": "DsRolerGetPrimaryDomainInformation",
    "9": "DsRolerDnsNameToFlatName",
    "10": "DsRolerDcAsDc",
    "11": "DsRolerDcAsReplica",
    "12": "DsRolerDemoteDc",
    "13": "DsRolerGetDcOperationProgress",
    "14": "DsRolerGetDcOperationResults",
    "15": "DsRolerCancel",
    "16": "DsRolerServerSaveStateForUpgrade",
    "17": "DsRolerUpgradeDownlevelServer",
}

EFSR_OPNUMS = {
    "0": "EfsRpcOpenFileRaw",
    "1": "EfsRpcReadFileRaw",
    "2": "EfsRpcWriteFileRaw",
    "4": "EfsRpcEncryptFileSrv",
    "5": "EfsRpcDecryptFileSrv",
}

SPOOLSS_OPNUMS = {
    "0": "EnumPrinters",
    "1": "OpenPrinter",
    "26": "GetPrinterDriver",
    "29": "EnumPrinterDrivers",
    "56": "OpenPrinterEx",
    "57": "AddPrinterEx",
    "69": "RpcOpenPrinter",
}

DFSNM_OPNUMS = {
    "0": "NetrDfsManagerGetVersion",
    "15": "NetrDfsRemoveStdRoot",
    "18": "NetrDfsAddStdRoot",
}

# Map interface name -> opnum table
INTERFACE_OPNUMS = {
    "SAMR": SAMR_OPNUMS,
    "LSARPC": LSARPC_OPNUMS,
    "DRSUAPI": DRSUAPI_OPNUMS,
    "SVCCTL": SVCCTL_OPNUMS,
    "SRVSVC": SRVSVC_OPNUMS,
    "NETLOGON": NETLOGON_OPNUMS,
    "WINREG": WINREG_OPNUMS,
    "ATSVC": ATSVC_OPNUMS,
    "ATSVC_V1": ATSVC_OPNUMS,
    "ITaskScheduler": ITASKSCHEDULER_OPNUMS,
    "WKSSVC": WKSSVC_OPNUMS,
    "EPMAPPER": EPMAPPER_OPNUMS,
    "DSSETUP": DSSETUP_OPNUMS,
    "EFSR": EFSR_OPNUMS,
    "EFSR_V2": EFSR_OPNUMS,
    "SPOOLSS": SPOOLSS_OPNUMS,
    "DFSNM": DFSNM_OPNUMS,
}

# Share type mapping for srvsvc NetShareEnum/NetShareGetInfo
SHARE_TYPES = {
    "0x00000000": "Disk",
    "0x00000001": "Printer",
    "0x00000002": "Device",
    "0x00000003": "IPC",
    "0x80000000": "Disk (Temp)",
    "0x80000001": "Printer (Temp)",
    "0x80000002": "Device (Temp)",
    "0x80000003": "IPC$ (Hidden)",
    "0xc0000000": "Cluster",
}

# Registry paths indicative of persistence / autorun
_AUTORUN_KEY_PATTERNS = (
    "\\Run",
    "\\RunOnce",
    "\\RunOnceEx",
    "\\Services\\",
    "\\Winlogon\\",
    "\\Explorer\\Shell Folders",
)


class MSRPCPassiveListener(PySharkListenerBase):
    """Passive MSRPC/DCERPC traffic listener for Windows RPC interface enumeration.

    Captures DCERPC traffic to extract:
    - Interface UUIDs and their corresponding Windows service names
    - PDU types (Bind, Request, Response, Fault)
    - Operation numbers resolved to human-readable names for known interfaces
    - Call correlation via call IDs
    - Bind context tracking so Request/Response PDUs resolve their interface
    - Authentication type and level per session
    - Per-server interface and operation statistics

    Usage:
        listener = MSRPCPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for ix in listener.interactions:
            print(f"{ix.operation}: {ix.details}")
    """

    PROTOCOL_NAME = "msrpc"
    DISPLAY_FILTER = "dcerpc"
    REQUIRED_LAYERS = ("dcerpc",)
    PROTOCOL_COLUMNS = ("pdu_type", "interface", "op_num", "operation", "call_id", "auth", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # Track discovered interfaces per server
        self.interfaces_seen: Dict[str, set] = {}  # server_ip -> set of service names

        # Bind context map: (stream_id, ctx_id_str) -> (uuid, interface_name)
        # Populated by Bind/Alter_Context, consumed by Request/Response
        self._bind_contexts: Dict[Tuple[str, str], Tuple[str, str]] = {}

        # Track operations per server per interface: server_ip -> iface -> Counter of opnums
        self._server_ops: Dict[str, Dict[str, Counter]] = {}

        # Track auth info per stream: stream_id -> (auth_type_name, auth_level_name)
        self._stream_auth: Dict[str, Tuple[str, str]] = {}

        # Track call IDs: (stream_id, call_id) -> {interface, opnum, opnum_name, ...}
        self._call_map: Dict[Tuple[str, str], Dict[str, str]] = {}

        # Sub-dissector extracted data
        self._winreg_ops: List[Dict] = []
        self._srvsvc_shares: Dict[str, Dict[str, Dict]] = {}  # server -> {share: {type, comment}}
        self._samr_ops: List[Dict] = []
        self._ntlmssp_auths: List[Dict] = []
        self._ntlmssp_challenges: Dict[str, str] = {}  # stream_id -> server_challenge
        self._unknown_uuids: Dict[str, Dict] = {}  # uuid -> {servers, call_count, opnums, ports}

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format MSRPC interaction as protocol-specific table columns."""
        d = ix.details
        pdu_type = d.get("pdu_type_name", "?")
        interface = d.get("interface_name", "") or d.get("interface_uuid", "") or "-"
        opnum = d.get("opnum", "") or "-"
        opnum_name = d.get("opnum_name", "") or "-"
        call_id = d.get("call_id", "") or "-"

        # Auth info
        auth_type = d.get("auth_type_name", "")
        auth_level = d.get("auth_level_name", "")
        if auth_type and auth_level:
            auth = f"{auth_type}/{auth_level}"
        elif auth_type:
            auth = auth_type
        else:
            auth = "-"

        # Build detail string
        detail_parts = []
        ack_result = d.get("ack_result_name", "")
        if ack_result:
            detail_parts.append(ack_result)
        sec_addr = d.get("sec_addr", "")
        if sec_addr:
            detail_parts.append(f"port={sec_addr}")
        alloc_hint = d.get("alloc_hint", "")
        if alloc_hint:
            detail_parts.append(f"hint={alloc_hint}")
        # Sub-dissector enrichment
        winreg_key = d.get("winreg_key", "")
        if winreg_key:
            wv = d.get("winreg_value", "")
            detail_parts.append(f"reg={winreg_key}" + (f"\\{wv}" if wv else ""))
        share_name = d.get("share_name", "")
        if share_name:
            detail_parts.append(f"share={share_name}")
        ntlmssp_user = d.get("ntlmssp_user", "")
        if ntlmssp_user:
            detail_parts.append(f"user={ntlmssp_user}")
        detail = " ".join(detail_parts) if detail_parts else "-"

        return [pdu_type, interface, opnum, opnum_name, call_id, auth, detail]

    def _resolve_interface_for_ctx(self, stream_id: str, ctx_id_str: str) -> Tuple[str, str]:
        """Resolve interface UUID and name from the bind context map.

        Returns (uuid, interface_name). Falls back to ("", "") if no bind
        has been seen for this (stream, ctx_id) pair.
        """
        key = (stream_id, ctx_id_str)
        if key in self._bind_contexts:
            return self._bind_contexts[key]
        # Fall back: try ctx_id "0" which is the most common default
        fallback = (stream_id, "0")
        if fallback in self._bind_contexts:
            return self._bind_contexts[fallback]
        return ("", "")

    def _store_bind_context(
        self, stream_id: str, ctx_id_str: str, uuid: str, interface_name: str
    ) -> None:
        """Store a bind context mapping for later resolution."""
        key = (stream_id, ctx_id_str)
        self._bind_contexts[key] = (uuid, interface_name)

    # ------------------------------------------------------------------
    # Sub-dissector handlers
    # ------------------------------------------------------------------

    def _normalize_hex(self, value) -> str:
        """Normalize hex value from PyShark to plain lowercase hex string.

        Handles colon-separated, space-separated, and plain hex formats.
        """
        if not value:
            return ""
        val_str = str(value).replace(":", "").replace(" ", "").lower()
        try:
            int(val_str, 16)
            return val_str
        except ValueError as e:
            self.logger.debug(f"MSRPC: hex validation of normalized value failed: {e}")
            return ""

    def _process_winreg(
        self,
        packet,
        server_ip: str,
        client_ip: str,
        details: Dict[str, Any],
    ) -> None:
        """Extract Windows Registry operations from winreg sub-dissector layer."""
        if not hasattr(packet, "winreg"):
            return

        layer = packet.winreg
        opnum_raw = self.get_field(layer, "opnum", None)
        opnum_name = ""
        if opnum_raw is not None:
            opnum_name = WINREG_OPNUMS.get(str(opnum_raw), f"opnum_{opnum_raw}")

        # Extract key/value paths depending on the operation
        key_path = ""
        value_name = ""
        data = ""
        result_str = ""

        # OpenKey -> keyname
        opened_key = self.get_field(layer, "winreg_OpenKey.keyname", None)
        if opened_key:
            key_path = str(opened_key)

        # QueryValue -> value_name
        qv = self.get_field(layer, "winreg_QueryValue.value_name", None)
        if qv:
            value_name = str(qv)

        # SetValue -> name + data
        sv_name = self.get_field(layer, "winreg_SetValue.name", None)
        if sv_name:
            value_name = str(sv_name)
        sv_data = self.get_field(layer, "winreg_SetValue.data", None)
        if sv_data:
            data = str(sv_data)

        # CreateKey -> name
        ck_name = self.get_field(layer, "winreg_CreateKey.name", None)
        if ck_name:
            key_path = key_path or str(ck_name)

        # DeleteKey -> key
        dk = self.get_field(layer, "winreg_DeleteKey.key", None)
        if dk:
            key_path = key_path or str(dk)

        # DeleteValue -> value
        dv = self.get_field(layer, "winreg_DeleteValue.value", None)
        if dv:
            value_name = value_name or str(dv)

        # EnumKey -> name
        ek = self.get_field(layer, "winreg_EnumKey.name", None)
        if ek:
            key_path = key_path or str(ek)

        # EnumValue -> name
        ev = self.get_field(layer, "winreg_EnumValue.name", None)
        if ev:
            value_name = value_name or str(ev)

        # Operation result
        werror = self.get_field(layer, "werror", None)
        if werror is not None:
            result_str = str(werror)

        record = {
            "server": server_ip,
            "client": client_ip,
            "opnum_name": opnum_name,
            "key": key_path,
            "value": value_name,
            "data": data,
            "result": result_str,
        }
        self._winreg_ops.append(record)

        # Enrich interaction details
        if key_path:
            details["winreg_key"] = key_path
        if value_name:
            details["winreg_value"] = value_name

    def _process_srvsvc(
        self,
        packet,
        server_ip: str,
        client_ip: str,
        details: Dict[str, Any],
    ) -> None:
        """Extract share enumeration data from srvsvc sub-dissector layer."""
        if not hasattr(packet, "srvsvc"):
            return

        layer = packet.srvsvc

        # Share info from NetShareEnumAll / NetShareGetInfo responses
        share_names_raw = self.get_field(layer, "srvsvc_NetShareInfo1.name", None)
        share_types_raw = self.get_field(layer, "srvsvc_NetShareInfo1.type", None)
        share_comments_raw = self.get_field(layer, "srvsvc_NetShareInfo1.comment", None)

        # Single share query
        single_share = self.get_field(layer, "srvsvc_NetShareGetInfo.share_name", None)
        if single_share:
            details["share_name"] = str(single_share)

        # Server UNC from enum request
        server_unc = self.get_field(layer, "srvsvc_NetShareEnumAll.server_unc", None)
        if server_unc:
            details["server_unc"] = str(server_unc)

        if not share_names_raw:
            return

        names = [n.strip() for n in str(share_names_raw).split(",") if n.strip()]
        types = (
            [t.strip() for t in str(share_types_raw).split(",") if t.strip()]
            if share_types_raw
            else []
        )
        # Do NOT drop empty comments: they are positional slots aligned with
        # `names` (ADMIN$/C$ etc. commonly have empty comments), so filtering
        # them shifts every later comment onto the wrong share.
        comments = (
            [c.strip() for c in str(share_comments_raw).split(",")] if share_comments_raw else []
        )

        if server_ip not in self._srvsvc_shares:
            self._srvsvc_shares[server_ip] = {}

        for i, name in enumerate(names):
            type_raw = types[i] if i < len(types) else ""
            type_name = SHARE_TYPES.get(type_raw, "")
            if not type_name and type_raw:
                # Convert decimal to hex for lookup (e.g. "2147483651" -> "0x80000003")
                try:
                    type_int = int(type_raw, 0)
                    type_hex = f"0x{type_int:08x}"
                    type_name = SHARE_TYPES.get(type_hex, type_raw)
                except (ValueError, TypeError):
                    type_name = type_raw
            comment = comments[i] if i < len(comments) else ""
            self._srvsvc_shares[server_ip][name] = {
                "type": type_name,
                "type_raw": type_raw,
                "comment": comment,
            }

        if names:
            details["share_name"] = names[0] if len(names) == 1 else f"{len(names)} shares"

    def _process_samr(
        self,
        packet,
        server_ip: str,
        client_ip: str,
        details: Dict[str, Any],
    ) -> None:
        """Extract SAMR operation info from samr sub-dissector layer."""
        if not hasattr(packet, "samr"):
            return

        layer = packet.samr
        opnum_raw = self.get_field(layer, "opnum", None)
        if opnum_raw is None:
            return

        opnum_name = SAMR_OPNUMS.get(str(opnum_raw), f"opnum_{opnum_raw}")
        self._samr_ops.append(
            {
                "server": server_ip,
                "client": client_ip,
                "opnum": str(opnum_raw),
                "opnum_name": opnum_name,
            }
        )

    def _get_ntlmssp_ek_dict(self, packet) -> Optional[Dict]:
        """Find the ntlmssp sub-dict in EK mode _fields_dict.

        In EK mode, NTLMSSP fields are nested inside dcerpc._fields_dict
        under the key 'ntlmssp' with keys prefixed 'ntlmssp_ntlmssp_'.
        """
        if not hasattr(packet, "dcerpc"):
            return None
        fd = getattr(packet.dcerpc, "_fields_dict", None)
        if not fd or not isinstance(fd, dict):
            return None
        ntlm = fd.get("ntlmssp")
        if isinstance(ntlm, dict) and "ntlmssp_ntlmssp_messagetype" in ntlm:
            return ntlm
        return None

    def _get_ntlmssp_field(self, packet, field_name: str, default=None):
        """Get an NTLMSSP field from packet.

        NTLMSSP fields may appear as:
        1. Separate layer: packet.ntlmssp (XML mode)
        2. Embedded in dcerpc._all_fields with 'ntlmssp.' prefix (XML mode)
        3. Nested in dcerpc._fields_dict['ntlmssp'] with 'ntlmssp_ntlmssp_'
           prefix (EK mode)
        """
        # Try separate ntlmssp layer first
        if hasattr(packet, "ntlmssp"):
            val = self.get_field(packet.ntlmssp, field_name, None)
            if val is not None:
                return val

        if hasattr(packet, "dcerpc"):
            # XML mode: dcerpc._all_fields with 'ntlmssp.' prefix
            all_fields = getattr(packet.dcerpc, "_all_fields", {})
            val = all_fields.get(f"ntlmssp.{field_name}")
            if val is not None:
                return val

            # EK mode: dcerpc._fields_dict['ntlmssp'] with 'ntlmssp_ntlmssp_' keys
            ek_dict = self._get_ntlmssp_ek_dict(packet)
            if ek_dict:
                # Convert dotted field name to EK underscore format
                ek_key = f"ntlmssp_ntlmssp_{field_name.replace('.', '_')}"
                val = ek_dict.get(ek_key)
                if val is not None:
                    return val

        return default

    def _has_ntlmssp(self, packet) -> bool:
        """Check if packet has NTLMSSP data (separate layer or embedded)."""
        if hasattr(packet, "ntlmssp"):
            return True
        if hasattr(packet, "dcerpc"):
            all_fields = getattr(packet.dcerpc, "_all_fields", {})
            if "ntlmssp.messagetype" in all_fields:
                return True
            # EK mode check
            if self._get_ntlmssp_ek_dict(packet) is not None:
                return True
        return False

    def _process_ntlmssp(
        self,
        packet,
        server_ip: str,
        client_ip: str,
        stream_id: str,
    ) -> None:
        """Extract NTLMSSP authentication data for hash correlation.

        Correlates Type 2 (Challenge) with Type 3 (Authenticate) via stream_id
        to build hashcat-compatible NTLMv2 hashes.

        NTLMSSP may appear as a separate PyShark layer or embedded in the
        dcerpc layer's _all_fields (when carried in DCERPC auth trailers).
        """
        if not self._has_ntlmssp(packet):
            return

        msg_type_raw = self._get_ntlmssp_field(packet, "messagetype")
        if msg_type_raw is None:
            return

        msg_type = str(msg_type_raw)

        # Type 2 - Challenge (from server)
        if msg_type in ("0x00000002", "2"):
            challenge = self._get_ntlmssp_field(packet, "ntlmserverchallenge")
            target_name = self._get_ntlmssp_field(packet, "challenge.target_name")
            if challenge:
                challenge_hex = self._normalize_hex(challenge)
                self._ntlmssp_challenges[stream_id] = challenge_hex
                self.logger.debug(
                    f"NTLMSSP Type 2: challenge={challenge_hex} "
                    f"target={target_name or '?'} stream={stream_id}"
                )

        # Type 3 - Authenticate (from client)
        elif msg_type in ("0x00000003", "3"):
            domain = str(self._get_ntlmssp_field(packet, "auth.domain", "") or "")
            username = str(self._get_ntlmssp_field(packet, "auth.username", "") or "")
            ntproofstr = self._get_ntlmssp_field(packet, "ntlmv2_response.ntproofstr")
            nt_response = self._get_ntlmssp_field(packet, "auth.ntresponse")

            if not username:
                return

            # Look up the challenge from the same stream
            challenge_hex = self._ntlmssp_challenges.get(stream_id, "")

            ntproofstr_hex = self._normalize_hex(ntproofstr) if ntproofstr else ""
            nt_response_hex = self._normalize_hex(nt_response) if nt_response else ""

            # Build hashcat-compatible NTLMv2 format:
            # username::domain:challenge:ntproofstr:blob_remainder
            hashcat_str = ""
            if username and challenge_hex and ntproofstr_hex and len(nt_response_hex) > 32:
                blob = nt_response_hex[32:]
                hashcat_str = f"{username}::{domain}:{challenge_hex}:{ntproofstr_hex}:{blob}"

            auth_entry = {
                "server": server_ip,
                "client": client_ip,
                "domain": domain,
                "username": username,
                "challenge": challenge_hex,
                "ntproofstr": ntproofstr_hex,
                "nt_response": nt_response_hex,
                "hash_type": "NTLMv2" if ntproofstr_hex else "NTLMv1",
                "hashcat_format": hashcat_str,
                "stream_id": stream_id,
            }
            self._ntlmssp_auths.append(auth_entry)

            # Enrich the DCERPC details for this packet
            if username:
                # Update the most recent interaction's details
                if self.interactions:
                    last_ix = self.interactions[-1]
                    last_ix.details["ntlmssp_user"] = (
                        f"{domain}\\{username}" if domain else username
                    )

            self.logger.debug(
                f"NTLMSSP Type 3: {domain}\\{username} "
                f"challenge={'present' if challenge_hex else 'MISSING'} "
                f"stream={stream_id}"
            )

    def _track_unknown_uuid(self, uuid: str, server_ip: str, opnum_str: str, dst_port: int) -> None:
        """Track interfaces not in WELL_KNOWN_IFIDS for reporting."""
        uuid_lower = uuid.lower()
        if uuid_lower not in self._unknown_uuids:
            self._unknown_uuids[uuid_lower] = {
                "servers": set(),
                "call_count": 0,
                "opnums": Counter(),
                "ports": set(),
            }
        entry = self._unknown_uuids[uuid_lower]
        entry["servers"].add(server_ip)
        entry["call_count"] += 1
        if opnum_str:
            entry["opnums"][opnum_str] += 1
        if dst_port:
            entry["ports"].add(dst_port)

    def process_packet(self, packet) -> None:
        """Process DCERPC packet and extract interface, operation, and PDU info."""
        if not hasattr(packet, "dcerpc"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        dcerpc = packet.dcerpc
        flow_id = self.get_flow_id(packet)
        stream_id = self.get_stream_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        # Extract PDU type
        pdu_type_raw = self.get_field(dcerpc, "pkt_type", None)
        if pdu_type_raw is None:
            pdu_type_name = "?"
            self.logger.debug(f"Missing pkt_type in DCERPC packet from {src_ip} -> {dst_ip}")
        else:
            pdu_type_name = PDU_TYPES.get(str(pdu_type_raw), str(pdu_type_raw))

        # Determine direction
        is_response = pdu_type_name in (
            "Response",
            "Bind_Ack",
            "Alter_Context_Resp",
            "Fault",
            "Bind_Nak",
            "Reject",
        )
        direction = "response" if is_response else "request"

        # Extract protocol version
        ver = str(self.get_field(dcerpc, "ver", "") or "")
        ver_minor = str(self.get_field(dcerpc, "ver_minor", "") or "")
        version = f"{ver}.{ver_minor}" if ver and ver_minor else ver or "?"

        # Extract context ID (used by all PDU types)
        ctx_id = self.get_field(dcerpc, "cn_ctx_id", None)
        ctx_id_str = str(ctx_id) if ctx_id is not None else ""

        # Extract call ID for correlation
        call_id = self.get_field(dcerpc, "cn_call_id", None)
        call_id_str = str(call_id) if call_id is not None else ""

        # ---------------------------------------------------------------
        # Interface resolution: depends on PDU type
        # ---------------------------------------------------------------
        if_id = ""
        interface_name = ""

        if pdu_type_name in ("Bind", "Alter_Context"):
            # Bind/Alter_Context carry the interface UUID directly.
            # tshark may return comma-separated UUIDs if multiple ctx items.
            raw_uuid = str(self.get_field(dcerpc, "cn_bind_to_uuid", "") or "")
            if not raw_uuid:
                raw_uuid = str(self.get_field(dcerpc, "dg_if_id", "") or "")

            # Handle multi-context binds (comma-separated UUIDs and ctx_ids)
            uuids = [u.strip() for u in raw_uuid.split(",") if u.strip()] if raw_uuid else []
            ctx_ids = [c.strip() for c in ctx_id_str.split(",") if c.strip()] if ctx_id_str else []

            # Store each context binding
            for i, uuid in enumerate(uuids):
                cid = ctx_ids[i] if i < len(ctx_ids) else str(i)
                iname = WELL_KNOWN_IFIDS.get(uuid.lower(), "") if uuid else ""
                self._store_bind_context(stream_id, cid, uuid, iname)

            # Use the first UUID for this interaction's display
            if uuids:
                if_id = uuids[0]
                interface_name = WELL_KNOWN_IFIDS.get(if_id.lower(), "") if if_id else ""

        elif pdu_type_name in ("Bind_Ack", "Alter_Context_Resp", "Bind_Nak"):
            # Bind_Ack doesn't carry the UUID; resolve from the bind context
            # using the same stream. The ctx_id in Bind_Ack refers to the
            # ctx_id from the original Bind.
            if ctx_id_str:
                if_id, interface_name = self._resolve_interface_for_ctx(stream_id, ctx_id_str)
            if not if_id:
                # Try the call_id to match back to a bind
                if_id, interface_name = self._resolve_interface_for_ctx(stream_id, "0")

        else:
            # Request, Response, Fault, Shutdown, etc.: resolve via ctx_id
            if ctx_id_str:
                if_id, interface_name = self._resolve_interface_for_ctx(stream_id, ctx_id_str)
            if not if_id and not interface_name:
                # Last resort: check if call_id maps to a known request
                ck = (stream_id, call_id_str)
                if ck in self._call_map:
                    if_id = self._call_map[ck].get("interface_uuid", "")
                    interface_name = self._call_map[ck].get("interface_name", "")

        # If we still didn't find the interface, try the direct field
        if not if_id:
            if_id = str(self.get_field(dcerpc, "dg_if_id", "") or "")
            if if_id:
                interface_name = WELL_KNOWN_IFIDS.get(if_id.lower(), "")

        # ---------------------------------------------------------------
        # Extract operation number
        # ---------------------------------------------------------------
        opnum = self.get_field(dcerpc, "opnum", None)
        opnum_str = str(opnum) if opnum is not None else ""

        # Resolve opnum to name for known interfaces
        opnum_name = ""
        if interface_name and opnum_str:
            opnum_table = INTERFACE_OPNUMS.get(interface_name)
            if opnum_table:
                opnum_name = opnum_table.get(opnum_str, "")
            if not opnum_name:
                opnum_name = f"opnum_{opnum_str}"
        elif opnum_str and not interface_name:
            opnum_name = f"opnum_{opnum_str}"

        # ---------------------------------------------------------------
        # Store call context for response correlation
        # ---------------------------------------------------------------
        if pdu_type_name == "Request" and call_id_str and stream_id:
            self._call_map[(stream_id, call_id_str)] = {
                "interface_uuid": if_id,
                "interface_name": interface_name,
                "opnum": opnum_str,
                "opnum_name": opnum_name,
            }
        elif pdu_type_name == "Response" and not opnum_name:
            # Inherit opnum info from the matching request
            ck = (stream_id, call_id_str)
            if ck in self._call_map:
                cm = self._call_map[ck]
                if not opnum_str:
                    opnum_str = cm.get("opnum", "")
                if not opnum_name:
                    opnum_name = cm.get("opnum_name", "")
                if not interface_name:
                    interface_name = cm.get("interface_name", "")
                if not if_id:
                    if_id = cm.get("interface_uuid", "")

        # ---------------------------------------------------------------
        # Extract additional fields
        # ---------------------------------------------------------------

        # Number of context items (in bind requests)
        num_ctx_items = self.get_field(dcerpc, "cn_num_ctx_items", None)
        num_ctx_str = str(num_ctx_items) if num_ctx_items is not None else ""

        # Fragment info
        fragment = self.get_field(dcerpc, "fragment", None)
        fragment_str = str(fragment) if fragment is not None else ""

        # Fragment length
        frag_len = self.get_field(dcerpc, "cn_frag_len", None)
        frag_len_str = str(frag_len) if frag_len is not None else ""

        # Allocation hint (expected stub data size)
        alloc_hint = self.get_field(dcerpc, "cn_alloc_hint", None)
        alloc_hint_str = str(alloc_hint) if alloc_hint is not None else ""

        # Max transmit/receive fragment sizes (Bind/Bind_Ack)
        max_xmit = self.get_field(dcerpc, "cn_max_xmit", None)
        max_xmit_str = str(max_xmit) if max_xmit is not None else ""
        max_recv = self.get_field(dcerpc, "cn_max_recv", None)
        max_recv_str = str(max_recv) if max_recv is not None else ""

        # Secondary address (Bind_Ack: the server's listening port)
        sec_addr = str(self.get_field(dcerpc, "cn_sec_addr", "") or "")

        # Ack result (Bind_Ack)
        ack_result_raw = self.get_field(dcerpc, "cn_ack_result", None)
        ack_result_name = ""
        if ack_result_raw is not None:
            ack_result_name = ACK_RESULTS.get(str(ack_result_raw), str(ack_result_raw))

        # Authentication info
        auth_type_raw = self.get_field(dcerpc, "auth_type", None)
        auth_type_name = ""
        if auth_type_raw is not None:
            auth_type_name = AUTH_TYPES.get(str(auth_type_raw), f"type_{auth_type_raw}")
            # Store auth for this stream
            auth_level_raw = self.get_field(dcerpc, "auth_level", None)
            auth_level_name = ""
            if auth_level_raw is not None:
                auth_level_name = AUTH_LEVELS.get(str(auth_level_raw), f"level_{auth_level_raw}")
            if stream_id:
                self._stream_auth[stream_id] = (auth_type_name, auth_level_name)
        else:
            auth_type_name = ""

        # Resolve auth from stream if not on this packet
        auth_level_raw = self.get_field(dcerpc, "auth_level", None)
        auth_level_name = ""
        if auth_level_raw is not None:
            auth_level_name = AUTH_LEVELS.get(str(auth_level_raw), f"level_{auth_level_raw}")
        elif stream_id and stream_id in self._stream_auth:
            if not auth_type_name:
                auth_type_name = self._stream_auth[stream_id][0]
            auth_level_name = self._stream_auth[stream_id][1]

        # Auth context ID
        auth_ctx_id = self.get_field(dcerpc, "auth_ctx_id", None)
        auth_ctx_id_str = str(auth_ctx_id) if auth_ctx_id is not None else ""

        # Build details dict
        details: Dict[str, Any] = {
            "version": version,
            "pdu_type": str(pdu_type_raw) if pdu_type_raw is not None else "",
            "pdu_type_name": pdu_type_name,
            "interface_uuid": if_id,
            "interface_name": interface_name,
            "opnum": opnum_str,
            "opnum_name": opnum_name,
            "call_id": call_id_str,
            "ctx_id": ctx_id_str,
            "num_ctx_items": num_ctx_str,
            "fragment": fragment_str,
            "frag_len": frag_len_str,
            "alloc_hint": alloc_hint_str,
            "max_xmit": max_xmit_str,
            "max_recv": max_recv_str,
            "sec_addr": sec_addr,
            "ack_result_name": ack_result_name,
            "auth_type_name": auth_type_name,
            "auth_level_name": auth_level_name,
            "auth_ctx_id": auth_ctx_id_str,
        }

        # Build summary and operation string
        op_parts = [f"DCERPC {pdu_type_name}"]
        if interface_name:
            op_parts.append(interface_name)
        elif if_id:
            op_parts.append(if_id)

        operation = " ".join(op_parts)
        summary = operation
        if opnum_str:
            if opnum_name and opnum_name != f"opnum_{opnum_str}":
                summary += f" {opnum_name}"
            else:
                summary += f" opnum={opnum_str}"

        now = datetime.now().isoformat()
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

        # Track interfaces per server
        if is_response:
            server_ip, client_ip = src_ip, dst_ip
            server_mac, client_mac = src_mac, dst_mac
        else:
            server_ip, client_ip = dst_ip, src_ip
            server_mac, client_mac = dst_mac, src_mac

        if interface_name:
            if server_ip not in self.interfaces_seen:
                self.interfaces_seen[server_ip] = set()
            self.interfaces_seen[server_ip].add(interface_name)

        # Sub-dissector extraction
        if hasattr(packet, "winreg"):
            self._process_winreg(packet, server_ip, client_ip, details)
        if hasattr(packet, "srvsvc"):
            self._process_srvsvc(packet, server_ip, client_ip, details)
        if hasattr(packet, "samr"):
            self._process_samr(packet, server_ip, client_ip, details)
        # NTLMSSP may be a separate layer or embedded in dcerpc._all_fields
        self._process_ntlmssp(packet, server_ip, client_ip, stream_id)

        # Track unknown UUIDs
        if if_id and not interface_name:
            self._track_unknown_uuid(if_id, server_ip, opnum_str, dst_port)

        # Track operations per server per interface
        if interface_name and opnum_str and pdu_type_name == "Request":
            if server_ip not in self._server_ops:
                self._server_ops[server_ip] = {}
            if interface_name not in self._server_ops[server_ip]:
                self._server_ops[server_ip][interface_name] = Counter()
            label = (
                opnum_name
                if opnum_name and opnum_name != f"opnum_{opnum_str}"
                else f"opnum_{opnum_str}"
            )
            self._server_ops[server_ip][interface_name][label] += 1

        # Create device entries
        if is_valid_discovered_ip(server_ip):
            server_vendor = lookup_mac_vendor(server_mac) if server_mac else ""
            device, is_new = self._ensure_device(
                f"msrpc-server:{server_ip}",
                server_ip,
                mac=server_mac or "",
                device_type="MSRPC Server",
                manufacturer=server_vendor if server_vendor != "Unknown" else "",
            )
            if is_new:
                device.msrpc_passive_data = {
                    "role": "server",
                    "version": version,
                    "protocol": "DCERPC/TCP",
                    "interfaces_seen": [],
                    "auth_type": auth_type_name,
                    "auth_level": auth_level_name,
                }
            pdata = getattr(device, "msrpc_passive_data", None)
            if pdata:
                ifaces = pdata.get("interfaces_seen", [])
                if interface_name and interface_name not in ifaces:
                    ifaces.append(interface_name)
                    pdata["interfaces_seen"] = ifaces
                # Update auth info if we have it and it's not yet set
                if auth_type_name and not pdata.get("auth_type"):
                    pdata["auth_type"] = auth_type_name
                if auth_level_name and not pdata.get("auth_level"):
                    pdata["auth_level"] = auth_level_name

        if is_valid_discovered_ip(client_ip):
            client_vendor = lookup_mac_vendor(client_mac) if client_mac else ""
            self._ensure_device(
                f"msrpc-client:{client_ip}",
                client_ip,
                mac=client_mac or "",
                device_type="MSRPC Client",
                manufacturer=client_vendor if client_vendor != "Unknown" else "",
            )

        self.logger.debug(
            f"DCERPC: {pdu_type_name} {interface_name or if_id or '?'} "
            f"({src_ip} -> {dst_ip}) call={call_id_str} "
            f"opnum={opnum_str} ({opnum_name})"
        )

    def get_hashes_summary(self) -> List[Dict[str, Any]]:
        """Return NTLMSSP hashes extracted from DCERPC traffic.

        Returns list of dicts with keys expected by base class harvest():
        protocol, hash_type, username, domain, server_ip, client_ip,
        credential_type, hash_value, hashcat_format.
        """
        result = []
        for auth in self._ntlmssp_auths:
            if not auth.get("username"):
                continue
            entry: Dict[str, Any] = {
                "protocol": "DCERPC/NTLMSSP",
                "hash_type": auth.get("hash_type", "NTLMv2"),
                "username": auth.get("username", ""),
                "domain": auth.get("domain", ""),
                "server_ip": auth.get("server", ""),
                "client_ip": auth.get("client", ""),
                "credential_type": "hash",
                "hash_value": auth.get("nt_response", ""),
                "hashcat_format": auth.get("hashcat_format", ""),
            }
            result.append(entry)
        return result

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data with interface and operation tables."""
        base = super().harvest()
        tables = base.get("tables", [])
        alerts: List[Dict[str, str]] = base.get("alerts", [])

        # --- Interface discovery table (expanded with operations and auth) ---
        iface_rows = []
        for server_ip in sorted(self.interfaces_seen.keys()):
            ifaces = self.interfaces_seen[server_ip]
            server_ops = self._server_ops.get(server_ip, {})
            # Get auth info for this server from device data
            dev = self.discovered_devices.get(f"msrpc-server:{server_ip}")
            pdata = getattr(dev, "msrpc_passive_data", None) if dev else None
            auth_type = pdata.get("auth_type", "-") if pdata else "-"
            auth_level = pdata.get("auth_level", "-") if pdata else "-"

            for iface in sorted(ifaces):
                ops_counter = server_ops.get(iface, Counter())
                call_count = sum(ops_counter.values())
                # Build operations summary: top 5 most common
                top_ops = ops_counter.most_common(5)
                if top_ops:
                    ops_str = ", ".join(f"{name}({cnt})" for name, cnt in top_ops)
                else:
                    ops_str = "-"
                iface_rows.append(
                    [
                        server_ip,
                        iface,
                        str(call_count),
                        ops_str,
                        auth_type,
                        auth_level,
                    ]
                )

        if iface_rows:
            tables.append(
                {
                    "title": f"DCERPC Interfaces Discovered ({len(iface_rows)})",
                    "headers": [
                        "Server",
                        "Interface",
                        "Calls",
                        "Operations",
                        "Auth Type",
                        "Auth Level",
                    ],
                    "rows": iface_rows,
                }
            )

        # --- WINREG Operations table ---
        if self._winreg_ops:
            # Deduplicate by (server, operation, key)
            seen_winreg = set()
            winreg_rows = []
            for op in self._winreg_ops:
                dedup_key = (op["server"], op["opnum_name"], op["key"])
                if dedup_key in seen_winreg:
                    continue
                seen_winreg.add(dedup_key)
                key_val = op["key"]
                if op["value"]:
                    key_val += f"\\{op['value']}" if key_val else op["value"]
                winreg_rows.append(
                    [
                        op["server"],
                        op["opnum_name"],
                        key_val or "-",
                        op["data"] if op["data"] else "-",
                        op["result"] or "-",
                    ]
                )
            if winreg_rows:
                tables.append(
                    {
                        "title": f"WINREG Operations ({len(winreg_rows)})",
                        "headers": ["Server", "Operation", "Key/Value", "Data", "Result"],
                        "rows": winreg_rows,
                    }
                )

        # --- Network Shares table ---
        if self._srvsvc_shares:
            share_rows = []
            for srv_ip in sorted(self._srvsvc_shares.keys()):
                for share_name in sorted(self._srvsvc_shares[srv_ip].keys()):
                    info = self._srvsvc_shares[srv_ip][share_name]
                    share_rows.append(
                        [
                            srv_ip,
                            share_name,
                            info.get("type", "-"),
                            info.get("comment", "") or "-",
                        ]
                    )
            if share_rows:
                tables.append(
                    {
                        "title": f"Network Shares ({len(share_rows)})",
                        "headers": ["Server", "Share Name", "Type", "Comment"],
                        "rows": share_rows,
                    }
                )

        # --- NTLMSSP Authentication table ---
        if self._ntlmssp_auths:
            auth_rows = []
            for auth in self._ntlmssp_auths:
                if not auth.get("username"):
                    continue
                auth_rows.append(
                    [
                        auth.get("server", "-"),
                        auth.get("domain", "-"),
                        auth.get("username", "-"),
                        auth.get("hash_type", "-"),
                        auth.get("challenge", "-") or "(missing)",
                    ]
                )
            if auth_rows:
                tables.append(
                    {
                        "title": f"NTLMSSP Authentication ({len(auth_rows)})",
                        "headers": ["Server", "Domain", "Username", "Hash Type", "Challenge"],
                        "rows": auth_rows,
                    }
                )

        # --- Unknown Interfaces table ---
        if self._unknown_uuids:
            unknown_rows = []
            for uuid_str in sorted(
                self._unknown_uuids.keys(),
                key=lambda u: self._unknown_uuids[u]["call_count"],
                reverse=True,
            ):
                entry = self._unknown_uuids[uuid_str]
                servers = ", ".join(sorted(entry["servers"]))
                top_opnums = entry["opnums"].most_common(5)
                opnums_str = (
                    ", ".join(f"{op}({cnt})" for op, cnt in top_opnums) if top_opnums else "-"
                )
                ports = sorted(entry["ports"])
                port_labels = []
                for p in ports:
                    if p == 593:
                        port_labels.append(f"{p} (HTTP RPC Proxy?)")
                    elif p >= 49152:
                        port_labels.append(f"{p} (Dynamic RPC)")
                    else:
                        port_labels.append(str(p))
                ports_str = ", ".join(port_labels) if port_labels else "-"
                unknown_rows.append(
                    [
                        uuid_str,
                        servers,
                        str(entry["call_count"]),
                        opnums_str,
                        ports_str,
                    ]
                )
            if unknown_rows:
                tables.append(
                    {
                        "title": f"Unknown Interfaces ({len(unknown_rows)})",
                        "headers": ["UUID", "Server(s)", "Calls", "Top OpNums", "Port(s)"],
                        "rows": unknown_rows,
                    }
                )

        # --- Security-relevant interface alerts ---
        sec_ifaces = {"SAMR", "DRSUAPI", "LSARPC", "NETLOGON", "SVCCTL", "EFSR", "EFSR_V2"}
        for server_ip, ifaces in self.interfaces_seen.items():
            sec_found = ifaces & sec_ifaces
            if sec_found:
                alerts.append(
                    {
                        "level": "warn",
                        "category": "rpc_security",
                        "message": (
                            f"Security-sensitive DCERPC interfaces on {server_ip}: "
                            f"{', '.join(sorted(sec_found))}"
                        ),
                    }
                )

        # --- Registry write alerts (autorun/persistence) ---
        for op in self._winreg_ops:
            if op["opnum_name"] in ("SetValue", "CreateKey"):
                key_path = op.get("key", "")
                for pattern in _AUTORUN_KEY_PATTERNS:
                    if pattern in key_path:
                        alerts.append(
                            {
                                "level": "critical",
                                "category": "registry_persistence",
                                "message": (
                                    f"Registry write to autorun key on {op['server']}: "
                                    f"{op['opnum_name']} {key_path}"
                                ),
                            }
                        )
                        break

        # --- Share enumeration alert ---
        srvsvc_enum_seen = False
        for op_counter in self._server_ops.values():
            srvsvc_ops = op_counter.get("SRVSVC", Counter())
            if (
                srvsvc_ops.get("NetrShareEnum", 0) > 0
                or srvsvc_ops.get("NetrShareEnumSticky", 0) > 0
            ):
                srvsvc_enum_seen = True
                break
        if srvsvc_enum_seen:
            alerts.append(
                {
                    "level": "info",
                    "category": "share_enumeration",
                    "message": "Network share enumeration (srvsvc NetShareEnum) detected",
                }
            )

        # --- NTLMSSP weak auth alert ---
        for stream_id, (auth_type, auth_level) in self._stream_auth.items():
            if auth_type == "NTLMSSP" and auth_level == "Connect":
                alerts.append(
                    {
                        "level": "warn",
                        "category": "weak_auth",
                        "message": (
                            "NTLMSSP authentication at Connect level (no message integrity/privacy)"
                        ),
                    }
                )
                break  # One alert is sufficient

        # --- Task scheduler registration alert ---
        for srv_ops in self._server_ops.values():
            ts_ops = srv_ops.get("ITaskScheduler", Counter())
            if ts_ops.get("SchRpcRegisterTask", 0) > 0:
                alerts.append(
                    {
                        "level": "critical",
                        "category": "task_scheduler",
                        "message": "Remote scheduled task registration (SchRpcRegisterTask) detected",
                    }
                )
                break

        base["tables"] = tables
        if alerts:
            base["alerts"] = alerts
        return base
