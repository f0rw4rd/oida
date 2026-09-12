"""SRVSVC opnum table must match the MS-SRVS opnum assignments.

Reference: [MS-SRVS] 3.1.4 "Message Processing Events and Sequencing Rules"
(cross-checked against Wireshark's srvsvc.opnum value_string, ``tshark -G values``).

Three entries used to be off-by-a-method, which made the listener print a
wrong -- and in one case far more alarming -- RPC method name:

  * opnum 24 was labelled ``NetrServerDiskEnum`` (that is opnum 23; 24 is
    ``NetrServerStatisticsGet``)
  * opnum 31 was labelled ``NetrpSetFileSecurity`` (that is opnum 40; 31 is
    ``NetprPathCanonicalize``)
  * opnum 48 was labelled ``NetrShareDelEx`` (that is opnum 57; 48 is
    ``NetrDfsCreateExitPoint``)
"""

from oida.pcap.msrpc import SRVSVC_OPNUMS

# (opnum, canonical MS-SRVS method name)
MS_SRVS_OPNUMS = {
    "0": "NetrCharDevEnum",
    "8": "NetrConnectionEnum",
    "9": "NetrFileEnum",
    "15": "NetrShareEnum",
    "16": "NetrShareGetInfo",
    "17": "NetrShareSetInfo",
    "18": "NetrShareDel",
    "21": "NetrServerGetInfo",
    "23": "NetrServerDiskEnum",
    "24": "NetrServerStatisticsGet",
    "28": "NetrRemoteTOD",
    "31": "NetprPathCanonicalize",
    "36": "NetrShareEnumSticky",
    "40": "NetrpSetFileSecurity",
    "48": "NetrDfsCreateExitPoint",
    "57": "NetrShareDelEx",
}


def test_srvsvc_opnums_match_ms_srvs():
    """Every opnum present in the listener table must carry the MS-SRVS name."""
    wrong = {
        op: (name, MS_SRVS_OPNUMS[op])
        for op, name in SRVSVC_OPNUMS.items()
        if op in MS_SRVS_OPNUMS and name != MS_SRVS_OPNUMS[op]
    }
    assert not wrong, f"SRVSVC opnum names disagree with MS-SRVS: {wrong}"


def test_srvsvc_disk_enum_and_statistics_get_are_not_swapped():
    assert SRVSVC_OPNUMS.get("23") == "NetrServerDiskEnum"
    assert SRVSVC_OPNUMS.get("24") == "NetrServerStatisticsGet"


def test_srvsvc_set_file_security_is_opnum_40():
    assert SRVSVC_OPNUMS.get("40") == "NetrpSetFileSecurity"
    assert SRVSVC_OPNUMS.get("31") != "NetrpSetFileSecurity"


def test_srvsvc_share_del_ex_is_opnum_57():
    """A destructive-sounding name must not be attached to a DFS call."""
    assert SRVSVC_OPNUMS.get("57") == "NetrShareDelEx"
    assert SRVSVC_OPNUMS.get("48") != "NetrShareDelEx"


def test_no_opnum_name_is_duplicated():
    names = [n for n in SRVSVC_OPNUMS.values()]
    assert len(names) == len(set(names)), f"duplicate method names: {names}"
