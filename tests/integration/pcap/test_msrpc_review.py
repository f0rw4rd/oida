"""Regression tests for the SVCCTL opnum table in the MSRPC passive listener.

Bug found in the pcap bug hunt: ``SVCCTL_OPNUMS`` mapped opnum 36 to
"QueryServiceConfig2W".  Per MS-SCMR section 3.1.4 ("Methods in RPC Opnum
Order") opnum 36 is RChangeServiceConfig2A -- a service-configuration WRITE --
while RQueryServiceConfig2W is opnum 39 and was missing from the table
entirely.  For a passive monitoring tool that means a configuration
modification was displayed to the operator as a harmless read.

Source of truth:
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/0d7a7011-9f41-470d-ad52-8535b47ac282
"""

import pytest

pytestmark = [pytest.mark.integration]

# Opnum -> method name (MS-SCMR "R" prefix dropped, matching msrpc.py style).
# Only the entries this module claims to know are listed; the table is allowed
# to be a subset of MS-SCMR but every entry it does have must be correct.
MS_SCMR_OPNUMS = {
    "0": "CloseServiceHandle",
    "1": "ControlService",
    "2": "DeleteService",
    "3": "LockServiceDatabase",
    "4": "QueryServiceObjectSecurity",
    "5": "SetServiceObjectSecurity",
    "6": "QueryServiceStatus",
    "7": "SetServiceStatus",
    "8": "UnlockServiceDatabase",
    "9": "NotifyBootConfigStatus",
    "11": "ChangeServiceConfigW",
    "12": "CreateServiceW",
    "13": "EnumDependentServicesW",
    "14": "EnumServicesStatusW",
    "15": "OpenSCManagerW",
    "16": "OpenServiceW",
    "17": "QueryServiceConfigW",
    "18": "QueryServiceLockStatusW",
    "19": "StartServiceW",
    "20": "GetServiceDisplayNameW",
    "21": "GetServiceKeyNameW",
    "23": "ChangeServiceConfigA",
    "24": "CreateServiceA",
    "25": "EnumDependentServicesA",
    "26": "EnumServicesStatusA",
    "27": "OpenSCManagerA",
    "28": "OpenServiceA",
    "29": "QueryServiceConfigA",
    "30": "QueryServiceLockStatusA",
    "31": "StartServiceA",
    "32": "GetServiceDisplayNameA",
    "33": "GetServiceKeyNameA",
    "35": "EnumServiceGroupW",
    "36": "ChangeServiceConfig2A",
    "37": "ChangeServiceConfig2W",
    "38": "QueryServiceConfig2A",
    "39": "QueryServiceConfig2W",
    "40": "QueryServiceStatusEx",
    "41": "EnumServicesStatusExA",
    "42": "EnumServicesStatusExW",
    "44": "CreateServiceWOW64A",
    "45": "CreateServiceWOW64W",
    "47": "NotifyServiceStatusChange",
    "48": "GetNotifyResults",
    "49": "CloseNotifyHandle",
    "50": "ControlServiceExA",
    "51": "ControlServiceExW",
    "56": "QueryServiceConfigEx",
    "60": "CreateWowService",
    "64": "OpenSCManager2",
}

# Opnums reserved for local use by MS-SCMR -- they must never be labeled.
NOT_USED_ON_WIRE = {"10", "22", "34", "43", "46", "52", "53", "54", "55", "57", "58", "59"}

# Prefixes that denote a state-changing operation.
WRITE_PREFIXES = ("Change", "Create", "Delete", "Set", "Start", "Control", "Notify", "Lock")
READ_PREFIXES = ("Query", "Enum", "Get")


def _table():
    from oida.pcap.msrpc import SVCCTL_OPNUMS

    return SVCCTL_OPNUMS


class TestSvcctlOpnumTable:
    def test_opnum_36_is_a_write_not_a_query(self):
        """The specific regression: 36 is RChangeServiceConfig2A."""
        assert _table()["36"] == "ChangeServiceConfig2A", (
            "opnum 36 is RChangeServiceConfig2A (MS-SCMR 3.1.4), a service-config "
            "WRITE; labeling it QueryServiceConfig2W reports a modification as a read"
        )

    def test_query_service_config2w_is_opnum_39(self):
        assert _table().get("39") == "QueryServiceConfig2W", (
            "RQueryServiceConfig2W is opnum 39 per MS-SCMR and must be present"
        )

    @pytest.mark.parametrize(
        "opnum,expected",
        [
            ("36", "ChangeServiceConfig2A"),
            ("37", "ChangeServiceConfig2W"),
            ("38", "QueryServiceConfig2A"),
            ("39", "QueryServiceConfig2W"),
        ],
    )
    def test_config2_quad_is_correct(self, opnum, expected):
        """The 2A/2W change/query quad is the easiest group to get wrong."""
        assert _table().get(opnum) == expected

    def test_every_entry_matches_ms_scmr(self):
        wrong = {
            op: (name, MS_SCMR_OPNUMS.get(op))
            for op, name in _table().items()
            if MS_SCMR_OPNUMS.get(op) != name
        }
        assert not wrong, f"opnums disagreeing with MS-SCMR (got, expected): {wrong}"

    def test_no_reserved_opnums_labeled(self):
        bogus = {op: name for op, name in _table().items() if op in NOT_USED_ON_WIRE}
        assert not bogus, f"opnums MS-SCMR reserves for local use are labeled: {bogus}"

    def test_no_write_opnum_is_labeled_as_a_read(self):
        """Guards the bug class, not just the one instance."""
        mislabeled = {}
        for opnum, expected in MS_SCMR_OPNUMS.items():
            actual = _table().get(opnum)
            if actual is None:
                continue
            if expected.startswith(WRITE_PREFIXES) and actual.startswith(READ_PREFIXES):
                mislabeled[opnum] = (actual, expected)
        assert not mislabeled, (
            f"state-changing SVCCTL operations labeled as reads (got, expected): {mislabeled}"
        )

    def test_keys_are_strings_and_values_unique(self):
        table = _table()
        assert all(isinstance(k, str) for k in table), "lookup is done with string opnums"
        dupes = {n for n in table.values() if list(table.values()).count(n) > 1}
        assert not dupes, f"the same method name is mapped to several opnums: {dupes}"

    def test_table_is_wired_into_the_interface_dispatch(self):
        from oida.pcap import msrpc

        assert msrpc.INTERFACE_OPNUMS["SVCCTL"] is msrpc.SVCCTL_OPNUMS
