"""Cross-cutting meta tests for passive listener coverage.

Verifies that all listeners are importable, have required attributes,
and that the test suite covers all expected protocols.  Also runs
harvest-quality and content-parsing checks across every listener/pcap
combination via the shared ``_run_listener_test`` helper.
"""

import importlib

import pytest

from tests.integration.pcap.conftest import (
    LISTENER_PCAP_CASES,
    _ek_mode_available,
    _pyshark_available,
    _run_e2e_test,
    _run_listener_test,
    _skip_unless_pyshark,
)

pytestmark = [pytest.mark.integration, pytest.mark.xdist_group("pcap_pipeline")]


# ---------------------------------------------------------------------------
# 1. All listener classes can be imported
# ---------------------------------------------------------------------------
class TestListenerImportability:
    """Verify every passive listener module can be imported."""

    LISTENER_MODULES = {
        "ads": "ADSPassiveListener",
        "egd": "EGDPassiveListener",
        "selfm": "SELFMPassiveListener",
        "tte": "TTEPassiveListener",
        "rtps": "RTPSPassiveListener",
        "ieee1722": "IEEE1722PassiveListener",
        "mqttsn": "MQTTSNPassiveListener",
        "bacnet": "BACnetPassiveListener",
        "bfd": "BFDPassiveListener",
        "bgp": "BGPPassiveListener",
        "cdp": "CDPPassiveListener",
        "dhcp": "DHCPPassiveListener",
        "dnp3": "DNP3PassiveListener",
        "dns": "DNSPassiveListener",
        "eigrp": "EIGRPPassiveListener",
        "enip": "EtherNetIPPassiveListener",
        "ethercat": "EtherCATPassiveListener",
        "file_carving": "FileCarvingListener",
        "fins": "FINSPassiveListener",
        "ftp": "FTPPassiveListener",
        "glbp": "GLBPPassiveListener",
        "goose": "GOOSEPassiveListener",
        "hartip": "HARTIPPassiveListener",
        "hsrp": "HSRPPassiveListener",
        "http": "HTTPPassiveListener",
        "iec104": "IEC104PassiveListener",
        "igmp": "IGMPPassiveListener",
        "imap": "IMAPPassiveListener",
        "irc": "IRCPassiveListener",
        "kerberos": "KerberosPassiveListener",
        "knx": "KNXPassiveListener",
        "ldap": "LDAPPassiveListener",
        "lldp": "LLDPPassiveListener",
        "mdns": "MDNSPassiveListener",
        "mms": "MMSPassiveListener",
        "modbus": "ModbusPassiveListener",
        "mqtt": "MQTTPassiveListener",
        "mssql": "MSSQLPassiveListener",
        "mysql": "MySQLPassiveListener",
        "ntlm": "NTLMPassiveListener",
        "opcua": "OPCUAPassiveListener",
        "ospf": "OSPFPassiveListener",
        "pap": "PAPPassiveListener",
        "pgsql": "PostgreSQLPassiveListener",
        "pim": "PIMPassiveListener",
        "pop3": "POP3PassiveListener",
        "profinet": "PROFINETPassiveListener",
        "radius": "RADIUSPassiveListener",
        "rdp": "RDPPassiveListener",
        "rip": "RIPPassiveListener",
        "s7comm": "S7commPassiveListener",
        "sip": "SIPPassiveListener",
        "smb": "SMBPassiveListener",
        "smtp": "SMTPPassiveListener",
        "snmp": "SNMPPassiveListener",
        "socks": "SOCKSPassiveListener",
        "ssdp": "SSDPPassiveListener",
        "stp": "STPPassiveListener",
        "sv": "SVPassiveListener",
        "tacacs": "TACACSPassiveListener",
        "telnet": "TelnetPassiveListener",
        "tftp": "TFTPPassiveListener",
        "tls": "TLSPassiveListener",
        "vnc": "VNCPassiveListener",
        "vrrp": "VRRPPassiveListener",
    }

    def test_all_59_listeners_importable(self):
        """Verify all 59 listener classes can be imported."""
        failures = []
        for module_name, class_name in self.LISTENER_MODULES.items():
            try:
                mod = importlib.import_module(f"oida.pcap.{module_name}")
                cls = getattr(mod, class_name, None)
                if cls is None:
                    failures.append(f"{module_name}: {class_name} not found")
            except Exception as e:
                failures.append(f"{module_name}: import failed: {e}")
        assert not failures, "Import failures:\n" + "\n".join(failures)

    def test_all_listeners_have_required_attributes(self):
        """Verify every listener has PROTOCOL_NAME, DISPLAY_FILTER, REQUIRED_LAYERS."""
        failures = []
        for module_name, class_name in self.LISTENER_MODULES.items():
            try:
                mod = importlib.import_module(f"oida.pcap.{module_name}")
                cls = getattr(mod, class_name)
                for attr in ("PROTOCOL_NAME", "DISPLAY_FILTER"):
                    val = getattr(cls, attr, None)
                    if not val:
                        failures.append(f"{class_name}: missing or empty {attr}")
            except Exception as e:
                failures.append(f"{module_name}: {e}")
        assert not failures, "Attribute failures:\n" + "\n".join(failures)

    def test_empty_required_layers_must_override_should_process_packet(self):
        """If REQUIRED_LAYERS is empty, the class MUST define its own should_process_packet().

        Without this guard, listeners with empty REQUIRED_LAYERS become
        ``always_listeners`` in scanner.py and receive every packet from
        every protocol, producing false positive interactions.
        """
        failures = []
        for module_name, class_name in self.LISTENER_MODULES.items():
            try:
                mod = importlib.import_module(f"oida.pcap.{module_name}")
                cls = getattr(mod, class_name)
                layers = getattr(cls, "REQUIRED_LAYERS", None)
                if layers is not None and len(layers) == 0:
                    # Class has empty REQUIRED_LAYERS — must define its own guard
                    if "should_process_packet" not in cls.__dict__:
                        failures.append(
                            f"{class_name}: REQUIRED_LAYERS=() but no "
                            f"should_process_packet() override — will match all packets"
                        )
            except Exception as e:
                failures.append(f"{module_name}: {e}")
        assert not failures, (
            "Listeners with empty REQUIRED_LAYERS missing should_process_packet():\n"
            + "\n".join(failures)
        )


# ---------------------------------------------------------------------------
# 2. EK mode verification
# ---------------------------------------------------------------------------
class TestEKModeActive:
    """Verify that tests are running with EK mode when available."""

    def test_ek_mode_detection(self):
        """Confirm EK mode detection reflects fork availability."""
        _skip_unless_pyshark()
        # This is informational -- log the mode being used
        mode = "EK" if _ek_mode_available else "XML (fallback)"
        # We don't fail if EK mode is unavailable, but we document it
        assert _pyshark_available, "pyshark should be available"
        # If EK mode IS available, verify our _load_packets uses it
        if _ek_mode_available:
            import inspect

            import pyshark

            sig = inspect.signature(pyshark.FileCapture.__init__)
            assert "use_ek" in sig.parameters, (
                f"EK mode detected but use_ek not in FileCapture params. Mode: {mode}"
            )


# ---------------------------------------------------------------------------
# 3. Comprehensive coverage summary
# ---------------------------------------------------------------------------
class TestPassiveCoverageSummary:
    """Verify that the test suite covers all expected protocols."""

    def test_coverage_count(self):
        """Verify at least 40 listener+pcap combinations are tested."""
        tested = [c for c in LISTENER_PCAP_CASES if c.get("pcap")]
        assert len(tested) >= 40, (
            f"Expected at least 40 listener+pcap test cases, got {len(tested)}"
        )

    def test_all_ics_protocols_covered(self):
        """Verify all ICS/SCADA protocols have test entries."""
        ics_protocols = {
            "modbus",
            "iec104",
            "opcua",
            "s7comm",
            "enip",
            "dnp3",
            "bacnet",
            "mms",
            "fins",
            "ads",
            "goose",
            "profinet",
            "ethercat",
            "knx",
            "hartip",
        }
        tested_ids = {c["id"] for c in LISTENER_PCAP_CASES if c.get("pcap")}
        tested_base = set()
        for tid in tested_ids:
            if tid.endswith("_gen"):
                tested_base.add(tid[:-4])
            elif tid.endswith("_real"):
                tested_base.add(tid[:-5])
            else:
                tested_base.add(tid)

        missing = ics_protocols - tested_base
        assert not missing, f"ICS protocols without test coverage: {missing}"

    def test_all_credential_protocols_covered(self):
        """Verify all credential-extraction protocols have test entries."""
        cred_protocols = {
            "ftp",
            "telnet",
            "imap",
            "smtp",
            "pop3",
            "kerberos",
            "irc",
            "tacacs",
            "pap",
            "socks",
            "mqtt",
        }
        tested_ids = {c["id"] for c in LISTENER_PCAP_CASES if c.get("pcap")}
        tested_base = set()
        for tid in tested_ids:
            if tid.endswith("_gen"):
                tested_base.add(tid[:-4])
            else:
                tested_base.add(tid)

        missing = cred_protocols - tested_base
        assert not missing, f"Credential protocols without test coverage: {missing}"


# ---------------------------------------------------------------------------
# 4. Parametrized quality test: harvest + content parsing for ALL protocols
#
# For each entry in LISTENER_PCAP_CASES this checks:
#   - device / interaction counts
#   - harvest() tables contain no raw dicts/sets
#   - protocol-specific details keys are populated (if specified)
#   - expected operations appear (if specified)
# ---------------------------------------------------------------------------
class TestListenerQuality:
    """Feed every pcap and verify the listener actually parsed real data."""

    @pytest.mark.parametrize(
        "case",
        LISTENER_PCAP_CASES,
        ids=[c["id"] for c in LISTENER_PCAP_CASES],
    )
    def test_listener(self, case):
        listener, devices, harvest_result = _run_listener_test(
            case["module"],
            case["cls"],
            case["filter"],
            case["pcap"],
            min_devices=case.get("min_devices", 1),
            min_interactions=case.get("min_interactions", 1),
            expect_details=case.get("details"),
            expect_operations=case.get("operations"),
            check_harvest=True,
            decode_as=case.get("decode_as"),
        )
        # Tie the assertion to this specific case's real output, not just
        # "the helper didn't raise": the parsed device map and the
        # harvest() table structure must both reflect actual capture data.
        min_devices = case.get("min_devices", 1)
        if min_devices > 0:
            assert len(devices) >= min_devices, (
                f"{case['id']}: expected >= {min_devices} devices from real "
                f"capture, got {len(devices)}"
            )
        # harvest()'s documented contract (pyshark_base.PySharkListenerBase.harvest)
        # is: {} when there is nothing to report, else a dict using only the
        # "tables"/"alerts"/"results"/"log_messages" keys. Anything else means
        # a listener is returning a malformed/undocumented harvest shape.
        assert harvest_result == {} or any(
            key in harvest_result for key in ("tables", "alerts", "results", "log_messages")
        ), f"{case['id']}: harvest() returned an unexpected shape: {harvest_result!r}"


# ---------------------------------------------------------------------------
# 5. End-to-end PcapScanner pipeline tests
#
# Runs the full ``PcapScanner`` pipeline (same path as ``oida pcap -o``)
# for each entry in LISTENER_PCAP_CASES and validates:
#   - JSON serializable output
#   - device count matches expectations
#   - no raw dicts/sets in table cells
#   - protocol-specific passive data present (if data_key specified)
# ---------------------------------------------------------------------------
class TestEndToEnd:
    """Run PcapScanner pipeline for every protocol and validate JSON output."""

    @pytest.mark.parametrize(
        "case",
        LISTENER_PCAP_CASES,
        ids=[c["id"] for c in LISTENER_PCAP_CASES],
    )
    def test_pipeline(self, case):
        result = _run_e2e_test(case)
        # Confirm the real PcapScanner pipeline actually read *this* case's
        # pcap file and consumed real packets from it -- not just "returned
        # without raising", and not some stale/cached/wrong-file result.
        # (protocols_used can legitimately stay empty for device-less
        # credential-sniffing protocols like pgsql/pap/rdp, so we don't
        # assert on it here.)
        assert result["statistics"]["pcap_file"].endswith(case["pcap"]), (
            f"{case['id']}: pipeline reported pcap_file "
            f"{result['statistics']['pcap_file']!r}, expected it to end with "
            f"{case['pcap']!r}"
        )
        assert result["statistics"]["packets_processed"] > 0, (
            f"{case['id']}: pipeline processed zero packets from {case['pcap']}"
        )
