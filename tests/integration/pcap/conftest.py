"""Conftest for pcap integration tests.

Provides shared helpers for EK-mode packet loading and pyshark detection,
plus a fresh asyncio event loop fixture to avoid contamination from other
async tests (OPC UA, etc.) that run in the same pytest session.
"""

import asyncio
import os
import shutil
import subprocess

import pytest

# ---------------------------------------------------------------------------
# Event loop isolation
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _fresh_event_loop():
    """Create a fresh event loop for each pcap test.

    pyshark's FileCapture creates and uses an asyncio event loop.
    When the full test suite runs, previous async tests (e.g. OPC UA)
    may leave behind a closed or still-running event loop, causing
    'RuntimeError: This event loop is already running' or
    'RuntimeError: Event loop is closed'.

    This fixture replaces the current event loop with a fresh one before
    each test and restores/closes it after.
    """
    # Save the current loop (may be None or closed)
    try:
        old_loop = asyncio.get_event_loop()
    except RuntimeError:
        old_loop = None

    # Create and set a fresh loop
    new_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(new_loop)

    yield

    # Clean up: close the test loop
    try:
        new_loop.close()
    except Exception:
        pass

    # Restore previous loop state (or set a new default)
    if old_loop is not None and not old_loop.is_closed():
        asyncio.set_event_loop(old_loop)
    else:
        asyncio.set_event_loop(asyncio.new_event_loop())


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# tests/integration/pcap/ -> tests/integration/ -> tests/ -> tests/fixtures/pcap/
_TESTS_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURE_DIR = os.path.join(_TESTS_DIR, "fixtures", "pcap")

# ---------------------------------------------------------------------------
# pyshark / tshark availability
# ---------------------------------------------------------------------------
_pyshark_available = False
_ek_mode_available = False
try:
    import pyshark  # noqa: F401

    _pyshark_available = bool(shutil.which("tshark"))
    if _pyshark_available:
        # Probe for EK mode support (f0rw4rd/pyshark fork)
        import inspect

        sig = inspect.signature(pyshark.FileCapture.__init__)
        _ek_mode_available = "use_ek" in sig.parameters
except Exception:
    pass


def _skip_unless_pyshark():
    if not _pyshark_available:
        pytest.skip("pyshark or tshark not available")


# git-lfs pointer signature -- pcap fixtures stored in LFS are <200-byte text
# pointers until 'git lfs pull' fetches them.  tshark crashes on the pointer
# text; detect and skip instead of failing.
_LFS_POINTER_MAGIC = b"version https://git-lfs.github.com/spec/v1"


def _is_lfs_pointer(path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(len(_LFS_POINTER_MAGIC)).startswith(_LFS_POINTER_MAGIC)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Packet loading (use_ek=True for production parity)
# ---------------------------------------------------------------------------
_MAX_TEST_PACKETS = 500  # Cap packets to keep tests fast (ethercat has 44k)


def _load_packets(
    pcap_path: str,
    display_filter: str | None = None,
    max_packets: int = _MAX_TEST_PACKETS,
    decode_as: dict | None = None,
    override_prefs: dict | None = None,
    _retries: int = 2,
) -> list:
    """Load packets from *pcap_path* using pyshark.FileCapture.

    Production uses ``use_ek=True`` for speed; we replicate that here so
    tests exercise the same EK-mode field names that listeners see at
    runtime.  Falls back to XML mode if the fork isn't installed.

    *max_packets* caps the number of packets loaded to keep tests fast.
    *_retries* allows up to 2 retries if TShark crashes (retcode 255) due to
    transient resource pressure in the full test suite.
    """
    import time

    import pyshark
    from pyshark.capture.capture import TSharkCrashException

    if _is_lfs_pointer(pcap_path):
        pytest.skip(
            f"pcap fixture is an unfetched git-lfs pointer (run 'git lfs pull'): {pcap_path}"
        )

    cap_kwargs: dict = {"input_file": pcap_path}
    if display_filter:
        cap_kwargs["display_filter"] = display_filter
    if decode_as:
        cap_kwargs["decode_as"] = decode_as
    if override_prefs:
        cap_kwargs["override_prefs"] = override_prefs
    if _ek_mode_available:
        cap_kwargs["use_ek"] = True

    try:
        cap = pyshark.FileCapture(**cap_kwargs)
        packets = []
        for i, pkt in enumerate(cap):
            packets.append(pkt)
            if i + 1 >= max_packets:
                break
        try:
            cap.close()
        except Exception:
            pass  # TShark may exit non-zero when killed after packet cap; not a real crash
        return packets
    except TSharkCrashException:
        if _retries > 0:
            time.sleep(0.3)  # brief pause to let previous TShark process exit
            return _load_packets(
                pcap_path,
                display_filter=display_filter,
                max_packets=max_packets,
                decode_as=decode_as,
                override_prefs=override_prefs,
                _retries=_retries - 1,
            )
        raise


def _pcap_path(*parts: str) -> str:
    """Return absolute path; skip test if file is missing."""
    path = os.path.join(FIXTURE_DIR, *parts)
    if not os.path.exists(path):
        pytest.fail(f"Pcap fixture not found: {path}")
    return path


def _count_tshark_packets(
    pcap_path: str,
    display_filter: str,
    decode_as: dict | None = None,
) -> int:
    """Count packets in *pcap_path* matching *display_filter* using tshark.

    Returns 0 if tshark is unavailable or the command fails.
    """
    cmd = ["tshark", "-r", pcap_path, "-Y", display_filter, "-T", "fields", "-e", "frame.number"]
    if decode_as:
        for k, v in decode_as.items():
            cmd.extend(["-d", f"{k},{v}"])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return 0
        return len([line for line in result.stdout.strip().split("\n") if line.strip()])
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return 0


# ---------------------------------------------------------------------------
# Shared listener test helper
# ---------------------------------------------------------------------------

import importlib  # noqa: E402 (already imported at top for some callers)


def _run_listener_test(
    module_name: str,
    class_name: str,
    display_filter: str,
    pcap_subpath: str,
    *,
    min_devices: int = 1,
    min_interactions: int = 1,
    expect_details: list[str] | None = None,
    expect_operations: list[str] | None = None,
    check_harvest: bool = True,
    decode_as: dict | None = None,
):
    """Run smoke + content-quality assertions for a passive listener.

    Args:
        module_name: Module under ``oida.pcap`` (e.g. ``"modbus"``).
        class_name: Listener class name.
        display_filter: tshark display filter.
        pcap_subpath: Path relative to fixture dir.
        min_devices: Minimum device count (0 to skip).
        min_interactions: Minimum interaction count (0 to skip).
        expect_details: Detail-dict keys that at least one interaction
            must have with a truthy value (e.g. ``["function_code"]``).
            Verifies the listener actually parsed protocol fields.
        expect_operations: Operation strings that should appear in at
            least one interaction's ``operation`` field.
        check_harvest: Run harvest() and assert no raw dicts/sets in
            table cells.
        decode_as: tshark decode-as rules for protocols that need
            explicit port mapping (e.g. ``{"tcp.port==8009": "ajp13"}``).

    Returns:
        Tuple of ``(listener, devices, harvest_result)``.
    """
    _skip_unless_pyshark()
    pcap = _pcap_path(pcap_subpath)
    mod = importlib.import_module(f"oida.pcap.{module_name}")
    cls = getattr(mod, class_name)
    listener = cls(interface="lo", timeout=10)
    listener._x509 = True
    # Mirror the production PcapScanner pipeline: forward the listener's
    # OVERRIDE_PREFS to tshark so prefs like
    # ``tcp.analyze_sequence_numbers=FALSE`` (which surfaces otherwise-dropped
    # MongoDB OP_INSERT segments) take effect under the same capture the
    # listener sees at runtime.
    override_prefs = getattr(cls, "OVERRIDE_PREFS", None) or None
    packets = _load_packets(
        pcap,
        display_filter=display_filter,
        decode_as=decode_as,
        override_prefs=override_prefs,
    )
    devices = listener.feed_packets(iter(packets))

    assert isinstance(devices, dict)
    if min_devices > 0:
        assert len(devices) >= min_devices, f"Expected >= {min_devices} devices, got {len(devices)}"
    if min_interactions > 0:
        assert len(listener.interactions) >= min_interactions, (
            f"Expected >= {min_interactions} interactions, got {len(listener.interactions)}"
        )

    # Verify protocol fields were actually parsed
    if expect_details and listener.interactions:
        for key in expect_details:
            found = any(ix.details.get(key) is not None for ix in listener.interactions)
            assert found, (
                f"No interaction has details[{key!r}]; "
                f"EK field extraction likely broken. "
                f"Sample details: {listener.interactions[0].details}"
            )

    # Verify expected operations appear
    if expect_operations and listener.interactions:
        seen_ops = {ix.operation for ix in listener.interactions if ix.operation}
        for expected in expect_operations:
            assert any(expected in op for op in seen_ops), (
                f"Expected operation containing {expected!r} not found; "
                f"saw: {sorted(seen_ops)[:10]}"
            )

    result = {}
    if check_harvest:
        result = listener.harvest()
        for table in result.get("tables", []):
            for row in table.get("rows", []):
                for cell in row:
                    assert not isinstance(cell, dict), f"Raw dict in table cell: {cell}"
                    assert not isinstance(cell, set), f"Raw set in table cell: {cell}"

    return listener, devices, result


# ---------------------------------------------------------------------------
# End-to-end PcapScanner pipeline helper
# ---------------------------------------------------------------------------


def _run_e2e_test(case: dict) -> dict:
    """Run the full PcapScanner pipeline for a listener case and validate output.

    This tests the same code path as ``oida pcap -o``: PcapScanner creates
    listeners, feeds packets, collects devices, and returns JSON-serializable
    results.

    Args:
        case: Dict from LISTENER_PCAP_CASES.

    Returns:
        The result dict from PcapScanner.run_scan().
    """
    import json

    from oida.protocols.pcap.scanner import PcapScanner

    _skip_unless_pyshark()
    pcap = _pcap_path(case["pcap"])
    module_name = case["module"]

    scan_args: dict = {"protocols": module_name}
    decode_as = case.get("decode_as")
    if decode_as:
        # PcapScanner expects semicolon-separated "key,value" pairs
        scan_args["decode_as"] = ";".join(f"{k},{v}" for k, v in decode_as.items())
    max_packets = case.get("max_packets", _MAX_TEST_PACKETS)
    scan_args["max_packets"] = max_packets
    scanner = PcapScanner(pcap, args=scan_args)
    result = scanner.run_scan()

    # --- Pipeline completed assertions ---
    assert "statistics" in result, "Missing 'statistics' key in pipeline output"
    assert result["statistics"]["packets_processed"] >= 0
    # JSON serialization validation
    serialized = json.dumps(result, default=str)
    assert len(serialized) > 0
    for key in ("pcap_file", "scan_mode", "protocols_used", "devices", "statistics"):
        assert key in result, f"Missing top-level key: {key}"

    # --- Device count ---
    min_devices = case.get("min_devices", 1)
    if min_devices > 0:
        assert len(result["devices"]) >= min_devices, (
            f"E2E {module_name}: expected >= {min_devices} devices, got {len(result['devices'])}"
        )

    # --- Table quality (no raw dicts/sets in cells) ---
    for table in result.get("tables", []):
        for row in table.get("rows", []):
            for cell in row:
                assert not isinstance(cell, dict), (
                    f"E2E {module_name}: raw dict in table cell: {cell}"
                )
                assert not isinstance(cell, set), (
                    f"E2E {module_name}: raw set in table cell: {cell}"
                )

    # --- Protocol-specific passive data on devices ---
    data_key = case.get("data_key")
    if data_key and result["devices"]:
        has_data = any(data_key in d for d in result["devices"])
        assert has_data, (
            f"E2E {module_name}: no device has '{data_key}'; "
            f"keys seen: {[list(d.keys()) for d in result['devices'][:2]]}"
        )

        # Check required fields inside the passive data — at least one
        # device with data_key must have each field (server vs client
        # devices may use different key names)
        data_fields = case.get("data_fields", [])
        if data_fields:
            devices_with_data = [d[data_key] for d in result["devices"] if d.get(data_key)]
            for field_name in data_fields:
                found = any(field_name in pdata for pdata in devices_with_data)
                assert found, (
                    f"E2E {module_name}: no device has '{field_name}' in "
                    f"{data_key}; sample keys: "
                    f"{list(devices_with_data[0].keys()) if devices_with_data else '[]'}"
                )

    # Every device must be JSON-serializable individually
    for device in result.get("devices", []):
        json.dumps(device, default=str)

    return result


# ---------------------------------------------------------------------------
# Complete listener -> pcap fixture mapping
#
# Each dict defines a test case.  Required keys: id, module, cls, filter, pcap.
# Optional:
#   min_devices (default 1)      — expected device count
#   min_interactions (default 1) — expected interaction count
#   details                      — detail-dict keys that at least one
#                                  interaction must have with a truthy value.
#                                  Proves the listener *actually parsed* fields.
#   operations                   — substrings that should appear in at least
#                                  one interaction.operation field.
#   data_key                     — passive data attribute to check on devices
#                                  (e.g. "modbus_passive_data")
#   data_fields                  — keys that must exist in the passive data dict
#
# Setting min_devices/min_interactions to 0 means "just don't crash".
# ---------------------------------------------------------------------------
LISTENER_PCAP_CASES: list[dict] = [
    # -----------------------------------------------------------------------
    # ICS / SCADA protocols
    # -----------------------------------------------------------------------
    {
        "id": "modbus",
        "module": "modbus",
        "cls": "ModbusPassiveListener",
        "filter": "mbtcp",
        "pcap": "modbus/cisagov_modbus_example.pcap",
        "details": ["function_code", "unit_id", "trans_id"],
        "operations": ["Read"],
        "data_key": "modbus_passive_data",
        "data_fields": [
            "role",
            "unit_ids",
            "function_codes_seen",
            "function_names",
            "read_ranges",
            "write_ranges",
            "write_operations",
            "read_operations",
            "protocol",
            "first_seen",
            "last_seen",
        ],
    },
    {
        "id": "modbus_writes",
        "module": "modbus",
        "cls": "ModbusPassiveListener",
        "filter": "mbtcp",
        "pcap": "modbus/modbus_tcp_full.pcap",
        "details": ["function_code", "unit_id"],
        "operations": ["Write"],
        "data_key": "modbus_passive_data",
        "data_fields": [
            "role",
            "unit_ids",
            "function_codes_seen",
            "write_operations",
            "read_operations",
            "protocol",
        ],
    },
    {
        "id": "iec104",
        "module": "iec104",
        "cls": "IEC104PassiveListener",
        "filter": "iec60870_104",
        "pcap": "iec104/emreekin_iec104_baselines.pcap",
        "details": ["type_id", "type_name", "common_address", "rw"],
        "operations": ["C_SC_NA_1"],
        "data_key": "iec104_passive_data",
        "data_fields": ["role", "common_addresses", "type_ids_seen", "type_names"],
    },
    {
        "id": "iec104_cmd",
        "module": "iec104",
        "cls": "IEC104PassiveListener",
        "filter": "iec60870_104",
        "pcap": "iec104/emreekin_iec104_type58_59.pcap",
        "details": ["type_id", "type_name", "rw", "ioa"],
        "operations": ["C_SC_TA_1", "C_DC_TA_1"],
        "data_key": "iec104_passive_data",
        "data_fields": ["role", "common_addresses", "type_ids_seen", "type_names"],
    },
    {
        "id": "opcua",
        "module": "opcua",
        "cls": "OPCUAPassiveListener",
        "filter": "opcua",
        "pcap": "opcua/cisagov_opcua_with-gap_with-handshake.pcap",
        "details": ["service"],
        "operations": ["GetEndpoints"],
        "data_key": "opcua_passive_data",
        "data_fields": ["role", "services_seen"],
    },
    {
        "id": "s7comm",
        "module": "s7comm",
        "cls": "S7commPassiveListener",
        "filter": "s7comm",
        "pcap": "s7comm/cisagov_snap7.pcap",
        "details": ["function_code"],
        "data_key": "s7comm_passive_data",
        "data_fields": ["role"],
    },
    {
        "id": "s7comm_gen",
        "module": "s7comm",
        "cls": "S7commPassiveListener",
        "filter": "s7comm",
        "pcap": "s7comm/generated_s7comm.pcap",
        "details": ["function_code"],
    },
    {
        "id": "enip",
        "module": "enip",
        "cls": "EtherNetIPPassiveListener",
        "filter": "enip or cip",
        "pcap": "enip/cisagov_enip_cip_example.pcap",
        "details": ["command_name"],
        "data_key": "enip_passive_data",
        "data_fields": ["protocol"],
    },
    {
        "id": "enip_gen",
        "module": "enip",
        "cls": "EtherNetIPPassiveListener",
        "filter": "enip or cip",
        "pcap": "enip/generated_enip.pcap",
        "details": ["command_name"],
    },
    {
        "id": "dnp3",
        "module": "dnp3",
        "cls": "DNP3PassiveListener",
        "filter": "dnp3",
        "pcap": "dnp3/cisagov_dnp3_example.pcap",
        "details": ["function_name"],
        "data_key": "dnp3_passive_data",
        "data_fields": ["role"],
    },
    {
        "id": "bacnet",
        "module": "bacnet",
        "cls": "BACnetPassiveListener",
        "filter": "bacapp",
        "pcap": "bacnet/cisagov_bacnet_example.pcap",
        "details": ["service"],
        "data_key": "bacnet_passive_data",
        "data_fields": ["protocol"],
    },
    {
        "id": "mms",
        "module": "mms",
        "cls": "MMSPassiveListener",
        "filter": "acse or mms",
        "pcap": "mms/iti_iec61850_session.pcap",
        "data_key": "mms_passive_data",
        "data_fields": ["role", "protocol"],
    },
    {
        "id": "fins",
        "module": "fins",
        "cls": "FINSPassiveListener",
        "filter": "omron",
        "pcap": "fins/cisagov_omron_fins_tcp.pcap",
        "details": ["command_code"],
        "data_key": "fins_passive_data",
        "data_fields": ["role", "protocol"],
    },
    {
        "id": "fins_gen",
        "module": "fins",
        "cls": "FINSPassiveListener",
        "filter": "omron",
        "pcap": "fins/generated_fins.pcap",
        "details": ["command_code"],
    },
    {
        "id": "ads",
        "module": "ads",
        "cls": "ADSPassiveListener",
        "filter": "ams",
        "pcap": "ads/iti_addroute1.pcapng",
        "details": ["command_name"],
        "data_key": "ads_passive_data",
        "data_fields": ["role", "protocol"],
    },
    {
        "id": "goose",
        "module": "goose",
        "cls": "GOOSEPassiveListener",
        "filter": "goose",
        "pcap": "goose/goosestalker_GOOSE.pcap",
        "data_key": "goose_passive_data",
        "data_fields": ["role", "protocol"],
    },
    {
        "id": "profinet",
        "module": "profinet",
        "cls": "PROFINETPassiveListener",
        "filter": "pn_io || pn_dcp || pn_rt || pn_io.opnum",
        "pcap": "profinet/cisagov_profinet_io_cm_mixed_1.pcap",
        "data_key": "profinet_passive_data",
        "data_fields": ["role", "protocol"],
    },
    {
        "id": "ethercat",
        "module": "ethercat",
        "cls": "EtherCATPassiveListener",
        "filter": "ecat",
        "pcap": "ethercat/cisagov_ethercat_example.pcap",
        "data_key": "ethercat_passive_data",
        "data_fields": ["role", "protocol"],
        "max_packets": 1000,  # PCAP has 44k packets; cap e2e pipeline to stay under 60s
    },
    {
        "id": "knx",
        "module": "knx",
        "cls": "KNXPassiveListener",
        "filter": "kip",
        "pcap": "knx/ndpi_knxip.pcapng",
        "data_key": "knx_passive_data",
        "data_fields": ["role", "protocol"],
    },
    {
        "id": "hartip",
        "module": "hartip",
        "cls": "HARTIPPassiveListener",
        "filter": "hart_ip",
        "pcap": "hart/iti_hart_ip.pcap",
        "details": ["command"],
        "data_key": "hartip_passive_data",
        "data_fields": ["role", "protocol"],
    },
    # -----------------------------------------------------------------------
    # Routing / FHRP / multicast
    # -----------------------------------------------------------------------
    {
        "id": "ospf",
        "module": "ospf",
        "cls": "OSPFPassiveListener",
        "filter": "ospf",
        "pcap": "ospf/generated_ospf.pcap",
        "details": ["router_id"],
    },
    {
        "id": "eigrp",
        "module": "eigrp",
        "cls": "EIGRPPassiveListener",
        "filter": "eigrp",
        "pcap": "eigrp/generated_eigrp.pcap",
        "details": ["opcode"],
    },
    {
        "id": "rip",
        "module": "rip",
        "cls": "RIPPassiveListener",
        "filter": "rip",
        "pcap": "rip/generated_rip.pcap",
    },
    {
        "id": "pim",
        "module": "pim",
        "cls": "PIMPassiveListener",
        "filter": "pim",
        "pcap": "pim/generated_pim.pcap",
    },
    {
        "id": "glbp",
        "module": "glbp",
        "cls": "GLBPPassiveListener",
        "filter": "glbp",
        "pcap": "glbp/generated_glbp.pcap",
    },
    {
        "id": "hsrp",
        "module": "hsrp",
        "cls": "HSRPPassiveListener",
        "filter": "hsrp",
        "pcap": "hsrp/filtered_hsrp.pcap",
        "min_devices": 2,
        "details": ["version", "state", "virtual_ip"],
        "data_key": "hsrp_data",
        "data_fields": ["version", "state_name", "group", "priority", "protocol"],
    },
    {
        "id": "vrrp",
        "module": "vrrp",
        "cls": "VRRPPassiveListener",
        "filter": "vrrp",
        "pcap": "vrrp/filtered_vrrp.pcap",
        "details": ["vrid", "version", "addr_count", "checksum"],
        "data_key": "vrrp_data",
        "data_fields": [
            "vrid",
            "version",
            "priority",
            "virtual_ips",
            "addr_count",
            "auth_type",
        ],
    },
    {
        "id": "bfd",
        "module": "bfd",
        "cls": "BFDPassiveListener",
        "filter": "bfd",
        "pcap": "bfd/generated_bfd.pcap",
        "min_devices": 2,
        "min_interactions": 2,
        "details": ["version", "state_name", "auth_type", "auth_len"],
        "operations": ["BFD Up"],
        "data_key": "bfd_passive_data",
        "data_fields": ["role", "protocol", "version", "state"],
    },
    # -----------------------------------------------------------------------
    # Credential / auth protocols
    # -----------------------------------------------------------------------
    {
        "id": "ftp",
        "module": "ftp",
        "cls": "FTPPassiveListener",
        "filter": "ftp",
        "pcap": "ftp/bruteshark_ftp.pcap",
        "details": ["command"],
    },
    {
        "id": "telnet",
        "module": "telnet",
        "cls": "TelnetPassiveListener",
        "filter": "telnet",
        "pcap": "telnet/bruteshark_telnet.pcap",
    },
    {
        "id": "imap",
        "module": "imap",
        "cls": "IMAPPassiveListener",
        "filter": "imap",
        "pcap": "imap/bruteshark_imap_login1.pcap",
    },
    {
        "id": "smtp",
        "module": "smtp",
        "cls": "SMTPPassiveListener",
        "filter": "smtp",
        "pcap": "smtp/bruteshark_smtp_auth_login.pcap",
    },
    {
        "id": "pop3",
        "module": "pop3",
        "cls": "POP3PassiveListener",
        "filter": "pop",
        "pcap": "pop3/bruteshark_pop3.pcap",
    },
    {
        "id": "kerberos",
        "module": "kerberos",
        "cls": "KerberosPassiveListener",
        "filter": "kerberos",
        "pcap": "kerberos/bruteshark_kerberos_v5_tcp.pcap",
        "details": ["msg_type"],
    },
    {
        "id": "ntlm_smb",
        "module": "ntlm",
        "cls": "NTLMPassiveListener",
        "filter": "ntlmssp",
        "pcap": "smb/bruteshark_ntlm_smb.pcap",
        "details": ["msg_type"],
        "max_packets": 1000,  # PCAP has 1000 total; real credentials start at packet 707
    },
    {
        "id": "irc",
        "module": "irc",
        "cls": "IRCPassiveListener",
        "filter": "irc",
        "pcap": "irc/generated_irc.pcap",
    },
    {
        "id": "tacacs",
        "module": "tacacs",
        "cls": "TACACSPassiveListener",
        "filter": "tacacs or tacplus",
        "pcap": "tacacs/generated_tacacs.pcap",
    },
    {
        "id": "pap",
        "module": "pap",
        "cls": "PAPPassiveListener",
        "filter": "pap",
        "pcap": "pap/generated_pap.pcap",
        "min_devices": 0,
    },
    {
        "id": "socks",
        "module": "socks",
        "cls": "SOCKSPassiveListener",
        "filter": "socks",
        "pcap": "socks/generated_socks.pcap",
    },
    {
        "id": "mqtt",
        "module": "mqtt",
        "cls": "MQTTPassiveListener",
        "filter": "mqtt",
        "pcap": "mqtt/emreekin_mqtt_user_credentials.pcap",
        "details": ["username"],
    },
    {
        "id": "mqtt_gen",
        "module": "mqtt",
        "cls": "MQTTPassiveListener",
        "filter": "mqtt",
        "pcap": "mqtt/generated_mqtt.pcap",
    },
    {
        "id": "bgp",
        "module": "bgp",
        "cls": "BGPPassiveListener",
        "filter": "bgp",
        "pcap": "bgp/generated_bgp.pcap",
        "min_devices": 0,
        "min_interactions": 0,
    },
    {
        "id": "rdp",
        "module": "rdp",
        "cls": "RDPPassiveListener",
        "filter": "rdp",
        "pcap": "rdp/generated_rdp.pcap",
        "min_devices": 0,
        "min_interactions": 0,
    },
    {
        "id": "radius",
        "module": "radius",
        "cls": "RADIUSPassiveListener",
        "filter": "radius",
        "pcap": "radius/generated_radius.pcap",
        "details": ["code"],
    },
    {
        "id": "sip",
        "module": "sip",
        "cls": "SIPPassiveListener",
        "filter": "sip",
        "pcap": "sip/wireshark_sip_rtp.pcapng",
        "min_devices": 2,
        "min_interactions": 10,
        "details": ["method", "call_id", "cseq_method"],
        "operations": ["SIP INVITE"],
        "data_key": "sip_passive_data",
        "data_fields": ["role", "calls", "protocol"],
    },
    {
        "id": "vnc",
        "module": "vnc",
        "cls": "VNCPassiveListener",
        "filter": "vnc",
        "pcap": "vnc/generated_vnc.pcap",
    },
    # -----------------------------------------------------------------------
    # Database protocols
    # -----------------------------------------------------------------------
    {
        "id": "pgsql",
        "module": "pgsql",
        "cls": "PostgreSQLPassiveListener",
        "filter": "pgsql",
        "pcap": "pgsql/credslayer_pgsql.pcap",
        "min_devices": 0,
    },
    {
        "id": "mysql",
        "module": "mysql",
        "cls": "MySQLPassiveListener",
        "filter": "mysql",
        "pcap": "mysql/credslayer_mysql.pcap",
    },
    {
        "id": "mssql",
        "module": "mssql",
        "cls": "MSSQLPassiveListener",
        "filter": "tds",
        "pcap": "mssql/generated_mssql.pcap",
    },
    # -----------------------------------------------------------------------
    # Network service listeners
    # -----------------------------------------------------------------------
    {
        "id": "http",
        "module": "http",
        "cls": "HTTPPassiveListener",
        "filter": "http",
        "pcap": "http/bruteshark_http_basic.pcap",
        "details": ["method"],
    },
    {
        "id": "tls",
        "module": "tls",
        "cls": "TLSPassiveListener",
        "filter": "tls.handshake or tls.alert_message",
        "pcap": "tls/zeek_client-certificate.pcap",
    },
    {
        "id": "dns_real",
        "module": "dns",
        "cls": "DNSPassiveListener",
        "filter": "dns",
        "pcap": "dns/zeek_dns-binds.pcap",
        "details": ["query"],
    },
    {
        "id": "dns_gen",
        "module": "dns",
        "cls": "DNSPassiveListener",
        "filter": "dns",
        "pcap": "dns/generated_dns.pcap",
        "details": ["query"],
    },
    {
        "id": "snmp",
        "module": "snmp",
        "cls": "SNMPPassiveListener",
        "filter": "snmp",
        "pcap": "snmp/zeek_snmpv1_get.pcap",
        "details": ["community"],
    },
    {
        "id": "ldap",
        "module": "ldap",
        "cls": "LDAPPassiveListener",
        "filter": "ldap",
        "pcap": "ldap/credslayer_ldap_simpleauth.pcap",
    },
    {
        "id": "smb",
        "module": "smb",
        "cls": "SMBPassiveListener",
        "filter": "smb or smb2",
        "pcap": "smb/bruteshark_ntlm_smb.pcap",
    },
    {
        "id": "dhcp",
        "module": "dhcp",
        "cls": "DHCPPassiveListener",
        "filter": "dhcp || bootp",
        "pcap": "dhcp/zeek_dhcp_flood.pcap",
        "details": ["msg_type"],
    },
    # -----------------------------------------------------------------------
    # Discovery / broadcast protocols
    # -----------------------------------------------------------------------
    {
        "id": "cdp",
        "module": "cdp",
        "cls": "CDPPassiveListener",
        "filter": "cdp",
        "pcap": "cdp/filtered_cdp.pcap",
        "min_devices": 1,
        "details": ["device_id", "platform", "cdp_version", "trust_bitmap"],
        "operations": ["CDP Announcement"],
        "data_key": "cdp_data",
        "data_fields": ["device_id", "platform", "cdp_version", "protocol"],
    },
    {
        "id": "lldp",
        "module": "lldp",
        "cls": "LLDPPassiveListener",
        "filter": "lldp",
        "pcap": "lldp/wireshark_lldp_detailed.pcap",
    },
    {
        "id": "ssdp",
        "module": "ssdp",
        "cls": "SSDPPassiveListener",
        "filter": "ssdp",
        "pcap": "ssdp/ssdp.pcap",
        "min_devices": 0,
        "min_interactions": 0,
    },
    {
        "id": "stp",
        "module": "stp",
        "cls": "STPPassiveListener",
        "filter": "stp",
        "pcap": "stp/wireshark_stp_old.pcap",
    },
    {
        "id": "mdns",
        "module": "mdns",
        "cls": "MDNSPassiveListener",
        "filter": "mdns",
        "pcap": "mdns/filtered_mdns.pcap",
        "min_devices": 0,
        "min_interactions": 0,
    },
    {
        "id": "igmp",
        "module": "igmp",
        "cls": "IGMPPassiveListener",
        "filter": "igmp",
        "pcap": "igmp/filtered_igmp.pcap",
    },
    {
        "id": "tftp",
        "module": "tftp",
        "cls": "TFTPPassiveListener",
        "filter": "tftp",
        "pcap": "tftp/internet_tftp_rrq.pcap",
    },
    # -----------------------------------------------------------------------
    # NEW: Network infrastructure protocols
    # -----------------------------------------------------------------------
    {
        "id": "ntp",
        "module": "ntp",
        "cls": "NTPPassiveListener",
        "filter": "ntp",
        "pcap": "ntp/filtered_ntp.pcap",
        "min_devices": 2,
        "min_interactions": 2,
        "details": ["version", "mode_name", "stratum"],
        "operations": ["NTP v3"],
        "data_key": "ntp_passive_data",
        "data_fields": ["role", "protocol"],
    },
    {
        "id": "netbios",
        "module": "netbios",
        "cls": "NetBIOSPassiveListener",
        "filter": "nbns || nbss || netbios",
        "pcap": "netbios/generated_netbios.pcap",
        "min_devices": 1,
        "min_interactions": 1,
        "details": ["msg_type", "name"],
        "data_key": "netbios_passive_data",
        "data_fields": ["role", "protocol"],
    },
    {
        "id": "ipmi",
        "module": "ipmi",
        "cls": "IPMIPassiveListener",
        "filter": "ipmi_session || rmcp",
        "pcap": "ipmi/generated_ipmi.pcap",
        "min_devices": 2,
        "min_interactions": 1,
        "details": ["auth_type_name"],
        "data_key": "ipmi_passive_data",
        "data_fields": ["role", "protocol"],
    },
    {
        "id": "rpcbind",
        "module": "rpcbind",
        "cls": "RPCBindPassiveListener",
        "filter": "portmap",
        "pcap": "rpcbind/generated_rpcbind.pcap",
        "min_devices": 2,
        "min_interactions": 2,
        "details": ["procedure_name"],
        "operations": ["Portmap"],
        "data_key": "rpcbind_passive_data",
        "data_fields": ["role", "protocol"],
    },
    # -----------------------------------------------------------------------
    # NEW: Storage / VPN protocols
    # -----------------------------------------------------------------------
    {
        "id": "nfs",
        "module": "nfs",
        "cls": "NFSPassiveListener",
        "filter": "nfs",
        "pcap": "nfs/wireshark_nfs.cap",
        "min_devices": 2,
        "details": ["version", "procedure_name"],
        "operations": ["NFS v3 GETATTR"],
        "data_key": "nfs_passive_data",
        "data_fields": ["role", "protocol"],
    },
    {
        "id": "msrpc",
        "module": "msrpc",
        "cls": "MSRPCPassiveListener",
        "filter": "dcerpc",
        "pcap": "msrpc/generated_msrpc.pcap",
        "min_devices": 2,
        "details": ["pdu_type_name", "interface_name"],
        "operations": ["DCERPC Bind"],
        "data_key": "msrpc_passive_data",
        "data_fields": ["role", "protocol"],
    },
    {
        "id": "ipsec",
        "module": "ipsec",
        "cls": "IPsecPassiveListener",
        "filter": "isakmp",
        "pcap": "ipsec/wireshark_isakmp.cap",
        "min_devices": 2,
        "details": ["ike_version", "exchange_type_name"],
        "operations": ["IKE v1 Main"],
        "data_key": "ipsec_passive_data",
        "data_fields": ["role", "protocol"],
    },
    {
        "id": "iscsi",
        "module": "iscsi",
        "cls": "ISCSIPassiveListener",
        "filter": "iscsi",
        "pcap": "iscsi/generated_iscsi.pcap",
        "min_devices": 2,
        "details": ["opcode_name"],
        "operations": ["iSCSI Login"],
        "data_key": "iscsi_passive_data",
        "data_fields": ["role", "protocol"],
    },
    # -----------------------------------------------------------------------
    # NEW: Discovery / messaging
    # -----------------------------------------------------------------------
    {
        "id": "wsdiscovery",
        "module": "wsdiscovery",
        "cls": "WSDiscoveryPassiveListener",
        "filter": "xml && udp.port == 3702",
        "pcap": "wsdiscovery/generated_wsdiscovery.pcap",
        "min_devices": 1,
        "min_interactions": 1,
        "details": ["action"],
        "operations": ["WSD"],
        "data_key": "wsdiscovery_data",
        "data_fields": ["protocol"],
    },
    {
        "id": "smartinstall",
        "module": "smartinstall",
        "cls": "SmartInstallPassiveListener",
        "filter": "tcp.port == 4786",
        "pcap": "smartinstall/generated_smartinstall.pcap",
        "min_devices": 2,
        "min_interactions": 1,
        "details": ["operation"],
        "operations": ["SMI"],
        "data_key": "smartinstall_data",
        "data_fields": ["role", "protocol"],
    },
    {
        "id": "amqp",
        "module": "amqp",
        "cls": "AMQPPassiveListener",
        "filter": "amqp",
        "pcap": "amqp/generated_amqp.pcap",
        "min_devices": 2,
        "min_interactions": 1,
        "details": ["class_method"],
        "operations": ["AMQP Connection"],
        "data_key": "amqp_passive_data",
        "data_fields": ["role", "protocol"],
    },
    {
        "id": "rtsp",
        "module": "rtsp",
        "cls": "RTSPPassiveListener",
        "filter": "rtsp",
        "pcap": "rtsp/generated_rtsp.pcap",
        "min_devices": 2,
        "min_interactions": 4,
        "details": ["method"],
        "operations": ["RTSP DESCRIBE", "RTSP SETUP"],
        "data_key": "rtsp_passive_data",
        "data_fields": ["role", "protocol"],
    },
    # -----------------------------------------------------------------------
    # NEW: Database protocols (additional)
    # -----------------------------------------------------------------------
    {
        "id": "tns",
        "module": "tns",
        "cls": "TNSPassiveListener",
        "filter": "tns",
        "pcap": "tns/generated_tns.pcap",
        "min_devices": 2,
        "min_interactions": 2,
        "details": ["packet_type_name"],
        "operations": ["TNS Connect"],
        "data_key": "tns_passive_data",
        "data_fields": ["role", "protocol"],
    },
    {
        "id": "mongodb",
        "module": "mongodb",
        "cls": "MongoDBPassiveListener",
        "filter": "mongo",
        "pcap": "mongodb/generated_mongodb.pcap",
        "min_devices": 2,
        "min_interactions": 2,
        "details": ["opcode", "database"],
        "operations": ["OP_QUERY"],
        "data_key": "mongodb_passive_data",
        "data_fields": ["role", "protocol"],
    },
    {
        "id": "redis",
        "module": "redis",
        "cls": "RedisPassiveListener",
        "filter": "resp",
        "pcap": "redis/generated_redis.pcap",
        "min_devices": 2,
        "min_interactions": 2,
        "details": ["command"],
        "operations": ["AUTH"],
        "data_key": "redis_passive_data",
        "data_fields": ["role", "protocol"],
    },
    {
        "id": "memcached",
        "module": "memcached",
        "cls": "MemcachedPassiveListener",
        "filter": "memcache",
        "pcap": "memcached/generated_memcached.pcap",
        "min_devices": 2,
        "min_interactions": 2,
        "details": ["command"],
        "data_key": "memcached_passive_data",
        "data_fields": ["role", "protocol"],
    },
    # -----------------------------------------------------------------------
    # NEW: Printing protocols
    # -----------------------------------------------------------------------
    {
        "id": "ipp",
        "module": "ipp",
        "cls": "IPPPassiveListener",
        "filter": "ipp",
        "pcap": "ipp/generated_ipp.pcap",
        "min_devices": 2,
        "min_interactions": 2,
        "details": ["operation_name"],
        "data_key": "ipp_passive_data",
        "data_fields": ["role", "protocol"],
    },
    {
        "id": "pjl",
        "module": "pjl",
        "cls": "PJLPassiveListener",
        "filter": "tcp.port == 9100",
        "pcap": "pjl/generated_pjl.pcap",
        "min_devices": 2,
        "min_interactions": 1,
        "details": ["command"],
        "data_key": "pjl_passive_data",
        "data_fields": ["role", "protocol"],
    },
    # -----------------------------------------------------------------------
    # NEW: Messaging protocols
    # -----------------------------------------------------------------------
    {
        "id": "ibmmq",
        "module": "ibmmq",
        "cls": "IBMMQPassiveListener",
        "filter": "mq",
        "pcap": "ibmmq/generated_ibmmq.pcap",
        "min_devices": 2,
        "min_interactions": 2,
        "details": ["segment_type_name"],
        "data_key": "ibmmq_passive_data",
        "data_fields": ["role", "protocol"],
    },
    # -----------------------------------------------------------------------
    # NEW: Remote display / X11
    # -----------------------------------------------------------------------
    {
        "id": "x11",
        "module": "x11",
        "cls": "X11PassiveListener",
        "filter": "x11",
        "pcap": "x11/generated_x11.pcap",
        "min_devices": 2,
        "min_interactions": 1,
        "details": ["auth_method"],
        "operations": ["Connect"],
        "data_key": "x11_passive_data",
        "data_fields": ["role", "protocol"],
    },
    # -----------------------------------------------------------------------
    # NEW: Java / application server protocols
    # -----------------------------------------------------------------------
    {
        "id": "ajp",
        "module": "ajp",
        "cls": "AJPPassiveListener",
        "filter": "ajp13",
        "pcap": "ajp/generated_ajp.pcap",
        "min_devices": 2,
        "min_interactions": 3,
        "details": ["method_name", "uri"],
        "operations": ["AJP GET"],
        "data_key": "ajp_passive_data",
        "data_fields": ["role", "protocol"],
        "decode_as": {"tcp.port==8009": "ajp13"},
    },
    {
        "id": "rmi",
        "module": "rmi",
        "cls": "RMIPassiveListener",
        "filter": "rmi",
        "pcap": "rmi/generated_rmi.pcap",
        "min_devices": 2,
        "min_interactions": 2,
        "details": ["message_type"],
        "operations": ["RMI Handshake"],
        "data_key": "rmi_passive_data",
        "data_fields": ["role", "protocol"],
        "decode_as": {"tcp.port==1099": "rmi"},
    },
    {
        "id": "rsync",
        "module": "rsync",
        "cls": "RsyncPassiveListener",
        "filter": "rsync",
        "pcap": "rsync/generated_rsync.pcap",
        "min_devices": 2,
        "min_interactions": 3,
        "details": ["version"],
        "operations": ["Rsync Version"],
        "data_key": "rsync_passive_data",
        "data_fields": ["role", "protocol"],
        "decode_as": {"tcp.port==873": "rsync"},
    },
]


# ---------------------------------------------------------------------------
# Expanded coverage: ALL pcaps per listener (for packet-drop tests)
# ---------------------------------------------------------------------------
import glob as _glob


# Per-pcap decode_as overrides for the coverage sweep.
#
# COVERAGE_ALL_PCAPS globs EVERY pcap in a protocol's fixture dir and runs it
# through that protocol's single display filter.  A few fixtures carry the
# right protocol on a NON-STANDARD port that tshark won't heuristically
# dissect, so the sweep would skip them with "tshark found 0 packets".
# Mapping the port to an explicit decode_as makes tshark (and the listener)
# actually parse them, so they're exercised instead of silently skipped.
#
# Only files that genuinely contain the target protocol belong here.  Fixtures
# that legitimately lack the protocol (encrypted MQ in ibmmq/mq-sample.cap,
# the corrupt rmi/wireshark_rmi.pcap, the portmap-free NFS captures under
# rpcbind/) are intentionally left to skip.
_COVERAGE_DECODE_AS: dict[str, dict] = {
    "opcua/wireshark_opcua.pcap": {"tcp.port==12001": "opcua"},
    "opcua/wireshark_opcua_icsmaster.pcap": {"tcp.port==12001": "opcua"},
    "opcua/cisagov_open62541_client-server_mainloop-not-localhost-non-standard-port.pcap": {
        "tcp.port==48010": "opcua"
    },
    "telnet/credslayer_telnet_hidden.pcap": {"tcp.port==1337": "telnet"},
    # MQTT on non-standard ports — without decode_as tshark sees only TCP.
    "mqtt/emreekin_mqtt_example.pcap": {"tcp.port==13600": "mqtt"},
    "mqtt/ndpi_coap_mqtt.pcap": {"tcp.port==17501": "mqtt"},
}


def _build_coverage_all_pcaps() -> list[dict]:
    """Expand LISTENER_PCAP_CASES to cover ALL pcaps in each protocol's fixture dir."""
    # Deduplicate: one entry per (module, cls, filter) → fixture subdirectory
    seen: dict[tuple, dict] = {}
    for case in LISTENER_PCAP_CASES:
        key = (case["module"], case["cls"], case["filter"])
        if key not in seen:
            # Derive fixture subdir from pcap path (e.g. "iec104/foo.pcap" → "iec104")
            subdir = case["pcap"].split("/")[0]
            seen[key] = {
                "module": case["module"],
                "cls": case["cls"],
                "filter": case["filter"],
                "decode_as": case.get("decode_as"),
                "subdir": subdir,
            }

    # Expand: glob all pcap files per subdir
    cases = []
    for info in seen.values():
        pattern = os.path.join(FIXTURE_DIR, info["subdir"], "*")
        for filepath in sorted(_glob.glob(pattern)):
            if not filepath.endswith((".pcap", ".pcapng", ".cap")):
                continue
            filename = os.path.basename(filepath)
            rel_path = f"{info['subdir']}/{filename}"
            # Per-pcap override (non-standard-port fixtures) takes precedence
            # over the filter-level decode_as inherited from LISTENER_PCAP_CASES.
            decode_as = _COVERAGE_DECODE_AS.get(rel_path, info.get("decode_as"))
            cases.append(
                {
                    "id": f"{info['module']}::{filename}",
                    "module": info["module"],
                    "cls": info["cls"],
                    "filter": info["filter"],
                    "pcap": rel_path,
                    "decode_as": decode_as,
                }
            )
    return cases


COVERAGE_ALL_PCAPS: list[dict] = _build_coverage_all_pcaps()
