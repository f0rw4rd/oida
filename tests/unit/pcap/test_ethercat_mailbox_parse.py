"""Behavioral parse tests for the EtherCAT passive listener.

``EtherCATPassiveListener`` is an L2 (EtherType 0x88A4) listener keyed by source
MAC. It parses datagram commands (APRD/FPWR/LRW/...), CoE/FoE/SoE mailbox
protocols, and dissected ESC register content, then raises security alerts for
firmware (FoE) transfers and SDO writes to critical OD ranges.

These tests build fake pyshark packets (eth + ecat layer carrying mailbox /
register fields as underscore attributes) and drive ``process_packet()``,
``harvest()``, the column formatters, and the helper parsers. No pyshark,
tshark, or .pcap needed -- assertions check parsed output against the exact fed
field values and the module's constant tables.
"""

from oida.pcap.ethercat import EtherCATPassiveListener


class _Layer:
    """Minimal stand-in for a pyshark layer (attribute access only)."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakePacket:
    """A fake L2 EtherCAT frame: eth layer + a single ecat layer."""

    def __init__(self, ecat_fields, *, src_mac="aa:bb:cc:00:00:01", dst_mac="ff:ff:ff:ff:ff:ff"):
        self.eth = _Layer(src=src_mac, dst=dst_mac)
        self.ecat = _Layer(**ecat_fields)


MASTER_MAC = "aa:bb:cc:00:00:01"


def _make_listener():
    return EtherCATPassiveListener(interface="lo", timeout=1)


# ---------------------------------------------------------------------------
# Gating + primary datagram
# ---------------------------------------------------------------------------


def test_packet_without_ecat_layer_ignored():
    listener = _make_listener()

    class _NoEcat:
        pass

    listener.process_packet(_NoEcat())
    assert listener.interactions == []
    assert listener.masters == {}


def test_packet_without_src_mac_ignored():
    listener = _make_listener()
    listener.process_packet(_FakePacket({"cmd": "0x04"}, src_mac=""))
    assert listener.masters == {}


def test_primary_fprd_datagram_read_classification():
    """FPRD (0x04) is a configured-address physical read."""
    listener = _make_listener()
    listener.process_packet(
        _FakePacket({"cmd": "0x04", "adp": "0x03e9", "ado": "0x0130", "cnt": "1"})
    )
    master = listener.masters[MASTER_MAC]
    assert master.total_frames == 1
    assert master.total_datagrams == 1
    assert master.read_datagrams == 1
    assert master.write_datagrams == 0
    assert master.commands_used["FPRD"] == 1
    assert 0x03E9 in master.slave_addrs_seen
    assert 0x0130 in master.offsets_seen

    ix = listener.interactions[-1]
    assert ix.operation == "FPRD"
    assert ix.details["rw"] == "read"
    assert ix.details["slave_addr"] == 0x03E9
    assert ix.details["offset"] == 0x0130
    assert ix.details["wkc"] == 1
    # AL Status register name annotation in summary
    assert "0x0130 (AL Status)" in ix.summary


def test_lrw_logical_command_tracks_logical_address():
    """LRW (0x0C) is a logical read-write; the logical address is recorded and
    formatted in the summary."""
    listener = _make_listener()
    listener.process_packet(_FakePacket({"cmd": "0x0c", "lad": "0x00010000", "cnt": "2"}))
    master = listener.masters[MASTER_MAC]
    assert 0x00010000 in master.logical_addrs_seen
    assert master.read_datagrams == 1
    assert master.write_datagrams == 1  # rw counts both
    ix = listener.interactions[-1]
    assert ix.details["logical_addr"] == 0x00010000
    assert "addr=0x00010000" in ix.summary


def test_wkc_zero_counted_for_non_nop_command():
    listener = _make_listener()
    listener.process_packet(_FakePacket({"cmd": "0x05", "adp": "0x0001", "cnt": "0"}))  # FPWR WKC=0
    assert listener.masters[MASTER_MAC].wkc_zero_count == 1


def test_nop_with_zero_wkc_not_counted():
    listener = _make_listener()
    listener.process_packet(_FakePacket({"cmd": "0x00", "cnt": "0"}))  # NOP
    assert listener.masters[MASTER_MAC].wkc_zero_count == 0


def test_sub_datagrams_processed_until_gap():
    """Two sub-datagrams present then a gap -> exactly 3 datagrams total."""
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {
                "cmd": "0x07",  # primary BRD
                "adp": "0x0000",
                "cnt": "3",
                "sub1_cmd": "0x04",  # FPRD
                "sub1_adp": "0x0001",
                "sub1_cnt": "1",
                "sub2_cmd": "0x05",  # FPWR
                "sub2_adp": "0x0002",
                "sub2_cnt": "1",
                # no sub3_cmd -> loop breaks
            }
        )
    )
    master = listener.masters[MASTER_MAC]
    assert master.total_datagrams == 3
    assert master.commands_used["BRD"] == 1
    assert master.commands_used["FPRD"] == 1
    assert master.commands_used["FPWR"] == 1


def test_unknown_command_code_formatted_as_hex():
    listener = _make_listener()
    listener.process_packet(_FakePacket({"cmd": "0x1f"}))  # not in ECAT_COMMANDS
    assert listener.interactions[-1].operation == "0x1f"


# ---------------------------------------------------------------------------
# CoE (CAN over EtherCAT) mailbox
# ---------------------------------------------------------------------------


def test_coe_sdo_download_request_critical_od():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {
                "cmd": "0x05",
                "adp": "0x0001",
                "ecat_mailbox_type": "3",  # CoE
                "ecat_mailbox_coe_type": "2",  # SDO Request
                "ecat_mailbox_coe_sdoreq": "1",  # Download
                "ecat_mailbox_coe_sdoidx": "0x1c12",  # SM PDO Assignment range
                "ecat_mailbox_coe_sdosub": "0x00",
                "ecat_mailbox_coe_sdodata": "0x00000002",
            }
        )
    )
    master = listener.masters[MASTER_MAC]
    assert master.coe_sdo_downloads == 1
    assert "0x1c12:0x00" in master.coe_od_indices_seen

    # The mailbox interaction is the last recorded one.
    ix = listener.interactions[-1]
    assert ix.details["mailbox_type"] == "CoE"
    assert ix.details["coe_type"] == "SDO Request"
    assert ix.operation == "SDO Download"
    assert ix.details["od_index"] == "0x1c12"
    assert "OD=0x1c12:00" in ix.summary


def test_coe_sdo_upload_request():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {
                "cmd": "0x04",
                "adp": "0x0001",
                "ecat_mailbox_type": "3",
                "ecat_mailbox_coe_type": "2",
                "ecat_mailbox_coe_sdoreq": "3",  # Upload
                "ecat_mailbox_coe_sdoidx": "0x1000",
            }
        )
    )
    master = listener.masters[MASTER_MAC]
    assert master.coe_sdo_uploads == 1
    assert listener.interactions[-1].operation == "SDO Upload"


def test_coe_sdo_abort_request():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {
                "cmd": "0x05",
                "adp": "0x0001",
                "ecat_mailbox_type": "3",
                "ecat_mailbox_coe_type": "2",
                "ecat_mailbox_coe_sdoreq": "5",  # Abort
                "ecat_mailbox_coe_sdoidx": "0x6000",
                "ecat_mailbox_coe_abortcode": "0x06090011",
            }
        )
    )
    master = listener.masters[MASTER_MAC]
    assert master.coe_sdo_aborts == 1
    assert listener.interactions[-1].details["abort_code"] == "0x06090011"


def test_coe_sdo_response_direction():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {
                "cmd": "0x04",
                "adp": "0x0001",
                "ecat_mailbox_type": "3",
                "ecat_mailbox_coe_type": "3",  # SDO Response
                "ecat_mailbox_coe_sdores": "3",  # Upload Initiated
                "ecat_mailbox_coe_sdoidx": "0x1018",
                "ecat_mailbox_coe_sdodata": "0x00000002",
            }
        )
    )
    ix = listener.interactions[-1]
    assert ix.direction == "response"
    assert ix.operation == "SDO Upload Response"
    assert ix.details["coe_type"] == "SDO Response"


# ---------------------------------------------------------------------------
# FoE (File over EtherCAT) mailbox -- firmware risk
# ---------------------------------------------------------------------------


def test_foe_write_transfer_records_filename():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {
                "cmd": "0x05",
                "adp": "0x0001",
                "ecat_mailbox_type": "4",  # FoE
                "ecat_mailbox_foe_opmode": "2",  # Write (firmware upload)
                "ecat_mailbox_foe_filename": "firmware.bin",
                "ecat_mailbox_foe_filelength": "65536",
                "ecat_mailbox_foe_packetno": "1",
            }
        )
    )
    master = listener.masters[MASTER_MAC]
    assert master.foe_transfers == 1
    assert "firmware.bin" in master.foe_filenames
    ix = listener.interactions[-1]
    assert ix.operation == "FoE Write"
    assert ix.details["filename"] == "firmware.bin"
    assert ix.details["file_length"] == 65536
    assert "file=firmware.bin" in ix.summary


def test_foe_error_packet():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {
                "cmd": "0x05",
                "adp": "0x0001",
                "ecat_mailbox_type": "4",
                "ecat_mailbox_foe_opmode": "5",  # Error
                "ecat_mailbox_foe_errcode": "32",
                "ecat_mailbox_foe_errtext": "access denied",
            }
        )
    )
    ix = listener.interactions[-1]
    assert ix.operation == "FoE Error"
    assert ix.details["error_code"] == 32
    assert ix.details["error_text"] == "access denied"


# ---------------------------------------------------------------------------
# SoE (Servo over EtherCAT) mailbox
# ---------------------------------------------------------------------------


def test_soe_write_request():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {
                "cmd": "0x05",
                "adp": "0x0001",
                "ecat_mailbox_type": "5",  # SoE
                "ecat_mailbox_soe_opcode": "3",  # Write request
                "ecat_mailbox_soe_header_driveno": "2",
                "ecat_mailbox_soe_idn": "0x0024",
            }
        )
    )
    master = listener.masters[MASTER_MAC]
    assert master.soe_operations == 1
    assert 2 in master.soe_drives_seen
    ix = listener.interactions[-1]
    assert ix.direction == "request"
    assert ix.operation == "SoE Write"
    assert ix.details["drive_no"] == 2
    assert ix.details["idn"] == "0x0024"


def test_soe_read_response_with_error():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {
                "cmd": "0x04",
                "adp": "0x0001",
                "ecat_mailbox_type": "5",
                "ecat_mailbox_soe_opcode": "2",  # Read response
                "ecat_mailbox_soe_header_error": "True",
            }
        )
    )
    ix = listener.interactions[-1]
    assert ix.direction == "response"
    assert ix.details["error"] is True
    assert "ERROR" in ix.summary


def test_unknown_mailbox_type_skipped():
    """Mailbox type 1 (AoE) is not handled by the CoE/FoE/SoE dispatch and must
    not raise; the datagram interaction is still recorded."""
    listener = _make_listener()
    listener.process_packet(_FakePacket({"cmd": "0x04", "adp": "0x0001", "ecat_mailbox_type": "1"}))
    master = listener.masters[MASTER_MAC]
    assert master.foe_transfers == 0
    assert master.soe_operations == 0
    assert master.total_datagrams == 1


# ---------------------------------------------------------------------------
# Register-level field extraction
# ---------------------------------------------------------------------------


def test_al_status_state_recorded():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket({"cmd": "0x04", "adp": "0x0001", "reg_alstatus_status": "8"})  # Operational
    )
    master = listener.masters[MASTER_MAC]
    assert 8 in master.al_status_states_seen
    al_ix = [ix for ix in listener.interactions if ix.operation == "AL Status"]
    assert al_ix
    assert al_ix[-1].details["al_status_name"] == "Operational"
    assert "AL Status: Operational" in al_ix[-1].summary


def test_al_status_multivalue_broadcast():
    """EK-mode broadcast reads return a comma-separated state list; all unique
    values are captured."""
    listener = _make_listener()
    listener.process_packet(
        _FakePacket({"cmd": "0x07", "adp": "0x0000", "reg_alstatus_status": "1,2,8"})
    )
    master = listener.masters[MASTER_MAC]
    assert {1, 2, 8} <= master.al_status_states_seen
    al_ix = [ix for ix in listener.interactions if ix.operation == "AL Status"][-1]
    assert "al_status_all" in al_ix.details


def test_al_status_code_nonzero_recorded():
    listener = _make_listener()
    # reg.alstatuscode is dissected as a decimal value (ETG.1000.6 Table 11);
    # 0x0011 == 17 == "Invalid requested state change".
    listener.process_packet(_FakePacket({"cmd": "0x04", "adp": "0x0001", "reg_alstatuscode": "17"}))
    master = listener.masters[MASTER_MAC]
    assert 0x0011 in master.al_status_codes_seen
    code_ix = [ix for ix in listener.interactions if ix.operation == "AL Status Code"][-1]
    assert code_ix.details["al_status_code_name"] == "Invalid requested state change"


def test_al_status_code_zero_skipped():
    """AL status code 0 (No error) must not create an interaction."""
    listener = _make_listener()
    listener.process_packet(_FakePacket({"cmd": "0x04", "adp": "0x0001", "reg_alstatuscode": "0"}))
    assert [ix for ix in listener.interactions if ix.operation == "AL Status Code"] == []


def test_esc_identity_registers_captured_once():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {
                "cmd": "0x04",
                "adp": "0x0001",
                "reg_type": "5",
                "reg_revision": "2",
                "reg_build": "10",
            }
        )
    )
    master = listener.masters[MASTER_MAC]
    assert master.esc_type == 5
    assert master.esc_revision == 2
    assert master.esc_build == 10


def test_syncmanager_and_dc_flags():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {
                "cmd": "0x05",
                "adp": "0x0001",
                "syncman_ctrlstatus": "0x24",
                "syncman_enable": "True",
                "reg_dc_activation_enablecyclic": "True",
            }
        )
    )
    master = listener.masters[MASTER_MAC]
    assert master.syncman_enabled is True
    assert master.dc_cyclic_enabled is True
    ops = {ix.operation for ix in listener.interactions}
    assert "SyncManager Config" in ops
    assert "DC Activation" in ops


def test_dl_status_port_states():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {
                "cmd": "0x04",
                "adp": "0x0001",
                "reg_dlstatus1": "0x0d",
                "reg_dlstatus2_port0": "1",
                "reg_dlstatus2_port1": "0",
            }
        )
    )
    master = listener.masters[MASTER_MAC]
    assert master.dl_port_states == {"port0": "1", "port1": "0"}
    dl_ix = [ix for ix in listener.interactions if ix.operation == "DL Status"][-1]
    assert "port0=1" in dl_ix.details["port_link_states"]


# ---------------------------------------------------------------------------
# Device data construction
# ---------------------------------------------------------------------------


def test_device_data_built_with_master_state():
    listener = _make_listener()
    listener.process_packet(_FakePacket({"cmd": "0x05", "adp": "0x0001", "cnt": "1"}))  # FPWR
    key = f"ethercat-master:{MASTER_MAC}"
    assert key in listener.discovered_devices
    data = listener.discovered_devices[key].ethercat_passive_data
    assert data["role"] == "master"
    assert data["protocol"] == "EtherCAT/L2"
    assert data["write_datagrams"] == 1
    assert 0x0001 in data["slave_addresses"]
    assert data["commands_used"]["FPWR"] == 1


def test_device_data_includes_mailbox_sections():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {
                "cmd": "0x05",
                "adp": "0x0001",
                "ecat_mailbox_type": "4",
                "ecat_mailbox_foe_opmode": "2",
                "ecat_mailbox_foe_filename": "fw.bin",
            }
        )
    )
    data = listener.discovered_devices[f"ethercat-master:{MASTER_MAC}"].ethercat_passive_data
    assert data["foe"]["transfers"] == 1
    assert "fw.bin" in data["foe"]["filenames"]


# ---------------------------------------------------------------------------
# Column formatting
# ---------------------------------------------------------------------------


def test_format_columns_standard_datagram():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {"cmd": "0x04", "adp": "0x0009", "ado": "0x0120", "cnt": "1", "subframe_length": "4"}
        )
    )
    # The first interaction is the datagram (register reads add later ones).
    ix = listener.interactions[0]
    cols = listener._format_protocol_columns(ix)
    cmd, addr, offset, length, wkc = cols
    assert cmd == "FPRD (read)"
    assert addr == "0x0009"
    assert "AL Control" in offset
    assert length == "4"
    assert wkc == "1"


def test_format_columns_logical_address():
    listener = _make_listener()
    listener.process_packet(_FakePacket({"cmd": "0x0c", "lad": "0x00020000", "cnt": "1"}))
    cols = listener._format_protocol_columns(listener.interactions[0])
    assert cols[1] == "L:0x00020000"


def test_format_mailbox_columns_coe():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {
                "cmd": "0x05",
                "adp": "0x0001",
                "ecat_mailbox_type": "3",
                "ecat_mailbox_coe_type": "2",
                "ecat_mailbox_coe_sdoreq": "1",
                "ecat_mailbox_coe_sdoidx": "0x1c12",
                "ecat_mailbox_coe_sdosub": "0x01",
                "ecat_mailbox_coe_sdodata": "0xdead",
            }
        )
    )
    mb_ix = [ix for ix in listener.interactions if ix.details.get("mailbox_type") == "CoE"][-1]
    cols = listener._format_protocol_columns(mb_ix)
    assert cols[0] == "SDO Download"
    assert cols[1] == "0x1c12:0x01"
    assert cols[2] == "0xdead"


def test_format_mailbox_columns_foe():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {
                "cmd": "0x05",
                "adp": "0x0001",
                "ecat_mailbox_type": "4",
                "ecat_mailbox_foe_opmode": "2",
                "ecat_mailbox_foe_filename": "image.efw",
                "ecat_mailbox_foe_filelength": "1024",
            }
        )
    )
    mb_ix = [ix for ix in listener.interactions if ix.details.get("mailbox_type") == "FoE"][-1]
    cols = listener._format_protocol_columns(mb_ix)
    assert cols[0] == "FoE Write"
    assert cols[1] == "image.efw"
    assert cols[3] == "1024"


# ---------------------------------------------------------------------------
# harvest() security alerts
# ---------------------------------------------------------------------------


def test_harvest_foe_firmware_alert():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {
                "cmd": "0x05",
                "adp": "0x0001",
                "ecat_mailbox_type": "4",
                "ecat_mailbox_foe_opmode": "2",
                "ecat_mailbox_foe_filename": "fw.bin",
            }
        )
    )
    result = listener.harvest()
    cats = {a["category"] for a in result["alerts"]}
    assert "firmware_alert" in cats
    msg = next(a["message"] for a in result["alerts"] if a["category"] == "firmware_alert")
    assert "fw.bin" in msg
    assert MASTER_MAC in msg


def test_harvest_critical_od_write_alert():
    """An SDO download to the RxPDO mapping range (0x1600-0x17FF) raises a
    config-tampering alert."""
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {
                "cmd": "0x05",
                "adp": "0x0001",
                "ecat_mailbox_type": "3",
                "ecat_mailbox_coe_type": "2",
                "ecat_mailbox_coe_sdoreq": "1",  # Download
                "ecat_mailbox_coe_sdoidx": "0x1600",  # RxPDO Mapping
                "ecat_mailbox_coe_sdosub": "0x00",
            }
        )
    )
    result = listener.harvest()
    config_alerts = [a for a in result["alerts"] if a["category"] == "config_alert"]
    assert config_alerts
    assert "RxPDO Mapping" in config_alerts[0]["message"]


def test_harvest_no_alert_for_noncritical_od_write():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            {
                "cmd": "0x05",
                "adp": "0x0001",
                "ecat_mailbox_type": "3",
                "ecat_mailbox_coe_type": "2",
                "ecat_mailbox_coe_sdoreq": "1",
                "ecat_mailbox_coe_sdoidx": "0x2000",  # device profile, not critical
            }
        )
    )
    result = listener.harvest()
    assert [a for a in result.get("alerts", []) if a["category"] == "config_alert"] == []


def test_get_write_operations_summary():
    listener = _make_listener()
    listener.process_packet(_FakePacket({"cmd": "0x05", "adp": "0x0001", "cnt": "1"}))  # FPWR write
    writes = listener.get_write_operations()
    assert len(writes) == 1
    assert writes[0]["client"] == MASTER_MAC
    assert writes[0]["write_count"] == 1


# ---------------------------------------------------------------------------
# Helper parsers
# ---------------------------------------------------------------------------


def test_parse_hex_int_variants():
    listener = _make_listener()
    assert listener._parse_hex_int("0x10") == 16
    assert listener._parse_hex_int("255") == 255
    assert listener._parse_hex_int(None, -1) == -1
    assert listener._parse_hex_int("nope", -1) == -1


def test_parse_first_int_comma_list():
    listener = _make_listener()
    assert listener._parse_first_int("1,2,3") == 1
    assert listener._parse_first_int("7") == 7
    assert listener._parse_first_int(None, -1) == -1


def test_parse_int_list():
    listener = _make_listener()
    assert listener._parse_int_list("1,2,bad,4") == [1, 2, 4]
    assert listener._parse_int_list(None) == []


def test_format_offset_named_and_unnamed():
    assert EtherCATPassiveListener._format_offset(0x0130) == "0x0130 (AL Status)"
    assert EtherCATPassiveListener._format_offset(0x1234) == "0x1234"


def test_classify_offsets_keeps_only_known():
    out = EtherCATPassiveListener._classify_offsets({0x0130, 0x9999, 0x0120})
    assert any("AL Status" in o for o in out)
    assert any("AL Control" in o for o in out)
    assert all("0x9999" not in o for o in out)
