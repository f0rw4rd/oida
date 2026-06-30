"""Unit tests for the IEC 60870-5-103 passive listener / frame parser.

These tests drive ``IEC103PassiveListener.process_packet`` with hand-built
fake PyShark layers (no tshark / pyshark required). The fakes reproduce the
single access pattern the iec103 parser relies on: scalar attribute access
(``layer.linkaddr`` -> a value, read through ``get_field`` / ``_parse_int``).

Unlike iec101, the iec103 dissector exposes separate monitor/control type-ID
fields (``asdu_typeid_mon`` / ``asdu_typeid_ctrl``) and direction-split COT
maps, and it has no multi-IOA value extractors -- so a plain string attribute
per field is sufficient.

Everything asserted here is derived from the mock IEC-103 frames built in each
test: the parser's interactions, session state, discovered devices and
protocol_data are checked against the known input.
"""

from typing import Any, Dict

from oida.pcap.iec103 import (
    ASDU_TYPE_CTRL,
    ASDU_TYPE_MON,
    FUNCTION_TYPES,
    LINK_FUNC_PRI_TO_SEC,
    LINK_FUNC_SEC_TO_PRI,
    IEC103PassiveListener,
    _get_function_type_name,
)


# ---------------------------------------------------------------------------
# Fake PyShark layer scaffolding
# ---------------------------------------------------------------------------


class _Layer:
    """Minimal PyShark layer exposing fields as string attributes.

    Fields present in ``fields`` become attributes; absent fields raise
    AttributeError via ``getattr`` so ``get_field`` returns its default,
    matching a dissector that did not emit the field.
    """

    def __init__(self, fields: Dict[str, Any]):
        for name, val in fields.items():
            setattr(self, name, str(val))


class _Packet:
    """Fake packet carrying the iec60870_5_103 layer."""

    def __init__(self, fields: Dict[str, Any]):
        self.iec60870_5_103 = _Layer(fields)


CONTROLLING_IP = "10.0.0.1"  # bay controller / SA system
CONTROLLED_IP = "10.0.0.2"  # protection relay
CONTROLLING_MAC = "aa:bb:cc:dd:ee:01"
CONTROLLED_MAC = "aa:bb:cc:dd:ee:02"


def _make_listener() -> IEC103PassiveListener:
    """Build a listener with the base PyShark transport helpers stubbed.

    The src is always the master (10.0.0.1) and dst the relay (10.0.0.2);
    the parser flips controlling/controlled based on the PRM bit, so each
    test controls direction via ``ctrl_prm``.
    """
    listener = IEC103PassiveListener("test0")
    listener.get_ip_info = lambda packet: (CONTROLLING_IP, CONTROLLED_IP)
    listener.get_port_info = lambda packet: (50000, 2404)
    listener.get_mac_info = lambda packet: (CONTROLLING_MAC, CONTROLLED_MAC)
    listener.get_flow_id = lambda packet: "flow-1"
    listener.get_stream_id = lambda packet: "stream-1"
    return listener


def _feed(listener: IEC103PassiveListener, fields: Dict[str, Any]):
    listener.process_packet(_Packet(fields))
    return listener.interactions[-1]


# ---------------------------------------------------------------------------
# Function-type name resolution (_get_function_type_name)
# ---------------------------------------------------------------------------


class TestFunctionTypeNames:
    def test_exact_mapped_values(self):
        assert _get_function_type_name(128) == "Distance Protection"
        assert _get_function_type_name(160) == "Overcurrent Protection"
        assert _get_function_type_name(255) == FUNCTION_TYPES[255]

    def test_range_lookup_above_exact_anchor(self):
        """A value inside a range but not on an anchor resolves via ranges."""
        assert _get_function_type_name(150) == "Distance Protection"
        assert _get_function_type_name(170) == "Overcurrent Protection"
        assert _get_function_type_name(200) == "Line Differential Protection"
        assert _get_function_type_name(215) == "Reserved"
        assert _get_function_type_name(245) == "Vendor-Specific"

    def test_application_func_below_128(self):
        assert _get_function_type_name(50) == "Application Func 50"

    def test_unmapped_high_func(self):
        """Above all ranges but not exactly mapped -> generic Func N."""
        # 254 is exact-mapped; pick a gap not covered: there is none above 240
        # except 254/255 which are exact. Use an out-of-range value > 255 path
        # via the final fallback by passing a value the ranges miss.
        # 240..253 is Vendor-Specific, 254/255 exact -> only <128 hits the
        # other branch, so exercise the final 'Func N' return with e.g. 256.
        assert _get_function_type_name(256) == "Func 256"


# ---------------------------------------------------------------------------
# Link-layer only frames (no ASDU type IDs)
# ---------------------------------------------------------------------------


class TestLinkFrames:
    def test_primary_request_status_of_link(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            {
                "linkaddr": "7",
                "ctrl_prm": "1",
                "ctrl_func_pri_to_sec": "9",
            },
        )
        assert ix.direction == "request"
        assert ix.operation == f"Link: {LINK_FUNC_PRI_TO_SEC[9]}"
        assert ix.details["frame_type"] == "link"
        assert ix.details["is_primary"] is True
        assert ix.details["link_addr"] == 7
        assert ix.details["link_func_code"] == 9
        assert ix.details["link_func_name"] == "Request Status of Link"
        assert "addr=7" in ix.summary

        session = listener.sessions[(CONTROLLING_IP, CONTROLLED_IP)]
        assert 7 in session.link_addresses

    def test_secondary_response_function_code(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            {
                "linkaddr": "3",
                "ctrl_prm": "0",
                "ctrl_func_sec_to_pri": "11",
            },
        )
        assert ix.direction == "response"
        assert ix.operation == f"Link: {LINK_FUNC_SEC_TO_PRI[11]}"
        assert ix.details["is_primary"] is False
        assert ix.details["link_func_name"] == "Status of Link / Access Demand"

        # PRM=0: controlling=dst(10.0.0.2), controlled=src(10.0.0.1).
        session = listener.sessions[(CONTROLLED_IP, CONTROLLING_IP)]
        assert 3 in session.link_addresses

    def test_unknown_primary_func_falls_back(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            {"linkaddr": "2", "ctrl_prm": "1", "ctrl_func_pri_to_sec": "7"},
        )
        assert ix.details["link_func_code"] == 7
        assert ix.details["link_func_name"] == "PRI Func 7"
        assert ix.operation == "Link: PRI Func 7"

    def test_unknown_secondary_func_falls_back(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            {"linkaddr": "5", "ctrl_prm": "0", "ctrl_func_sec_to_pri": "13"},
        )
        assert ix.details["link_func_code"] == 13
        assert ix.details["link_func_name"] == "SEC Func 13"

    def test_primary_without_func_code(self):
        """PRM=1 but no function field -> func_code -1, name 'PRI Func -1',
        and no link_func_code key recorded (the >= 0 guard)."""
        listener = _make_listener()
        ix = _feed(listener, {"linkaddr": "5", "ctrl_prm": "1"})
        assert ix.operation == "Link: PRI Func -1"
        assert "link_func_code" not in ix.details
        assert ix.details["is_primary"] is True


# ---------------------------------------------------------------------------
# Monitor-direction ASDU frames
# ---------------------------------------------------------------------------


class TestMonitorAsdu:
    def test_time_tagged_message_dpi(self):
        """Type 1 (time-tagged message) decodes dpi via _DPI_VALUES (ON) and
        rolls up a monitor message; rw is always 'read'."""
        listener = _make_listener()
        ix = _feed(
            listener,
            {
                "linkaddr": "4",
                "ctrl_prm": "0",
                "asdu_typeid_mon": "1",
                "asdu_address": "11",
                "func_type": "160",
                "info_num": "23",
                "cot_mon": "1",
                "dpi": "2",
            },
        )
        assert ix.direction == "response"
        assert ix.operation == ASDU_TYPE_MON[1]
        d = ix.details
        assert d["type_id"] == 1
        assert d["type_name"] == "Time-tagged message"
        assert d["direction_type"] == "monitor"
        assert d["link_addr"] == 4
        assert d["asdu_addr"] == 11
        assert d["cot_name"] == "Spontaneous"
        assert d["rw"] == "read"
        assert d["func_type"] == 160
        assert d["func_type_name"] == "Overcurrent Protection"
        assert d["info_num"] == 23
        assert d["dpi"] == 2
        assert d["dpi_name"] == "ON"
        assert d["detail_str"] == "DPI=ON"
        assert ix.summary.startswith("MON Time-tagged message")
        assert "[DPI=ON]" in ix.summary

        session = listener.sessions[(CONTROLLED_IP, CONTROLLING_IP)]
        assert 1 in session.type_ids_mon
        assert session.monitor_count == 1
        assert session.control_count == 0
        assert 11 in session.asdu_addresses
        assert 160 in session.function_types

    def test_time_tagged_relative_with_supplementary(self):
        """Type 2 surfaces both dpi and supplementary info (sin)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            {
                "linkaddr": "1",
                "ctrl_prm": "0",
                "asdu_typeid_mon": "2",
                "dpi": "1",
                "sin": "55",
            },
        )
        assert ix.details["dpi"] == 1
        assert ix.details["detail_str"] == "DPI=OFF"
        assert ix.details["supplementary_info"] == 55

    def test_identification_message(self):
        """Type 5 (identification) extracts manufacturer, sw id and
        compatibility level, and stores them on the session."""
        listener = _make_listener()
        ix = _feed(
            listener,
            {
                "linkaddr": "1",
                "ctrl_prm": "0",
                "asdu_typeid_mon": "5",
                "mfg": "SIEMENS",
                "mfg_sw": "12345",
                "col": "2",
            },
        )
        d = ix.details
        assert d["manufacturer"] == "SIEMENS"
        assert d["manufacturer_sw"] == "12345"
        assert d["compatibility_level"] == 2
        assert "MFG=SIEMENS" in d["detail_str"]
        assert "SW=12345" in d["detail_str"]

        session = listener.sessions[(CONTROLLED_IP, CONTROLLING_IP)]
        assert session.manufacturer == "SIEMENS"
        assert session.manufacturer_sw == "12345"

    def test_time_sync_response(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            {"linkaddr": "1", "ctrl_prm": "0", "asdu_typeid_mon": "6"},
        )
        assert ix.details["detail_str"] == "Time sync response"
        assert ix.details["type_name"] == "Time synchronization"

    def test_gi_termination(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            {"linkaddr": "1", "ctrl_prm": "0", "asdu_typeid_mon": "8"},
        )
        assert ix.details["detail_str"] == "GI termination"

    def test_disturbance_value_transmission(self):
        """Type 30 maps to the 'Disturbance values' detail string."""
        listener = _make_listener()
        ix = _feed(
            listener,
            {"linkaddr": "1", "ctrl_prm": "0", "asdu_typeid_mon": "30"},
        )
        assert ix.details["detail_str"] == "Disturbance values"
        assert ix.details["type_name"] == "Transmission of disturbance values"

    def test_unknown_mon_type_id(self):
        """An unmapped monitor type ID renders 'Mon Type N'."""
        listener = _make_listener()
        ix = _feed(
            listener,
            {"linkaddr": "1", "ctrl_prm": "0", "asdu_typeid_mon": "99"},
        )
        assert ix.details["type_name"] == "Mon Type 99"
        assert ix.operation == "Mon Type 99"

    def test_unknown_mon_cot_renders_numeric(self):
        """A COT not in COT_MON falls back to its decimal string."""
        listener = _make_listener()
        ix = _feed(
            listener,
            {
                "linkaddr": "1",
                "ctrl_prm": "0",
                "asdu_typeid_mon": "9",
                "cot_mon": "200",
            },
        )
        assert ix.details["cot_name"] == "200"


# ---------------------------------------------------------------------------
# Control-direction ASDU frames
# ---------------------------------------------------------------------------


class TestControlAsdu:
    def test_general_interrogation_with_scan(self):
        """Type 7 (general interrogation) extracts the scan number and is
        classified rw=read."""
        listener = _make_listener()
        ix = _feed(
            listener,
            {
                "linkaddr": "8",
                "ctrl_prm": "1",
                "asdu_typeid_ctrl": "7",
                "asdu_address": "5",
                "cot_ctrl": "9",
                "scn": "3",
            },
        )
        assert ix.direction == "request"
        d = ix.details
        assert d["type_id"] == 7
        assert d["type_name"] == ASDU_TYPE_CTRL[7]
        assert d["direction_type"] == "control"
        assert d["rw"] == "read"
        assert d["cot_name"] == "General interrogation"
        assert d["scan_number"] == 3
        assert d["detail_str"] == "GI scan=3"
        assert ix.summary.startswith("CMD General interrogation")

        session = listener.sessions[(CONTROLLING_IP, CONTROLLED_IP)]
        assert 7 in session.type_ids_ctrl
        assert session.control_count == 1

    def test_general_interrogation_without_scan(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            {"linkaddr": "1", "ctrl_prm": "1", "asdu_typeid_ctrl": "7"},
        )
        assert ix.details["detail_str"] == "General interrogation"
        assert "scan_number" not in ix.details

    def test_general_command_with_dco_and_rii(self):
        """Type 20 (general command) decodes dco via _DCO_VALUES and records
        the return information identifier; classified rw=write."""
        listener = _make_listener()
        ix = _feed(
            listener,
            {
                "linkaddr": "1",
                "ctrl_prm": "1",
                "asdu_typeid_ctrl": "20",
                "dco": "2",
                "rii": "7",
            },
        )
        d = ix.details
        assert d["rw"] == "write"
        assert d["dco"] == 2
        assert d["dco_name"] == "ON"
        assert d["rii"] == 7
        assert d["detail_str"] == "GC DCO=ON"

    def test_general_command_without_dco(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            {"linkaddr": "1", "ctrl_prm": "1", "asdu_typeid_ctrl": "20"},
        )
        assert ix.details["detail_str"] == "General command"
        assert "dco" not in ix.details

    def test_time_sync_command(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            {"linkaddr": "1", "ctrl_prm": "1", "asdu_typeid_ctrl": "6"},
        )
        assert ix.details["detail_str"] == "Time sync command"
        assert ix.details["rw"] == "control"

    def test_disturbance_data_order_and_ack(self):
        listener = _make_listener()
        ix_order = _feed(
            listener,
            {"linkaddr": "1", "ctrl_prm": "1", "asdu_typeid_ctrl": "24"},
        )
        assert ix_order.details["detail_str"] == "Disturbance data order"
        assert ix_order.details["rw"] == "control"

        ix_ack = _feed(
            listener,
            {"linkaddr": "1", "ctrl_prm": "1", "asdu_typeid_ctrl": "25"},
        )
        assert ix_ack.details["detail_str"] == "Disturbance data ACK"
        assert ix_ack.details["rw"] == "control"

    def test_generic_command_type_21_is_write(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            {"linkaddr": "1", "ctrl_prm": "1", "asdu_typeid_ctrl": "21"},
        )
        assert ix.details["rw"] == "write"

    def test_unknown_ctrl_type_default_write(self):
        """An unmapped control type ID gets a generic name and defaults to
        rw=write (the final else of the rw ladder)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            {"linkaddr": "1", "ctrl_prm": "1", "asdu_typeid_ctrl": "200"},
        )
        assert ix.details["type_name"] == "Ctrl Type 200"
        assert ix.details["rw"] == "write"

    def test_unknown_ctrl_cot_renders_numeric(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            {
                "linkaddr": "1",
                "ctrl_prm": "1",
                "asdu_typeid_ctrl": "20",
                "cot_ctrl": "123",
            },
        )
        assert ix.details["cot_name"] == "123"


# ---------------------------------------------------------------------------
# Device discovery & protocol_data aggregation
# ---------------------------------------------------------------------------


class TestDeviceDiscovery:
    def test_relay_and_controller_devices_created(self):
        listener = _make_listener()
        _feed(
            listener,
            {
                "linkaddr": "9",
                "ctrl_prm": "1",
                "asdu_typeid_ctrl": "20",
                "asdu_address": "1",
                "func_type": "128",
                "dco": "2",
            },
        )

        relay = listener.discovered_devices[f"iec103-relay:{CONTROLLED_IP}"]
        controller = listener.discovered_devices[f"iec103-controller:{CONTROLLING_IP}"]

        assert relay.device_type == "IEC 103 Protection Relay"
        assert controller.device_type == "IEC 103 Bay Controller"
        assert CONTROLLED_IP in relay.ip_addresses
        assert CONTROLLING_IP in controller.ip_addresses
        assert relay.protocol_data["role"] == "protection_relay"
        assert controller.protocol_data["role"] == "bay_controller"

    def test_protocol_data_aggregates_session(self):
        """protocol_data carries link/asdu addresses, monitor+control type
        IDs, function-type names and counts, plus the IEC103/Serial label."""
        listener = _make_listener()
        # One control (type 20) and one monitor (type 1) on the same session.
        _feed(
            listener,
            {
                "linkaddr": "9",
                "ctrl_prm": "1",
                "asdu_typeid_ctrl": "20",
                "asdu_address": "5",
                "func_type": "160",
                "dco": "2",
            },
        )
        _feed(
            listener,
            {
                "linkaddr": "9",
                "ctrl_prm": "1",
                "asdu_typeid_mon": "1",
                "asdu_address": "5",
                "func_type": "160",
                "dpi": "2",
            },
        )

        relay = listener.discovered_devices[f"iec103-relay:{CONTROLLED_IP}"]
        pdata = relay.protocol_data
        assert pdata["protocol"] == "IEC103/Serial"
        assert pdata["link_addresses"] == [9]
        assert pdata["asdu_addresses"] == [5]
        assert pdata["type_ids_monitor"] == [1]
        assert pdata["type_ids_control"] == [20]
        assert pdata["type_ids_all"] == [1, 20]
        assert pdata["function_types"] == [160]
        assert "Overcurrent Protection" in pdata["function_type_names"]
        assert pdata["control_commands"] == 1
        assert pdata["monitor_messages"] == 1

    def test_identification_promoted_to_protocol_data(self):
        """A type-5 identification frame surfaces manufacturer + sw on the
        relay's protocol_data."""
        listener = _make_listener()
        _feed(
            listener,
            {
                "linkaddr": "1",
                "ctrl_prm": "0",
                "asdu_typeid_mon": "5",
                "mfg": "ABB",
                "mfg_sw": "999",
            },
        )
        # PRM=0 -> controlled is src (CONTROLLING_IP host alias). The relay key
        # uses the controlled IP, which is CONTROLLING_IP here because PRM
        # flips roles for a secondary frame.
        relay = listener.discovered_devices[f"iec103-relay:{CONTROLLING_IP}"]
        assert relay.protocol_data["manufacturer"] == "ABB"
        assert relay.protocol_data["manufacturer_sw"] == "999"


# ---------------------------------------------------------------------------
# Output column formatting (_format_protocol_columns)
# ---------------------------------------------------------------------------


class TestColumnFormatting:
    def test_columns_for_monitor_frame(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            {
                "linkaddr": "9",
                "ctrl_prm": "0",
                "asdu_typeid_mon": "1",
                "asdu_address": "7",
                "func_type": "160",
                "info_num": "23",
                "cot_mon": "1",
                "dpi": "2",
            },
        )
        cols = listener._format_protocol_columns(ix)
        # rw, operation, link_addr, asdu_type, func_type, info_num, cot, detail
        assert cols[0] == "read"
        assert cols[1] == "Time-tagged message"
        assert cols[2] == 9
        assert cols[3] == "1 (Time-tagged message)"
        assert cols[4] == "160 (Overcurrent Protection)"
        assert cols[5] == "23"
        assert cols[6] == "Spontaneous"
        assert cols[7] == "DPI=ON"

    def test_columns_for_link_frame_blanks(self):
        """A link-only frame leaves type/func/info/cot columns blank."""
        listener = _make_listener()
        ix = _feed(
            listener,
            {"linkaddr": "4", "ctrl_prm": "1", "ctrl_func_pri_to_sec": "9"},
        )
        cols = listener._format_protocol_columns(ix)
        assert cols[2] == 4  # link_addr
        assert cols[3] == ""  # asdu_type blank
        assert cols[4] == ""  # func_type blank
        assert cols[5] == ""  # info_num blank


# ---------------------------------------------------------------------------
# Public API: session / control-operation summaries
# ---------------------------------------------------------------------------


class TestPublicApi:
    def test_get_sessions_summary(self):
        listener = _make_listener()
        _feed(
            listener,
            {
                "linkaddr": "12",
                "ctrl_prm": "1",
                "asdu_typeid_ctrl": "20",
                "asdu_address": "3",
                "dco": "2",
            },
        )
        _feed(
            listener,
            {
                "linkaddr": "12",
                "ctrl_prm": "1",
                "asdu_typeid_mon": "1",
                "asdu_address": "3",
                "dpi": "1",
            },
        )
        summary = listener.get_sessions_summary()
        assert len(summary) == 1
        s = summary[0]
        assert s["controlling"] == CONTROLLING_IP
        assert s["controlled"] == CONTROLLED_IP
        assert s["link_addresses"] == [12]
        assert s["asdu_addresses"] == [3]
        assert s["type_ids_ctrl"] == [20]
        assert s["type_ids_mon"] == [1]
        assert s["control_count"] == 1
        assert s["monitor_count"] == 1

    def test_get_control_operations_lists_only_command_sessions(self):
        listener = _make_listener()
        # Monitor-only frame (PRM=0) -> a session with no control commands.
        _feed(
            listener,
            {"linkaddr": "1", "ctrl_prm": "0", "asdu_typeid_mon": "1", "dpi": "1"},
        )
        # A control session (PRM=1, GI type 7 which is in _CONTROL_TYPE_IDS).
        _feed(
            listener,
            {"linkaddr": "2", "ctrl_prm": "1", "asdu_typeid_ctrl": "7", "scn": "1"},
        )
        ops = listener.get_control_operations()
        assert len(ops) == 1
        assert ops[0]["controlling"] == CONTROLLING_IP
        assert ops[0]["control_count"] == 1
        assert "General interrogation" in ops[0]["control_types"]


# ---------------------------------------------------------------------------
# process_packet guards
# ---------------------------------------------------------------------------


class TestProcessPacketGuards:
    def test_packet_without_ip_is_ignored(self):
        listener = _make_listener()
        listener.get_ip_info = lambda packet: ("", "")
        listener.process_packet(_Packet({"linkaddr": "1", "ctrl_prm": "1"}))
        assert listener.interactions == []

    def test_packet_without_iec103_layer_is_ignored(self):
        listener = _make_listener()

        class _Empty:
            pass

        listener.process_packet(_Empty())
        assert listener.interactions == []

    def test_session_split_per_direction(self):
        """A primary command and a secondary monitor frame flip roles, so
        they land in two distinct (controlling, controlled) sessions."""
        listener = _make_listener()
        _feed(
            listener,
            {"linkaddr": "1", "ctrl_prm": "1", "asdu_typeid_ctrl": "7", "scn": "1"},
        )
        _feed(
            listener,
            {"linkaddr": "1", "ctrl_prm": "0", "asdu_typeid_mon": "1", "dpi": "1"},
        )
        assert (CONTROLLING_IP, CONTROLLED_IP) in listener.sessions
        assert (CONTROLLED_IP, CONTROLLING_IP) in listener.sessions

    def test_control_frame_carries_info_num(self):
        """A control-direction ASDU with an information number surfaces it in
        details (the control-path info_num branch)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            {
                "linkaddr": "1",
                "ctrl_prm": "1",
                "asdu_typeid_ctrl": "20",
                "info_num": "42",
                "dco": "2",
            },
        )
        assert ix.details["info_num"] == 42
        assert "IN=42" in ix.summary

    def test_update_devices_with_unknown_session_returns(self):
        """_update_devices early-returns when no session exists for the pair
        (defensive guard) -- no device is created."""
        listener = _make_listener()
        listener._update_devices("10.9.9.9", "", "10.9.9.10", "")
        assert "iec103-relay:10.9.9.10" not in listener.discovered_devices
        assert "iec103-controller:10.9.9.9" not in listener.discovered_devices

    def test_func_type_zero_is_tracked(self):
        """func_type 0 ('Not Used') is still a valid int and tracked on the
        session (the parser distinguishes None from 0)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            {
                "linkaddr": "1",
                "ctrl_prm": "1",
                "asdu_typeid_ctrl": "7",
                "func_type": "0",
            },
        )
        assert ix.details["func_type"] == 0
        assert ix.details["func_type_name"] == "Not Used"
        session = listener.sessions[(CONTROLLING_IP, CONTROLLED_IP)]
        assert 0 in session.function_types
