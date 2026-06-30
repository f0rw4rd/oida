"""Unit tests for the IEC 60870-5-101 passive listener / frame parser.

These tests drive ``IEC101PassiveListener.process_packet`` with hand-built
fake PyShark layers (no tshark / pyshark required). The fakes faithfully
reproduce the two access patterns the parser relies on:

1. scalar attribute access  -- ``layer.linkaddr`` -> a value (used by
   ``get_field`` / ``_parse_int``); and
2. multi-field access        -- ``layer.siq_spi.all_fields`` -> an iterable
   of objects each exposing ``.show`` (used by the per-IOA value/quality
   extractors).

A field is therefore modeled as ``_Field`` (carries ``.show`` and the raw
``value``) so both ``str(field)`` (scalar) and ``field.all_fields[i].show``
(multi) resolve to the bytes the real iec60870_asdu dissector would emit.

Everything asserted here is derived from the mock IEC-101 link-layer / ASDU
frames built in each test -- the parser's own output (interactions, session
state, discovered devices, protocol_data) is checked against the known input.
"""

from typing import Any, Dict, List, Optional

from oida.pcap.iec101 import (
    LINK_FUNC_PRI_TO_SEC,
    LINK_FUNC_SEC_TO_PRI,
    IEC101PassiveListener,
)


# ---------------------------------------------------------------------------
# Fake PyShark layer scaffolding
# ---------------------------------------------------------------------------


class _Field(str):
    """A single dissected field value, modeled like a pyshark ``LayerField``.

    Real pyshark field accessors return a string-like object that ALSO exposes
    ``.show`` and ``.all_fields``. We subclass ``str`` so ``get_field`` /
    ``_parse_int`` / ``int(...)`` read the scalar wire value directly, while the
    per-IOA extractors can still iterate ``.all_fields`` and read each ``.show``.
    ``.all_fields`` defaults to ``[self]`` (single occurrence) and is overridden
    for multi-IOA frames.
    """

    def __new__(cls, value: Any, all_values: Optional[List[Any]] = None):
        obj = super().__new__(cls, str(value))
        obj.show = str(value)
        obj.value = value
        if all_values is None:
            obj.all_fields = [obj]
        else:
            obj.all_fields = [_Field(v) for v in all_values]
        return obj


class _Scalar(str):
    """A bare scalar field value with NO ``.all_fields`` / ``.show``.

    Used to exercise the *scalar fallback* branches of the extractors, where
    ``getattr(layer, field).all_fields`` raises AttributeError and the code
    falls back to parsing the raw ``get_field`` string. Wrap a value with
    ``_scalar(...)`` in an asdu_fields dict to force that path.
    """


def _scalar(value: Any) -> _Scalar:
    return _Scalar(str(value))


class _Layer:
    """Minimal PyShark layer: attribute access only over an explicit dict.

    Fields present in ``fields`` are exposed as attributes; everything else
    raises AttributeError via ``getattr`` (so ``get_field`` returns its
    default), matching a real dissector that simply did not emit the field.
    """

    def __init__(self, fields: Dict[str, Any]):
        for name, val in fields.items():
            if isinstance(val, _Field) or isinstance(val, _Scalar):
                setattr(self, name, val)
            elif isinstance(val, list):
                # Multi-occurrence field (per-IOA): first .show is val[0].
                f = _Field(val[0], all_values=val)
                setattr(self, name, f)
            else:
                setattr(self, name, _Field(val))


class _Packet:
    """Fake packet carrying the iec60870_101 link layer and optional ASDU."""

    def __init__(self, iec101_fields: Dict[str, Any], asdu_fields: Optional[Dict[str, Any]] = None):
        self.iec60870_101 = _Layer(iec101_fields)
        if asdu_fields is not None:
            self.iec60870_asdu = _Layer(asdu_fields)


CONTROLLING_IP = "10.0.0.1"  # SCADA / master
CONTROLLED_IP = "10.0.0.2"  # RTU / slave
CONTROLLING_MAC = "aa:bb:cc:dd:ee:01"
CONTROLLED_MAC = "aa:bb:cc:dd:ee:02"


def _make_listener() -> IEC101PassiveListener:
    """Build a listener with the base PyShark transport helpers stubbed.

    The src is always the *master* (10.0.0.1) and dst the *slave* (10.0.0.2);
    the parser flips controlling/controlled based on the PRM bit, not on the
    raw src/dst, so each test controls direction via ``ctrl_prm``.
    """
    listener = IEC101PassiveListener("test0")
    listener.get_ip_info = lambda packet: (CONTROLLING_IP, CONTROLLED_IP)
    listener.get_port_info = lambda packet: (50000, 2404)
    listener.get_mac_info = lambda packet: (CONTROLLING_MAC, CONTROLLED_MAC)
    listener.get_flow_id = lambda packet: "flow-1"
    listener.get_stream_id = lambda packet: "stream-1"
    return listener


def _feed(listener: IEC101PassiveListener, packet: _Packet):
    listener.process_packet(packet)
    return listener.interactions[-1]


# ---------------------------------------------------------------------------
# Link-layer frame parsing (fixed-length / no ASDU)
# ---------------------------------------------------------------------------


class TestLinkLayerFrames:
    def test_primary_request_status_of_link(self):
        """PRM=1 + pri-to-sec func 9 (Request Status of Link) -> a request
        link frame; the master is the controlling station."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {
                    "linkaddr": "7",
                    "ctrl_prm": "1",
                    "ctrl_func_pri_to_sec": "9",
                    "header": "0x10",
                }
            ),
        )

        assert ix.direction == "request"
        assert ix.operation == f"Link: {LINK_FUNC_PRI_TO_SEC[9]}"
        assert ix.details["frame_type"] == "link"
        assert ix.details["is_primary"] is True
        assert ix.details["link_addr"] == 7
        assert ix.details["link_func_code"] == 9
        assert ix.details["link_func_name"] == "Request Status of Link"
        assert "addr=7" in ix.summary

        # The PRM=1 packet makes src(10.0.0.1) the controlling station.
        session = listener.sessions[(CONTROLLING_IP, CONTROLLED_IP)]
        assert 7 in session.link_addresses

    def test_secondary_response_function_code(self):
        """PRM=0 + sec-to-pri func 11 (Status of Link / Access Demand) ->
        a response; the slave (src) becomes the controlled station and the
        master (dst) the controlling station."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {
                    "linkaddr": "3",
                    "ctrl_prm": "0",
                    "ctrl_func_sec_to_pri": "11",
                    "header": "0x10",
                }
            ),
        )

        assert ix.direction == "response"
        assert ix.operation == f"Link: {LINK_FUNC_SEC_TO_PRI[11]}"
        assert ix.details["is_primary"] is False
        assert ix.details["link_func_name"] == "Status of Link / Access Demand"

        # PRM=0: controlling=dst(10.0.0.2), controlled=src(10.0.0.1).
        session = listener.sessions[(CONTROLLED_IP, CONTROLLING_IP)]
        assert 3 in session.link_addresses

    def test_single_char_ack_e5(self):
        """A single-character ACK frame (header 0xE5) from the secondary
        station maps to the 'Single Char ACK (E5h)' operation."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {
                    "linkaddr": "1",
                    "ctrl_prm": "0",
                    "ctrl_func_sec_to_pri": "0",  # ACK (positive)
                    "header": "0xe5",
                }
            ),
        )

        assert ix.operation == "Single Char ACK (E5h)"
        assert ix.direction == "response"
        assert ix.details["link_func_name"] == "ACK (positive)"

    def test_unknown_primary_func_code_falls_back(self):
        """An unmapped pri-to-sec function code yields a 'PRI Func N' name and
        still records the numeric code in details."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {
                    "linkaddr": "2",
                    "ctrl_prm": "1",
                    "ctrl_func_pri_to_sec": "7",  # not in LINK_FUNC_PRI_TO_SEC
                    "header": "0x10",
                }
            ),
        )

        assert ix.details["link_func_code"] == 7
        assert ix.details["link_func_name"] == "PRI Func 7"
        assert ix.operation == "Link: PRI Func 7"

    def test_primary_without_func_field_is_unknown(self):
        """PRM=1 but no function-code field present -> 'Unknown Link Func'
        with no link_func_code recorded, direction still request."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet({"linkaddr": "5", "ctrl_prm": "1", "header": "0x10"}),
        )

        assert ix.operation == "Link: Unknown Link Func"
        assert ix.direction == "request"
        assert "link_func_code" not in ix.details


# ---------------------------------------------------------------------------
# ASDU monitor-direction frames (measurements)
# ---------------------------------------------------------------------------


class TestAsduMonitorFrames:
    def test_single_point_information_on(self):
        """M_SP_NA_1 (type 1) with siq.spi=1 decodes to value 'ON', classifies
        as a monitor (response) message, and rolls up session monitor_count."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "4", "ctrl_prm": "0"},
                asdu_fields={
                    "typeid": "1",
                    "addr": "11",
                    "ioa": "100",
                    "causetx": "3",  # spontaneous
                    "siq_spi": "1",
                },
            ),
        )

        assert ix.operation == "M_SP_NA_1"
        assert ix.direction == "response"
        d = ix.details
        assert d["type_id"] == 1
        assert d["type_name"] == "M_SP_NA_1"
        assert d["common_address"] == 11
        assert d["ioa"] == 100
        assert d["cot_name"] == "spontaneous"
        assert d["rw"] == "read"
        assert d["values"] == ["ON"]
        assert ix.summary.startswith("MON M_SP_NA_1")
        assert "val=ON" in ix.summary

        session = listener.sessions[(CONTROLLED_IP, CONTROLLING_IP)]
        assert 1 in session.type_ids
        assert session.monitor_count == 1
        assert session.control_count == 0
        assert 100 in session.ioa_seen
        assert 11 in session.common_addresses

    def test_double_point_information_with_diq_quality(self):
        """M_DP_NA_1 (type 3) decodes diq.dpi via _DPI_VALUES and surfaces DIQ
        quality flags (IV) per IOA."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "4", "ctrl_prm": "0"},
                asdu_fields={
                    "typeid": "3",
                    "addr": "1",
                    "ioa": "200",
                    "causetx": "3",
                    "diq_dpi": "2",  # ON
                    "diq_iv": "True",
                },
            ),
        )

        assert ix.details["values"] == ["ON"]
        assert ix.details["quality"] == ["IV"]
        assert "IV" in ix.summary or ix.details["quality"] == ["IV"]

    def test_short_float_measured_value_with_qds_overflow(self):
        """M_ME_NC_1 (type 13) formats the float and reports QDS overflow."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "4", "ctrl_prm": "0"},
                asdu_fields={
                    "typeid": "13",
                    "addr": "1",
                    "ioa": "300",
                    "causetx": "1",  # periodic
                    "float": "23.5",
                    "qds_ov": "True",
                },
            ),
        )

        assert ix.details["values"] == ["23.5"]
        assert ix.details["quality"] == ["OV"]
        assert ix.details["cot_name"] == "periodic"

    def test_float_value_trailing_zero_stripped(self):
        """_format_float turns 42.0 into '42' (integral floats lose the .0)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": "13", "addr": "1", "ioa": "5", "float": "42.0"},
            ),
        )
        assert ix.details["values"] == ["42"]

    def test_multi_ioa_measurement_range(self):
        """Several IOAs in one ASDU populate ioa_seen and render an IOA range
        in the summary (first-last)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={
                    "typeid": "13",
                    "addr": "1",
                    "ioa": ["10", "11", "12"],
                    "float": ["1.5", "2.5", "3.5"],
                },
            ),
        )

        assert ix.details["ioa"] == [10, 11, 12]
        assert ix.details["values"] == ["1.5", "2.5", "3.5"]
        assert "IOA=10-12" in ix.summary

        session = listener.sessions[(CONTROLLED_IP, CONTROLLING_IP)]
        assert {10, 11, 12} <= session.ioa_seen

    def test_scaled_value_extraction(self):
        """M_ME_NB_1 (type 11, scalval) extracts the scaled integer value."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": "11", "addr": "1", "ioa": "7", "scalval": "1234"},
            ),
        )
        assert ix.details["values"] == ["1234"]

    def test_integrated_total_counter_bcr(self):
        """M_IT_NA_1 (type 15) extracts the binary counter reading (bcr.count)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": "15", "addr": "1", "ioa": "9", "bcr_count": "98765"},
            ),
        )
        assert ix.details["values"] == ["98765"]

    def test_step_position_transient(self):
        """M_ST_NA_1 (type 5) marks a transient step position value with (T)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={
                    "typeid": "5",
                    "addr": "1",
                    "ioa": "3",
                    "vti_v": "5",
                    "vti_t": "True",
                },
            ),
        )
        assert ix.details["values"] == ["5(T)"]

    def test_end_of_initialization_coi(self):
        """M_EI_NA_1 (type 70) decodes the cause-of-initialization field."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": "70", "addr": "1", "ioa": "0", "coi_r": "2"},
            ),
        )
        assert ix.details["values"] == ["COI=remote_reset"]


# ---------------------------------------------------------------------------
# ASDU control-direction frames (commands)
# ---------------------------------------------------------------------------


class TestAsduControlFrames:
    def test_single_command_select(self):
        """C_SC_NA_1 (type 45) is a control command: direction request, rw
        write, control_count incremented, and the select bit rendered (S)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "8", "ctrl_prm": "1"},
                asdu_fields={
                    "typeid": "45",
                    "addr": "1",
                    "ioa": "500",
                    "causetx": "6",  # activation
                    "sco_on": "True",
                    "sco_se": "True",
                },
            ),
        )

        assert ix.direction == "request"
        assert ix.details["rw"] == "write"
        assert ix.details["values"] == ["ON(S)"]
        assert ix.summary.startswith("CMD C_SC_NA_1")
        assert ix.details["cot_name"] == "activation"

        session = listener.sessions[(CONTROLLING_IP, CONTROLLED_IP)]
        assert session.control_count == 1
        assert session.monitor_count == 0

    def test_double_command_value(self):
        """C_DC_NA_1 (type 46) decodes dco.on through _DPI_VALUES (OFF)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={"typeid": "46", "addr": "1", "ioa": "1", "dco_on": "1"},
            ),
        )
        assert ix.details["values"] == ["OFF"]
        assert ix.details["rw"] == "write"

    def test_regulating_step_command(self):
        """C_RC_NA_1 (type 47) decodes rco.up through _RCO_VALUES (HIGHER)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={"typeid": "47", "addr": "1", "ioa": "1", "rco_up": "2"},
            ),
        )
        assert ix.details["values"] == ["HIGHER"]

    def test_interrogation_command_is_read(self):
        """C_IC_NA_1 (type 100) is a read/query command (rw=read) carrying a
        QOI value; it is still counted as a control message."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={"typeid": "100", "addr": "1", "ioa": "0", "qoi": "20"},
            ),
        )
        assert ix.details["rw"] == "read"
        assert ix.details["values"] == ["QOI=20"]
        session = listener.sessions[(CONTROLLING_IP, CONTROLLED_IP)]
        assert session.control_count == 1

    def test_clock_sync_is_control_system(self):
        """C_CS_NA_1 (type 103) classifies as a system control (rw=control)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={"typeid": "103", "addr": "1", "ioa": "0", "cp56time": "2024-01-01"},
            ),
        )
        assert ix.details["rw"] == "control"
        assert ix.details["values"] == ["2024-01-01"]

    def test_file_ready_is_file_rw(self):
        """F_FR_NA_1 (type 120) classifies as rw=file."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={"typeid": "120", "addr": "1", "ioa": "0"},
            ),
        )
        assert ix.details["rw"] == "file"


# ---------------------------------------------------------------------------
# Cause-of-transmission / error handling
# ---------------------------------------------------------------------------


class TestCotAndErrors:
    def test_negative_confirmation_flagged_as_error(self):
        """A negative P/N bit prefixes the COT name with 'neg_', marks the
        interaction as an error (ERR summary), and sets rw=error."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={
                    "typeid": "45",
                    "addr": "1",
                    "ioa": "1",
                    "causetx": "7",  # actcon
                    "nega": "True",
                    "sco_on": "True",
                },
            ),
        )
        assert ix.details["negative"] is True
        assert ix.details["cot_name"] == "neg_actcon"
        assert ix.details["rw"] == "error"
        assert ix.summary.startswith("ERR ")

    def test_error_cot_unknown_type(self):
        """COT 44 (unknown_type) is an error COT -> ERR summary, rw=error."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={"typeid": "100", "addr": "1", "ioa": "0", "causetx": "44"},
            ),
        )
        assert ix.details["cot_name"] == "unknown_type"
        assert ix.details["rw"] == "error"
        assert ix.summary.startswith("ERR ")

    def test_unknown_cot_value_renders_numeric(self):
        """A COT not present in COT_NAMES falls back to its decimal string."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={
                    "typeid": "1",
                    "addr": "1",
                    "ioa": "1",
                    "causetx": "99",
                    "siq_spi": "0",
                },
            ),
        )
        assert ix.details["cot_name"] == "99"

    def test_malformed_asdu_without_typeid(self):
        """An ASDU layer present but with no typeid is recorded as a malformed
        ASDU, not silently dropped."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "6", "ctrl_prm": "1"},
                asdu_fields={"addr": "1", "ioa": "1"},  # no typeid
            ),
        )
        assert ix.operation == "ASDU (malformed)"
        assert ix.details["malformed"] is True
        assert ix.details["link_addr"] == 6
        assert "Malformed ASDU" in ix.summary

    def test_unknown_type_id_gets_generic_name(self):
        """An unmapped type ID renders as 'Type<N>' and still records."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": "199", "addr": "1", "ioa": "1"},
            ),
        )
        assert ix.details["type_name"] == "Type199"
        assert ix.operation == "Type199"


# ---------------------------------------------------------------------------
# Device discovery & protocol_data
# ---------------------------------------------------------------------------


class TestDeviceDiscovery:
    def test_controlled_and_controlling_devices_created(self):
        """A primary ASDU frame creates both an RTU (controlled) and a SCADA
        (controlling) device, each with the right device_type and role."""
        listener = _make_listener()
        _feed(
            listener,
            _Packet(
                {"linkaddr": "9", "ctrl_prm": "1"},
                asdu_fields={"typeid": "45", "addr": "1", "ioa": "1", "sco_on": "True"},
            ),
        )

        controlled = listener.discovered_devices[f"iec101-controlled:{CONTROLLED_IP}"]
        controlling = listener.discovered_devices[f"iec101-controlling:{CONTROLLING_IP}"]

        assert controlled.device_type == "IEC 101 Controlled Station (RTU)"
        assert controlling.device_type == "IEC 101 Controlling Station (SCADA)"
        assert CONTROLLED_IP in controlled.ip_addresses
        assert CONTROLLING_IP in controlling.ip_addresses
        assert controlled.protocol_data["role"] == "controlled_station"
        assert controlling.protocol_data["role"] == "controlling_station"

    def test_protocol_data_aggregates_session(self):
        """protocol_data carries link addresses, common addresses, type IDs
        (with names), control/monitor counts and the IEC101/Serial label."""
        listener = _make_listener()
        # One control command (type 45) and one monitor reading (type 13).
        _feed(
            listener,
            _Packet(
                {"linkaddr": "9", "ctrl_prm": "1"},
                asdu_fields={"typeid": "45", "addr": "5", "ioa": "10", "sco_on": "True"},
            ),
        )
        _feed(
            listener,
            _Packet(
                {"linkaddr": "9", "ctrl_prm": "1"},
                asdu_fields={"typeid": "13", "addr": "5", "ioa": "20", "float": "1.0"},
            ),
        )

        device = listener.discovered_devices[f"iec101-controlled:{CONTROLLED_IP}"]
        pdata = device.protocol_data
        assert pdata["protocol"] == "IEC101/Serial"
        assert pdata["link_addresses"] == [9]
        assert pdata["common_addresses"] == [5]
        assert set(pdata["type_ids_seen"]) == {13, 45}
        assert "C_SC_NA_1" in pdata["type_names"]
        assert "M_ME_NC_1" in pdata["type_names"]
        assert pdata["control_commands"] == 1
        assert pdata["monitor_messages"] == 1
        # IOAs 10 and 20 are within 10 of each other -> single merged range.
        assert pdata["ioa_ranges"] == [(10, 20)]

    def test_ioa_ranges_split_on_gap(self):
        """IOAs more than 10 apart split into separate ranges.

        These are primary (master->slave) frames so the RTU is the dst
        (CONTROLLED_IP) -- matching the iec101-controlled device key.
        """
        listener = _make_listener()
        for ioa in ("1", "2", "50", "51"):
            _feed(
                listener,
                _Packet(
                    {"linkaddr": "1", "ctrl_prm": "1"},
                    asdu_fields={"typeid": "13", "addr": "1", "ioa": ioa, "float": "1.0"},
                ),
            )
        device = listener.discovered_devices[f"iec101-controlled:{CONTROLLED_IP}"]
        assert device.protocol_data["ioa_ranges"] == [(1, 2), (50, 51)]


# ---------------------------------------------------------------------------
# Public API: sessions / control operations summaries
# ---------------------------------------------------------------------------


class TestPublicApi:
    def test_get_sessions_summary(self):
        """get_sessions_summary reflects the accumulated link/common addrs,
        type IDs and counts for the master->slave session."""
        listener = _make_listener()
        _feed(
            listener,
            _Packet(
                {"linkaddr": "12", "ctrl_prm": "1"},
                asdu_fields={"typeid": "45", "addr": "3", "ioa": "1", "sco_on": "True"},
            ),
        )
        _feed(
            listener,
            _Packet(
                {"linkaddr": "12", "ctrl_prm": "1"},
                asdu_fields={"typeid": "1", "addr": "3", "ioa": "2", "siq_spi": "1"},
            ),
        )

        summary = listener.get_sessions_summary()
        assert len(summary) == 1
        s = summary[0]
        assert s["controlling"] == CONTROLLING_IP
        assert s["controlled"] == CONTROLLED_IP
        assert s["link_addresses"] == [12]
        assert s["common_addresses"] == [3]
        assert set(s["type_ids"]) == {1, 45}
        assert s["control_count"] == 1
        assert s["monitor_count"] == 1

    def test_get_control_operations_only_lists_command_sessions(self):
        """get_control_operations returns only sessions with control commands,
        naming the control type(s) seen."""
        listener = _make_listener()
        # A monitor-only session (slave -> master) must NOT appear.
        _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": "13", "addr": "1", "ioa": "1", "float": "1.0"},
            ),
        )
        # A control session (master -> slave) MUST appear.
        _feed(
            listener,
            _Packet(
                {"linkaddr": "2", "ctrl_prm": "1"},
                asdu_fields={"typeid": "46", "addr": "1", "ioa": "1", "dco_on": "2"},
            ),
        )

        ops = listener.get_control_operations()
        assert len(ops) == 1
        assert ops[0]["controlling"] == CONTROLLING_IP
        assert ops[0]["control_count"] == 1
        assert "C_DC_NA_1" in ops[0]["control_types"]

    def test_harvest_emits_control_alert(self):
        """harvest() surfaces a control alert describing the command flow."""
        listener = _make_listener()
        _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={"typeid": "45", "addr": "1", "ioa": "1", "sco_on": "True"},
            ),
        )

        harvest = listener.harvest()
        alerts = harvest.get("alerts", [])
        assert any(a["category"] == "control_alert" for a in alerts)
        control_alert = next(a for a in alerts if a["category"] == "control_alert")
        assert "IEC101 CONTROL" in control_alert["message"]
        assert CONTROLLING_IP in control_alert["message"]
        assert CONTROLLED_IP in control_alert["message"]


# ---------------------------------------------------------------------------
# Output column formatting (_format_protocol_columns)
# ---------------------------------------------------------------------------


class TestColumnFormatting:
    def test_format_columns_single_ioa(self):
        """_format_protocol_columns lays out rw / op / link / type / cot / ca /
        ioa / value / quality for a single-IOA measurement."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "9", "ctrl_prm": "0"},
                asdu_fields={
                    "typeid": "13",
                    "addr": "7",
                    "ioa": "42",
                    "causetx": "3",
                    "float": "12.5",
                    "qds_iv": "True",
                },
            ),
        )

        cols = listener._format_protocol_columns(ix)
        # Columns: rw, operation, link_addr, type_id, cot, common_addr, ioa, value, quality
        assert cols[0] == "read"
        assert cols[1] == "M_ME_NC_1"
        assert cols[2] == 9  # link_addr
        assert cols[3] == "13 (M_ME_NC_1)"
        assert cols[4] == "spontaneous"
        assert cols[5] == 7  # common_addr
        assert cols[6] == "42"
        assert cols[7] == "12.5"
        assert cols[8] == "IV"

    def test_format_columns_multi_ioa_range(self):
        """Many IOAs collapse to a first-last range in the IOA column."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={
                    "typeid": "13",
                    "addr": "1",
                    "ioa": ["1", "2", "3", "4", "5", "6"],
                    "float": ["1.0"] * 6,
                },
            ),
        )
        cols = listener._format_protocol_columns(ix)
        assert cols[6] == "1-6"  # ioa range for >5 entries

    def test_format_columns_small_ioa_list_joined(self):
        """A small (<=5) IOA list is pipe-joined rather than ranged."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={
                    "typeid": "13",
                    "addr": "1",
                    "ioa": ["10", "20", "30"],
                    "float": ["1.0", "2.0", "3.0"],
                },
            ),
        )
        cols = listener._format_protocol_columns(ix)
        assert cols[6] == "10 | 20 | 30"


# ---------------------------------------------------------------------------
# Multi-packet session accumulation
# ---------------------------------------------------------------------------


class TestSessionAccumulation:
    def test_separate_sessions_per_direction_pair(self):
        """A primary frame (master->slave) and a secondary frame (slave->master)
        canonicalize to the same controlling/controlled ordering, so both land
        in a single session keyed (controlling, controlled)."""
        listener = _make_listener()
        # Primary: controlling=10.0.0.1, controlled=10.0.0.2
        _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={"typeid": "45", "addr": "1", "ioa": "1", "sco_on": "True"},
            ),
        )
        # Secondary response: PRM=0 with src=10.0.0.1,dst=10.0.0.2 flips the
        # roles, producing a DISTINCT (controlled, controlling) session key.
        _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": "1", "addr": "1", "ioa": "2", "siq_spi": "1"},
            ),
        )

        assert (CONTROLLING_IP, CONTROLLED_IP) in listener.sessions
        assert (CONTROLLED_IP, CONTROLLING_IP) in listener.sessions

    def test_multiple_link_and_common_addresses_tracked(self):
        """Repeated primary frames with differing link/common addresses
        accumulate every value in the one session."""
        listener = _make_listener()
        for la, ca in (("1", "10"), ("2", "20"), ("3", "30")):
            _feed(
                listener,
                _Packet(
                    {"linkaddr": la, "ctrl_prm": "1"},
                    asdu_fields={"typeid": "45", "addr": ca, "ioa": "1", "sco_on": "True"},
                ),
            )
        session = listener.sessions[(CONTROLLING_IP, CONTROLLED_IP)]
        assert session.link_addresses == {1, 2, 3}
        assert session.common_addresses == {10, 20, 30}
        assert session.control_count == 3


# ---------------------------------------------------------------------------
# Scalar-fallback extraction paths (fields without .all_fields)
# ---------------------------------------------------------------------------


class TestScalarFallbackExtraction:
    """Drive the per-extractor scalar fallback branches: when a field exposes
    no ``.all_fields`` iterator the code parses the raw string instead. Each
    test wraps the value with ``_scalar(...)`` to force that path."""

    def test_spi_scalar_fallback(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": "1", "addr": "1", "ioa": "1", "siq_spi": _scalar("True")},
            ),
        )
        assert ix.details["values"] == ["ON"]

    def test_dpi_scalar_fallback(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": "3", "addr": "1", "ioa": "1", "diq_dpi": _scalar("1")},
            ),
        )
        assert ix.details["values"] == ["OFF"]

    def test_float_scalar_fallback(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": "13", "addr": "1", "ioa": "1", "float": _scalar("3.25")},
            ),
        )
        assert ix.details["values"] == ["3.25"]

    def test_sco_scalar_fallback_with_select(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={
                    "typeid": "45",
                    "addr": "1",
                    "ioa": "1",
                    "sco_on": _scalar("True"),
                    "sco_se": _scalar("True"),
                },
            ),
        )
        assert ix.details["values"] == ["ON(S)"]

    def test_dco_scalar_fallback(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={"typeid": "46", "addr": "1", "ioa": "1", "dco_on": _scalar("2")},
            ),
        )
        assert ix.details["values"] == ["ON"]

    def test_rco_scalar_fallback(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={"typeid": "47", "addr": "1", "ioa": "1", "rco_up": _scalar("1")},
            ),
        )
        assert ix.details["values"] == ["LOWER"]

    def test_bcr_scalar_fallback_via_bcr_field(self):
        """When bcr_count is absent the extractor falls back to the raw bcr
        field."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": "15", "addr": "1", "ioa": "1", "bcr": "555"},
            ),
        )
        assert ix.details["values"] == ["555"]

    def test_vti_raw_fallback(self):
        """With no vti_v present the step-position extractor falls back to the
        raw 'vti' field."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": "5", "addr": "1", "ioa": "1", "vti": "3"},
            ),
        )
        assert ix.details["values"] == ["3"]


# ---------------------------------------------------------------------------
# More value kinds + quality variants
# ---------------------------------------------------------------------------


class TestMoreValueKinds:
    def test_bitstring_value(self):
        """M_BO_NA_1 (type 7, bitstring) surfaces the raw bitstring value."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": "7", "addr": "1", "ioa": "1", "bitstring": "0xdeadbeef"},
            ),
        )
        assert ix.details["values"] == ["0xdeadbeef"]

    def test_normalized_value(self):
        """M_ME_NA_1 (type 9, normval) surfaces the normalized value."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": "9", "addr": "1", "ioa": "1", "normval": "0.75"},
            ),
        )
        assert ix.details["values"] == ["0.75"]

    def test_counter_interrogation_qcc(self):
        """C_CI_NA_1 (type 101) surfaces the QCC qualifier."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={"typeid": "101", "addr": "1", "ioa": "0", "qcc": "5"},
            ),
        )
        assert ix.details["values"] == ["QCC=5"]
        assert ix.details["rw"] == "read"

    def test_siq_quality_flags_multiple(self):
        """SIQ quality fields combine into a pipe-joined flag set per IOA."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={
                    "typeid": "1",
                    "addr": "1",
                    "ioa": "1",
                    "siq_spi": "1",
                    "siq_iv": "True",
                    "siq_nt": "True",
                },
            ),
        )
        assert ix.details["quality"] == ["IV|NT"]

    def test_qds_multi_ioa_quality(self):
        """QDS flags align per IOA: only the second IOA is invalid."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={
                    "typeid": "13",
                    "addr": "1",
                    "ioa": ["1", "2"],
                    "float": ["1.0", "2.0"],
                    "qds_iv": ["False", "True"],
                },
            ),
        )
        assert ix.details["quality"] == ["", "IV"]

    def test_no_quality_for_command_types(self):
        """Command types (e.g. C_SE_NC_1 setpoint float) have no quality
        source, so no quality key is added."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={"typeid": "50", "addr": "1", "ioa": "1", "float": "9.0"},
            ),
        )
        assert "quality" not in ix.details
        assert ix.details["values"] == ["9"]


# ---------------------------------------------------------------------------
# Malformed common-address & no-value edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_non_numeric_common_address_defaults_zero(self):
        """A non-integer common address parses to 0 (and is not surfaced in
        the CA portion of the summary)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={
                    "typeid": "1",
                    "addr": _scalar("notanumber"),
                    "ioa": "1",
                    "siq_spi": "0",
                },
            ),
        )
        assert ix.details["common_address"] == 0
        assert " CA=" not in ix.summary

    def test_value_kind_with_no_field_present(self):
        """A type with a value category but no value field present yields no
        'values' key (extractor returns empty)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": "13", "addr": "1", "ioa": "1"},  # no float field
            ),
        )
        assert "values" not in ix.details

    def test_format_columns_no_values_or_quality(self):
        """_format_protocol_columns renders empty value/quality cells when the
        ASDU carried none."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "3", "ctrl_prm": "1"},
                asdu_fields={"typeid": "100", "addr": "0", "ioa": "0"},  # GI, no value
            ),
        )
        cols = listener._format_protocol_columns(ix)
        assert cols[7] == ""  # value
        assert cols[8] == ""  # quality

    def test_format_columns_link_frame_blanks(self):
        """A link-only frame has no type/CA columns -> those cells blank."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "4", "ctrl_prm": "1", "ctrl_func_pri_to_sec": "9", "header": "0x10"}
            ),
        )
        cols = listener._format_protocol_columns(ix)
        assert cols[2] == 4  # link_addr still present
        assert cols[3] == ""  # type_id blank
        assert cols[5] == ""  # common_addr blank


# ---------------------------------------------------------------------------
# Deeper fallback / error branches
# ---------------------------------------------------------------------------


class TestDeepBranches:
    def test_non_integer_typeid_is_dropped(self):
        """A present-but-unparseable typeid (e.g. 'XX') is silently dropped:
        no interaction is recorded."""
        listener = _make_listener()
        before = len(listener.interactions)
        listener.process_packet(
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": _scalar("XX"), "addr": "1", "ioa": "1"},
            )
        )
        assert len(listener.interactions) == before

    def test_multi_ioa_comma_split_fallback(self):
        """A scalar IOA field holding a comma-separated list is split into
        individual IOAs (the _get_multi_field_ints fallback)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={
                    "typeid": "13",
                    "addr": "1",
                    "ioa": _scalar("10, 20, 30"),
                    "float": "1.0",
                },
            ),
        )
        assert ix.details["ioa"] == [10, 20, 30]
        session = listener.sessions[(CONTROLLED_IP, CONTROLLING_IP)]
        assert {10, 20, 30} <= session.ioa_seen

    def test_dco_scalar_non_integer_value(self):
        """A non-integer dco.on scalar falls through to the raw string value."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={"typeid": "46", "addr": "1", "ioa": "1", "dco_on": _scalar("weird")},
            ),
        )
        assert ix.details["values"] == ["weird"]

    def test_rco_scalar_non_integer_value(self):
        """A non-integer rco.up scalar falls through to the raw string value."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={"typeid": "47", "addr": "1", "ioa": "1", "rco_up": _scalar("oops")},
            ),
        )
        assert ix.details["values"] == ["oops"]

    def test_dco_multifield_with_select(self):
        """Multi-field dco.on with an aligned dco.se select bit renders (S)
        on the selected entry."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={
                    "typeid": "46",
                    "addr": "1",
                    "ioa": ["1", "2"],
                    "dco_on": ["1", "2"],
                    "dco_se": ["True", "False"],
                },
            ),
        )
        assert ix.details["values"] == ["OFF(S)", "ON"]

    def test_rco_multifield_with_select(self):
        """Multi-field rco.up with an aligned rco.se select bit renders (S)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={
                    "typeid": "47",
                    "addr": "1",
                    "ioa": ["1", "2"],
                    "rco_up": ["1", "2"],
                    "rco_se": ["True", "False"],
                },
            ),
        )
        assert ix.details["values"] == ["LOWER(S)", "HIGHER"]

    def test_sco_multifield_with_select(self):
        """Multi-field sco.on with an aligned sco.se select bit renders (S)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={
                    "typeid": "45",
                    "addr": "1",
                    "ioa": ["1", "2"],
                    "sco_on": ["True", "False"],
                    "sco_se": ["True", "False"],
                },
            ),
        )
        assert ix.details["values"] == ["ON(S)", "OFF"]


class TestValueFieldAbsent:
    """Each extractor must early-return (no 'values' key) when its specific
    value field is absent from the ASDU."""

    def _no_value(self, type_id: str):
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={"typeid": type_id, "addr": "1", "ioa": "1"},
            ),
        )
        return ix

    def test_spi_absent(self):
        assert "values" not in self._no_value("1").details  # spi

    def test_dpi_absent(self):
        assert "values" not in self._no_value("3").details  # dpi

    def test_bcr_absent(self):
        assert "values" not in self._no_value("15").details  # bcr

    def test_sco_absent(self):
        assert "values" not in self._no_value("45").details  # sco

    def test_dco_absent(self):
        assert "values" not in self._no_value("46").details  # dco

    def test_rco_absent(self):
        assert "values" not in self._no_value("47").details  # rco

    def test_coi_absent(self):
        assert "values" not in self._no_value("70").details  # coi

    def test_qoi_absent(self):
        assert "values" not in self._no_value("100").details  # qoi

    def test_coi_non_integer_reason(self):
        """A non-integer COI reason falls back to its raw string."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": "70", "addr": "1", "ioa": "0", "coi_r": _scalar("zz")},
            ),
        )
        assert ix.details["values"] == ["COI=zz"]


class TestProcessPacketGuards:
    def test_packet_without_ip_is_ignored(self):
        """No src/dst IP -> process_packet returns without recording."""
        listener = _make_listener()
        listener.get_ip_info = lambda packet: ("", "")
        listener.process_packet(_Packet({"linkaddr": "1", "ctrl_prm": "1"}))
        assert listener.interactions == []

    def test_packet_without_iec101_layer_is_ignored(self):
        """A packet lacking the iec60870_101 layer is skipped."""
        listener = _make_listener()

        class _Empty:
            pass

        listener.process_packet(_Empty())
        assert listener.interactions == []

    def test_link_frame_with_other_header_byte(self):
        """A link frame whose header is neither 0xE5 nor 0x10 still records a
        'Link: <func>' operation (the generic else branch)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {
                    "linkaddr": "1",
                    "ctrl_prm": "1",
                    "ctrl_func_pri_to_sec": "9",
                    "header": "0x68",  # variable-frame start, neither E5 nor 10
                }
            ),
        )
        assert ix.operation == "Link: Request Status of Link"

    def test_dpi_scalar_non_integer_value(self):
        """A non-integer diq.dpi scalar falls through to the raw string."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": "3", "addr": "1", "ioa": "1", "diq_dpi": _scalar("bogus")},
            ),
        )
        assert ix.details["values"] == ["bogus"]

    def test_vti_non_transient_value(self):
        """A step-position value with the transient bit clear is rendered
        plainly (no (T) suffix)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={
                    "typeid": "5",
                    "addr": "1",
                    "ioa": "1",
                    "vti_v": "8",
                    "vti_t": "False",
                },
            ),
        )
        assert ix.details["values"] == ["8"]

    def test_dco_scalar_non_int_with_select(self):
        """Non-int dco.on scalar with dco.se=True appends the (S) select bit."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={
                    "typeid": "46",
                    "addr": "1",
                    "ioa": "1",
                    "dco_on": _scalar("x"),
                    "dco_se": _scalar("True"),
                },
            ),
        )
        assert ix.details["values"] == ["x(S)"]

    def test_rco_scalar_non_int_with_select(self):
        """Non-int rco.up scalar with rco.se=True appends the (S) select bit."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "1"},
                asdu_fields={
                    "typeid": "47",
                    "addr": "1",
                    "ioa": "1",
                    "rco_up": _scalar("y"),
                    "rco_se": _scalar("True"),
                },
            ),
        )
        assert ix.details["values"] == ["y(S)"]


class TestColumnFormatterDetails:
    def test_columns_single_element_ioa_list(self):
        """A single-element IOA list renders as the bare number in the IOA
        column (not a range)."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={"typeid": "13", "addr": "1", "ioa": ["77"], "float": ["1.0"]},
            ),
        )
        cols = listener._format_protocol_columns(ix)
        assert cols[6] == "77"

    def test_columns_cot_recomputed_from_raw(self):
        """When cot_name is stripped from details, the column formatter
        recomputes it from the raw cause_of_transmission code."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                {"linkaddr": "1", "ctrl_prm": "0"},
                asdu_fields={
                    "typeid": "1",
                    "addr": "1",
                    "ioa": "1",
                    "causetx": "6",
                    "siq_spi": "1",
                },
            ),
        )
        # Force the recompute branch by clearing the cached COT name.
        ix.details["cot_name"] = ""
        cols = listener._format_protocol_columns(ix)
        assert cols[4] == "activation"
