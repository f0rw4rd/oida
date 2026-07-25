"""Unit tests for the CIP Safety passive listener / frame parser.

These tests drive ``CIPSafetyPassiveListener.process_packet`` with hand-built
fake PyShark layers (no tshark / pyshark required). The CIP Safety dissector
splits across three layers -- ``cipsafety`` (base I/O), ``cipssupervisor``
(configuration object) and ``cipsvalidator`` (connection state) -- so a fake
packet exposes whichever of those three attributes a test needs.

``get_field`` reads each field via ``getattr(layer, "<underscore_name>")``, so
the fake layer simply carries the underscored field names as string attributes
(e.g. ``mode_byte_run_idle``). Absent attributes raise AttributeError and the
parser sees the field as missing.

Everything asserted is derived from the mock frames built per-test: recorded
interactions, session counters, the listener's ``_alerts`` list, discovered
devices and the public summary are all checked against the known input.
"""

from typing import Any, Dict

from oida.pcap.cipsafety import (
    SUPERVISOR_SERVICES,
    VALIDATOR_STATES,
    CIPSafetyPassiveListener,
)


# ---------------------------------------------------------------------------
# Fake PyShark layer scaffolding
# ---------------------------------------------------------------------------


class _Layer:
    """Minimal PyShark layer exposing fields as string attributes."""

    def __init__(self, fields: Dict[str, Any]):
        for name, val in fields.items():
            setattr(self, name, str(val))


class _Packet:
    """Fake packet carrying any subset of the three CIP Safety layers."""

    def __init__(
        self,
        cipsafety: Dict[str, Any] = None,
        cipssupervisor: Dict[str, Any] = None,
        cipsvalidator: Dict[str, Any] = None,
    ):
        if cipsafety is not None:
            self.cipsafety = _Layer(cipsafety)
        if cipssupervisor is not None:
            self.cipssupervisor = _Layer(cipssupervisor)
        if cipsvalidator is not None:
            self.cipsvalidator = _Layer(cipsvalidator)


SRC_IP = "10.0.0.1"  # producer / originator
DST_IP = "10.0.0.2"  # consumer / target


def _make_listener() -> CIPSafetyPassiveListener:
    listener = CIPSafetyPassiveListener("test0")
    listener.get_ip_info = lambda packet: (SRC_IP, DST_IP)
    listener.get_port_info = lambda packet: (2222, 2222)
    listener.get_flow_id = lambda packet: "flow-1"
    listener.get_stream_id = lambda packet: "stream-1"
    return listener


def _feed(listener: CIPSafetyPassiveListener, packet: _Packet):
    listener.process_packet(packet)
    return listener.interactions[-1]


# ---------------------------------------------------------------------------
# Safety base I/O frames (cipsafety layer)
# ---------------------------------------------------------------------------


class TestSafetyDataFrames:
    def test_run_state_frame(self):
        """A RUN mode safety frame records run_idle=RUN, increments the
        session frame counter, and produces a 'Safety I/O RUN' summary."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                cipsafety={
                    "mode_byte": "1",
                    "mode_byte_run_idle": "True",
                    "mode_byte_ping_count": "3",
                    "timestamp": "4096",
                }
            ),
        )
        assert ix.operation == "Safety I/O"
        assert ix.direction == "request"
        d = ix.details
        assert d["frame_type"] == "safety_data"
        assert d["run_idle"] == "RUN"
        assert d["ping_count"] == "3"
        assert d["safety_timestamp"] == "4096"
        assert ix.summary == "Safety I/O RUN"
        assert "crc_status" not in d  # CRC fields absent -> no failure

        session = listener.sessions[(SRC_IP, DST_IP)]
        assert session.safety_frames == 1
        assert session.crc_errors == 0

    def test_idle_state_frame(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(cipsafety={"mode_byte_run_idle": "False", "mode_byte": "0"}),
        )
        assert ix.details["run_idle"] == "IDLE"
        assert ix.summary == "Safety I/O IDLE"

    def test_crc_failure_raises_alert(self):
        """A non-zero CRC status marks the frame FAIL, increments crc_errors
        and pushes a cipsafety_crc_error alert."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                cipsafety={
                    "mode_byte_run_idle": "True",
                    "crc_s1_status": "0",
                    "crc_s3_status": "2",  # non-zero -> FAIL
                }
            ),
        )
        assert ix.details["crc_status"] == "FAIL"
        assert "CRC_S3=FAIL" in ix.details["crc_detail"]
        assert "[FAIL]" in ix.summary

        session = listener.sessions[(SRC_IP, DST_IP)]
        assert session.crc_errors == 1
        assert any(a["category"] == "cipsafety_crc_error" for a in listener._alerts)
        alert = next(a for a in listener._alerts if a["category"] == "cipsafety_crc_error")
        assert "CRC FAIL" in alert["message"]
        assert SRC_IP in alert["message"]

    def test_multiple_crc_failures_listed(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                cipsafety={
                    "crc_s1_status": "1",
                    "crc_s2_status": "3",
                    "complement_crc_s3_status": "5",
                }
            ),
        )
        detail = ix.details["crc_detail"]
        assert "CRC_S1=FAIL" in detail
        assert "CRC_S2=FAIL" in detail
        assert "CRC_cS3=FAIL" in detail

    def test_multicast_and_ack_fields(self):
        """Multicast and ack byte fields are surfaced in details."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                cipsafety={
                    "mcast_byte": "128",
                    "mcast_byte_consumer_num": "2",
                    "mcast_byte_active_idle": "True",
                    "time_correction": "500",
                    "ack_byte": "64",
                    "ack_byte_ping_response": "True",
                    "consumer_time_value": "1000",
                    "message_encoding": "777",
                }
            ),
        )
        d = ix.details
        assert d["mcast_byte"] == "128"
        assert d["consumer_num"] == "2"
        assert d["mcast_active_idle"] == "True"
        assert d["time_correction"] == "500"
        assert d["ack_byte"] == "64"
        assert d["ping_response"] == "True"
        assert d["consumer_time_value"] == "1000"
        assert d["message_encoding"] == "777"

    def test_safety_frame_creates_device(self):
        listener = _make_listener()
        _feed(listener, _Packet(cipsafety={"mode_byte_run_idle": "True"}))
        dev = listener.discovered_devices[f"cipsafety:{SRC_IP}"]
        assert dev.device_type == "CIP Safety Device"
        assert SRC_IP in dev.ip_addresses
        assert dev.cipsafety_passive_data["protocol"] == "CIP Safety/EtherNet/IP"


# ---------------------------------------------------------------------------
# Supervisor service frames (cipssupervisor layer)
# ---------------------------------------------------------------------------


class TestSupervisorServices:
    def test_configure_request_is_security_event(self):
        """Service 0x4F (Configure_Request) is security-relevant: it surfaces
        the TUNID + has_password flag, increments security_events and pushes
        a cipsafety_security_event alert, and the summary is tagged."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                cipssupervisor={
                    "sc": "0x4f",
                    "configure_request_tunid": "01:02:03:04",
                    "configure_request_password": "73:65:63:72:65:74",
                }
            ),
        )
        d = ix.details
        assert d["frame_type"] == "supervisor"
        assert d["service_code"] == 0x4F
        assert d["service_name"] == SUPERVISOR_SERVICES[0x4F]
        assert d["security_event"] is True
        assert d["tunid"] == "01:02:03:04"
        assert d["has_password"] is True
        assert ix.summary.startswith("[SECURITY] Supervisor")
        assert ix.direction == "request"

        session = listener.sessions[(SRC_IP, DST_IP)]
        assert "Configure_Request" in session.supervisor_services
        assert session.security_events == 1
        assert any(a["category"] == "cipsafety_security_event" for a in listener._alerts)

    def test_set_password_counts_as_password_op(self):
        listener = _make_listener()
        _feed(listener, _Packet(cipssupervisor={"sc": "0x51"}))
        session = listener.sessions[(SRC_IP, DST_IP)]
        assert session.password_operations == 1
        assert session.security_events == 1

    def test_reset_password_counts_as_password_op(self):
        listener = _make_listener()
        _feed(listener, _Packet(cipssupervisor={"sc": "0x55"}))
        session = listener.sessions[(SRC_IP, DST_IP)]
        assert session.password_operations == 1

    def test_mode_change_counted(self):
        """Service 0x53 (Mode_Change) bumps mode_changes and surfaces the
        mode value."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(cipssupervisor={"sc": "0x53", "mode_change_value": "4"}),
        )
        assert ix.details["mode_value"] == "4"
        session = listener.sessions[(SRC_IP, DST_IP)]
        assert session.mode_changes == 1

    def test_safety_reset_counted_with_reset_type(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(cipssupervisor={"sc": "0x54", "reset_type": "1"}),
        )
        assert ix.details["reset_type"] == "1"
        session = listener.sessions[(SRC_IP, DST_IP)]
        assert session.resets == 1

    def test_configuration_lock_value(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(cipssupervisor={"sc": "0x52", "configure_lock_lock": "1"}),
        )
        assert ix.details["lock_value"] == "1"
        assert ix.details["security_event"] is True

    def test_response_bit_flips_direction_and_session_orientation(self):
        """A service code with the 0x80 response bit set is a response; the
        session is then keyed (dst, src) rather than (src, dst), and the
        masked-out service code resolves the base service name."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(cipssupervisor={"sc": "0xce"}),  # 0x4E | 0x80
        )
        assert ix.direction == "response"
        assert ix.details["service_code"] == 0x4E
        assert ix.details["service_name"] == SUPERVISOR_SERVICES[0x4E]
        # response -> session keyed (dst, src)
        assert (DST_IP, SRC_IP) in listener.sessions
        # A response must NOT count as a security event even for a sec service.
        session = listener.sessions[(DST_IP, SRC_IP)]
        assert session.security_events == 0

    def test_non_security_service_no_alert(self):
        """A benign service (Get_Attributes_All, 0x01) records but raises no
        security alert and does not bump security_events."""
        listener = _make_listener()
        ix = _feed(listener, _Packet(cipssupervisor={"sc": "0x01"}))
        assert ix.details["security_event"] is False
        assert not any(a["category"] == "cipsafety_security_event" for a in listener._alerts)
        session = listener.sessions[(SRC_IP, DST_IP)]
        assert session.security_events == 0

    def test_unknown_service_code_generic_name(self):
        listener = _make_listener()
        ix = _feed(listener, _Packet(cipssupervisor={"sc": "0x2a"}))
        assert ix.details["service_name"] == "Supervisor Svc 0x2a"

    def test_device_info_fields_in_supervisor(self):
        """Manufacturer/model/serial/revision/status fields ride along in a
        supervisor frame and the device status is name-resolved."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                cipssupervisor={
                    "sc": "0x0e",
                    "manufacture_name": "Rockwell",
                    "manufacture_model_number": "1791ES",
                    "manufacture_serial_number": "SN12345",
                    "sw_rev_level": "2.1",
                    "hw_rev_level": "A",
                    "device_status": "4",  # Running
                    "configuration_lock": "1",
                }
            ),
        )
        d = ix.details
        assert d["manufacturer_name"] == "Rockwell"
        assert d["model_number"] == "1791ES"
        assert d["serial_number"] == "SN12345"
        assert d["sw_revision"] == "2.1"
        assert d["hw_revision"] == "A"
        assert d["device_status"] == "Running"
        assert d["configuration_lock"] == "1"

        # Device name should be derived from manufacturer/model.
        dev = listener.discovered_devices[f"cipsafety:{SRC_IP}"]
        assert dev.name == "Rockwell 1791ES"


class TestSupervisorAttributesOnly:
    def test_attributes_without_service_code(self):
        """A supervisor frame with no 'sc' field but device attributes is
        treated as a Get response carrying device identity."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                cipssupervisor={
                    "manufacture_name": "Pilz",
                    "manufacture_model_number": "PNOZ",
                    "manufacture_serial_number": "S-9",
                    "device_status": "2",  # Idle
                }
            ),
        )
        d = ix.details
        assert d["frame_type"] == "supervisor_attr"
        assert d["manufacturer_name"] == "Pilz"
        assert d["model_number"] == "PNOZ"
        assert d["device_status"] == "Idle"
        assert ix.direction == "response"
        assert "Pilz" in ix.summary
        assert "status=Idle" in ix.summary

    def test_attributes_empty_records_nothing(self):
        """A supervisor frame with neither service code nor any attribute
        is dropped: no interaction recorded."""
        listener = _make_listener()
        before = len(listener.interactions)
        listener.process_packet(_Packet(cipssupervisor={"some_irrelevant": "1"}))
        assert len(listener.interactions) == before


# ---------------------------------------------------------------------------
# Validator frames (cipsvalidator layer)
# ---------------------------------------------------------------------------


class TestValidatorFrames:
    def test_established_state(self):
        """An Established validator (state 2) records its state, type and
        producer/consumer flag without raising a fault alert."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                cipsvalidator={
                    "sc": "0x0e",
                    "state": "2",
                    "type": "16",
                    "type_pc": "True",
                    "type_conn_type": "1",
                    "ping_epi": "100",
                    "data_conn_inst": "3",
                    "max_consumer_num": "1",
                    "max_data_age": "200",
                }
            ),
        )
        d = ix.details
        assert d["frame_type"] == "validator"
        assert d["validator_state"] == VALIDATOR_STATES[2]
        assert d["validator_type"] == "16"
        assert d["producer_consumer"] == "Producer"
        assert d["conn_type"] == "1"
        assert d["ping_epi"] == "100"
        assert d["data_conn_inst"] == "3"
        assert d["max_consumer_num"] == "1"
        assert d["max_data_age"] == "200"
        assert ix.operation == "Validator Established"
        assert not any(a["category"] == "cipsafety_validator_fault" for a in listener._alerts)

        session = listener.sessions[(SRC_IP, DST_IP)]
        assert "Established" in session.validator_states

    def test_consumer_flag(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(cipsvalidator={"state": "1", "type_pc": "False"}),
        )
        assert ix.details["producer_consumer"] == "Consumer"

    def test_faulted_state_raises_alert(self):
        """State 4 (Faulted) raises a validator-fault alert."""
        listener = _make_listener()
        ix = _feed(listener, _Packet(cipsvalidator={"state": "4"}))
        assert ix.details["validator_state"] == "Faulted"
        faults = [a for a in listener._alerts if a["category"] == "cipsafety_validator_fault"]
        assert len(faults) == 1
        assert "state=Faulted" in faults[0]["message"]

    def test_connection_failed_state_raises_alert(self):
        listener = _make_listener()
        _feed(listener, _Packet(cipsvalidator={"state": "3"}))
        assert any(a["category"] == "cipsafety_validator_fault" for a in listener._alerts)

    def test_high_fault_count_raises_alert(self):
        """A fault_count > 10 raises a high-fault-count alert and the summary
        annotates the fault total."""
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(cipsvalidator={"state": "2", "sconn_fault_count": "15"}),
        )
        assert ix.details["fault_count"] == "15"
        assert "faults=15" in ix.summary
        high = [a for a in listener._alerts if a["category"] == "cipsafety_high_fault_count"]
        assert len(high) == 1
        assert "fault_count=15" in high[0]["message"]

    def test_low_fault_count_no_alert(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(cipsvalidator={"state": "2", "sconn_fault_count": "3"}),
        )
        assert "faults=3" in ix.summary
        assert not any(a["category"] == "cipsafety_high_fault_count" for a in listener._alerts)

    def test_error_code_field(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(cipsvalidator={"state": "4", "error_code": "513"}),
        )
        assert ix.details["error_code"] == "513"

    def test_unknown_state_value(self):
        """A state outside VALIDATOR_STATES renders Unknown(N)."""
        listener = _make_listener()
        ix = _feed(listener, _Packet(cipsvalidator={"state": "9"}))
        assert ix.details["validator_state"] == "Unknown(9)"

    def test_validator_response_session_orientation(self):
        """The response bit (0x80 on sc) keys the session (dst, src)."""
        listener = _make_listener()
        _feed(listener, _Packet(cipsvalidator={"sc": "0x8e", "state": "2"}))
        assert (DST_IP, SRC_IP) in listener.sessions


# ---------------------------------------------------------------------------
# Multi-layer packets & column formatting
# ---------------------------------------------------------------------------


class TestMultiLayerAndFormatting:
    def test_packet_with_all_three_layers(self):
        """A single packet carrying base + supervisor + validator layers
        produces three interactions in order."""
        listener = _make_listener()
        listener.process_packet(
            _Packet(
                cipsafety={"mode_byte_run_idle": "True"},
                cipssupervisor={"sc": "0x01"},
                cipsvalidator={"state": "2"},
            )
        )
        types = [ix.details.get("frame_type") for ix in listener.interactions]
        assert types == ["safety_data", "supervisor", "validator"]

    def test_format_columns_safety_data(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                cipsafety={
                    "mode_byte_run_idle": "True",
                    "crc_s1_status": "1",  # FAIL
                }
            ),
        )
        cols = listener._format_protocol_columns(ix)
        # operation, run_idle, crc_status, detail
        assert cols[0] == "Safety I/O"
        assert cols[1] == "RUN"
        assert cols[2] == "FAIL"
        assert "CRC_S1=FAIL" in cols[3]

    def test_format_columns_supervisor(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(
                cipssupervisor={
                    "sc": "0x4f",
                    "manufacture_name": "ABB",
                    "device_status": "4",
                }
            ),
        )
        cols = listener._format_protocol_columns(ix)
        assert cols[0] == SUPERVISOR_SERVICES[0x4F]
        assert "status=Running" in cols[3]
        assert "ABB" in cols[3]
        assert "[SECURITY]" in cols[3]

    def test_format_columns_validator(self):
        listener = _make_listener()
        ix = _feed(
            listener,
            _Packet(cipsvalidator={"state": "4", "sconn_fault_count": "7"}),
        )
        cols = listener._format_protocol_columns(ix)
        assert cols[0] == "Validator"
        assert "state=Faulted" in cols[3]
        assert "faults=7" in cols[3]


# ---------------------------------------------------------------------------
# harvest() + public summary
# ---------------------------------------------------------------------------


class TestHarvestAndSummary:
    def test_harvest_includes_alerts(self):
        """harvest() merges the protocol-specific alert list into its output."""
        listener = _make_listener()
        _feed(listener, _Packet(cipsvalidator={"state": "4"}))
        harvest = listener.harvest()
        alerts = harvest.get("alerts", [])
        assert any(a["category"] == "cipsafety_validator_fault" for a in alerts)

    def test_harvest_empty_when_nothing_seen(self):
        listener = _make_listener()
        assert listener.harvest() == {}

    def test_get_sessions_summary(self):
        listener = _make_listener()
        # One safety frame, one security supervisor op, one validator state.
        _feed(listener, _Packet(cipsafety={"mode_byte_run_idle": "True"}))
        _feed(listener, _Packet(cipssupervisor={"sc": "0x51"}))  # Set_Password
        _feed(listener, _Packet(cipsvalidator={"state": "2"}))

        summary = listener.get_sessions_summary()
        # supervisor + validator + safety all key (SRC, DST) here (all requests)
        s = next(x for x in summary if x["client"] == SRC_IP)
        assert s["server"] == DST_IP
        assert s["safety_frames"] == 1
        assert "Set_Password" in s["supervisor_services"]
        assert "Established" in s["validator_states"]
        assert s["password_operations"] == 1
        assert s["security_events"] == 1


# ---------------------------------------------------------------------------
# process_packet guards
# ---------------------------------------------------------------------------


class TestProcessPacketGuards:
    def test_packet_without_ip_is_ignored(self):
        listener = _make_listener()
        listener.get_ip_info = lambda packet: ("", "")
        listener.process_packet(_Packet(cipsafety={"mode_byte_run_idle": "True"}))
        assert listener.interactions == []

    def test_packet_with_no_cip_layers_is_ignored(self):
        listener = _make_listener()

        class _Empty:
            pass

        listener.process_packet(_Empty())
        assert listener.interactions == []

    def test_invalid_ip_is_skipped_for_device_creation(self):
        """An endpoint that is not a valid discoverable IP (the unspecified
        0.0.0.0 address) is skipped by _update_devices: only the valid peer
        becomes a device."""
        listener = _make_listener()
        listener.get_ip_info = lambda packet: (SRC_IP, "0.0.0.0")
        _feed(listener, _Packet(cipsafety={"mode_byte_run_idle": "True"}))
        assert f"cipsafety:{SRC_IP}" in listener.discovered_devices
        assert "cipsafety:0.0.0.0" not in listener.discovered_devices


class TestColumnFormattingFallback:
    def test_format_columns_unknown_frame_type(self):
        """The _format_protocol_columns else-branch handles an interaction
        whose details carry no recognized frame_type: it echoes the operation
        and blanks the rest."""
        listener = _make_listener()
        ix = _feed(listener, _Packet(cipsafety={"mode_byte_run_idle": "True"}))
        # Strip the frame_type so the formatter hits its final else branch.
        ix.details.pop("frame_type", None)
        cols = listener._format_protocol_columns(ix)
        assert cols == [ix.operation, "", "", ""]
