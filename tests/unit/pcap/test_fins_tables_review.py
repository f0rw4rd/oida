"""Regression tests for FINS command/memory-area registry corrections.

Bugs fixed (see task report):
  1. FINS_COMMANDS did not match Omron's real command_code_cv[] registry
     (verified via `tshark -G values | grep omron.command`).
  2. FINS_MEMORY_AREAS did not match memory_area_code_cv[]
     (verified via `tshark -G values | grep omron.memory.area.read`).
  3. _FINS_FATAL_ERROR_FIELDS was missing cycle_time_over/io_point_overflow,
     and num_items was parsed with a bare int() that chokes on "0x..." values.
"""

from oida.pcap.fins import (
    _FINS_ERROR_LOG_COMMANDS,
    _FINS_FATAL_ERROR_FIELDS,
    FINS_COMMANDS,
    FINS_MEMORY_AREAS,
    FINS_WRITE_COMMANDS,
    FINSPassiveListener,
)


class _Layer:
    def __init__(self, **fields):
        for key, value in fields.items():
            setattr(self, key, value)


class _Packet:
    def __init__(self, omron_layer, sport=54321, dport=9600):
        self.omron = omron_layer
        self.ip = _Layer(src="10.0.0.10", dst="10.0.0.20")
        self.tcp = _Layer(srcport=str(sport), dstport=str(dport), stream="0")
        self.eth = _Layer(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        self.transport_layer = "TCP"
        self.highest_layer = "OMRON"

    def __contains__(self, item):
        return hasattr(self, str(item).lower())


def _make_listener():
    return FINSPassiveListener(interface="lo", timeout=1)


# --- Bug 1: FINS_COMMANDS registry -----------------------------------------------


def test_fins_commands_corrected_against_registry():
    # Spot checks taken from `tshark -G values | grep omron.command`.
    expected = {
        0x0620: "Cycle Time Read",
        0x0701: "Clock Read",
        0x0702: "Clock Write",
        0x0801: "LOOP-BACK Test",
        0x0802: "Broadcast Test Results Read",
        0x0920: "Message Read/Clear/FAL(S) Read",
        0x2101: "Error Clear",
        0x2102: "Error Log Read",
        0x2103: "Error Log Clear",
        0x0C01: "Access Right Acquire",
        0x0C02: "Access Right Forced Acquire",
        0x0C03: "Access Right Release",
    }
    for code, name in expected.items():
        assert FINS_COMMANDS[code] == name, f"0x{code:04x} -> {FINS_COMMANDS.get(code)!r}"

    # These codes are not in the real registry and must not be invented.
    for bogus in (0x0301, 0x0302, 0x0303, 0x0921, 0x0922):
        assert bogus not in FINS_COMMANDS, f"0x{bogus:04x} is not a registered FINS command"

    # 57 rows in the authoritative dump (/tmp/fins_cmd.txt).
    assert len(FINS_COMMANDS) == 57


# --- Bug 2: FINS_MEMORY_AREAS registry -------------------------------------------


def test_fins_memory_areas_corrected_against_registry():
    # Spot checks taken from `tshark -G values | grep omron.memory.area.read`.
    expected = {
        0x00: "CIO bit",
        0x80: "CIO word",
        0x01: "Timer/Counter completion flag",
        0x81: "Timer/Counter PV",
        0x82: "DM word",
        0x03: "Transition flag",
        0x02: "CS1 DM bit",
        0x09: "CS1 Timer/Counter completion flag",
        0x20: "CS1 Expansion DM bit (bank E0)",
        0xA0: "CS1 Expansion DM word (bank E0)",
    }
    for code, name in expected.items():
        assert FINS_MEMORY_AREAS[code] == name, f"0x{code:02x} -> {FINS_MEMORY_AREAS.get(code)!r}"

    # 76 rows in the authoritative dump (/tmp/fmem.txt).
    assert len(FINS_MEMORY_AREAS) == 76


def test_fins_write_commands_use_corrected_codes():
    # Error Log Clear (0x2103) is a real write op now that codes are correct.
    assert 0x2103 in FINS_WRITE_COMMANDS
    # The old (wrong) "Error Clear"/"Error Log Clear" codes must be gone.
    assert 0x0920 not in FINS_WRITE_COMMANDS
    assert 0x0922 not in FINS_WRITE_COMMANDS
    # 0x0302/0x0303 never existed in the registry.
    assert 0x0302 not in FINS_WRITE_COMMANDS
    assert 0x0303 not in FINS_WRITE_COMMANDS
    # Run/Stop still correctly flagged as write/control ops.
    assert 0x0401 in FINS_WRITE_COMMANDS
    assert 0x0402 in FINS_WRITE_COMMANDS


# --- Bug 1b: error-log dispatch --------------------------------------------------


def test_error_log_command_reaches_process_error_log(monkeypatch):
    """0x2102 (Error Log Read) is a real error-log op and must dispatch there."""
    listener = _make_listener()
    calls = []
    monkeypatch.setattr(listener, "_process_error_log", lambda omron, details: calls.append(omron))

    omron = _Layer(command="0x2102", icf_dtb="0x00")
    listener.process_packet(_Packet(omron))

    assert len(calls) == 1


def test_message_read_command_no_longer_reaches_process_error_log(monkeypatch):
    """0x0920 (Message Read/Clear/FAL(S) Read) must NOT be treated as error-log traffic."""
    listener = _make_listener()
    calls = []
    monkeypatch.setattr(listener, "_process_error_log", lambda omron, details: calls.append(omron))

    omron = _Layer(command="0x0920", icf_dtb="0x00")
    listener.process_packet(_Packet(omron))

    assert calls == []


def test_error_log_commands_set_is_exactly_read_and_clear():
    assert _FINS_ERROR_LOG_COMMANDS == frozenset({0x2102, 0x2103})


# --- Bug 3a: missing fatal-error fields -------------------------------------------


def test_fatal_error_fields_include_cycle_time_and_io_point_overflow():
    assert "fatal_cycle_time_over" in _FINS_FATAL_ERROR_FIELDS
    assert "fatal_io_point_overflow" in _FINS_FATAL_ERROR_FIELDS

    listener = _make_listener()
    omron = _Layer(fatal_cycle_time_over="0x01", fatal_io_point_overflow="1")
    active = listener._collect_active_flags(omron, _FINS_FATAL_ERROR_FIELDS)

    assert "Cycle Time Over" in active
    assert "I/O Point Overflow" in active


# --- Bug 3b: unsafe int() parse of num_items --------------------------------------


def test_num_items_parses_hex_prefixed_value():
    listener = _make_listener()
    omron = _Layer(memory_numitems="0x0a")
    details = {}

    listener._process_memory_op(omron, 0x0101, "Memory Area Read", details, is_response=True)

    assert details["num_items"] == 10
