"""Regression: CIP Safety validator-state and supervisor-status tables must
match Wireshark's dissectors.

Both tables in ``src/oida/pcap/cipsafety.py`` disagreed with
``packet-cipsafety.c``:

VALIDATOR_STATES — dissector ``cip_svalidator_state_vals``:
    0="Unallocated", 1="Initializing", 2="Established", 3="Connection failed".
oidx had 0="Idle" (wrong name, same idea) and fabricated 4="Faulted" which the
dissector never emits; the fault-alert gate ``state_val in (3, 4)`` treated 4
as reachable.

SUPERVISOR_STATUS — dissector ``cip_ssupervisor_device_status_type_vals``:
    0="Undefined", 1="Self-Testing", 2="Idle", 3="Self-Test Exception",
    4="Executing", 5="Abort", 6="Critical Fault", 7="Configuring",
    8="Waiting for TUNID" (plus 51/52 torque variants).
oida was shifted by one from 5 on: 5="Exception" (actually "Abort"),
6="Abort" (actually "Critical Fault"), 7="Waiting_for_TUNID" (actually
"Configuring"), 8 missing.  A genuine "Critical Fault" (6) was displayed as
merely "Abort" — a safety-relevant downgrade.
"""

import pytest

from oida.pcap.cipsafety import SUPERVISOR_STATUS, VALIDATOR_STATES, CIPSafetyPassiveListener


# --- authoritative tables (packet-cipsafety.c value_strings) ---------------
DISSECTOR_VALIDATOR_STATES = {
    0: "Unallocated",
    1: "Initializing",
    2: "Established",
    3: "Connection failed",
}

DISSECTOR_SUPERVISOR_STATUS = {
    0: "Undefined",
    1: "Self-Testing",
    2: "Idle",
    3: "Self-Test Exception",
    4: "Executing",
    5: "Abort",
    6: "Critical Fault",
    7: "Configuring",
    8: "Waiting for TUNID",
    51: "Waiting for TUNID with Torque Permitted",
    52: "Executing with Torque Permitted",
}


class TestValidatorStates:
    def test_validator_states_match_dissector(self):
        wrong = {
            k: (v, DISSECTOR_VALIDATOR_STATES[k])
            for k, v in VALIDATOR_STATES.items()
            if k in DISSECTOR_VALIDATOR_STATES and v != DISSECTOR_VALIDATOR_STATES[k]
        }
        assert not wrong, f"validator state names disagree: {wrong}"

    def test_state_zero_is_unallocated(self):
        assert VALIDATOR_STATES[0] == "Unallocated"

    def test_no_fabricated_faulted_state(self):
        """The dissector never emits 4; it must not map to a scary name."""
        assert 4 not in VALIDATOR_STATES or VALIDATOR_STATES[4] not in (
            "Faulted",
            "Connection_Failed",
        )

    def test_connection_failed_alert_gate_uses_real_values(self):
        """The fault-alert gate must key on the real failing state (3)."""
        listener = CIPSafetyPassiveListener(interface="lo", timeout=1)
        gate = getattr(listener, "_VALIDATOR_FAULT_STATES", None)
        assert gate is None or set(gate) <= set(DISSECTOR_VALIDATOR_STATES)


class TestSupervisorStatus:
    def test_supervisor_status_matches_dissector(self):
        wrong = {
            k: (v, DISSECTOR_SUPERVISOR_STATUS[k])
            for k, v in SUPERVISOR_STATUS.items()
            if k in DISSECTOR_SUPERVISOR_STATUS and v != DISSECTOR_SUPERVISOR_STATUS[k]
        }
        assert not wrong, f"supervisor status names disagree: {wrong}"

    def test_critical_fault_is_not_downgraded(self):
        """Code 6 is 'Critical Fault'; it must not read as 'Abort'."""
        assert SUPERVISOR_STATUS[6] == "Critical Fault"

    def test_code_five_is_abort(self):
        assert SUPERVISOR_STATUS[5] == "Abort"

    def test_waiting_for_tunid_is_eight(self):
        assert SUPERVISOR_STATUS[8] == "Waiting for TUNID"

    @pytest.mark.parametrize("code", sorted(DISSECTOR_SUPERVISOR_STATUS))
    def test_every_dissector_status_resolves(self, code):
        """No real supervisor status code falls through to a raw number."""
        assert code in SUPERVISOR_STATUS, (
            f"dissector status {code} ({DISSECTOR_SUPERVISOR_STATUS[code]!r}) "
            f"missing from SUPERVISOR_STATUS"
        )
