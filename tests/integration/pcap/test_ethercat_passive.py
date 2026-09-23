"""Integration tests for EtherCAT passive listener in EK mode."""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

# Shared helper -- run listener against the CISA pcap (largest fixture).
_CISA_PCAP = "ethercat/cisagov_ethercat_example.pcap"
_BOOTUP_PCAP = "ethercat/wireshark_ethercat_bootup.cap"


def _run_ethercat(pcap_subpath: str = _CISA_PCAP, **kwargs):
    """Run the EtherCAT listener with sensible defaults."""
    return _run_listener_test(
        "ethercat",
        "EtherCATPassiveListener",
        "ecat",
        pcap_subpath,
        **kwargs,
    )


class TestEtherCATPassiveEK:
    """EtherCAT-specific tests beyond the parametrized quality suite."""

    def test_ethercat_masters_and_commands(self):
        listener, devices, result = _run_ethercat()
        # EtherCAT should identify at least one master
        assert len(listener.masters) >= 1, (
            f"Expected >= 1 EtherCAT master, got {len(listener.masters)}"
        )

        # Check that masters tracked commands
        for master in listener.masters.values():
            assert master.total_frames >= 1, "Master should have processed frames"
            assert master.total_datagrams >= 1, "Master should have processed datagrams"

        # Check that ethercat_passive_data is populated
        has_passive_data = any(
            hasattr(d, "ethercat_passive_data") and d.ethercat_passive_data
            for d in devices.values()
        )
        assert has_passive_data, "No device has ethercat_passive_data"

        # Harvest returns a dict (tables are now built centrally by scanner)
        assert isinstance(result, dict)

    # ------------------------------------------------------------------
    # T1 register field extraction tests
    # ------------------------------------------------------------------

    def test_esc_device_identity_registers(self):
        """Verify reg_type, reg_revision, reg_build are extracted."""
        listener, devices, _ = _run_ethercat(
            expect_details=["al_status_state"],
        )
        # At least one master should have ESC identity populated
        found_identity = False
        for master in listener.masters.values():
            if master.esc_revision is not None:
                found_identity = True
                assert master.esc_type is not None, "esc_type should be set when revision is"
                assert master.esc_build is not None, "esc_build should be set when revision is"
        assert found_identity, (
            "No master has ESC identity registers (reg_type/revision/build). "
            "Check that the pcap contains ESC register read responses."
        )

        # Verify device protocol_data includes ESC identity
        for device in devices.values():
            data = getattr(device, "ethercat_passive_data", None)
            if data and data.get("esc_revision") is not None:
                assert "esc_type" in data
                assert "esc_build" in data
                break
        else:
            pytest.fail("No device ethercat_passive_data has esc_revision")

    def test_al_status_state_extraction(self):
        """Verify AL Status state machine values are captured."""
        listener, devices, _ = _run_ethercat()
        # The CISA pcap contains bootup sequences with AL Status reads
        found_al = False
        for master in listener.masters.values():
            if master.al_status_states_seen:
                found_al = True
                # Should see Init (1) or Pre-Op (2) states during bootup
                assert any(s in master.al_status_states_seen for s in (1, 2, 4, 8)), (
                    f"Expected common AL states (Init/PreOp/SafeOp/Op), "
                    f"got {master.al_status_states_seen}"
                )
        assert found_al, "No master captured AL Status states"

        # Verify AL Status interaction details
        al_interactions = [ix for ix in listener.interactions if ix.operation == "AL Status"]
        assert len(al_interactions) >= 1, "Expected AL Status interactions"
        for ix in al_interactions:
            assert "al_status_state" in ix.details, "Missing al_status_state in details"
            assert "al_status_name" in ix.details, "Missing al_status_name in details"

        # Verify device data includes al_status_states
        for device in devices.values():
            data = getattr(device, "ethercat_passive_data", None)
            if data and data.get("al_status_states"):
                # Should be a dict mapping state int -> name
                assert isinstance(data["al_status_states"], dict)
                break
        else:
            pytest.fail("No device ethercat_passive_data has al_status_states")

    def test_syncman_config_extraction(self):
        """Verify SyncManager ctrlstatus and enable fields are extracted."""
        listener, _, _ = _run_ethercat()
        # Look for SyncManager Config interactions
        sm_interactions = [
            ix for ix in listener.interactions if ix.operation == "SyncManager Config"
        ]
        assert len(sm_interactions) >= 1, (
            "Expected SyncManager Config interactions. The pcap should contain SM register reads."
        )
        for ix in sm_interactions:
            assert "syncman_ctrlstatus" in ix.details

    def test_dc_activation_extraction(self):
        """Verify DC activation enablecyclic field is extracted."""
        listener, _, _ = _run_ethercat()
        dc_interactions = [ix for ix in listener.interactions if ix.operation == "DC Activation"]
        assert len(dc_interactions) >= 1, "Expected DC Activation interactions"
        for ix in dc_interactions:
            assert "dc_cyclic_enabled" in ix.details

    def test_dl_status_port_link_states(self):
        """Verify DL Status and port link states are extracted."""
        listener, devices, _ = _run_ethercat()
        dl_interactions = [ix for ix in listener.interactions if ix.operation == "DL Status"]
        assert len(dl_interactions) >= 1, "Expected DL Status interactions"

        # At least one DL Status should have port link states
        has_ports = any("port_link_states" in ix.details for ix in dl_interactions)
        assert has_ports, "No DL Status interaction has port_link_states"

        # Verify dl_status2 raw field is present
        has_dl2 = any("dl_status2" in ix.details for ix in dl_interactions)
        assert has_dl2, "No DL Status interaction has dl_status2"

        # Port states should be serialized strings (not raw dicts)
        for ix in dl_interactions:
            ps = ix.details.get("port_link_states")
            if ps is not None:
                assert isinstance(ps, str), f"port_link_states should be a string, got {type(ps)}"

    def test_al_status_code_extraction(self):
        """Verify AL Status Codes (error codes) are extracted when present.

        The CISA pcap may not have non-zero AL status codes (most bootups
        succeed), so this test checks the mechanism works when data is present.
        """
        listener, devices, _ = _run_ethercat()
        # Check that the code path exists and doesn't crash -- the pcap
        # may or may not have non-zero status codes
        for master in listener.masters.values():
            # al_status_codes_seen is always a set (possibly empty)
            assert isinstance(master.al_status_codes_seen, set)
            # If codes are present, verify device data has them
            if master.al_status_codes_seen:
                for device in devices.values():
                    data = getattr(device, "ethercat_passive_data", None)
                    if data and data.get("al_status_codes"):
                        assert isinstance(data["al_status_codes"], dict)

    def test_bootup_pcap_register_fields(self):
        """Verify register extraction works on the bootup pcap fixture."""
        listener, devices, _ = _run_ethercat(
            pcap_subpath=_BOOTUP_PCAP,
        )
        # Bootup sequence should have AL Status state transitions
        found_al = False
        for master in listener.masters.values():
            if master.al_status_states_seen:
                found_al = True
        assert found_al, "Bootup pcap should contain AL Status state reads"

        # Should also have register identity fields
        found_rev = any(m.esc_revision is not None for m in listener.masters.values())
        assert found_rev, "Bootup pcap should contain ESC revision register"

    def test_harvest_returns_dict(self):
        """Verify harvest() returns a dict (tables are now built centrally by scanner)."""
        _, _, result = _run_ethercat()
        assert isinstance(result, dict)
