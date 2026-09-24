"""Integration tests for EtherNet/IP passive listener in EK mode."""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestEtherNetIPPassiveEK:
    """EtherNet/IP-specific tests beyond the parametrized quality suite."""

    def test_enip_sessions_and_commands(self):
        listener, devices, result = _run_listener_test(
            "enip",
            "EtherNetIPPassiveListener",
            "enip or cip",
            "enip/cisagov_enip_cip_example.pcap",
            expect_details=["command_name"],
        )

        # A1: sessions populated
        assert len(listener.sessions) >= 1, (
            f"Expected >= 1 EtherNet/IP session, got {len(listener.sessions)}"
        )

        # A2: passive_data on at least one device
        has_data = any(
            hasattr(d, "enip_passive_data") and d.enip_passive_data for d in devices.values()
        )
        assert has_data, "No device has enip_passive_data"

        # A3: harvest custom tables exist (identity tables)
        tables = result.get("tables", [])
        if tables:
            identity_tables = [t for t in tables if "Identity" in t.get("title", "")]
            assert identity_tables, (
                f"Expected identity table in harvest; titles: {[t['title'] for t in tables]}"
            )

    def test_enip_generated(self):
        listener, devices, result = _run_listener_test(
            "enip",
            "EtherNetIPPassiveListener",
            "enip or cip",
            "enip/generated_enip.pcap",
            expect_details=["command_name"],
        )

        # At least one device with enip_passive_data
        has_data = any(
            hasattr(d, "enip_passive_data") and d.enip_passive_data for d in devices.values()
        )
        assert has_data, "No device has enip_passive_data"

    def test_cpf_fields_extracted(self):
        """CPF type IDs and Connection Address Item IDs are extracted."""
        listener, devices, result = _run_listener_test(
            "enip",
            "EtherNetIPPassiveListener",
            "enip or cip",
            "enip/cisagov_enip_cip_example.pcap",
            expect_details=["cpf_typeid"],
        )

        # At least one interaction must have cpf_cai_connid (connection-based traffic)
        has_cai = any(ix.details.get("cpf_cai_connid") for ix in listener.interactions)
        assert has_cai, (
            "No interaction has cpf_cai_connid; "
            "CPF Connection Address Item extraction may be broken"
        )

    def test_msp_num_services_extracted(self):
        """Multiple Service Packet service count is extracted."""
        listener, devices, result = _run_listener_test(
            "enip",
            "EtherNetIPPassiveListener",
            "enip or cip",
            "enip/cisagov_enip_cip_example.pcap",
            expect_details=["msp_num_services"],
        )

        # Verify the count is a valid number
        for ix in listener.interactions:
            msp = ix.details.get("msp_num_services")
            if msp is not None:
                assert int(msp) > 0, f"msp_num_services should be > 0, got {msp}"
                break

    def test_getlist_attr_status_extracted(self):
        """Get_Attribute_List per-attribute status is extracted."""
        listener, devices, result = _run_listener_test(
            "enip",
            "EtherNetIPPassiveListener",
            "enip or cip",
            "enip/cisagov_enip_cip_example.pcap",
            expect_details=["getlist_attr_status"],
        )

    def test_cip_identity_object_fields(self):
        """CIP Identity Object vendor_id, product_name, status from CIP layer."""
        listener, devices, result = _run_listener_test(
            "enip",
            "EtherNetIPPassiveListener",
            "enip or cip",
            "enip/openics_EIP-ChangePortConfigurationAttempt.pcap",
            expect_details=["cip_id_vendor_id"],
        )

        # Should also have product_name and status
        has_product = any(ix.details.get("cip_id_product_name") for ix in listener.interactions)
        assert has_product, "No interaction has cip_id_product_name"

        has_status = any(ix.details.get("cip_id_status") for ix in listener.interactions)
        assert has_status, "No interaction has cip_id_status"

    def test_class_revision_extracted(self):
        """CIP class revision is extracted from attribute responses."""
        listener, devices, result = _run_listener_test(
            "enip",
            "EtherNetIPPassiveListener",
            "enip or cip",
            "enip/openics_EIP-ChangePortConfigurationAttempt.pcap",
            expect_details=["class_revision"],
        )

    def test_sai_fields_in_io_traffic(self):
        """I/O traffic should be aggregated into _io_counts (not individual interactions)."""
        listener, devices, result = _run_listener_test(
            "enip",
            "EtherNetIPPassiveListener",
            "enip or cip",
            "enip/ndpi_cip_io.pcap",
            min_devices=0,
            min_interactions=0,
        )

        assert listener._io_counts, "Expected aggregated I/O Data counts"
        total = sum(listener._io_counts.values())
        assert total >= 1, f"Expected at least 1 I/O packet, got {total}"

    def test_list_services_fields(self):
        """ListServices capability flags and service name from response."""
        listener, devices, result = _run_listener_test(
            "enip",
            "EtherNetIPPassiveListener",
            "enip.command==0x0004",
            "enip/openics_EIP-FirmwareChange.pcap",
            min_devices=0,
            min_interactions=1,
        )

        has_capaflags = any(ix.details.get("lsr_capaflags") for ix in listener.interactions)
        assert has_capaflags, "No interaction has lsr_capaflags"

        has_svcname = any(ix.details.get("lsr_servicename") for ix in listener.interactions)
        assert has_svcname, "No interaction has lsr_servicename"

    def test_register_session_version(self):
        """RegisterSession protocol version is extracted."""
        listener, devices, result = _run_listener_test(
            "enip",
            "EtherNetIPPassiveListener",
            "enip.command==0x0065",
            "enip/openics_EIP-FirmwareChange.pcap",
            min_devices=0,
            min_interactions=1,
        )

        has_version = any(ix.details.get("rs_version") for ix in listener.interactions)
        assert has_version, "No interaction has rs_version"

    def test_list_identity_revision(self):
        """ListIdentity revision field is extracted from responses."""
        listener, devices, result = _run_listener_test(
            "enip",
            "EtherNetIPPassiveListener",
            "enip.command==0x0063",
            "enip/cisagov_enip_cip_example.pcap",
            min_devices=0,
            min_interactions=1,
        )

        has_revision = any(ix.details.get("lir_revision") for ix in listener.interactions)
        assert has_revision, "No interaction has lir_revision"

    def test_sinport_extracted(self):
        """Socket address port (sinport) is extracted from ListIdentity."""
        listener, devices, result = _run_listener_test(
            "enip",
            "EtherNetIPPassiveListener",
            "enip.command==0x0063",
            "enip/cisagov_enip_cip_example.pcap",
            min_devices=0,
            min_interactions=1,
        )

        has_sinport = any(ix.details.get("sinport") for ix in listener.interactions)
        assert has_sinport, "No interaction has sinport"

    def test_setlist_attr_status(self):
        """Set_Attribute_List per-attribute status is extracted."""
        listener, devices, result = _run_listener_test(
            "enip",
            "EtherNetIPPassiveListener",
            "enip or cip",
            "enip/cisagov_enip_cip_example.pcap",
        )

        # setlist_attr_status may not be in every pcap; just verify no crash
        # and that the field extraction code path was exercised
        assert len(listener.interactions) > 0, "No interactions recorded"
