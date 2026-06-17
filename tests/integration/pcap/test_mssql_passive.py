"""Integration tests for MSSQL/TDS passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestMSSQLPassiveEK:
    """MSSQL-specific field-coverage tests."""

    def test_mssql_colmetadata_usertype(self):
        """ColMetadata token exposes per-column usertype tag."""
        listener, devices, result = _run_listener_test(
            "mssql",
            "MSSQLPassiveListener",
            "tds",
            "mssql/wireshark_mssql.cap",
            expect_operations=["ColMetadata"],
        )
        found = any(ix.details.get("usertype") for ix in listener.interactions)
        assert found, (
            "Expected usertype in ColMetadata interaction details; "
            f"sample details: {[ix.details for ix in listener.interactions if ix.operation == 'ColMetadata'][:1]}"
        )

    def test_mssql_colmetadata_charset_id(self):
        """ColMetadata token exposes collate_charset_id."""
        listener, devices, result = _run_listener_test(
            "mssql",
            "MSSQLPassiveListener",
            "tds",
            "mssql/wireshark_mssql.cap",
        )
        found = any(ix.details.get("collate_charset_id") for ix in listener.interactions)
        assert found, "No interaction has collate_charset_id in details"

    def test_mssql_collation_lcid(self):
        """type_info collation LCID is captured on the RPC interaction."""
        listener, devices, result = _run_listener_test(
            "mssql",
            "MSSQLPassiveListener",
            "tds",
            "mssql/wireshark_mssql.cap",
        )
        found = any(ix.details.get("collation_lcid") for ix in listener.interactions)
        assert found, "No interaction has collation_lcid in details"

    def test_mssql_device_collation_lcid(self):
        """Server device protocol_data carries the collation LCID (server locale)."""
        listener, devices, result = _run_listener_test(
            "mssql",
            "MSSQLPassiveListener",
            "tds",
            "mssql/wireshark_mssql.cap",
        )
        has_field = any(
            getattr(d, "mssql_passive_data", None)
            and "collation_lcid" in d.mssql_passive_data
            for d in devices.values()
        )
        assert has_field, "No device has collation_lcid in mssql_passive_data"
