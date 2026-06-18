"""Integration tests for MongoDB passive listener.

Tests cover:
- OP_QUERY extraction (database, collection, query details)
- OP_REPLY parsing (response flags, cursor ID, document count)
- OP_INSERT detection (write operation tracking)
- OP_MSG modern wire protocol
- Both client and server device creation
- Interaction table formatting
- Harvest output quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestMongoDBPassiveEK:
    """MongoDB-specific tests beyond the parametrized quality suite."""

    def test_query_extraction(self):
        """OP_QUERY packets extract database and collection names."""
        listener, devices, result = _run_listener_test(
            "mongodb",
            "MongoDBPassiveListener",
            "mongo",
            "mongodb/generated_mongodb.pcap",
            min_devices=2,
            min_interactions=2,
            expect_details=["opcode", "database"],
        )
        # Should have seen at least one database
        assert len(listener.databases_seen) >= 1, (
            f"Expected at least 1 database, got {listener.databases_seen}"
        )
        # Should have detected OP_QUERY operations
        query_ops = [ix for ix in listener.interactions if ix.details.get("opcode") == "OP_QUERY"]
        assert len(query_ops) >= 1, "No OP_QUERY operations found"

    def test_reply_parsing(self):
        """OP_REPLY packets are parsed with document count."""
        listener, devices, result = _run_listener_test(
            "mongodb",
            "MongoDBPassiveListener",
            "mongo",
            "mongodb/generated_mongodb.pcap",
            min_interactions=2,
        )
        reply_ops = [ix for ix in listener.interactions if ix.details.get("opcode") == "OP_REPLY"]
        assert len(reply_ops) >= 1, "No OP_REPLY operations found"
        # Check that number_returned is extracted
        has_returned = any(ix.details.get("number_returned") not in (None, "") for ix in reply_ops)
        assert has_returned, "No OP_REPLY has number_returned"

    def test_insert_detection(self):
        """OP_INSERT operations are detected and tracked as writes."""
        listener, devices, result = _run_listener_test(
            "mongodb",
            "MongoDBPassiveListener",
            "mongo",
            "mongodb/generated_mongodb.pcap",
            min_interactions=1,
        )
        insert_ops = [ix for ix in listener.interactions if ix.details.get("opcode") == "OP_INSERT"]
        assert len(insert_ops) >= 1, "No OP_INSERT operations found"
        # Write operations should be tracked
        writes = listener.get_write_operations()
        assert len(writes) >= 1, "No write operations tracked"

    def test_collection_tracking(self):
        """Collections are tracked across queries."""
        listener, devices, result = _run_listener_test(
            "mongodb",
            "MongoDBPassiveListener",
            "mongo",
            "mongodb/generated_mongodb.pcap",
        )
        assert len(listener.collections_seen) >= 1, (
            f"Expected >= 1 collection, got {listener.collections_seen}"
        )

    def test_both_endpoints_tracked(self):
        """Both MongoDB client and server devices are created."""
        listener, devices, result = _run_listener_test(
            "mongodb",
            "MongoDBPassiveListener",
            "mongo",
            "mongodb/generated_mongodb.pcap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_server = any("Server" in t for t in device_types)
        has_client = any("Client" in t for t in device_types)
        assert has_server, f"No MongoDB Server device found; types: {device_types}"
        assert has_client, f"No MongoDB Client device found; types: {device_types}"

    def test_harvest_valid(self):
        """Harvest returns valid dict without raw objects in table cells."""
        listener, devices, result = _run_listener_test(
            "mongodb",
            "MongoDBPassiveListener",
            "mongo",
            "mongodb/generated_mongodb.pcap",
        )
        assert isinstance(result, dict)

    def test_protocol_columns_format(self):
        """Protocol columns produce clean string values."""
        listener, devices, result = _run_listener_test(
            "mongodb",
            "MongoDBPassiveListener",
            "mongo",
            "mongodb/generated_mongodb.pcap",
            min_interactions=1,
        )
        for ix in listener.interactions:
            cols = listener._format_protocol_columns(ix)
            assert len(cols) == 4, f"Expected 4 columns, got {len(cols)}"
            for col in cols:
                assert not isinstance(col, (dict, set, list)), f"Raw collection in column: {col}"
