"""Integration tests for AMQP passive listener.

Tests cover:
- Connection.Start/Start-Ok handshake detection
- Connection.Tune/Tune-Ok detection
- Connection.Open with virtual host extraction
- Queue.Declare with queue name extraction
- Basic.Publish with exchange and routing key
- Heartbeat frame detection
- Broker vs Client device role assignment
- Class.Method resolution from numeric IDs
- Harvest table output quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestAMQPPassiveEK:
    """AMQP-specific tests beyond the parametrized quality suite."""

    def test_amqp_interactions_created(self):
        """AMQP packets create interactions with class_method field."""
        listener, devices, result = _run_listener_test(
            "amqp",
            "AMQPPassiveListener",
            "amqp",
            "amqp/generated_amqp.pcap",
            min_devices=2,
            min_interactions=1,
            expect_details=["class_method"],
        )
        methods = {ix.details.get("class_method", "") for ix in listener.interactions}
        assert any(m != "" for m in methods), f"No class_methods found; got: {methods}"

    def test_amqp_connection_handshake(self):
        """Connection.Start and Start-Ok are detected."""
        listener, devices, result = _run_listener_test(
            "amqp",
            "AMQPPassiveListener",
            "amqp",
            "amqp/generated_amqp.pcap",
            min_interactions=2,
        )
        methods = {ix.details.get("class_method", "") for ix in listener.interactions}
        assert any("Connection.Start" in m for m in methods), (
            f"Expected Connection.Start; got: {sorted(methods)}"
        )

    def test_amqp_connection_open_vhost(self):
        """Connection.Open extracts virtual host."""
        listener, devices, result = _run_listener_test(
            "amqp",
            "AMQPPassiveListener",
            "amqp",
            "amqp/generated_amqp.pcap",
            min_interactions=1,
        )
        open_ixs = [
            ix
            for ix in listener.interactions
            if "Connection.Open" in ix.details.get("class_method", "")
            and "Ok" not in ix.details.get("class_method", "")
        ]
        if open_ixs:
            vhost = open_ixs[0].details.get("vhost", "")
            assert vhost, f"Connection.Open should have vhost; details: {open_ixs[0].details}"

    def test_amqp_queue_declare(self):
        """Queue.Declare extracts queue name."""
        listener, devices, result = _run_listener_test(
            "amqp",
            "AMQPPassiveListener",
            "amqp",
            "amqp/generated_amqp.pcap",
            min_interactions=1,
        )
        queue_ixs = [
            ix
            for ix in listener.interactions
            if "Queue.Declare" in ix.details.get("class_method", "")
        ]
        if queue_ixs:
            queue = queue_ixs[0].details.get("queue", "")
            assert queue, f"Queue.Declare should have queue name; details: {queue_ixs[0].details}"

    def test_amqp_basic_publish(self):
        """Basic.Publish extracts exchange and routing key."""
        listener, devices, result = _run_listener_test(
            "amqp",
            "AMQPPassiveListener",
            "amqp",
            "amqp/generated_amqp.pcap",
            min_interactions=1,
        )
        publish_ixs = [
            ix
            for ix in listener.interactions
            if "Basic.Publish" in ix.details.get("class_method", "")
        ]
        if publish_ixs:
            exchange = publish_ixs[0].details.get("exchange", "")
            routing_key = publish_ixs[0].details.get("routing_key", "")
            assert exchange or routing_key, (
                f"Basic.Publish should have exchange or routing_key; "
                f"details: {publish_ixs[0].details}"
            )

    def test_amqp_broker_device_tracked(self):
        """AMQP broker (port 5672) is tracked as a device."""
        listener, devices, result = _run_listener_test(
            "amqp",
            "AMQPPassiveListener",
            "amqp",
            "amqp/generated_amqp.pcap",
            min_devices=2,
        )
        broker_devices = [
            d
            for d in devices.values()
            if hasattr(d, "device_type") and "Broker" in (d.device_type or "")
        ]
        assert len(broker_devices) >= 1, (
            f"Expected at least 1 broker device; types: {[d.device_type for d in devices.values()]}"
        )

    def test_amqp_client_device_tracked(self):
        """AMQP client is tracked as a device."""
        listener, devices, result = _run_listener_test(
            "amqp",
            "AMQPPassiveListener",
            "amqp",
            "amqp/generated_amqp.pcap",
            min_devices=2,
        )
        client_devices = [
            d
            for d in devices.values()
            if hasattr(d, "device_type") and "Client" in (d.device_type or "")
        ]
        assert len(client_devices) >= 1, (
            f"Expected at least 1 client device; types: {[d.device_type for d in devices.values()]}"
        )

    def test_amqp_heartbeat_detected(self):
        """Heartbeat frames are detected."""
        listener, devices, result = _run_listener_test(
            "amqp",
            "AMQPPassiveListener",
            "amqp",
            "amqp/generated_amqp.pcap",
            min_interactions=1,
        )
        heartbeat_ixs = [
            ix for ix in listener.interactions if "Heartbeat" in ix.details.get("class_method", "")
        ]
        assert len(heartbeat_ixs) >= 1, (
            f"Expected at least 1 Heartbeat interaction; "
            f"methods: {[ix.details.get('class_method') for ix in listener.interactions]}"
        )

    def test_amqp_operation_prefix(self):
        """All AMQP operations start with 'AMQP'."""
        listener, devices, result = _run_listener_test(
            "amqp",
            "AMQPPassiveListener",
            "amqp",
            "amqp/generated_amqp.pcap",
            min_interactions=1,
        )
        for ix in listener.interactions:
            assert ix.operation.startswith("AMQP"), (
                f"Operation should start with 'AMQP'; got: {ix.operation}"
            )

    def test_amqp_harvest_valid(self):
        """Harvest returns a valid dict."""
        listener, devices, result = _run_listener_test(
            "amqp",
            "AMQPPassiveListener",
            "amqp",
            "amqp/generated_amqp.pcap",
            check_harvest=True,
        )
        assert isinstance(result, dict)

    def test_amqp_protocol_columns_format(self):
        """Protocol columns return correct number of values."""
        listener, devices, result = _run_listener_test(
            "amqp",
            "AMQPPassiveListener",
            "amqp",
            "amqp/generated_amqp.pcap",
            min_interactions=1,
        )
        for ix in listener.interactions:
            cols = listener._format_protocol_columns(ix)
            assert len(cols) == len(listener.PROTOCOL_COLUMNS), (
                f"Expected {len(listener.PROTOCOL_COLUMNS)} columns, got {len(cols)}: {cols}"
            )

    def test_amqp_passive_data_fields(self):
        """Device amqp_passive_data contains expected fields."""
        listener, devices, result = _run_listener_test(
            "amqp",
            "AMQPPassiveListener",
            "amqp",
            "amqp/generated_amqp.pcap",
            min_devices=2,
        )
        for d in devices.values():
            data = getattr(d, "amqp_passive_data", None)
            if data:
                assert "role" in data, f"Missing 'role' in amqp_passive_data: {data}"
                assert "protocol" in data, f"Missing 'protocol' in amqp_passive_data: {data}"

    def test_amqp_class_method_resolution(self):
        """Class IDs and method IDs are resolved to human-readable names."""
        from oida.pcap.passive.amqp import AMQP_CLASSES, AMQP_METHOD_MAPS

        assert AMQP_CLASSES.get("10") == "Connection"
        assert AMQP_CLASSES.get("50") == "Queue"
        assert AMQP_CLASSES.get("60") == "Basic"
        assert AMQP_METHOD_MAPS["10"].get("10") == "Start"
        assert AMQP_METHOD_MAPS["60"].get("40") == "Publish"
