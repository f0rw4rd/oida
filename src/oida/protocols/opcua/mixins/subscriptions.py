"""
OPC UA Subscriptions Mixin

Provides data change and event subscription functionality.
"""

import asyncio

from oida.utils.protocol_helpers import refuse_without_confirm
from oida.protocols.opcua.handlers import DataChangeHandler, EventHandler
from oida.protocols.opcua.helpers import ua


class SubscriptionsMixin:
    """Mixin providing OPC UA subscription operations."""

    async def _subscribe_data_changes(self):
        """Subscribe to variable data changes"""
        # argparse dest for --duration is 'duration'; default to 10s.
        duration = getattr(self.args, "duration", None) or 10
        interval = getattr(self.args, "subscription_interval", 500)

        self.logger.display(f"Subscribing for {duration}s (interval: {interval}ms)...")

        handler = DataChangeHandler(self.logger)
        sub = await self._client.create_subscription(interval, handler)

        try:
            # Get all variable nodes up to a limit
            objects = self._client.get_objects_node()
            variables = []

            async def find_variables(node, depth=0):
                if depth > 3 or len(variables) >= 50:
                    return
                try:
                    children = await node.get_children()
                    for child in children:
                        try:
                            nc = await child.read_node_class()
                            if nc.name == "Variable" and len(variables) < 50:
                                variables.append(child)
                            await find_variables(child, depth + 1)
                        except Exception as e:
                            self.logger.debug("find variables failed: %s", e)
                            pass
                except Exception as e:
                    self.logger.debug("find variables failed: %s", e)
                    pass

            await find_variables(objects)

            if variables:
                await sub.subscribe_data_change(variables)
                self.logger.display(f"Monitoring {len(variables)} variables...")

                await asyncio.sleep(duration)

                self.logger.display(f"Captured {len(handler.changes)} changes")
                self.results["data"]["subscription_changes"] = handler.changes
            else:
                self.logger.display("No variables found to subscribe to")
        finally:
            try:
                await sub.delete()
            except Exception as e:
                self.logger.debug("subscription delete failed: %s", e)

    async def _subscribe_events(self):
        """Subscribe to server events with EventNotifier permission check"""
        # argparse dest for --duration is 'duration'; default to 10s.
        duration = getattr(self.args, "duration", None) or 10

        self.logger.display(f"Subscribing to events for {duration}s...")

        # Get server node
        server = self._client.get_server_node()

        # Check EventNotifier attribute before subscribing
        event_notifier_info = {}
        try:
            notifier = await server.read_attribute(ua.AttributeIds.EventNotifier)
            level = notifier.Value.Value
            can_subscribe = (level & 0x01) != 0
            can_history_read = (level & 0x04) != 0
            can_history_write = (level & 0x08) != 0

            event_notifier_info = {
                "event_notifier": level,
                "subscribe_to_events": can_subscribe,
                "history_read": can_history_read,
                "history_write": can_history_write,
            }

            self.logger.display(f"EventNotifier: 0x{level:02x}")
            if can_subscribe:
                self.logger.success("[+] SubscribeToEvents permitted")
            else:
                self.logger.warning("[!] SubscribeToEvents bit NOT set - subscription may fail")
            if can_history_read:
                self.logger.display("    HistoryRead: Yes")
            if can_history_write:
                self.logger.display("    HistoryWrite: Yes")

        except Exception as e:
            self.logger.debug(f"Could not read EventNotifier: {e}")

        handler = EventHandler(self.logger)
        sub = await self._client.create_subscription(500, handler)

        # Subscribe to events from server node
        await sub.subscribe_events(server)

        await asyncio.sleep(duration)
        await sub.delete()

        self.logger.display(f"Captured {len(handler.events)} events")
        self.results["data"]["events"] = handler.events
        self.results["data"]["event_notifier"] = event_notifier_info

    async def _test_subscription_limits(self):
        """Test for subscription-based DoS vulnerabilities"""
        # This is a DoS ramp against the live server — opens subscriptions
        # until it hits the limit, then more until the server falls over.
        # Gated on --confirm.
        if refuse_without_confirm(
            self,
            "--test-subscription-limits performs a DoS ramp against the live "
            "server (opens subscriptions until rejection)",
            preview="open subscriptions until the server rejects them",
        ):
            return
        self.logger.display("Testing subscription limits...")

        # Create a simple handler for testing
        class TestHandler:
            def datachange_notification(self, node, val, data):
                pass

        handler = TestHandler()
        subs = []
        max_subs_reached = 0

        # Test: Create many subscriptions rapidly
        self.logger.display("Testing maximum subscription count...")
        try:
            for i in range(100):
                sub = await self._client.create_subscription(100, handler)
                subs.append(sub)
                max_subs_reached = i + 1

            self.logger.warning("[!] Server allows 100+ subscriptions (no rate limit)")

        except Exception as e:
            self.logger.display(f"Server limited at {max_subs_reached} subscriptions")
            self.logger.debug(f"Limit error: {e}")

        # Cleanup subscriptions
        for sub in subs:
            try:
                await sub.delete()
            except Exception as e:
                self.logger.debug("datachange notification failed: %s", e)
                pass

        # Test: Many monitored items on single subscription
        self.logger.display("Testing monitored item limits...")
        try:
            sub = await self._client.create_subscription(500, handler)
            objects = self._client.get_objects_node()
            children = await objects.get_children()

            # Try to subscribe to all children
            if children:
                try:
                    await sub.subscribe_data_change(children[:50])
                    self.logger.display(
                        f"Successfully subscribed to {min(len(children), 50)} items"
                    )
                except Exception as e:
                    self.logger.debug("datachange notification failed: %s", e)
                    self.logger.display(f"Monitored item limit: {e}")

            await sub.delete()

        except Exception as e:
            self.logger.debug(f"Monitored item test error: {e}")

        self.results["data"]["subscription_limits"] = {
            "max_subscriptions_tested": max_subs_reached,
        }
