#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OPC UA Event and Data Change Handlers

This module provides handler classes for OPC UA subscriptions and events.
"""


class DataChangeHandler:
    """Handler for subscription data changes"""

    def __init__(self, logger, results):
        self.logger = logger
        self.results = results
        self.changes = []

    def datachange_notification(self, node, val, data):
        """Called by asyncua on every data change"""
        node_id = str(node.nodeid) if hasattr(node, "nodeid") else str(node)
        self.logger.display(f"Change: {node_id} = {val}")
        self.changes.append(
            {
                "node": node_id,
                "value": str(val),
                "timestamp": (
                    str(data.monitored_item.Value.SourceTimestamp)
                    if hasattr(data, "monitored_item")
                    else None
                ),
            }
        )


class EventHandler:
    """Handler for OPC UA events"""

    def __init__(self, logger):
        self.logger = logger
        self.events = []

    def event_notification(self, event):
        """Called by asyncua on event notification"""
        event_info = {
            "type": str(getattr(event, "EventType", "Unknown")),
            "message": str(getattr(event, "Message", "")),
            "severity": getattr(event, "Severity", 0),
            "time": str(getattr(event, "Time", "")),
        }
        self.logger.warning(f"Event: {event_info['type']} - {event_info['message']}")
        self.events.append(event_info)
