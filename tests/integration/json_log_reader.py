"""
Structured JSON Log Reader for OIDA Integration Tests

Parses NDJSON log files produced by --json-log and provides query/assertion
helpers for precise, structured test assertions.

Usage:
    log = ScanLog("/tmp/scan.jsonl")
    log.assert_connected(transport="TCP")
    findings = log.get_security_findings()
    results = log.get_scan_results()
"""

import json
from typing import Any, Dict, List, Optional


class ScanLog:
    """Parse and query structured JSON log from a scan run.

    Each event is a dict with at least:
        timestamp, level, event_type, module, host, port, message
    and optionally:
        function, data
    """

    def __init__(self, log_path: str):
        """Load events from an NDJSON log file.

        Args:
            log_path: Path to the JSON log file.
        """
        self.log_path = log_path
        self.events: List[Dict[str, Any]] = []
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        self.events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass  # Skip malformed lines

    def __len__(self) -> int:
        return len(self.events)

    def __repr__(self) -> str:
        return f"ScanLog({self.log_path!r}, {len(self.events)} events)"

    # -----------------------------------------------------------------
    # Query methods
    # -----------------------------------------------------------------

    def get_events(
        self,
        event_type: Optional[str] = None,
        level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return events matching the given filters.

        Args:
            event_type: Filter by event_type (e.g., "connection", "security")
            level: Filter by level (e.g., "info", "error")

        Returns:
            List of matching event dicts.
        """
        result = self.events
        if event_type is not None:
            result = [e for e in result if e.get("event_type") == event_type]
        if level is not None:
            result = [e for e in result if e.get("level") == level]
        return result

    def get_security_findings(self) -> List[Dict[str, Any]]:
        """Return all security-related events."""
        return self.get_events(event_type="security")

    def get_connection_events(self) -> List[Dict[str, Any]]:
        """Return all connection lifecycle events."""
        return self.get_events(event_type="connection")

    def get_scan_results(self) -> List[Dict[str, Any]]:
        """Return all scan_result events."""
        return self.get_events(event_type="scan_result")

    def get_errors(self) -> List[Dict[str, Any]]:
        """Return all error-level events."""
        return self.get_events(level="error")

    def get_enumeration_events(self) -> List[Dict[str, Any]]:
        """Return all enumeration events."""
        return self.get_events(event_type="enumeration")

    def find_events(self, **kwargs) -> List[Dict[str, Any]]:
        """Find events where top-level or data fields match all kwargs.

        Example:
            log.find_events(event_type="scan_result", data__type="registers")
        """
        results = []
        for event in self.events:
            match = True
            for key, value in kwargs.items():
                if "__" in key:
                    # Nested lookup: data__type -> event["data"]["type"]
                    parts = key.split("__", 1)
                    container = event.get(parts[0])
                    if not isinstance(container, dict) or container.get(parts[1]) != value:
                        match = False
                        break
                else:
                    if event.get(key) != value:
                        match = False
                        break
            if match:
                results.append(event)
        return results

    # -----------------------------------------------------------------
    # Assertion helpers
    # -----------------------------------------------------------------

    def assert_connected(self, transport: Optional[str] = None) -> None:
        """Assert that a successful connection event exists.

        Args:
            transport: If given, also check the transport type matches.

        Raises:
            AssertionError: If no matching connected event found.
        """
        conn_events = self.get_connection_events()
        connected = [e for e in conn_events if e.get("data", {}).get("action") == "connected"]
        assert connected, f"No 'connected' event found in {len(conn_events)} connection events"
        if transport:
            matching = [
                e
                for e in connected
                if e.get("data", {}).get("transport", "").upper() == transport.upper()
            ]
            assert matching, (
                f"No connection event with transport={transport!r}. "
                f"Found transports: {[e.get('data', {}).get('transport') for e in connected]}"
            )

    def assert_security_finding(self, finding: str) -> None:
        """Assert that a specific security finding exists.

        Args:
            finding: The finding identifier to look for in data.finding fields.

        Raises:
            AssertionError: If finding not present.
        """
        findings = self.get_security_findings()
        matching = [f for f in findings if f.get("data", {}).get("finding") == finding]
        assert matching, (
            f"Security finding {finding!r} not found. "
            f"Available findings: {[f.get('data', {}).get('finding') for f in findings]}"
        )

    def assert_has_result(self, result_type: str, **expected_data) -> Dict[str, Any]:
        """Assert that a scan result of the given type exists.

        Args:
            result_type: The data.type field to match.
            **expected_data: Additional data fields that must match.

        Returns:
            The first matching result event.

        Raises:
            AssertionError: If no matching result found.
        """
        results = self.get_scan_results()
        matching = [r for r in results if r.get("data", {}).get("type") == result_type]
        assert matching, (
            f"No scan_result with type={result_type!r}. "
            f"Available types: {[r.get('data', {}).get('type') for r in results]}"
        )
        if expected_data:
            for result in matching:
                data = result.get("data", {}).get("result", {})
                if all(data.get(k) == v for k, v in expected_data.items()):
                    return result
            assert False, (
                f"scan_result type={result_type!r} exists but no match for {expected_data}. "
                f"First result data: {matching[0].get('data')}"
            )
        return matching[0]

    def assert_no_errors(self) -> None:
        """Assert that no error-level events were logged.

        Raises:
            AssertionError: If any error events exist.
        """
        errors = self.get_errors()
        assert not errors, (
            f"Expected no errors but found {len(errors)}: "
            f"{[e.get('message', '')[:80] for e in errors[:5]]}"
        )

    def assert_event_sequence(self, *event_types: str) -> None:
        """Assert that events of the given types appear in order.

        The events don't have to be adjacent, just in the correct relative order.

        Args:
            *event_types: Sequence of event_type values to check.

        Raises:
            AssertionError: If the sequence is not found in order.
        """
        idx = 0
        for event in self.events:
            if idx < len(event_types) and event.get("event_type") == event_types[idx]:
                idx += 1
        assert idx == len(event_types), (
            f"Event sequence {event_types} not found in order. "
            f"Matched {idx}/{len(event_types)} events. "
            f"Actual event_types: {[e.get('event_type') for e in self.events]}"
        )

    def assert_has_events(self, min_count: int = 1) -> None:
        """Assert that the log contains at least min_count events.

        Args:
            min_count: Minimum number of events expected.

        Raises:
            AssertionError: If fewer events exist.
        """
        assert len(self.events) >= min_count, (
            f"Expected at least {min_count} events, got {len(self.events)}"
        )
