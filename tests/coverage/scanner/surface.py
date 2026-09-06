"""Expected scanner semantic surface per protocol.

Each entry lists the set of ``results["data"][<key>]`` paths the scanner
*can* populate when invoked against a representative target with the
right flags. Coverage % = |populated ∩ expected| / |expected|.

These sets are hand-curated from the scanner's own source. To regenerate
the candidate list for a protocol, run::

    grep -rhE 'self\\.results\\["data"\\]\\["[^"]+"\\]' src/oida/protocols/<proto>/

and prune to keys that a fully-flagged scan would actually exercise. The
goal is a *reasonable* surface — not "every key the code touches if
every flag is set" (some are mutually exclusive).
"""

from __future__ import annotations

# Each value is a set of top-level keys we expect to see populated in
# ``results["data"]`` after a maximal scan against a healthy target.
# Nested paths use dot notation (e.g. ``device_info.vendor``).
EXPECTED_SURFACE: dict[str, set[str]] = {
    "modbus": {
        # Connection / framing
        "connection_type",
        "units",
        "server_info",
        # Discovery
        "scan_results",
        "function_codes",
        # Operations a `--quick` scan should reach
        "device_id",
        "diagnostics",
    },
    "iec104": {
        "device_info",
        "scan_results",
        "scan_results.server_info",
        "scan_results.type_ids",
        "scan_results.data_points",
    },
    "opcua": {
        "endpoints",
        "server_info",
        "security_policies",
        "namespaces",
        "browse",
    },
    "dnp3": {
        "device_info",
        "scan_results",
        "address_scan",
    },
    "ethernetip": {
        "device_info",
        "identity",
        "services",
        "interface_config",
    },
    "ads": {
        "device_info",
        "router_state",
        "symbols",
    },
    "bacnet": {
        "device_info",
        "device_info.devices",
    },
    "snap7": {
        "device_info",
        "scan_results",
        "scan_results.cpu_info",
        "scan_results.plc_status",
        "scan_results.firmware_info",
        "security_findings",
    },
    "mms": {
        "device_info",
        "logical_devices",
        "data_objects",
    },
    "hart": {
        "device_info",
        "tags",
    },
    "knx": {
        "gateway",
        "gateways",
        "device_info",
    },
    "snmp": {
        "sys_info",
        "vendor",
    },
    "coap": {
        "scan_results",
        "scan_results.resources",
    },
    "ocpp": {
        "target_url",
        "server_info",
        "boot_notification",
    },
    "mqtt": {
        "broker_info",
        "topics",
    },
    "hl7": {
        "connected",
        "server_info",
        "ack_code",
    },
    "fhir": {
        "server_info",
        "capability_statement",
        "resource_types",
    },
    "dicom": {
        "connected",
        "accepted_contexts",
        "c_echo",
    },
}


def expected_for(protocol: str) -> set[str]:
    """Return the expected ``results["data"]`` key set for a protocol."""
    return EXPECTED_SURFACE.get(protocol, set())
