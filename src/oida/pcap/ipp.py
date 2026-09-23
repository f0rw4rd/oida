"""
IPP (Internet Printing Protocol) Passive Listener for network printer discovery.

Passively captures IPP traffic to extract:
- Printer names, URIs, and locations
- Printer make and model information
- Supported document formats
- Printer state and state reasons
- IPP operations (Get-Printer-Attributes, Print-Job, etc.)
- Requesting user names from print jobs
- Job names (document titles)

IPP runs over HTTP/HTTPS on port 631 (default).
tshark dissects IPP within HTTP as the ``ipp`` layer.

Key tshark IPP fields:
- ipp.version: IPP version (e.g., "1.1")
- ipp.operation_id: Operation ID (request: 0x000B=Get-Printer-Attributes, 0x0002=Print-Job)
- ipp.status_code: Status code (response: 0x0000=successful-ok)
- ipp.request_id: Request ID for correlation
- ipp.name: Attribute name
- ipp.charstring_value: String attribute value (printer-name, printer-uri, etc.)
- ipp.integer_value: Integer attribute value (printer-state, etc.)
- ipp.boolean_value: Boolean attribute value

IPP operations of interest:
- 0x0002: Print-Job
- 0x0003: Print-URI
- 0x0004: Validate-Job
- 0x0005: Create-Job
- 0x0006: Send-Document
- 0x0008: Cancel-Job
- 0x0009: Get-Job-Attributes
- 0x000A: Get-Jobs
- 0x000B: Get-Printer-Attributes
- 0x0010: CUPS-Get-Default
- 0x4001: CUPS-Get-Printers
- 0x4002: CUPS-Add-Modify-Printer
"""

from typing import Any, Dict, List, Optional

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# IPP operation IDs
IPP_OPERATIONS = {
    "0x0002": "Print-Job",
    "0x0003": "Print-URI",
    "0x0004": "Validate-Job",
    "0x0005": "Create-Job",
    "0x0006": "Send-Document",
    "0x0007": "Send-URI",
    "0x0008": "Cancel-Job",
    "0x0009": "Get-Job-Attributes",
    "0x000a": "Get-Jobs",
    "0x000b": "Get-Printer-Attributes",
    "0x000c": "Hold-Job",
    "0x000d": "Release-Job",
    "0x000e": "Restart-Job",
    "0x0010": "Pause-Printer",
    "0x0011": "Resume-Printer",
    "0x0012": "Purge-Jobs",
    "0x4001": "CUPS-Get-Printers",
    "0x4002": "CUPS-Add-Modify-Printer",
    "0x4003": "CUPS-Delete-Printer",
    "0x4004": "CUPS-Get-Classes",
    "0x4005": "CUPS-Add-Modify-Class",
    "0x4006": "CUPS-Delete-Class",
    "0x4007": "CUPS-Accept-Jobs",
    "0x4008": "CUPS-Reject-Jobs",
    "0x4009": "CUPS-Set-Default",
    "0x400a": "CUPS-Get-Devices",
    "0x400b": "CUPS-Get-PPDs",
    "0x400c": "CUPS-Move-Job",
    "0x400d": "CUPS-Authenticate-Job",
    "0x400e": "CUPS-Get-PPD",
}

# IPP status codes
IPP_STATUS_CODES = {
    "0x0000": "successful-ok",
    "0x0001": "successful-ok-ignored-or-substituted",
    "0x0002": "successful-ok-conflicting-attributes",
    "0x0400": "client-error-bad-request",
    "0x0401": "client-error-forbidden",
    "0x0402": "client-error-not-authenticated",
    "0x0403": "client-error-not-authorized",
    "0x0404": "client-error-not-possible",
    "0x0405": "client-error-timeout",
    "0x0406": "client-error-not-found",
    "0x0407": "client-error-gone",
    "0x0408": "client-error-request-entity-too-large",
    "0x0409": "client-error-request-value-too-long",
    "0x040a": "client-error-document-format-not-supported",
    "0x040b": "client-error-attributes-or-values-not-supported",
    "0x0500": "server-error-internal-error",
    "0x0501": "server-error-operation-not-supported",
    "0x0502": "server-error-service-unavailable",
    "0x0503": "server-error-version-not-supported",
    "0x0504": "server-error-device-error",
    "0x0505": "server-error-temporary-error",
    "0x0506": "server-error-not-accepting-jobs",
    "0x0507": "server-error-busy",
    "0x0508": "server-error-job-canceled",
}

# Printer state mapping
PRINTER_STATE = {
    "3": "idle",
    "4": "processing",
    "5": "stopped",
}

IPP_DEFAULT_PORT = 631


class IPPPassiveListener(PySharkListenerBase):
    """Passive IPP traffic listener for network printer discovery and enumeration.

    Captures IPP traffic to extract:
    - Printer names, models, locations, and URIs
    - Print job submissions with user names
    - Supported document formats
    - Printer state information
    - CUPS-specific operations

    Security value:
    - Network printer discovery and inventory
    - Information disclosure (printer model, firmware version)
    - User activity tracking (who prints what)
    - CUPS server enumeration

    Usage:
        listener = IPPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
    """

    PROTOCOL_NAME = "ipp"
    DISPLAY_FILTER = "ipp"
    REQUIRED_LAYERS = ("ipp",)
    PROTOCOL_COLUMNS = ("operation", "status", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # Track discovered printers
        self.printers: Dict[str, Dict[str, Any]] = {}  # printer_uri -> info
        # Track print jobs
        self.print_jobs: List[Dict[str, Any]] = []

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format IPP interaction as protocol-specific table columns."""
        d = ix.details
        operation = d.get("operation_name", "") or d.get("status_name", "")
        status = d.get("status_name", "") if d.get("operation_name") else ""

        # Build detail string
        parts = []
        printer_name = d.get("printer_name", "")
        if printer_name:
            parts.append(f"printer={printer_name}")
        printer_uri = d.get("printer_uri", "")
        if printer_uri and not printer_name:
            parts.append(f"uri={printer_uri}")
        model = d.get("printer_make_and_model", "")
        if model:
            parts.append(f"model={model}")
        user = d.get("requesting_user", "")
        if user:
            parts.append(f"user={user}")
        job = d.get("job_name", "")
        if job:
            parts.append(f"job={job}")
        detail = " ".join(parts)

        return [operation, status, detail]

    def process_packet(self, packet) -> None:
        """Process IPP packet and extract printer information."""
        if not hasattr(packet, "ipp"):
            return

        ipp_layer = packet.ipp
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        stream_id = self.get_stream_id(packet)
        now = self._get_timestamp()

        # Determine if request or response
        operation_id = self.get_field(ipp_layer, "operation_id", "")
        status_code = self.get_field(ipp_layer, "status_code", "")
        request_id = self.get_field(ipp_layer, "request_id", "")

        is_request = bool(operation_id)
        direction = "request" if is_request else "response"

        details: Dict[str, Any] = {}
        if request_id:
            details["request_id"] = str(request_id)

        if is_request:
            # operation_id arrives as a native int in EK mode (e.g. 11) or as a
            # hex string in XML mode (e.g. "0x000b"); normalize to the zero-padded
            # hex key used by IPP_OPERATIONS. base 0 parses both forms.
            try:
                op_str = f"0x{int(str(operation_id), 0):04x}"
            except (ValueError, TypeError):
                op_str = str(operation_id).lower()
            op_name = IPP_OPERATIONS.get(op_str, f"op={operation_id}")
            details["operation_id"] = str(operation_id)
            details["operation_name"] = op_name
        else:
            try:
                status_str = f"0x{int(str(status_code), 0):04x}"
            except (ValueError, TypeError):
                status_str = str(status_code).lower()
            status_name = IPP_STATUS_CODES.get(status_str, f"status={status_code}")
            details["status_code"] = str(status_code)
            details["status_name"] = status_name

        # Extract IPP attributes from the packet
        # PyShark exposes IPP attributes as name/value pairs
        self._extract_attributes(ipp_layer, details)

        # Build operation string for the interaction
        if is_request:
            op_label = details.get("operation_name", "IPP Request")
        else:
            op_label = f"IPP Response ({details.get('status_name', '?')})"

        # Build summary
        summary_parts = [op_label]
        if details.get("printer_name"):
            summary_parts.append(f"printer={details['printer_name']}")
        if details.get("requesting_user"):
            summary_parts.append(f"user={details['requesting_user']}")
        if details.get("job_name"):
            summary_parts.append(f"job={details['job_name']}")
        summary = " ".join(summary_parts)

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            op_label,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Track printer info from responses
        if not is_request:
            self._track_printer_info(details, src_ip, src_port, src_mac)

        # Track print jobs
        if is_request and details.get("operation_name") in ("Print-Job", "Create-Job"):
            self.print_jobs.append(
                {
                    "client_ip": src_ip,
                    "server_ip": dst_ip,
                    "user": details.get("requesting_user", ""),
                    "job_name": details.get("job_name", ""),
                    "printer_uri": details.get("printer_uri", ""),
                    "timestamp": now,
                }
            )

        # Track devices
        if is_request:
            self._update_client_device(src_ip, dst_ip, src_mac)
            self._update_server_device(dst_ip, dst_port, dst_mac)
        else:
            self._update_server_device(src_ip, src_port, src_mac)
            self._update_client_device(dst_ip, src_ip, dst_mac)

    def _extract_attributes(self, ipp_layer: Any, details: Dict[str, Any]) -> None:
        """Extract IPP attributes from the packet layer."""
        fields = self.get_all_fields(ipp_layer)

        # Map IPP attribute names to detail keys
        attr_map = {
            "printer-name": "printer_name",
            "printer-uri": "printer_uri",
            "printer-uri-supported": "printer_uri",
            "printer-make-and-model": "printer_make_and_model",
            "printer-info": "printer_info",
            "printer-location": "printer_location",
            "printer-state": "printer_state",
            "printer-state-reasons": "printer_state_reasons",
            "document-format-supported": "document_formats",
            "requesting-user-name": "requesting_user",
            "job-name": "job_name",
            "job-id": "job_id",
            "copies": "copies",
        }

        # Extract from charstring_value fields (most IPP attributes are strings).
        # In EK mode, all IPP attributes may appear as ipp.name / ipp.charstring_value.
        # ipp.name lists EVERY attribute name (integer/boolean/enum/keyword/string),
        # while ipp.charstring_value lists ONLY the string-typed values, so the two
        # flattened comma-joined lists are NOT positionally aligned in general
        # (e.g. names=6 / values=8). Zipping them would pair a name with the value
        # of an unrelated attribute and surface wrong printer/user/job data. tshark
        # does not expose the per-attribute (name,type,value) grouping through these
        # flattened arrays, so we only trust a positional pairing when the two lists
        # have equal length; otherwise we skip it and rely on the typed-field
        # fallback loop below, which keys off real field names.
        name_vals = self.get_field(ipp_layer, "name", "")
        string_vals = self.get_field(ipp_layer, "charstring_value", "")

        if name_vals and string_vals:
            names = [n.strip() for n in str(name_vals).split(",")]
            values = [v.strip() for v in str(string_vals).split(",")]
            if len(names) == len(values):
                for name, value in zip(names, values):
                    if name in attr_map and value:
                        details[attr_map[name]] = value
            else:
                self.logger.debug(
                    "IPP: name/charstring_value count mismatch "
                    f"({len(names)} names vs {len(values)} values); "
                    "skipping positional pairing to avoid mis-associating attributes"
                )

        # Also check for fields directly in the all_fields dict
        for key, value in fields.items():
            # Strip protocol prefix
            attr_name = key.replace("ipp.", "").replace("_", "-")
            if attr_name in attr_map and value:
                if attr_map[attr_name] not in details:
                    details[attr_map[attr_name]] = str(value)

        # Extract printer state as human-readable
        if details.get("printer_state"):
            state_str = str(details["printer_state"])
            details["printer_state_name"] = PRINTER_STATE.get(state_str, state_str)

    def _track_printer_info(
        self, details: Dict[str, Any], server_ip: str, server_port: int, server_mac: str
    ) -> None:
        """Track printer information from IPP responses."""
        printer_uri = details.get("printer_uri", "")
        if not printer_uri:
            printer_uri = f"ipp://{server_ip}:{server_port}"

        if printer_uri not in self.printers:
            self.printers[printer_uri] = {}

        info = self.printers[printer_uri]
        for key in (
            "printer_name",
            "printer_make_and_model",
            "printer_info",
            "printer_location",
            "printer_state_name",
            "document_formats",
        ):
            if details.get(key):
                info[key] = details[key]
        info["server_ip"] = server_ip
        info["server_port"] = server_port

    # -------------------------------------------------------------------------
    # Device tracking
    # -------------------------------------------------------------------------

    def _update_server_device(self, server_ip: str, server_port: int, server_mac: str = "") -> None:
        """Update or create IPP server (printer/CUPS) device entry."""
        if not is_valid_discovered_ip(server_ip):
            return

        device_key = f"ipp-server:{server_ip}"
        vendor = lookup_mac_vendor(server_mac) if server_mac else ""

        # Find printer info for this server
        printer_name = ""
        printer_model = ""
        for uri, info in self.printers.items():
            if info.get("server_ip") == server_ip:
                printer_name = info.get("printer_name", "")
                printer_model = info.get("printer_make_and_model", "")
                break

        name = printer_name or f"IPP Printer ({server_ip})"
        device_type = printer_model or "Network Printer"

        device, is_new = self._ensure_device(
            device_key,
            server_ip,
            mac=server_mac,
            name=name,
            device_type=device_type,
            manufacturer=vendor if vendor != "Unknown" else "",
        )

        protocol_data: Dict[str, Any] = {
            "role": "server",
            "port": server_port,
            "protocol": "IPP/TCP",
        }
        if printer_name:
            protocol_data["printer_name"] = printer_name
        if printer_model:
            protocol_data["printer_model"] = printer_model

        # Collect all printer URIs for this server
        uris = [uri for uri, info in self.printers.items() if info.get("server_ip") == server_ip]
        if uris:
            protocol_data["printer_uris"] = uris

        device.ipp_passive_data = protocol_data

    def _update_client_device(self, client_ip: str, server_ip: str, client_mac: str = "") -> None:
        """Update or create IPP client device entry."""
        if not is_valid_discovered_ip(client_ip):
            return

        device_key = f"ipp-client:{client_ip}"
        vendor = lookup_mac_vendor(client_mac) if client_mac else ""

        device, is_new = self._ensure_device(
            device_key,
            client_ip,
            mac=client_mac,
            name=f"IPP Client ({client_ip})",
            device_type="Print Client",
            manufacturer=vendor if vendor != "Unknown" else "",
        )

        if is_new:
            device.ipp_passive_data = {
                "role": "client",
                "servers_accessed": [server_ip],
                "protocol": "IPP/TCP",
            }
        else:
            if device.ipp_passive_data:
                servers = device.ipp_passive_data.get("servers_accessed", [])
                if server_ip not in servers:
                    servers.append(server_ip)
                    device.ipp_passive_data["servers_accessed"] = servers

    # -------------------------------------------------------------------------
    # Harvest
    # -------------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data with printer discovery tables."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}

        tables = result.setdefault("tables", [])

        # Printer discovery table
        if self.printers:
            rows = []
            for uri, info in sorted(self.printers.items()):
                name = info.get("printer_name", "-")
                model = info.get("printer_make_and_model", "-")
                location = info.get("printer_location", "-")
                state = info.get("printer_state_name", "-")
                rows.append([info.get("server_ip", "?"), name, model, location, state])
            if rows:
                tables.append(
                    {
                        "headers": ["Server", "Printer Name", "Model", "Location", "State"],
                        "rows": rows,
                        "title": f"IPP Printers ({len(rows)})",
                    }
                )

        # Print jobs table -- surfaces requesting user names and document
        # titles captured from Print-Job / Create-Job requests.  These were
        # collected in process_packet() but previously never rendered, so all
        # job/user attribution was lost from the scanner output.
        if self.print_jobs:
            job_rows = []
            for job in self.print_jobs:
                job_rows.append(
                    [
                        job.get("client_ip", "?"),
                        job.get("server_ip", "?"),
                        job.get("user", "") or "?",
                        job.get("job_name", "") or "?",
                        job.get("printer_uri", "") or "-",
                    ]
                )
            tables.append(
                {
                    "headers": ["Client", "Server", "User", "Job Name", "Printer URI"],
                    "rows": job_rows,
                    "title": f"IPP Print Jobs ({len(job_rows)})",
                }
            )

        return result
