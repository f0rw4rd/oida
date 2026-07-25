"""
DICOM Reporting Mixin

Handles host info enumeration, display, security analysis, and export.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..nxc_connection import DICOM_VENDOR_MAP
from oida.utils.common_types import Category

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class ReportingMixin(_ScannerBase):
    """Mixin providing reporting and analysis for the DICOM scanner."""

    def enum_host_info(self):
        """Perform C-ECHO verification and extract server implementation info"""
        if not self.assoc or not self.assoc.is_established:
            self.logger.fail("No active association")
            return

        # Extract implementation info from association
        try:
            impl_class_uid = str(self.assoc.acceptor.implementation_class_uid or "")
            impl_version = str(self.assoc.acceptor.implementation_version_name or "")

            self.results["data"]["implementation_class_uid"] = impl_class_uid
            self.results["data"]["implementation_version"] = impl_version

            # Try to identify vendor from Implementation Class UID
            vendor_name, vendor_desc = self._identify_vendor(impl_class_uid)
            if vendor_name:
                self.results["data"]["vendor"] = vendor_name
                self.results["data"]["vendor_description"] = vendor_desc

            # Extract additional protocol parameters
            # Max PDU size
            max_pdu = getattr(self.assoc.acceptor, "maximum_length", None)
            if max_pdu:
                self.results["data"]["max_pdu_size"] = max_pdu

            # Accepted presentation contexts
            contexts = []
            transfer_syntaxes = set()
            if hasattr(self.assoc, "accepted_contexts"):
                for cx in self.assoc.accepted_contexts:
                    # Handle transfer_syntax - could be UID object or list
                    ts = cx.transfer_syntax
                    if hasattr(ts, "__iter__") and not isinstance(ts, str):
                        # It's a list/tuple of UIDs - take the first one
                        ts_str = str(ts[0]) if ts else ""
                    else:
                        # Single UID object - get string representation of UID name
                        ts_str = str(ts.name) if hasattr(ts, "name") else str(ts)
                    ctx_info = {
                        "abstract_syntax": str(cx.abstract_syntax),
                        "transfer_syntax": ts_str,
                    }
                    contexts.append(ctx_info)
                    if ts_str:
                        transfer_syntaxes.add(ts_str)

            self.results["data"]["accepted_contexts"] = contexts
            self.results["data"]["transfer_syntaxes"] = sorted(transfer_syntaxes)

            # User identity negotiation (indicates if auth is required)
            user_identity = getattr(self.assoc.acceptor, "user_identity", None)
            self.results["data"]["user_identity_required"] = bool(user_identity)

            # Asynchronous operations window
            async_ops = getattr(self.assoc.acceptor, "asynchronous_operations", None)
            if async_ops:
                self.results["data"]["async_operations"] = {
                    "max_invoked": async_ops[0] if isinstance(async_ops, tuple) else None,
                    "max_performed": async_ops[1] if isinstance(async_ops, tuple) else None,
                }

        except Exception as e:
            self.logger.debug(f"Could not extract implementation info: {e}")

        # Perform C-ECHO
        try:
            status = self.assoc.send_c_echo()
            if status and status.Status == 0x0000:
                self.results["data"]["c_echo"] = "Success"
                self.logger.success("C-ECHO: Success (DICOM service available)")
            else:
                self.results["data"]["c_echo"] = (
                    f"Failed (status: {status.Status if status else 'None'})"
                )
                self.logger.warning("C-ECHO: Failed")
        except Exception as e:
            self.results["data"]["c_echo"] = f"Error: {e}"
            self.logger.debug(f"C-ECHO error: {e}")

    def _identify_vendor(self, impl_class_uid: str) -> tuple:
        """
        Identify vendor from Implementation Class UID.

        Args:
            impl_class_uid: The Implementation Class UID from the DICOM association

        Returns:
            Tuple of (vendor_name, vendor_description) or (None, None) if unknown
        """
        if not impl_class_uid:
            return (None, None)

        # Try exact match first
        if impl_class_uid in DICOM_VENDOR_MAP:
            return DICOM_VENDOR_MAP[impl_class_uid]

        # Try prefix matching (UIDs are hierarchical) — longest prefix first
        # so specific entries like "1.2.840.113619.6" beat "1.2.840.113619"
        for prefix in sorted(DICOM_VENDOR_MAP, key=len, reverse=True):
            if impl_class_uid.startswith(prefix):
                return DICOM_VENDOR_MAP[prefix]

        return (None, None)

    def print_host_info(self):
        """Display discovered DICOM endpoint info"""
        data = self.results.get("data", {})

        if data.get("connected"):
            self.logger.display(f"  Calling AET: {data.get('calling_aet', 'Unknown')}")
            self.logger.display(f"  Called AET: {data.get('called_aet', 'Unknown')}")

            # Display implementation/version info
            impl_uid = data.get("implementation_class_uid", "")
            impl_ver = data.get("implementation_version", "")
            vendor = data.get("vendor", "")

            if impl_uid or impl_ver:
                self.logger.display(f"  Implementation UID: {impl_uid or 'N/A'}")
                self.logger.display(f"  Implementation Version: {impl_ver or 'N/A'}")
                if vendor:
                    self.logger.success(
                        f"  Vendor: {vendor} ({data.get('vendor_description', '')})"
                    )

            # Display PDU and context info
            max_pdu = data.get("max_pdu_size")
            if max_pdu:
                self.logger.display(f"  Max PDU Size: {max_pdu} bytes")

            contexts = data.get("accepted_contexts", [])
            if contexts:
                self.logger.display(f"  Presentation Contexts: {len(contexts)} accepted")

                # Map abstract syntax UIDs to operation names
                op_map = {
                    # Verification
                    "1.2.840.10008.1.1": "C-ECHO",
                    # Patient Root Query/Retrieve
                    "1.2.840.10008.5.1.4.1.2.1.1": "C-FIND (Patient)",
                    "1.2.840.10008.5.1.4.1.2.1.2": "C-MOVE (Patient)",
                    "1.2.840.10008.5.1.4.1.2.1.3": "C-GET (Patient)",
                    # Study Root Query/Retrieve
                    "1.2.840.10008.5.1.4.1.2.2.1": "C-FIND (Study)",
                    "1.2.840.10008.5.1.4.1.2.2.2": "C-MOVE (Study)",
                    "1.2.840.10008.5.1.4.1.2.2.3": "C-GET (Study)",
                    # Patient/Study Only
                    "1.2.840.10008.5.1.4.1.2.3.1": "C-FIND (Patient/Study)",
                    # Composite Instance
                    "1.2.840.10008.5.1.4.1.2.4.2": "C-MOVE (Composite)",
                    "1.2.840.10008.5.1.4.1.2.4.3": "C-GET (Composite)",
                    "1.2.840.10008.5.1.4.1.2.5.3": "C-GET (No Bulk)",
                    # Modality Worklist
                    "1.2.840.10008.5.1.4.31": "Worklist (MWL)",
                    # MPPS
                    "1.2.840.10008.3.1.2.3.3": "MPPS",
                    # Storage Commitment
                    "1.2.840.10008.1.20.1": "Storage Commit",
                    # Print Management
                    "1.2.840.10008.5.1.1.9": "Print (Grayscale)",
                    "1.2.840.10008.5.1.1.18": "Print (Color)",
                    "1.2.840.10008.5.1.1.16": "Printer",
                    "1.2.840.10008.5.1.1.16.376": "Printer Config",
                    # Unified Procedure Step (UPS)
                    "1.2.840.10008.5.1.4.34.6.1": "UPS Push",
                    "1.2.840.10008.5.1.4.34.6.2": "UPS Watch",
                    "1.2.840.10008.5.1.4.34.6.3": "UPS Pull",
                    "1.2.840.10008.5.1.4.34.6.5": "UPS Query",
                    # Instance Availability
                    "1.2.840.10008.5.1.4.33": "Instance Avail",
                    # Hanging Protocol
                    "1.2.840.10008.5.1.4.38.1": "Hanging Protocol",
                    "1.2.840.10008.5.1.4.38.2": "Hanging FIND",
                    "1.2.840.10008.5.1.4.38.3": "Hanging MOVE",
                    "1.2.840.10008.5.1.4.38.4": "Hanging GET",
                    # Color Palette
                    "1.2.840.10008.5.1.4.39.1": "Color Palette",
                    "1.2.840.10008.5.1.4.39.2": "Palette FIND",
                    "1.2.840.10008.5.1.4.39.3": "Palette MOVE",
                    "1.2.840.10008.5.1.4.39.4": "Palette GET",
                    # Display System
                    "1.2.840.10008.5.1.1.40": "Display System",
                    # Defined Procedure Protocol
                    "1.2.840.10008.5.1.4.20.1": "Procedure FIND",
                    "1.2.840.10008.5.1.4.20.2": "Procedure MOVE",
                    "1.2.840.10008.5.1.4.20.3": "Procedure GET",
                    # Protocol Approval
                    "1.2.840.10008.5.1.4.1.1.200.3": "Protocol Approval",
                    "1.2.840.10008.5.1.4.1.1.200.4": "Approval FIND",
                    "1.2.840.10008.5.1.4.1.1.200.5": "Approval MOVE",
                    "1.2.840.10008.5.1.4.1.1.200.6": "Approval GET",
                    # Generic Implant Template
                    "1.2.840.10008.5.1.4.43.1": "Implant Template",
                    "1.2.840.10008.5.1.4.43.2": "Implant FIND",
                    "1.2.840.10008.5.1.4.43.3": "Implant MOVE",
                    "1.2.840.10008.5.1.4.43.4": "Implant GET",
                    # Inventory
                    "1.2.840.10008.5.1.4.1.1.201.1": "Inventory",
                    "1.2.840.10008.5.1.4.1.1.201.2": "Inventory FIND",
                    "1.2.840.10008.5.1.4.1.1.201.3": "Inventory MOVE",
                    "1.2.840.10008.5.1.4.1.1.201.4": "Inventory GET",
                    "1.2.840.10008.5.1.4.1.1.201.5": "Inventory Create",
                    # Relevant Patient Information
                    "1.2.840.10008.5.1.4.37.1": "Relevant Patient",
                    "1.2.840.10008.5.1.4.37.2": "Breast Imaging",
                    "1.2.840.10008.5.1.4.37.3": "Cardiac Info",
                    # Media Creation
                    "1.2.840.10008.5.1.1.33": "Media Creation",
                    # Substance
                    "1.2.840.10008.5.1.4.41": "Substance Query",
                }

                supported_ops = []
                storage_count = 0
                for ctx in contexts:
                    abstract = ctx.get("abstract_syntax", "")
                    if abstract in op_map:
                        op_name = op_map[abstract]
                        if op_name not in supported_ops:
                            supported_ops.append(op_name)
                    elif abstract.startswith("1.2.840.10008.5.1.4.1.1"):
                        # Storage SOP classes
                        storage_count += 1

                if storage_count > 0:
                    supported_ops.append(f"C-STORE ({storage_count} SOP classes)")

                if supported_ops:
                    ops_str = ", ".join(supported_ops)
                    # Add hint if only basic operations negotiated and we haven't probed yet
                    probe_ops = getattr(self.args, "probe_ops", False)
                    if not probe_ops and not any(
                        x in ops_str for x in ["C-GET", "C-MOVE", "C-STORE"]
                    ):
                        ops_str += " (use --probe-ops to discover all)"
                    self.logger.display(f"  Supported Operations: {ops_str}")
                    self.results["data"]["supported_operations"] = supported_ops

            transfer_syntaxes = data.get("transfer_syntaxes", [])
            if transfer_syntaxes:
                # Map UIDs and pynetdicom names to short names
                ts_map = {
                    # UID mappings
                    "1.2.840.10008.1.2": "Implicit VR LE",
                    "1.2.840.10008.1.2.1": "Explicit VR LE",
                    "1.2.840.10008.1.2.2": "Explicit VR BE",
                    "1.2.840.10008.1.2.4.50": "JPEG Baseline",
                    "1.2.840.10008.1.2.4.51": "JPEG Extended",
                    "1.2.840.10008.1.2.4.57": "JPEG Lossless",
                    "1.2.840.10008.1.2.4.70": "JPEG Lossless SV1",
                    "1.2.840.10008.1.2.4.80": "JPEG-LS Lossless",
                    "1.2.840.10008.1.2.4.81": "JPEG-LS Lossy",
                    "1.2.840.10008.1.2.4.90": "JPEG 2000 Lossless",
                    "1.2.840.10008.1.2.4.91": "JPEG 2000",
                    "1.2.840.10008.1.2.5": "RLE Lossless",
                    "1.2.840.10008.1.2.1.99": "Deflated Explicit VR LE",
                    # pynetdicom name mappings
                    "Implicit VR Little Endian": "Implicit VR LE",
                    "Explicit VR Little Endian": "Explicit VR LE",
                    "Explicit VR Big Endian": "Explicit VR BE",
                }
                ts_names = []
                for ts in transfer_syntaxes:
                    ts_str = str(ts)
                    if ts_str in ts_map:
                        ts_names.append(ts_map[ts_str])
                    elif "JPEG" in ts_str:
                        ts_names.append("JPEG")
                    elif "RLE" in ts_str:
                        ts_names.append("RLE")
                    else:
                        ts_names.append(ts_str[:30])  # Use as-is or truncate long names
                self.logger.display(f"  Transfer Syntaxes: {', '.join(ts_names)}")

            # User identity info
            user_identity = data.get("user_identity_required", False)
            self.logger.display(
                f"  User Identity: {'Required' if user_identity else 'Not required'}"
            )

            # Async operations
            async_ops = data.get("async_operations")
            if async_ops:
                max_inv = async_ops.get("max_invoked", "N/A")
                max_perf = async_ops.get("max_performed", "N/A")
                self.logger.display(f"  Async Operations: Invoked={max_inv}, Performed={max_perf}")

    def _export_results(self):
        """Export query results using central export_data() utility"""
        from ....utils.export_utils import export_data

        output_dir = getattr(self.args, "output", None)
        if not output_dir:
            return  # No export requested

        fmt = getattr(self.args, "format", "json")
        # Don't print tables to console - data already shown during scan
        file_fmt = fmt.replace("console", "").replace("all", "csv,json").strip(",") or "json"

        data = self.results.get("data", {})
        # proto_args registers --port with default=None, so getattr's default
        # is never used (the attribute exists, just equals None) -- resolve
        # the effective port the same way create_conn_obj()/enumeration.py do,
        # or every exported row's port column comes out blank/None.
        use_tls = getattr(self.args, "tls", False)
        port = getattr(self.args, "port", None) or (2762 if use_tls else self.default_port)

        # Export C-FIND results. The columns must match the query level: a
        # PATIENT-level query never carries StudyDate/Modality/StudyInstanceUID,
        # so hard-coding study columns would export blank cells and drop the
        # patient demographics actually retrieved.
        cfind = data.get("cfind_results", {})
        results = cfind.get("results", [])
        if results:
            query_level = (cfind.get("query_level") or "PATIENT").upper()
            # (column label, result-dict key) per query level
            level_columns = {
                "PATIENT": [
                    ("PatientName", "PatientName"),
                    ("PatientID", "PatientID"),
                    ("BirthDate", "PatientBirthDate"),
                    ("Sex", "PatientSex"),
                    ("StudyCount", "StudyCount"),
                ],
                "STUDY": [
                    ("PatientName", "PatientName"),
                    ("PatientID", "PatientID"),
                    ("StudyDate", "StudyDate"),
                    ("StudyDescription", "StudyDescription"),
                    ("AccessionNumber", "AccessionNumber"),
                    ("StudyUID", "StudyInstanceUID"),
                ],
                "SERIES": [
                    ("Modality", "Modality"),
                    ("SeriesNumber", "SeriesNumber"),
                    ("SeriesDescription", "SeriesDescription"),
                    ("InstanceCount", "InstanceCount"),
                    ("SeriesUID", "SeriesInstanceUID"),
                ],
                "IMAGE": [
                    ("InstanceNumber", "InstanceNumber"),
                    ("SOPClassUID", "SOPClassUID"),
                    ("SOPInstanceUID", "SOPInstanceUID"),
                ],
            }
            columns = level_columns.get(query_level, level_columns["PATIENT"])
            headers = ["Host", "Port"] + [label for label, _ in columns]
            rows = [
                [self.ip, port] + [str(r.get(key, ""))[:64] for _, key in columns] for r in results
            ]
            export_data(rows, headers, file_fmt, output_dir, "dicom_cfind", logger=self.logger)

        # Export server info
        if data.get("connected"):
            headers = ["Host", "Port", "AET", "Vendor", "Version", "MaxPDU", "Operations"]
            rows = [
                [
                    self.ip,
                    port,
                    self.called_aet,
                    data.get("vendor", ""),
                    data.get("implementation_version", ""),
                    str(data.get("max_pdu_size", "")),
                    ", ".join(data.get("supported_operations", [])),
                ]
            ]
            export_data(rows, headers, file_fmt, output_dir, "dicom_server", logger=self.logger)

        # Export enumerated devices/modalities (--enum-devices)
        devices = data.get("devices", {})
        if devices:
            headers = ["Host", "Port", "Modalities", "Stations", "Manufacturers", "Institutions"]
            rows = [
                [
                    self.ip,
                    port,
                    ", ".join(devices.get("modalities", [])),
                    ", ".join(devices.get("stations", [])),
                    ", ".join(devices.get("manufacturers", [])),
                    ", ".join(devices.get("institutions", [])),
                ]
            ]
            export_data(rows, headers, file_fmt, output_dir, "dicom_devices", logger=self.logger)

        # Security findings are exported via self.logger.findings (populated by security_finding())

    def _analyze_security(self):
        """Analyze DICOM endpoint security"""
        data = self.results.get("data", {})

        # Check if association established without strict AET
        if data.get("connected"):
            if self.calling_aet in ["ANY", "*", "ANYSCU", "OIDA"]:
                self.logger.security_finding(
                    "Weak AET whitelist",
                    category=Category.AUTHENTICATION,
                    detail=f"Server accepted non-specific AE Title: {self.calling_aet}",
                )

        # Check AET brute force results
        aet_brute = data.get("aet_brute", {})
        if aet_brute.get("valid", []):
            if len(aet_brute["valid"]) > 5:
                self.logger.security_finding(
                    "Permissive AET policy",
                    category=Category.AUTHENTICATION,
                    detail=f"Server accepts {len(aet_brute['valid'])} different AE Titles",
                )

        # Check wildcard query results
        cfind = data.get("cfind_results", {})
        if cfind.get("query", {}).get("PatientName") == "*" and cfind.get("count", 0) > 0:
            self.logger.security_finding(
                "Unrestricted query access",
                category=Category.ACCESS_CONTROL,
                detail=f"Wildcard query returned {cfind['count']} patient records",
            )

        # Check C-GET results
        cget = data.get("cget_results", {})
        if cget.get("files_retrieved", 0) > 0:
            self.logger.security_finding(
                "Unrestricted image retrieval",
                category=Category.ACCESS_CONTROL,
                detail=f"Retrieved {cget['files_retrieved']} images via C-GET",
            )

        # Check C-STORE results
        cstore = data.get("cstore_results", {})
        if cstore.get("files_uploaded", 0) > 0:
            self.logger.security_finding(
                "Unrestricted upload",
                category=Category.ACCESS_CONTROL,
                detail=f"Server accepted {cstore['files_uploaded']} file uploads",
            )

        # Check C-MOVE results
        cmove = data.get("cmove_results", {})
        if cmove.get("completed", 0) > 0:
            self.logger.security_finding(
                "Open transfer policy",
                category=Category.ACCESS_CONTROL,
                detail=f"Transferred {cmove['completed']} images to external AET '{cmove.get('dest_aet', '')}'",
            )

        # Personnel exposure (from --enum-operators)
        personnel = data.get("personnel", {})
        named_personnel = sum(
            len(personnel.get(k, []))
            for k in (
                "operators",
                "performing_physicians",
                "referring_physicians",
                "reading_physicians",
                "requesting_physicians",
            )
        )
        if named_personnel > 0:
            self.logger.security_finding(
                "Personnel exposure",
                category=Category.INFO_DISCLOSURE,
                detail=f"{named_personnel} staff names (operators/physicians) readable via metadata",
            )

        # Excessive data retention (from --time-analysis)
        time_analysis = data.get("time_analysis", {})
        retention_days = time_analysis.get("retention_days", 0)
        if retention_days > 365 * 10:
            self.logger.security_finding(
                "Excessive data retention",
                category=Category.INFO_DISCLOSURE,
                detail=f"{retention_days // 365} years of historical PHI retained (oldest: {time_analysis.get('oldest_study', '')})",
            )

        # No TLS
        if not getattr(self.args, "tls", False):
            self.logger.security_finding(
                "No encryption",
                category=Category.ENCRYPTION,
                detail="DICOM traffic transmitted in plaintext (PHI exposure)",
            )
