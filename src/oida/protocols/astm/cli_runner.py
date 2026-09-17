"""
ASTM/LIS NXC Connection

NXC-style callable class that composes mixins for ASTM scanning.
"""

from typing import Any, Dict, Optional

from ...connection import NetworkConnection
from ...utils.protocol_helpers import ConnectionHelper
from .records import (
    ASTMRecordBuilder,
    ENQ,
    ACK,
    identify_vendor_from_name,
)
from .mixins import FramingMixin, RecordsMixin, EnumerationMixin, SecurityMixin


class astm(FramingMixin, RecordsMixin, EnumerationMixin, SecurityMixin, NetworkConnection):
    """ASTM/LIS E1381/E1394 Scanner (NXC-style)"""

    # Class-level default so the connection-1 false-positive gate works on any
    # construction path, including harnesses that bypass __init__. Defaults to
    # False so an uninitialized gate fails safe (claims no success) rather than
    # raising AttributeError.
    _astm_response_seen: bool = False

    name = "ASTM"
    protocol_name = "astm"
    # 12000 is the most common ASTM/LIS instrument port (Sysmex/Abbott default).
    # Other vendors use 5000 (Roche), 6000 (Beckman Coulter), 9100 (Siemens).
    # The previous default (1394) was a misread of the ASTM "E1394" standard
    # name — IEEE-1394 is FireWire, not ASTM. Override with --port for the
    # vendor-specific value when needed.
    default_port = 12000

    def __init__(self, args: Any, db: Optional[Any], host: str):
        self.record_builder: Optional[ASTMRecordBuilder] = None
        self.detected_analyzer: Optional[str] = None
        self.frame_number: int = 1
        # P1 false-positive guard: only a real ASTM analyzer ACKs our ENQ.
        # A bare TCP connect to a silent/non-ASTM port must not report success.
        self._astm_response_seen: bool = False
        super().__init__(args, db, host)

    def proto_flow(self):
        """Main ASTM scanning workflow"""

        # Initialize record builder
        version = getattr(self.args, "astm_version", "E1394")
        self.record_builder = ASTMRecordBuilder(version=version)

        # Create connection
        if not self.create_conn_obj():
            # Closed/refused port is not an ASTM device — do not report success.
            self.results["success"] = False
            self.results.setdefault("error", "Connection failed")
            return

        # Probe operations if requested (runs before other operations)
        if getattr(self.args, "probe_ops", False):
            self._probe_operations()
            self._astm_response_gate()
            self._analyze_security()
            self._export_results()
            self._disconnect()
            return

        # Enumerate host info (ENQ/ACK test + header exchange)
        self.enum_host_info()
        self._astm_response_gate()
        self.print_host_info()

        # Record operations based on args
        if getattr(self.args, "send_query", False):
            self._send_query_record()

        if getattr(self.args, "send_patient", False):
            if self.require_confirm(
                "--send-patient",
                detail="--send-patient injects forged Patient demographics into the LIS — "
                "requires --confirm",
            ):
                self._send_patient_record()

        if getattr(self.args, "send_order", False):
            if self.require_confirm(
                "--send-order",
                detail="Order records require --confirm flag (dangerous operation)",
            ):
                self._send_order_record()

        if getattr(self.args, "send_result", False):
            if self.require_confirm(
                "--send-result",
                detail="Result records require --confirm flag (dangerous operation)",
            ):
                self._send_result_record()

        if getattr(self.args, "fuzz", False):
            if self.require_confirm("--fuzz", detail="Fuzzing requires --confirm flag"):
                self._fuzz_records()

        # Enumeration features
        if getattr(self.args, "enum_tests", False):
            self._enum_tests()

        if getattr(self.args, "enum_instruments", False):
            self._enum_instruments()

        if getattr(self.args, "enum_patients", False):
            if self.require_confirm(
                "--confirm", detail="Patient enumeration requires --confirm flag (PHI access)"
            ):
                self._enum_patients()

        # Analyze security
        self._analyze_security()

        # Export results if requested
        self._export_results()

        # Cleanup
        self._disconnect()

    def _astm_response_gate(self):
        """P1 false-positive guard.

        A bare TCP connect succeeds against any listening socket, including
        silent or non-ASTM services. Only a real ASTM analyzer answers our
        ENQ with an ACK (tracked via self._astm_response_seen). If we never
        saw that, mark the scan unsuccessful so identification is not faked.
        """
        if not self._astm_response_seen:
            self.results["success"] = False
            self.results.setdefault("error", "No valid ASTM response (ENQ/ACK handshake failed)")

    def create_conn_obj(self) -> bool:
        """Establish TCP connection (optionally with TLS)"""
        timeout = getattr(self.args, "timeout", 10)
        use_tls = getattr(self.args, "tls", False)

        port = getattr(self.args, "port", self.default_port)

        try:
            # The central helper forwards all four TLS flags to build_tls_context
            # (a supplied --tls-ca triggers CERT_REQUIRED + hostname verification),
            # so there is no need for a local TLS path.
            self.conn = ConnectionHelper.create_tls_tcp_connection(
                self.ip,
                port,
                timeout=timeout,
                use_tls=use_tls,
                tls_cert=getattr(self.args, "tls_cert", None),
                tls_key=getattr(self.args, "tls_key", None),
                tls_ca=getattr(self.args, "tls_ca", None),
                tls_insecure=getattr(self.args, "tls_insecure", False),
                protocol="astm",
                endpoint_label="ASTM endpoint",
                logger=self.logger,
            )
            self.results["data"]["connected"] = True
            self.results["data"]["tls_enabled"] = use_tls
            return True

        except Exception as e:  # noqa: BLE001 — report any connect failure and move to the next host
            self.logger.debug("create conn obj failed: %s", e)
            if isinstance(e, TimeoutError):
                self.logger.fail("Connection timed out")
            elif isinstance(e, ConnectionRefusedError):
                self.logger.fail("Connection refused")
            else:
                self.logger.fail(f"Connection failed: {e}")
            self.results["data"]["connected"] = False
            return False

    def enum_host_info(self):
        """Test ASTM connection with ENQ/ACK handshake and header exchange"""
        if self.record_builder is None:
            return
        # Step 1: ENQ/ACK handshake
        if not self._send_enq():
            self.logger.warning("ENQ/ACK handshake failed")
            return

        self.logger.success("ENQ/ACK handshake successful")

        # Step 2: Send header record
        sender_name = getattr(self.args, "sender_name", "OIDA") or "OIDA"
        sender_id = getattr(self.args, "sender_id", "") or ""
        receiver_name = getattr(self.args, "receiver_name", "") or ""
        receiver_id = getattr(self.args, "receiver_id", "") or ""

        header = self.record_builder.build_header(
            sender_name=sender_name,
            sender_id=sender_id,
            receiver_name=receiver_name,
            receiver_id=receiver_id,
        )

        # Send header frame
        if self._send_frame(header):
            self.logger.success("Header record accepted")
            self.results["data"]["header_accepted"] = True
            # Try to identify server from any response
            self._identify_server()
        else:
            self.logger.warning("Header record rejected")
            self.results["data"]["header_accepted"] = False

        # Step 3: Send terminator
        terminator = self.record_builder.build_terminator()
        self._send_frame(terminator)

        # Step 4: End transmission
        self._send_eot()

    def _identify_server(self):
        """Try to identify the ASTM server/analyzer from responses or probing"""
        if not self.conn:
            return

        try:
            if not self._send_enq():
                return

            header = self.record_builder.build_header(sender_name="OIDA")
            self._send_frame(header)

            query = self.record_builder.build_query(starting_range="*")
            self._send_frame(query)

            # Send terminator to complete our transmission first
            terminator = self.record_builder.build_terminator()
            self._send_frame(terminator)
            self._send_eot()

            # Now wait for server response (server sends after we finish)
            self.conn.settimeout(2)
            try:
                data = self._buf_recv(1)
                if data == ENQ:
                    # Server wants to send data - ACK and receive full response
                    self.conn.sendall(ACK)
                    self._receive_server_response()
            except TimeoutError as e:
                self.logger.debug("identify server failed: %s", e)

            # Reset timeout
            timeout = getattr(self.args, "timeout", 10)
            self.conn.settimeout(timeout)

        except Exception as e:
            self.logger.debug("identify server failed: %s", e)

    def _receive_server_response(self):
        """Receive server response frames and extract analyzer info.

        Delegates the actual wire parsing to FramingMixin._read_frames_until_eot,
        which buffers across recv() calls so frames coalesced into one recv() (or
        split across several) are all parsed, checksum-validated, and ACKed/NAKed
        individually instead of only the first one being seen.
        """
        if not self.conn:
            return

        try:
            frames = self._read_frames_until_eot(timeout=2)
            for frame_bytes in frames:
                self._extract_analyzer_info(frame_bytes)
        except Exception as e:
            self.logger.debug("receive server response failed: %s", e)

    def _extract_analyzer_info(self, data: bytes):
        """Extract analyzer info from received data"""
        try:
            text = data.decode("utf-8", errors="ignore")

            # Look for header record pattern: H|...|SenderName^Vendor|...
            if "H|" in text:
                # Find header record. The record proper ends at whichever of
                # CR (record terminator) or ETX (frame terminator) comes
                # first - a well-formed frame has CR immediately before ETX,
                # so stopping at ETX alone would leave a trailing "\r" stuck
                # on the last field.
                h_start = text.find("H|")
                etx_pos = text.find("\x03", h_start)
                cr_pos = text.find("\x0d", h_start)
                candidates = [p for p in (etx_pos, cr_pos) if p != -1]
                h_end = min(candidates) if candidates else len(text)

                header_record = text[h_start:h_end]
                fields = header_record.split("|")

                analyzer_info: Dict[str, str] = {}

                # Field 5 contains sender info (e.g., "COBAS_8000^Roche^8.1.2")
                if len(fields) > 4 and fields[4]:
                    sender = fields[4]
                    parts = sender.split("^")

                    analyzer_info["name"] = parts[0]
                    if len(parts) > 1:
                        analyzer_info["vendor"] = parts[1]
                    if len(parts) > 2:
                        analyzer_info["version"] = parts[2]

                    # Try vendor lookup if vendor not in response
                    if "vendor" not in analyzer_info:
                        match = identify_vendor_from_name(parts[0])
                        if match:
                            analyzer_info["vendor"], analyzer_info["product"] = match

                # Field 9 (H-9): Sender/analyzer characteristics
                if len(fields) > 8 and fields[8]:
                    analyzer_info["characteristics"] = fields[8]

                # Field 12 (H-12): Processing ID (P=Production, D=Debug, T=Training)
                if len(fields) > 11 and fields[11]:
                    analyzer_info["processing_id"] = fields[11]

                # Field 13 (H-13): Version Number (may contain software version)
                if len(fields) > 12 and fields[12]:
                    version_field = fields[12]
                    if "-" in version_field and "version" not in analyzer_info:
                        # Format: E1394-8.1.2
                        analyzer_info["version"] = version_field.split("-", 1)[1]
                    elif "version" not in analyzer_info:
                        analyzer_info["version"] = version_field

                if analyzer_info:
                    self.results["data"]["analyzer_info"] = analyzer_info
                    self.detected_analyzer = analyzer_info.get("name")

        except Exception as e:
            self.logger.debug("extract analyzer info failed: %s", e)

    def print_host_info(self):
        """Display discovered ASTM endpoint info"""
        data = self.results.get("data", {})

        if data.get("connected"):
            if data.get("header_accepted"):
                self.logger.display("  ASTM Protocol: Header exchange successful")
            else:
                self.logger.warning(
                    "  ASTM Protocol: Header rejected (NAK received - check sender name/ID or analyzer compatibility)"
                )

        if data.get("analyzer_info"):
            info = data["analyzer_info"]
            # Build analyzer line with version if available
            analyzer_str = info.get("name", "Unknown")
            if info.get("version"):
                analyzer_str += f" v{info['version']}"
            self.logger.display(f"  Analyzer: {analyzer_str}")

            if info.get("vendor"):
                vendor_str = info["vendor"]
                if info.get("product"):
                    vendor_str += f" ({info['product']})"
                if info.get("type"):
                    vendor_str += f" [{info['type']}]"
                self.logger.display(f"  Vendor: {vendor_str}")

        if data.get("tls_enabled"):
            self.logger.display("  Encryption: TLS enabled")
        else:
            self.logger.security_finding(
                "No encryption",
                detail="ASTM communication is unencrypted (plaintext)",
            )

    def _export_results(self):
        """Export results if output requested"""
        output_dir = getattr(self.args, "output", None)
        if not output_dir:
            return

        from oida.utils.export_utils import export_json

        export_json(self.results, output_dir, "astm_results.json", logger=self.logger)

    def _disconnect(self):
        """Close ASTM connection"""
        if self.conn:
            try:
                self.conn.close()
            except Exception as e:
                self.logger.debug("disconnect failed: %s", e)
            self.conn = None
