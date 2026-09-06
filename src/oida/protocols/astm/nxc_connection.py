"""
ASTM/LIS NXC Connection

NXC-style callable class that composes mixins for ASTM scanning.
"""

from typing import Any, Dict, Optional

from ...connection import NetworkConnection
from ...utils.protocol_helpers import ConnectionHelper
from .records import (
    ASTMRecordBuilder,
    STX,
    EOT,
    ENQ,
    ACK,
    CR,
    LF,
    ASTM_VENDOR_MAP,
)
from .mixins import FramingMixin, RecordsMixin, EnumerationMixin, SecurityMixin
from oida.utils.common_types import Category


class astm(FramingMixin, RecordsMixin, EnumerationMixin, SecurityMixin, NetworkConnection):
    """ASTM/LIS E1381/E1394 Scanner (NXC-style)"""

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
        super().__init__(args, db, host)

    def proto_flow(self):
        """Main ASTM scanning workflow"""

        # Initialize record builder
        version = getattr(self.args, "astm_version", "E1394")
        self.record_builder = ASTMRecordBuilder(version=version)

        # Create connection
        if not self.create_conn_obj():
            return

        # Probe operations if requested (runs before other operations)
        if getattr(self.args, "probe_ops", False):
            self._probe_operations()
            self._analyze_security()
            self._export_results()
            self._disconnect()
            return

        # Enumerate host info (ENQ/ACK test + header exchange)
        self.enum_host_info()
        self.print_host_info()

        # Record operations based on args
        if getattr(self.args, "send_query", False):
            self._send_query_record()

        if getattr(self.args, "send_patient", False):
            if not getattr(self.args, "confirm", False):
                self.logger.fail(
                    "--send-patient injects forged Patient demographics into the LIS — "
                    "requires --confirm"
                )
            else:
                self._send_patient_record()

        if getattr(self.args, "send_order", False):
            if not getattr(self.args, "confirm", False):
                self.logger.fail("Order records require --confirm flag (dangerous operation)")
            else:
                self._send_order_record()

        if getattr(self.args, "send_result", False):
            if not getattr(self.args, "confirm", False):
                self.logger.fail("Result records require --confirm flag (dangerous operation)")
            else:
                self._send_result_record()

        if getattr(self.args, "fuzz", False):
            if not getattr(self.args, "confirm", False):
                self.logger.fail("Fuzzing requires --confirm flag")
            else:
                self._fuzz_records()

        # Enumeration features
        if getattr(self.args, "enum_tests", False):
            self._enum_tests()

        if getattr(self.args, "enum_instruments", False):
            self._enum_instruments()

        if getattr(self.args, "enum_patients", False):
            if not getattr(self.args, "confirm", False):
                self.logger.fail("Patient enumeration requires --confirm flag (PHI access)")
            else:
                self._enum_patients()

        # Analyze security
        self._analyze_security()

        # Export results if requested
        self._export_results()

        # Cleanup
        self._disconnect()

    def create_conn_obj(self) -> bool:
        """Establish TCP connection (optionally with TLS)"""
        timeout = getattr(self.args, "timeout", 10)
        use_tls = getattr(self.args, "tls", False)

        # The shared create_tls_tcp_connection() helper only forwards
        # tls-cert/tls-key, so --tls-ca / --tls-insecure would be silently
        # dropped and the server certificate never verified (PHI MITM risk).
        # Build the TLS socket here instead so all four flags are honored.
        tls_ca = getattr(self.args, "tls_ca", None)
        tls_insecure = getattr(self.args, "tls_insecure", False)

        port = getattr(self.args, "port", self.default_port)

        try:
            if use_tls:
                self.conn = self._create_tls_connection(
                    port, timeout, tls_ca=tls_ca, tls_insecure=tls_insecure
                )
            else:
                self.conn = ConnectionHelper.create_tls_tcp_connection(
                    self.ip,
                    port,
                    timeout=timeout,
                    use_tls=False,
                    protocol="astm",
                    endpoint_label="ASTM endpoint",
                    logger=self.logger,
                )
            self.results["data"]["connected"] = True
            self.results["data"]["tls_enabled"] = use_tls
            return True

        except TimeoutError as e:
            self.logger.debug("create conn obj failed: %s", e)
            self.logger.fail("Connection timed out")
            self.results["data"]["connected"] = False
            return False
        except ConnectionRefusedError as e:
            self.logger.debug("create conn obj failed: %s", e)
            self.logger.fail("Connection refused")
            self.results["data"]["connected"] = False
            return False
        except Exception as e:
            self.logger.debug("create conn obj failed: %s", e)
            self.logger.fail(f"Connection failed: {e}")
            self.results["data"]["connected"] = False
            return False

    def _create_tls_connection(self, port, timeout, *, tls_ca=None, tls_insecure=False):
        """Wrap a TCP socket in TLS, honoring --tls-ca / --tls-insecure.

        Unlike the shared create_tls_tcp_connection() helper (which only
        forwards tls-cert/tls-key), this passes the CA bundle and insecure flag
        through to build_tls_context() so a supplied --tls-ca actually triggers
        CERT_REQUIRED server verification.
        """
        from ...utils.socket_helpers import build_tls_context

        self.logger.info(f"Connecting to {self.ip}:{port}")
        sock = ConnectionHelper.create_tcp_socket(self.ip, port, timeout=timeout)
        try:
            ssl_context = build_tls_context(
                {
                    "tls-cert": getattr(self.args, "tls_cert", None),
                    "tls-key": getattr(self.args, "tls_key", None),
                    "tls-ca": tls_ca,
                    "tls-insecure": tls_insecure,
                },
                logger=self.logger,
            )
            if tls_ca and not tls_insecure:
                ssl_context.check_hostname = True
            tls_sock = ssl_context.wrap_socket(sock, server_hostname=self.ip)
        except Exception:
            sock.close()
            raise

        try:
            cert_der = tls_sock.getpeercert(binary_form=True)
            if cert_der:
                from ...utils.security_findings import display_cert_info

                display_cert_info(
                    logger=self.logger,
                    cert=cert_der,
                    protocol="astm",
                    target=f"{self.ip}:{port}",
                    verbose=True,
                )
        except Exception as e:
            self.logger.debug(f"Certificate check failed: {e}")

        self.logger.success(f"Connected to ASTM endpoint at {self.ip}:{port} (TLS)")
        return tls_sock

    def enum_host_info(self):
        """Test ASTM connection with ENQ/ACK handshake and header exchange"""
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
                data = self.conn.recv(1)
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
        """Receive server response frames and extract analyzer info"""
        if not self.conn:
            return

        MAX_FRAMES = 100
        MAX_FRAME_SIZE = 64 * 1024  # 64KB per frame (ASTM frames are small)
        try:
            self.conn.settimeout(2)
            for _frame_count in range(MAX_FRAMES):
                # Receive frame data
                frame_data = bytearray()
                while True:
                    chunk = self.conn.recv(1024)
                    if not chunk:
                        break
                    frame_data.extend(chunk)
                    if len(frame_data) > MAX_FRAME_SIZE:
                        self.logger.debug(
                            "Frame data exceeded %d bytes, truncating", MAX_FRAME_SIZE
                        )
                        break
                    # Check if we have complete frame (ends with CR LF) or EOT
                    if CR + LF in frame_data or EOT in frame_data:
                        break

                if not frame_data:
                    break

                frame_bytes = bytes(frame_data)

                # Check for EOT - end of server transmission
                if frame_bytes == EOT or frame_bytes.endswith(EOT):
                    # Extract info from any data before EOT
                    if len(frame_bytes) > 1:
                        self._extract_analyzer_info(frame_bytes)
                    break

                # Parse frame and send ACK. ACK every received data frame (not
                # only those whose STX landed in this chunk) so a strict
                # analyzer that waits for a per-frame ACK before sending the
                # next frame doesn't stall.
                if STX in frame_bytes:
                    self._extract_analyzer_info(frame_bytes)
                self.conn.sendall(ACK)

        except Exception as e:
            self.logger.debug("receive server response failed: %s", e)

    def _extract_analyzer_info(self, data: bytes):
        """Extract analyzer info from received data"""
        try:
            text = data.decode("utf-8", errors="ignore")

            # Look for header record pattern: H|...|SenderName^Vendor|...
            if "H|" in text:
                # Find header record
                h_start = text.find("H|")
                h_end = text.find("\x03", h_start)  # ETX
                if h_end == -1:
                    h_end = text.find("\x0d", h_start)  # CR
                if h_end == -1:
                    h_end = len(text)

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
                        name_upper = parts[0].upper()
                        for pattern, (vendor, product) in ASTM_VENDOR_MAP.items():
                            if pattern in name_upper:
                                analyzer_info["vendor"] = vendor
                                analyzer_info["product"] = product
                                break

                # Field 12: Analyzer type (Chemistry, Hematology, etc.)
                if len(fields) > 11 and fields[11]:
                    analyzer_info["type"] = fields[11]

                # Field 14: Protocol version (may contain software version)
                if len(fields) > 13 and fields[13]:
                    version_field = fields[13]
                    if "-" in version_field and "version" not in analyzer_info:
                        # Format: E1394-8.1.2
                        analyzer_info["version"] = version_field.split("-", 1)[1]

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
                category=Category.ENCRYPTION,
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
