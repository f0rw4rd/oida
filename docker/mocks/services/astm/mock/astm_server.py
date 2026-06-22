#!/usr/bin/env python3
"""
Mock ASTM/LIS Server for testing OIDA ASTM scanner

Supports:
- ENQ/ACK handshake
- Frame validation with checksum
- H/P/O/R/C/Q/L record handling
- Mock analyzer data for fingerprinting
- Mock patient/test data for enumeration testing

Environment variables:
- ASTM_PORT: Server port (default: 1394)
- ASTM_ANALYZER: Analyzer name (default: COBAS_8000)
- ASTM_ACCEPT_ALL: Accept all record types (default: true)

Usage:
    python astm_server.py
    ASTM_PORT=1395 ASTM_ANALYZER=XN-2000 python astm_server.py
"""

import logging
import os
import socket
import socketserver
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ASTM framing constants
STX = b"\x02"
ETX = b"\x03"
EOT = b"\x04"
ENQ = b"\x05"
ACK = b"\x06"
NAK = b"\x15"
ETB = b"\x17"
CR = b"\x0d"
LF = b"\x0a"

# Configuration from environment
SERVER_PORT = int(os.environ.get("ASTM_PORT", "1394"))
SERVER_ANALYZER = os.environ.get("ASTM_ANALYZER", "COBAS_8000")
ACCEPT_ALL = os.environ.get("ASTM_ACCEPT_ALL", "true").lower() == "true"

# Mock analyzers
MOCK_ANALYZERS = [
    {"name": "COBAS_8000", "vendor": "Roche", "type": "Chemistry", "version": "8.1.2"},
    {"name": "XN-2000", "vendor": "Sysmex", "type": "Hematology", "version": "5.0.3"},
    {"name": "CLINITEK_500", "vendor": "Siemens", "type": "Urinalysis", "version": "3.2.1"},
    {"name": "VITROS_5600", "vendor": "Ortho Clinical", "type": "Chemistry", "version": "7.0.1"},
    {"name": "ACCESS_2", "vendor": "Beckman Coulter", "type": "Immunoassay", "version": "2.5.0"},
]

# Mock test types
MOCK_TESTS = [
    {"code": "GLU", "name": "Glucose", "units": "mg/dL", "range": "70-100"},
    {"code": "CBC", "name": "Complete Blood Count", "units": "", "range": ""},
    {"code": "BMP", "name": "Basic Metabolic Panel", "units": "", "range": ""},
    {"code": "CMP", "name": "Comprehensive Metabolic Panel", "units": "", "range": ""},
    {"code": "HBA1C", "name": "Hemoglobin A1c", "units": "%", "range": "<5.7"},
    {"code": "WBC", "name": "White Blood Cell", "units": "10^3/uL", "range": "4.5-11.0"},
    {"code": "HGB", "name": "Hemoglobin", "units": "g/dL", "range": "12.0-17.5"},
    {"code": "PLT", "name": "Platelet", "units": "10^3/uL", "range": "150-400"},
    {"code": "PT", "name": "Prothrombin Time", "units": "sec", "range": "11-13.5"},
    {"code": "INR", "name": "INR", "units": "", "range": "0.8-1.1"},
    {"code": "TSH", "name": "TSH", "units": "mIU/L", "range": "0.4-4.0"},
    {"code": "T4", "name": "Thyroxine", "units": "ug/dL", "range": "4.5-12.0"},
    {"code": "CHOL", "name": "Total Cholesterol", "units": "mg/dL", "range": "<200"},
    {"code": "TRIG", "name": "Triglycerides", "units": "mg/dL", "range": "<150"},
]

# Mock patients
MOCK_PATIENTS = [
    {"id": "P001", "name": "DOE^JOHN^M", "dob": "19800101", "sex": "M", "mrn": "MRN001"},
    {"id": "P002", "name": "SMITH^JANE^A", "dob": "19750515", "sex": "F", "mrn": "MRN002"},
    {"id": "P003", "name": "WILSON^ROBERT^T", "dob": "19651220", "sex": "M", "mrn": "MRN003"},
    {"id": "P004", "name": "JOHNSON^MARY^L", "dob": "19900308", "sex": "F", "mrn": "MRN004"},
    {"id": "P005", "name": "BROWN^DAVID^K", "dob": "19550712", "sex": "M", "mrn": "MRN005"},
]

# Mock orders/samples
MOCK_ORDERS = [
    {"sample_id": "S001", "patient_id": "P001", "test": "GLU", "status": "pending"},
    {"sample_id": "S002", "patient_id": "P001", "test": "CBC", "status": "completed"},
    {"sample_id": "S003", "patient_id": "P002", "test": "BMP", "status": "pending"},
    {"sample_id": "S004", "patient_id": "P003", "test": "HBA1C", "status": "completed"},
    {"sample_id": "S005", "patient_id": "P004", "test": "TSH", "status": "pending"},
]


def calculate_checksum(data: bytes) -> bytes:
    """Calculate modulus-256 checksum as 2-char hex"""
    total = sum(data) % 256
    return f"{total:02X}".encode()


def get_timestamp() -> str:
    """Get current timestamp in ASTM format"""
    return datetime.now().strftime("%Y%m%d%H%M%S")


class ASTMHandler(socketserver.BaseRequestHandler):
    """Handle ASTM client connections"""

    def setup(self):
        """Initialize connection state"""
        self.frame_number = 1
        self.in_transmission = False
        self.current_records = []

    def handle(self):
        """Handle client connection"""
        client_addr = self.client_address[0]
        log.info(f"Connection from {client_addr}")

        try:
            while True:
                data = self.request.recv(1024)
                if not data:
                    break

                self._process_data(data)

        except ConnectionResetError:
            log.info(f"Connection reset by {client_addr}")
        except Exception as e:
            log.error(f"Error handling {client_addr}: {e}")
        finally:
            log.info(f"Connection closed: {client_addr}")

    def _process_data(self, data: bytes):
        """Process received ASTM data"""
        log.debug(f"Received: {data!r}")

        # Handle control characters
        if data == ENQ:
            self._handle_enq()
        elif data == EOT:
            self._handle_eot()
        elif data.startswith(STX):
            self._handle_frame(data)
        else:
            log.debug(f"Unknown data: {data!r}")

    def _handle_enq(self):
        """Handle ENQ (enquiry) - start of transmission"""
        log.info("Received ENQ")
        self.in_transmission = True
        self.current_records = []
        self.request.sendall(ACK)
        log.info("Sent ACK")

    def _handle_eot(self):
        """Handle EOT (end of transmission)"""
        log.info("Received EOT - end of transmission")
        self.in_transmission = False
        self.frame_number = 1

        # Process collected records and send responses AFTER client's transmission ends
        if self.current_records:
            pending_queries = self._process_message()
            self.current_records = []

            # Send responses for any queries (now that client finished)
            if pending_queries:
                import time

                time.sleep(0.05)  # Brief delay before responding
                for query_record in pending_queries:
                    self._send_query_response(query_record)

    def _handle_frame(self, data: bytes):
        """Handle ASTM frame"""
        if not self.in_transmission:
            log.warning("Frame received outside transmission")
            self.request.sendall(NAK)
            return

        try:
            # Parse frame: STX + frame_num + record + ETX/ETB + checksum + CR + LF
            if not data.startswith(STX):
                log.warning("Invalid frame: missing STX")
                self.request.sendall(NAK)
                return

            # Strip STX
            frame_data = data[1:]

            # Find end marker (ETX or ETB)
            etx_pos = frame_data.find(ETX)
            etb_pos = frame_data.find(ETB)

            if etx_pos == -1 and etb_pos == -1:
                log.warning("Invalid frame: missing ETX/ETB")
                self.request.sendall(NAK)
                return

            end_pos = etx_pos if etx_pos != -1 else etb_pos
            is_intermediate = etb_pos != -1 and (etx_pos == -1 or etb_pos < etx_pos)

            # Extract frame content
            frame_content = frame_data[: end_pos + 1]

            # Validate checksum
            if len(frame_data) > end_pos + 3:
                received_checksum = frame_data[end_pos + 1 : end_pos + 3]
                calculated_checksum = calculate_checksum(frame_content)

                if received_checksum != calculated_checksum:
                    log.warning(
                        f"Checksum mismatch: {received_checksum!r} vs {calculated_checksum!r}"
                    )
                    self.request.sendall(NAK)
                    return

            # Extract record data (skip frame number, remove end marker)
            record_data = frame_content[1:-1].decode("utf-8", errors="ignore")
            log.info(f"Received record: {record_data[:80]}...")

            # Store record
            self.current_records.append(record_data)

            # Accept frame FIRST (before any response)
            self.frame_number += 1
            self.request.sendall(ACK)
            log.info("Sent ACK for frame")

            # Note: Query responses are now sent AFTER EOT (when client finishes)

        except Exception as e:
            log.error(f"Frame processing error: {e}")
            self.request.sendall(NAK)

    def _process_message(self) -> list:
        """Process complete ASTM message, return list of pending queries"""
        log.info(f"Processing message with {len(self.current_records)} records")
        pending_queries = []

        for record in self.current_records:
            record_type = record[0] if record else ""
            log.info(f"Record type: {record_type}")

            if record_type == "H":
                self._handle_header_record(record)
            elif record_type == "P":
                self._handle_patient_record(record)
            elif record_type == "O":
                self._handle_order_record(record)
            elif record_type == "R":
                self._handle_result_record(record)
            elif record_type == "Q":
                pending_queries.append(record)  # Collect for response after EOT
            elif record_type == "C":
                self._handle_comment_record(record)
            elif record_type == "L":
                self._handle_terminator_record(record)

        return pending_queries

    def _handle_header_record(self, record: str):
        """Handle H (Header) record"""
        fields = record.split("|")
        log.info(f"Header record: sender={fields[4] if len(fields) > 4 else 'unknown'}")

    def _handle_patient_record(self, record: str):
        """Handle P (Patient) record"""
        fields = record.split("|")
        patient_id = fields[2] if len(fields) > 2 else ""
        log.info(f"Patient record: ID={patient_id}")

    def _handle_order_record(self, record: str):
        """Handle O (Order) record"""
        fields = record.split("|")
        sample_id = fields[2] if len(fields) > 2 else ""
        test_id = fields[4] if len(fields) > 4 else ""
        priority = fields[5] if len(fields) > 5 else ""
        action_code = fields[11] if len(fields) > 11 else "N"

        action_desc = {
            "N": "NEW",
            "A": "ADD",
            "C": "CANCEL",
            "P": "PENDING",
            "R": "REQUEST",
            "X": "DELETE",
        }.get(action_code, action_code)

        log.info(
            f"Order record: sample={sample_id}, test={test_id}, action={action_desc}, priority={priority}"
        )

        if action_code == "C":
            log.warning(f"ORDER CANCELLATION REQUEST for sample={sample_id}")
        elif action_code == "X":
            log.warning(f"ORDER DELETION REQUEST for sample={sample_id}")

    def _handle_result_record(self, record: str):
        """Handle R (Result) record"""
        fields = record.split("|")
        test_id = fields[2] if len(fields) > 2 else ""
        value = fields[3] if len(fields) > 3 else ""
        units = fields[4] if len(fields) > 4 else ""
        ref_range = fields[5] if len(fields) > 5 else ""
        abnormal_flag = fields[6] if len(fields) > 6 else ""
        result_status = fields[8] if len(fields) > 8 else "F"

        status_desc = {
            "P": "PRELIMINARY",
            "F": "FINAL",
            "C": "CORRECTED",
            "X": "CANCELED",
            "I": "INCOMPLETE",
            "S": "PARTIAL",
            "M": "MANUAL",
            "R": "RERUN",
            "N": "NOT_VERIFIED",
            "W": "WRONG",
        }.get(result_status, result_status)

        log.info(
            f"Result record: test={test_id}, value={value} {units}, status={status_desc}, flag={abnormal_flag}"
        )

        if result_status == "C":
            log.warning(f"RESULT CORRECTION for test={test_id}: {value} {units}")
        elif result_status == "X":
            log.warning(f"RESULT DELETION for test={test_id}")

    def _handle_comment_record(self, record: str):
        """Handle C (Comment) record"""
        fields = record.split("|")
        comment = fields[3] if len(fields) > 3 else ""
        log.info(f"Comment record: {comment[:50]}...")

    def _handle_terminator_record(self, record: str):
        """Handle L (Terminator) record"""
        log.info("Terminator record received")

    def _send_query_response(self, query_record: str):
        """Send response to Q (Query) record"""
        log.info("Generating query response...")

        fields = query_record.split("|")
        query_range = fields[2] if len(fields) > 2 else "*"
        query_type = fields[5] if len(fields) > 5 else "A"

        # Build response message
        response_records = []

        # Header with analyzer info including version
        analyzer = next(
            (a for a in MOCK_ANALYZERS if a["name"] == SERVER_ANALYZER), MOCK_ANALYZERS[0]
        )
        # Format: H|delim||password|SenderName^Vendor^Version|...|ReceiverID|ProcessingID|VersionNo|Timestamp
        header = f"H|\\^&|||{analyzer['name']}^{analyzer['vendor']}^{analyzer['version']}|||||||{analyzer['type']}|P|E1394-{analyzer['version']}|{get_timestamp()}"
        response_records.append(header)

        # Based on query type, add data
        if query_type in ["A", "S"]:  # All or demographics
            # Add patient records
            for patient in MOCK_PATIENTS[:3]:
                p_rec = (
                    f"P|1|{patient['id']}||{patient['name']}|||{patient['dob']}|{patient['sex']}"
                )
                response_records.append(p_rec)

        if query_type in ["A", "O"]:  # All or orders
            # Add order records
            for order in MOCK_ORDERS[:3]:
                o_rec = f"O|1|{order['sample_id']}||{order['test']}|R|{get_timestamp()}"
                response_records.append(o_rec)

        if query_type in ["A", "R"]:  # All or results
            # Add some result records
            for i, test in enumerate(MOCK_TESTS[:5]):
                r_rec = f"R|{i + 1}|{test['code']}|100|{test['units']}|{test['range']}|N||F"
                response_records.append(r_rec)

        # Terminator
        response_records.append("L|1|N")

        # Send response
        self._send_response_message(response_records)

    def _send_response_message(self, records: list):
        """Send ASTM response message"""
        log.info(f"Sending response with {len(records)} records")

        # Send ENQ first
        self.request.sendall(ENQ)

        # Wait for ACK
        try:
            ack = self.request.recv(1)
            if ack != ACK:
                log.warning(f"Expected ACK, got {ack!r}")
                return
        except socket.timeout:
            log.warning("Timeout waiting for ACK")
            return

        # Send each record as a frame
        frame_num = 1
        for record in records:
            is_last = record == records[-1]
            self._send_frame(record, frame_num, is_last)
            frame_num = (frame_num % 7) + 1

            # Wait for ACK
            try:
                ack = self.request.recv(1)
                if ack != ACK:
                    log.warning(f"Expected ACK for frame, got {ack!r}")
                    break
            except socket.timeout:
                log.warning("Timeout waiting for frame ACK")
                break

        # Send EOT
        self.request.sendall(EOT)
        log.info("Response complete")

    def _send_frame(self, record: str, frame_num: int, is_last: bool):
        """Send single ASTM frame"""
        end_marker = ETX if is_last else ETB
        frame_num_byte = str(frame_num % 8).encode()
        record_bytes = record.encode("utf-8")

        # Build frame content for checksum
        frame_content = frame_num_byte + record_bytes + end_marker
        checksum = calculate_checksum(frame_content)

        # Full frame
        frame = STX + frame_content + checksum + CR + LF
        self.request.sendall(frame)
        log.debug(f"Sent frame: {record[:50]}...")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded TCP server for handling multiple connections"""

    allow_reuse_address = True
    daemon_threads = True


def main():
    """Start ASTM mock server"""
    log.info(f"Starting ASTM mock server on port {SERVER_PORT}")
    log.info(f"Analyzer: {SERVER_ANALYZER}")
    log.info(f"Accept all records: {ACCEPT_ALL}")

    with ThreadedTCPServer(("0.0.0.0", SERVER_PORT), ASTMHandler) as server:
        log.info(f"Server listening on 0.0.0.0:{SERVER_PORT}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            log.info("Server shutting down...")
            server.shutdown()


if __name__ == "__main__":
    main()
