"""
CAN UDS Mixin

Handles UDS (ISO 14229) service discovery and enumeration:
- UDS ECU discovery via TesterPresent
- UDS response reception
- Service enumeration
- Diagnostic session scanning
- DID (Data Identifier) scanning
- Security seed collection and analysis
- Routine scanning
- ECU reset
- TesterPresent keep-alive
"""

import time
from typing import Any, Dict, List, Optional, Tuple

from ..constants import (
    COMMON_UDS_PAIRS,
    OBD2_REQUEST_ID,
    OBD2_RESPONSE_RANGE,
    UDS_DID_SCAN_DEFAULT_END,
    UDS_DID_SCAN_DEFAULT_START,
    UDS_NEGATIVE_RESPONSE,
    UDS_NRC,
    UDS_POSITIVE_RESPONSE_OFFSET,
    UDS_RESET_TYPES,
    UDS_SERVICES,
    UDS_SESSIONS,
    UDS_STANDARD_DIDS,
    UDSScanResult,
)


def _get_python_can() -> Any:
    """Resolve _python_can from scanner module (avoids circular import)."""
    from ..scanner import _python_can

    return _python_can


class UDSMixin:
    """Mixin providing UDS (ISO 14229) service discovery and enumeration."""

    def _scan_uds(self, bus: Any) -> List[UDSScanResult]:
        """
        Scan for UDS-capable ECUs using TesterPresent (0x3E).

        Sends TesterPresent to known UDS request IDs and listens for responses.

        Args:
            bus: python-can Bus instance

        Returns:
            List of UDSScanResult for each discovered ECU
        """
        can = _get_python_can()()
        results: List[UDSScanResult] = []

        # Build list of request IDs to probe
        probe_ids = list(COMMON_UDS_PAIRS.keys())

        # Also try scanning a wider range if extended scan
        if self.extended:
            # Scan 0x600-0x7FF range for non-standard UDS endpoints
            for arb_id in range(0x600, 0x800):
                if arb_id not in probe_ids:
                    probe_ids.append(arb_id)

        self.logger.display(f"  Probing {len(probe_ids)} arbitration IDs for UDS...")

        for req_id in probe_ids:
            # Send TesterPresent (0x3E, sub-function 0x00 = no response suppression)
            # ISO-TP single frame: [<pci>, <sid>, <sub>]
            tester_present_data = [0x02, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

            try:
                msg = can.Message(
                    arbitration_id=req_id,
                    data=tester_present_data,
                    is_extended_id=False,
                )
                bus.send(msg)
            except Exception as e:
                self.logger.debug(f"Failed to send to 0x{req_id:03X}: {e}")
                continue

            # Listen for response (typical response on req_id + 0x08)
            response = self._recv_uds_response(bus, req_id, timeout=0.1)
            if response is not None:
                resp_id, resp_data = response

                # Check for valid UDS response
                if len(resp_data) >= 2:
                    pci_len = resp_data[0] & 0x0F
                    service_resp = resp_data[1] if pci_len >= 1 else 0

                    if service_resp == (0x3E + UDS_POSITIVE_RESPONSE_OFFSET):
                        # Positive response to TesterPresent
                        self.logger.success(f"UDS ECU found: 0x{req_id:03X} -> 0x{resp_id:03X}")

                        # Enumerate services
                        uds_result = self._enumerate_uds_services(bus, req_id, resp_id)
                        results.append(uds_result)

                    elif service_resp == UDS_NEGATIVE_RESPONSE and len(resp_data) >= 4:
                        nrc = resp_data[3]
                        nrc_name = UDS_NRC.get(nrc, f"Unknown(0x{nrc:02X})")
                        # A negative response still means something is listening
                        self.logger.display(
                            f"  UDS endpoint 0x{req_id:03X} -> 0x{resp_id:03X} (NRC: {nrc_name})"
                        )

        if not results:
            self.logger.display("  No UDS-capable ECUs found")

        return results

    def _recv_uds_response(
        self, bus: Any, request_id: int, timeout: float = 0.1
    ) -> Optional[Tuple[int, bytes]]:
        """
        Receive a UDS response for a given request ID.

        Looks for responses on expected response IDs (request + 0x08 offset,
        or any ID in COMMON_UDS_PAIRS).

        Args:
            bus: python-can Bus instance
            request_id: The arbitration ID the request was sent on
            timeout: Maximum wait time in seconds

        Returns:
            Tuple of (response_id, response_data) or None
        """
        expected_resp = COMMON_UDS_PAIRS.get(request_id, request_id + 0x08)
        end_time = time.time() + timeout

        while time.time() < end_time:
            remaining = end_time - time.time()
            if remaining <= 0:
                break
            msg = bus.recv(timeout=min(remaining, 0.05))
            if msg is None:
                continue

            # Check if this is a response to our request
            if msg.arbitration_id == expected_resp:
                return (msg.arbitration_id, bytes(msg.data))

            # Also check for broadcast responses in the standard range
            if OBD2_RESPONSE_RANGE[0] <= msg.arbitration_id <= OBD2_RESPONSE_RANGE[1]:
                if request_id == OBD2_REQUEST_ID:
                    return (msg.arbitration_id, bytes(msg.data))

        return None

    def _enumerate_uds_services(self, bus: Any, req_id: int, resp_id: int) -> UDSScanResult:
        """
        Enumerate supported UDS services on a discovered ECU.

        Args:
            bus: python-can Bus instance
            req_id: ECU request arbitration ID
            resp_id: ECU response arbitration ID

        Returns:
            UDSScanResult with discovered capabilities
        """
        can = _get_python_can()()
        result = UDSScanResult(request_id=req_id, response_id=resp_id)

        # Probe each known UDS service
        for service_id, service_name in UDS_SERVICES.items():
            # Send service request as single-frame ISO-TP
            if service_id in (0x10,):
                # DiagnosticSessionControl needs a sub-function
                data = [0x02, service_id, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
            elif service_id in (0x27,):
                # SecurityAccess needs odd sub-function for request seed
                data = [0x02, service_id, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
            elif service_id in (0x22,):
                # ReadDataByIdentifier needs a DID (try 0xF190 = VIN)
                data = [0x03, service_id, 0xF1, 0x90, 0x00, 0x00, 0x00, 0x00]
            elif service_id in (0x3E,):
                # TesterPresent
                data = [0x02, service_id, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
            else:
                # Generic single-byte service request
                data = [0x01, service_id, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

            try:
                msg = can.Message(
                    arbitration_id=req_id,
                    data=data,
                    is_extended_id=False,
                )
                bus.send(msg)
            except Exception as e:
                self.logger.debug(f"Failed to send UDS service probe to 0x{req_id:03X}: {e}")
                continue

            response = self._recv_uds_response(bus, req_id, timeout=0.05)
            if response is None:
                continue

            _, resp_data = response
            if len(resp_data) < 2:
                continue

            pci_len = resp_data[0] & 0x0F
            resp_service = resp_data[1] if pci_len >= 1 else 0

            if resp_service == service_id + UDS_POSITIVE_RESPONSE_OFFSET:
                # Service is supported
                result.supported_services.append(service_id)
                self.logger.debug(
                    f"  0x{req_id:03X}: Service 0x{service_id:02X} ({service_name}) supported"
                )

                # Extract extra info from specific services
                if service_id == 0x10 and len(resp_data) >= 4:
                    session = resp_data[2]
                    result.diagnostic_sessions.append(session)

                if service_id == 0x22 and pci_len > 3:
                    # ReadDataByIdentifier response may contain VIN
                    vin_data = resp_data[4 : 4 + pci_len - 3]
                    try:
                        vin = vin_data.decode("ascii", errors="ignore").strip("\x00")
                        if vin:
                            result.vehicle_info["VIN"] = vin
                    except Exception as e:
                        self.logger.debug(f"Failed to decode VIN data: {e}")

            elif resp_service == UDS_NEGATIVE_RESPONSE and len(resp_data) >= 4:
                nrc = resp_data[3]
                result.negative_responses[service_id] = nrc

                # Some NRCs still indicate the service exists but is blocked
                if nrc in (0x22, 0x31, 0x33, 0x35, 0x36, 0x37, 0x7E, 0x7F):
                    # Service exists but conditions/access prevent use
                    result.supported_services.append(service_id)

        # Print summary for this ECU
        if result.supported_services:
            svc_list = [
                f"0x{s:02X}({UDS_SERVICES.get(s, '?')[:12]})"
                for s in sorted(result.supported_services)
            ]
            self.logger.display(
                f"  ECU 0x{req_id:03X}: {len(result.supported_services)} services "
                f"[{', '.join(svc_list[:8])}{'...' if len(svc_list) > 8 else ''}]"
            )

        return result

    def uds_session_scan(self, bus: Any, req_id: int, resp_id: int) -> List[int]:
        """
        Enumerate supported diagnostic sessions on a UDS ECU.

        Tries switching to each known session type (0x01-0x04, plus
        vendor-specific range 0x40-0x7E) and records which are accepted.

        Args:
            bus: python-can Bus instance
            req_id: ECU request arbitration ID
            resp_id: ECU response arbitration ID

        Returns:
            List of supported session IDs
        """
        can = _get_python_can()()
        supported: List[int] = []

        # Standard sessions + vendor-specific range
        session_ids = list(UDS_SESSIONS.keys()) + list(range(0x40, 0x7F))

        self.logger.display(
            f"[UDS Sessions] Probing {len(session_ids)} session types on 0x{req_id:03X}..."
        )

        for session_id in session_ids:
            # DiagnosticSessionControl: [PCI=0x02, SID=0x10, session]
            data = bytes([0x02, 0x10, session_id, 0x00, 0x00, 0x00, 0x00, 0x00])
            try:
                msg = can.Message(arbitration_id=req_id, data=data, is_extended_id=False)
                bus.send(msg)
            except Exception as e:
                self.logger.debug(f"Failed to send session probe 0x{session_id:02X}: {e}")
                continue

            resp = self._recv_uds_response(bus, req_id, timeout=0.1)
            if resp is None:
                continue

            _, resp_data = resp
            if len(resp_data) < 2:
                continue

            resp_service = resp_data[1]

            if resp_service == 0x10 + UDS_POSITIVE_RESPONSE_OFFSET:
                session_name = UDS_SESSIONS.get(session_id, f"VendorSpecific(0x{session_id:02X})")
                self.logger.display(f"  Session 0x{session_id:02X}: {session_name} -- supported")
                supported.append(session_id)

                # Switch back to default session to not leave ECU in odd state
                reset_data = bytes([0x02, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
                try:
                    msg = can.Message(arbitration_id=req_id, data=reset_data, is_extended_id=False)
                    bus.send(msg)
                    self._recv_uds_response(bus, req_id, timeout=0.05)
                except Exception as e:
                    self.logger.debug(f"Failed to reset to default session: {e}")

            elif resp_service == UDS_NEGATIVE_RESPONSE and len(resp_data) >= 4:
                nrc = resp_data[3]
                # 0x7E = subFunctionNotSupportedInActiveSession (still means service exists)
                if nrc in (0x22, 0x33, 0x7E, 0x7F):
                    session_name = UDS_SESSIONS.get(
                        session_id, f"VendorSpecific(0x{session_id:02X})"
                    )
                    nrc_name = UDS_NRC.get(nrc, f"0x{nrc:02X}")
                    self.logger.display(
                        f"  Session 0x{session_id:02X}: {session_name} -- blocked ({nrc_name})"
                    )
                    supported.append(session_id)

        if not supported:
            self.logger.display("  No diagnostic sessions responded")

        return supported

    def uds_did_scan(
        self,
        bus: Any,
        req_id: int,
        resp_id: int,
        did_range: Optional[Tuple[int, int]] = None,
    ) -> Dict[int, bytes]:
        """
        Scan ReadDataByIdentifier (0x22) across a DID range.

        Args:
            bus: python-can Bus instance
            req_id: ECU request arbitration ID
            resp_id: ECU response arbitration ID
            did_range: (start_did, end_did) range to scan.
                       Defaults to standard F-DID range 0xF180-0xF19F.

        Returns:
            Dict mapping DID -> response data bytes
        """
        can = _get_python_can()()
        readable_dids: Dict[int, bytes] = {}

        if did_range is None:
            start_did = UDS_DID_SCAN_DEFAULT_START
            end_did = UDS_DID_SCAN_DEFAULT_END
        else:
            start_did, end_did = did_range

        total = end_did - start_did + 1
        self.logger.display(
            f"[UDS DIDs] Scanning {total} DIDs "
            f"(0x{start_did:04X}-0x{end_did:04X}) on 0x{req_id:03X}..."
        )

        for did in range(start_did, end_did + 1):
            did_hi = (did >> 8) & 0xFF
            did_lo = did & 0xFF
            # ReadDataByIdentifier: [PCI=0x03, SID=0x22, DID_hi, DID_lo]
            data = bytes([0x03, 0x22, did_hi, did_lo, 0x00, 0x00, 0x00, 0x00])

            try:
                msg = can.Message(arbitration_id=req_id, data=data, is_extended_id=False)
                bus.send(msg)
            except Exception as e:
                self.logger.debug(f"Failed to send DID read 0x{did:04X}: {e}")
                continue

            resp = self._recv_uds_response(bus, req_id, timeout=0.1)
            if resp is None:
                continue

            _, resp_data = resp
            if len(resp_data) < 2:
                continue

            resp_service = resp_data[1]

            if resp_service == 0x22 + UDS_POSITIVE_RESPONSE_OFFSET:
                # Positive response: [PCI, 0x62, DID_hi, DID_lo, data...]
                pci_len = resp_data[0] & 0x0F
                did_data = resp_data[4 : 4 + max(0, pci_len - 3)] if pci_len > 3 else b""
                readable_dids[did] = did_data
                did_name = UDS_STANDARD_DIDS.get(did, f"DID 0x{did:04X}")

                # Try to decode as ASCII if printable
                try:
                    text = did_data.decode("ascii", errors="ignore").strip("\x00")
                    if text and all(32 <= ord(c) < 127 for c in text):
                        display = text
                    else:
                        display = " ".join(f"{b:02X}" for b in did_data)
                except Exception:
                    display = " ".join(f"{b:02X}" for b in did_data)

                self.logger.display(f"  0x{did:04X} ({did_name}): {display}")

        self.logger.display(f"  {len(readable_dids)} readable DIDs found")
        return readable_dids

    def uds_security_seed_collect(
        self,
        bus: Any,
        req_id: int,
        resp_id: int,
        security_level: int = 0x01,
        count: int = 10,
    ) -> List[bytes]:
        """
        Collect SecurityAccess (0x27) seeds for randomness analysis.

        Requests seed at the given security level N times, collecting
        the seed bytes returned. Useful for analyzing seed randomness
        and detecting weak seed generators.

        Args:
            bus: python-can Bus instance
            req_id: ECU request arbitration ID
            resp_id: ECU response arbitration ID
            security_level: Odd sub-function for requestSeed (default 0x01)
            count: Number of seeds to collect

        Returns:
            List of seed byte arrays
        """
        can = _get_python_can()()
        seeds: List[bytes] = []

        self.logger.display(
            f"[UDS Seeds] Collecting {count} seeds at level 0x{security_level:02X} "
            f"on 0x{req_id:03X}..."
        )

        for i in range(count):
            # SecurityAccess requestSeed: [PCI=0x02, SID=0x27, level]
            data = bytes([0x02, 0x27, security_level, 0x00, 0x00, 0x00, 0x00, 0x00])

            try:
                msg = can.Message(arbitration_id=req_id, data=data, is_extended_id=False)
                bus.send(msg)
            except Exception as e:
                self.logger.debug(f"Failed to send seed request #{i + 1}: {e}")
                continue

            resp = self._recv_uds_response(bus, req_id, timeout=0.2)
            if resp is None:
                continue

            _, resp_data = resp
            if len(resp_data) < 2:
                continue

            resp_service = resp_data[1]

            if resp_service == 0x27 + UDS_POSITIVE_RESPONSE_OFFSET:
                pci_len = resp_data[0] & 0x0F
                seed_data = resp_data[3 : 3 + max(0, pci_len - 2)] if pci_len > 2 else b""
                seeds.append(seed_data)

            elif resp_service == UDS_NEGATIVE_RESPONSE and len(resp_data) >= 4:
                nrc = resp_data[3]
                nrc_name = UDS_NRC.get(nrc, f"0x{nrc:02X}")
                if nrc == 0x37:
                    # RequiredTimeDelayNotExpired - wait and retry
                    self.logger.debug(f"  Seed #{i + 1}: time delay, waiting...")
                    time.sleep(1.0)
                    continue
                if nrc == 0x36:
                    self.logger.warning(f"  Exceeded number of attempts at seed #{i + 1}")
                    break
                self.logger.debug(f"  Seed #{i + 1}: NRC={nrc_name}")

            # Small delay between requests to avoid flooding
            time.sleep(0.05)

        if seeds:
            # Print basic entropy analysis
            self._print_seed_analysis(seeds)
        else:
            self.logger.display("  No seeds collected")

        return seeds

    def _print_seed_analysis(self, seeds: List[bytes]) -> None:
        """Print basic analysis of collected security seeds."""
        self.logger.display(f"  Collected {len(seeds)} seeds")

        if not seeds:
            return

        seed_len = len(seeds[0])
        self.logger.display(f"  Seed length: {seed_len} bytes")

        # Check for duplicates
        unique_seeds = set(s.hex() for s in seeds)
        dup_count = len(seeds) - len(unique_seeds)
        if dup_count > 0:
            self.logger.warning(f"  DUPLICATE seeds found: {dup_count}/{len(seeds)}")
        else:
            self.logger.display(f"  All seeds unique: {len(unique_seeds)}/{len(seeds)}")

        # Check for all-zero seeds (bypass possible)
        zero_seeds = sum(1 for s in seeds if all(b == 0 for b in s))
        if zero_seeds > 0:
            self.logger.warning(
                f"  ALL-ZERO seeds: {zero_seeds}/{len(seeds)} (security bypass may be possible)"
            )

        # Check for incrementing pattern
        if len(seeds) >= 3 and seed_len >= 2:
            ints = [int.from_bytes(s[:2], "big") for s in seeds]
            diffs = [ints[i + 1] - ints[i] for i in range(len(ints) - 1)]
            if len(set(diffs)) == 1 and diffs[0] != 0:
                self.logger.warning(f"  SEQUENTIAL seeds detected (increment={diffs[0]})")

        # Show first few seeds
        for i, seed in enumerate(seeds[:5]):
            self.logger.display(f"    Seed #{i + 1}: {' '.join(f'{b:02X}' for b in seed)}")
        if len(seeds) > 5:
            self.logger.display(f"    ... ({len(seeds) - 5} more)")

    def uds_routine_scan(
        self,
        bus: Any,
        req_id: int,
        resp_id: int,
        routine_range: Optional[Tuple[int, int]] = None,
    ) -> List[int]:
        """
        Discover available UDS routines via RoutineControl (0x31).

        Sends startRoutine (sub-function 0x01) for each routine ID and
        checks if the ECU responds positively or with a meaningful NRC.

        Args:
            bus: python-can Bus instance
            req_id: ECU request arbitration ID
            resp_id: ECU response arbitration ID
            routine_range: (start, end) routine ID range. Default 0x0000-0x00FF.

        Returns:
            List of discovered routine IDs
        """
        can = _get_python_can()()
        discovered: List[int] = []

        if routine_range is None:
            start_routine, end_routine = 0x0000, 0x00FF
        else:
            start_routine, end_routine = routine_range

        total = end_routine - start_routine + 1
        self.logger.display(
            f"[UDS Routines] Scanning {total} routine IDs "
            f"(0x{start_routine:04X}-0x{end_routine:04X}) on 0x{req_id:03X}..."
        )

        for routine_id in range(start_routine, end_routine + 1):
            rid_hi = (routine_id >> 8) & 0xFF
            rid_lo = routine_id & 0xFF
            # RoutineControl startRoutine: [PCI=0x04, SID=0x31, sub=0x01, rid_hi, rid_lo]
            data = bytes([0x04, 0x31, 0x01, rid_hi, rid_lo, 0x00, 0x00, 0x00])

            try:
                msg = can.Message(arbitration_id=req_id, data=data, is_extended_id=False)
                bus.send(msg)
            except Exception as e:
                self.logger.debug(f"UDS: RoutineControl CAN frame send failed: {e}")
                continue

            resp = self._recv_uds_response(bus, req_id, timeout=0.05)
            if resp is None:
                continue

            _, resp_data = resp
            if len(resp_data) < 2:
                continue

            resp_service = resp_data[1]

            if resp_service == 0x31 + UDS_POSITIVE_RESPONSE_OFFSET:
                discovered.append(routine_id)
                self.logger.display(f"  Routine 0x{routine_id:04X}: available (positive response)")
            elif resp_service == UDS_NEGATIVE_RESPONSE and len(resp_data) >= 4:
                nrc = resp_data[3]
                # These NRCs indicate the routine exists but cannot run right now
                if nrc in (0x22, 0x31, 0x33, 0x7E, 0x7F):
                    discovered.append(routine_id)
                    nrc_name = UDS_NRC.get(nrc, f"0x{nrc:02X}")
                    self.logger.display(f"  Routine 0x{routine_id:04X}: exists ({nrc_name})")

        self.logger.display(f"  {len(discovered)} routines discovered")
        return discovered

    def uds_ecu_reset(
        self,
        bus: Any,
        req_id: int,
        resp_id: int,
        reset_type: int = 0x01,
    ) -> bool:
        """
        Send ECU Reset (0x11) command. Requires --confirm flag.

        Args:
            bus: python-can Bus instance
            req_id: ECU request arbitration ID
            resp_id: ECU response arbitration ID
            reset_type: Reset sub-function (0x01=hard, 0x02=keyOffOn, 0x03=soft)

        Returns:
            True if ECU acknowledged the reset
        """
        can = _get_python_can()()
        reset_name = UDS_RESET_TYPES.get(reset_type, f"0x{reset_type:02X}")

        self.logger.display(f"[UDS Reset] Sending ECUReset ({reset_name}) to 0x{req_id:03X}...")

        # ECUReset: [PCI=0x02, SID=0x11, sub_function]
        data = bytes([0x02, 0x11, reset_type, 0x00, 0x00, 0x00, 0x00, 0x00])

        try:
            msg = can.Message(arbitration_id=req_id, data=data, is_extended_id=False)
            bus.send(msg)
        except Exception as e:
            self.logger.fail(f"Failed to send ECUReset: {e}")
            return False

        resp = self._recv_uds_response(bus, req_id, timeout=0.5)
        if resp is None:
            self.logger.display("  No response (ECU may have reset)")
            return True  # No response can mean successful reset

        _, resp_data = resp
        if len(resp_data) >= 2:
            if resp_data[1] == 0x11 + UDS_POSITIVE_RESPONSE_OFFSET:
                self.logger.success(f"  ECU reset acknowledged ({reset_name})")
                return True
            elif resp_data[1] == UDS_NEGATIVE_RESPONSE and len(resp_data) >= 4:
                nrc = resp_data[3]
                nrc_name = UDS_NRC.get(nrc, f"0x{nrc:02X}")
                self.logger.fail(f"  ECU reset rejected: {nrc_name}")
                return False

        return False

    def uds_tester_present_keepalive(
        self, bus: Any, req_id: int, suppress_response: bool = True
    ) -> bool:
        """
        Send a single TesterPresent (0x3E) keep-alive message.

        Args:
            bus: python-can Bus instance
            req_id: ECU request arbitration ID
            suppress_response: If True, use sub-function 0x80 (no response needed)

        Returns:
            True if message was sent
        """
        can = _get_python_can()()
        sub_func = 0x80 if suppress_response else 0x00
        data = bytes([0x02, 0x3E, sub_func, 0x00, 0x00, 0x00, 0x00, 0x00])
        try:
            msg = can.Message(arbitration_id=req_id, data=data, is_extended_id=False)
            bus.send(msg)
            return True
        except Exception as e:
            self.logger.debug(f"UDS: TesterPresent CAN frame send failed: {e}")
            return False
