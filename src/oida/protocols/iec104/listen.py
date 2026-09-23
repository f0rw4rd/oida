"""
IEC 104 Listen/Monitor Mode Mixin

Provides ASDU parsing, monitor callbacks, and listen mode for IEC 104 TCP.
"""

from typing import Dict, Any, Set, Tuple, Optional
from datetime import datetime
import struct
import json
import time

from oida.protocols.iec104.constants import (
    IEC104_TYPE_IDS,
    IEC104_COT,
    CapturedASDU,
    ListenStats,
    ASDU_CA_OFFSET,
    ASDU_COT_OFFSET,
    ASDU_DATA_OFFSET,
    ASDU_HEADER_SIZE,
    ASDU_IOA_OFFSET,
    ASDU_TYPE_ID_OFFSET,
    COT_ACTIVATION,
    COT_ACTIVATION_CONFIRM,
    COT_SPONTANEOUS,
    COT_VALUE_MASK,
    DIQ_DPI_MASK,
    IFRAME_MASK,
    IOA_SIZE,
    NORMALIZED_SCALE,
    QDS_BL,
    QDS_IV,
    QDS_NT,
    QDS_OV,
    QDS_SB,
    SIQ_SPI_MASK,
    VTI_TRANSIENT,
    VTI_VALUE_MASK,
)


class ListenMixin:
    """Mixin providing IEC 104 listen/monitor mode functionality.

    Expects the host class to provide:
        - self.logger
        - self._lock
        - self._captured_asdus, self._listen_stats, self._stop_listen
        - self._listen_output_fh
        - self.listen_mode, self.listen_time, self.listen_output
        - self.listen_raw, self.listen_filter
        - self.debug
    """

    def _parse_type_filter(self, filter_str: Optional[str]) -> Optional[Set[int]]:
        """Parse comma-separated type ID filter string"""
        if not filter_str:
            return None
        try:
            return set(int(t.strip()) for t in filter_str.split(","))
        except ValueError:
            self.logger.warning(f"Invalid type filter: {filter_str}")
            return None

    def _parse_asdu_value(self, type_id: int, data: bytes) -> Tuple[Any, str]:
        """Parse value and quality from ASDU data based on type ID"""
        if not data:
            return None, ""

        try:
            # Single-point information (Type 1, 30)
            if type_id in [1, 30]:
                siq = data[0]
                value = bool(siq & SIQ_SPI_MASK)
                quality = self._parse_quality_flags(siq, check_ov=False)
                return value, quality

            # Double-point information (Type 3, 31)
            elif type_id in [3, 31]:
                diq = data[0]
                value = diq & DIQ_DPI_MASK  # 0=indeterminate, 1=off, 2=on, 3=indeterminate
                quality = self._parse_quality_flags(diq, check_ov=False)
                return value, quality

            # Measured value, normalized (Type 9, 34 carry a QDS octet;
            # Type 21 = M_ME_ND_1 has NO quality descriptor, so reading data[2]
            # would splice in the next element/object as a spurious quality).
            elif type_id in [9, 21, 34]:
                if len(data) >= 2:
                    nva = struct.unpack("<h", data[0:2])[0]
                    value = nva / NORMALIZED_SCALE  # Normalize to -1.0 to 1.0
                    if type_id == 21:
                        quality = ""
                    else:
                        quality = self._parse_quality_flags(data[2]) if len(data) > 2 else ""
                    return round(value, 4), quality

            # Measured value, scaled (Type 11, 35)
            elif type_id in [11, 35]:
                if len(data) >= 2:
                    sva = struct.unpack("<h", data[0:2])[0]
                    quality = self._parse_quality_flags(data[2]) if len(data) > 2 else ""
                    return sva, quality

            # Measured value, short float (Type 13, 36)
            elif type_id in [13, 36]:
                if len(data) >= 4:
                    value = struct.unpack("<f", data[0:4])[0]
                    quality = self._parse_quality_flags(data[4]) if len(data) > 4 else ""
                    return round(value, 4), quality

            # Step position (Type 5, 32)
            elif type_id in [5, 32]:
                vti = data[0]
                raw = vti & VTI_VALUE_MASK  # 7-bit two's-complement value, -64..+63
                value = raw - 128 if (vti & 0x40) else raw
                quality = self._parse_quality_flags(data[1]) if len(data) > 1 else ""
                if vti & VTI_TRANSIENT:  # Transient flag (equipment in transit)
                    quality = f"{quality},T" if quality else "T"
                return value, quality

            # Integrated totals (Type 15, 37)
            elif type_id in [15, 37]:
                if len(data) >= 4:
                    bcr = struct.unpack("<i", data[0:4])[0]
                    return bcr, ""

            # Bitstring (Type 7, 33)
            elif type_id in [7, 33]:
                if len(data) >= 4:
                    bsi = struct.unpack("<I", data[0:4])[0]
                    quality = self._parse_quality_flags(data[4]) if len(data) > 4 else ""
                    return f"0x{bsi:08X}", quality

            # Default: return hex representation
            return data.hex(), ""

        except Exception as e:
            return data.hex() if data else None, f"parse_error: {e}"

    def _parse_quality_flags(self, qds: int, check_ov: bool = True) -> str:
        """Parse quality descriptor flags.

        IV/NT/SB/BL live in the high nibble and are shared by QDS, SIQ and DIQ.
        OV (bit 0) exists ONLY in QDS: in SIQ bit 0 is the SPI value and in DIQ
        bits 0-1 are the DPI value, so callers parsing an SIQ/DIQ byte must pass
        check_ov=False -- otherwise every ON single-point / DPI-bit-0
        double-point is falsely flagged OV.
        """
        flags = []
        if qds & QDS_IV:
            flags.append("IV")  # Invalid
        if qds & QDS_NT:
            flags.append("NT")  # Not topical
        if qds & QDS_SB:
            flags.append("SB")  # Substituted
        if qds & QDS_BL:
            flags.append("BL")  # Blocked
        if check_ov and qds & QDS_OV:
            flags.append("OV")  # Overflow
        return ",".join(flags) if flags else "OK"

    def _display_captured_asdu(self, asdu: CapturedASDU):
        """Display captured ASDU in real-time and write to output file if open."""
        timestamp = asdu.timestamp.split("T")[1].split(".")[0]  # HH:MM:SS

        # Format: [HH:MM:SS] CA=1 IOA=100 M_SP_NA_1 = True [OK] COT=spontaneous
        quality_str = f"[{asdu.quality}]" if asdu.quality else ""

        msg = (
            f"[{timestamp}] CA={asdu.common_address} IOA={asdu.ioa:5d} "
            f"{asdu.type_name} = {asdu.value} {quality_str} COT={asdu.cot_name}"
        )

        # Color based on COT
        if asdu.cause_of_transmission == COT_SPONTANEOUS:
            self.logger.success(msg)
        elif asdu.cause_of_transmission in (COT_ACTIVATION, COT_ACTIVATION_CONFIRM):
            self.logger.warning(msg)
        else:
            self.logger.display(msg)

        # Write to listen output file if active (replaces monkey-patching)
        output_fh = getattr(self, "_listen_output_fh", None)
        if output_fh:
            output_fh.write(json.dumps(asdu.to_dict()) + "\n")
            output_fh.flush()

    def _create_monitor_callback(self):
        """Create callback optimized for monitor/listen mode"""
        from oida.protocols.iec104 import _deps

        c104 = _deps._get_c104()
        scanner = self

        def on_receive_raw_monitor(connection: c104.Connection, data: bytes) -> None:
            """Enhanced callback that captures full ASDU details"""
            # Need the full ASDU header (APCI+TI+VSQ+COT+CA) before unpacking CA;
            # a shorter frame would struct.error on data[ASDU_CA_OFFSET:+2].
            if len(data) < ASDU_HEADER_SIZE:
                return

            # Check if this is an I-frame (data transfer)
            if len(data) >= 6 and (data[2] & IFRAME_MASK) == 0:
                try:
                    # Parse ASDU header
                    type_id = data[ASDU_TYPE_ID_OFFSET]

                    # Apply type filter if set
                    if scanner.listen_filter and type_id not in scanner.listen_filter:
                        return

                    cot = data[ASDU_COT_OFFSET] & COT_VALUE_MASK
                    common_address = struct.unpack("<H", data[ASDU_CA_OFFSET : ASDU_CA_OFFSET + 2])[
                        0
                    ]

                    # Parse IOA (3 bytes in IEC 104)
                    if len(data) >= ASDU_DATA_OFFSET:
                        ioa = struct.unpack(
                            "<I", data[ASDU_IOA_OFFSET : ASDU_IOA_OFFSET + IOA_SIZE] + b"\x00"
                        )[0]
                    else:
                        ioa = 0

                    # Get type info
                    type_info = IEC104_TYPE_IDS.get(type_id, (f"UNKNOWN_{type_id}", "Unknown type"))
                    cot_name = IEC104_COT.get(cot, f"cot_{cot}")

                    # Parse value based on type
                    value, quality = scanner._parse_asdu_value(
                        type_id, data[ASDU_DATA_OFFSET:] if len(data) > ASDU_DATA_OFFSET else b""
                    )

                    # Create captured ASDU
                    captured = CapturedASDU(
                        timestamp=datetime.now().isoformat(),
                        type_id=type_id,
                        type_name=type_info[0],
                        type_description=type_info[1],
                        cause_of_transmission=cot,
                        cot_name=cot_name,
                        common_address=common_address,
                        ioa=ioa,
                        value=value,
                        quality=quality,
                        raw_bytes=data if scanner.listen_raw else None,
                    )

                    with scanner._lock:
                        scanner._captured_asdus.append(captured)
                        if scanner._listen_stats:
                            scanner._listen_stats.asdu_count += 1
                            scanner._listen_stats.type_ids_seen.add(type_id)
                            scanner._listen_stats.common_addresses_seen.add(common_address)
                            scanner._listen_stats.ioas_seen.add(ioa)
                            scanner._listen_stats.bytes_received += len(data)

                    # Real-time output
                    scanner._display_captured_asdu(captured)

                except Exception as e:
                    scanner.logger.debug(f"Error parsing ASDU: {e}")

        return on_receive_raw_monitor

    def _run_listen_mode(self, client: Any, conn: Any) -> Dict[str, Any]:
        """Run monitor/listen mode to capture spontaneous ASDUs"""
        self._listen_stats = ListenStats()
        self._captured_asdus = []
        self._stop_listen.clear()
        self._listen_output_fh = None

        # Setup enhanced monitor callback.
        #
        # Registering a raw-receive callback REPLACES any previously installed
        # one (c104 exposes a single raw-receive slot). The discovery callback
        # installed during connect() populates _discovered_points/_raw_type_ids/
        # _discovered_stations; overwriting it here would silently lose that data
        # when listen mode is combined with --interrogate (discover() falls
        # through to interrogation after listen). To keep both working, compose
        # the monitor callback with the original discovery callback so both run.
        monitor_callback = self._create_monitor_callback()
        discovery_callback = self._create_callbacks()[2]

        # c104 introspects the callback's annotations and rejects anything but
        # exactly (connection: c104.Connection, data: bytes) -> None, so the
        # composed wrapper must carry the real c104.Connection annotation.
        from oida.protocols.iec104 import _deps

        c104 = _deps._get_c104()

        def on_receive_raw_composed(connection: c104.Connection, data: bytes) -> None:
            # Run discovery first so _discovered_* is populated even if the
            # monitor parser raises; monitor handles its own exceptions.
            try:
                discovery_callback(connection, data)
            except Exception as e:
                self.logger.debug(f"Discovery callback error during listen: {e}")
            monitor_callback(connection, data)

        conn.on_receive_raw(on_receive_raw_composed)

        # Display mode info
        duration_str = f"{self.listen_time}s" if self.listen_time > 0 else "indefinite"
        self.logger.display(f"Listening for ASDUs ({duration_str})")
        if self.listen_filter:
            self.logger.display(f"  Type filter: {sorted(self.listen_filter)}")

        try:
            # Open output file inside try so finally always closes it
            if self.listen_output:
                try:
                    self._listen_output_fh = open(self.listen_output, "a")
                    self.logger.display(f"Logging to: {self.listen_output}")
                except IOError as e:
                    self.logger.fail(f"Cannot open output file: {e}")

            if self.listen_time > 0:
                # Fixed duration with countdown
                for remaining in range(self.listen_time, 0, -1):
                    if self._stop_listen.is_set():
                        break
                    if remaining % 30 == 0 or remaining <= 10:
                        self.logger.debug(f"Listening... {remaining}s remaining")
                    time.sleep(1)
            else:
                # Indefinite - wait for Ctrl+C
                while not self._stop_listen.is_set():
                    time.sleep(1)

        except KeyboardInterrupt:
            self.logger.display("Stopped by user")
        finally:
            if self._listen_output_fh:
                self._listen_output_fh.close()
                self._listen_output_fh = None

        # Compile results
        with self._lock:
            stats = self._listen_stats
            result = {
                "duration_seconds": round(stats.duration, 1),
                "asdus_captured": stats.asdu_count,
                "type_ids_seen": sorted(stats.type_ids_seen),
                "common_addresses_seen": sorted(stats.common_addresses_seen),
                "ioas_seen_count": len(stats.ioas_seen),
                "bytes_received": stats.bytes_received,
                "rate_per_second": round(stats.rate, 2),
                "captured_asdus": [a.to_dict() for a in self._captured_asdus],
            }

        # Display summary
        self._display_listen_summary(result)

        return result

    def _display_listen_summary(self, result: Dict[str, Any]):
        """Display listen mode summary statistics as a single log message."""
        lines = [
            "=" * 60,
            "Listen Mode Summary",
            "=" * 60,
            f"  Duration:        {result['duration_seconds']}s",
            f"  ASDUs captured:  {result['asdus_captured']}",
            f"  Rate:            {result['rate_per_second']} ASDUs/sec",
            f"  Bytes received:  {result.get('bytes_received', 'N/A')}",
            f"  Type IDs seen:   {result['type_ids_seen']}",
            f"  Stations (CA):   {result['common_addresses_seen']}",
            f"  Unique IOAs:     {result.get('ioas_seen_count', 'N/A')}",
        ]

        # Type breakdown
        if result["type_ids_seen"]:
            lines.append("Type ID breakdown:")
            type_counts: Dict[int, int] = {}
            for asdu in result.get("captured_asdus", []):
                tid = asdu["type_id"]
                type_counts[tid] = type_counts.get(tid, 0) + 1
            for tid in sorted(type_counts.keys()):
                info = IEC104_TYPE_IDS.get(tid, (f"TYPE_{tid}", "Unknown"))
                lines.append(f"    {info[0]:12s}: {type_counts[tid]:4d} ({info[1]})")

        self.logger.display("\n".join(lines))
