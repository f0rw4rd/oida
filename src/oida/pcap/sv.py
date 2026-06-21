"""
IEC 61850 Sampled Values (SV) Passive Listener (PyShark-based).

Passively monitors IEC 61850-9-2 Sampled Values traffic to identify:
- Merging Units (MUs) publishing digitized current/voltage measurements
- SV stream identifiers (SvID) and configuration revisions
- Sample counts (SmpCnt) and synchronization status
- Sample rates and measurement quality flags
- Security anomalies (unsynchronized samples, config changes, sample gaps)

SV is a Layer 2 multicast protocol (EtherType 0x88BA) used in IEC 61850
power substations for transmitting digitized analog measurements from
instrument transformers. It has no IP/TCP layers -- frames are identified
by source MAC and SvID.

Protocol format:
- Ethernet header: dst MAC (multicast 01:0c:cd:04:xx:xx), src MAC, EtherType 0x88BA
- SV header: APPID (2), Length (2), Reserved1 (2), Reserved2 (2)
- SV PDU (ASN.1 BER encoded):
  - noASDU: Number of ASDUs in the message (typically 1 for 9-2LE)
  - seqASDU: Sequence of ASDU entries, each containing:
    - svID: Sampled Value ID (identifies the MU stream, e.g., "MU01_SVID")
    - datSet: Dataset reference (optional)
    - smpCnt: Sample Count (0-3999 for 4000 sps at 50Hz, 0-4799 for 60Hz)
    - confRev: Configuration Revision (must match between publisher/subscriber)
    - refrTm: Refresh Time (UTC timestamp, optional)
    - smpSynch: Sample Synchronization (0=none, 1=local clock, 2=global GPS/PTP)
    - smpRate: Sample Rate (samples per second, e.g., 4000 or 4800)
    - smpMod: Sample Mode (0=samples per nominal period, 1=samples per second, 2=seconds per sample)
    - seqData: Sequence of measurement data (raw bytes)

9-2LE profile (IEC 61850-9-2 Light Edition):
- 8 measurement values per ASDU: 4 currents (Ia, Ib, Ic, In) + 4 voltages (Va, Vb, Vc, Vn)
- Each value is a 32-bit signed integer (FT_INT32)
- Each value has an associated 32-bit quality descriptor
- Published at 4000 samples/second (50Hz) or 4800 samples/second (60Hz)

Security notes:
- SV has NO authentication by default -- any device on the LAN can inject frames
- IEC 62351-6 adds HMAC authentication but is rarely deployed in practice
- smpSynch=0 (unsynchronized) means measurements cannot be trusted for protection
- confRev mismatch between MU and subscriber can cause protection malfunction
- Sample gaps (missing smpCnt values) may indicate frame injection or network issues
- Simulated flag (reserve1.s_bit) in production is a red flag

tshark fields used:
- sv.appid: Application ID (FT_UINT16)
- sv.svID: Sampled Value ID (FT_STRING)
- sv.datSet: Dataset reference (FT_STRING)
- sv.smpCnt: Sample Count (FT_UINT32)
- sv.confRev: Configuration Revision (FT_UINT32)
- sv.refrTm: Refresh Time (FT_STRING, UTC)
- sv.smpSynch: Sample Synchronization (FT_INT32: 0=none, 1=local, 2=global)
- sv.smpRate: Sample Rate (FT_UINT32)
- sv.smpMod: Sample Mode (FT_INT32)
- sv.noASDU: Number of ASDUs (FT_UINT32)
- sv.seqASDU: Sequence of ASDU (FT_UINT32)
- sv.reserve1.s_bit: Simulated flag (FT_BOOLEAN)
- sv.meas_value: Measurement value (FT_INT32, multiple per frame)
- sv.meas_quality: Quality descriptor (FT_UINT32, multiple per frame)
- sv.meas_quality.validity: Validity bits (FT_UINT32)
- sv.meas_quality.overflow: Overflow flag (FT_BOOLEAN)
- sv.meas_quality.outofrange: Out of range flag (FT_BOOLEAN)
- sv.meas_quality.badreference: Bad reference flag (FT_BOOLEAN)
- sv.meas_quality.failure: Failure flag (FT_BOOLEAN)
- sv.meas_quality.olddata: Old data flag (FT_BOOLEAN)
- sv.meas_quality.test: Test flag (FT_BOOLEAN)
- sv.meas_quality.operatorblocked: Operator blocked flag (FT_BOOLEAN)

References:
- IEC 61850-9-2: Communication networks and systems -- Part 9-2: Sampled Values
- IEC 61850-9-2LE: Light Edition (practical interoperability profile)
- IEC 62351-6: Security for IEC 61850 (SV authentication)
- Wireshark dissector: packet-sv.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import lookup_mac_vendor

# Sample synchronization mode names
SMP_SYNCH_MODES = {
    0: "none",
    1: "local",
    2: "global",
}

# Sample mode names (smpMod)
SMP_MOD_NAMES = {
    0: "samples/period",
    1: "samples/second",
    2: "seconds/sample",
}

# Measurement quality validity values (2-bit field)
QUALITY_VALIDITY = {
    0: "good",
    1: "invalid",
    2: "reserved",
    3: "questionable",
}

# Quality flag field names and their display abbreviations
QUALITY_FLAGS = [
    ("meas_quality_overflow", "OV"),
    ("meas_quality_outofrange", "OOR"),
    ("meas_quality_badreference", "BADREF"),
    ("meas_quality_failure", "FAIL"),
    ("meas_quality_olddata", "OLD"),
    ("meas_quality_inconsistent", "INCON"),
    ("meas_quality_inaccurate", "INACC"),
    ("meas_quality_test", "TEST"),
    ("meas_quality_operatorblocked", "BLOCKED"),
]

# 9-2LE channel names (4 currents + 4 voltages)
LE_CHANNEL_NAMES = ["Ia", "Ib", "Ic", "In", "Va", "Vb", "Vc", "Vn"]


@dataclass
class SVStream:
    """Track a Sampled Values stream (identified by SvID)."""

    src_mac: str
    sv_id: str
    appid: int = 0
    conf_revs: Set[int] = field(default_factory=set)
    smp_synch_modes: Set[int] = field(default_factory=set)
    smp_rates: Set[int] = field(default_factory=set)
    smp_mods: Set[int] = field(default_factory=set)
    datasets: Set[str] = field(default_factory=set)
    last_smp_cnt: int = -1
    sample_gaps: int = 0
    total_frames: int = 0
    simulated_frames: int = 0
    no_asdu_values: Set[int] = field(default_factory=set)
    min_meas_value: Optional[int] = None
    max_meas_value: Optional[int] = None
    quality_issues: int = 0
    first_seen: str = ""
    last_seen: str = ""


class SVPassiveListener(PySharkListenerBase):
    """Passive IEC 61850 Sampled Values traffic listener (PyShark-based).

    Monitors SV multicast traffic without sending packets to:
    - Identify Merging Units publishing SV streams by source MAC and SvID
    - Track sample counts (SmpCnt) and detect gaps (missing samples)
    - Monitor synchronization status (smpSynch) for measurement accuracy
    - Detect configuration revision changes (confRev mismatches)
    - Extract measurement values and quality flags
    - Alert on unsynchronized samples, simulated data, and sample gaps

    SV is Layer 2 only (EtherType 0x88BA) -- there are no IP addresses.
    Devices are keyed by source MAC address. Flow IDs use MAC addresses.

    Usage:
        listener = SVPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Access stream statistics
        for stream in listener.streams.values():
            print(f"{stream.src_mac} SvID={stream.sv_id}")
            print(f"  Sample rate: {stream.smp_rates}")
            print(f"  Sample gaps: {stream.sample_gaps}")
            print(f"  Synch modes: {stream.smp_synch_modes}")

    Data stored in device.sv_passive_data:
        {
            "role": "publisher",
            "sv_ids": ["MU01_SVID"],
            "datasets": ["MU01/LLN0$DataSet01"],
            "appid": 0x4000,
            "conf_revs": [1],
            "smp_synch_modes": [2],
            "smp_rates": [4000],
            "sample_gaps": 0,
            "total_frames": 5000,
            "simulated_frames": 0,
            "quality_issues": 0,
            "protocol": "SV/L2",
        }
    """

    PROTOCOL_NAME = "sv"
    DISPLAY_FILTER = "sv"
    REQUIRED_LAYERS = ("sv",)
    PROTOCOL_COLUMNS = (
        "svid",
        "smp_cnt",
        "conf_rev",
        "samples",
        "smp_synch",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize SV passive listener."""
        super().__init__(interface, timeout, nxc_logger)
        # Track SV streams by SvID (unique per Merging Unit stream)
        self.streams: Dict[str, SVStream] = {}
        # Security tracking: per-SvID confRev history for mismatch detection
        self._conf_rev_by_svid: Dict[str, Set[int]] = {}

    def process_packet(self, packet) -> None:
        """Process a Sampled Values packet using PyShark dissection."""
        if not hasattr(packet, "sv"):
            return

        sv_layer = packet.sv

        # SV is Layer 2 -- extract MAC addresses (no IP)
        src_mac, dst_mac = self.get_mac_info(packet)

        if not src_mac:
            return

        # Extract SV header fields
        appid = self._parse_int(self.get_field(sv_layer, "appid"), 0)
        sv_id = str(self.get_field(sv_layer, "svID") or "")
        dat_set = str(self.get_field(sv_layer, "datSet") or "")
        smp_cnt = self._parse_int(self.get_field(sv_layer, "smpCnt"), 0)
        conf_rev = self._parse_int(self.get_field(sv_layer, "confRev"), 0)
        smp_synch = self._parse_int(self.get_field(sv_layer, "smpSynch"), -1)
        smp_rate = self._parse_int(self.get_field(sv_layer, "smpRate"), 0)
        smp_mod = self._parse_int(self.get_field(sv_layer, "smpMod"), -1)
        no_asdu = self._parse_int(self.get_field(sv_layer, "noASDU"), 0)

        # Parse simulated flag from reserve1 S-bit
        simulated = self._parse_bool(self.get_field(sv_layer, "reserve1_s_bit"))

        # Extract measurement values and quality
        meas_values = self._extract_meas_values(sv_layer)
        quality_issues = self._extract_quality_issues(sv_layer)

        # Use SvID as the stream key (unique per MU stream)
        # Fall back to src_mac:appid if SvID is empty
        stream_key = sv_id if sv_id else f"{src_mac}:0x{appid:04x}"

        # Update stream state
        stream = self._update_stream(
            stream_key,
            src_mac,
            sv_id,
            appid,
            dat_set,
            smp_cnt,
            conf_rev,
            smp_synch,
            smp_rate,
            smp_mod,
            no_asdu,
            simulated,
            meas_values,
            quality_issues,
        )

        # Build flow ID from MAC (no IP/TCP for SV)
        flow_id = self.get_flow_id(packet)

        # Record interaction
        now = datetime.now().isoformat()
        synch_label = SMP_SYNCH_MODES.get(smp_synch, str(smp_synch)) if smp_synch >= 0 else ""

        details: Dict[str, Any] = {
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "sv_id": sv_id,
            "smp_cnt": smp_cnt,
            "conf_rev": conf_rev,
            "smp_synch": smp_synch,
            "smp_synch_label": synch_label,
            "smp_rate": smp_rate,
            "appid": appid,
            "simulated": simulated,
            "no_asdu": no_asdu,
        }
        if dat_set:
            details["dataset"] = dat_set
        if meas_values:
            details["meas_values"] = meas_values
        if quality_issues:
            details["quality_issues"] = quality_issues
        if smp_mod >= 0:
            details["smp_mod"] = smp_mod

        summary = self._build_summary(
            sv_id,
            smp_cnt,
            conf_rev,
            smp_synch,
            simulated,
            meas_values,
        )
        self._record_interaction(
            now,
            src_mac,
            dst_mac,
            "request",  # SV is publish-only (multicast)
            "sample",
            details,
            summary,
            flow_id=flow_id,
        )

        # Update device entry
        self._update_device(src_mac, stream_key, stream)

    # ------------------------------------------------------------------
    # Stream tracking
    # ------------------------------------------------------------------

    def _update_stream(
        self,
        stream_key: str,
        src_mac: str,
        sv_id: str,
        appid: int,
        dat_set: str,
        smp_cnt: int,
        conf_rev: int,
        smp_synch: int,
        smp_rate: int,
        smp_mod: int,
        no_asdu: int,
        simulated: bool,
        meas_values: List[int],
        quality_issues: List[str],
    ) -> SVStream:
        """Update or create an SV stream entry."""
        now = datetime.now().isoformat()

        if stream_key not in self.streams:
            self.streams[stream_key] = SVStream(
                src_mac=src_mac,
                sv_id=sv_id,
                appid=appid,
                first_seen=now,
                last_seen=now,
            )

        stream = self.streams[stream_key]
        stream.last_seen = now
        stream.total_frames += 1

        if dat_set:
            stream.datasets.add(dat_set)
        if conf_rev:
            stream.conf_revs.add(conf_rev)
        if smp_synch >= 0:
            stream.smp_synch_modes.add(smp_synch)
        if smp_rate > 0:
            stream.smp_rates.add(smp_rate)
        if smp_mod >= 0:
            stream.smp_mods.add(smp_mod)
        if no_asdu > 0:
            stream.no_asdu_values.add(no_asdu)

        # Track confRev for mismatch detection
        if sv_id and conf_rev:
            self._conf_rev_by_svid.setdefault(sv_id, set()).add(conf_rev)

        # Detect sample gaps (missing smpCnt values)
        if stream.last_smp_cnt >= 0 and smp_cnt != stream.last_smp_cnt:
            expected_next = stream.last_smp_cnt + 1
            # Handle wrap-around: smpCnt resets to 0 at smpRate boundary
            max_cnt = max(stream.smp_rates) if stream.smp_rates else 4000
            if expected_next >= max_cnt:
                expected_next = 0
            if smp_cnt != expected_next:
                stream.sample_gaps += 1
        stream.last_smp_cnt = smp_cnt

        if simulated:
            stream.simulated_frames += 1

        # Track measurement value range
        for val in meas_values:
            if stream.min_meas_value is None or val < stream.min_meas_value:
                stream.min_meas_value = val
            if stream.max_meas_value is None or val > stream.max_meas_value:
                stream.max_meas_value = val

        if quality_issues:
            stream.quality_issues += 1

        return stream

    # ------------------------------------------------------------------
    # Measurement value extraction
    # ------------------------------------------------------------------

    def _extract_meas_values(self, sv_layer) -> List[int]:
        """Extract measurement values from sv.meas_value fields.

        In 9-2LE, there are 8 values per ASDU: 4 currents + 4 voltages,
        each as a 32-bit signed integer.
        """
        result: List[int] = []
        raw = self.get_field(sv_layer, "meas_value", None)
        if raw is None:
            return result

        try:
            for fld in getattr(sv_layer, "meas_value").all_fields:
                result.append(int(fld.show))
        except Exception:
            # Fallback: parse comma-separated or single value
            for part in str(raw).split(","):
                try:
                    result.append(int(part.strip()))
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"result.append(int(part.strip())): {e}")
        return result

    def _extract_quality_issues(self, sv_layer) -> List[str]:
        """Extract quality flag issues from sv.meas_quality fields.

        Returns a list of active quality issue abbreviations for the frame.
        Empty list means all quality flags are OK.
        """
        issues: List[str] = []

        # Check validity field (0=good, 1=invalid, 2=reserved, 3=questionable)
        validity_raw = self.get_field(sv_layer, "meas_quality_validity", None)
        if validity_raw is not None:
            try:
                vals = []
                try:
                    for fld in getattr(sv_layer, "meas_quality_validity").all_fields:
                        vals.append(int(fld.show))
                except Exception:
                    vals.append(int(validity_raw))
                for v in vals:
                    if v != 0:
                        label = QUALITY_VALIDITY.get(v, f"validity={v}")
                        if label not in issues:
                            issues.append(label)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"SV: meas_quality_validity int parse failed: {e}")

        # Check boolean quality flags
        for field_name, abbrev in QUALITY_FLAGS:
            raw = self.get_field(sv_layer, field_name, None)
            if raw is None:
                continue
            try:
                flag_values = []
                try:
                    for fld in getattr(sv_layer, field_name).all_fields:
                        flag_values.append(str(fld.show))
                except Exception:
                    flag_values.append(str(raw))
                for fv in flag_values:
                    if fv in ("True", "1", "true"):
                        if abbrev not in issues:
                            issues.append(abbrev)
                        break
            except Exception as e:
                self.logger.debug(f"Failed to get flag_values: {e}")

        return issues

    # ------------------------------------------------------------------
    # Interaction formatting
    # ------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details

        sv_id = d.get("sv_id", "")
        smp_cnt = d.get("smp_cnt", "")
        conf_rev = d.get("conf_rev", "")

        # Format measurement values summary
        meas_values = d.get("meas_values", [])
        if isinstance(meas_values, list) and meas_values:
            samples_str = self._format_meas_summary(meas_values)
        else:
            samples_str = ""

        # Synchronization label
        smp_synch = d.get("smp_synch", -1)
        synch_str = d.get("smp_synch_label", "")
        if not synch_str and smp_synch >= 0:
            synch_str = SMP_SYNCH_MODES.get(smp_synch, str(smp_synch))

        return [
            sv_id,
            smp_cnt,
            conf_rev,
            samples_str,
            synch_str,
        ]

    # ------------------------------------------------------------------
    # Security alerts
    # ------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return harvest data with SV-specific security alerts."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}
        if "alerts" not in result:
            result["alerts"] = []

        for stream in self.streams.values():
            # Alert: unsynchronized samples (smpSynch=0)
            if 0 in stream.smp_synch_modes:
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "sv_unsynchronized",
                        "message": (
                            f"SV UNSYNCHRONIZED: {stream.src_mac} SvID={stream.sv_id} "
                            f"has smpSynch=0 (samples not synchronized to time source -- "
                            f"measurements cannot be trusted for differential protection)"
                        ),
                    }
                )

            # Alert: simulated frames detected
            if stream.simulated_frames > 0:
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "sv_simulated",
                        "message": (
                            f"SV SIMULATED: {stream.src_mac} SvID={stream.sv_id} "
                            f"sent {stream.simulated_frames} simulated frame(s) "
                            f"(S-bit set -- may indicate test mode or spoofing)"
                        ),
                    }
                )

            # Alert: sample gaps detected
            if stream.sample_gaps > 0:
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "sv_sample_gap",
                        "message": (
                            f"SV SAMPLE GAP: {stream.src_mac} SvID={stream.sv_id} "
                            f"has {stream.sample_gaps} sample gap(s) "
                            f"(missing smpCnt values -- possible frame loss or injection)"
                        ),
                    }
                )

            # Alert: quality issues detected
            if stream.quality_issues > 0:
                result["alerts"].append(
                    {
                        "level": "highlight",
                        "category": "sv_quality",
                        "message": (
                            f"SV QUALITY: {stream.src_mac} SvID={stream.sv_id} "
                            f"had quality issues in {stream.quality_issues} frame(s)"
                        ),
                    }
                )

        # Alert: confRev mismatch (multiple confRevs for same SvID)
        for sv_id, revs in self._conf_rev_by_svid.items():
            if len(revs) > 1:
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "sv_confrev_mismatch",
                        "message": (
                            f"SV CONFIG MISMATCH: SvID={sv_id} "
                            f"has multiple confRev values: {sorted(revs)} "
                            f"(subscribers may reject data or malfunction)"
                        ),
                    }
                )

        # Clean up empty results
        if not result.get("tables") and not result.get("alerts"):
            return {}
        return result

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _update_device(self, src_mac: str, stream_key: str, stream: SVStream) -> None:
        """Update or create a device entry for an SV publisher (Merging Unit)."""
        if not src_mac:
            return

        device_key = f"sv-mu:{src_mac}"
        vendor = lookup_mac_vendor(src_mac) if src_mac else ""

        device, is_new = self._ensure_device(
            device_key,
            "",  # No IP address for SV (Layer 2 only)
            mac=src_mac,
            device_type="IEC 61850 Merging Unit (SV Publisher)",
            manufacturer=vendor if vendor else "",
        )

        # Aggregate data from all streams for this MAC
        device.sv_passive_data = self._build_device_data(src_mac)

        if is_new:
            self.logger.debug(f"SV: MU {src_mac} SvID={stream.sv_id} APPID=0x{stream.appid:04x}")

    def _build_device_data(self, src_mac: str) -> Dict[str, Any]:
        """Build sv_passive_data dict aggregated across all streams for a MAC."""
        sv_ids: List[str] = []
        datasets: Set[str] = set()
        conf_revs: Set[int] = set()
        smp_synch_modes: Set[int] = set()
        smp_rates: Set[int] = set()
        appids: Set[int] = set()
        total_frames = 0
        simulated_frames = 0
        sample_gaps = 0
        quality_issues = 0
        first_seen = ""
        last_seen = ""

        for stream in self.streams.values():
            if stream.src_mac != src_mac:
                continue
            if stream.sv_id:
                sv_ids.append(stream.sv_id)
            datasets.update(stream.datasets)
            conf_revs.update(stream.conf_revs)
            smp_synch_modes.update(stream.smp_synch_modes)
            smp_rates.update(stream.smp_rates)
            if stream.appid:
                appids.add(stream.appid)
            total_frames += stream.total_frames
            simulated_frames += stream.simulated_frames
            sample_gaps += stream.sample_gaps
            quality_issues += stream.quality_issues
            if not first_seen or (stream.first_seen and stream.first_seen < first_seen):
                first_seen = stream.first_seen
            if not last_seen or (stream.last_seen and stream.last_seen > last_seen):
                last_seen = stream.last_seen

        return {
            "role": "publisher",
            "sv_ids": sorted(sv_ids),
            "datasets": sorted(datasets),
            "appids": sorted(appids),
            "conf_revs": sorted(conf_revs),
            "smp_synch_modes": sorted(smp_synch_modes),
            "smp_synch_labels": [SMP_SYNCH_MODES.get(m, str(m)) for m in sorted(smp_synch_modes)],
            "smp_rates": sorted(smp_rates),
            "total_frames": total_frames,
            "simulated_frames": simulated_frames,
            "sample_gaps": sample_gaps,
            "quality_issues": quality_issues,
            "protocol": "SV/L2",
            "first_seen": first_seen,
            "last_seen": last_seen,
        }

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(
        sv_id: str,
        smp_cnt: int,
        conf_rev: int,
        smp_synch: int,
        simulated: bool,
        meas_values: List[int],
    ) -> str:
        """Build a one-line human-readable interaction summary."""
        parts: List[str] = []

        if sv_id:
            parts.append(f"SvID={sv_id}")

        parts.append(f"Cnt={smp_cnt}")

        if conf_rev:
            parts.append(f"Rev={conf_rev}")

        synch_label = SMP_SYNCH_MODES.get(smp_synch, "")
        if synch_label:
            parts.append(f"Synch={synch_label}")

        if simulated:
            parts.append("[SIM]")

        if meas_values:
            val_strs = [str(v) for v in meas_values]
            parts.append(f"[{','.join(val_strs)}]")

        return " ".join(parts)

    @staticmethod
    def _format_meas_summary(meas_values: List[int]) -> str:
        """Format measurement values into a compact display string.

        For 9-2LE (8 values): shows channel labels (Ia,Ib,...,Vn).
        For other counts: shows raw values with truncation.
        """
        if not meas_values:
            return ""

        if len(meas_values) == 8:
            # 9-2LE: label channels
            parts = []
            for i, val in enumerate(meas_values):
                parts.append(f"{LE_CHANNEL_NAMES[i]}={val}")
            return " ".join(parts)
        else:
            return " | ".join(str(v) for v in meas_values)

    # ------------------------------------------------------------------
    # Parse helpers
    # ------------------------------------------------------------------
