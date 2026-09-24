"""Shared helpers for the IEC 60870-5 passive listeners (iec101 / iec103 / iec104).

These three protocols share the same ASDU framing concepts. This module
centralizes the pieces of logic that previously diverged per-file:

1. ``parse_asdu_field()`` — ASDU type-ID / COT integer parse. tshark renders
   these ``FT_UINT8`` fields in DECIMAL (a real ``0x`` prefix is still honored).
   Single-sourcing the base here prevents per-listener drift — iec103 once
   parsed these with ``base=16``, turning decimal ``"20"`` into ``32`` and
   mislabeling every multi-digit command/COT.

2. ``classify_rw()`` — the read/write/control/file/error classification ladder
   for IEC-101/104, which was previously copy-pasted identically in iec101 and
   twice in iec104.

3. The IEC-101/104 ASDU type/COT lookup tables and the ``IecAsduValueMixin``
   class — the per-IOA value/quality extraction methods, the ASDU-header
   parse core, the unified summary builder, and the link-frame interaction
   recorder. iec101 and iec104 share the exact same ASDU encoding (only the
   transport framing — FT1.2 link layer vs. APCI/TCP — differs), and iec103's
   FT1.2 link-layer function-code maps and link-frame recording are identical
   to iec101's, so those live here too.

iec103 (the protection profile) keeps its own direction-split type/COT maps,
ASDU processing, and its own rw rules for monitor/control ASDUs — those are
genuinely different semantics — but it shares ``parse_asdu_field()``, the
FT1.2 link function-code maps, and the link-frame recording helper so those
pieces can no longer diverge.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from oida.pcap.pyshark_base import PySharkListenerBase


def parse_asdu_field(raw: Any, default: Any = 0) -> Any:
    """Parse an IEC 60870-5 ASDU type-ID or COT field as a base-10 integer.

    Delegates to ``PySharkListenerBase._parse_int`` (base 10, ``0x``-prefix
    aware) so every IEC listener resolves these decimal tshark fields the same
    way. Returns *default* for ``None`` or unparseable input.
    """
    return PySharkListenerBase._parse_int(raw, default)


def classify_rw(
    type_id: int,
    is_error_cot: bool,
    *,
    write_ids: Set[int],
    read_ids: Set[int],
    system_ids: Set[int],
    file_ids: Set[int],
) -> str:
    """Classify an IEC-101/104 ASDU's access intent.

    Mirrors the historical ladder exactly: error > write > read(command) >
    control(system) > file, with a ``type_id <= 44`` monitor/read fallback and
    a write default for everything above.
    """
    if is_error_cot:
        return "error"
    if type_id in write_ids:
        return "write"
    if type_id in read_ids:
        return "read"
    if type_id in system_ids:
        return "control"
    if type_id in file_ids:
        return "file"
    if type_id <= 44:
        return "read"
    return "write"


# IEC 101/104 Type IDs (common subset)
TYPE_IDS = {
    # Monitoring (process info in monitor direction)
    1: "M_SP_NA_1",  # Single-point information
    3: "M_DP_NA_1",  # Double-point information
    5: "M_ST_NA_1",  # Step position information
    7: "M_BO_NA_1",  # Bitstring of 32 bits
    9: "M_ME_NA_1",  # Measured value, normalized
    11: "M_ME_NB_1",  # Measured value, scaled
    13: "M_ME_NC_1",  # Measured value, short floating point
    15: "M_IT_NA_1",  # Integrated totals
    20: "M_PS_NA_1",  # Packed single-point with status
    21: "M_ME_ND_1",  # Measured value, normalized without quality
    30: "M_SP_TB_1",  # Single-point with time tag CP56Time2a
    31: "M_DP_TB_1",  # Double-point with time tag CP56Time2a
    32: "M_ST_TB_1",  # Step position with time tag
    33: "M_BO_TB_1",  # Bitstring with time tag
    34: "M_ME_TD_1",  # Measured value, normalized with time tag
    35: "M_ME_TE_1",  # Measured value, scaled with time tag
    36: "M_ME_TF_1",  # Measured value, float with time tag
    37: "M_IT_TB_1",  # Integrated totals with time tag
    38: "M_EP_TD_1",  # Event of protection equipment
    39: "M_EP_TE_1",  # Packed start events
    40: "M_EP_TF_1",  # Packed output circuit info
    # Control (command direction)
    45: "C_SC_NA_1",  # Single command
    46: "C_DC_NA_1",  # Double command
    47: "C_RC_NA_1",  # Regulating step command
    48: "C_SE_NA_1",  # Setpoint command, normalized
    49: "C_SE_NB_1",  # Setpoint command, scaled
    50: "C_SE_NC_1",  # Setpoint command, float
    51: "C_BO_NA_1",  # Bitstring command
    58: "C_SC_TA_1",  # Single command with time tag
    59: "C_DC_TA_1",  # Double command with time tag
    60: "C_RC_TA_1",  # Regulating step with time tag
    61: "C_SE_TA_1",  # Setpoint normalized with time tag
    62: "C_SE_TB_1",  # Setpoint scaled with time tag
    63: "C_SE_TC_1",  # Setpoint float with time tag
    64: "C_BO_TA_1",  # Bitstring command with time tag
    # System info
    70: "M_EI_NA_1",  # End of initialization
    100: "C_IC_NA_1",  # Interrogation command
    101: "C_CI_NA_1",  # Counter interrogation
    102: "C_RD_NA_1",  # Read command
    103: "C_CS_NA_1",  # Clock synchronization
    104: "C_TS_NA_1",  # Test command
    105: "C_RP_NA_1",  # Reset process
    106: "C_CD_NA_1",  # Delay acquisition
    107: "C_TS_TA_1",  # Test command with time tag
    # Parameter
    110: "P_ME_NA_1",  # Parameter of measured value, normalized
    111: "P_ME_NB_1",  # Parameter of measured value, scaled
    112: "P_ME_NC_1",  # Parameter of measured value, float
    113: "P_AC_NA_1",  # Parameter activation
    # File transfer
    120: "F_FR_NA_1",  # File ready
    121: "F_SR_NA_1",  # Section ready
    122: "F_SC_NA_1",  # Call directory
    123: "F_LS_NA_1",  # Last section
    124: "F_AF_NA_1",  # Ack file
    125: "F_SG_NA_1",  # Segment
    126: "F_DR_TA_1",  # Directory
    127: "F_SC_NB_1",  # Query log
}

# Control type IDs (commands — all types in the control direction)
CONTROL_TYPE_IDS = {
    45,
    46,
    47,
    48,
    49,
    50,
    51,  # Direct commands
    58,
    59,
    60,
    61,
    62,
    63,
    64,  # Commands with time tag
    100,
    101,
    102,
    103,
    104,
    105,
    106,
    107,  # System commands
    110,
    111,
    112,
    113,  # Parameter commands
    120,
    121,
    122,
    123,
    124,
    125,
    126,
    127,  # File transfer
}

# Write commands — types that actually modify process state
_WRITE_TYPE_IDS = {
    45,
    46,
    47,
    48,
    49,
    50,
    51,  # C_SC/DC/RC/SE commands
    58,
    59,
    60,
    61,
    62,
    63,
    64,  # Same with time tag
    110,
    111,
    112,
    113,  # Parameter set commands
}

# Read/query commands — request data but don't modify state
_READ_COMMAND_TYPE_IDS = {100, 101, 102}  # GI, CI, Read command

# System/management commands
_SYSTEM_TYPE_IDS = {103, 104, 105, 106, 107}  # Clock sync, test, reset, delay, test+time

# File transfer types
_FILE_TYPE_IDS = {120, 121, 122, 123, 124, 125, 126, 127}

# Cause of Transmission (COT) names per IEC 60870-5-101 §7.2.3
COT_NAMES = {
    1: "periodic",
    2: "background",
    3: "spontaneous",
    4: "initialized",
    5: "request",
    6: "activation",
    7: "actcon",
    8: "deactivation",
    9: "deactcon",
    10: "actterm",
    11: "retrem",
    12: "retloc",
    13: "file_transfer",
    20: "inrogen",
    37: "reqcogen",
    44: "unknown_type",
    45: "unknown_cot",
    46: "unknown_ca",
    47: "unknown_ioa",
}

# Error COTs (44-47)
_ERROR_COTS = {44, 45, 46, 47}

# Double-point interpretation (DPI field values) -- monitoring direction
_DPI_VALUES = {0: "INTERMEDIATE", 1: "OFF", 2: "ON", 3: "INDETERMINATE"}

# Double-command state (DCS field values) -- control direction (C_DC_NA_1 /
# C_DC_TA_1). Unlike the monitoring DPI table, values 0 and 3 are NOT_PERMITTED,
# not INTERMEDIATE/INDETERMINATE (per IEC 60870-5-101/104, as iec103 uses).
_DCO_VALUES = {0: "NOT_PERMITTED", 1: "OFF", 2: "ON", 3: "NOT_PERMITTED"}

# Regulating step command interpretation (RCO.up field values)
_RCO_VALUES = {0: "NOT_PERMITTED", 1: "LOWER", 2: "HIGHER", 3: "NOT_PERMITTED"}

# Map type IDs to their value extraction category.
# Each tuple: (value_field, quality_source)
# quality_source: "qds" (QDS descriptor), "siq" (SIQ), "diq" (DIQ), None
_TYPE_CATEGORIES: Dict[int, Tuple[str, Optional[str]]] = {
    # Single-point: siq.spi (bool) with SIQ quality
    1: ("spi", "siq"),
    30: ("spi", "siq"),
    # Double-point: diq.dpi (int) with DIQ quality
    3: ("dpi", "diq"),
    31: ("dpi", "diq"),
    # Step position: vti.v (int) + vti.t (bool) with QDS quality
    5: ("vti", "qds"),
    32: ("vti", "qds"),
    # Bitstring: bitstring (hex) with QDS quality
    7: ("bitstring", "qds"),
    33: ("bitstring", "qds"),
    # Normalized value: normval (float) with QDS quality
    9: ("normval", "qds"),
    34: ("normval", "qds"),
    # Normalized without quality
    21: ("normval", None),
    # Scaled value: scalval (int) with QDS quality
    11: ("scalval", "qds"),
    35: ("scalval", "qds"),
    # Short float: float (float) with QDS quality
    13: ("float", "qds"),
    36: ("float", "qds"),
    # Integrated totals: bcr.count (int), no standard QDS
    15: ("bcr", None),
    37: ("bcr", None),
    # Single command: sco.on (bool)
    45: ("sco", None),
    58: ("sco", None),
    # Double command: dco.on (int)
    46: ("dco", None),
    59: ("dco", None),
    # Regulating step command: rco.up (int)
    47: ("rco", None),
    60: ("rco", None),
    # Setpoint normalized: normval with QOS
    48: ("normval", None),
    61: ("normval", None),
    # Parameter of measured value, normalized
    110: ("normval", None),
    # Setpoint scaled: scalval with QOS
    49: ("scalval", None),
    62: ("scalval", None),
    # Parameter of measured value, scaled
    111: ("scalval", None),
    # Setpoint float: float with QOS
    50: ("float", None),
    63: ("float", None),
    # Parameter of measured value, float
    112: ("float", None),
    # Bitstring command
    51: ("bitstring", None),
    64: ("bitstring", None),
    # Interrogation command: qoi (int)
    100: ("qoi", None),
    # Counter interrogation: qcc (int)
    101: ("qcc", None),
    # End of initialization: coi (int)
    70: ("coi", None),
    # Clock sync: cp56time
    103: ("cp56time", None),
}

# IEC 101/103 link layer function codes (primary station -> secondary station)
LINK_FUNC_PRI_TO_SEC = {
    0: "Reset Remote Link",
    1: "Reset User Process",
    2: "Test Function for Link",
    3: "User Data (Confirmed)",
    4: "User Data (No Reply)",
    8: "Expected Response Specifies Access Demand",
    9: "Request Status of Link",
    10: "Request User Data Class 1",
    11: "Request User Data Class 2",
}

# IEC 101/103 link layer function codes (secondary station -> primary station)
LINK_FUNC_SEC_TO_PRI = {
    0: "ACK (positive)",
    1: "NACK (link busy)",
    8: "User Data",
    9: "No Data Available (NACK)",
    11: "Status of Link / Access Demand",
    14: "Link Not Functioning",
    15: "Link Not Implemented",
}


class IecAsduValueMixin:
    """Shared ASDU field-extraction, summary, and recording helpers.

    Mixed into ``IEC101PassiveListener`` and ``IEC104PassiveListener`` (both of
    which subclass ``PySharkListenerBase``), and into ``IEC103PassiveListener``
    for the link-frame recording helper. Relies on ``self.get_field``,
    ``self.logger``, ``self._format_float``, ``self._parse_int``,
    ``self._record_interaction``, ``self.get_port_info``, and
    ``self.get_stream_id`` — all provided by ``PySharkListenerBase``.
    """

    def _get_multi_field_ints(self, layer, field_name: str) -> List[int]:
        """Get all instances of an integer field from a PyShark layer.

        Handles multi-IOA packets by using ``all_fields`` when available,
        falling back to the single scalar value.
        """
        result: List[int] = []
        raw = self.get_field(layer, field_name, None)
        if raw is None:
            return result

        # Try all_fields for multi-value support
        try:
            for f in getattr(layer, field_name).all_fields:
                result.append(int(f.show))
        except Exception:
            # Fallback: parse comma-separated or single value
            for part in str(raw).split(","):
                try:
                    result.append(int(part.strip()))
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"result.append(int(part.strip())): {e}")
        return result

    def _get_multi_field_strs(self, layer, field_name: str) -> List[str]:
        """Get all instances of a field as strings from a PyShark layer."""
        result: List[str] = []
        raw = self.get_field(layer, field_name, None)
        if raw is None:
            return result
        try:
            for f in getattr(layer, field_name).all_fields:
                result.append(str(f.show))
        except Exception:
            result.append(str(raw))
        return result

    def _extract_values(self, asdu_layer, type_id: int) -> List[str]:
        """Extract per-IOA values from the ASDU layer based on type ID.

        Returns a list of human-readable value strings, one per IOA.
        """
        cat = _TYPE_CATEGORIES.get(type_id)
        if cat is None:
            return []

        value_kind = cat[0]

        if value_kind == "spi":
            return self._extract_spi_values(asdu_layer)
        elif value_kind == "dpi":
            return self._extract_dpi_values(asdu_layer)
        elif value_kind == "vti":
            return self._extract_vti_values(asdu_layer)
        elif value_kind == "bitstring":
            return self._get_multi_field_strs(asdu_layer, "bitstring")
        elif value_kind == "normval":
            return self._get_multi_field_strs(asdu_layer, "normval")
        elif value_kind == "scalval":
            return self._get_multi_field_strs(asdu_layer, "scalval")
        elif value_kind == "float":
            return self._extract_float_values(asdu_layer)
        elif value_kind == "bcr":
            return self._extract_bcr_values(asdu_layer)
        elif value_kind == "sco":
            return self._extract_sco_values(asdu_layer)
        elif value_kind == "dco":
            return self._extract_dco_values(asdu_layer)
        elif value_kind == "rco":
            return self._extract_rco_values(asdu_layer)
        elif value_kind == "qoi":
            return self._extract_simple_field(asdu_layer, "qoi", "QOI=")
        elif value_kind == "qcc":
            return self._extract_simple_field(asdu_layer, "qcc", "QCC=")
        elif value_kind == "coi":
            return self._extract_coi_values(asdu_layer)
        elif value_kind == "cp56time":
            return self._get_multi_field_strs(asdu_layer, "cp56time")
        return []

    def _extract_spi_values(self, asdu_layer) -> List[str]:
        """Extract single-point SPI values (ON/OFF)."""
        result: List[str] = []
        raw = self.get_field(asdu_layer, "siq_spi", None)
        if raw is None:
            return result
        try:
            for f in getattr(asdu_layer, "siq_spi").all_fields:
                val = str(f.show)
                result.append("ON" if val in ("True", "On", "1") else "OFF")
        except Exception:
            val = str(raw)
            result.append("ON" if val in ("True", "On", "1") else "OFF")
        return result

    def _extract_dpi_values(self, asdu_layer) -> List[str]:
        """Extract double-point DPI values."""
        result: List[str] = []
        raw = self.get_field(asdu_layer, "diq_dpi", None)
        if raw is None:
            return result
        try:
            for f in getattr(asdu_layer, "diq_dpi").all_fields:
                val = int(f.show)
                result.append(_DPI_VALUES.get(val, str(val)))
        except Exception:
            try:
                val = int(raw)
                result.append(_DPI_VALUES.get(val, str(val)))
            except (ValueError, TypeError):
                result.append(str(raw))
        return result

    def _extract_vti_values(self, asdu_layer) -> List[str]:
        """Extract step position VTI values (value + transient flag)."""
        result: List[str] = []
        vals = self._get_multi_field_strs(asdu_layer, "vti_v")
        transients = self._get_multi_field_strs(asdu_layer, "vti_t")
        for i, v in enumerate(vals):
            t = transients[i] if i < len(transients) else ""
            if t and t in ("True", "Transient", "1"):
                result.append(f"{v}(T)")
            else:
                result.append(v)
        if not result:
            # Fallback: try the raw vti field
            raw_vals = self._get_multi_field_strs(asdu_layer, "vti")
            result.extend(raw_vals)
        return result

    def _extract_float_values(self, asdu_layer) -> List[str]:
        """Extract short floating point values, cleaning up trailing zeros."""
        result: List[str] = []
        raw = self.get_field(asdu_layer, "float", None)
        if raw is None:
            return result
        try:
            for f in getattr(asdu_layer, "float").all_fields:
                result.append(self._format_float(f.show))
        except Exception:
            result.append(self._format_float(str(raw)))
        return result

    def _extract_bcr_values(self, asdu_layer) -> List[str]:
        """Extract binary counter reading (integrated totals) values."""
        result: List[str] = []
        raw = self.get_field(asdu_layer, "bcr_count", None)
        if raw is not None:
            try:
                for f in getattr(asdu_layer, "bcr_count").all_fields:
                    result.append(str(f.show))
            except Exception:
                result.append(str(raw))
        if not result:
            # Fallback to bcr field
            raw = self.get_field(asdu_layer, "bcr", None)
            if raw is not None:
                result.append(str(raw))
        return result

    def _extract_sco_values(self, asdu_layer) -> List[str]:
        """Extract single command values (ON/OFF with select/execute)."""
        result: List[str] = []
        on_raw = self.get_field(asdu_layer, "sco_on", None)
        se_raw = self.get_field(asdu_layer, "sco_se", None)
        if on_raw is None:
            return result
        try:
            on_fields = list(getattr(asdu_layer, "sco_on").all_fields)
            se_fields: list = []
            if se_raw is not None:
                try:
                    se_fields = list(getattr(asdu_layer, "sco_se").all_fields)
                except Exception as e:
                    self.logger.debug(f"Failed to get se_fields: {e}")
            for i, f in enumerate(on_fields):
                val = "ON" if str(f.show) == "True" else "OFF"
                if i < len(se_fields) and str(se_fields[i].show) == "True":
                    val += "(S)"  # Select
                result.append(val)
        except Exception:
            val = "ON" if str(on_raw) == "True" else "OFF"
            if se_raw is not None and str(se_raw) == "True":
                val += "(S)"
            result.append(val)
        return result

    def _extract_dco_values(self, asdu_layer) -> List[str]:
        """Extract double command values."""
        result: List[str] = []
        on_raw = self.get_field(asdu_layer, "dco_on", None)
        se_raw = self.get_field(asdu_layer, "dco_se", None)
        if on_raw is None:
            return result
        try:
            on_fields = list(getattr(asdu_layer, "dco_on").all_fields)
            se_fields: list = []
            if se_raw is not None:
                try:
                    se_fields = list(getattr(asdu_layer, "dco_se").all_fields)
                except Exception as e:
                    self.logger.debug(f"Failed to get se_fields: {e}")
            for i, f in enumerate(on_fields):
                val = _DCO_VALUES.get(int(f.show), str(f.show))
                if i < len(se_fields) and str(se_fields[i].show) == "True":
                    val += "(S)"
                result.append(val)
        except Exception:
            try:
                val = _DCO_VALUES.get(int(on_raw), str(on_raw))
            except (ValueError, TypeError):
                val = str(on_raw)
            if se_raw is not None and str(se_raw) == "True":
                val += "(S)"
            result.append(val)
        return result

    def _extract_rco_values(self, asdu_layer) -> List[str]:
        """Extract regulating step command values."""
        result: List[str] = []
        up_raw = self.get_field(asdu_layer, "rco_up", None)
        se_raw = self.get_field(asdu_layer, "rco_se", None)
        if up_raw is None:
            return result
        try:
            up_fields = list(getattr(asdu_layer, "rco_up").all_fields)
            se_fields: list = []
            if se_raw is not None:
                try:
                    se_fields = list(getattr(asdu_layer, "rco_se").all_fields)
                except Exception as e:
                    self.logger.debug(f"Failed to get se_fields: {e}")
            for i, f in enumerate(up_fields):
                val = _RCO_VALUES.get(int(f.show), str(f.show))
                if i < len(se_fields) and str(se_fields[i].show) == "True":
                    val += "(S)"
                result.append(val)
        except Exception:
            try:
                val = _RCO_VALUES.get(int(up_raw), str(up_raw))
            except (ValueError, TypeError):
                val = str(up_raw)
            if se_raw is not None and str(se_raw) == "True":
                val += "(S)"
            result.append(val)
        return result

    def _extract_coi_values(self, asdu_layer) -> List[str]:
        """Extract cause of initialization values."""
        raw = self.get_field(asdu_layer, "coi_r", None)
        if raw is None:
            return []
        coi_reasons = {0: "local_power", 1: "local_reset", 2: "remote_reset"}
        try:
            reason = coi_reasons.get(int(raw), str(raw))
        except (ValueError, TypeError):
            reason = str(raw)
        return [f"COI={reason}"]

    def _extract_simple_field(self, asdu_layer, field_name: str, prefix: str = "") -> List[str]:
        """Extract a simple single-valued field."""
        raw = self.get_field(asdu_layer, field_name, None)
        if raw is None:
            return []
        return [f"{prefix}{raw}"]

    def _extract_quality(self, asdu_layer, type_id: int) -> List[str]:
        """Extract quality flags per IOA as abbreviated strings.

        Returns a list of quality strings (one per IOA), e.g. ["IV,NT", "", "OV"].
        Empty strings mean no quality issues (all flags OK).
        """
        cat = _TYPE_CATEGORIES.get(type_id)
        if cat is None:
            return []

        quality_source = cat[1]
        if quality_source is None:
            return []

        if quality_source == "qds":
            return self._extract_qds_flags(asdu_layer)
        elif quality_source == "siq":
            return self._extract_siq_flags(asdu_layer)
        elif quality_source == "diq":
            return self._extract_diq_flags(asdu_layer)
        return []

    def _extract_qds_flags(self, asdu_layer) -> List[str]:
        """Extract QDS quality descriptor set flags per IOA."""
        flag_fields = [
            ("qds_iv", "IV"),
            ("qds_nt", "NT"),
            ("qds_sb", "SB"),
            ("qds_bl", "BL"),
            ("qds_ov", "OV"),
        ]
        return self._collect_quality_flags(asdu_layer, flag_fields)

    def _extract_siq_flags(self, asdu_layer) -> List[str]:
        """Extract SIQ quality flags per IOA."""
        flag_fields = [
            ("siq_iv", "IV"),
            ("siq_nt", "NT"),
            ("siq_sb", "SB"),
            ("siq_bl", "BL"),
        ]
        return self._collect_quality_flags(asdu_layer, flag_fields)

    def _extract_diq_flags(self, asdu_layer) -> List[str]:
        """Extract DIQ quality flags per IOA."""
        flag_fields = [
            ("diq_iv", "IV"),
            ("diq_nt", "NT"),
            ("diq_sb", "SB"),
            ("diq_bl", "BL"),
        ]
        return self._collect_quality_flags(asdu_layer, flag_fields)

    def _collect_quality_flags(self, asdu_layer, flag_fields: List[Tuple[str, str]]) -> List[str]:
        """Collect quality flags across multiple IOAs.

        For each IOA, builds a comma-separated string of active flag abbreviations.
        """
        # Determine how many IOAs we have from the first available flag field
        n_ioas = 0
        flag_arrays: List[List[bool]] = []

        for attr_name, _abbrev in flag_fields:
            raw = self.get_field(asdu_layer, attr_name, None)
            if raw is None:
                flag_arrays.append([])
                continue

            bools: List[bool] = []
            try:
                for f in getattr(asdu_layer, attr_name).all_fields:
                    bools.append(str(f.show) == "True")
            except Exception:
                bools.append(str(raw) == "True")

            flag_arrays.append(bools)
            if len(bools) > n_ioas:
                n_ioas = len(bools)

        if n_ioas == 0:
            return []

        result: List[str] = []
        for i in range(n_ioas):
            active: List[str] = []
            for j, (_attr, abbrev) in enumerate(flag_fields):
                arr = flag_arrays[j]
                if i < len(arr) and arr[i]:
                    active.append(abbrev)
            result.append("|".join(active))
        return result

    @staticmethod
    def _build_asdu_summary(
        type_id: int,
        type_name: str,
        ioa_list: List[int],
        common_addr: int,
        is_control: bool,
        values: Optional[List[str]] = None,
        cot_name: str = "",
        is_error: bool = False,
        link_addr: int = 0,
    ) -> str:
        """Build summary for an ASDU/I-frame interaction."""
        if is_error:
            prefix = "ERR"
        elif is_control:
            prefix = "CMD"
        else:
            prefix = "MON"

        ioa_str = ""
        if ioa_list:
            if len(ioa_list) == 1:
                ioa_str = f" IOA={ioa_list[0]}"
            else:
                ioa_str = f" IOA={ioa_list[0]}-{ioa_list[-1]}"

        ca_str = f" CA={common_addr}" if common_addr else ""
        la_str = f" LA={link_addr}" if link_addr else ""
        cot_str = f" COT={cot_name}" if cot_name else ""
        val_str = ""
        if values:
            if len(values) == 1:
                val_str = f" val={values[0]}"
            else:
                val_str = f" val=[{','.join(values)}]"
        return f"{prefix} {type_name}{la_str}{ioa_str}{ca_str}{cot_str}{val_str}"

    def _parse_asdu_core(self, session, asdu_layer) -> Optional[Dict[str, Any]]:
        """Parse the common ASDU header fields shared by IEC 101/104.

        Extracts common address, IOA list, cause of transmission, P/N bit,
        control/monitor classification, values, and quality. Returns a dict
        with parsed fields, or ``None`` on parse failure (missing/unparseable
        type ID).
        """
        type_id_raw = self.get_field(asdu_layer, "typeid", None)
        if not type_id_raw:
            return None
        try:
            type_id = int(type_id_raw)
        except (ValueError, TypeError) as e:
            self.logger.debug(f"Failed to get type_id: {e}")
            return None

        common_addr = 0
        common_addr_raw = self.get_field(asdu_layer, "addr", None)
        if common_addr_raw:
            try:
                common_addr = int(common_addr_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get common_addr: {e}")
        session.common_addresses.add(common_addr)

        ioa_list = self._get_multi_field_ints(asdu_layer, "ioa")
        for ioa in ioa_list:
            session.ioa_seen.add(ioa)

        cause_tx = parse_asdu_field(self.get_field(asdu_layer, "causetx", None), 0)

        is_negative = False
        nega_raw = self.get_field(asdu_layer, "nega", None)
        if nega_raw is not None:
            is_negative = str(nega_raw) in ("True", "1", "true")

        session.type_ids.add(type_id)
        is_control = type_id in CONTROL_TYPE_IDS
        if is_control:
            session.control_count += 1
        else:
            session.monitor_count += 1

        type_name = TYPE_IDS.get(type_id, f"Type{type_id}")
        cot_name = COT_NAMES.get(cause_tx, str(cause_tx))
        if is_negative:
            cot_name = f"neg_{cot_name}"
        is_error_cot = cause_tx in _ERROR_COTS or is_negative

        values = self._extract_values(asdu_layer, type_id)
        quality_list = self._extract_quality(asdu_layer, type_id)

        rw = classify_rw(
            type_id,
            is_error_cot,
            write_ids=_WRITE_TYPE_IDS,
            read_ids=_READ_COMMAND_TYPE_IDS,
            system_ids=_SYSTEM_TYPE_IDS,
            file_ids=_FILE_TYPE_IDS,
        )

        return {
            "type_id": type_id,
            "type_name": type_name,
            "common_address": common_addr,
            "cause_of_transmission": cause_tx,
            "cot_name": cot_name,
            "rw": rw,
            "negative": is_negative,
            "is_control": is_control,
            "is_error_cot": is_error_cot,
            "ioa_list": ioa_list,
            "values": values,
            "quality": quality_list,
        }

    def _record_link_frame(
        self,
        packet,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        link_addr: int,
        is_primary: bool,
        func_code: int,
        func_name: str,
        direction: str,
        operation: str,
        *,
        rw: Optional[str] = None,
    ) -> None:
        """Record a link-layer-only frame interaction (no ASDU)."""
        now = datetime.now().isoformat()
        _sp, _dp = self.get_port_info(packet)

        details: Dict[str, Any] = {
            "link_addr": link_addr,
            "frame_type": "link",
            "is_primary": is_primary,
        }
        if rw is not None:
            details["rw"] = rw
        if func_code >= 0:
            details["link_func_code"] = func_code
            details["link_func_name"] = func_name

        summary = f"Link {func_name} addr={link_addr}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=_sp,
            dst_port=_dp,
            stream_id=self.get_stream_id(packet),
        )
