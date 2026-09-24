"""
Modbus SunSpec Discovery Mixin

Handles SunSpec runtime model discovery per the SunSpec specification:
- Probes well-known base addresses (40000, 0, 50000) for the SunSpec marker
- Walks the model chain to discover all supported models
- Reads and decodes registers using static JSON map files where available
- Applies scale factors from sunssf (signed int16 exponent) registers
- Handles SunSpec "not implemented" sentinel values

SunSpec Protocol Overview:
    Every SunSpec-compliant device has a magic marker 0x53756E53 ("SunS")
    at a well-known base address. After the marker, models are chained:
    each starts with [model_id (u16), length (u16)] followed by `length`
    registers of model data. The chain ends with model_id = 0xFFFF.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from oida.protocols.modbus.decoder import REGISTERS_PER_TYPE, ModbusDecoder

import logging

logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object
from oida.protocols.modbus.mixins.sunspec_constants import (
    SUNSPEC_ACTIVE_STATES,
    SUNSPEC_BASE_ADDRESSES,
    SUNSPEC_CRITICAL_CONTROLS,
    SUNSPEC_END_MODEL_ID,
    SUNSPEC_MARKER,
    SUNSPEC_MODEL_NAMES,
    SUNSPEC_NOT_IMPLEMENTED,
    SUNSPEC_SECURITY_MODELS,
    SUNSPEC_SF_MAX,
    SUNSPEC_SF_MIN,
)


def _load_sunspec_maps() -> Dict[int, dict]:
    """
    Load all SunSpec register map JSON files and index by model ID.

    Returns:
        Dictionary mapping model_id -> register map dict
    """
    maps = {}
    sunspec_dir = Path(__file__).parent.parent / "register_maps" / "sunspec"

    if not sunspec_dir.exists():
        return maps

    for json_file in sunspec_dir.glob("sunspec-*.json"):
        try:
            with open(json_file, "r") as f:
                data = json.load(f)
            model_id = data.get("sunspec_model_id")
            if model_id is not None:
                maps[model_id] = data
        except (json.JSONDecodeError, KeyError, OSError) as e:
            logger.debug(f"Failed to load SunSpec map {json_file.name}: {e}")
            continue

    return maps


def _is_not_implemented(value: Any, dtype: str) -> bool:
    """
    Check if a raw value matches the SunSpec "Not Implemented" sentinel.

    Handles both raw unsigned register values and decoded signed values,
    since the sentinel for i16 is 0x8000 which decodes to -32768.

    Args:
        value: The raw integer or float value
        dtype: The SunSpec data type string

    Returns:
        True if the value is a "not implemented" sentinel
    """
    sentinel = SUNSPEC_NOT_IMPLEMENTED.get(dtype)
    if sentinel is None:
        return False

    if dtype == "f32":
        # math.isnan raises TypeError on a non-numeric value; treat that as
        # "not the NaN sentinel".
        try:
            return math.isnan(value)
        except TypeError:
            return False

    # For signed types, check both the unsigned sentinel and the signed equivalent
    if dtype in ("i16", "sunssf"):
        return bool(value == 0x8000 or value == -32768)
    if dtype == "i32":
        return bool(value == 0x80000000 or value == -2147483648)
    if dtype == "i64":
        return bool(value == 0x8000000000000000 or value == -(1 << 63))

    return value == sentinel


# SunSpec accumulator / scale-factor aliases map onto the standard integer
# types the ModbusDecoder already understands. SunSpec is always big-endian.
_SUNSPEC_TYPE_ALIASES = {
    "sunssf": "i16",
    "acc16": "u16",
    "acc32": "u32",
    "acc64": "u64",
    "string": "str",
}

_sunspec_decoder = ModbusDecoder(byte_order="big", word_order="big")


def _raw_regs_to_value(regs: List[int], dtype: str) -> Optional[Any]:
    """
    Convert a raw register list to a typed scalar value.

    Thin wrapper over :class:`ModbusDecoder` (big/big, as SunSpec mandates)
    that folds the SunSpec-specific aliases (sunssf, acc16/32/64) onto the
    base integer types.

    Args:
        regs: List of 16-bit unsigned register values
        dtype: Data type (u16, i16, u32, i32, str, sunssf, acc32, etc.)

    Returns:
        Decoded value, or None on failure / insufficient registers.
    """
    if not regs:
        return None

    decode_type = _SUNSPEC_TYPE_ALIASES.get(dtype, dtype)
    try:
        decoded = _sunspec_decoder.decode(regs, decode_type)
    except ValueError:
        # Unknown SunSpec type — fall back to the raw first register.
        return regs[0]
    return decoded[0]["value"] if decoded else None


class SunSpecMixin(_ScannerBase):
    """Mixin providing SunSpec runtime model discovery for Modbus connections."""

    def _handle_sunspec(self):
        """
        Main SunSpec discovery handler.

        Probes well-known base addresses for the SunSpec marker, walks the
        model chain, reads register data using static JSON maps where available,
        and displays results.
        """
        self.logger.display("[SunSpec] Starting SunSpec device discovery...")

        unit_id = getattr(self.args, "unit_id", None)
        if unit_id is None:
            unit_id = 1
        verbose = getattr(self.args, "verbose", 0) or 0

        # Step 1: Find the SunSpec base address
        base_addr = self._sunspec_find_base(unit_id)
        if base_addr is None:
            self.logger.fail("[SunSpec] No SunSpec marker found at any well-known address")
            self.logger.display(
                "  Probed addresses: " + ", ".join(str(a) for a in SUNSPEC_BASE_ADDRESSES)
            )
            self.results["data"]["sunspec"] = {"found": False}
            return

        self.logger.success(f"[SunSpec] Marker found at base address {base_addr}")

        # Step 2: Walk the model chain
        models = self._sunspec_walk_models(base_addr, unit_id)
        if not models:
            self.logger.warning("[SunSpec] No models found after marker")
            self.results["data"]["sunspec"] = {
                "found": True,
                "base_address": base_addr,
                "models": [],
            }
            return

        self.logger.success(f"[SunSpec] Discovered {len(models)} model(s)")

        # Show model summary
        model_summary = []
        for m in models:
            mid = m["model_id"]
            name = SUNSPEC_MODEL_NAMES.get(mid, "Unknown")
            model_summary.append(f"{mid} ({name})")
        self.logger.display("  Models: " + ", ".join(model_summary))

        # Step 3: Load static register maps
        sunspec_maps = _load_sunspec_maps()
        self.logger.debug(f"Loaded {len(sunspec_maps)} SunSpec register map(s)")

        # Step 4: Read and decode each model
        results_models = []
        for model_info in models:
            model_result = self._sunspec_read_model(model_info, sunspec_maps, unit_id, verbose)
            results_models.append(model_result)

        # Store results
        self.results["data"]["sunspec"] = {
            "found": True,
            "base_address": base_addr,
            "models": results_models,
        }

        # Step 5: Security assessment (gated on --sunspec-assess)
        if getattr(self.args, "sunspec_assess", False):
            self._sunspec_assess_security(results_models)

    def _sunspec_find_base(self, unit_id: int) -> Optional[int]:
        """
        Probe well-known addresses for the SunSpec magic marker (0x53756E53).

        The marker is a 32-bit value stored across two consecutive holding
        registers. We read 2 registers starting at each candidate base address.

        Args:
            unit_id: Modbus unit/slave ID

        Returns:
            Base address where marker was found, or None
        """
        for addr in SUNSPEC_BASE_ADDRESSES:
            self.logger.debug(f"Probing SunSpec marker at address {addr}...")
            try:
                result = self.conn.read_holding_registers(addr, count=2, device_id=unit_id)
                if result.isError():
                    self.logger.debug(f"  Address {addr}: read error")
                    continue

                regs = list(result.registers)
                if len(regs) < 2:
                    continue

                marker = (regs[0] << 16) | regs[1]
                if marker == SUNSPEC_MARKER:
                    return addr

                self.logger.debug(
                    f"  Address {addr}: got 0x{marker:08X}, expected 0x{SUNSPEC_MARKER:08X}"
                )
            except Exception as e:
                self.logger.debug(f"  Address {addr}: exception {e}")
                continue

        return None

    def _sunspec_walk_models(self, base_addr: int, unit_id: int) -> List[Dict[str, Any]]:
        """
        Walk the SunSpec model chain starting after the magic marker.

        Each model header is [model_id (u16), length (u16)]. We read headers
        sequentially, advancing by (2 + length) registers each time, until
        we hit model_id 0xFFFF (end sentinel) or a read error.

        Args:
            base_addr: Address where the SunSpec marker was found
            unit_id: Modbus unit/slave ID

        Returns:
            List of dicts with model_id, length, and data_address for each model
        """
        models = []
        # First model header starts 2 registers after the marker
        cursor = base_addr + 2
        max_models = 50  # Safety limit to prevent infinite loops

        for _ in range(max_models):
            try:
                result = self.conn.read_holding_registers(cursor, count=2, device_id=unit_id)
                if result.isError():
                    self.logger.debug(f"Model walk: read error at address {cursor}")
                    break

                regs = list(result.registers)
                if len(regs) < 2:
                    break

                model_id = regs[0]
                model_length = regs[1]

                # End sentinel
                if model_id == SUNSPEC_END_MODEL_ID:
                    self.logger.debug(f"Model walk: end sentinel at address {cursor}")
                    break

                # Sanity check: model_length should be reasonable
                if model_length == 0 or model_length > 2000:
                    self.logger.debug(
                        f"Model walk: suspicious length {model_length} for model {model_id} at {cursor}"
                    )
                    break

                name = SUNSPEC_MODEL_NAMES.get(model_id, "Unknown")
                self.logger.debug(
                    f"Model walk: ID={model_id} ({name}), length={model_length}, "
                    f"data_addr={cursor + 2}"
                )

                models.append(
                    {
                        "model_id": model_id,
                        "length": model_length,
                        "header_address": cursor,
                        "data_address": cursor + 2,
                    }
                )

                # Advance cursor past header (2 regs) + data (model_length regs)
                cursor += 2 + model_length

            except Exception as e:
                self.logger.debug(f"Model walk: exception at address {cursor}: {e}")
                break
        else:
            self.logger.warning(
                f"[SunSpec] Model walk stopped at {max_models} model limit "
                f"(address {cursor}) -- possible malformed model chain"
            )

        return models

    def _sunspec_read_model(
        self,
        model_info: Dict[str, Any],
        sunspec_maps: Dict[int, dict],
        unit_id: int,
        verbose: int,
    ) -> Dict[str, Any]:
        """
        Read all registers for a discovered SunSpec model.

        If a static JSON register map exists for this model ID, use it to
        decode registers with names, types, units, and scale factors.
        Otherwise, dump raw register values.

        Args:
            model_info: Dict with model_id, length, data_address
            sunspec_maps: Loaded JSON maps indexed by model_id
            unit_id: Modbus unit/slave ID
            verbose: Verbosity level

        Returns:
            Dict with model metadata and decoded register values
        """

        model_id = model_info["model_id"]
        model_length = model_info["length"]
        data_address = model_info["data_address"]
        name = SUNSPEC_MODEL_NAMES.get(model_id, "Unknown")
        reg_map = sunspec_maps.get(model_id)

        result_data = {
            "model_id": model_id,
            "name": name,
            "length": model_length,
            "address": model_info["header_address"],
            "has_map": reg_map is not None,
            "registers": {},
        }

        # Read all model registers in a single batch (or chunks if > 125)
        raw_data = self._sunspec_read_block(data_address, model_length, unit_id)
        if raw_data is None:
            self.logger.warning(f"[SunSpec] Failed to read model {model_id} ({name}) data")
            return result_data

        if reg_map:
            # Decode using the static register map
            self._sunspec_display_mapped_model(
                model_id, name, reg_map, raw_data, data_address, verbose, result_data
            )
        else:
            # No map available - show raw dump
            self._sunspec_display_raw_model(
                model_id, name, raw_data, data_address, model_length, verbose, result_data
            )

        return result_data

    def _sunspec_read_block(self, start_addr: int, count: int, unit_id: int) -> Optional[List[int]]:
        """
        Read a block of holding registers, chunking if necessary.

        Modbus limits reads to 125 registers per request. This method
        handles splitting larger reads into multiple requests.

        Args:
            start_addr: Starting register address
            count: Number of registers to read
            unit_id: Modbus unit/slave ID

        Returns:
            List of register values, or None on failure
        """
        max_per_read = getattr(self.args, "max_registers", 125) or 125
        all_regs = []
        remaining = count
        addr = start_addr

        while remaining > 0:
            chunk = min(remaining, max_per_read)
            try:
                result = self.conn.read_holding_registers(addr, count=chunk, device_id=unit_id)
                if result.isError():
                    self.logger.debug(f"Block read error at address {addr}, chunk={chunk}")
                    return None
                all_regs.extend(list(result.registers))
            except Exception as e:
                self.logger.debug(f"Block read exception at address {addr}: {e}")
                return None

            addr += chunk
            remaining -= chunk

        return all_regs

    def _sunspec_display_mapped_model(
        self,
        model_id: int,
        name: str,
        reg_map: dict,
        raw_data: List[int],
        data_address: int,
        verbose: int,
        result_data: Dict[str, Any],
    ):
        """
        Display a SunSpec model using a static register map for decoding.

        Reads through the register map definitions, extracts values from
        the raw data block, applies scale factors, and formats output as
        a table.

        Args:
            model_id: SunSpec model ID
            name: Human-readable model name
            reg_map: The loaded JSON register map
            raw_data: All register values for this model block
            data_address: Absolute Modbus address of first data register
            verbose: Verbosity level
            result_data: Dict to populate with decoded values
        """
        from oida.utils.export_utils import print_table

        registers_def = reg_map.get("registers", {})
        if not registers_def:
            self.logger.display(
                f"[SunSpec Model {model_id}] {name} - map has no register definitions"
            )
            return

        model_desc = reg_map.get("description", name)
        self.logger.display(f"[SunSpec Model {model_id}] {model_desc}")

        # Compute the data offset: JSON addresses include the model header
        # (2 registers: model_id + model_length). For model 1, they also include
        # the SunS marker (2 more registers). raw_data starts at the first data
        # register after the header, so we subtract the header size.
        # Detect this by finding the "model_id" or "model_length" register in
        # the map — the data starts right after it.
        header_end = 2  # default: model_id(0) + model_length(1) -> data at 2
        if "model_id" in registers_def:
            header_end = registers_def["model_id"].get("address", 0) + 2
        elif "model_length" in registers_def:
            header_end = registers_def["model_length"].get("address", 0) + 1
        data_offset = header_end  # JSON address of first data register

        # Filter to only data registers (skip header fields in the JSON)
        data_regs = {k: v for k, v in registers_def.items() if v.get("address", 0) >= data_offset}

        # First pass: read all scale factor values from the raw data
        # Scale factor registers are relative offsets within the model data
        sf_values = {}
        for reg_name, reg_def in data_regs.items():
            addr_offset = reg_def.get("address", 0) - data_offset
            dtype = reg_def.get("type", "u16")
            # Scale factor registers are typically i16 (sunssf)
            if dtype in ("i16", "sunssf") and "_sf" in reg_name.lower():
                regs_needed = REGISTERS_PER_TYPE.get(dtype, 1) or 1
                if addr_offset + regs_needed <= len(raw_data):
                    sf_raw = raw_data[addr_offset : addr_offset + regs_needed]
                    sf_val = _raw_regs_to_value(sf_raw, "i16")
                    if sf_val is not None and not _is_not_implemented(sf_raw[0], "sunssf"):
                        # SunSpec defines sunssf as -10..10. The value comes off
                        # the wire and is used as an exponent (10 ** sf), so an
                        # out-of-range one would build a multi-thousand-digit int
                        # (ValueError on str()) or overflow a float. Drop it and
                        # report the register unscaled instead.
                        if not (SUNSPEC_SF_MIN <= sf_val <= SUNSPEC_SF_MAX):
                            self.logger.debug(
                                f"Ignoring out-of-range SunSpec scale factor "
                                f"{reg_name}={sf_val} (legal range "
                                f"{SUNSPEC_SF_MIN}..{SUNSPEC_SF_MAX})"
                            )
                            continue
                        # Store keyed by the JSON address so scale_factor_register refs work
                        sf_values[reg_def.get("address", 0)] = sf_val

        # Second pass: decode all registers
        sorted_regs = sorted(data_regs.items(), key=lambda x: x[1].get("address", 0))

        rows = []
        if verbose:
            headers = ["Name", "Addr", "Type", "Value", "Raw", "Description"]
        else:
            headers = ["Name", "Addr", "Value", "Description"]

        for reg_name, reg_def in sorted_regs:
            json_addr = reg_def.get("address")
            if json_addr is None:
                continue

            # Convert JSON address to raw_data index
            raw_idx = json_addr - data_offset
            abs_addr = data_address + raw_idx  # absolute Modbus address for display

            dtype = reg_def.get("type", "u16")
            unit = reg_def.get("unit", "")
            description = reg_def.get("description", "")
            sf_register = reg_def.get("scale_factor_register")
            enum_map = reg_def.get("enum")

            # Determine register count
            if dtype in ("str", "string"):
                char_length = reg_def.get("length", 2)
                regs_needed = (char_length + 1) // 2
            else:
                regs_needed = REGISTERS_PER_TYPE.get(dtype, 1) or 1

            # Skip if data not available for this register
            if raw_idx < 0 or raw_idx + regs_needed > len(raw_data):
                if verbose:
                    rows.append([reg_name, f"{abs_addr}", dtype, "N/A", "-", description])
                else:
                    rows.append([reg_name, f"{abs_addr}", "N/A", description])
                continue

            # Extract raw register values
            reg_slice = raw_data[raw_idx : raw_idx + regs_needed]
            raw_hex = " ".join(f"{r:04X}" for r in reg_slice)

            # Decode raw value
            raw_value = _raw_regs_to_value(reg_slice, dtype)

            # Check for "not implemented" sentinel
            if raw_value is not None and _is_not_implemented(raw_value, dtype):
                value_str = "N/I"
                result_data["registers"][reg_name] = {"value": None, "not_implemented": True}
                if verbose:
                    rows.append([reg_name, f"{abs_addr}", dtype, value_str, raw_hex, description])
                else:
                    rows.append([reg_name, f"{abs_addr}", value_str, description])
                continue

            if raw_value is None:
                value_str = f"[{raw_hex}]"
                result_data["registers"][reg_name] = {
                    "raw": None,
                    "value": None,
                    "access": reg_def.get("access", "r"),
                }
            elif isinstance(raw_value, str):
                value_str = raw_value if raw_value else "(empty)"
                result_data["registers"][reg_name] = {
                    "raw": raw_value,
                    "value": raw_value,
                    "access": reg_def.get("access", "r"),
                }
            else:
                # Apply scale factor if defined
                scaled_value = raw_value
                if sf_register is not None and sf_register in sf_values:
                    sf = sf_values[sf_register]
                    scaled_value = raw_value * (10**sf)

                # Format the number
                if isinstance(scaled_value, float) and not math.isfinite(scaled_value):
                    # inf/-inf survives the "not implemented" NaN check for f32
                    # and would blow up int(scaled_value) below.
                    value_str = str(scaled_value)
                elif isinstance(scaled_value, float):
                    if scaled_value == int(scaled_value):
                        value_str = str(int(scaled_value))
                    else:
                        value_str = f"{scaled_value:.6g}"
                else:
                    value_str = str(scaled_value)

                # Apply enum mapping
                if enum_map:
                    key = str(int(raw_value))
                    label = enum_map.get(key)
                    if label:
                        value_str = f"{value_str} ({label})"

                # Append unit
                if unit:
                    value_str = f"{value_str} {unit}"

                access = reg_def.get("access", "r")
                reg_entry: Dict[str, Any] = {
                    "raw": raw_value,
                    "value": scaled_value if sf_register else raw_value,
                    "unit": unit,
                    "access": access,
                }
                result_data["registers"][reg_name] = reg_entry

            if verbose:
                rows.append([reg_name, f"{abs_addr}", dtype, value_str, raw_hex, description])
            else:
                rows.append([reg_name, f"{abs_addr}", value_str, description])

        if rows:
            print_table(rows, headers, logger=self.logger)

    def _sunspec_display_raw_model(
        self,
        model_id: int,
        name: str,
        raw_data: List[int],
        data_address: int,
        model_length: int,
        verbose: int,
        result_data: Dict[str, Any],
    ):
        """
        Display a SunSpec model as raw register values (no map available).

        Shows a compact dump of register addresses and values for models
        where no static JSON map is available.

        Args:
            model_id: SunSpec model ID
            name: Human-readable model name
            raw_data: All register values for this model block
            data_address: Absolute Modbus address of first data register
            model_length: Number of data registers
            verbose: Verbosity level
            result_data: Dict to populate with raw values
        """
        self.logger.display(f"[SunSpec Model {model_id}] {name} ({model_length} registers, no map)")

        if not raw_data:
            return

        # Show a compact hex dump
        line_parts = []
        for i, val in enumerate(raw_data):
            abs_addr = data_address + i
            line_parts.append(f"{abs_addr}=0x{val:04X}")
            result_data["registers"][f"reg_{i}"] = {"raw": val, "address": abs_addr}

        # Display in rows of 8
        chunk_size = 8
        for i in range(0, len(line_parts), chunk_size):
            chunk = line_parts[i : i + chunk_size]
            self.logger.display("  " + "  ".join(chunk))

    def _sunspec_assess_security(
        self,
        results_models: List[Dict[str, Any]],
    ):
        """
        Analyze discovered SunSpec models for security concerns.

        Checks for:
        - Absence of security models (3-9)
        - Writable critical control registers (connect/disconnect, power limiting)
        - Active production state with exposed controls
        - Battery remote control exposure
        - Device rated capacity for impact assessment

        Args:
            results_models: Decoded model results from _sunspec_read_model()
        """
        from oida.utils.export_utils import print_table

        self.logger.display("")
        self.logger.display("[SunSpec Security Assessment]")

        model_ids = {m["model_id"] for m in results_models}
        findings_start_idx = len(self.logger.findings)

        # Build lookup of model results by ID (first instance wins for duplicates)
        models_by_id: Dict[int, Dict[str, Any]] = {}
        for m in results_models:
            mid = m["model_id"]
            if mid in models_by_id:
                self.logger.debug(f"[SunSpec] Duplicate model ID {mid} -- using first instance")
            else:
                models_by_id[mid] = m

        # --- 1. Check for security models (3-9) ---
        found_security = model_ids & SUNSPEC_SECURITY_MODELS
        if not found_security:
            self.logger.security_finding(
                "No SunSpec security models (3-9) present",
                detail=(
                    "Device has no Secure Dataset models -- all Modbus registers "
                    "readable/writable without authentication"
                ),
            )

        else:
            self.logger.display(f"  Security models present: {sorted(found_security)}")

        # --- 2. Check for writable critical controls ---
        writable_controls: List[List[str]] = []  # rows for summary table
        for ctrl_model_id, ctrl_regs in SUNSPEC_CRITICAL_CONTROLS.items():
            model_data = models_by_id.get(ctrl_model_id)
            if model_data is None:
                continue

            registers = model_data.get("registers", {})
            for reg_name, impact in ctrl_regs.items():
                reg_info = registers.get(reg_name)
                if reg_info is None:
                    continue
                # Use the actual access level from the register map.
                # Previously we overrode 'r' with the spec's 'rw' which
                # produced a false-positive 'writable control' finding for
                # every device whose vendor map correctly marks the
                # register read-only (the spec says 'rw' for the field
                # class, but a given device may restrict it). Trust the
                # map; the spec value is informational only.
                access = reg_info.get("access", "r")
                if access == "rw":
                    value = reg_info.get("value")
                    not_impl = reg_info.get("not_implemented", False)
                    if not_impl:
                        continue
                    value_str = str(value) if value is not None else "?"
                    model_name = SUNSPEC_MODEL_NAMES.get(ctrl_model_id, "Unknown")
                    writable_controls.append(
                        [f"{ctrl_model_id}", model_name, reg_name, value_str, impact]
                    )

        if writable_controls:
            self.logger.security_finding(
                f"{len(writable_controls)} writable control register(s) exposed",
                detail="Critical DER control registers accessible without authentication",
            )

            headers = ["Model", "Name", "Register", "Value", "Impact"]
            print_table(writable_controls, headers, logger=self.logger)

            # Highlight most dangerous registers
            conn_exposed = any(r[2] == "conn" for r in writable_controls)
            set_op_exposed = any(r[2] == "set_op" for r in writable_controls)
            stor_ctl_exposed = any(r[2] == "stor_ctl_mod" for r in writable_controls)

            if conn_exposed:
                self.logger.security_finding(
                    "Inverter connect/disconnect register (Conn) is writable",
                    detail="Model 123 Conn register can disconnect inverter from grid via single Modbus write",
                )

            if set_op_exposed:
                self.logger.security_finding(
                    "Battery connect/disconnect register (SetOp) is writable",
                    detail="Model 802 SetOp can disconnect battery system via Modbus write",
                )

            if stor_ctl_exposed:
                self.logger.security_finding(
                    "Battery storage control mode (StorCtl_Mod) is writable",
                    detail="Model 124 StorCtl_Mod controls charge/discharge behavior",
                )

        # --- 3. Detect active production state ---
        active_production = False
        ac_power_w = None
        operating_state_str = None

        for inv_model_id in (101, 102, 103, 111, 112, 113):
            inv_data = models_by_id.get(inv_model_id)
            if inv_data is None:
                continue

            inv_regs = inv_data.get("registers", {})

            # Check operating_state
            op_state = inv_regs.get("operating_state", {})
            op_raw = op_state.get("raw") if isinstance(op_state, dict) else None
            if op_raw is not None and op_raw in SUNSPEC_ACTIVE_STATES:
                active_production = True
                enum_map = {4: "MPPT", 5: "THROTTLED"}
                operating_state_str = enum_map.get(op_raw, str(op_raw))

            # Check ac_power
            power_info = inv_regs.get("ac_power", {})
            if isinstance(power_info, dict):
                pv = power_info.get("value")
                if pv is not None and isinstance(pv, (int, float)) and pv > 0:
                    ac_power_w = pv

        if active_production and writable_controls:
            detail_parts = []
            if operating_state_str:
                detail_parts.append(f"state={operating_state_str}")
            if ac_power_w is not None:
                detail_parts.append(f"AC power={ac_power_w:.0f}W")
            self.logger.security_finding(
                "Inverter actively producing with writable controls exposed",
                detail=f"Device is online and generating power ({', '.join(detail_parts)})",
            )

        # --- 4. Detect battery remote control state ---
        bat_data = models_by_id.get(802)
        if bat_data:
            bat_regs = bat_data.get("registers", {})
            loc_rem = bat_regs.get("loc_rem_ctl", {})
            if isinstance(loc_rem, dict) and loc_rem.get("raw") == 0:
                self.logger.security_finding(
                    "Battery in REMOTE control mode",
                    detail="Battery accepts remote commands -- writable registers are live",
                )

        # --- 5. Report device rated capacity ---
        np_data = models_by_id.get(120)
        if np_data:
            np_regs = np_data.get("registers", {})
            w_rtg_info = np_regs.get("w_rtg", {})
            if isinstance(w_rtg_info, dict):
                w_rtg = w_rtg_info.get("value")
                if w_rtg is not None and isinstance(w_rtg, (int, float)) and w_rtg > 0:
                    if w_rtg >= 1_000_000:
                        capacity_str = f"{w_rtg / 1_000_000:.1f} MW"
                    elif w_rtg >= 1_000:
                        capacity_str = f"{w_rtg / 1_000:.1f} kW"
                    else:
                        capacity_str = f"{w_rtg:.0f} W"
                    self.logger.display(f"  Rated capacity: {capacity_str}")

                    if w_rtg >= 100_000 and writable_controls:
                        self.logger.security_finding(
                            f"High-capacity DER ({capacity_str}) with exposed controls",
                            detail=(
                                "Utility-scale device with writable control registers -- "
                                "grid stability impact if manipulated"
                            ),
                        )

        # --- Summary ---
        sunspec_findings = self.logger.findings[findings_start_idx:]
        findings_count = len(sunspec_findings)

        self.logger.display("")
        if findings_count == 0:
            self.logger.success("[SunSpec] No security findings")
        else:
            self.logger.warning(f"[SunSpec] {findings_count} security finding(s) identified")

        # Store findings in results for JSON export
        sunspec_data = self.results["data"].get("sunspec", {})
        sunspec_data["security_findings_count"] = findings_count
        sunspec_data["security_findings"] = list(sunspec_findings)
