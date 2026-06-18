#!/usr/bin/env python3
"""
Modbus Register Map Validator

Validates all JSON register map files for correct structure and values.
Performs strict schema validation including nested structures.

Usage:
    python -m oida.protocols.modbus.validate_maps
    python -m oida.protocols.modbus.validate_maps --fix  # Auto-fix common issues
    python -m oida.protocols.modbus.validate_maps path/to/map.json  # Validate single file
"""

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from ...utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)

# =============================================================================
# SCHEMA DEFINITIONS
# =============================================================================

# Valid top-level keys in register map files
VALID_TOP_KEYS: Set[str] = {
    # Device identification
    "vendor",
    "model",
    "models",
    "device_type",
    "description",
    "version",
    # Connection defaults
    "byte_order",
    "word_order",
    "default_unit_id",
    "default_port",
    "default_ip",
    "function_code",
    "protocol",
    # Documentation
    "notes",
    "source",
    # Register sections
    "holding_registers",
    "input_registers",
    "coils",
    "discrete_inputs",
    "registers",
    # Metadata sections
    "enums",
    "commands",
    "fault_codes",
    "warning_codes",
    "error_flags",
    "control_word_bits",
    "status_word_bits",
    "control_commands",
    # SunSpec specific
    "sunspec_model_id",
    "base_address",
    "standard",
    # MEI device identification
    "mei_expected",
    # Supported features
    "supported_function_codes",
    # Address ranges
    "address_ranges",
    # Extended/custom info container (for device-specific data)
    "extended_info",
}

# Register section keys (Modbus function code specific)
REGISTER_SECTIONS: Set[str] = {
    "holding_registers",  # FC 3/6/16
    "input_registers",  # FC 4
    "coils",  # FC 1/5/15
    "discrete_inputs",  # FC 2
    "registers",  # Legacy generic key
}

# Valid register field keys (generic only - no vendor-specific fields)
VALID_REG_KEYS: Set[str] = {
    # Required
    "address",
    "type",
    # Common optional
    "access",
    "scale",
    "unit",
    "description",
    "function_code",
    "notes",
    # Enums and bitfields
    "enum",
    "bits",
    "bitfield",
    "values",
    # Constraints
    "min",
    "max",
    "range",
    "length",
    # SunSpec scale factor
    "scale_factor_register",
    # Computed addresses
    "offset",
    # Validation/expected value
    "expected_value",
}

# Valid keys in command definitions
VALID_COMMAND_KEYS: Set[str] = {
    "register",
    "address",
    "value",
    "description",
    "notes",
    "function_code",
    "type",
    "access",
}

# Valid keys in supported_function_codes list items
VALID_FC_ITEM_KEYS: Set[str] = {
    "code",
    "function",
    "area",
    "description",
    "notes",
}

# Valid keys in models dict entries
VALID_MODEL_KEYS: Set[str] = {
    "description",
    "has_modbus_tcp",
    "has_modbus_rtu",
    "default_unit_id",
    "notes",
    "variants",
    "ports",
}

# Valid keys in address_ranges dict entries
VALID_ADDR_RANGE_KEYS: Set[str] = {
    "start",
    "end",
    "function_code",
    "description",
    "ads_group",
    "notes",
}

# Valid data types (matches decoder.py TYPE_ALIASES)
VALID_TYPES: Set[str] = {
    # Floats
    "f32",
    "f64",
    "float",
    "float32",
    "float64",
    "double",
    # Signed integers
    "i16",
    "i32",
    "i64",
    "int",
    "int16",
    "int32",
    "int64",
    "s16",
    "s32",
    "s64",
    # Unsigned integers
    "u16",
    "u32",
    "u64",
    "uint",
    "uint16",
    "uint32",
    "uint64",
    # String/text
    "str",
    "string",
    "text",
    "ascii",
    # Binary
    "hex",
    "raw",
    "binary",
    "bits",
    "bit",
    # BCD
    "bcd",
    # Coil type
    "coil",
    "bool",
    "boolean",
}

# Valid access modes
VALID_ACCESS: Set[str] = {
    "ro",
    "rw",
    "r",
    "w",
    "read",
    "write",
    "read-only",
    "read-write",
    "readonly",
    "readwrite",
}

# Valid byte/word orders
VALID_ENDIAN: Set[str] = {"big", "little"}

# Type to expected register count
TYPE_REG_COUNT: Dict[str, int] = {
    "u16": 1,
    "i16": 1,
    "s16": 1,
    "uint16": 1,
    "int16": 1,
    "uint": 1,
    "int": 1,
    "u32": 2,
    "i32": 2,
    "s32": 2,
    "uint32": 2,
    "int32": 2,
    "f32": 2,
    "float": 2,
    "float32": 2,
    "u64": 4,
    "i64": 4,
    "s64": 4,
    "uint64": 4,
    "int64": 4,
    "f64": 4,
    "double": 4,
    "float64": 4,
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def is_valid_type(type_str: str) -> bool:
    """Check if type is valid, including string types with length suffix."""
    type_lower = type_str.lower()
    if type_lower in VALID_TYPES:
        return True
    # Check for string with length: str7, str10, str20, string16, etc.
    if re.match(r"^(str|string)\d+$", type_lower):
        return True
    return False


def is_valid_bit_key(key: str) -> bool:
    """Check if a key is a valid bit position (0-31 as string or int)."""
    try:
        bit_num = int(key)
        return 0 <= bit_num <= 31
    except (ValueError, TypeError) as e:
        logger.debug(f"Failed to get bit_num: {e}")
        return False


def is_valid_enum_key(key: str) -> bool:
    """Check if a key is a valid enum code (numeric string or hex)."""
    try:
        # Allow decimal
        int(key)
        return True
    except ValueError as e:
        logger.debug(f"Decimal int parse failed for enum key: {e}")
    # Allow hex format
    if key.startswith("0x") or key.startswith("0X"):
        try:
            int(key, 16)
            return True
        except ValueError as e:
            logger.debug(f"Hex int parse failed for enum key: {e}")
    return False


# =============================================================================
# VALIDATION RESULT CLASS
# =============================================================================


class ValidationResult:
    """Holds validation results for a single file."""

    def __init__(self, path: Path):
        self.path = path
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.fixes: List[Tuple[str, Any, Any]] = []  # (field, old_value, new_value)

    def error(self, msg: str):
        self.errors.append(msg)

    def warning(self, msg: str):
        self.warnings.append(msg)

    def fix(self, field: str, old_val: Any, new_val: Any):
        self.fixes.append((field, old_val, new_val))

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0


# =============================================================================
# NESTED STRUCTURE VALIDATORS
# =============================================================================


def validate_enums(data: dict, result: ValidationResult) -> None:
    """Validate the 'enums' section structure."""
    enums = data.get("enums")
    if enums is None:
        return

    if not isinstance(enums, dict):
        result.error("'enums' must be a dictionary")
        return

    for enum_name, enum_values in enums.items():
        if not isinstance(enum_values, dict):
            result.error(
                f"enums['{enum_name}']: must be a dictionary mapping codes to descriptions"
            )
            continue

        for code, description in enum_values.items():
            if not isinstance(description, str):
                result.error(
                    f"enums['{enum_name}']['{code}']: value must be a string, got {type(description).__name__}"
                )


def validate_fault_warning_codes(data: dict, result: ValidationResult) -> None:
    """Validate fault_codes, warning_codes, error_flags sections."""
    for section in ("fault_codes", "warning_codes", "error_flags"):
        codes = data.get(section)
        if codes is None:
            continue

        if not isinstance(codes, dict):
            result.error(f"'{section}' must be a dictionary")
            continue

        for code, description in codes.items():
            if not isinstance(description, str):
                result.error(
                    f"{section}['{code}']: value must be a string, got {type(description).__name__}"
                )


def validate_control_status_bits(data: dict, result: ValidationResult) -> None:
    """Validate control_word_bits and status_word_bits sections."""
    for section in ("control_word_bits", "status_word_bits"):
        bits = data.get(section)
        if bits is None:
            continue

        if not isinstance(bits, dict):
            result.error(f"'{section}' must be a dictionary")
            continue

        for bit_pos, bit_name in bits.items():
            if not is_valid_bit_key(bit_pos):
                result.warning(f"{section}['{bit_pos}']: bit position should be 0-31")
            if not isinstance(bit_name, str):
                result.error(
                    f"{section}['{bit_pos}']: value must be a string, got {type(bit_name).__name__}"
                )


def validate_commands(data: dict, result: ValidationResult) -> None:
    """Validate the 'commands' and 'control_commands' sections."""
    for section in ("commands", "control_commands"):
        commands = data.get(section)
        if commands is None:
            continue

        if not isinstance(commands, dict):
            result.error(f"'{section}' must be a dictionary")
            continue

        for cmd_name, cmd_def in commands.items():
            if not isinstance(cmd_def, dict):
                result.error(f"{section}['{cmd_name}']: must be a dictionary")
                continue

            for key in cmd_def.keys():
                if key not in VALID_COMMAND_KEYS:
                    result.warning(f"{section}['{cmd_name}']: non-standard key '{key}'")


def validate_supported_function_codes(data: dict, result: ValidationResult) -> None:
    """Validate supported_function_codes list."""
    fc_list = data.get("supported_function_codes")
    if fc_list is None:
        return

    if not isinstance(fc_list, list):
        result.error("'supported_function_codes' must be a list")
        return

    for i, fc_item in enumerate(fc_list):
        if not isinstance(fc_item, dict):
            result.error(f"supported_function_codes[{i}]: must be a dictionary")
            continue

        for key in fc_item.keys():
            if key not in VALID_FC_ITEM_KEYS:
                result.warning(f"supported_function_codes[{i}]: non-standard key '{key}'")


def validate_models(data: dict, result: ValidationResult) -> None:
    """Validate the 'models' section (for multi-model files).

    Can be either:
    - A list of model names: ["Model1", "Model2", ...]
    - A dict with model details: {"Model1": {"description": "...", ...}, ...}
    """
    models = data.get("models")
    if models is None:
        return

    if isinstance(models, list):
        # Simple list of model names is valid
        for i, item in enumerate(models):
            if not isinstance(item, str):
                result.error(f"models[{i}]: list items must be strings")
        return

    if not isinstance(models, dict):
        result.error("'models' must be a list or dictionary")
        return

    for model_id, model_info in models.items():
        if not isinstance(model_info, dict):
            result.error(f"models['{model_id}']: must be a dictionary")
            continue

        for key in model_info.keys():
            if key not in VALID_MODEL_KEYS:
                result.warning(f"models['{model_id}']: non-standard key '{key}'")


def validate_address_ranges(data: dict, result: ValidationResult) -> None:
    """Validate the 'address_ranges' section."""
    ranges = data.get("address_ranges")
    if ranges is None:
        return

    if not isinstance(ranges, dict):
        result.error("'address_ranges' must be a dictionary")
        return

    for range_name, range_def in ranges.items():
        if not isinstance(range_def, dict):
            result.error(f"address_ranges['{range_name}']: must be a dictionary")
            continue

        for key in range_def.keys():
            if key not in VALID_ADDR_RANGE_KEYS:
                result.warning(f"address_ranges['{range_name}']: non-standard key '{key}'")

        # Validate start/end are integers
        if "start" in range_def and not isinstance(range_def["start"], int):
            result.error(f"address_ranges['{range_name}']: 'start' must be an integer")
        if "end" in range_def and not isinstance(range_def["end"], int):
            result.error(f"address_ranges['{range_name}']: 'end' must be an integer")


def validate_mei_expected(data: dict, result: ValidationResult) -> None:
    """Validate the 'mei_expected' section."""
    mei = data.get("mei_expected")
    if mei is None:
        return

    if not isinstance(mei, dict):
        result.error("'mei_expected' must be a dictionary")
        return

    # Valid MEI object IDs (from Modbus spec)
    valid_mei_keys = {
        "0x00",
        "0x01",
        "0x02",
        "0x03",
        "0x04",
        "0x05",
        "0x06",
        "0x07",
        "vendor_name",
        "product_code",
        "major_minor_revision",
        "vendor_url",
        "product_name",
        "model_name",
        "user_application_name",
        "supported_objects",  # List of supported MEI objects
    }

    for key, value in mei.items():
        if key not in valid_mei_keys:
            result.warning(f"mei_expected['{key}']: non-standard MEI object key")
        # Values can be string or list (for supported_objects)
        if not isinstance(value, (str, list)):
            result.error(f"mei_expected['{key}']: value must be a string or list")


def validate_notes(data: dict, result: ValidationResult) -> None:
    """Validate the 'notes' field (can be string or dict)."""
    notes = data.get("notes")
    if notes is None:
        return

    if not isinstance(notes, (str, dict)):
        result.error("'notes' must be a string or dictionary")
        return

    if isinstance(notes, dict):
        for key, value in notes.items():
            if not isinstance(value, str):
                result.error(f"notes['{key}']: value must be a string")


def validate_extended_info(data: dict, result: ValidationResult) -> None:
    """Validate the 'extended_info' section (allows any keys but must be dict)."""
    ext = data.get("extended_info")
    if ext is None:
        return

    if not isinstance(ext, dict):
        result.error("'extended_info' must be a dictionary")


def validate_register_bits(reg_name: str, reg_def: dict, result: ValidationResult) -> None:
    """Validate 'bits' field within a register definition."""
    bits = reg_def.get("bits")
    if bits is None:
        return

    if not isinstance(bits, dict):
        result.error(f"Register '{reg_name}': 'bits' must be a dictionary")
        return

    for bit_pos, bit_desc in bits.items():
        if not is_valid_bit_key(bit_pos):
            result.warning(
                f"Register '{reg_name}': bits['{bit_pos}'] - bit position should be 0-31"
            )
        if not isinstance(bit_desc, str):
            result.error(f"Register '{reg_name}': bits['{bit_pos}'] value must be a string")


def validate_register_enum(
    reg_name: str, reg_def: dict, data: dict, result: ValidationResult
) -> None:
    """Validate 'enum' field within a register definition."""
    enum = reg_def.get("enum")
    if enum is None:
        return

    if isinstance(enum, str):
        # Reference to global enum
        enums = data.get("enums", {})
        if enum not in enums:
            result.warning(f"Register '{reg_name}': enum '{enum}' not found in 'enums' section")
    elif isinstance(enum, dict):
        # Inline enum definition
        for code, description in enum.items():
            if not isinstance(description, str):
                result.error(f"Register '{reg_name}': enum['{code}'] value must be a string")
    else:
        result.error(
            f"Register '{reg_name}': 'enum' must be a string (reference) or dictionary (inline)"
        )


# =============================================================================
# MAIN VALIDATION FUNCTION
# =============================================================================


def validate_register_map(
    filepath: Path, auto_fix: bool = False, strict: bool = False
) -> ValidationResult:
    """
    Validate a single register map file with strict schema checking.

    Args:
        filepath: Path to JSON file
        auto_fix: If True, apply fixes to the data structure
        strict: If True, treat 'no registers' as error instead of warning

    Returns:
        ValidationResult with errors, warnings, and suggested fixes
    """
    result = ValidationResult(filepath)

    # Load JSON
    try:
        with open(filepath) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        result.error(f"Invalid JSON: {e}")
        return result
    except Exception as e:
        result.error(f"Failed to read file: {e}")
        return result

    if not isinstance(data, dict):
        result.error("Root element must be a JSON object")
        return result

    # =========================================================================
    # TOP-LEVEL FIELD VALIDATION
    # =========================================================================

    # Check required fields
    if "vendor" not in data:
        result.error("Missing required field 'vendor'")
    elif not isinstance(data["vendor"], str):
        result.error("Field 'vendor' must be a string")

    if "model" not in data:
        result.error("Missing required field 'model'")
    elif not isinstance(data["model"], str):
        result.error("Field 'model' must be a string")

    # Check byte_order
    if "byte_order" in data:
        if data["byte_order"] not in VALID_ENDIAN:
            if data["byte_order"] == "configurable":
                result.warning("byte_order is 'configurable' - using 'big' as default")
                if auto_fix:
                    result.fix("byte_order", data["byte_order"], "big")
                    data["byte_order"] = "big"
            else:
                result.error(f"Invalid byte_order '{data['byte_order']}' (must be: {VALID_ENDIAN})")

    # Check word_order
    if "word_order" in data:
        if data["word_order"] not in VALID_ENDIAN:
            if data["word_order"] == "configurable":
                result.warning("word_order is 'configurable' - using 'big' as default")
                if auto_fix:
                    result.fix("word_order", data["word_order"], "big")
                    data["word_order"] = "big"
            else:
                result.error(f"Invalid word_order '{data['word_order']}' (must be: {VALID_ENDIAN})")

    # Check for non-standard top-level keys
    for key in data.keys():
        if key not in VALID_TOP_KEYS:
            result.error(f"Non-standard top-level key '{key}' (move to 'extended_info' if custom)")

    # =========================================================================
    # VALIDATE NESTED METADATA SECTIONS
    # =========================================================================

    validate_enums(data, result)
    validate_fault_warning_codes(data, result)
    validate_control_status_bits(data, result)
    validate_commands(data, result)
    validate_supported_function_codes(data, result)
    validate_models(data, result)
    validate_address_ranges(data, result)
    validate_mei_expected(data, result)
    validate_notes(data, result)
    validate_extended_info(data, result)

    # =========================================================================
    # REGISTER VALIDATION
    # =========================================================================

    all_registers: Dict[str, dict] = {}
    has_any_registers = False

    for section in REGISTER_SECTIONS:
        section_regs = data.get(section, {})
        if section_regs and isinstance(section_regs, dict):
            has_any_registers = True
            for reg_name, reg_def in section_regs.items():
                all_registers[f"{section}.{reg_name}"] = reg_def

    if not has_any_registers:
        msg = "No registers defined (holding_registers, input_registers, coils, discrete_inputs)"
        if strict:
            result.error(msg)
        else:
            result.warning(msg)
        # Still validate metadata sections even without registers
        if auto_fix and result.fixes:
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
        return result

    # Track addresses for overlap detection
    addresses_by_fc: Dict[int, Dict[int, str]] = {}
    registers_to_remove: List[str] = []

    for full_reg_name, reg_def in all_registers.items():
        section, reg_name = full_reg_name.split(".", 1)

        if not isinstance(reg_def, dict):
            result.error(f"Register '{reg_name}': definition must be a dictionary")
            continue

        # ----- Check address -----
        address = reg_def.get("address")
        if address is None:
            result.error(f"Register '{reg_name}': missing 'address' field")
            continue

        if not isinstance(address, int):
            if address in ("configurable", "application_defined", "N/A", "varies"):
                result.warning(f"Register '{reg_name}': address is '{address}' (placeholder)")
                if auto_fix:
                    registers_to_remove.append((section, reg_name))
                    result.fix(f"{full_reg_name}", "placeholder", "removed")
            else:
                result.error(f"Register '{reg_name}': address must be integer, got '{address}'")
            continue

        if address < 0 or address > 65535:
            result.error(f"Register '{reg_name}': address {address} out of range (0-65535)")

        # ----- Check type -----
        reg_type = reg_def.get("type", "u16")
        if not isinstance(reg_type, str):
            result.error(f"Register '{reg_name}': type must be a string")
        elif not is_valid_type(reg_type):
            result.error(f"Register '{reg_name}': invalid type '{reg_type}'")

        # ----- Check access -----
        if "access" in reg_def:
            access = reg_def["access"]
            if isinstance(access, str) and access.lower() not in VALID_ACCESS:
                result.warning(f"Register '{reg_name}': unusual access mode '{access}'")

        # ----- Check scale -----
        if "scale" in reg_def:
            scale = reg_def["scale"]
            if not isinstance(scale, (int, float)):
                result.error(f"Register '{reg_name}': scale must be numeric, got '{scale}'")

        # ----- Check for address overlaps -----
        fc = reg_def.get("function_code", 3)
        if fc not in addresses_by_fc:
            addresses_by_fc[fc] = {}

        type_lower = reg_type.lower() if isinstance(reg_type, str) else "u16"
        reg_count = TYPE_REG_COUNT.get(type_lower, 1)
        for offset in range(reg_count):
            addr = address + offset
            if addr in addresses_by_fc[fc]:
                other = addresses_by_fc[fc][addr]
                result.warning(
                    f"Register '{reg_name}': address {addr} overlaps with '{other}' (FC {fc})"
                )
            else:
                addresses_by_fc[fc][addr] = reg_name

        # ----- Check for non-standard register keys -----
        for key in reg_def.keys():
            if key not in VALID_REG_KEYS:
                result.error(f"Register '{reg_name}': non-standard key '{key}'")

        # ----- Validate nested register fields -----
        validate_register_bits(reg_name, reg_def, result)
        validate_register_enum(reg_name, reg_def, data, result)

    # Remove placeholder registers if auto-fixing
    if auto_fix and registers_to_remove:
        for section, reg_name in registers_to_remove:
            if section in data and reg_name in data[section]:
                del data[section][reg_name]

    # Save fixed file if auto-fix was applied
    if auto_fix and result.fixes:
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")

    return result


# =============================================================================
# BATCH VALIDATION
# =============================================================================


def validate_all_maps(
    map_dir: Path, auto_fix: bool = False, strict: bool = False
) -> List[ValidationResult]:
    """Validate all register map files in a directory."""
    results = []
    # Track vendor+model for duplicate detection
    seen_devices: Dict[str, List[Path]] = {}

    for json_file in sorted(map_dir.rglob("*.json")):
        result = validate_register_map(json_file, auto_fix, strict)
        results.append(result)

        # Track vendor+model for duplicate detection
        try:
            with open(json_file) as f:
                data = json.load(f)
            vendor = data.get("vendor", "").lower().strip()
            model = data.get("model", "").lower().strip()
            if vendor and model:
                key = f"{vendor}|{model}"
                if key not in seen_devices:
                    seen_devices[key] = []
                seen_devices[key].append(json_file)
        except Exception as e:
            logger.debug(f"with open(json_file) as f:: {e}")

    # Check for duplicates
    for key, files in seen_devices.items():
        if len(files) > 1:
            vendor, model = key.split("|")
            # Find which file has the most registers
            file_reg_counts = []
            for f in files:
                try:
                    with open(f) as fp:
                        data = json.load(fp)
                    count = sum(len(data.get(section, {})) for section in REGISTER_SECTIONS)
                    file_reg_counts.append((f, count))
                except Exception:
                    file_reg_counts.append((f, 0))

            # Sort by register count descending
            file_reg_counts.sort(key=lambda x: x[1], reverse=True)
            best_file, best_count = file_reg_counts[0]

            # Add warnings to all results for duplicate files
            for r in results:
                if r.path in files:
                    if r.path == best_file:
                        r.warning(
                            f"Duplicate device '{vendor} {model}' - this file has most registers ({best_count})"
                        )
                    else:
                        r.warning(
                            f"Duplicate device '{vendor} {model}' - consider removing (better: {best_file.name})"
                        )

    return results


# =============================================================================
# REPORTING
# =============================================================================


def print_report(results: List[ValidationResult], verbose: bool = False) -> bool:
    """Print validation report."""
    total_errors = sum(len(r.errors) for r in results)
    total_warnings = sum(len(r.warnings) for r in results)
    total_fixes = sum(len(r.fixes) for r in results)

    # Count registers
    total_registers = 0
    for r in results:
        try:
            with open(r.path) as f:
                data = json.load(f)
            for section in REGISTER_SECTIONS:
                total_registers += len(data.get(section, {}))
        except Exception as e:
            logger.debug(f"with open(r.path) as f:: {e}")

    logger.info("=" * 70)
    logger.info("MODBUS REGISTER MAP VALIDATION REPORT")
    logger.info("=" * 70)
    logger.info("Files checked:  %d", len(results))
    logger.info("Total registers: %d", total_registers)
    logger.info("Errors:         %d", total_errors)
    logger.info("Warnings:       %d", total_warnings)
    if total_fixes:
        logger.info("Fixes applied:  %d", total_fixes)

    # Group results
    error_files = [r for r in results if r.errors]
    warning_files = [r for r in results if r.warnings and not r.errors]

    if error_files:
        logger.info("-" * 70)
        logger.info("FILES WITH ERRORS:")
        logger.info("-" * 70)
        for r in error_files:
            rel_path = r.path.name
            logger.info("  %s:", rel_path)
            for e in r.errors:
                logger.error("    %s", e)
            if verbose:
                for w in r.warnings:
                    logger.warning("    %s", w)

    if verbose and warning_files:
        logger.info("-" * 70)
        logger.info("FILES WITH WARNINGS:")
        logger.info("-" * 70)
        for r in warning_files:
            rel_path = r.path.name
            logger.info("  %s:", rel_path)
            for w in r.warnings:
                logger.warning("    %s", w)
    elif warning_files and not verbose:
        logger.info("%d files have warnings (use -v to see details)", len(warning_files))

    # Summary
    logger.info("=" * 70)
    if total_errors == 0:
        logger.info("All register maps are valid!")
    else:
        logger.error("%d errors found in %d files", total_errors, len(error_files))
    logger.info("=" * 70)

    return total_errors == 0


# =============================================================================
# CLI
# =============================================================================


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Validate Modbus register map JSON files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m oida.protocols.modbus.validate_maps           # Validate all maps
  python -m oida.protocols.modbus.validate_maps -v        # Verbose output
  python -m oida.protocols.modbus.validate_maps --fix     # Auto-fix issues
  python -m oida.protocols.modbus.validate_maps --strict  # Require registers
  python -m oida.protocols.modbus.validate_maps --dupes   # Show duplicates only
  python -m oida.protocols.modbus.validate_maps map.json  # Single file
        """,
    )
    parser.add_argument("files", nargs="*", help="Specific JSON files to validate")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all warnings")
    parser.add_argument("--fix", action="store_true", help="Auto-fix common issues")
    parser.add_argument("--strict", action="store_true", help="Treat 'no registers' as error")
    parser.add_argument("--dupes", action="store_true", help="Show duplicate vendor+model only")
    parser.add_argument("--map-dir", type=Path, help="Register map directory")

    args = parser.parse_args()

    # Determine map directory
    if args.map_dir:
        map_dir = args.map_dir
    else:
        # Find relative to this script
        script_dir = Path(__file__).parent
        map_dir = script_dir / "register_maps"
        if not map_dir.exists():
            # Try from cwd
            map_dir = Path("src/oida/protocols/modbus/register_maps")

    if args.files:
        # Validate specific files
        results = []
        for f in args.files:
            filepath = Path(f)
            if not filepath.exists():
                logger.error("File not found: %s", f)
                continue
            results.append(validate_register_map(filepath, args.fix, args.strict))
    else:
        # Validate all maps
        if not map_dir.exists():
            logger.error("Map directory not found: %s", map_dir)
            sys.exit(1)
        results = validate_all_maps(map_dir, args.fix, args.strict)

    # Filter to duplicates only if --dupes flag
    if args.dupes:
        results = [r for r in results if any("Duplicate device" in w for w in r.warnings)]
        args.verbose = True  # Show details for duplicates

    success = print_report(results, args.verbose)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
