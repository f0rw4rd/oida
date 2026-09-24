#!/usr/bin/env python3
"""
Convert external Modbus register map formats to OIDA format.

Supported input formats:
- Solarman YAML (Home Assistant integration)
- Nymea JSON (nymea-plugins-modbus)
- mbmd Go meter definitions

OIDA Format Specification:
{
  "vendor": "string",           # Required
  "model": "string",            # Required
  "description": "string",      # Optional
  "byte_order": "big|little",   # Default: "big"
  "word_order": "big|little",   # Default: "big"
  "registers": {
    "register_name": {
      "address": int,           # Required: 0-65535
      "type": "string",         # Required: u16, i16, u32, i32, f32, f64, str, etc.
      "access": "ro|rw|w",      # Default: "ro"
      "description": "string",  # Optional
      "unit": "string",         # Optional: V, A, W, kWh, °C, etc.
      "scale": float,           # Optional: default 1.0
      "function_code": int,     # Optional: default 3
      "enum": {}                # Optional: value-to-label mapping
    }
  }
}

Usage:
    python -m oida.protocols.modbus.convert_maps solarman /path/to/yaml_dir -o output_dir
    python -m oida.protocols.modbus.convert_maps nymea /path/to/json_dir -o output_dir
    python -m oida.protocols.modbus.convert_maps mbmd /path/to/mbmd -o output_dir
"""

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from oida.utils.ics_logger import get_module_logger
from oida.utils.lazy_import import lazy_import

logger = get_module_logger(__name__)

_yaml = lazy_import("yaml", "Modbus", install_hint="pip install oida-ics[modbus]")


# =============================================================================
# OIDA Type Mapping
# =============================================================================

# Solarman rule to OIDA type mapping
SOLARMAN_RULE_TO_TYPE = {
    1: "u16",  # Single unsigned 16-bit
    2: "i16",  # Signed 16-bit
    3: "u32",  # 32-bit big-endian
    4: "u32",  # 32-bit little-endian (word order differs)
    5: "str",  # Multi-register string
    6: "str",  # Single register string
    9: "u16",  # Time of use (BCD)
    10: "str",  # DateTime array
}

# Nymea type to OIDA type mapping
NYMEA_TYPE_MAP = {
    "float": "f32",
    "double": "f64",
    "uint16": "u16",
    "uint32": "u32",
    "uint64": "u64",
    "int16": "i16",
    "int32": "i32",
    "int64": "i64",
    "string": "str",
}

# Nymea register type to function code
NYMEA_REGTYPE_TO_FC = {
    "holdingRegister": 3,
    "inputRegister": 4,
    "coil": 1,
    "discreteInput": 2,
}


# =============================================================================
# Solarman YAML Converter
# =============================================================================


def convert_solarman_yaml(filepath: Path) -> Optional[Dict[str, Any]]:
    """
    Convert Solarman YAML inverter definition to OIDA format.

    Solarman format:
        parameters:
          - group: solar
            items:
              - name: "PV1 Power"
                uom: "W"
                scale: 1
                rule: 1
                registers: [0x00BA]
    """
    if not _yaml.is_available:
        logger.error("PyYAML required. Install with: pip install oida-ics[modbus]")
        return None

    try:
        with open(filepath) as f:
            data = _yaml.safe_load(f)
    except Exception as e:
        logger.error("Error parsing %s: %s", filepath.name, e)
        return None

    if not data or "parameters" not in data:
        return None

    # Extract vendor/model from filename (e.g., deye_hybrid.yaml -> Deye, Hybrid)
    stem = filepath.stem
    parts = stem.split("_", 1)
    vendor = parts[0].title()
    model = parts[1].replace("_", " ").title() if len(parts) > 1 else stem.title()

    # Determine word order from rule 4 usage (little-endian 32-bit)
    has_rule_4 = any(
        item.get("rule") == 4
        for group in data.get("parameters", [])
        for item in group.get("items", [])
    )

    oida_map = {
        "vendor": vendor,
        "model": model,
        "description": f"Imported from Home Assistant Solarman ({filepath.name})",
        "byte_order": "big",
        "word_order": "little" if has_rule_4 else "big",
        "source": f"home_assistant_solarman/{filepath.name}",
        "registers": {},
    }

    # Process parameter groups
    for group in data.get("parameters", []):
        for item in group.get("items", []):
            name = item.get("name", "")
            if not name:
                continue

            registers = item.get("registers", [])
            if not registers:
                continue

            # Get address from first register
            address = registers[0]
            if isinstance(address, str):
                address = int(address, 0)  # Handle hex strings like "0x00BA"

            # Determine type from rule
            rule = item.get("rule", 1)
            reg_type = SOLARMAN_RULE_TO_TYPE.get(rule, "u16")

            # Convert name to snake_case ID
            reg_id = re.sub(r"[^\w\s]", "", name.lower())
            reg_id = re.sub(r"\s+", "_", reg_id.strip())

            # Build register definition
            oida_reg = {
                "address": address,
                "type": reg_type,
                "access": "ro",
                "description": name,
            }

            # Add optional fields
            if item.get("uom"):
                oida_reg["unit"] = item["uom"]

            scale = item.get("scale", 1)
            if scale != 1:
                oida_reg["scale"] = scale

            # Handle offset (solarman subtracts offset, we store it for reference)
            if item.get("offset"):
                oida_reg["offset"] = -item["offset"]  # Negate for standard formula

            # Handle enumeration (lookup table)
            if item.get("isstr") and item.get("lookup"):
                oida_reg["enum"] = {str(entry["key"]): entry["value"] for entry in item["lookup"]}

            # Add function code if not default (3)
            # Solarman uses mb_functioncode in requests section
            # Default to holding registers (FC 3)

            oida_map["registers"][reg_id] = oida_reg

    return oida_map if oida_map["registers"] else None


# =============================================================================
# Nymea JSON Converter
# =============================================================================


def convert_nymea_json(filepath: Path) -> Optional[Dict[str, Any]]:
    """
    Convert nymea-plugins-modbus JSON to OIDA format.

    Nymea format:
        {
          "className": "Sdm630",
          "endianness": "BigEndian",
          "registers": [...],
          "blocks": [{"registers": [...]}]
        }
    """
    try:
        with open(filepath) as f:
            data = json.load(f)
    except Exception as e:
        logger.error("Error parsing %s: %s", filepath.name, e)
        return None

    class_name = data.get("className", filepath.stem)
    endianness = data.get("endianness", "BigEndian")

    # Determine byte/word order
    byte_order = "little" if endianness == "LittleEndian" else "big"
    word_order = byte_order  # Nymea doesn't distinguish

    oida_map = {
        "vendor": class_name,
        "model": class_name,
        "description": f"Imported from nymea-plugins-modbus ({filepath.parent.name})",
        "byte_order": byte_order,
        "word_order": word_order,
        "source": f"nymea-plugins-modbus/{filepath.parent.name}/{filepath.name}",
        "registers": {},
    }

    # Collect all registers from both top-level and blocks
    all_registers = list(data.get("registers", []))
    for block in data.get("blocks", []):
        all_registers.extend(block.get("registers", []))

    for reg in all_registers:
        reg_id = reg.get("id", "")
        if not reg_id:
            continue

        address = reg.get("address")
        if address is None or not isinstance(address, int):
            continue

        # Convert type
        size = reg.get("size", 1)
        nymea_type = reg.get("type", "uint16").lower()
        if nymea_type == "float":
            reg_type = "f32" if size == 2 else "f64"
        else:
            reg_type = NYMEA_TYPE_MAP.get(nymea_type, "u16")

        # Convert access
        access = reg.get("access", "RO").upper()
        oida_access = "rw" if access == "RW" else "ro"

        # Convert register type to function code
        reg_fc = NYMEA_REGTYPE_TO_FC.get(reg.get("registerType", "holdingRegister"), 3)

        oida_reg = {
            "address": address,
            "type": reg_type,
            "access": oida_access,
            "description": reg.get("description", ""),
        }

        if reg.get("unit"):
            oida_reg["unit"] = reg["unit"]

        if reg.get("scaleFactor") and reg["scaleFactor"] != 1:
            oida_reg["scale"] = reg["scaleFactor"]

        if reg_fc != 3:
            oida_reg["function_code"] = reg_fc

        oida_map["registers"][reg_id] = oida_reg

    # Process enums
    for enum in data.get("enums", []):
        enum_name = enum.get("name", "")
        if enum_name:
            # Store enums at top level for reference
            if "enums" not in oida_map:
                oida_map["enums"] = {}
            oida_map["enums"][enum_name] = {
                str(v["value"]): v["key"] for v in enum.get("values", [])
            }

    return oida_map if oida_map["registers"] else None


# =============================================================================
# mbmd Go Meter Converter
# =============================================================================


def convert_mbmd_go(filepath: Path) -> Optional[Dict[str, Any]]:
    """
    Convert an mbmd Go meter definition to OIDA format.

    mbmd format (Go source):
        Register("ABB", ...)
        opcodes: { Power: 0x5B14, // Total power }
    """
    try:
        content = filepath.read_text()
    except Exception as e:
        logger.error("Error reading %s: %s", filepath.name, e)
        return None

    # Extract meter name from Register() call
    name_match = re.search(r'Register\s*\(\s*"([^"]+)"', content)
    if not name_match:
        return None
    meter_name = name_match.group(1)

    # Extract description
    desc_match = re.search(r'func \([^)]+\) Description\(\) string \{\s*return "([^"]+)"', content)
    description = desc_match.group(1) if desc_match else meter_name

    # Extract opcodes (name: address, // comment)
    opcodes = {}
    opcode_pattern = re.compile(r"(\w+):\s*(0x[0-9A-Fa-f]+|\d+),?\s*//\s*(.+)?")
    for match in opcode_pattern.finditer(content):
        name = match.group(1)
        address = int(match.group(2), 0)  # Handles hex and decimal
        comment = match.group(3).strip() if match.group(3) else name
        opcodes[name] = {"address": address, "description": comment}

    if not opcodes:
        return None

    # Most meters read input registers (FC 4); holding registers if ReadHoldingReg present
    fc = 3 if "ReadHoldingReg" in content else 4

    oida_map = {
        "vendor": meter_name,
        "model": description,
        "description": f"Imported from mbmd ({filepath.stem})",
        "byte_order": "big",
        "word_order": "big",
        "source": f"mbmd/meters/rs485/{filepath.name}",
        "registers": {},
    }

    for name, info in opcodes.items():
        snake_name = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
        oida_map["registers"][snake_name] = {
            "address": info["address"],
            "type": "f32",  # Most meters use float32
            "access": "ro",
            "description": info["description"],
            "function_code": fc,
        }

    return oida_map if oida_map["registers"] else None


# =============================================================================
# Batch Conversion
# =============================================================================


def convert_directory(source_dir: Path, output_dir: Path, fmt: str) -> Tuple[int, int]:
    """
    Convert all files in a directory.

    Returns:
        Tuple of (success_count, total_count)
    """
    success = 0
    total = 0

    if fmt == "solarman":
        # Find solarman inverter definitions
        yaml_dir = source_dir / "custom_components" / "solarman" / "inverter_definitions"
        if not yaml_dir.exists():
            yaml_dir = source_dir  # Direct path to YAML files

        for yaml_file in sorted(yaml_dir.glob("*.yaml")):
            if yaml_file.name == "services.yaml":
                continue

            total += 1
            logger.info("Converting: %s", yaml_file.name)

            oida_map = convert_solarman_yaml(yaml_file)
            if not oida_map:
                logger.info("  Skipped (no registers)")
                continue

            # Output to solar subdirectory
            out_path = output_dir / "solar" / f"solarman-{yaml_file.stem}.json"
            out_path.parent.mkdir(parents=True, exist_ok=True)

            with open(out_path, "w") as f:
                json.dump(oida_map, f, indent=2)
                f.write("\n")

            logger.info(
                "  -> %s (%d registers)",
                out_path.relative_to(output_dir),
                len(oida_map["registers"]),
            )
            success += 1

    elif fmt == "nymea":
        for json_file in sorted(source_dir.rglob("*-registers.json")):
            total += 1
            logger.info("Converting: %s", json_file.relative_to(source_dir))

            oida_map = convert_nymea_json(json_file)
            if not oida_map:
                logger.info("  Skipped (no registers)")
                continue

            # Determine output subdirectory based on device type
            parent = json_file.parent.name
            if parent in ("sma", "solax", "sungrow", "kostal", "huawei", "wattsonic"):
                subdir = "solar"
            elif parent in (
                "amperfied",
                "mennekes",
                "vestel",
                "webasto",
                "schrack",
                "pcelectric",
                "phoenixconnect",
            ):
                subdir = "evchargers"
            elif parent in ("alphainnotec", "idm", "stiebeleltron"):
                subdir = "heatpumps"
            elif parent in ("bgetech", "inepro"):
                subdir = "meters"
            else:
                subdir = "misc"

            out_name = f"{parent}-{json_file.stem.replace('-registers', '')}.json"
            out_path = output_dir / subdir / out_name
            out_path.parent.mkdir(parents=True, exist_ok=True)

            with open(out_path, "w") as f:
                json.dump(oida_map, f, indent=2)
                f.write("\n")

            logger.info(
                "  -> %s (%d registers)",
                out_path.relative_to(output_dir),
                len(oida_map["registers"]),
            )
            success += 1

    elif fmt == "mbmd":
        meters_dir = source_dir / "meters" / "rs485"
        if not meters_dir.exists():
            meters_dir = source_dir  # Direct path to .go files

        skip = {"registry.go", "rs485.go", "producer.go", "transform.go"}
        for go_file in sorted(meters_dir.glob("*.go")):
            if go_file.name in skip:
                continue

            total += 1
            logger.info("Converting: %s", go_file.name)

            oida_map = convert_mbmd_go(go_file)
            if not oida_map:
                logger.info("  Skipped (no registers)")
                continue

            out_path = output_dir / "meters" / f"mbmd-{go_file.stem}.json"
            out_path.parent.mkdir(parents=True, exist_ok=True)

            with open(out_path, "w") as f:
                json.dump(oida_map, f, indent=2)
                f.write("\n")

            logger.info(
                "  -> %s (%d registers)",
                out_path.relative_to(output_dir),
                len(oida_map["registers"]),
            )
            success += 1

    return success, total


# =============================================================================
# CLI
# =============================================================================


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Convert external Modbus register maps to OIDA format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Convert Solarman YAML files
  python -m oida.protocols.modbus.convert_maps solarman /tmp/home_assistant_solarman

  # Convert Nymea JSON files
  python -m oida.protocols.modbus.convert_maps nymea /tmp/nymea-plugins-modbus

  # Convert mbmd Go meter definitions
  python -m oida.protocols.modbus.convert_maps mbmd /tmp/mbmd

  # Custom output directory
  python -m oida.protocols.modbus.convert_maps solarman /tmp/solarman -o ./my-maps
        """,
    )
    parser.add_argument(
        "format", choices=["solarman", "nymea", "mbmd"], help="Input format to convert from"
    )
    parser.add_argument(
        "source", type=Path, help="Source directory containing register definitions"
    )
    parser.add_argument(
        "-o", "--output", type=Path, help="Output directory (default: register_maps/)"
    )

    args = parser.parse_args()

    if not args.source.exists():
        logger.error("Source not found: %s", args.source)
        sys.exit(1)

    # Default output directory
    if args.output:
        output_dir = args.output
    else:
        output_dir = Path(__file__).parent / "register_maps"

    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Format: %s", args.format)
    logger.info("Source: %s", args.source)
    logger.info("Output: %s", output_dir)

    success, total = convert_directory(args.source, output_dir, args.format)

    logger.info("Converted %d/%d files to %s", success, total, output_dir)

    logger.info("Running validation...")
    from oida.protocols.modbus.validate_maps import validate_all_maps, print_report

    results = validate_all_maps(output_dir)
    print_report(results, verbose=False)


if __name__ == "__main__":
    main()
