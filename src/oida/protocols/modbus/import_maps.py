#!/usr/bin/env python3
"""
Import Modbus register maps from external sources.

Supports:
- nymea-plugins-modbus JSON format
- mbmd Go meter definitions
- Home Assistant Solarman YAML format
- Home Assistant integrations

Usage:
    python -m oida.protocols.modbus.import_maps /path/to/nymea-plugins-modbus
    python -m oida.protocols.modbus.import_maps /path/to/mbmd --format mbmd
    python -m oida.protocols.modbus.import_maps /path/to/home_assistant_solarman --format solarman
"""

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from ...utils.ics_logger import get_module_logger
from ...utils.lazy_import import lazy_import

logger = get_module_logger(__name__)

_yaml = lazy_import("yaml", "Modbus", install_hint="pip install pyyaml")


def convert_nymea_type(nymea_type: str, size: int) -> str:
    """Convert nymea type to OIDA type."""
    type_map = {
        "float": "f32" if size == 2 else "f64",
        "uint16": "u16",
        "uint32": "u32",
        "uint64": "u64",
        "int16": "i16",
        "int32": "i32",
        "int64": "i64",
        "string": "str",
    }
    return type_map.get(nymea_type.lower(), "u16")


def convert_nymea_access(access: str) -> str:
    """Convert nymea access to OIDA access."""
    access_map = {
        "RO": "ro",
        "RW": "rw",
        "WO": "w",
    }
    return access_map.get(access.upper(), "ro")


def convert_nymea_register_type(reg_type: str) -> int:
    """Convert nymea registerType to function code."""
    type_map = {
        "holdingRegister": 3,
        "inputRegister": 4,
        "coil": 1,
        "discreteInput": 2,
    }
    return type_map.get(reg_type, 3)


def parse_nymea_file(filepath: Path) -> Optional[Dict[str, Any]]:
    """Parse a nymea register JSON file and convert to OIDA format."""
    try:
        with open(filepath) as f:
            data = json.load(f)
    except (json.JSONDecodeError, Exception) as e:
        logger.error("Error parsing %s: %s", filepath, e)
        return None

    # Extract metadata
    class_name = data.get("className", filepath.stem)
    endianness = data.get("endianness", "BigEndian")

    # Determine byte/word order from endianness
    if endianness == "LittleEndian":
        byte_order = "little"
        word_order = "little"
    else:
        byte_order = "big"
        word_order = "big"

    # Build OIDA map
    oida_map = {
        "vendor": class_name,
        "model": class_name,
        "description": f"Imported from nymea-plugins-modbus ({filepath.parent.name})",
        "version": "1.0",
        "byte_order": byte_order,
        "word_order": word_order,
        "source": f"nymea-plugins-modbus/{filepath.parent.name}",
        "registers": {},
    }

    # Process standalone registers
    for reg in data.get("registers", []):
        reg_id = reg.get("id", "")
        if not reg_id:
            continue

        address = reg.get("address")
        if address is None or not isinstance(address, int):
            continue

        size = reg.get("size", 1)
        reg_type = convert_nymea_type(reg.get("type", "uint16"), size)
        access = convert_nymea_access(reg.get("access", "RO"))
        fc = convert_nymea_register_type(reg.get("registerType", "holdingRegister"))

        oida_reg = {
            "address": address,
            "type": reg_type,
            "access": access,
            "description": reg.get("description", ""),
        }

        if fc != 3:
            oida_reg["function_code"] = fc
        if reg.get("unit"):
            oida_reg["unit"] = reg["unit"]
        if reg.get("scaleFactor"):
            oida_reg["scale"] = reg["scaleFactor"]

        oida_map["registers"][reg_id] = oida_reg

    # Process blocks
    for block in data.get("blocks", []):
        for reg in block.get("registers", []):
            reg_id = reg.get("id", "")
            if not reg_id:
                continue

            address = reg.get("address")
            if address is None or not isinstance(address, int):
                continue

            size = reg.get("size", 1)
            reg_type = convert_nymea_type(reg.get("type", "uint16"), size)
            access = convert_nymea_access(reg.get("access", "RO"))
            fc = convert_nymea_register_type(reg.get("registerType", "holdingRegister"))

            oida_reg = {
                "address": address,
                "type": reg_type,
                "access": access,
                "description": reg.get("description", ""),
            }

            if fc != 3:
                oida_reg["function_code"] = fc
            if reg.get("unit"):
                oida_reg["unit"] = reg["unit"]
            if reg.get("scaleFactor"):
                oida_reg["scale"] = reg["scaleFactor"]

            oida_map["registers"][reg_id] = oida_reg

    # Process enums for reference
    enums = data.get("enums", [])
    if enums:
        oida_map["enums"] = {}
        for enum in enums:
            enum_name = enum.get("name", "")
            if enum_name:
                oida_map["enums"][enum_name] = {
                    v["key"]: v["value"] for v in enum.get("values", [])
                }

    return oida_map if oida_map["registers"] else None


def parse_mbmd_go_file(filepath: Path) -> Optional[Dict[str, Any]]:
    """Parse an mbmd Go meter file and convert to OIDA format."""
    try:
        content = filepath.read_text()
    except Exception as e:
        logger.error("Error reading %s: %s", filepath, e)
        return None

    # Extract meter name from Register() call
    name_match = re.search(r'Register\s*\(\s*"([^"]+)"', content)
    if not name_match:
        return None

    meter_name = name_match.group(1)

    # Extract description
    desc_match = re.search(r'func \([^)]+\) Description\(\) string \{\s*return "([^"]+)"', content)
    description = desc_match.group(1) if desc_match else meter_name

    # Extract opcodes
    opcodes = {}
    opcode_pattern = re.compile(r"(\w+):\s*(0x[0-9A-Fa-f]+|\d+),?\s*//\s*(.+)?")

    for match in opcode_pattern.finditer(content):
        name = match.group(1)
        address = int(match.group(2), 0)  # Handles both hex and decimal
        comment = match.group(3).strip() if match.group(3) else name
        opcodes[name] = {"address": address, "description": comment}

    if not opcodes:
        return None

    # Build OIDA map
    oida_map = {
        "vendor": meter_name,
        "model": description,
        "description": f"Imported from mbmd ({filepath.stem})",
        "version": "1.0",
        "byte_order": "big",
        "word_order": "big",
        "source": f"mbmd/meters/rs485/{filepath.name}",
        "registers": {},
    }

    # Determine function code from snip() method
    fc = 4  # Default to input registers for meters
    if "ReadHoldingReg" in content:
        fc = 3

    for name, info in opcodes.items():
        # Convert camelCase to snake_case
        snake_name = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()

        oida_map["registers"][snake_name] = {
            "address": info["address"],
            "type": "f32",  # Most meters use float32
            "access": "ro",
            "description": info["description"],
            "function_code": fc,
        }

    return oida_map


def import_nymea_directory(source_dir: Path, output_dir: Path) -> int:
    """Import all nymea register maps from a directory."""
    imported = 0

    for json_file in sorted(source_dir.rglob("*-registers.json")):
        logger.info("Processing: %s", json_file.relative_to(source_dir))

        oida_map = parse_nymea_file(json_file)
        if not oida_map:
            logger.info("  Skipped (no valid registers)")
            continue

        # Generate output filename
        parent_name = json_file.parent.name
        out_name = f"{parent_name}-{json_file.stem.replace('-registers', '')}.json"
        out_name = out_name.replace("--", "-")
        out_path = output_dir / out_name

        # Write output
        with open(out_path, "w") as f:
            json.dump(oida_map, f, indent=2)
            f.write("\n")

        reg_count = len(oida_map["registers"])
        logger.info("  Imported %d registers -> %s", reg_count, out_name)
        imported += 1

    return imported


def import_mbmd_directory(source_dir: Path, output_dir: Path) -> int:
    """Import all mbmd meter definitions from a directory."""
    imported = 0
    meters_dir = source_dir / "meters" / "rs485"

    if not meters_dir.exists():
        logger.error("mbmd meters directory not found: %s", meters_dir)
        return 0

    for go_file in sorted(meters_dir.glob("*.go")):
        # Skip non-meter files
        if go_file.name in ("registry.go", "rs485.go", "producer.go", "transform.go"):
            continue

        logger.info("Processing: %s", go_file.name)

        oida_map = parse_mbmd_go_file(go_file)
        if not oida_map:
            logger.info("  Skipped (no valid registers)")
            continue

        # Generate output filename
        out_name = f"mbmd-{go_file.stem}.json"
        out_path = output_dir / "meters" / out_name

        # Ensure output directory exists
        out_path.parent.mkdir(parents=True, exist_ok=True)

        # Write output
        with open(out_path, "w") as f:
            json.dump(oida_map, f, indent=2)
            f.write("\n")

        reg_count = len(oida_map["registers"])
        logger.info("  Imported %d registers -> meters/%s", reg_count, out_name)
        imported += 1

    return imported


def parse_solarman_yaml(filepath: Path) -> Optional[Dict[str, Any]]:
    """Parse a Home Assistant Solarman inverter definition YAML file."""
    if not _yaml.is_available:
        logger.warning("PyYAML not installed, skipping YAML files")
        return None

    try:
        with open(filepath) as f:
            data = _yaml.safe_load(f)
    except Exception as e:
        logger.error("Error parsing %s: %s", filepath, e)
        return None

    if not data or "parameters" not in data:
        return None

    # Extract inverter name from filename
    inverter_name = filepath.stem.replace("_", " ").title()
    vendor = inverter_name.split()[0] if inverter_name else "Unknown"

    # Build OIDA map
    oida_map = {
        "vendor": vendor,
        "model": inverter_name,
        "description": f"Imported from home_assistant_solarman ({filepath.stem})",
        "version": "1.0",
        "byte_order": "big",
        "word_order": "big",
        "source": f"home_assistant_solarman/{filepath.name}",
        "registers": {},
    }

    # Process parameters groups
    for group in data.get("parameters", []):
        group.get("group", "")
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
                address = int(address, 0)  # Handle hex strings

            # Determine type from rule and register count
            rule = item.get("rule", 1)
            reg_count = len(registers)

            if reg_count == 1:
                reg_type = "u16" if rule == 1 else "i16"
            elif reg_count == 2:
                reg_type = "u32" if rule in (1, 3) else "i32"
            elif reg_count == 4:
                reg_type = "u64"
            else:
                reg_type = "u16"

            # Convert name to snake_case
            reg_id = re.sub(r"[^\w\s]", "", name.lower())
            reg_id = re.sub(r"\s+", "_", reg_id)

            oida_reg = {
                "address": address,
                "type": reg_type,
                "access": "ro",
                "description": name,
            }

            if item.get("uom"):
                oida_reg["unit"] = item["uom"]
            if item.get("scale") and item["scale"] != 1:
                oida_reg["scale"] = item["scale"]

            oida_map["registers"][reg_id] = oida_reg

    return oida_map if oida_map["registers"] else None


def import_solarman_directory(source_dir: Path, output_dir: Path) -> int:
    """Import all Solarman inverter definitions from a directory."""
    imported = 0

    # Find inverter definitions directory
    defs_dir = source_dir / "custom_components" / "solarman" / "inverter_definitions"
    if not defs_dir.exists():
        # Try alternate path
        defs_dir = source_dir
        if not list(defs_dir.glob("*.yaml")):
            logger.error("Solarman definitions not found in: %s", source_dir)
            return 0

    for yaml_file in sorted(defs_dir.glob("*.yaml")):
        if yaml_file.name == "services.yaml":
            continue

        logger.info("Processing: %s", yaml_file.name)

        oida_map = parse_solarman_yaml(yaml_file)
        if not oida_map:
            logger.info("  Skipped (no valid registers)")
            continue

        # Generate output filename
        out_name = f"solarman-{yaml_file.stem}.json"
        out_path = output_dir / "solar" / out_name

        # Ensure output directory exists
        out_path.parent.mkdir(parents=True, exist_ok=True)

        # Write output
        with open(out_path, "w") as f:
            json.dump(oida_map, f, indent=2)
            f.write("\n")

        reg_count = len(oida_map["registers"])
        logger.info("  Imported %d registers -> solar/%s", reg_count, out_name)
        imported += 1

    return imported


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Import Modbus register maps from external sources",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Import from nymea-plugins-modbus
  python -m oida.protocols.modbus.import_maps /tmp/nymea-plugins-modbus

  # Import from mbmd
  python -m oida.protocols.modbus.import_maps /tmp/mbmd --format mbmd

  # Import from Home Assistant Solarman
  python -m oida.protocols.modbus.import_maps /tmp/home_assistant_solarman --format solarman

  # Import to custom output directory
  python -m oida.protocols.modbus.import_maps /tmp/source -o ./my-maps
        """,
    )
    parser.add_argument("source", type=Path, help="Source directory to import from")
    parser.add_argument(
        "-f",
        "--format",
        choices=["nymea", "mbmd", "solarman", "auto"],
        default="auto",
        help="Source format (default: auto-detect)",
    )
    parser.add_argument("-o", "--output", type=Path, help="Output directory")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be imported")

    args = parser.parse_args()

    if not args.source.exists():
        logger.error("Source directory not found: %s", args.source)
        sys.exit(1)

    # Determine output directory
    if args.output:
        output_dir = args.output
    else:
        script_dir = Path(__file__).parent
        output_dir = script_dir / "register_maps" / "imported"

    output_dir.mkdir(parents=True, exist_ok=True)

    # Auto-detect format
    fmt = args.format
    if fmt == "auto":
        if (args.source / "meters").exists():
            fmt = "mbmd"
        elif list(args.source.rglob("*-registers.json")):
            fmt = "nymea"
        elif (args.source / "custom_components" / "solarman" / "inverter_definitions").exists() or (
            list(args.source.glob("*.yaml"))
        ):
            fmt = "solarman"
        else:
            logger.error("Could not auto-detect source format")
            sys.exit(1)

    logger.info("Source: %s", args.source)
    logger.info("Format: %s", fmt)
    logger.info("Output: %s", output_dir)

    # Import based on format. (Solarman was advertised in --format choices and
    # the docstring but never dispatched, so --format solarman used to exit 1.)
    importers = {
        "nymea": import_nymea_directory,
        "mbmd": import_mbmd_directory,
        "solarman": import_solarman_directory,
    }
    importer = importers.get(fmt)
    if importer is None:
        logger.error("Unknown format: %s", fmt)
        sys.exit(1)

    if args.dry_run:
        # The importers write unconditionally, so honour --dry-run by skipping
        # the call entirely rather than letting the flag silently lie.
        logger.info("DRY RUN - no files will be written (%s import skipped)", fmt)
        imported = 0
    else:
        imported = importer(args.source, output_dir)

    logger.info("Imported %d register maps to %s", imported, output_dir)


if __name__ == "__main__":
    main()
