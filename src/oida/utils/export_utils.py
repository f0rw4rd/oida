#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Centralized export utilities for oida.

Modules should use the simplified API:
    - export_table(name, headers, rows) for tabular data
    - get_export_path(name, ext) for custom binary/non-table data

Configure once at startup:
    from oida.utils.export_utils import configure
    configure(output_dir=args.output, fmt="csv,json")
"""

import csv
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import List, Any, Optional, Dict, Union
from xml.etree import ElementTree as ET
from xml.dom import minidom
from .ics_logger import log, log_error as error


# =============================================================================
# Global Configuration
# =============================================================================

_config: Dict[str, Any] = {
    "output_dir": None,  # Path or None
    "format": "csv,json",  # csv, json, xml, or comma-separated combo
    "logger": None,  # Optional logger instance
    "full_width": False,  # When True, don't truncate tables to terminal width
}


def add_export_args(parser) -> None:
    """
    Add standard --output, --format, --full-width, and --json-log arguments to an argparse parser.

    Call this once when setting up your argument parser:
        parser = argparse.ArgumentParser()
        add_export_args(parser)

    Args:
        parser: argparse.ArgumentParser or argument group
    """
    parser.add_argument(
        "-o",
        "--output",
        metavar="DIR",
        help="Output directory for exported files (CSV/JSON)",
    )
    parser.add_argument(
        "-f",
        "--format",
        metavar="FMT",
        default="csv,json",
        help="Export format(s): csv, json, xml, or comma-separated (default: csv,json)",
    )
    parser.add_argument(
        "-W",
        "--full-width",
        action="store_true",
        default=False,
        help="Show full-width tables without truncating to terminal width",
    )
    parser.add_argument(
        "--json-log",
        type=str,
        metavar="FILE",
        help="Write structured JSON log events to FILE (NDJSON format)",
    )


def add_common_args(parser) -> None:
    """
    Add common arguments used by most modules: output, format, full-width, json-log, verbose, debug.

    Call this once when setting up your argument parser:
        parser = argparse.ArgumentParser()
        add_common_args(parser)

    Args:
        parser: argparse.ArgumentParser or argument group
    """
    # Export options
    parser.add_argument(
        "-o",
        "--output",
        metavar="DIR",
        help="Output directory for exported files (CSV/JSON)",
    )
    parser.add_argument(
        "-f",
        "--format",
        metavar="FMT",
        default="csv,json",
        help="Export format(s): csv, json, xml, or comma-separated (default: csv,json)",
    )
    parser.add_argument(
        "-W",
        "--full-width",
        action="store_true",
        default=False,
        help="Show full-width tables without truncating to terminal width",
    )
    parser.add_argument(
        "--json-log",
        type=str,
        metavar="FILE",
        help="Write structured JSON log events to FILE (NDJSON format)",
    )
    # Verbosity options
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Debug output (implies verbose)",
    )


def configure_from_args(args, logger=None) -> None:
    """
    Configure exports from parsed argparse namespace.

    Call this after parsing arguments:
        args = parser.parse_args()
        configure_from_args(args, logger=my_logger)

    Args:
        args: argparse.Namespace with 'output' and 'format' attributes
        logger: Optional logger instance
    """
    output_dir = getattr(args, "output", None)
    fmt = getattr(args, "format", "csv,json") or "csv,json"
    full_width = getattr(args, "full_width", False)
    configure(output_dir=output_dir, fmt=fmt, logger=logger, full_width=full_width)


def configure(
    output_dir: Optional[Union[str, Path]] = None,
    fmt: str = "csv,json",
    logger=None,
    full_width: bool = False,
) -> None:
    """
    Configure global export settings. Call once at startup.

    Args:
        output_dir: Directory for file exports (None = no file export)
        fmt: Export format(s) - "csv", "json", "xml", or comma-separated like "csv,json"
        logger: Optional logger instance with success/display methods
        full_width: If True, don't truncate tables to terminal width
    """
    if output_dir:
        _config["output_dir"] = Path(output_dir)
        _config["output_dir"].mkdir(parents=True, exist_ok=True)
    else:
        _config["output_dir"] = None

    _config["format"] = fmt
    _config["logger"] = logger
    _config["full_width"] = full_width


def get_config() -> Dict[str, Any]:
    """Get current export configuration (for debugging)."""
    return _config.copy()


# =============================================================================
# Simplified Module API
# =============================================================================


def export_table(
    name: str,
    headers: List[str],
    rows: List[List[Any]],
    title: Optional[str] = None,
) -> bool:
    """
    Export tabular data - simplified API for modules.

    Always prints to console. Exports to file(s) if output_dir configured.
    When table output is truncated to fit the terminal, informs the user
    where the full data is stored (or suggests using -o to save it).

    Args:
        name: Base filename (without extension), e.g. "ads_symbols"
        headers: Column headers
        rows: List of rows (each row is a list of values)
        title: Optional title for console output

    Returns:
        True if successful
    """
    if not rows or not headers:
        _log_msg("No data to export", level="warning")
        return False

    # Always print to console
    print_table(rows, headers, title, logger=_config["logger"])

    # Check if table was truncated and inform the user
    was_truncated = _config.get("_last_table_truncated", False)

    # Export to file if configured
    if not _config["output_dir"]:
        if was_truncated:
            _log_msg(
                "Table truncated to fit terminal. Use --full-width to show all columns, "
                "or -o <dir> to save full output to file.",
                level="info",
            )
        return True

    formats = [f.strip().lower() for f in _config["format"].split(",")]
    success = True
    written_paths = []

    for fmt in formats:
        if fmt == "csv":
            path = _config["output_dir"] / f"{name}.csv"
            if _write_csv(path, headers, rows):
                _log_msg(f"Wrote {path}", level="good")
                written_paths.append(str(path))
            else:
                success = False
        elif fmt == "json":
            path = _config["output_dir"] / f"{name}.json"
            if _write_json(path, headers, rows):
                _log_msg(f"Wrote {path}", level="good")
                written_paths.append(str(path))
            else:
                success = False
        elif fmt == "xml":
            path = _config["output_dir"] / f"{name}.xml"
            if _write_xml(path, headers, rows, name):
                _log_msg(f"Wrote {path}", level="good")
                written_paths.append(str(path))
            else:
                success = False

    if was_truncated and written_paths:
        _log_msg(
            f"Table truncated to fit terminal. Full data saved to: {written_paths[0]}",
            level="info",
        )

    return success


def get_export_path(name: str, ext: str = "bin") -> Optional[Path]:
    """
    Get file path for non-table data (EEPROM, raw dumps, etc).

    Args:
        name: Base filename (without extension)
        ext: File extension (default: "bin")

    Returns:
        Path to write to, or None if no output_dir configured.
        Module is responsible for writing data to returned path.

    Example:
        path = get_export_path("eeprom", "bin")
        if path:
            path.write_bytes(eeprom_data)
        else:
            print(eeprom_data.hex())  # fallback to console
    """
    if not _config["output_dir"]:
        return None

    path = _config["output_dir"] / f"{name}.{ext}"
    _log_msg(f"Writing {path}", level="good")
    return path


# =============================================================================
# Internal Helpers
# =============================================================================


def _log_msg(message: str, level: str = "info"):
    """Log using configured logger or global log."""
    logger = _config["logger"]
    if logger:
        if level == "good" and hasattr(logger, "success"):
            logger.success(message)
        elif level in ("warning", "error") and hasattr(logger, "fail"):
            logger.fail(message)
        elif hasattr(logger, "display"):
            logger.display(message)
        else:
            log(message, level=level)
    else:
        log(message, level=level)


def _write_csv(path: Path, headers: List[str], rows: List[List[Any]]) -> bool:
    """Write CSV file."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        return True
    except Exception as e:
        _log_msg(f"Error writing CSV: {e}", level="error")
        return False


def _write_json(path: Path, headers: List[str], rows: List[List[Any]]) -> bool:
    """Write JSON file (list of dicts)."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = [dict(zip(headers, row)) for row in rows]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return True
    except Exception as e:
        _log_msg(f"Error writing JSON: {e}", level="error")
        return False


def _write_xml(path: Path, headers: List[str], rows: List[List[Any]], root_name: str) -> bool:
    """Write XML file."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        root = ET.Element(root_name)
        for row in rows:
            record = ET.SubElement(root, "record")
            for i, header in enumerate(headers):
                tag_name = _sanitize_xml_tag(header)
                field = ET.SubElement(record, tag_name)
                value = row[i] if i < len(row) else ""
                field.text = str(value) if value is not None else ""

        xml_str = ET.tostring(root, encoding="unicode")
        dom = minidom.parseString(xml_str)
        pretty_xml = dom.toprettyxml(indent="  ")
        lines = [line for line in pretty_xml.split("\n") if line.strip()]

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return True
    except Exception as e:
        _log_msg(f"Error writing XML: {e}", level="error")
        return False


# =============================================================================
# Legacy API (backward compatible)
# =============================================================================


def _log_message(logger, message: str, level: str = "info"):
    """Log a message using the provided logger or fall back to global log."""
    if logger:
        if level == "warning" and hasattr(logger, "fail"):
            logger.fail(message)
        elif level == "error" and hasattr(logger, "fail"):
            logger.fail(message)
        elif level == "good" and hasattr(logger, "success"):
            logger.success(message)
        elif hasattr(logger, "display"):
            logger.display(message)
        else:
            log(message, level=level)
    else:
        log(message, level=level)


def export_data(
    data: List[List[Any]],
    headers: List[str],
    output_format: str = "console",
    output_dir: Optional[str] = None,
    filename_prefix: str = "export",
    title: str = None,
    logger=None,
) -> bool:
    """
    Generic function to export data in various formats.

    Args:
        data: 2D matrix of values (list of rows)
        headers: List of column headers
        output_format: Output format option ("console", "csv", "json", "all", "none")
        output_dir: Directory for file output (required for csv/json)
        filename_prefix: Prefix for output filenames
        title: Optional title for console output
        logger: Optional logger instance (uses global log if not provided)

    Returns:
        True if at least one export was successful, False otherwise
    """
    if not output_dir:
        output_dir = tempfile.gettempdir()

    if not data or not headers:
        _log_message(logger, "No data to export", level="warning")
        return False

    # Verify data structure
    if not all(len(row) == len(headers) for row in data):
        _log_message(logger, "Data rows must have same length as headers", level="error")
        return False

    # Parse the output format option
    formats = parse_output_format(output_format)

    # Track export success
    success = False
    # Handle each output format
    for fmt in formats:
        if fmt == "console":
            success = print_table(data, headers, title, logger=logger) or success
        elif fmt == "csv" and output_dir:
            file_path = os.path.join(output_dir, f"{filename_prefix}.csv")
            success = _export_csv(data, headers, file_path) or success
        elif fmt == "json" and output_dir:
            file_path = os.path.join(output_dir, f"{filename_prefix}.json")
            success = _export_json(data, headers, file_path) or success
        elif fmt == "xml" and output_dir:
            file_path = os.path.join(output_dir, f"{filename_prefix}.xml")
            success = _export_xml(data, headers, file_path, filename_prefix) or success
        else:
            error(f"Unknown export format {fmt}")

    return success


def parse_output_format(format_option: str) -> List[str]:
    """
    Parse output format option into a list of format strings.

    Args:
        format_option: Format option string ("console", "csv", "json", "all", "none")

    Returns:
        List of format strings to process
    """
    formats = []

    # Handle special cases
    if format_option.lower() == "none":
        return ["console"]  # Default to console only

    if format_option.lower() == "all":
        return ["console", "csv", "json", "xml"]

    # Parse comma-separated formats
    valid_formats = ["console", "csv", "json", "xml"]
    if "," in format_option:
        for fmt in format_option.split(","):
            fmt = fmt.strip().lower()
            if fmt in valid_formats:
                formats.append(fmt)
    else:
        # Single format
        format_option = format_option.lower()
        if format_option in valid_formats:
            formats.append(format_option)

    # Default to console if no valid format was specified
    if not formats:
        formats = ["console"]

    return formats


def print_table(
    data: List[List[Any]], headers: List[str], title: Optional[str] = None, logger=None
) -> bool:
    """Print data as a formatted console table.

    By default, truncates lines to fit the terminal width. Use --full-width
    or configure(full_width=True) to disable truncation.

    Args:
        data: List of rows, each row is a list of cell values
        headers: Column header names
        title: Optional table title
        logger: Optional logger with display() method

    Returns:
        True if table printed successfully, False otherwise
    """

    # Use provided logger or fall back to global log
    def output(msg):
        if logger and hasattr(logger, "display"):
            logger.display(msg)
        else:
            log(msg)

    try:
        # Convert all data to strings
        str_data = [[str(cell) for cell in row] for row in data]
        str_headers = [str(h) for h in headers]

        # Calculate column widths based on content
        col_widths = []
        for i in range(len(headers)):
            header_width = len(str_headers[i])
            max_data_width = max(len(row[i]) for row in str_data) if str_data else 0
            col_widths.append(max(header_width, max_data_width) + 2)

        # Determine if truncation is needed
        full_width = _config.get("full_width", False)
        term_width = shutil.get_terminal_size((120, 24)).columns
        # Subtract logger prefix width — when output() calls logger.display(),
        # the logger prepends "PROTO  host:port  [*] " before our line.
        try:
            prefix_w = int(getattr(logger, "prefix_width", 0)) if logger else 0
        except (TypeError, ValueError):
            prefix_w = 0
        avail_width = term_width - prefix_w
        truncated = False

        def maybe_truncate(line: str) -> str:
            """Truncate line to available width if not in full-width mode."""
            nonlocal truncated
            if full_width or avail_width <= 0 or len(line) <= avail_width:
                return line
            truncated = True
            # Leave room for "..." suffix
            return line[: avail_width - 3] + "..."

        # Create horizontal separator
        separator = "+" + "+".join("-" * width for width in col_widths) + "+"

        # Print title if provided
        if title:
            output(title)

        # Print table header
        output(maybe_truncate(separator))
        header_row = "|"
        for i, header in enumerate(str_headers):
            header_row += f" {header:<{col_widths[i] - 2}} " + "|"
        output(maybe_truncate(header_row))
        output(maybe_truncate(separator))

        # Print data rows (with redundancy compression)
        compress = not _config.get("full_width", False)
        # Compare structural columns — skip first (#) and last (Details)
        compare_slice = slice(1, -1) if len(str_headers) > 2 else slice(None)

        prev_key = None
        prev_row = None
        dup_count = 0

        def _flush_dups(count):
            if count < 1:
                return
            if count == 1 and prev_row is not None:
                line = "|"
                for i, cell in enumerate(prev_row):
                    line += f" {cell:<{col_widths[i] - 2}} " + "|"
                output(maybe_truncate(line))
                return
            label = f"...  {count} identical row{'s' if count != 1 else ''}"
            total_inner = sum(col_widths) + len(col_widths) - 1
            line = "| " + f"{label:<{total_inner - 2}}" + " |"
            output(maybe_truncate(line))

        for row in str_data:
            key = tuple(row[compare_slice]) if compress else None

            if compress and key == prev_key:
                dup_count += 1
                continue

            _flush_dups(dup_count)
            dup_count = 0
            prev_key = key
            prev_row = row

            data_row = "|"
            for i, cell in enumerate(row):
                data_row += f" {cell:<{col_widths[i] - 2}} " + "|"
            output(maybe_truncate(data_row))

        _flush_dups(dup_count)

        # Print bottom separator
        output(maybe_truncate(separator))

        # Store truncation state so export_table can check it
        _config["_last_table_truncated"] = truncated

        return True
    except Exception as e:
        log(f"Error printing table: {e}", level="error")
        return False


def _export_csv(data: List[List[Any]], headers: List[str], file_path: str) -> bool:
    """Export data to CSV file."""
    if not file_path:
        log("No file path provided for CSV export", level="error")
        return False

    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        with open(file_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(data)

        log(f"Data exported to CSV file: {file_path}", level="good")
        return True
    except Exception as e:
        log(f"Error exporting to CSV: {e}", level="error")
        return False


def _export_json(data: List[List[Any]], headers: List[str], file_path: str) -> bool:
    """Export data to JSON file."""
    if not file_path:
        log("No file path provided for JSON export", level="error")
        return False

    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        # Convert 2D matrix to list of dictionaries
        json_data = []
        for row in data:
            json_data.append(dict(zip(headers, row)))

        with open(file_path, "w") as f:
            json.dump(json_data, f, indent=2)

        log(f"Data exported to JSON file: {file_path}", level="good")
        return True
    except Exception as e:
        log(f"Error exporting to JSON: {e}", level="error")
        return False


def _export_xml(
    data: List[List[Any]], headers: List[str], file_path: str, root_name: str = "results"
) -> bool:
    """Export data to XML file.

    Args:
        data: 2D matrix of values (list of rows)
        headers: List of column headers
        file_path: Path to output XML file
        root_name: Name for the root XML element

    Returns:
        True if export was successful, False otherwise
    """
    if not file_path:
        log("No file path provided for XML export", level="error")
        return False

    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        # Create root element
        root = ET.Element(root_name)

        # Add each row as a record element
        for row in data:
            record = ET.SubElement(root, "record")
            for i, header in enumerate(headers):
                # Sanitize header name for XML tag (replace spaces, ensure valid)
                tag_name = _sanitize_xml_tag(header)
                field = ET.SubElement(record, tag_name)
                # Handle None and convert to string
                value = row[i] if i < len(row) else ""
                field.text = str(value) if value is not None else ""

        # Pretty print with minidom
        xml_str = ET.tostring(root, encoding="unicode")
        dom = minidom.parseString(xml_str)
        pretty_xml = dom.toprettyxml(indent="  ")

        # Remove extra blank lines from minidom output
        lines = [line for line in pretty_xml.split("\n") if line.strip()]
        pretty_xml = "\n".join(lines)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(pretty_xml)

        log(f"Data exported to XML file: {file_path}", level="good")
        return True
    except Exception as e:
        log(f"Error exporting to XML: {e}", level="error")
        return False


def _sanitize_xml_tag(name: str) -> str:
    """Sanitize a string to be a valid XML tag name.

    Args:
        name: Original string to sanitize

    Returns:
        Valid XML tag name
    """
    import re

    # Replace spaces and special chars with underscores
    sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", str(name))

    # Ensure it starts with a letter or underscore
    if sanitized and not sanitized[0].isalpha() and sanitized[0] != "_":
        sanitized = "_" + sanitized

    # Handle empty string
    if not sanitized:
        sanitized = "field"

    return sanitized


def export_json(
    data: Any,
    output_dir: str,
    filename: str,
    logger=None,
) -> bool:
    """Export arbitrary data structure to JSON file.

    Args:
        data: Any JSON-serializable data structure (dict, list, etc.)
        output_dir: Directory for output file
        filename: Output filename (with or without .json extension)
        logger: Optional logger instance

    Returns:
        True if export was successful, False otherwise
    """
    if not output_dir:
        _log_message(logger, "No output directory provided for JSON export", level="error")
        return False

    if not filename:
        _log_message(logger, "No filename provided for JSON export", level="error")
        return False

    # Ensure .json extension
    if not filename.endswith(".json"):
        filename = f"{filename}.json"

    file_path = os.path.join(output_dir, filename)

    try:
        # Create directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        with open(file_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        _log_message(logger, f"Data exported to {file_path}", level="good")
        return True
    except Exception as e:
        _log_message(logger, f"Error exporting to JSON: {e}", level="error")
        return False
