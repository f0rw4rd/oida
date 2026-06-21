#!/usr/bin/env python3
"""Audit tshark field coverage for passive listeners.

Compares three data sources for each protocol:
  1. tshark -G fields  -> all fields tshark can dissect for the protocol
  2. tshark -T ek -r <pcap> -> fields actually present in pcap fixtures
  3. grep get_field <listener.py> -> fields the listener extracts

Generates per-protocol JSON inventories in ref/<proto>/tshark_fields.json
and prints a console report showing coverage gaps by value tier (T1-T4).

Usage:
    python tools/audit_listener_fields.py mms              # Audit one protocol
    python tools/audit_listener_fields.py --all            # Audit all protocols
    python tools/audit_listener_fields.py --all --refresh-refs  # Just regenerate ref files
    python tools/audit_listener_fields.py mms --verbose    # Show all tiers in report
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Project layout
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT / "src" / "oida" / "pcap"
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "pcap"
REF_DIR = ROOT / "ref"

# Listener module names that are NOT protocol listeners
_SKIP_MODULES = {"__init__", "pyshark_base", "interactions", "file_carving"}

# Mapping: listener module name -> pcap fixture directory name
# (only needed when they differ from the module name)
_PCAP_DIR_MAP: dict[str, list[str]] = {
    "hartip": ["hart"],
    "ntlm": ["smb"],
    "mssql": ["mssql"],
    "sv": [],  # no fixtures yet
    "hsrp": ["hsrp"],
    "glbp": ["glbp"],
    "vrrp": ["vrrp"],
}

# Mapping: listener module name -> ref/ directory name
# (only needed when they differ)
_REF_DIR_MAP: dict[str, str] = {
    "enip": "ethernetip",
    "profinet": "profinet_dcp",
}

# ---------------------------------------------------------------------------
# Source parsing
# ---------------------------------------------------------------------------
_DISPLAY_FILTER_RE = re.compile(r'DISPLAY_FILTER\s*=\s*["\'](.+?)["\']')
_CLASS_RE = re.compile(r"^class\s+(\w+Listener)\s*\(", re.MULTILINE)
_GET_FIELD_RE = re.compile(r"\.get_field\s*\(\s*\w+\s*,\s*[\"']([^\"']+)[\"']")
_GETATTR_RE = re.compile(r"getattr\s*\(\s*(?:packet\.\w+|\w+)\s*,\s*[\"']([^\"']+)[\"']")


def _parse_listener_source(path: Path) -> dict[str, Any] | None:
    """Parse a listener .py file for metadata and extracted field names."""
    text = path.read_text(errors="replace")

    m = _DISPLAY_FILTER_RE.search(text)
    if not m:
        return None
    display_filter = m.group(1)

    m = _CLASS_RE.search(text)
    class_name = m.group(1) if m else ""

    # Collect field names from get_field() and getattr() calls
    fields: set[str] = set()
    for rx in (_GET_FIELD_RE, _GETATTR_RE):
        fields.update(rx.findall(text))

    # Also extract string literals from tuples/lists used as field name iterables.
    # Pattern: for var in ("fieldA", "fieldB", ...): ... get_field(..., var, ...)
    # We look for tuples/lists of quoted strings on lines near get_field(*, var, *)
    # Simpler: just collect all quoted strings in tuple/list literals that look
    # like tshark field names (camelCase or snake_case, no spaces)
    _FIELD_TUPLE_RE = re.compile(
        r"(?:_FIELDS|_DOMAIN_FIELDS|field_names?|fname)\s*[=:]\s*"
        r"[\(\[](.*?)[\)\]]",
        re.DOTALL,
    )
    _QUOTED_STR = re.compile(r'["\']([a-zA-Z][a-zA-Z0-9_.]+)["\']')
    for m2 in _FIELD_TUPLE_RE.finditer(text):
        for s in _QUOTED_STR.findall(m2.group(1)):
            fields.add(s)

    # Also catch bare string literals in for-loops that iterate over field names
    # e.g.: for pf in ("programInvocationName", "deleteProgramInvocation", ...):
    _FOR_TUPLE_RE = re.compile(
        r'for\s+\w+\s+in\s+[\(\[]((?:\s*["\'][a-zA-Z]\w*["\']'
        r"(?:\s*,\s*)?)+)\s*[\)\]]",
    )
    for m2 in _FOR_TUPLE_RE.finditer(text):
        for s in _QUOTED_STR.findall(m2.group(1)):
            fields.add(s)

    # Filter out non-protocol fields (IP helpers, frame metadata, etc.)
    _IGNORE = {
        "src",
        "dst",
        "srcport",
        "dstport",
        "src_port",
        "dst_port",
        "type",
        "len",
        "payload",
    }
    fields -= _IGNORE

    return {
        "module": path.stem,
        "path": str(path),
        "class_name": class_name,
        "display_filter": display_filter,
        "extracted_fields": sorted(fields),
    }


def _parse_display_filter(display_filter: str) -> list[str]:
    """Extract protocol abbreviations from a display filter string.

    "acse or mms"  -> ["acse", "mms"]
    "enip or cip"  -> ["cip", "enip"]
    "tls.handshake or tls.alert_message" -> ["tls"]
    "dhcp || bootp" -> ["bootp", "dhcp"]
    """
    terms = re.split(r"\s+or\s+|\s*\|\|\s*", display_filter)
    protos: set[str] = set()
    for term in terms:
        term = term.strip()
        proto = term.split(".")[0].strip()
        if proto:
            protos.add(proto)
    return sorted(protos)


# ---------------------------------------------------------------------------
# tshark interface
# ---------------------------------------------------------------------------


def _get_tshark_version() -> str:
    """Get tshark version string."""
    try:
        r = subprocess.run(
            ["tshark", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        first_line = r.stdout.split("\n")[0]
        # "TShark (Wireshark) 4.6.2" -> "4.6.2"
        m = re.search(r"(\d+\.\d+\.\d+)", first_line)
        return m.group(1) if m else first_line.strip()
    except Exception:
        return "unknown"


def _get_all_dissector_fields() -> dict[str, list[dict[str, str]]]:
    """Run ``tshark -G fields`` once and return fields grouped by protocol.

    Returns dict mapping protocol abbreviation -> list of field dicts.
    Each field dict: {"name": display_name, "filter": filter_name,
                      "type": FT_xxx, "description": blurb}
    """
    r = subprocess.run(
        ["tshark", "-G", "fields"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if r.returncode != 0:
        print(f"ERROR: tshark -G fields failed: {r.stderr[:200]}", file=sys.stderr)
        sys.exit(1)

    fields: dict[str, list[dict[str, str]]] = {}
    for line in r.stdout.splitlines():
        cols = line.split("\t")
        # Format: F<TAB>display_name<TAB>filter_name<TAB>type<TAB>protocol<TAB>base<TAB>bitmask<TAB>description
        if len(cols) < 5 or cols[0] != "F":
            continue
        display_name = cols[1]
        filter_name = cols[2]  # e.g. "mms.domainId"
        ftype = cols[3]  # e.g. "FT_UINT32"
        proto_col = cols[4]  # e.g. "mms"
        description = cols[7] if len(cols) >= 8 else display_name

        # Protocol abbreviation from either the explicit column or the filter name
        proto = proto_col if proto_col else filter_name.split(".")[0]
        if "." not in filter_name:
            continue

        entry = {
            "name": filter_name,
            "display_name": display_name,
            "type": ftype,
            "description": description,
        }
        fields.setdefault(proto, []).append(entry)

    return fields


def _get_pcap_ek_fields(
    pcap_path: str,
    display_filter: str,
    protocols: list[str],
) -> dict[str, set[str]]:
    """Run ``tshark -T ek`` on a pcap and collect EK field key names.

    Returns dict mapping protocol abbreviation -> set of EK key names.
    """
    cmd = ["tshark", "-T", "ek", "-r", pcap_path]
    if display_filter:
        cmd.extend(["-Y", display_filter])

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {p: set() for p in protocols}

    result: dict[str, set[str]] = {p: set() for p in protocols}

    for line in r.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        layers = obj.get("layers", {})
        for proto in protocols:
            layer_data = layers.get(proto)
            if isinstance(layer_data, dict):
                result[proto].update(layer_data.keys())

    return result


# ---------------------------------------------------------------------------
# Field name normalization and matching
# ---------------------------------------------------------------------------


def _dotted_to_ek(filter_name: str) -> str:
    """Convert dotted filter name to EK key name.

    ``mms.domainId`` -> ``mms_mms_domainId``
    ``mms.iec61850.rptid`` -> ``mms_mms_iec61850_rptid``

    EK format: ``{layer}_{filter_name_with_dots_as_underscores}``
    Since filter_name starts with the protocol abbreviation (same as layer),
    the result always has the protocol prefix doubled.
    """
    proto = filter_name.split(".")[0]
    return f"{proto}_{filter_name.replace('.', '_')}"


def _normalize_field(name: str, protos: list[str]) -> str:
    """Normalize a field name to leaf form for matching.

    Strips protocol prefix(es) and converts dots to underscores.
    """
    for proto in protos:
        # Double prefix: mms_mms_
        dp = f"{proto}_{proto}_"
        if name.startswith(dp):
            name = name[len(dp) :]
            break
        # Single underscore prefix: mms_
        sp = f"{proto}_"
        if name.startswith(sp):
            name = name[len(sp) :]
            break
        # Dotted prefix: mms.
        dp2 = f"{proto}."
        if name.startswith(dp2):
            name = name[len(dp2) :]
            break
    return name.replace(".", "_")


def _match_extracted_to_dissector(
    extracted: list[str],
    protos: list[str],
    dissector_fields: list[dict[str, str]],
) -> set[str]:
    """Match extracted field names to dissector filter names.

    Returns set of matched dissector filter names.
    """
    # Build lookup: normalized leaf -> dissector filter name
    dissector_lookup: dict[str, str] = {}
    for f in dissector_fields:
        leaf = _normalize_field(f["name"], protos)
        dissector_lookup[leaf] = f["name"]

    matched: set[str] = set()
    for ext in extracted:
        norm = _normalize_field(ext, protos)
        if norm in dissector_lookup:
            matched.add(dissector_lookup[norm])
        else:
            # Try with each protocol prefix prepended
            for proto in protos:
                prefixed = f"{proto}_{norm}"
                pnorm = _normalize_field(prefixed, protos)
                if pnorm in dissector_lookup:
                    matched.add(dissector_lookup[pnorm])
                    break

    return matched


def _match_ek_to_dissector(
    ek_keys: set[str],
    protos: list[str],
    dissector_fields: list[dict[str, str]],
) -> set[str]:
    """Match EK key names to dissector filter names.

    Returns set of matched dissector filter names.
    """
    # Build lookup: EK key -> dissector filter name
    dissector_by_ek: dict[str, str] = {}
    for f in dissector_fields:
        ek = _dotted_to_ek(f["name"])
        dissector_by_ek[ek] = f["name"]
        # Also try without protocol prefix (in case EK format varies)
        norm = _normalize_field(f["name"], protos)
        dissector_by_ek[norm] = f["name"]

    matched: set[str] = set()
    for ek in ek_keys:
        if ek in dissector_by_ek:
            matched.add(dissector_by_ek[ek])
        else:
            norm = _normalize_field(ek, protos)
            if norm in dissector_by_ek:
                matched.add(dissector_by_ek[norm])

    return matched


# ---------------------------------------------------------------------------
# Field classification (T1-T4 tiers)
# ---------------------------------------------------------------------------

# T1 identity/operation name patterns
_T1_NAME_PATTERNS = re.compile(
    r"(Id$|Name$|Identifier|vendor|model|revision|version|address|"
    r"domainId|itemId|objectName|objectClass|Sequence|variable|"
    r"confirmedService|unconfirmedService|service|command|function|"
    r"opcode|operation|action|method|request_type|response_type|"
    r"error|exception|abort|reject|status|result|success|"
    r"password|credential|auth|user|community|secret|"
    r"ctlval|ctlModel|origin|operTm|check|"
    r"datset|rptid|rptEna|optFlds|trgOps|"
    r"filename|fileSize|obtainFile|deleteFile|"
    r"program|semaphore|download|upload|"
    r"visible.string|octet.string|integer$|unsigned$|"
    r"boolean$|floating_point$)",
    re.IGNORECASE,
)

# T3 bit-flag patterns in field names
_T3_BITMASK_PATTERNS = re.compile(
    r"(Options\.|Supported\.|capabilities\.|features\.|"
    r"ParameterSupport|ServiceSupport|CBBSupport|"
    r"AdditionalSupport|NestingLevel|"
    r"_element$|_tree$|padding|reserved)",
    re.IGNORECASE,
)

# T1 boolean state/control field patterns
_T1_BOOL_PATTERNS = re.compile(
    r"(ctlval|activeAlarms|enrollments|sharable|moreFollows|"
    r"enable|disable|start|stop|delete|create|"
    r"deletable|reusable|running|idle)",
    re.IGNORECASE,
)


def _classify_field(name: str, ftype: str, description: str) -> str:
    """Classify a dissector field into T1/T2/T3/T4 tier.

    T1 (Extract): high-value identity/operation/data fields
    T2 (Consider): metadata/config fields
    T3 (Skip): bit flags, container elements, padding
    T4 (Ignore): tshark internal bookkeeping (frame refs, timing)
    """
    # T4: tshark internal fields
    if ftype in ("FT_FRAMENUM", "FT_RELATIVE_TIME"):
        return "T4"

    # T3: container markers (no data)
    if ftype == "FT_NONE":
        return "T3"

    # T3: element suffix (container markers)
    if name.endswith("_element") or name.endswith("_tree"):
        return "T3"

    # T3: boolean bit flags in capability bitmasks
    if ftype == "FT_BOOLEAN" and _T3_BITMASK_PATTERNS.search(name):
        return "T3"

    # T1: boolean state/control fields
    if ftype == "FT_BOOLEAN" and _T1_BOOL_PATTERNS.search(name):
        return "T1"

    # Remaining booleans that aren't bit flags
    if ftype == "FT_BOOLEAN":
        # Generic booleans without clear T1 or T3 signal -> T2
        return "T2"

    # T1: string/integer fields with identity/operation/data semantics
    if ftype in ("FT_STRING", "FT_STRINGZ", "FT_UINT_STRING"):
        if _T1_NAME_PATTERNS.search(name) or _T1_NAME_PATTERNS.search(description):
            return "T1"
        return "T2"

    if ftype in (
        "FT_UINT8",
        "FT_UINT16",
        "FT_UINT32",
        "FT_UINT64",
        "FT_INT8",
        "FT_INT16",
        "FT_INT32",
        "FT_INT64",
    ):
        if _T1_NAME_PATTERNS.search(name) or _T1_NAME_PATTERNS.search(description):
            return "T1"
        return "T2"

    # T2: bytes (sometimes useful: certs, encoded values; often noise)
    if ftype in ("FT_BYTES", "FT_UINT_BYTES"):
        if _T1_NAME_PATTERNS.search(name):
            return "T1"
        return "T2"

    # T3: other protocol-specific types
    if ftype in ("FT_PROTOCOL",):
        return "T3"

    # Default: T2
    return "T2"


# ---------------------------------------------------------------------------
# Inventory builder
# ---------------------------------------------------------------------------


def _find_pcap_dirs(module_name: str) -> list[Path]:
    """Find pcap fixture directories for a listener module."""
    dirs: list[Path] = []

    # Check explicit mapping first
    if module_name in _PCAP_DIR_MAP:
        for name in _PCAP_DIR_MAP[module_name]:
            d = FIXTURE_DIR / name
            if d.is_dir():
                dirs.append(d)
        return dirs

    # Default: same name as module
    d = FIXTURE_DIR / module_name
    if d.is_dir():
        dirs.append(d)

    return dirs


def _find_pcap_files(pcap_dirs: list[Path]) -> list[Path]:
    """Find all pcap/pcapng files in the given directories."""
    files: list[Path] = []
    for d in pcap_dirs:
        for f in sorted(d.iterdir()):
            if f.suffix in (".pcap", ".pcapng", ".cap"):
                files.append(f)
    return files


def _ref_dir_for_module(module_name: str) -> Path:
    """Get the ref/ directory path for a listener module."""
    ref_name = _REF_DIR_MAP.get(module_name, module_name)
    return REF_DIR / ref_name


def build_inventory(
    listener_info: dict[str, Any],
    all_dissector_fields: dict[str, list[dict[str, str]]],
    tshark_version: str,
    verbose_progress: bool = False,
) -> dict[str, Any]:
    """Build complete field inventory for a protocol.

    Returns the JSON-serializable inventory dict.
    """
    module_name = listener_info["module"]
    display_filter = listener_info["display_filter"]
    protos = _parse_display_filter(display_filter)

    # 1. Collect dissector fields for all protocol prefixes
    dissector_list: list[dict[str, str]] = []
    for p in protos:
        dissector_list.extend(all_dissector_fields.get(p, []))

    # Deduplicate by filter name
    seen: set[str] = set()
    unique_dissector: list[dict[str, str]] = []
    for f in dissector_list:
        if f["name"] not in seen:
            seen.add(f["name"])
            unique_dissector.append(f)
    dissector_list = unique_dissector

    # Count by type
    by_type: dict[str, int] = {}
    for f in dissector_list:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1

    # 2. Scan pcap fixtures
    pcap_dirs = _find_pcap_dirs(module_name)
    pcap_files = _find_pcap_files(pcap_dirs)

    pcap_fields_by_file: dict[str, list[str]] = {}
    pcap_union: set[str] = set()

    for pcap_path in pcap_files:
        if verbose_progress:
            print(f"  scanning {pcap_path.name}...", flush=True)
        ek_fields = _get_pcap_ek_fields(str(pcap_path), display_filter, protos)
        all_keys: set[str] = set()
        for keys in ek_fields.values():
            all_keys.update(keys)
        rel_name = pcap_path.name
        pcap_fields_by_file[rel_name] = sorted(all_keys)
        pcap_union.update(all_keys)

    # 3. Match pcap EK fields to dissector fields
    pcap_matched = _match_ek_to_dissector(pcap_union, protos, dissector_list)

    # 4. Get extracted fields from listener source
    extracted = listener_info["extracted_fields"]
    extracted_matched = _match_extracted_to_dissector(extracted, protos, dissector_list)

    # 5. Classify each dissector field
    classified: list[dict[str, Any]] = []
    for f in dissector_list:
        tier = _classify_field(f["name"], f["type"], f["description"])
        in_pcap = f["name"] in pcap_matched
        in_listener = f["name"] in extracted_matched

        # Find which pcap files contain this field
        ek_variants = {_dotted_to_ek(f["name"])}
        # Also check normalized form
        norm = _normalize_field(f["name"], protos)
        ek_variants.add(norm)
        for p in protos:
            ek_variants.add(f"{p}_{norm}")

        seen_in: list[str] = []
        for fname, fkeys in pcap_fields_by_file.items():
            if any(v in fkeys for v in ek_variants):
                seen_in.append(fname)

        classified.append(
            {
                "name": f["name"],
                "display_name": f["display_name"],
                "type": f["type"],
                "description": f["description"],
                "tier": tier,
                "in_pcap": in_pcap or bool(seen_in),
                "in_listener": in_listener,
                "seen_in": seen_in,
            }
        )

    # 6. Build coverage analysis
    tier_counts: dict[str, dict[str, int]] = {}
    t1_gaps: list[dict[str, Any]] = []
    t2_consider: list[dict[str, Any]] = []

    for tier_name in ("T1", "T2", "T3", "T4"):
        tier_fields = [f for f in classified if f["tier"] == tier_name]
        tier_in_pcap = [f for f in tier_fields if f["in_pcap"]]
        tier_extracted = [f for f in tier_fields if f["in_listener"]]
        tier_counts[tier_name] = {
            "total": len(tier_fields),
            "in_pcap": len(tier_in_pcap),
            "extracted": len(tier_extracted),
        }

    # T1 gaps: in pcap but not extracted
    for f in classified:
        if f["tier"] == "T1" and f["in_pcap"] and not f["in_listener"]:
            t1_gaps.append(
                {
                    "ek_name": _dotted_to_ek(f["name"]),
                    "field": f["name"],
                    "type": f["type"],
                    "tier": "T1",
                    "seen_in": f["seen_in"],
                    "description": f["description"],
                }
            )

    # T2 consider: in pcap but not extracted
    for f in classified:
        if f["tier"] == "T2" and f["in_pcap"] and not f["in_listener"]:
            t2_consider.append(
                {
                    "ek_name": _dotted_to_ek(f["name"]),
                    "field": f["name"],
                    "type": f["type"],
                    "tier": "T2",
                    "seen_in": f["seen_in"],
                    "description": f["description"],
                }
            )

    # Sort gaps by number of pcaps they appear in (most common first)
    t1_gaps.sort(key=lambda x: -len(x["seen_in"]))
    t2_consider.sort(key=lambda x: -len(x["seen_in"]))

    t1_total_in_pcap = tier_counts["T1"]["in_pcap"]
    t1_extracted = tier_counts["T1"]["extracted"]

    pcap_total = len(pcap_matched) + sum(
        1 for f in classified if f["in_pcap"] and f["name"] not in pcap_matched
    )

    # Build the inventory dict
    inventory: dict[str, Any] = {
        "protocol": module_name,
        "display_filter": display_filter,
        "tshark_version": tshark_version,
        "generated": datetime.now(timezone.utc).isoformat(),
        "dissector_fields": {
            "total": len(dissector_list),
            "by_type": dict(sorted(by_type.items())),
            "fields": [
                {
                    "name": f["name"],
                    "type": f["type"],
                    "description": f["description"],
                }
                for f in dissector_list
            ],
        },
        "pcap_fields": {
            "total": len(pcap_union),
            "by_pcap": pcap_fields_by_file,
            "union": sorted(pcap_union),
        },
        "extracted_fields": {
            "total": len(extracted),
            "fields": extracted,
        },
        "coverage": {
            "dissector_vs_pcap": _pct_str(pcap_total, len(dissector_list)),
            "pcap_vs_extracted": _pct_str(len(extracted_matched), pcap_total)
            if pcap_total
            else "0/0",
            "t1_extracted": _pct_str(t1_extracted, t1_total_in_pcap)
            if t1_total_in_pcap
            else f"{t1_extracted}/{tier_counts['T1']['total']}",
            "t1_gaps": t1_gaps,
            "t2_consider": t2_consider,
            "summary": {
                "t1_total": tier_counts["T1"]["total"],
                "t1_in_pcap": tier_counts["T1"]["in_pcap"],
                "t1_covered": tier_counts["T1"]["extracted"],
                "t2_total": tier_counts["T2"]["total"],
                "t2_in_pcap": tier_counts["T2"]["in_pcap"],
                "t2_covered": tier_counts["T2"]["extracted"],
                "t3_skipped": tier_counts["T3"]["total"],
                "t4_ignored": tier_counts["T4"]["total"],
            },
        },
    }

    return inventory


def _pct_str(num: int, denom: int) -> str:
    if denom == 0:
        return f"{num}/0"
    pct = num * 100 // denom
    return f"{num}/{denom} ({pct}%)"


# ---------------------------------------------------------------------------
# Console report
# ---------------------------------------------------------------------------


def print_report(inventory: dict[str, Any], verbose: bool = False) -> None:
    """Print a console coverage report."""
    proto = inventory["protocol"]
    cov = inventory["coverage"]
    summary = cov["summary"]

    bar = "\u2550" * 55
    print(f"\n{bar}")
    print(f"  {proto.upper()} Field Coverage Audit")
    print(f"{bar}")

    print(f"  Dissector fields:   {inventory['dissector_fields']['total']:>5} total")
    print(f"  Pcap fields:        {inventory['pcap_fields']['total']:>5} present in fixtures")
    print(f"  Extracted fields:   {inventory['extracted_fields']['total']:>5} in listener")
    print()

    print(f"  T1 (Extract):  {cov['t1_extracted']}")
    t2_cov = (
        _pct_str(summary["t2_covered"], summary["t2_in_pcap"])
        if summary["t2_in_pcap"]
        else f"{summary['t2_covered']}/{summary['t2_total']}"
    )
    print(f"  T2 (Consider): {t2_cov}")
    print(f"  T3 (Skip):     {summary['t3_skipped']} fields")
    print(f"  T4 (Ignore):   {summary['t4_ignored']} fields")

    # T1 gaps
    gaps = cov["t1_gaps"]
    if gaps:
        print(f"\n\u2500\u2500 T1 GAPS ({len(gaps)} missing high-value fields) " + "\u2500" * 20)
        for g in gaps:
            pcap_count = len(g["seen_in"])
            pcaps = ", ".join(g["seen_in"][:3])
            if pcap_count > 3:
                pcaps += f" +{pcap_count - 3} more"
            print(f"  {g['field']}  {g['type']}")
            print(f"    seen in: {pcaps}")
            if g["description"] and g["description"] != g["field"]:
                desc = g["description"][:80]
                print(f"    {desc}")
    else:
        print("\n  No T1 gaps -- all high-value fields are extracted!")

    # T2 consider
    consider = cov["t2_consider"]
    if consider and verbose:
        print(f"\n\u2500\u2500 T2 CONSIDER ({len(consider)} optional fields) " + "\u2500" * 20)
        for c in consider[:15]:
            pcap_count = len(c["seen_in"])
            print(
                f"  {c['field']}  {c['type']}  (seen in {pcap_count} pcap{'s' if pcap_count != 1 else ''})"
            )
    elif consider:
        print(f"\n  T2: {len(consider)} optional fields not extracted (use --verbose to list)")

    print()


def print_summary_table(inventories: list[dict[str, Any]]) -> None:
    """Print a summary table across all audited protocols."""
    print("\n" + "=" * 80)
    print("  SUMMARY")
    print("=" * 80)

    header = f"  {'Protocol':<15} {'Dissector':>9} {'In Pcap':>9} {'Extracted':>9} {'T1 Cov':>10} {'T1 Gaps':>8}"
    print(header)
    print("  " + "-" * 75)

    for inv in sorted(inventories, key=lambda x: len(x["coverage"]["t1_gaps"]), reverse=True):
        proto = inv["protocol"]
        d_total = inv["dissector_fields"]["total"]
        p_total = inv["pcap_fields"]["total"]
        e_total = inv["extracted_fields"]["total"]
        t1_cov = inv["coverage"]["t1_extracted"]
        t1_gaps = len(inv["coverage"]["t1_gaps"])
        print(f"  {proto:<15} {d_total:>9} {p_total:>9} {e_total:>9} {t1_cov:>10} {t1_gaps:>8}")

    print()


# ---------------------------------------------------------------------------
# File output
# ---------------------------------------------------------------------------


def write_inventory(inventory: dict[str, Any]) -> Path:
    """Write inventory JSON to the ref/ directory. Returns the output path."""
    module_name = inventory["protocol"]
    ref_dir = _ref_dir_for_module(module_name)
    ref_dir.mkdir(parents=True, exist_ok=True)

    out_path = ref_dir / "tshark_fields.json"
    with open(out_path, "w") as f:
        json.dump(inventory, f, indent=2, ensure_ascii=False)
        f.write("\n")

    return out_path


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def discover_all_listeners() -> list[dict[str, Any]]:
    """Discover all listener modules under src/oida/pcap/."""
    listeners: list[dict[str, Any]] = []
    for path in sorted(SRC_DIR.glob("*.py")):
        if path.stem in _SKIP_MODULES:
            continue
        info = _parse_listener_source(path)
        if info:
            listeners.append(info)
    return listeners


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit tshark field coverage for passive listeners.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s mms              # Audit MMS listener\n"
            "  %(prog)s --all            # Audit all listeners\n"
            "  %(prog)s --all --refresh-refs  # Regenerate ref files only\n"
        ),
    )
    parser.add_argument(
        "protocol",
        nargs="?",
        help="Protocol module name to audit (e.g. mms, modbus, opcua)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Audit all protocols with listeners",
    )
    parser.add_argument(
        "--refresh-refs",
        action="store_true",
        help="Only regenerate ref JSON files (skip console report)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show T2 fields in report",
    )
    args = parser.parse_args()

    if not args.protocol and not args.all:
        parser.print_help()
        sys.exit(1)

    # Check tshark availability
    if not _is_tshark_available():
        print("ERROR: tshark not found in PATH", file=sys.stderr)
        sys.exit(1)

    tshark_ver = _get_tshark_version()
    print(f"tshark version: {tshark_ver}")

    # Load all dissector fields once
    print("Loading tshark dissector fields...", flush=True)
    all_fields = _get_all_dissector_fields()
    total_protos = len(all_fields)
    total_fields = sum(len(v) for v in all_fields.values())
    print(f"  {total_fields} fields across {total_protos} protocols")

    # Discover listeners
    if args.all:
        listeners = discover_all_listeners()
    else:
        # Find the specific listener
        path = SRC_DIR / f"{args.protocol}.py"
        if not path.exists():
            print(f"ERROR: Listener not found: {path}", file=sys.stderr)
            sys.exit(1)
        info = _parse_listener_source(path)
        if not info:
            print(f"ERROR: Could not parse DISPLAY_FILTER from {path}", file=sys.stderr)
            sys.exit(1)
        listeners = [info]

    # Build inventories
    inventories: list[dict[str, Any]] = []
    for listener in listeners:
        name = listener["module"]
        pcap_dirs = _find_pcap_dirs(name)
        if not pcap_dirs:
            if not args.refresh_refs:
                print(f"  {name}: no pcap fixtures found, skipping pcap analysis")

        print(f"Auditing {name}...", flush=True)
        inv = build_inventory(
            listener,
            all_fields,
            tshark_ver,
            verbose_progress=not args.refresh_refs,
        )
        inventories.append(inv)

        # Write ref file
        out_path = write_inventory(inv)
        print(f"  wrote {out_path.relative_to(ROOT)}")

        # Print report
        if not args.refresh_refs:
            print_report(inv, verbose=args.verbose)

    # Summary table for --all
    if args.all and not args.refresh_refs and len(inventories) > 1:
        print_summary_table(inventories)


def _is_tshark_available() -> bool:
    """Check if tshark is in PATH."""
    try:
        subprocess.run(
            ["tshark", "--version"],
            capture_output=True,
            timeout=10,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


if __name__ == "__main__":
    main()
