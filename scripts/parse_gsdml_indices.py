#!/usr/bin/env python3
"""
GSDML Parser - Extract diagnostic data indices from PROFINET GSDML files.

Parses GSDML XML files to extract:
- ParameterRecordDataItem indices
- RecordDataRef indices
- F_ParameterRecordDataItem (PROFIsafe) indices
- ChannelDiagItem ErrorTypes
- ExtChannelDiagItem ErrorTypes
- ProfileChannelDiagItem ErrorTypes
- SubmoduleItem RecordDataList references
"""

import xml.etree.ElementTree as ET
import urllib.request
import ssl
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
import sys

# GSDML files to parse from GitHub
GSDML_URLS = [
    # ABB devices
    (
        "ABB FENA V2.31",
        "https://raw.githubusercontent.com/siamect/proview/master/profibus/exp/gsd/src/GSDML-V2.31-ABB-FENA-20140901.xml",
    ),
    (
        "ABB FENA V2.25",
        "https://raw.githubusercontent.com/siamect/proview/master/profibus/exp/gsd/src/GSDML-V2.25-ABB-FENA-20130603.xml",
    ),
    (
        "ABB RETA02",
        "https://raw.githubusercontent.com/siamect/proview/master/profibus/exp/gsd/src/GSDML-V2.0-ABBdrives-RETA02-20070621.xml",
    ),
    # Siemens devices
    (
        "Siemens SINAMICS G120",
        "https://raw.githubusercontent.com/siamect/proview/master/profibus/exp/gsd/src/gsdml-v2.0-siemens-sinamicsg120prof-20080514.xml",
    ),
    (
        "Siemens ET200M",
        "https://raw.githubusercontent.com/siamect/proview/master/profibus/exp/gsd/src/gsdml-v2.1-siemens-et200m-20070920.xml",
    ),
    (
        "Siemens ET200S",
        "https://raw.githubusercontent.com/siamect/proview/master/profibus/exp/gsd/src/gsdml-v2.1-siemens-et200s-20070701.xml",
    ),
    # Hilscher devices
    (
        "Hilscher NETX51",
        "https://raw.githubusercontent.com/HilscherAutomation/netPI-netx-programming-examples/master/electronic-data-sheets/PROFINET/GSDML-V2.33-HILSCHER-NETX%2051-RE%20PNS-20170216.xml",
    ),
    (
        "Hilscher NIOT",
        "https://raw.githubusercontent.com/HilscherAutomation/netPI-nodered-fieldbus/master/electronic-data-sheets/PROFINET/GSDML-V2.35-HILSCHER-NIOT-E-NPI3-51-EN-RE-20201005.xml",
    ),
    # Siemens SINAMICS CBE20
    (
        "Siemens SINAMICS CBE20",
        "https://raw.githubusercontent.com/wvdmbel/siemensmotor/master/gsdml-v1.0-siemens-sinamics-cbe20PilotRT-20070726.xml",
    ),
    # p-net sample device (RT-Labs PROFINET stack)
    (
        "p-net Sample Device",
        "https://raw.githubusercontent.com/rtlabs-com/p-net/master/sample_app/GSDML-V2.4-RT-Labs-P-Net-Sample-App-20220324.xml",
    ),
    # Tiberius Joystick
    (
        "HCC Tiberius",
        "https://raw.githubusercontent.com/jackoalan/pnet-tiberius/main/GSDML-V2.35-HCC-Tiberius-20200603.xml",
    ),
]


@dataclass
class GSDMLIndices:
    """Container for all indices found in a GSDML file."""

    device_name: str = ""
    vendor_id: str = ""
    device_id: str = ""
    gsdml_version: str = ""

    # Record data indices
    parameter_record_indices: dict = field(default_factory=dict)  # {index: {id, length, access}}
    f_parameter_record_indices: dict = field(default_factory=dict)  # PROFIsafe indices
    record_data_refs: list = field(default_factory=list)  # Referenced indices

    # Diagnostic indices
    channel_diag_items: dict = field(default_factory=dict)  # {error_type: name}
    ext_channel_diag_items: dict = field(default_factory=dict)
    profile_channel_diag_items: dict = field(default_factory=dict)  # {(api, error_type): name}

    # User structure identifiers
    user_structure_ids: list = field(default_factory=list)

    # Submodule record references
    submodule_records: dict = field(default_factory=dict)  # {submodule_id: [indices]}


def fetch_gsdml(url: str) -> Optional[str]:
    """Fetch GSDML content from URL."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, context=ctx, timeout=30) as response:
            raw = response.read()
            # Try different encodings
            for encoding in ["utf-8", "latin-1", "iso-8859-1", "cp1252"]:
                try:
                    return raw.decode(encoding)
                except UnicodeDecodeError:
                    continue
            # Fallback with error handling
            return raw.decode("utf-8", errors="replace")
    except Exception as e:
        print(f"  Error fetching: {e}")
        return None


def parse_gsdml(xml_content: str, device_label: str) -> GSDMLIndices:
    """Parse GSDML XML and extract all indices."""
    indices = GSDMLIndices()
    indices.device_name = device_label

    # Remove all namespace declarations and prefixes for easier parsing
    # First remove namespace declarations
    xml_content = re.sub(r'\sxmlns(?::[a-zA-Z0-9_]+)?="[^"]*"', "", xml_content)
    # Remove xsi:schemaLocation
    xml_content = re.sub(r'\sxsi:schemaLocation="[^"]*"', "", xml_content)
    # Remove namespace prefixes from tags (e.g., <pn:Tag> -> <Tag>)
    xml_content = re.sub(r"<(/?)([a-zA-Z0-9_]+):", r"<\1", xml_content)
    # Fix any XML declaration issues
    xml_content = re.sub(r"<\?xml[^?]*\?>\s*", "", xml_content)
    # Remove any BOM
    xml_content = xml_content.lstrip("\ufeff")

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        print(f"  XML Parse Error: {e}")
        # Try a more aggressive cleanup
        try:
            # Remove any problematic characters
            xml_content = "".join(c for c in xml_content if ord(c) < 128 or c in "\n\r\t")
            root = ET.fromstring(xml_content)
        except ET.ParseError as e2:
            print(f"  Second XML Parse Error: {e2}")
            return indices

    # Extract device info
    for dev_id in root.iter("DeviceIdentity"):
        indices.vendor_id = dev_id.get("VendorID", "")
        indices.device_id = dev_id.get("DeviceID", "")

    for dev_func in root.iter("DeviceFunction"):
        indices.gsdml_version = dev_func.get("MainFamily", "")

    # Extract ParameterRecordDataItem indices
    for item in root.iter("ParameterRecordDataItem"):
        idx = item.get("Index")
        if idx:
            idx_int = int(idx, 16) if idx.startswith("0x") else int(idx)
            indices.parameter_record_indices[idx_int] = {
                "id": item.get("ID", ""),
                "length": item.get("Length", ""),
                "access": item.get("Access", "prm"),
                "raw_index": idx,
            }

    # Extract F_ParameterRecordDataItem (PROFIsafe) indices
    for item in root.iter("F_ParameterRecordDataItem"):
        idx = item.get("Index")
        if idx:
            idx_int = int(idx, 16) if idx.startswith("0x") else int(idx)
            indices.f_parameter_record_indices[idx_int] = {
                "id": item.get("ID", ""),
                "f_param_crc": item.get("F_ParamDescCRC", ""),
                "raw_index": idx,
            }

    # Extract RecordDataRef indices
    for ref in root.iter("RecordDataRef"):
        idx = ref.get("Index")
        if idx:
            idx_int = int(idx, 16) if idx.startswith("0x") else int(idx)
            indices.record_data_refs.append(idx_int)

    # Also check ParameterRecordDataRef
    for ref in root.iter("ParameterRecordDataRef"):
        idx = ref.get("Index")
        if idx:
            idx_int = int(idx, 16) if idx.startswith("0x") else int(idx)
            indices.record_data_refs.append(idx_int)

    # Extract ChannelDiagItem ErrorTypes
    for item in root.iter("ChannelDiagItem"):
        error_type = item.get("ErrorType")
        if error_type:
            et_int = int(error_type, 16) if error_type.startswith("0x") else int(error_type)
            # Get name from child Name element
            name_elem = item.find("Name")
            name = name_elem.get("TextId", "") if name_elem is not None else ""
            indices.channel_diag_items[et_int] = name

    # Extract ExtChannelDiagItem ErrorTypes
    for item in root.iter("ExtChannelDiagItem"):
        error_type = item.get("ErrorType")
        if error_type:
            et_int = int(error_type, 16) if error_type.startswith("0x") else int(error_type)
            name_elem = item.find("Name")
            name = name_elem.get("TextId", "") if name_elem is not None else ""
            indices.ext_channel_diag_items[et_int] = name

    # Extract ProfileChannelDiagItem ErrorTypes (with API)
    for item in root.iter("ProfileChannelDiagItem"):
        error_type = item.get("ErrorType")
        api = item.get("API", "0")
        if error_type:
            et_int = int(error_type, 16) if error_type.startswith("0x") else int(error_type)
            api_int = int(api, 16) if api.startswith("0x") else int(api)
            name_elem = item.find("Name")
            name = name_elem.get("TextId", "") if name_elem is not None else ""
            indices.profile_channel_diag_items[(api_int, et_int)] = name

    # Extract UserStructureIdentifier values
    for item in root.iter("UserStructureIdentifier"):
        usi = item.get("Value") or item.text
        if usi:
            indices.user_structure_ids.append(usi)

    # Extract submodule record references
    for submod in root.iter("SubmoduleItem"):
        submod_id = submod.get("ID", "")
        record_refs = []
        for rec_list in submod.iter("RecordDataList"):
            for ref in rec_list:
                idx = ref.get("Index")
                if idx:
                    idx_int = int(idx, 16) if idx.startswith("0x") else int(idx)
                    record_refs.append(idx_int)
        if record_refs:
            indices.submodule_records[submod_id] = record_refs

    # Also check VirtualSubmoduleItem
    for submod in root.iter("VirtualSubmoduleItem"):
        submod_id = submod.get("ID", "")
        record_refs = []
        for rec_list in submod.iter("RecordDataList"):
            for ref in rec_list:
                idx = ref.get("Index")
                if idx:
                    idx_int = int(idx, 16) if idx.startswith("0x") else int(idx)
                    record_refs.append(idx_int)
        if record_refs:
            indices.submodule_records[submod_id] = record_refs

    return indices


def print_summary(all_indices: list[GSDMLIndices]):
    """Print summary of all found indices across all files."""

    print("\n" + "=" * 80)
    print("GSDML DIAGNOSTIC DATA INDICES SURVEY")
    print("=" * 80)

    # Aggregate all indices
    all_param_indices = defaultdict(list)  # {index: [devices]}
    all_f_param_indices = defaultdict(list)
    all_channel_diag = defaultdict(list)  # {error_type: [devices]}
    all_ext_channel_diag = defaultdict(list)
    all_profile_channel_diag = defaultdict(list)  # {(api, error_type): [devices]}

    for idx in all_indices:
        for param_idx in idx.parameter_record_indices:
            all_param_indices[param_idx].append(idx.device_name)
        for f_idx in idx.f_parameter_record_indices:
            all_f_param_indices[f_idx].append(idx.device_name)
        for et in idx.channel_diag_items:
            all_channel_diag[et].append((idx.device_name, idx.channel_diag_items[et]))
        for et in idx.ext_channel_diag_items:
            all_ext_channel_diag[et].append((idx.device_name, idx.ext_channel_diag_items[et]))
        for key in idx.profile_channel_diag_items:
            all_profile_channel_diag[key].append(
                (idx.device_name, idx.profile_channel_diag_items[key])
            )

    # Print Parameter Record Data Indices
    print("\n### ParameterRecordDataItem Indices ###")
    print(f"{'Index':<10} {'Hex':<10} {'Devices':<50}")
    print("-" * 70)
    for idx in sorted(all_param_indices.keys()):
        devices = ", ".join(all_param_indices[idx][:3])
        if len(all_param_indices[idx]) > 3:
            devices += f" (+{len(all_param_indices[idx]) - 3} more)"
        print(f"{idx:<10} 0x{idx:04X}     {devices:<50}")

    # Print F_ParameterRecordDataItem Indices (PROFIsafe)
    if all_f_param_indices:
        print("\n### F_ParameterRecordDataItem Indices (PROFIsafe) ###")
        print(f"{'Index':<10} {'Hex':<10} {'Devices':<50}")
        print("-" * 70)
        for idx in sorted(all_f_param_indices.keys()):
            devices = ", ".join(all_f_param_indices[idx])
            print(f"{idx:<10} 0x{idx:04X}     {devices:<50}")

    # Print ChannelDiagItem ErrorTypes
    if all_channel_diag:
        print("\n### ChannelDiagItem ErrorTypes ###")
        print(f"{'ErrorType':<12} {'Hex':<10} {'Name/TextId':<40} {'Device':<20}")
        print("-" * 82)
        for et in sorted(all_channel_diag.keys()):
            for device, name in all_channel_diag[et]:
                # Clean up name
                clean_name = name.replace("IDT_DIAG_NAME_", "").replace("Channel_Diag_", "")
                print(f"{et:<12} 0x{et:04X}     {clean_name:<40} {device:<20}")

    # Print ExtChannelDiagItem ErrorTypes
    if all_ext_channel_diag:
        print("\n### ExtChannelDiagItem ErrorTypes ###")
        print(f"{'ErrorType':<12} {'Hex':<10} {'Device':<30}")
        print("-" * 52)
        for et in sorted(all_ext_channel_diag.keys()):
            for device, name in all_ext_channel_diag[et]:
                print(f"{et:<12} 0x{et:04X}     {device:<30}")

    # Print ProfileChannelDiagItem ErrorTypes
    if all_profile_channel_diag:
        print("\n### ProfileChannelDiagItem ErrorTypes (Profile-Specific) ###")
        print(f"{'API':<10} {'ErrorType':<12} {'Hex':<10} {'Name':<35} {'Device':<15}")
        print("-" * 82)
        for api, et in sorted(all_profile_channel_diag.keys()):
            for device, name in all_profile_channel_diag[(api, et)]:
                clean_name = name.replace("IDT_DIAG_NAME_", "")[:35]
                print(f"{api:<10} {et:<12} 0x{et:04X}     {clean_name:<35} {device:<15}")

    # Print statistics
    print("\n### Statistics ###")
    print(f"Total GSDML files parsed: {len(all_indices)}")
    print(f"Unique ParameterRecordData indices: {len(all_param_indices)}")
    print(f"Unique F_ParameterRecordData indices: {len(all_f_param_indices)}")
    print(f"Unique ChannelDiag ErrorTypes: {len(all_channel_diag)}")
    print(f"Unique ExtChannelDiag ErrorTypes: {len(all_ext_channel_diag)}")
    print(f"Unique ProfileChannelDiag ErrorTypes: {len(all_profile_channel_diag)}")

    # Print per-device summary
    print("\n### Per-Device Summary ###")
    for idx in all_indices:
        print(f"\n{idx.device_name}:")
        print(f"  Vendor ID: {idx.vendor_id}, Device ID: {idx.device_id}")
        print(f"  ParameterRecordData indices: {sorted(idx.parameter_record_indices.keys())}")
        if idx.f_parameter_record_indices:
            print(
                f"  F_ParameterRecordData indices: {sorted(idx.f_parameter_record_indices.keys())}"
            )
        if idx.channel_diag_items:
            print(f"  ChannelDiag ErrorTypes: {sorted(idx.channel_diag_items.keys())}")
        if idx.profile_channel_diag_items:
            apis = set(api for api, _ in idx.profile_channel_diag_items.keys())
            print(f"  ProfileChannelDiag APIs: {sorted(apis)}")
            print(
                f"  ProfileChannelDiag ErrorTypes: {sorted(et for _, et in idx.profile_channel_diag_items.keys())}"
            )


def export_json(all_indices: list[GSDMLIndices], filename: str):
    """Export results to JSON."""
    output = {
        "summary": {
            "files_parsed": len(all_indices),
        },
        "devices": [],
    }

    for idx in all_indices:
        device = {
            "name": idx.device_name,
            "vendor_id": idx.vendor_id,
            "device_id": idx.device_id,
            "parameter_record_indices": {
                str(k): v for k, v in idx.parameter_record_indices.items()
            },
            "f_parameter_record_indices": {
                str(k): v for k, v in idx.f_parameter_record_indices.items()
            },
            "channel_diag_error_types": {str(k): v for k, v in idx.channel_diag_items.items()},
            "ext_channel_diag_error_types": {
                str(k): v for k, v in idx.ext_channel_diag_items.items()
            },
            "profile_channel_diag_error_types": {
                f"API{api}_ET{et}": name
                for (api, et), name in idx.profile_channel_diag_items.items()
            },
            "submodule_records": idx.submodule_records,
        }
        output["devices"].append(device)

    with open(filename, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults exported to {filename}")


def main():
    print("GSDML Diagnostic Index Parser")
    print("=" * 40)

    all_indices = []

    for name, url in GSDML_URLS:
        print(f"\nFetching: {name}")
        print(f"  URL: {url[:60]}...")

        content = fetch_gsdml(url)
        if content:
            print(f"  Downloaded {len(content)} bytes")
            indices = parse_gsdml(content, name)
            all_indices.append(indices)
            print(
                f"  Found {len(indices.parameter_record_indices)} param indices, "
                f"{len(indices.channel_diag_items)} channel diags, "
                f"{len(indices.profile_channel_diag_items)} profile diags"
            )
        else:
            print("  FAILED to download")

    if all_indices:
        print_summary(all_indices)
        export_json(all_indices, "/home/feb/pro/msf-ics/gsdml_indices_survey.json")
    else:
        print("\nNo GSDML files were successfully parsed.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
