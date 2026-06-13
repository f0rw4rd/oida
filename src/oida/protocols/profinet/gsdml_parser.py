"""GSDML (General Station Description Markup Language) Parser.

Parses PROFINET device description files to extract:
- Device identity (VendorID, DeviceID)
- Module/submodule structure
- Record data indices
- I&M capabilities
"""

try:
    from defusedxml import ElementTree as ET

    _DEFUSEDXML_AVAILABLE = True
except ImportError:
    from xml.etree import ElementTree as ET

    _DEFUSEDXML_AVAILABLE = False
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from zipfile import ZipFile

import logging

logger = logging.getLogger(__name__)


# GSDML namespace
NS = {"gsdml": "http://www.profibus.com/GSDML/2003/11/DeviceProfile"}


@dataclass
class RecordData:
    """PROFINET record data definition."""

    index: int
    length: int
    name: str = ""
    transfer_sequence: int = 0
    fields: List[Dict] = field(default_factory=list)


@dataclass
class Submodule:
    """PROFINET submodule definition."""

    id: str
    submodule_ident: int
    subslot: int = 0
    name: str = ""
    writeable_im: List[int] = field(default_factory=list)
    records: List[RecordData] = field(default_factory=list)


@dataclass
class Module:
    """PROFINET module definition."""

    id: str
    module_ident: int
    slot: int = 0
    name: str = ""
    submodules: List[Submodule] = field(default_factory=list)


@dataclass
class GSDMLDevice:
    """Parsed GSDML device description."""

    vendor_id: int = 0
    device_id: int = 0
    vendor_name: str = ""
    device_name: str = ""
    order_number: str = ""
    hw_release: str = ""
    sw_release: str = ""
    physical_slots: str = ""
    modules: List[Module] = field(default_factory=list)
    dap_submodules: List[Submodule] = field(default_factory=list)
    record_data: List[RecordData] = field(default_factory=list)
    texts: Dict[str, str] = field(default_factory=dict)

    def get_all_indices(self, include_standard: bool = True) -> List[Tuple[int, str]]:
        """Get all record data indices defined in the GSDML.

        Args:
            include_standard: Include standard PROFINET indices (default True)
        """
        indices = []

        # Standard PROFINET indices (always present on any device)
        if include_standard:
            standard_indices = [
                (0x8001, "RealIdentificationData"),
                (0x8028, "RecordInputDataObjectElement"),
                (0x8029, "RecordOutputDataObjectElement"),
                (0x802A, "PDPortDataReal"),
                (0x802B, "PDPortDataCheck"),
                (0x802C, "PDIRData"),
                (0x802D, "PDSyncData"),
                (0x802F, "PDPortDataAdjust"),
                (0xE002, "ModuleDiffBlock"),
                (0xF000, "RealIdentificationData"),
                (0xF00A, "Diagnosis"),
                (0xF00B, "DiagnosisForModule"),
                (0xF00C, "DiagnosisAll"),
                (0xF010, "MaintenanceRequiredInChannel"),
                (0xF011, "MaintenanceDemandedInChannel"),
                (0xF012, "MaintenanceRequiredAll"),
                (0xF013, "MaintenanceDemandedAll"),
                (0xF020, "ARBlockReq"),
                (0xF820, "ARData"),
                (0xF821, "APIData"),
                (0xF830, "LogData"),
                (0xF831, "PDevData"),
                (0xF840, "PDRealData"),
                (0xF841, "PDRealData"),
                (0xF842, "PDExpectedData"),
                (0xF850, "AutoConfiguration"),
            ]
            indices.extend(standard_indices)

        # I&M indices based on writeable_im from GSDML
        for submod in self.dap_submodules:
            for im_num in submod.writeable_im:
                idx = 0xAFF0 + im_num
                indices.append((idx, f"I&M{im_num}"))

        # Always include I&M0 (read-only, always present)
        if (0xAFF0, "I&M0") not in [i for i in indices if i[0] == 0xAFF0]:
            indices.append((0xAFF0, "I&M0"))

        # Record data indices from GSDML
        for rec in self.record_data:
            indices.append((rec.index, rec.name or f"Record_{rec.index}"))

        # Check submodule records
        for mod in self.modules:
            for submod in mod.submodules:
                for rec in submod.records:
                    indices.append((rec.index, rec.name or f"Record_{rec.index}"))

        return sorted(set(indices), key=lambda x: x[0])

    def get_slot_structure(self) -> List[Tuple[int, int, str]]:
        """Get slot/subslot structure: [(slot, subslot, name), ...]"""
        structure = []

        # DAP is always slot 0
        for submod in self.dap_submodules:
            structure.append((0, submod.subslot, submod.name))

        # Other modules
        for mod in self.modules:
            for submod in mod.submodules:
                structure.append((mod.slot, submod.subslot, submod.name))

        return structure


def _parse_hex(value: str) -> int:
    """Parse hex string like '0x02B8' to int."""
    if not value:
        return 0
    value = value.strip()
    if value.startswith("0x") or value.startswith("0X"):
        return int(value, 16)
    return int(value)


def _get_text(texts: Dict[str, str], text_id: str) -> str:
    """Resolve text ID to actual text."""
    return texts.get(text_id, text_id)


def parse_gsdml(source) -> Optional[GSDMLDevice]:
    """Parse GSDML file or ZIP containing GSDML.

    Args:
        source: Path to GSDML file (.xml) or ZIP file, or file-like object

    Returns:
        GSDMLDevice with parsed data, or None on error
    """
    if not _DEFUSEDXML_AVAILABLE:
        # GSDML files may be attacker-supplied; refuse to parse without XXE /
        # billion-laughs protection rather than silently using the stdlib parser.
        logger.error(
            "Cannot parse GSDML: defusedxml is not installed. "
            "Install it (pip install defusedxml, or the 'profinet' extra) "
            "to safely parse untrusted GSDML files."
        )
        return None
    try:
        # Handle ZIP files
        if isinstance(source, (str, Path)):
            source = Path(source)
            if source.suffix.lower() == ".zip":
                with ZipFile(source) as zf:
                    # Find XML file in ZIP
                    xml_files = [n for n in zf.namelist() if n.lower().endswith(".xml")]
                    if not xml_files:
                        return None  # No XML file found in ZIP
                    # Use first XML (or largest if multiple)
                    xml_file = max(xml_files, key=lambda n: zf.getinfo(n).file_size)
                    with zf.open(xml_file) as f:
                        tree = ET.parse(f)
            else:
                tree = ET.parse(source)
        else:
            tree = ET.parse(source)

        root = tree.getroot()
        device = GSDMLDevice()

        # Try with namespace first, then without
        def find(elem, path):
            result = elem.find(f"gsdml:{path}", NS)
            if result is None:
                result = elem.find(path)
            return result

        def findall(elem, path):
            result = elem.findall(f"gsdml:{path}", NS)
            if not result:
                result = elem.findall(path)
            return result

        # Parse texts first (for resolving TextId references)
        for text_list in root.iter():
            if "ExternalTextList" in text_list.tag:
                for lang in text_list:
                    for text in lang:
                        if "Text" in text.tag:
                            text_id = text.get("TextId", "")
                            value = text.get("Value", "")
                            if text_id:
                                device.texts[text_id] = value

        # Parse DeviceIdentity
        for elem in root.iter():
            if "DeviceIdentity" in elem.tag:
                device.vendor_id = _parse_hex(elem.get("VendorID", "0"))
                device.device_id = _parse_hex(elem.get("DeviceID", "0"))

                for child in elem:
                    if "VendorName" in child.tag:
                        device.vendor_name = child.get("Value", "")
                break

        # Parse Family (ProductFamily = device type like "ControlPlex")
        for elem in root.iter():
            if "Family" in elem.tag and "ProductFamily" in elem.attrib:
                device.device_name = elem.get("ProductFamily", "")
                break

        # Parse DeviceAccessPointItem (DAP)
        for elem in root.iter():
            if "DeviceAccessPointItem" in elem.tag:
                device.physical_slots = elem.get("PhysicalSlots", "")

                # Parse ModuleInfo
                for mod_info in elem.iter():
                    if "ModuleInfo" in mod_info.tag:
                        for child in mod_info:
                            if "Name" in child.tag:
                                text_id = child.get("TextId", "")
                                name = _get_text(device.texts, text_id)
                                # Only overwrite if we got a real name (not just TextId back)
                                if name and name != text_id:
                                    device.device_name = name
                            elif "OrderNumber" in child.tag:
                                device.order_number = child.get("Value", "")
                            elif "HardwareRelease" in child.tag:
                                device.hw_release = child.get("Value", "")
                            elif "SoftwareRelease" in child.tag:
                                device.sw_release = child.get("Value", "")
                        break

                # Parse VirtualSubmoduleItem
                for vsub in elem.iter():
                    if "VirtualSubmoduleItem" in vsub.tag:
                        submod = Submodule(
                            id=vsub.get("ID", ""),
                            submodule_ident=_parse_hex(vsub.get("SubmoduleIdentNumber", "0")),
                        )

                        # Parse Writeable_IM_Records
                        im_records = vsub.get("Writeable_IM_Records", "")
                        if im_records:
                            submod.writeable_im = [int(x) for x in im_records.split()]

                        # Parse RecordDataList
                        for rec_list in vsub.iter():
                            if "RecordDataList" in rec_list.tag:
                                for rec_item in rec_list:
                                    if "ParameterRecordDataItem" in rec_item.tag:
                                        rec = RecordData(
                                            index=_parse_hex(rec_item.get("Index", "0")),
                                            length=int(rec_item.get("Length", "0")),
                                            transfer_sequence=int(
                                                rec_item.get("TransferSequence", "0")
                                            ),
                                        )
                                        # Get name
                                        for name_elem in rec_item:
                                            if "Name" in name_elem.tag:
                                                rec.name = _get_text(
                                                    device.texts, name_elem.get("TextId", "")
                                                )
                                                break
                                        submod.records.append(rec)

                        device.dap_submodules.append(submod)

                # Parse SubslotItem
                for subslot in elem.iter():
                    if "SubslotItem" in subslot.tag:
                        subslot_num = int(subslot.get("SubslotNumber", "0"))
                        text_id = subslot.get("TextId", "")
                        # Update submodule with subslot number
                        for submod in device.dap_submodules:
                            if submod.subslot == 0:
                                submod.subslot = subslot_num
                                submod.name = _get_text(device.texts, text_id)
                                break
                break

        # Parse ModuleList
        for elem in root.iter():
            if "ModuleList" in elem.tag:
                for mod_item in elem:
                    if "ModuleItem" in mod_item.tag:
                        mod = Module(
                            id=mod_item.get("ID", ""),
                            module_ident=_parse_hex(mod_item.get("ModuleIdentNumber", "0")),
                        )

                        # Parse ModuleInfo
                        for mod_info in mod_item.iter():
                            if "ModuleInfo" in mod_info.tag:
                                for child in mod_info:
                                    if "Name" in child.tag:
                                        text_id = child.get("TextId", "")
                                        mod.name = _get_text(device.texts, text_id)
                                break

                        # Parse VirtualSubmoduleItem
                        for vsub in mod_item.iter():
                            if "VirtualSubmoduleItem" in vsub.tag:
                                submod = Submodule(
                                    id=vsub.get("ID", ""),
                                    submodule_ident=_parse_hex(
                                        vsub.get("SubmoduleIdentNumber", "0")
                                    ),
                                )

                                # Parse Writeable_IM_Records
                                im_records = vsub.get("Writeable_IM_Records", "")
                                if im_records:
                                    submod.writeable_im = [int(x) for x in im_records.split()]

                                mod.submodules.append(submod)

                        device.modules.append(mod)
                break

        # Parse global RecordDataList (if any)
        for elem in root.iter():
            if "RecordDataList" in elem.tag and "ApplicationProcess" in str(elem):
                for rec_item in elem:
                    if "ParameterRecordDataItem" in rec_item.tag:
                        rec = RecordData(
                            index=_parse_hex(rec_item.get("Index", "0")),
                            length=int(rec_item.get("Length", "0")),
                            transfer_sequence=int(rec_item.get("TransferSequence", "0")),
                        )
                        for name_elem in rec_item:
                            if "Name" in name_elem.tag:
                                rec.name = _get_text(device.texts, name_elem.get("TextId", ""))
                                break
                        device.record_data.append(rec)

        return device

    except Exception as e:
        logger.debug(f"Operation failed: {e}")
        return None  # Failed to parse GSDML


def match_device(gsdml: GSDMLDevice, vendor_id: int, device_id: int) -> bool:
    """Check if GSDML matches a discovered device."""
    return gsdml.vendor_id == vendor_id and gsdml.device_id == device_id
