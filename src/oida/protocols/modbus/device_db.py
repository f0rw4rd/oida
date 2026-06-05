"""
Modbus Device Identification Database

This module provides lookup functions for identifying Modbus devices
based on MEI (Modbus Encapsulated Interface) FC 43/14 responses.

The database contains 500+ devices from 85+ vendors including:
- PLCs (Schneider, Siemens, ABB, Rockwell, Beckhoff, etc.)
- Power Meters (Eastron, Carlo Gavazzi, Janitza, etc.)
- Energy Meters (Fronius, Huawei, SMA, Kostal, etc.)
- Drives (ABB, Danfoss, WEG, etc.)
- Gateways (Moxa, Advantech, Phoenix Contact, etc.)
"""

import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from fnmatch import fnmatch

from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)

# Cache for loaded database
_device_db: Optional[Dict] = None


def get_database_path() -> Path:
    """Get the path to the device database JSON file."""
    # Navigate from protocols/modbus/ up to oida/ package root
    oida_root = Path(__file__).parent.parent.parent
    return oida_root / "data" / "modbus" / "device_database.json"


def load_database() -> Dict:
    """
    Load the device database from JSON file.

    Returns:
        Dict containing the full device database
    """
    global _device_db

    if _device_db is not None:
        return _device_db

    db_path = get_database_path()

    if not db_path.exists():
        # Packaged data is missing (shouldn't happen in a normal install or the
        # frozen binary — it ships via package-data / collect_data_files). Degrade
        # gracefully to an empty database rather than crash a scan.
        return {
            "vendors": {},
            "function_codes": {},
            "mei_object_ids": {},
            "exception_codes": {},
        }

    with open(db_path, "r", encoding="utf-8") as f:
        _device_db = json.load(f)

    return _device_db


def identify_vendor(vendor_name: str) -> Optional[Dict[str, Any]]:
    """
    Identify a vendor from the MEI VendorName response.

    Args:
        vendor_name: The VendorName string from MEI response

    Returns:
        Dict with vendor info or None if not found
    """
    db = load_database()
    vendor_lower = vendor_name.lower().strip()

    for vendor_key, vendor_info in db.get("vendors", {}).items():
        # Check main vendor name
        if vendor_lower == vendor_info.get("vendor_name", "").lower():
            return {
                "vendor_key": vendor_key,
                "vendor_name": vendor_info.get("vendor_name"),
                "website": vendor_info.get("website"),
                "headquarters": vendor_info.get("headquarters"),
                "products": vendor_info.get("products", {}),
            }

        # Check aliases
        for alias in vendor_info.get("aliases", []):
            if vendor_lower == alias.lower():
                return {
                    "vendor_key": vendor_key,
                    "vendor_name": vendor_info.get("vendor_name"),
                    "website": vendor_info.get("website"),
                    "headquarters": vendor_info.get("headquarters"),
                    "products": vendor_info.get("products", {}),
                }
            # Also check with wildcard match
            if fnmatch(vendor_lower, alias.lower().replace("*", "")):
                return {
                    "vendor_key": vendor_key,
                    "vendor_name": vendor_info.get("vendor_name"),
                    "website": vendor_info.get("website"),
                    "headquarters": vendor_info.get("headquarters"),
                    "products": vendor_info.get("products", {}),
                }

    return None


def identify_product(vendor_name: str, product_code: str) -> Optional[Dict[str, Any]]:
    """
    Identify a specific product from vendor name and product code.

    Args:
        vendor_name: The VendorName string from MEI response
        product_code: The ProductCode string from MEI response

    Returns:
        Dict with product info or None if not found
    """
    vendor_info = identify_vendor(vendor_name)
    if not vendor_info:
        return None

    product_lower = product_code.lower().strip()
    products = vendor_info.get("products", {})

    for category, product_list in products.items():
        for product in product_list:
            pc = product.get("product_code", "").lower()
            model = product.get("model", "").lower()

            # Check exact match
            if product_lower == pc or product_lower == model:
                return {
                    "vendor": vendor_info.get("vendor_name"),
                    "category": category,
                    "model": product.get("model"),
                    "product_code": product.get("product_code"),
                    "mei_product_name": product.get("mei_product_name"),
                }

            # Check if product code starts with pattern
            if product_lower.startswith(pc) or pc.startswith(product_lower):
                return {
                    "vendor": vendor_info.get("vendor_name"),
                    "category": category,
                    "model": product.get("model"),
                    "product_code": product.get("product_code"),
                    "mei_product_name": product.get("mei_product_name"),
                }

    return None


def identify_device(mei_response: Dict[str, str]) -> Dict[str, Any]:
    """
    Identify a Modbus device from its complete MEI response.

    Args:
        mei_response: Dict with MEI object values, e.g.:
            {
                "VendorName": "Schneider Electric",
                "ProductCode": "PM5100",
                "MajorMinorRevision": "1.2.3",
                "ProductName": "PowerLogic PM5100"
            }

    Returns:
        Dict with identification results including:
            - vendor: Identified vendor info
            - product: Identified product info (if found)
            - confidence: Identification confidence level
            - raw_mei: Original MEI response
    """
    result = {"vendor": None, "product": None, "confidence": "unknown", "raw_mei": mei_response}

    vendor_name = mei_response.get("VendorName", "")
    product_code = mei_response.get("ProductCode", "")
    product_name = mei_response.get("ProductName", "")

    # Try to identify vendor
    if vendor_name:
        vendor_info = identify_vendor(vendor_name)
        if vendor_info:
            result["vendor"] = vendor_info
            result["confidence"] = "medium"

    # Try to identify specific product
    if vendor_name and product_code:
        product_info = identify_product(vendor_name, product_code)
        if product_info:
            result["product"] = product_info
            result["confidence"] = "high"

    # If product name matches but not code, still partial match
    if not result["product"] and product_name and result["vendor"]:
        products = result["vendor"].get("products", {})
        for category, product_list in products.items():
            for product in product_list:
                if product_name.lower() in product.get("mei_product_name", "").lower():
                    result["product"] = {
                        "vendor": result["vendor"].get("vendor_name"),
                        "category": category,
                        "model": product.get("model"),
                        "product_code": product.get("product_code"),
                        "mei_product_name": product.get("mei_product_name"),
                        "match_type": "product_name",
                    }
                    result["confidence"] = "medium"
                    break

    return result


def search_vendors(query: str) -> List[Dict[str, Any]]:
    """
    Search for vendors matching a query string.

    Args:
        query: Search string (partial match supported)

    Returns:
        List of matching vendor dictionaries
    """
    db = load_database()
    query_lower = query.lower()
    results = []

    for vendor_key, vendor_info in db.get("vendors", {}).items():
        # Check vendor name
        if query_lower in vendor_info.get("vendor_name", "").lower():
            results.append(
                {
                    "vendor_key": vendor_key,
                    "vendor_name": vendor_info.get("vendor_name"),
                    "website": vendor_info.get("website"),
                    "product_count": sum(len(p) for p in vendor_info.get("products", {}).values()),
                }
            )
            continue

        # Check aliases
        for alias in vendor_info.get("aliases", []):
            if query_lower in alias.lower():
                results.append(
                    {
                        "vendor_key": vendor_key,
                        "vendor_name": vendor_info.get("vendor_name"),
                        "website": vendor_info.get("website"),
                        "product_count": sum(
                            len(p) for p in vendor_info.get("products", {}).values()
                        ),
                    }
                )
                break

    return results


def search_products(query: str, vendor_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Search for products matching a query string.

    Args:
        query: Search string (partial match supported)
        vendor_filter: Optional vendor name to filter results

    Returns:
        List of matching product dictionaries
    """
    db = load_database()
    query_lower = query.lower()
    results = []

    for vendor_key, vendor_info in db.get("vendors", {}).items():
        vendor_name = vendor_info.get("vendor_name", "")

        # Apply vendor filter if specified
        if vendor_filter and vendor_filter.lower() not in vendor_name.lower():
            continue

        for category, product_list in vendor_info.get("products", {}).items():
            for product in product_list:
                model = product.get("model", "")
                product_code = product.get("product_code", "")
                mei_name = product.get("mei_product_name", "")

                # Check all fields for match
                if (
                    query_lower in model.lower()
                    or query_lower in product_code.lower()
                    or query_lower in mei_name.lower()
                ):
                    results.append(
                        {
                            "vendor": vendor_name,
                            "category": category,
                            "model": model,
                            "product_code": product_code,
                            "mei_product_name": mei_name,
                        }
                    )

    return results


def get_vendor_list() -> List[str]:
    """
    Get list of all vendor names in the database.

    Returns:
        Sorted list of vendor names
    """
    db = load_database()
    return sorted([v.get("vendor_name", "") for v in db.get("vendors", {}).values()])


def get_product_count() -> Tuple[int, int]:
    """
    Get total number of vendors and products in the database.

    Returns:
        Tuple of (vendor_count, product_count)
    """
    db = load_database()
    vendors = db.get("vendors", {})
    vendor_count = len(vendors)
    product_count = 0

    for vendor_info in vendors.values():
        for product_list in vendor_info.get("products", {}).values():
            product_count += len(product_list)

    return vendor_count, product_count


def get_function_code_info(fc: int) -> Optional[Dict[str, Any]]:
    """
    Get information about a Modbus function code (standard or vendor-specific).

    Args:
        fc: Function code number

    Returns:
        Dict with name, access type, vendor info (if vendor-specific), or None
    """
    db = load_database()
    fc_str = str(fc)
    function_codes = db.get("function_codes", {})

    # Check standard function codes first
    standard = function_codes.get("standard", {})
    if fc_str in standard:
        result = standard[fc_str].copy()
        result["type"] = "standard"
        return result

    # Check vendor-specific function codes
    vendor_specific = function_codes.get("vendor_specific", {})
    if fc_str in vendor_specific:
        result = vendor_specific[fc_str].copy()
        result["type"] = "vendor_specific"
        return result

    # Check if in user-defined ranges
    if 65 <= fc <= 72 or 100 <= fc <= 110:
        return {
            "name": f"User-Defined Function Code {fc}",
            "type": "user_defined",
            "access": "unknown",
            "description": "Vendor/user-defined function code - behavior varies by device",
        }

    # Reserved range check
    if fc > 127:
        return {
            "name": f"Reserved Function Code {fc}",
            "type": "reserved",
            "access": "unknown",
            "description": "Reserved for future use or error responses",
        }

    return None


def detect_custom_function_codes(supported_fcs: List[int]) -> Dict[str, Any]:
    """
    Analyze a list of supported function codes and identify vendor-specific ones.

    Args:
        supported_fcs: List of function codes supported by the device

    Returns:
        Dict with analysis results including:
            - standard: List of standard FCs supported
            - vendor_specific: List of identified vendor-specific FCs
            - user_defined: List of unknown user-defined FCs
            - security_findings: Any security-relevant function codes
            - possible_vendor: Likely vendor based on FC patterns
    """
    db = load_database()
    function_codes = db.get("function_codes", {})
    standard_fcs = function_codes.get("standard", {})
    vendor_fcs = function_codes.get("vendor_specific", {})

    result = {
        "standard": [],
        "vendor_specific": [],
        "user_defined": [],
        "security_findings": [],
        "possible_vendor": None,
    }

    vendor_hints = {}

    for fc in supported_fcs:
        fc_str = str(fc)

        # Standard function code
        if fc_str in standard_fcs:
            result["standard"].append(
                {
                    "code": fc,
                    "name": standard_fcs[fc_str]["name"],
                    "category": standard_fcs[fc_str].get("category", "unknown"),
                }
            )

        # Known vendor-specific
        elif fc_str in vendor_fcs:
            vendor_info = vendor_fcs[fc_str]
            result["vendor_specific"].append(
                {
                    "code": fc,
                    "name": vendor_info["name"],
                    "vendor": vendor_info.get("vendor", "Unknown"),
                    "description": vendor_info.get("description", ""),
                }
            )

            # Track vendor hints
            vendor = vendor_info.get("vendor", "")
            if vendor:
                vendor_hints[vendor] = vendor_hints.get(vendor, 0) + 1

            # Security findings
            if "security_note" in vendor_info:
                result["security_findings"].append(
                    {
                        "code": fc,
                        "name": vendor_info["name"],
                        "risk": vendor_info["security_note"],
                        "cves": vendor_info.get("cve_references", []),
                    }
                )

        # User-defined range
        elif 65 <= fc <= 72 or 100 <= fc <= 110:
            result["user_defined"].append(
                {
                    "code": fc,
                    "name": f"User-Defined FC {fc}",
                    "range": "65-72" if 65 <= fc <= 72 else "100-110",
                }
            )

    # Determine most likely vendor
    if vendor_hints:
        result["possible_vendor"] = max(vendor_hints, key=vendor_hints.get)

    return result


def is_security_sensitive_fc(fc: int) -> Tuple[bool, Optional[str]]:
    """
    Check if a function code has security implications.

    Args:
        fc: Function code number

    Returns:
        Tuple of (is_sensitive, reason)
    """
    db = load_database()
    vendor_fcs = db.get("function_codes", {}).get("vendor_specific", {})
    fc_str = str(fc)

    if fc_str in vendor_fcs:
        info = vendor_fcs[fc_str]
        if "security_note" in info:
            return True, info["security_note"]

    # Standard sensitive function codes
    sensitive_standard = {
        5: "Write Single Coil - can change output state",
        6: "Write Single Register - can modify configuration",
        15: "Write Multiple Coils - can change multiple outputs",
        16: "Write Multiple Registers - can modify multiple values",
        21: "Write File Record - can modify stored data",
        22: "Mask Write Register - can modify register bits",
        23: "Read/Write Multiple - combined read/write operation",
    }

    if fc in sensitive_standard:
        return True, sensitive_standard[fc]

    # User-defined ranges are potentially sensitive
    if 65 <= fc <= 72 or 100 <= fc <= 110:
        return True, "User-defined function code - behavior unknown, potentially dangerous"

    return False, None


def get_exception_info(code: int) -> Optional[Dict[str, str]]:
    """
    Get detailed information about a Modbus exception code.

    Args:
        code: Exception code number

    Returns:
        Dict with name, description, and fingerprint_use, or None
    """
    db = load_database()
    exc_info = db.get("exception_codes", {}).get(str(code))
    if isinstance(exc_info, dict):
        return exc_info
    elif isinstance(exc_info, str):
        # Legacy format compatibility
        return {"name": exc_info, "description": exc_info}
    return None


def get_exception_name(code: int) -> Optional[str]:
    """
    Get the name of a Modbus exception code.

    Args:
        code: Exception code number

    Returns:
        Exception name string or None
    """
    info = get_exception_info(code)
    if info:
        return info.get("name")
    return None


def analyze_exception_response(fc: int, exception_code: int) -> Dict[str, Any]:
    """
    Analyze an exception response to extract meaning.

    Args:
        fc: Function code that caused the exception
        exception_code: Exception code returned

    Returns:
        Dict with analysis including what this means for the device
    """
    result = {
        "function_code": fc,
        "exception_code": exception_code,
        "exception_name": get_exception_name(exception_code),
        "function_supported": None,
        "interpretation": "",
        "security_relevance": None,
    }

    fc_info = get_function_code_info(fc)

    if exception_code == 1:  # ILLEGAL_FUNCTION
        result["function_supported"] = False
        result["interpretation"] = f"FC {fc} is NOT supported by this device"
    elif exception_code == 2:  # ILLEGAL_DATA_ADDRESS
        result["function_supported"] = True
        result["interpretation"] = f"FC {fc} IS supported, but the address is invalid"
    elif exception_code == 3:  # ILLEGAL_DATA_VALUE
        result["function_supported"] = True
        result["interpretation"] = f"FC {fc} IS supported, but the value was rejected"
    elif exception_code == 4:  # SERVER_DEVICE_FAILURE
        result["function_supported"] = True
        result["interpretation"] = "Device encountered internal error processing request"
        result["security_relevance"] = "May indicate potential crash/DoS vector"
    elif exception_code == 5:  # ACKNOWLEDGE
        result["function_supported"] = True
        result["interpretation"] = "Request accepted, device processing (slow device)"
    elif exception_code == 6:  # SERVER_DEVICE_BUSY
        result["function_supported"] = True
        result["interpretation"] = "Device busy - may be single-threaded or overloaded"
    elif exception_code in [10, 11]:  # Gateway errors
        result["interpretation"] = "Device is behind a Modbus gateway/bridge"
        result["security_relevance"] = "Network architecture indicator"

    # Check if FC itself has security implications
    if fc_info and fc_info.get("type") == "vendor_specific":
        result["security_relevance"] = f"Vendor-specific FC: {fc_info.get('name', 'Unknown')}"

    return result


def fingerprint_by_exceptions(exception_results: Dict[int, Optional[int]]) -> Dict[str, Any]:
    """
    Fingerprint device based on exception response patterns.

    Args:
        exception_results: Dict mapping function codes to exception codes
                          (None = no exception/success, int = exception code)

    Returns:
        Dict with fingerprint analysis including likely vendor/device type
    """
    db = load_database()
    patterns = db.get("exception_fingerprints", {}).get("patterns", {})

    result = {
        "supported_fcs": [],
        "unsupported_fcs": [],
        "partial_support_fcs": [],
        "vendor_matches": [],
        "likely_vendor": None,
        "device_type": None,
        "confidence": 0,
        "notes": [],
    }

    # Categorize function codes by response
    for fc, exc_code in exception_results.items():
        if exc_code is None:
            result["supported_fcs"].append(fc)
        elif exc_code == 1:  # ILLEGAL_FUNCTION
            result["unsupported_fcs"].append(fc)
        elif exc_code == 2:  # ILLEGAL_DATA_ADDRESS (FC supported, address not)
            result["supported_fcs"].append(fc)
            result["partial_support_fcs"].append(fc)
        elif exc_code in [10, 11]:
            result["notes"].append("Device appears to be behind a gateway")

    # Check for Schneider UMAS (FC 90)
    if 90 in exception_results:
        if exception_results[90] is None:
            result["vendor_matches"].append(
                {
                    "vendor": "Schneider Electric",
                    "confidence": 90,
                    "reason": "UMAS protocol (FC 90) supported - Unity/Modicon PLC",
                }
            )
            result["notes"].append(
                "SECURITY: UMAS protocol exposed - CVE-2020-28212, CVE-2021-22779"
            )

    # Check for legacy Modicon (FC 66, 70)
    if 66 in exception_results and exception_results[66] is None:
        result["vendor_matches"].append(
            {
                "vendor": "Modicon (Legacy)",
                "confidence": 80,
                "reason": "Legacy program upload FC 66 supported",
            }
        )
        result["notes"].append("SECURITY: Legacy program upload exposed")

    if 70 in exception_results and exception_results[70] is None:
        result["notes"].append("SECURITY: Legacy program download FC 70 exposed - critical risk")

    # Match against known patterns
    supported_set = set(result["supported_fcs"])

    for pattern_name, pattern_info in patterns.items():
        fc_profile = set(pattern_info.get("fc_support_profile", []))
        if not fc_profile:
            continue

        # Calculate match score
        overlap = len(supported_set & fc_profile)
        total = len(fc_profile)
        unexpected = len(supported_set - fc_profile)

        if total > 0:
            match_score = (overlap / total) * 100 - (unexpected * 5)
            match_score = max(0, min(100, match_score))

            if match_score >= 50:
                result["vendor_matches"].append(
                    {
                        "vendor": pattern_info.get("description", pattern_name),
                        "confidence": round(match_score),
                        "reason": f"FC profile match: {overlap}/{total} expected FCs",
                    }
                )

    # Determine most likely vendor
    if result["vendor_matches"]:
        best_match = max(result["vendor_matches"], key=lambda x: x["confidence"])
        result["likely_vendor"] = best_match["vendor"]
        result["confidence"] = best_match["confidence"]

    # Detect device type
    if 4 in result["supported_fcs"] and len(result["supported_fcs"]) <= 4:
        result["device_type"] = "Power/Energy Meter"
    elif 43 in result["supported_fcs"] or 90 in result["supported_fcs"]:
        result["device_type"] = "PLC/Controller"
    elif 10 in exception_results.values() or 11 in exception_results.values():
        result["device_type"] = "Gateway/Bridge"

    return result


def get_exception_test_sequence() -> List[Dict[str, Any]]:
    """
    Get the recommended test sequence for exception-based fingerprinting.

    Returns:
        List of test definitions with id, test name, description, and purpose
    """
    db = load_database()
    return db.get("exception_test_sequence", {}).get("tests", [])


def get_mei_object_name(object_id: int) -> str:
    """
    Get the name of an MEI object ID.

    Args:
        object_id: MEI object ID (0-255)

    Returns:
        Object name string
    """
    db = load_database()
    hex_id = f"0x{object_id:02X}"
    mei_objects = db.get("mei_object_ids", {})

    if hex_id in mei_objects:
        return mei_objects[hex_id]

    if 0x07 <= object_id <= 0x7F:
        return "Reserved"

    if 0x80 <= object_id <= 0xFF:
        return "Vendor Defined Private Object"

    return "Unknown"


# Common vendor name patterns for fuzzy matching
VENDOR_PATTERNS = {
    r"schneid": "Schneider Electric",
    r"modicon": "Schneider Electric",
    r"siemens": "Siemens AG",
    r"abb": "ABB",
    r"rockwell": "Rockwell Automation",
    r"allen.?bradley": "Rockwell Automation",
    r"beckhoff": "Beckhoff Automation",
    r"wago": "WAGO Kontakttechnik GmbH & Co. KG",
    r"phoenix": "Phoenix Contact",
    r"eastron": "Zhejiang Eastron Electronic Co.,Ltd.",
    r"carlo.?gavazzi": "Carlo Gavazzi",
    r"janitza": "Janitza electronics GmbH",
    r"fronius": "Fronius International GmbH",
    r"huawei": "Huawei Technologies Co., Ltd.",
    r"sma": "SMA Solar Technology AG",
    r"kostal": "KOSTAL Solar Electric GmbH",
    r"omron": "OMRON Corporation",
    r"mitsubishi": "Mitsubishi Electric Corporation",
    r"delta": "Delta Electronics, Inc.",
    r"advantech": "Advantech Co., Ltd.",
    r"moxa": "Moxa Inc.",
    r"honeywell": "Honeywell International Inc.",
    r"emerson": "Emerson Electric Co.",
    r"yokogawa": "Yokogawa Electric Corporation",
    r"eaton": "Eaton Corporation",
    r"danfoss": "Danfoss A/S",
    r"weg": "WEG S.A.",
}


def fuzzy_vendor_match(vendor_string: str) -> Optional[str]:
    """
    Attempt fuzzy matching of vendor name.

    Args:
        vendor_string: Raw vendor name string from device

    Returns:
        Normalized vendor name or None
    """
    vendor_lower = vendor_string.lower()

    for pattern, vendor_name in VENDOR_PATTERNS.items():
        if re.search(pattern, vendor_lower):
            return vendor_name

    return None


def format_device_info(identification: Dict[str, Any]) -> str:
    """
    Format device identification result as a readable string.

    Args:
        identification: Result from identify_device()

    Returns:
        Formatted string
    """
    lines = []

    mei = identification.get("raw_mei", {})
    if mei:
        lines.append("MEI Device Identification:")
        for key, value in mei.items():
            lines.append(f"  {key}: {value}")

    vendor = identification.get("vendor")
    if vendor:
        lines.append(f"\nIdentified Vendor: {vendor.get('vendor_name')}")
        lines.append(f"  Website: {vendor.get('website', 'N/A')}")
        lines.append(f"  Headquarters: {vendor.get('headquarters', 'N/A')}")

    product = identification.get("product")
    if product:
        lines.append("\nIdentified Product:")
        lines.append(f"  Model: {product.get('model')}")
        lines.append(f"  Category: {product.get('category')}")
        lines.append(f"  Product Code: {product.get('product_code')}")

    lines.append(f"\nConfidence: {identification.get('confidence', 'unknown')}")

    return "\n".join(lines)


if __name__ == "__main__":
    # Configure logging for direct execution
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    # Self-test and database stats
    vendor_count, product_count = get_product_count()
    logger.info("Modbus Device Database Statistics:")
    logger.info(f"  Total Vendors: {vendor_count}")
    logger.info(f"  Total Products: {product_count}")
    logger.info("\nVendor List:")
    for vendor in get_vendor_list():
        logger.info(f"  - {vendor}")
