#!/usr/bin/env python3
"""
Generic Device Fingerprinting System

Provides a pattern-based fingerprinting system for extracting detailed
device information from protocol-specific data attributes.

Supports:
- Domain/namespace pattern matching
- Verification rules (attribute value checks)
- Attribute extraction with optional regex parsing
- Priority-based matching for fallback rules
"""

import json
import re
import os
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable
from pathlib import Path

from oida.utils.ics_logger import get_module_logger
from oida.utils.platform_compat import _pkg_root

logger = get_module_logger(__name__)


@dataclass
class FingerprintMatch:
    """Result of a successful fingerprint match"""

    fingerprint_name: str
    vendor_id: str
    device_type: str = "Unknown"
    vendor: Optional[str] = None
    model: Optional[str] = None
    serial: Optional[str] = None
    firmware: Optional[str] = None
    hardware_rev: Optional[str] = None
    config_rev: Optional[str] = None
    custom: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = {
            "fingerprint": self.fingerprint_name,
            "vendor_id": self.vendor_id,
            "device_type": self.device_type,
        }
        if self.vendor:
            result["vendor"] = self.vendor
        if self.model:
            result["model"] = self.model
        if self.serial:
            result["serial"] = self.serial
        if self.firmware:
            result["firmware"] = self.firmware
        if self.hardware_rev:
            result["hardware_rev"] = self.hardware_rev
        if self.config_rev:
            result["config_rev"] = self.config_rev
        if self.custom:
            result["custom"] = self.custom
        return result


@dataclass
class FingerprintRule:
    """A single fingerprint rule definition"""

    name: str
    vendor_id: str
    domain_pattern: str
    attributes: Dict[str, Any]
    verify: Dict[str, str] = field(default_factory=dict)
    custom: Dict[str, str] = field(default_factory=dict)
    device_type: str = "IED"
    priority: int = 0  # Lower = higher priority

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FingerprintRule":
        """Create rule from dictionary"""
        return cls(
            name=data.get("name", "Unknown"),
            vendor_id=data.get("vendor_id", "unknown"),
            domain_pattern=data.get("domain_pattern", ".*"),
            attributes=data.get("attributes", {}),
            verify=data.get("verify", {}),
            custom=data.get("custom", {}),
            device_type=data.get("device_type", "IED"),
            priority=data.get("priority", 0),
        )


class FingerprintMatcher:
    """
    Generic fingerprint matcher for device identification.

    Usage:
        matcher = FingerprintMatcher()
        matcher.load_fingerprints("mms_fingerprints.json")

        # Try to match a domain
        for rule in matcher.get_matching_rules("SIPApplication"):
            if matcher.verify_rule(rule, read_attribute_func):
                result = matcher.extract_attributes(rule, read_attribute_func)
                break
    """

    def __init__(self):
        self.rules: List[FingerprintRule] = []

    def load_fingerprints(self, filepath: str) -> bool:
        """
        Load fingerprint rules from JSON file.

        Args:
            filepath: Path to fingerprints JSON file

        Returns:
            True if loaded successfully
        """
        try:
            # Try relative to data directory first
            if not os.path.isabs(filepath):
                data_dir = _pkg_root() / "data"
                full_path = data_dir / filepath
                if not full_path.exists():
                    full_path = Path(filepath)
            else:
                full_path = Path(filepath)

            with open(full_path, "r") as f:
                data = json.load(f)

            fingerprints = data.get("fingerprints", [])
            for fp_data in fingerprints:
                rule = FingerprintRule.from_dict(fp_data)
                self.rules.append(rule)

            # Sort by priority (lower = higher priority)
            self.rules.sort(key=lambda r: r.priority)
            return True

        except Exception as e:
            logger.error(f"Error loading fingerprints from {filepath}: {e}")
            return False

    def get_matching_rules(self, domain_name: str) -> List[FingerprintRule]:
        """
        Get all rules that match the domain name pattern.

        Args:
            domain_name: The domain/namespace to match

        Returns:
            List of matching rules sorted by priority
        """
        matching = []
        for rule in self.rules:
            try:
                if re.match(rule.domain_pattern, domain_name):
                    matching.append(rule)
            except re.error as e:
                logger.debug(f"Invalid domain_pattern regex '{rule.domain_pattern}': {e}")
                continue
        return matching

    def verify_rule(
        self,
        rule: FingerprintRule,
        read_func: Callable[[str, str], Optional[str]],
        domain: str,
    ) -> bool:
        """
        Verify a rule by checking its verification attributes.

        Args:
            rule: The fingerprint rule to verify
            read_func: Function to read attribute value: read_func(domain, attribute) -> value
            domain: The domain name to read from

        Returns:
            True if all verification checks pass (or no verification required)
        """
        if not rule.verify:
            return True

        for attr_path, expected in rule.verify.items():
            try:
                actual = read_func(domain, attr_path)
                if actual is None:
                    return False

                # Check if expected is a regex pattern
                if expected.startswith("^") or expected.endswith("$"):
                    if not re.match(expected, str(actual)):
                        return False
                elif str(actual) != expected:
                    return False

            except Exception as e:
                logger.debug(f"Failed to get actual: {e}")
                return False

        return True

    def extract_attributes(
        self,
        rule: FingerprintRule,
        read_func: Callable[[str, str], Optional[str]],
        domain: str,
    ) -> FingerprintMatch:
        """
        Extract device attributes using the fingerprint rule.

        Args:
            rule: The fingerprint rule to use
            read_func: Function to read attribute value: read_func(domain, attribute) -> value
            domain: The domain name to read from

        Returns:
            FingerprintMatch with extracted values
        """
        match = FingerprintMatch(
            fingerprint_name=rule.name,
            vendor_id=rule.vendor_id,
            device_type=rule.device_type,
        )

        # Extract standard attributes
        for field_name, attr_spec in rule.attributes.items():
            value = self._read_attribute(attr_spec, read_func, domain)
            if value is not None:
                # Map to known fields
                if field_name == "vendor":
                    match.vendor = value
                elif field_name == "model":
                    match.model = value
                elif field_name == "serial":
                    match.serial = value
                elif field_name == "firmware":
                    match.firmware = value
                elif field_name == "hardware_rev":
                    match.hardware_rev = value
                elif field_name == "config_rev":
                    match.config_rev = value

        # Extract custom attributes
        for custom_name, attr_spec in rule.custom.items():
            value = self._read_attribute(attr_spec, read_func, domain)
            if value is not None:
                match.custom[custom_name] = value

        return match

    def _read_attribute(
        self,
        attr_spec: Any,
        read_func: Callable[[str, str], Optional[str]],
        domain: str,
    ) -> Optional[str]:
        """
        Read and optionally process an attribute value.

        Args:
            attr_spec: Either a string (attribute path) or dict with 'attribute' and 'regex'
            read_func: Function to read attribute value
            domain: Domain name

        Returns:
            Extracted value or None
        """
        if isinstance(attr_spec, str):
            # Simple attribute path
            return read_func(domain, attr_spec)

        elif isinstance(attr_spec, dict):
            attr_path = attr_spec.get("attribute")
            if not attr_path:
                return None

            raw_value = read_func(domain, attr_path)
            if raw_value is None:
                return None

            # Apply regex if specified
            regex = attr_spec.get("regex")
            if regex:
                try:
                    match = re.search(regex, str(raw_value))
                    if match:
                        # Return first group if available, otherwise full match
                        return match.group(1) if match.groups() else match.group(0)
                except re.error as e:
                    logger.debug(f"Failed to get match: {e}")
                return None

            return raw_value

        return None

    def fingerprint_device(
        self,
        domains: List[str],
        read_func: Callable[[str, str], Optional[str]],
    ) -> Optional[FingerprintMatch]:
        """
        Attempt to fingerprint a device by trying all domains.

        Args:
            domains: List of domain names discovered on the device
            read_func: Function to read attribute value

        Returns:
            Best FingerprintMatch found, or None
        """
        for domain in domains:
            matching_rules = self.get_matching_rules(domain)

            for rule in matching_rules:
                if self.verify_rule(rule, read_func, domain):
                    return self.extract_attributes(rule, read_func, domain)

        return None
