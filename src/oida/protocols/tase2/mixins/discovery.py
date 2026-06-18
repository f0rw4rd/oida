"""
TASE.2 Discovery Mixin

Handles protocol discovery operations:
- Supported features / conformance block enumeration
- TASE.2 version reading
- Domain discovery (VCC and ICC)
- VCC-scope variable discovery
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class DiscoveryMixin(_ScannerBase):
    """Mixin providing TASE.2 protocol discovery operations."""

    # =========================================================================
    # Phase 1: Protocol Discovery Methods
    # =========================================================================

    def get_supported_features(self, connection: Any) -> Dict[str, bool]:
        """
        Read Supported_Features bitmap from server via get_server_blocks().

        Returns:
            Dictionary mapping block keys to support status
        """
        features = {
            "block1": True,
            "block2": False,
            "block3": False,
            "block4": False,
            "block5": False,
        }

        try:
            blocks = connection.get_server_blocks()
            if blocks:
                for block_num, block_info in blocks.items():
                    key = f"block{block_num}"
                    if key in features:
                        supported = block_info.get("supported", False)
                        features[key] = bool(supported) if supported is not None else False

                self.logger.display("Supported Features (Conformance Blocks):")
                for block_num, block_info in blocks.items():
                    key = f"block{block_num}"
                    if key in features:
                        status = "YES" if features[key] else "NO"
                        name = block_info.get("name", f"Block {block_num}")
                        self.logger.display(f"  Block {block_num} ({name}): {status}")

        except Exception as e:
            self.logger.debug(f"Error getting supported features: {e}")

        self.supported_features = features
        return features

    def _enumerate_server_blocks(self, connection: Any) -> Dict[str, Any]:
        """
        Enumerate TASE.2 server conformance blocks (Block 1-5).

        Queries the server's Supported_Features variable to determine which
        TASE.2 conformance blocks are implemented:

        - Block 1: Data Transfer (basic services, association, datasets)
        - Block 2: Transfer Sets / RBE (report-by-exception, event-driven)
        - Block 3: Blocked Transfer (blocked data transfers)
        - Block 4: Information Messages (text/binary message transfer)
        - Block 5: Device Control (commands, select-before-operate)

        Returns:
            Dictionary with block enumeration results
        """
        block_results = {
            "blocks": {},
            "summary": "",
            "total_supported": 0,
        }

        block_descriptions = {
            1: "Data Transfer - basic services, association, data values, datasets, transfers",
            2: "Transfer Sets / RBE - conditional monitoring, event-driven transfer",
            3: "Blocked Transfer - blocked data transfers",
            4: "Information Messages - ASCII text, binary file transfer",
            5: "Device Control - commands, select-before-operate (SBO)",
        }

        try:
            blocks = connection.get_server_blocks()

            if not blocks:
                self.logger.display("Server block information not available")
                return block_results

            self.logger.display("TASE.2 Server Block Enumeration:")

            supported_names = []
            for block_num in range(1, 6):
                block_info = blocks.get(block_num, {})
                name = block_info.get("name", f"Block {block_num}")
                supported = block_info.get("supported")
                description = block_info.get("description", block_descriptions.get(block_num, ""))

                if supported is True:
                    status_str = "SUPPORTED"
                    supported_names.append(f"Block {block_num}")
                    block_results["total_supported"] += 1
                elif supported is False:
                    status_str = "NOT SUPPORTED"
                elif supported is None:
                    status_str = "UNKNOWN"
                else:
                    status_str = "UNKNOWN"

                block_results["blocks"][block_num] = {
                    "name": name,
                    "supported": supported,
                    "status": status_str,
                    "description": description,
                }

                self.logger.display(f"  Block {block_num} ({name}): {status_str}")
                if description:
                    self.logger.debug(f"    {description}")

            block_results["summary"] = ", ".join(supported_names) if supported_names else "none"
            self.logger.display(f"  Total: {block_results['total_supported']}/5 blocks supported")

        except Exception as e:
            self.logger.debug(f"Error enumerating server blocks: {e}")

        return block_results

    def get_tase2_version(self, connection: Any) -> Dict[str, int]:
        """
        Read TASE.2_Version from server (VMD-specific).

        Reads the TASE.2_Version variable directly via read_point().

        Returns:
            Dictionary with 'major' and 'minor' version numbers
        """
        version = {"major": 0, "minor": 0}

        try:
            pv = connection.read_point("", "TASE.2_Version")
            if pv and pv.value is not None:
                if isinstance(pv.value, dict):
                    version["major"] = pv.value.get("MajorVersionNumber", 0)
                    version["minor"] = pv.value.get("MinorVersionNumber", 0)
                elif isinstance(pv.value, (list, tuple)) and len(pv.value) >= 2:
                    version["major"] = int(pv.value[0])
                    version["minor"] = int(pv.value[1])
        except Exception as e:
            self.logger.debug(f"Could not read TASE.2_Version: {e}")

        if version["major"] > 0:
            self.logger.display(f"TASE.2 Version: {version['major']}.{version['minor']:02d}")

        self.tase2_version = version
        return version

    def _discover_domains(self, connection: Any) -> List[Dict[str, Any]]:
        """Discover VCC and ICC domains."""
        domains = []

        try:
            domain_list = connection.get_domains()
            self.domains = domain_list

            self.logger.display(f"Found {len(domain_list)} domain(s)")

            for domain in domain_list:
                domain_type = "VCC" if domain.is_vcc else "ICC"
                domain_info = {
                    "name": domain.name,
                    "type": domain_type,
                    "is_vcc": domain.is_vcc,
                    "variable_count": len(domain.variables),
                    "data_set_count": len(domain.data_sets),
                    "variables": domain.variables[: self.max_points],
                    "data_sets": domain.data_sets,
                }
                domains.append(domain_info)

                self.logger.display(
                    f"  {domain_type}: {domain.name} "
                    f"({len(domain.variables)} vars, {len(domain.data_sets)} datasets)"
                )

        except Exception as e:
            self.logger.debug(f"Error discovering domains: {e}")

        return domains

    def _discover_vcc_variables(self, connection: Any) -> List[Dict[str, Any]]:
        """Discover VCC-scope variables."""
        variables = []

        try:
            vcc_vars = connection.get_vcc_variables()

            for var_name in vcc_vars[: self.max_points]:
                variables.append(
                    {
                        "name": str(var_name),
                        "domain": None,
                        "scope": "VCC",
                    }
                )

            if vcc_vars:
                self.logger.display(f"VCC Variables: {len(vcc_vars)}")

        except Exception as e:
            self.logger.debug(f"Error getting VCC variables: {e}")

        return variables
