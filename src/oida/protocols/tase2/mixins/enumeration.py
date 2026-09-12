"""
TASE.2 Enumeration Mixin

Handles data point and data set operations:
- Data point enumeration and reading
- Data value type inspection
- Bulk data value reading
- Data set member listing
- Data set creation, deletion, and value reading
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class EnumerationMixin(_ScannerBase):
    """Mixin providing TASE.2 data point and data set operations."""

    def _enumerate_data_points(self, connection: Any) -> List[Dict[str, Any]]:
        """Enumerate and read data points from domains."""
        data_points = []

        for domain in self.domains:
            self.logger.display(f"Reading points from {domain.name}...")

            variables = connection.get_domain_variables(domain.name)
            var_names = [str(v) for v in variables[: self.max_points]]

            for var_name in var_names:
                point_info = {
                    "domain": domain.name,
                    "name": var_name,
                    "value": None,
                    "quality": None,
                    "readable": False,
                    "writable": False,
                }

                try:
                    pv = connection.read_point(domain.name, var_name)

                    if pv and pv.value is not None:
                        point_info["value"] = pv.value
                        point_info["quality"] = str(pv.quality)
                        point_info["point_type"] = str(pv.point_type) if pv.point_type else ""
                        point_info["readable"] = True
                        self.logger.debug(f"  {var_name}: {pv.value} [{pv.quality}]")
                    else:
                        self.logger.debug(f"  {var_name}: no value")

                except Exception as e:
                    self.logger.debug(f"  {var_name}: read error - {e}")

                data_points.append(point_info)

            if len(variables) > self.max_points:
                self.logger.display(f"  ... and {len(variables) - self.max_points} more points")

        self.logger.display(f"Enumerated {len(data_points)} data point(s)")
        return data_points

    # =========================================================================
    # Block 1 Data Value Operations
    # =========================================================================

    def get_data_value_type(self, connection: Any, domain: str, name: str) -> Dict[str, Any]:
        """
        Get type information for a data value by reading and inferring type.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name (or None for VMD-specific)
            name: Variable name

        Returns:
            Dictionary with type information
        """
        type_info = {
            "domain": domain,
            "name": name,
            "type_name": "",
        }

        try:
            pv = connection.read_point(domain, name)
            if pv:
                type_info["type_name"] = pv.type_name
                self.logger.display(f"Type of {domain}/{name}: {type_info['type_name']}")
        except Exception as e:
            self.logger.debug(f"Error getting type for {domain}/{name}: {e}")

        return type_info

    def get_data_values(
        self, connection: Any, domain: str, names: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Read multiple data values via bulk read.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            names: List of variable names

        Returns:
            List of point value dictionaries
        """
        results = []

        try:
            values = connection.read_points([(domain, n) for n in names])

            # zip() would silently truncate if the library returns fewer values
            # than names -- trailing points would vanish with no indication.
            # Detect the mismatch and emit an explicit per-name error instead.
            if len(values) != len(names):
                self.logger.warning(
                    f"Bulk read returned {len(values)} value(s) for {len(names)} requested "
                    f"point(s) in {domain}; missing points reported as errors."
                )

            for idx, name in enumerate(names):
                pv = values[idx] if idx < len(values) else None
                entry = {
                    "domain": domain,
                    "name": name,
                    "value": pv.value if pv else None,
                    "quality": str(pv.quality) if pv else None,
                    "point_type": pv.type_name if pv else None,
                }
                if idx >= len(values):
                    entry["error"] = "no value returned"
                results.append(entry)
        except Exception as e:
            self.logger.debug(f"Error in bulk read: {e}")

        return results

    # =========================================================================
    # Block 1 Data Set Operations
    # =========================================================================

    def get_data_set_members(
        self, connection: Any, domain: str, dataset_name: str
    ) -> List[Dict[str, str]]:
        """
        Get list of variables in a data set.

        Uses get_data_sets() to find the dataset and return its members.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            dataset_name: Data set name

        Returns:
            List of member variable references
        """
        members = []

        try:
            data_sets = connection.get_data_sets(domain)
            for ds in data_sets:
                if ds.name == dataset_name:
                    for member_name in ds.members:
                        members.append(
                            {
                                "domain": domain,
                                "name": str(member_name),
                            }
                        )
                    break

            if members:
                self.logger.display(f"Data set {domain}/{dataset_name} has {len(members)} members")
        except Exception as e:
            self.logger.debug(f"Error getting data set members: {e}")

        return members

    def create_data_set(
        self,
        connection: Any,
        domain: str,
        dataset_name: str,
        members: List[Dict[str, str]],
    ) -> bool:
        """
        Create a new data set on server.

        Uses MMS DefineNamedVariableList.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name for the new data set
            dataset_name: Name for the new data set
            members: List of member references [{"domain": str, "name": str}, ...]

        Returns:
            True if successful
        """
        if self.read_only:
            self.logger.warning("Cannot create data set in read-only mode")
            return False

        try:
            member_refs = [f"{m['domain']}/{m['name']}" for m in members]
            result = connection.create_data_set(domain, dataset_name, member_refs)
            if result:
                self.logger.display(f"Created data set {domain}/{dataset_name}")
            return bool(result)
        except Exception as e:
            self.logger.fail(f"Failed to create data set: {e}")
            return False

    def delete_data_set(self, connection: Any, domain: str, dataset_name: str) -> bool:
        """
        Delete a data set from server.

        Uses MMS DeleteNamedVariableList.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            dataset_name: Data set name

        Returns:
            True if successful
        """
        if self.read_only:
            self.logger.warning("Cannot delete data set in read-only mode")
            return False

        try:
            result = connection.delete_data_set(domain, dataset_name)
            if result:
                self.logger.display(f"Deleted data set {domain}/{dataset_name}")
            return bool(result)
        except Exception as e:
            self.logger.fail(f"Failed to delete data set: {e}")
            return False

    def read_data_set_values(
        self, connection: Any, domain: str, dataset_name: str
    ) -> List[Dict[str, Any]]:
        """
        Read all values in a data set.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            dataset_name: Data set name

        Returns:
            List of point values
        """
        values = []

        try:
            ds_values = connection.get_data_set_values(domain, dataset_name)

            if ds_values:
                for pv in ds_values:
                    values.append(
                        {
                            "name": pv.name or "",
                            "value": pv.value,
                            "quality": str(pv.quality),
                        }
                    )
        except Exception as e:
            self.logger.debug(f"Error reading data set values: {e}")

        return values
