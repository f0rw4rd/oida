"""
BACnet Export Mixin

Handles result export and helper methods like _parse_object_id.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Tuple

from ..constants import OBJECT_TYPE_NAMES


class ExportMixin:
    """Mixin providing BACnet result export and parsing helpers."""

    def _parse_object_id(self, obj_id) -> Tuple[int, int]:
        """Parse BACnet object identifier to (type, instance)"""
        if isinstance(obj_id, tuple):
            return obj_id
        if isinstance(obj_id, str):
            if ":" in obj_id:
                parts = obj_id.split(":")
            elif "," in obj_id:
                parts = obj_id.split(",")
            else:
                return (0, 0)

            obj_type = parts[0]
            instance = int(parts[1])

            if isinstance(obj_type, str):
                obj_type = OBJECT_TYPE_NAMES.get(obj_type, 0)

            return (obj_type, instance)
        if hasattr(obj_id, "objectType") and hasattr(obj_id, "objectIdentifier"):
            return (obj_id.objectType, obj_id.objectIdentifier[1])
        return (0, 0)

    def _export_results(self):
        """Export scan results"""
        from ....utils.export_utils import export_table, configure_from_args

        output_path = getattr(self.args, "output", None)
        if not output_path:
            return

        configure_from_args(self.args, logger=self.logger)

        results = {
            "timestamp": datetime.now().isoformat(),
            "target": self.host,
            "devices": self.devices,
            "objects": {str(k): v for k, v in self.objects.items()},
        }

        output_format = getattr(self.args, "format", "json")
        output_file = Path(output_path)

        if output_format == "json":
            output_file = output_file.with_suffix(".json")
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(json.dumps(results, indent=2, default=str))
            self.logger.success(f"Results exported to {output_file}")
        elif output_format == "csv":
            headers = ["device_id", "address", "object_type", "instance"]
            rows = []
            for device_id, objects in self.objects.items():
                address = self.devices.get(device_id, {}).get("address", "")
                for obj_type, instances in objects.items():
                    for instance in instances:
                        rows.append([device_id, address, obj_type, instance])
            if rows:
                export_table("bacnet_objects", headers, rows)
