"""
BACnet Export Mixin

Handles result export and helper methods like _parse_object_id.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Tuple

from oida.protocols.bacnet.constants import OBJECT_TYPE_NAMES
from oida.utils.export_utils import export_table, configure_from_args, parse_output_format


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

            # A malformed entry (single part, or a non-numeric instance from a
            # hostile/garbled objectList) must not abort enumeration of the
            # whole device; return (0, 0) so the caller skips just this entry.
            if len(parts) < 2:
                return (0, 0)
            obj_type = OBJECT_TYPE_NAMES.get(parts[0], 0)
            try:
                instance = int(parts[1])
            except ValueError:
                return (0, 0)
            return (obj_type, instance)
        # bacpypes3 exposes the identifier as a 2-tuple-like (type, instance)
        # via .objectIdentifier; read both elements from that single value so
        # the type/instance stay consistent (the type is an ObjectType enum,
        # which is an int subclass).
        if hasattr(obj_id, "objectIdentifier"):
            obj_type, instance = obj_id.objectIdentifier
            return (int(obj_type), int(instance))
        return (0, 0)

    def _export_results(self):
        """Export scan results"""
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
        formats = parse_output_format(output_format)
        output_file = Path(output_path)

        # Rich nested JSON (devices + objects) when JSON output is requested.
        if "json" in formats:
            json_file = output_file.with_suffix(".json")
            json_file.parent.mkdir(parents=True, exist_ok=True)
            json_file.write_text(json.dumps(results, indent=2, default=str))
            self.logger.success(f"Results exported to {json_file}")

        # Tabular object inventory for console/csv/xml (and the table rows of
        # "all"). Routed through export_table so xml/all/console no longer
        # silently no-op; export_table honours the configured format list.
        headers = ["device_id", "address", "object_type", "instance"]
        rows = []
        for device_id, objects in self.objects.items():
            address = self.devices.get(device_id, {}).get("address", "")
            for obj_type, instances in objects.items():
                for instance in instances:
                    rows.append([device_id, address, obj_type, instance])

        if rows and any(fmt in formats for fmt in ("console", "csv", "xml")):
            export_table("bacnet_objects", headers, rows)
