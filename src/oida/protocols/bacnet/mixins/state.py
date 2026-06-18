"""
BACnet State Mixin

Handles device state dump, diff comparison, and monitor loop.
"""

import asyncio
import json
import yaml
from datetime import datetime
from pathlib import Path
from ..constants import CONTROL_POINT_TYPES


class StateMixin:
    """Mixin providing BACnet device state operations."""

    def _handle_dump(self):
        """Full device state dump to file"""
        if not self.objects:
            self._handle_enumerate_objects()

        self.logger.display("\n[Object Dump]")

        dump_data = {
            "timestamp": datetime.now().isoformat(),
            "devices": {},
        }

        # Apply filters
        object_types_filter = getattr(self.args, "object_types", None)
        if object_types_filter:
            object_types_filter = set(t.strip().lower() for t in object_types_filter.split(","))

        control_points_only = getattr(self.args, "control_points", False)
        values_only = getattr(self.args, "values_only", False)
        full_properties = getattr(self.args, "full_properties", False)

        for device_id, device_info in self.devices.items():
            address = device_info.get("address", self.host)
            device_dump = {
                "device_id": device_id,
                "address": address,
                "info": device_info,
                "objects": {},
            }

            objects_by_type = self.objects.get(device_id, {})

            for obj_type_name, instances in objects_by_type.items():
                if object_types_filter:
                    if obj_type_name.lower() not in object_types_filter:
                        continue

                if control_points_only:
                    if obj_type_name not in CONTROL_POINT_TYPES:
                        continue

                type_objects = []

                for instance in instances:
                    obj_data = {
                        "instance": instance,
                    }

                    try:
                        obj_data["name"] = self._read_property(
                            address, obj_type_name, instance, "objectName"
                        )

                        if values_only:
                            obj_data["presentValue"] = self._read_property(
                                address, obj_type_name, instance, "presentValue"
                            )
                        elif full_properties:
                            obj_data["properties"] = self._read_all_properties(
                                address, obj_type_name, instance
                            )
                        else:
                            obj_data["description"] = self._read_property(
                                address, obj_type_name, instance, "description"
                            )
                            obj_data["presentValue"] = self._read_property(
                                address, obj_type_name, instance, "presentValue"
                            )
                            obj_data["statusFlags"] = self._read_property(
                                address, obj_type_name, instance, "statusFlags"
                            )
                            obj_data["outOfService"] = self._read_property(
                                address, obj_type_name, instance, "outOfService"
                            )

                    except Exception as e:
                        self.logger.debug(f"handle dump failed: {e}")
                        obj_data["error"] = str(e)

                    type_objects.append(obj_data)

                if type_objects:
                    device_dump["objects"][obj_type_name] = type_objects

            dump_data["devices"][device_id] = device_dump

        # Output dump
        output_path = getattr(self.args, "output", None)
        output_format = getattr(self.args, "format", "json")

        if output_path:
            dump_file = Path(output_path)
            if output_format == "json" or dump_file.suffix == ".json":
                dump_file = dump_file.with_suffix(".json")
                dump_file.write_text(json.dumps(dump_data, indent=2, default=str))
            elif output_format == "yaml":
                dump_file = dump_file.with_suffix(".yaml")
                dump_file.write_text(yaml.dump(dump_data, default_flow_style=False))

            self.logger.success(f"Dump saved to {dump_file}")
        else:
            for device_id, device_dump in dump_data["devices"].items():
                total_objects = sum(len(objs) for objs in device_dump["objects"].values())
                self.logger.display(f"  Device {device_id}: {total_objects} objects dumped")

    def _handle_diff(self):
        """Compare current state against baseline"""
        baseline_file = Path(self.args.diff).resolve()
        if not baseline_file.exists():
            self.logger.fail(f"Baseline file not found: {baseline_file}")
            return

        try:
            with open(baseline_file) as f:
                baseline = json.load(f)
        except Exception as e:
            self.logger.debug(f"handle diff failed: {e}")
            self.logger.fail(f"Failed to load baseline: {e}")
            return

        if not self.objects:
            self._handle_enumerate_objects()

        self.logger.display("\n[State Comparison]")

        baseline_devices = set(str(d) for d in baseline.get("devices", {}).keys())
        current_devices = set(str(d) for d in self.devices.keys())

        new_devices = current_devices - baseline_devices
        removed_devices = baseline_devices - current_devices

        if new_devices:
            self.logger.success(f"  New devices: {new_devices}")
        if removed_devices:
            self.logger.warning(f"  Removed devices: {removed_devices}")

        for device_id in current_devices & baseline_devices:
            baseline_device = baseline["devices"].get(str(device_id), {})
            baseline_objects = baseline_device.get("objects", {})

            current_objects = self.objects.get(int(device_id), {})

            changes = []
            for obj_type, instances in current_objects.items():
                baseline_type_objs = baseline_objects.get(obj_type, [])
                baseline_instances = {obj.get("instance") for obj in baseline_type_objs}
                current_instances = set(instances)

                new_objs = current_instances - baseline_instances
                if new_objs:
                    changes.append(f"New {obj_type}: {new_objs}")

            if changes:
                self.logger.display(f"\n  Device {device_id} changes:")
                for change in changes:
                    self.logger.display(f"    {change}")

        if not new_devices and not removed_devices:
            self.logger.display("  No significant changes detected")

    async def _async_handle_monitor(self):
        """Continuous value monitoring mode (async)"""
        if not self.objects:
            self._handle_enumerate_objects()

        if not self.objects:
            return

        interval = getattr(self.args, "interval", 1.0)

        self.logger.display(f"\n[Monitor Mode - Interval: {interval}s]")
        self.logger.display("Press Ctrl+C to stop...")

        try:
            while True:
                for device_id, objects_by_type in self.objects.items():
                    device_info = self.devices.get(device_id, {})
                    address = device_info.get("address", self.host)

                    for obj_type, instances in objects_by_type.items():
                        if obj_type not in CONTROL_POINT_TYPES:
                            continue

                        for instance in instances[:5]:
                            try:
                                value = self._read_property(
                                    address, obj_type, instance, "presentValue"
                                )
                                name = self._read_property(
                                    address, obj_type, instance, "objectName"
                                )
                                display = name or f"{obj_type}:{instance}"
                                self.logger.display(
                                    f"  [{datetime.now().strftime('%H:%M:%S')}] {display}: {value}"
                                )
                            except Exception as e:
                                self.logger.debug(f"Monitor value read failed: {e}")

                await asyncio.sleep(interval)

        except KeyboardInterrupt as e:
            self.logger.debug(f"async handle monitor failed: {e}")
            self.logger.display("\nMonitoring stopped")
