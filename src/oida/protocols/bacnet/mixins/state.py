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

        # If enumeration didn't fill self.objects we're about to write an
        # empty dump — say so explicitly. The bacpypes3 raw/remote path
        # was previously emitting `{"devices": {}}` with no warning,
        # leaving the operator thinking the dump worked.
        if not self.objects:
            self.logger.warning(
                "Dump skipped: no objects enumerated. Pass --enumerate-objects "
                "first, ensure the target is reachable, and (for remote unicast) "
                "pass --device-id."
            )
            return

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

        self._emit_dump(dump_data)

    def _emit_dump(self, dump_data):
        """Write a built dump to -o FILE, or render it to the console.

        Shared by the BAC0 (sync) and bacpypes3 (async) dump builders so both
        paths serialize and report identically.
        """
        output_path = getattr(self.args, "output", None)
        output_format = getattr(self.args, "format", "json")

        if output_path:
            dump_file = Path(output_path)
            # The real parser default for --format is "console", and csv/all
            # have no dump serializer. Anything that isn't an explicit yaml dump
            # (or a .yaml path) falls back to json so a -o backup always writes a
            # file instead of silently no-op'ing while claiming success.
            if output_format == "yaml" or dump_file.suffix in (".yaml", ".yml"):
                dump_file = dump_file.with_suffix(".yaml")
                dump_file.write_text(yaml.dump(dump_data, default_flow_style=False))
            else:
                dump_file = dump_file.with_suffix(".json")
                dump_file.write_text(json.dumps(dump_data, indent=2, default=str))

            self.logger.success(f"Dump saved to {dump_file}")
        else:
            # No -o given: the operator asked to dump but has nowhere to look.
            # Print the per-object detail we already read to the console instead
            # of discarding it behind a bare count, and point at -o for a file.
            self._print_dump_to_console(dump_data)

    async def _async_handle_dump(self, app, target_addr, device_id, timeout):
        """Full device state dump over the live bacpypes3 ``app`` (raw path).

        The synchronous ``_handle_dump`` reads each property through
        ``self.bacnet`` (BAC0), which is ``None`` in the default path -- so it
        could only list bare instance numbers. This reads every object's
        properties via ``app`` instead, then reuses ``_emit_dump`` to save or
        print, matching the BAC0 path's output.
        """
        if not self.objects:
            self._handle_enumerate_objects()

        if device_id is None or not self.objects.get(device_id):
            self.logger.warning(
                "Dump skipped: no objects enumerated. Pass --enumerate-objects "
                "first and ensure the device answered (pass --device-id for "
                "remote unicast)."
            )
            return

        self.logger.display("\n[Object Dump]")

        object_types_filter = getattr(self.args, "object_types", None)
        if object_types_filter:
            object_types_filter = set(t.strip().lower() for t in object_types_filter.split(","))
        control_points_only = getattr(self.args, "control_points", False)
        values_only = getattr(self.args, "values_only", False)

        device_info = self.devices.get(device_id, {})
        address = device_info.get("address", self.host)
        device_dump = {
            "device_id": device_id,
            "address": address,
            "info": device_info,
            "objects": {},
        }

        for obj_type_name, instances in self.objects.get(device_id, {}).items():
            if object_types_filter and obj_type_name.lower() not in object_types_filter:
                continue
            if control_points_only and obj_type_name not in CONTROL_POINT_TYPES:
                continue

            type_objects = []
            for instance in instances:
                obj_data = {"instance": instance}
                obj_data["name"] = await self._bacpypes3_read_one(
                    app, target_addr, obj_type_name, instance, "objectName", timeout
                )
                obj_data["presentValue"] = await self._bacpypes3_read_one(
                    app, target_addr, obj_type_name, instance, "presentValue", timeout
                )
                if not values_only:
                    obj_data["description"] = await self._bacpypes3_read_one(
                        app, target_addr, obj_type_name, instance, "description", timeout
                    )
                    obj_data["statusFlags"] = await self._bacpypes3_read_one(
                        app, target_addr, obj_type_name, instance, "statusFlags", timeout
                    )
                type_objects.append(obj_data)

            if type_objects:
                device_dump["objects"][obj_type_name] = type_objects

        dump_data = {
            "timestamp": datetime.now().isoformat(),
            "devices": {device_id: device_dump},
        }
        self._emit_dump(dump_data)

    def _print_dump_to_console(self, dump_data):
        """Render an in-memory dump to the console (used when no -o is given).

        Builds one table row per object and emits it through the framework's
        standard ``print_table`` exporter (terminal-width aware, same look as
        every other protocol's tabular output).
        """
        from ....utils.export_utils import print_table

        headers = ["Name", "Type", "Instance", "Present Value", "Description", "Status"]

        for device_id, device_dump in dump_data["devices"].items():
            objects_by_type = device_dump.get("objects", {})
            total_objects = sum(len(objs) for objs in objects_by_type.values())
            address = device_dump.get("address", self.host)

            rows = []
            for obj_type_name in sorted(objects_by_type):
                for obj in objects_by_type[obj_type_name]:
                    rows.append(
                        [
                            obj.get("name") or "",
                            obj_type_name,
                            obj.get("instance"),
                            "" if obj.get("presentValue") is None else obj.get("presentValue"),
                            obj.get("description") or "",
                            obj.get("error") or obj.get("statusFlags") or "",
                        ]
                    )

            # Drop columns that are empty across every row so a values-only dump
            # doesn't show blank Description/Status columns.
            keep = [i for i in range(len(headers)) if any(str(row[i]).strip() for row in rows)]
            active_headers = [headers[i] for i in keep]
            active_rows = [[row[i] for i in keep] for row in rows]

            title = f"  Device {device_id} @ {address} - {total_objects} objects"
            print_table(active_rows, active_headers, title=title, logger=self.logger)

        self.logger.display("  Pass -o FILE (with --format json|yaml) to save this dump to disk.")

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

        if not self.objects:
            # Same shape as the --dump fix above — be explicit instead
            # of silently producing an empty comparison.
            self.logger.warning(
                "Diff skipped: no objects enumerated against the target. "
                "Pass --enumerate-objects first, ensure the target is "
                "reachable, and (for remote unicast) pass --device-id."
            )
            return

        self.logger.display("\n[State Comparison]")

        baseline_devices = set(str(d) for d in baseline.get("devices", {}).keys())
        current_devices = set(str(d) for d in self.devices.keys())

        new_devices = current_devices - baseline_devices
        removed_devices = baseline_devices - current_devices

        if new_devices:
            self.logger.success(f"  New devices: {new_devices}")
        if removed_devices:
            self.logger.warning(f"  Removed devices: {removed_devices}")

        any_object_changes = False

        for device_id in current_devices & baseline_devices:
            baseline_device = baseline["devices"].get(str(device_id), {})
            baseline_objects = baseline_device.get("objects", {})

            current_objects = self.objects.get(int(device_id), {})

            changes = []
            # Walk every object type seen on EITHER side so a type that was
            # fully removed (present in the baseline, absent from the current
            # scan) is still reported, not just types the current scan found.
            for obj_type in set(current_objects) | set(baseline_objects):
                instances = current_objects.get(obj_type, [])
                baseline_type_objs = baseline_objects.get(obj_type, [])
                # Baselines come in two on-disk shapes: --dump writes dicts with
                # an "instance" key, while _export_results writes bare instance
                # ints. Tolerate both so diffing against either export format
                # doesn't raise AttributeError.
                baseline_instances = {
                    obj.get("instance") if isinstance(obj, dict) else obj
                    for obj in baseline_type_objs
                }
                current_instances = set(instances)

                new_objs = current_instances - baseline_instances
                removed_objs = baseline_instances - current_instances
                if new_objs:
                    changes.append(f"New {obj_type}: {new_objs}")
                if removed_objs:
                    changes.append(f"Removed {obj_type}: {removed_objs}")

            if changes:
                any_object_changes = True
                self.logger.display(f"\n  Device {device_id} changes:")
                for change in changes:
                    self.logger.display(f"    {change}")

        if not new_devices and not removed_devices and not any_object_changes:
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
